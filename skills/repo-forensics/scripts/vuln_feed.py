#!/usr/bin/env python3
"""
vuln_feed.py - CVE + KEV enrichment for repo-forensics.

Two data sources:
  1. CISA KEV catalog — CVEs confirmed actively exploited in the wild.
     Pulled as a single ~2 MB JSON file, cached locally for 24h.
     URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

  2. OSV (Open Source Vulnerabilities) query API — per-package lookup.
     Called only for packages we actually see in a manifest, cached 24h.
     URL: https://api.osv.dev/v1/query

Security model:
  - Feed URLs are module constants. The public functions accept NO url override
    (prevents SSRF / ENV-var abuse of our own fetcher).
  - HTTPS only. Response size caps. JSON parse + schema gate before use.
  - Cache files written atomically (tempfile + os.replace) with 0o600.
  - Package/version/ecosystem inputs validated against strict regex before
    being sent over the wire. No shell, no subprocess.
  - Any network or parse failure returns an empty result — the scanner
    continues with local data rather than crashing.

Usage:
  from vuln_feed import get_kev_cves, check_package_vulnerabilities

  kev = get_kev_cves()                      # set[str] of CVE IDs
  vulns = check_package_vulnerabilities(
      "npm", "lodash", "4.17.20", kev_set=kev
  )
  # vulns -> list[dict] with id, aliases, summary, severity, in_kev, fixed_in

CLI:
  python3 vuln_feed.py --update          # refresh KEV cache
  python3 vuln_feed.py --show            # show cache status
  python3 vuln_feed.py --query npm lodash 4.17.20

Created by Alex Greenshpun
"""

import os
import sys
import json
import re
import time
import tempfile
import urllib.request
import urllib.error

# ---- Hardcoded feed endpoints (NO user override at public API) ------------
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# ---- Limits (security: bomb/DoS protection) -------------------------------
KEV_MAX_BYTES = 20 * 1024 * 1024          # 20 MB — KEV is currently ~2 MB
OSV_RESPONSE_MAX_BYTES = 2 * 1024 * 1024  # 2 MB per OSV response
NETWORK_TIMEOUT_SEC = 10
KEV_CACHE_MAX_AGE_HOURS = 24
OSV_CACHE_MAX_AGE_HOURS = 24

KEV_CACHE_FILENAME = "kev.json"
OSV_CACHE_FILENAME = "osv-queries.json"

USER_AGENT = "repo-forensics-vuln-feed/1.0 (+https://github.com/alexgreensh/repo-forensics)"

# ---- Input validation regexes --------------------------------------------
#
# OSV accepts JSON, so shell-injection is not the concern — but a malformed
# manifest could still push 50KB of unicode junk into our POST body or be
# used to waste bandwidth. Keep names and versions to reasonable shapes.
_ECOSYSTEM_ALLOW = {
    "npm", "PyPI", "Go", "Maven", "NuGet", "RubyGems",
    "crates.io", "Packagist", "Hex", "Pub",
}
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9@/._+-]{1,214}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9._+\-:~^]{1,64}$")
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.IGNORECASE)

# Strip control chars (0x00-0x1F except \t, plus 0x7F) and BIDI overrides.
# Prevents log/terminal injection when OSV summaries or package names are
# embedded in Finding titles/descriptions printed by the scanner.
_CTRL_AND_BIDI_RE = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]"
)


def _sanitize_display_text(s, max_len=300):
    """Remove control chars and BIDI overrides from text that will be printed.
    Untrusted inputs: OSV summary, aliases, package names echoed in findings."""
    if not isinstance(s, str):
        return ""
    cleaned = _CTRL_AND_BIDI_RE.sub("", s)
    return cleaned[:max_len]


def canonicalize_pkg_name(ecosystem, name):
    """Canonical package identity for dedup + query.
    PyPI uses PEP 503: lowercase, any run of _ . - becomes a single -.
    Everything else: simple lowercase."""
    if not isinstance(name, str):
        return name
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


# ========================================================================
# Cache helpers
# ========================================================================

def _cache_dir(cache_dir=None):
    if cache_dir:
        return cache_dir
    return os.path.join(
        os.path.expanduser("~"), ".cache", "repo-forensics"
    )


def _cache_path(filename, cache_dir=None):
    return os.path.join(_cache_dir(cache_dir), filename)


def _atomic_write(path, data):
    """Write JSON atomically with mode 0o600. Prevents partial-file reads
    and prevents another local user on the box from seeing cache contents."""
    dirpath = os.path.dirname(path)
    os.makedirs(dirpath, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=dirpath)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


_CACHE_FILE_MAX_BYTES = 50 * 1024 * 1024  # hard ceiling for any cache read


def _load_cache(path, max_age_hours):
    if not os.path.exists(path):
        return None
    try:
        st = os.stat(path)
        if st.st_size > _CACHE_FILE_MAX_BYTES:
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cached_at = data.get("_cached_at", 0)
        if not isinstance(cached_at, (int, float)):
            return None
        now = time.time()
        # Reject future-dated timestamps (clock skew attack -> eternal cache).
        if cached_at > now + 300:
            return None
        age_hours = (now - cached_at) / 3600
        if age_hours > max_age_hours:
            return None
        return data
    except (OSError, json.JSONDecodeError, ValueError):
        return None


# ========================================================================
# HTTPS fetch (hardened)
# ========================================================================

def _https_fetch(url, max_bytes, body=None):
    """Hardened HTTPS fetch. Returns bytes or raises urllib.error.URLError.

    Hard rules (defense-in-depth, not negotiable):
      - URL must begin with "https://" — http:// is rejected.
      - Response is read with an explicit byte cap; oversize responses raise.
      - A fixed User-Agent and a tight timeout are always applied.
      - Method is inferred: POST iff body is given, else GET.
    """
    if not isinstance(url, str) or not url.startswith("https://"):
        raise urllib.error.URLError(f"refusing non-https URL: {url!r}")

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    data = None
    method = "GET"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"

    req = urllib.request.Request(url, headers=headers, data=data, method=method)
    with urllib.request.urlopen(req, timeout=NETWORK_TIMEOUT_SEC) as resp:
        # read(N+1) lets us detect overflow without loading more than needed
        raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise urllib.error.URLError(
                f"response exceeded {max_bytes} byte cap for {url}"
            )
        return raw


# ========================================================================
# KEV (CISA Known Exploited Vulnerabilities)
# ========================================================================

def fetch_kev():
    """Download and parse the KEV catalog. Returns dict or None on failure.

    Expected shape: {catalogVersion, dateReleased, count, vulnerabilities: [...]}
    We defensively gate on the top level being a dict with a list field.
    """
    try:
        raw = _https_fetch(KEV_FEED_URL, KEV_MAX_BYTES)
        data = json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError) as e:
        print(f"[!] KEV fetch failed: {e}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        return None
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return None
    return data


def update_kev_cache(cache_dir=None):
    """Pull KEV catalog and write to cache. Returns (success, message)."""
    data = fetch_kev()
    if data is None:
        return False, "KEV fetch failed (scanner will use stale cache if present)"
    cve_ids = []
    for v in data.get("vulnerabilities", []):
        if not isinstance(v, dict):
            continue
        cid = v.get("cveID")
        if isinstance(cid, str) and _CVE_ID_RE.match(cid):
            cve_ids.append(cid.upper())
    payload = {
        "_cached_at": time.time(),
        "catalogVersion": data.get("catalogVersion"),
        "dateReleased": data.get("dateReleased"),
        "count": len(cve_ids),
        "cve_ids": cve_ids,
    }
    _atomic_write(_cache_path(KEV_CACHE_FILENAME, cache_dir), payload)
    return True, f"KEV catalog cached: {len(cve_ids)} CVEs (v{payload['catalogVersion']})"


def get_kev_cves(cache_dir=None, offline=False):
    """Return the set of CVE IDs currently in the CISA KEV catalog.

    - Uses cache if present and fresh (<24h).
    - If cache is stale or missing and offline=False, refreshes in-process.
    - If all lookups fail, returns an empty set (scanner continues gracefully).
    """
    path = _cache_path(KEV_CACHE_FILENAME, cache_dir)
    cached = _load_cache(path, KEV_CACHE_MAX_AGE_HOURS)
    # Sanity floor: real KEV catalog has 1000+ CVEs. A cache with <100 entries
    # is almost certainly poisoned or truncated — treat as miss and refresh.
    if cached is not None and len(cached.get("cve_ids") or []) < 100:
        print("[!] KEV cache appears truncated/poisoned; refreshing",
              file=sys.stderr)
        cached = None
    if cached is None and not offline:
        ok, _msg = update_kev_cache(cache_dir)
        if ok:
            cached = _load_cache(path, KEV_CACHE_MAX_AGE_HOURS)
    if cached is None:
        # Try stale cache as last resort
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cached = json.load(f)
            except (OSError, json.JSONDecodeError):
                return set()
        else:
            return set()
    ids = cached.get("cve_ids", [])
    return {c.upper() for c in ids if isinstance(c, str) and _CVE_ID_RE.match(c)}


# ========================================================================
# OSV (per-package query API)
# ========================================================================

def _validate_query_inputs(ecosystem, name, version):
    if ecosystem not in _ECOSYSTEM_ALLOW:
        return False
    if not isinstance(name, str) or not _PKG_NAME_RE.match(name):
        return False
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        return False
    return True


def _osv_cache_key(ecosystem, name, version):
    return f"{ecosystem}::{name}::{version}"


# Per-process negative cache (ecosystem -> time of last failure).
# Short TTL: enough to avoid a retry storm for a ~500-package lockfile
# when OSV is briefly rate-limiting (429) or down (5xx). Not persisted.
_OSV_DEGRADED = {}
_OSV_DEGRADED_TTL_SEC = 60


def _osv_is_degraded(ecosystem):
    ts = _OSV_DEGRADED.get(ecosystem)
    return ts is not None and (time.time() - ts) < _OSV_DEGRADED_TTL_SEC


def _osv_mark_degraded(ecosystem):
    _OSV_DEGRADED[ecosystem] = time.time()


def _load_osv_cache(cache_dir=None):
    path = _cache_path(OSV_CACHE_FILENAME, cache_dir)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except (OSError, json.JSONDecodeError):
        return {}


def _save_osv_cache(cache, cache_dir=None):
    _atomic_write(_cache_path(OSV_CACHE_FILENAME, cache_dir), cache)


def query_osv(ecosystem, name, version, cache_dir=None, offline=False):
    """Query OSV for vulnerabilities in (ecosystem, name, version).

    Returns list[dict] with normalized shape:
      {"id": ..., "aliases": [...], "summary": ..., "severity": ...,
       "references": [...]}

    Errors and invalid inputs return []. A per-(pkg,version) 24h cache
    prevents hammering api.osv.dev on repeat scans.
    """
    if not _validate_query_inputs(ecosystem, name, version):
        return []

    cache = _load_osv_cache(cache_dir)
    key = _osv_cache_key(ecosystem, name, version)
    entry = cache.get(key)
    if isinstance(entry, dict):
        cached_at = entry.get("_cached_at", 0)
        if isinstance(cached_at, (int, float)):
            age_h = (time.time() - cached_at) / 3600
            if age_h <= OSV_CACHE_MAX_AGE_HOURS:
                return entry.get("vulns", [])

    if offline:
        return []

    # In-process negative-cache shortcircuit: if OSV just failed for this
    # ecosystem in the last 60s, don't hammer it again in the same scan run.
    if _osv_is_degraded(ecosystem):
        return []

    body = {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
    try:
        raw = _https_fetch(OSV_QUERY_URL, OSV_RESPONSE_MAX_BYTES, body=body)
        data = json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError) as e:
        print(f"[!] OSV query failed for {ecosystem}/{name}@{version}: {e}",
              file=sys.stderr)
        _osv_mark_degraded(ecosystem)
        return []

    vulns = _normalize_osv_vulns(data)
    cache[key] = {"_cached_at": time.time(), "vulns": vulns}
    # Guard against unbounded cache growth
    if len(cache) > 5000:
        # Drop oldest entries (rough LRU by cached_at)
        items = sorted(
            cache.items(),
            key=lambda kv: kv[1].get("_cached_at", 0) if isinstance(kv[1], dict) else 0
        )
        cache = dict(items[-4000:])
    try:
        _save_osv_cache(cache, cache_dir)
    except OSError as e:
        print(f"[!] OSV cache write failed: {e}", file=sys.stderr)
    return vulns


def _normalize_osv_vulns(data):
    """Extract a minimal, scanner-friendly shape from an OSV response."""
    if not isinstance(data, dict):
        return []
    out = []
    vulns = data.get("vulns", [])
    if not isinstance(vulns, list):
        return []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        vid = v.get("id")
        if not isinstance(vid, str) or len(vid) > 64:
            continue
        vid = _sanitize_display_text(vid, max_len=64)
        aliases = [
            _sanitize_display_text(a, max_len=64)
            for a in v.get("aliases", [])
            if isinstance(a, str) and len(a) <= 64
        ]
        summary = _sanitize_display_text(v.get("summary"), max_len=300)
        severity = _extract_severity(v)
        fixed_in = _extract_fixed_versions(v)
        out.append({
            "id": vid,
            "aliases": aliases,
            "summary": summary,
            "severity": severity,  # dict: {type, score} or None
            "fixed_in": fixed_in,  # list[str]
        })
    return out


def _extract_severity(vuln):
    sev = vuln.get("severity")
    if isinstance(sev, list):
        for s in sev:
            if isinstance(s, dict):
                t = s.get("type")
                score = s.get("score")
                if isinstance(t, str) and isinstance(score, str):
                    return {"type": t, "score": score[:64]}
    return None


def _extract_fixed_versions(vuln):
    out = []
    for aff in vuln.get("affected", []) or []:
        if not isinstance(aff, dict):
            continue
        for rng in aff.get("ranges", []) or []:
            if not isinstance(rng, dict):
                continue
            for ev in rng.get("events", []) or []:
                if isinstance(ev, dict) and isinstance(ev.get("fixed"), str):
                    out.append(ev["fixed"][:64])
    return out[:10]  # cap


# ========================================================================
# Public helper used by scan_dependencies
# ========================================================================

def check_package_vulnerabilities(ecosystem, name, version,
                                   kev_set=None, cache_dir=None, offline=False):
    """Return a list of findings (dicts) for a single package.

    Each finding:
      {"id": "GHSA-xxx", "aliases": ["CVE-2024-1234"], "summary": "...",
       "severity": {"type": "CVSS_V3", "score": "..."}, "fixed_in": [...],
       "in_kev": True/False, "suggested_severity": "critical"|"high"|"medium"}

    `suggested_severity` escalates to critical if the vuln's CVE alias
    appears in the CISA KEV catalog — that's the whole point of KEV.
    """
    vulns = query_osv(ecosystem, name, version, cache_dir=cache_dir, offline=offline)
    if not vulns:
        return []
    kev = kev_set if kev_set is not None else set()
    out = []
    for v in vulns:
        cves = [a.upper() for a in v.get("aliases", []) if _CVE_ID_RE.match(a)]
        in_kev = any(c in kev for c in cves)
        out.append({
            **v,
            "in_kev": in_kev,
            "suggested_severity": _suggest_severity(v, in_kev),
        })
    return out


def _suggest_severity(vuln, in_kev):
    """Map OSV severity + KEV presence to our scanner's severity tiers."""
    if in_kev:
        return "critical"
    sev = vuln.get("severity") or {}
    score_str = sev.get("score", "")
    # CVSS vector strings start with "CVSS:3.x/..." — extract basescore if present
    # Also tolerate plain numeric strings.
    cvss = _parse_cvss_score(score_str)
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


_CVSS_SCORE_RE = re.compile(r"\d+(?:\.\d+)?")


def _parse_cvss_score(s):
    if not isinstance(s, str) or not s:
        return None
    m = _CVSS_SCORE_RE.search(s)
    if not m:
        return None
    try:
        val = float(m.group(0))
    except ValueError:
        return None
    if 0.0 <= val <= 10.0:
        return val
    return None


# ========================================================================
# CLI
# ========================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="repo-forensics vuln feed (KEV + OSV)")
    parser.add_argument("--update", action="store_true",
                        help="Refresh CISA KEV cache now")
    parser.add_argument("--show", action="store_true",
                        help="Show cache status")
    parser.add_argument("--query", nargs=3, metavar=("ECOSYSTEM", "NAME", "VERSION"),
                        help="Query OSV for one package (e.g. --query npm lodash 4.17.20)")
    parser.add_argument("--cache-dir", default=None, help="Override cache directory")
    args = parser.parse_args()

    if args.update:
        ok, msg = update_kev_cache(args.cache_dir)
        print(f"{'[+]' if ok else '[!]'} {msg}")
        sys.exit(0 if ok else 1)

    if args.show:
        path = _cache_path(KEV_CACHE_FILENAME, args.cache_dir)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                age = (time.time() - data.get("_cached_at", 0)) / 3600
                print(f"KEV cache: {data.get('count', 0)} CVEs, "
                      f"v{data.get('catalogVersion')}, age {age:.1f}h")
            except (OSError, json.JSONDecodeError) as e:
                print(f"KEV cache: unreadable ({e})")
        else:
            print("KEV cache: none")
        opath = _cache_path(OSV_CACHE_FILENAME, args.cache_dir)
        if os.path.exists(opath):
            try:
                with open(opath, "r", encoding="utf-8") as f:
                    ocache = json.load(f)
                print(f"OSV cache: {len(ocache)} package queries")
            except (OSError, json.JSONDecodeError):
                print("OSV cache: unreadable")
        else:
            print("OSV cache: none")
        sys.exit(0)

    if args.query:
        eco, name, ver = args.query
        kev = get_kev_cves(cache_dir=args.cache_dir)
        findings = check_package_vulnerabilities(eco, name, ver, kev_set=kev,
                                                   cache_dir=args.cache_dir)
        if not findings:
            print(f"[+] No known vulns for {eco}/{name}@{ver}")
        else:
            for f in findings:
                flag = " [KEV!]" if f["in_kev"] else ""
                print(f"[{f['suggested_severity'].upper()}] {f['id']}{flag}: {f['summary']}")
                for c in f["aliases"]:
                    print(f"    alias: {c}")
                if f["fixed_in"]:
                    print(f"    fixed in: {', '.join(f['fixed_in'])}")
        sys.exit(0)

    parser.print_help()


if __name__ == "__main__":
    main()
