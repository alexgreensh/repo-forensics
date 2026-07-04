#!/usr/bin/env python3
"""
dead_anchors_probe.py - Network claimability layer for the dead-anchor scanner
(U2).

Turns an extracted Anchor into a CC / LO / NC verdict:
  CC = CONFIRMED-CLAIMABLE (404 / NXDOMAIN / RDAP-404 / provider fingerprint) -> the
       one signal that emits a Finding downstream.
  LO = LIVE-AND-OWNED (200 / registered) -> silent (normal state of the world).
  NC = COULDN'T-CHECK (403 / 429 / 5xx / timeout / offline / over-budget) -> silent.

Loop-safety & race-safety contract (spec §10), all STRUCTURAL not incidental:
  * Single attempt per probe. There is NO retry loop anywhere in this module.
  * HTTPError caught FIRST, branched on .code (KTD-3): 404 => CC (signal),
    403/429 => NC + trips the per-host circuit breaker, 5xx/other => NC. A 404
    NEVER collapses into the generic "network failed => NC" branch (inverts the
    vuln_feed.fetch_npm/pypi_freshness anti-pattern).
  * Per-host circuit breaker: first 403/429 from a host trips it; every later
    probe to that host short-circuits to NC with zero further calls, no reset.
  * One shared wall-clock deadline + a GH call cap + a total-probe ceiling; all
    checked BEFORE any socket is touched (network last).
  * 24h atomic result cache, reusing vuln_feed._atomic_write / _load_cache
    directly (temp+os.replace+0o600, no lock, tolerant reads). Only CC/LO are
    cached; NC (transient) always re-probes next scan.
  * offline=True is the cheapest path: instant NC before cache/deadline/budget.

All HTTPS goes through vuln_feed._https_fetch (no 4th hand-rolled urlopen). DNS
for cloud subdomains uses socket.gethostbyname (no HTTP equivalent), wrapped in
the same never-raise discipline.

Created by Alex Greenshpun
"""

import os
import re
import sys
import json
import time
import stat
import socket
import hashlib
import tempfile
import ipaddress
import threading
import http.client
import urllib.error
import urllib.parse
import urllib.request

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import vuln_feed
import forensics_core as core
from dead_anchors_extract import normalize_npm_name, normalize_pypi_name

# ---- Tunables (read at construction so tests can monkeypatch) --------------
NETWORK_DEADLINE_SEC = 12.0        # whole-pass wall-clock budget
GITHUB_CALL_CAP = 20               # unauthenticated GH calls/scan
GITHUB_CALL_CAP_TOKEN = 40         # raised (not authenticated) when a token exists
TOTAL_PROBE_CEILING = 50           # across ALL anchor types/scan
RESULT_CACHE_TTL_HOURS = 24

_HTTP_MAX_BYTES = 512 * 1024       # cap on any probe response body
_CLOUD_BODY_MAX_BYTES = 128 * 1024

_HOST_GITHUB = "api.github.com"
_HOST_NPM = "registry.npmjs.org"
_HOST_PYPI = "pypi.org"
_HOST_RDAP = "rdap.org"

# Input-validation charsets (defense-in-depth before a value hits a URL).
_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$")
_PKG_RE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9@/._-]{0,120}$")
_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,190}$")


# ---------------------------------------------------------------------------
# SSRF / redirect hardening (security-sentinel F1/F4, code-review F1).
#
# Python's DEFAULT urllib opener transparently follows up to 10 redirects, each
# a fresh request to a SERVER-CONTROLLED Location that bypasses the per-host
# breaker, the probe budget, the whole-pass deadline AND the https-only check
# (https->http downgrade + pivot to internal / link-local / metadata IPs are all
# allowed). Every dead_anchors probe therefore uses an EXPLICIT opener:
#   * fixed-host + attacker-host probes (GitHub/npm/PyPI/cloud) -> NO redirects.
#     A 3xx surfaces as its own HTTPError and is classified COULDN'T-CHECK; the
#     Location is never auto-fetched.
#   * rdap.org -> a BOUNDED, re-validated redirect (its whole purpose is to
#     bootstrap-redirect to the correct registry RDAP server): <=3 hops, each
#     https-only and each rejected if the target host resolves into a private /
#     loopback / link-local / metadata range.
# ---------------------------------------------------------------------------

def _is_internal_ip(ip):
    """True for any address a forensics probe must never connect to."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return True  # unparseable => refuse (fail closed)
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _hostname_is_internal(host):
    """Resolve host (A+AAAA) and return True if ANY address is internal, or if it
    cannot be resolved/validated (fail closed — block the redirect hop)."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except Exception:
        return True
    checked = False
    for info in infos:
        sockaddr = info[4] if len(info) > 4 else None
        if sockaddr:
            checked = True
            if _is_internal_ip(sockaddr[0]):
                return True
    return not checked


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse ALL redirects. Returning None makes urllib raise the 3xx as an
    HTTPError instead of following the Location header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow at most a few redirects, each re-validated: https-only, and the
    target host must not resolve into an internal range."""

    max_redirections = 3

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            parts = urllib.parse.urlsplit(newurl)
        except Exception:
            return None
        if parts.scheme != "https":
            return None
        host = parts.hostname
        if not host or _hostname_is_internal(host):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_NO_REDIRECT_OPENER = None
_BOUNDED_REDIRECT_OPENER = None


def _no_redirect_opener():
    global _NO_REDIRECT_OPENER
    if _NO_REDIRECT_OPENER is None:
        _NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)
    return _NO_REDIRECT_OPENER


def _bounded_redirect_opener():
    global _BOUNDED_REDIRECT_OPENER
    if _BOUNDED_REDIRECT_OPENER is None:
        _BOUNDED_REDIRECT_OPENER = urllib.request.build_opener(_BoundedRedirectHandler)
    return _BOUNDED_REDIRECT_OPENER


class _DirectOpener:
    """Test seam: an opener whose .open() routes back through
    vuln_feed.urllib.request.urlopen so the suite's single mock chokepoint still
    intercepts every dead_anchors probe. Production always uses the real
    no-redirect / bounded-redirect openers above."""

    def open(self, req, timeout=None):
        return vuln_feed.urllib.request.urlopen(req, timeout=timeout)


class _Deadline:
    """Single shared wall-clock budget for the whole claimability pass (mirrors
    scan_provenance._Deadline). NETWORK_DEADLINE_SEC read at construction so a
    test can monkeypatch it."""

    def __init__(self):
        self._end = time.monotonic() + NETWORK_DEADLINE_SEC

    def remaining(self):
        return max(0.0, self._end - time.monotonic())

    def expired(self):
        return self.remaining() <= 0.0


class _ProbeBudget:
    """GH-specific cap + total-probe ceiling. Consumed only when a probe is
    actually about to issue a request."""

    def __init__(self, github_cap, total_ceiling):
        self.gh_remaining = github_cap
        self.total_remaining = total_ceiling

    def take(self, github=False):
        if self.total_remaining <= 0:
            return False
        if github and self.gh_remaining <= 0:
            return False
        self.total_remaining -= 1
        if github:
            self.gh_remaining -= 1
        return True


class _CircuitBreaker:
    """Per-scan, per-host trip state. First 403/429 from a host trips it; never
    resets within the scan (no backoff, no Retry-After honoring)."""

    def __init__(self):
        self._tripped = set()

    def trip(self, host):
        self._tripped.add(host)

    def is_tripped(self, host):
        return host in self._tripped


class ProbeContext:
    """Bundles the per-scan state threaded through every probe. All state is
    LOCAL to one scan_repo() call — no module-level mutable globals (spec §10
    'no shared mutable state across scanners')."""

    def __init__(self, offline=False, cache_dir=None, github_token=None):
        self.offline = offline
        self.deadline = _Deadline()
        token = github_token if github_token is not None else os.environ.get("GITHUB_TOKEN")
        self.has_token = bool(token)
        # The token is NEVER attached to a request (no Authorization header is
        # added anywhere in the fetch path), so authenticated calls are not
        # actually made — a token must therefore NOT raise the call budget.
        # Inflating it only made the scanner hammer GitHub's real 60/hr limit,
        # trip the circuit breaker sooner and silently under-detect
        # (security-sentinel F7). Keep the cap fixed until real auth is wired.
        self.budget = _ProbeBudget(GITHUB_CALL_CAP, TOTAL_PROBE_CEILING)
        self.breaker = _CircuitBreaker()
        self.cache_dir = cache_dir if cache_dir is not None else _default_cache_dir()

    # -- 24h result cache (only CC/LO cached; NC always re-probes) ------------

    def _cache_path(self, key):
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return os.path.join(self.cache_dir, f"{digest}.json")

    def cache_get(self, key):
        """Return a cached (verdict, extra) tuple within TTL, else None.
        Tolerant: any read error / malformed / wrong-shape entry => cache-miss,
        never a crash (KTD-14). Refuses to read through a symlinked cache dir or
        entry (verdict-poisoning backstop, security-sentinel F6)."""
        try:
            path = self._cache_path(key)
            if os.path.islink(self.cache_dir) or os.path.islink(path):
                return None
            data = vuln_feed._load_cache(path, RESULT_CACHE_TTL_HOURS)
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        verdict = data.get("verdict")
        if verdict not in ("CC", "LO"):
            return None
        extra = data.get("extra")
        return verdict, (extra if isinstance(extra, dict) else None)

    def cache_put(self, key, verdict, extra=None):
        if verdict not in ("CC", "LO"):
            return  # never cache a transient NC
        try:
            path = self._cache_path(key)
            if os.path.islink(self.cache_dir) or os.path.islink(path):
                return  # never write through a symlinked cache dir/entry
        except OSError:
            return
        payload = {"_cached_at": time.time(), "verdict": verdict,
                   "extra": extra if isinstance(extra, dict) else {}}
        try:
            vuln_feed._atomic_write(path, payload)
        except OSError:
            pass  # cache write failure is non-fatal


def _default_cache_dir():
    """Never raise: in a UID-less container `~` may not expand
    (pwd.getpwuid -> KeyError), which must degrade to a temp dir, not crash the
    scan (python-redos F4)."""
    try:
        home = os.path.expanduser("~")
        if not home or home == "~":
            raise ValueError("no home directory")
        return os.path.join(home, ".cache", "repo-forensics", "dead-anchors")
    except Exception:
        return os.path.join(tempfile.gettempdir(), "repo-forensics-dead-anchors")


ProbeResult = None  # (kept as documentation; probes return (verdict, extra))


# ---------------------------------------------------------------------------
# Core HTTPS wrapper — the single most load-bearing correctness property.
# HTTPError caught BEFORE URLError, branched on .code. Single attempt.
# ---------------------------------------------------------------------------

def _call_timeout(ctx):
    """Per-call socket timeout = min(network timeout, remaining pass deadline) so
    one hung probe can never overrun the whole-pass budget by a full timeout
    (code-review F2, integration F4)."""
    remaining = ctx.deadline.remaining()
    base = getattr(vuln_feed, "NETWORK_TIMEOUT_SEC", 10)
    if remaining <= 0:
        return 0.001
    return min(base, remaining)


def _probe_https(url, host, ctx, max_bytes=_HTTP_MAX_BYTES, opener=None):
    """Issue ONE GET via the hardened vuln_feed._https_fetch, with NO redirect
    following (opener defaults to the no-redirect opener). Returns
    (verdict, raw_bytes_or_None). On 403/429 trips the host breaker. A 3xx
    (redirect refused) is classified NC — never auto-fetched. Never raises."""
    if opener is None:
        opener = _no_redirect_opener()
    try:
        raw = vuln_feed._https_fetch(url, max_bytes, opener=opener,
                                     timeout=_call_timeout(ctx))
        return "LO", raw
    except urllib.error.HTTPError as e:  # MUST precede URLError (subclass)
        code = getattr(e, "code", None)
        if code == 404:
            return "CC", None
        if code in (403, 429):
            ctx.breaker.trip(host)
            return "NC", None
        return "NC", None  # incl. 3xx (redirect refused) => couldn't-check
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        return "NC", None


def _pre_network_ok(ctx, host, github=False):
    """Shared cheap gate run before any request: deadline -> breaker -> budget.
    Returns True iff a request may be issued. 'network last'."""
    if ctx.deadline.expired():
        return False
    if ctx.breaker.is_tripped(host):
        return False
    if not ctx.budget.take(github=github):
        return False
    return True


def _parse_json(raw):
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# Per-anchor-type probes. Order in each: offline -> cache -> pre-network -> fetch.
# ---------------------------------------------------------------------------

def probe_github_user(owner, ctx):
    """GET api.github.com/users/{owner}. On LO returns the parsed JSON (for
    DA-10 owner-trust enrichment)."""
    if ctx.offline:
        return "NC", None
    if not _OWNER_RE.match(owner or ""):
        return "NC", None
    key = f"gh_user::{owner.lower()}"
    cached = ctx.cache_get(key)
    if cached is not None:
        return cached
    if not _pre_network_ok(ctx, _HOST_GITHUB, github=True):
        return "NC", None
    url = f"https://api.github.com/users/{urllib.parse.quote(owner, safe='')}"
    verdict, raw = _probe_https(url, _HOST_GITHUB, ctx)
    meta = _github_owner_meta(_parse_json(raw)) if verdict == "LO" else None
    if verdict in ("CC", "LO"):
        ctx.cache_put(key, verdict, meta)
    return verdict, meta


def probe_github_repo(owner, repo, ctx):
    """GET api.github.com/repos/{owner}/{repo}. Only meaningful when the owner
    probe returned LO (caller enforces)."""
    if ctx.offline:
        return "NC", None
    if not (_OWNER_RE.match(owner or "") and _OWNER_RE.match(repo or "")):
        return "NC", None
    key = f"gh_repo::{owner.lower()}/{repo.lower()}"
    cached = ctx.cache_get(key)
    if cached is not None:
        return cached
    if not _pre_network_ok(ctx, _HOST_GITHUB, github=True):
        return "NC", None
    url = (f"https://api.github.com/repos/{urllib.parse.quote(owner, safe='')}/"
           f"{urllib.parse.quote(repo, safe='')}")
    verdict, _raw = _probe_https(url, _HOST_GITHUB, ctx)
    if verdict in ("CC", "LO"):
        ctx.cache_put(key, verdict, None)
    return verdict, None


def probe_npm(name, ctx):
    if ctx.offline:
        return "NC", None
    if not _PKG_RE.match(name or "") or ".." in name:
        return "NC", None
    # npm names are case-insensitive & lowercase: probe (and cache) the canonical
    # form so 'npm install React' resolves to the live 'react', not a phantom
    # 404 (integration F2).
    probe_name = normalize_npm_name(name)
    if not probe_name:
        return "NC", None
    key = f"npm::{probe_name}"
    cached = ctx.cache_get(key)
    if cached is not None:
        return cached
    if not _pre_network_ok(ctx, _HOST_NPM):
        return "NC", None
    url = f"https://registry.npmjs.org/{urllib.parse.quote(probe_name, safe='@')}"
    verdict, _raw = _probe_https(url, _HOST_NPM, ctx)
    if verdict in ("CC", "LO"):
        ctx.cache_put(key, verdict, None)
    return verdict, None


def probe_pypi(name, ctx):
    if ctx.offline:
        return "NC", None
    if not _PKG_RE.match(name or "") or ".." in name:
        return "NC", None
    # PEP 503 canonicalization before probing: 'My_Package', 'my-package',
    # 'my.package' are one live distribution, not a phantom (integration F3).
    probe_name = normalize_pypi_name(name)
    if not probe_name:
        return "NC", None
    key = f"pypi::{probe_name}"
    cached = ctx.cache_get(key)
    if cached is not None:
        return cached
    if not _pre_network_ok(ctx, _HOST_PYPI):
        return "NC", None
    url = f"https://pypi.org/pypi/{urllib.parse.quote(probe_name, safe='')}/json"
    verdict, _raw = _probe_https(url, _HOST_PYPI, ctx)
    if verdict in ("CC", "LO"):
        ctx.cache_put(key, verdict, None)
    return verdict, None


def _rdap_probe(url, ctx):
    """rdap.org fetch with BOUNDED, re-validated redirects. Returns
    (verdict, extra). A 404 is CC only when it was delivered by a delegated
    registry RDAP server (i.e. a redirect off rdap.org actually happened —
    genuine 'domain does not exist'); a bare 404 straight from rdap.org means it
    could not bootstrap a server for that TLD (ccTLD gap / transient) and must
    NOT fire a false CRITICAL on a live domain (security-sentinel F2)."""
    opener = _bounded_redirect_opener()
    try:
        raw = vuln_feed._https_fetch(url, _HTTP_MAX_BYTES, opener=opener,
                                     timeout=_call_timeout(ctx))
        return "LO", _rdap_expiry_meta(_parse_json(raw))
    except urllib.error.HTTPError as e:
        code = getattr(e, "code", None)
        if code in (403, 429):
            ctx.breaker.trip(_HOST_RDAP)
            return "NC", None
        if code == 404:
            final = getattr(e, "url", "") or ""
            try:
                host = (urllib.parse.urlsplit(final).hostname or "").lower()
            except Exception:
                host = ""
            if host and host != _HOST_RDAP:
                return "CC", None      # registry itself said 'not found'
            return "NC", None          # rdap.org bootstrap gap => ambiguous
        return "NC", None
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        return "NC", None


def probe_domain_rdap(domain, ctx):
    """GET rdap.org/domain/{domain}. Registry 404 (after bootstrap redirect) =>
    CC (unregistered/expired). On LO, inspect the events array for a PAST
    expiration date (imminent-expiry flag)."""
    if ctx.offline:
        return "NC", None
    if not _DOMAIN_RE.match(domain or ""):
        return "NC", None
    key = f"rdap::{domain.lower()}"
    cached = ctx.cache_get(key)
    if cached is not None:
        return cached
    if not _pre_network_ok(ctx, _HOST_RDAP):
        return "NC", None
    url = f"https://rdap.org/domain/{urllib.parse.quote(domain, safe='')}"
    verdict, extra = _rdap_probe(url, ctx)
    if verdict in ("CC", "LO"):
        ctx.cache_put(key, verdict, extra)
    return verdict, extra


def _resolve_with_timeout(host, timeout):
    """Resolve host (A+AAAA via getaddrinfo, not IPv4-only gethostbyname) with a
    HARD wall-clock bound so a hung resolver can never overrun the pass deadline
    (integration F4). Returns (status, addrs):
      'ok'       -> addrs is the list of resolved IP strings
      'nxdomain' -> the name provably does not resolve (EAI_NONAME)
      'nc'       -> couldn't-check (timeout / temporary failure / other)
    An AAAA-only (IPv6-only) host resolves to 'ok', NOT a false 'nxdomain'
    (security-sentinel F3). A hung resolver returns 'nc', never 'nxdomain'."""
    result = {}

    def _run():
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            result["addrs"] = [i[4][0] for i in infos
                               if i and len(i) > 4 and i[4]]
        except socket.gaierror as e:
            if getattr(e, "errno", None) == socket.EAI_NONAME:
                result["nx"] = True
            else:
                result["err"] = True
        except (OSError, UnicodeError, ValueError):
            result["err"] = True

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout if timeout and timeout > 0 else None)
    if t.is_alive():
        return "nc", None            # resolver hung -> couldn't-check
    if result.get("addrs"):
        return "ok", result["addrs"]
    if result.get("nx"):
        return "nxdomain", None
    return "nc", None


def _cloud_http(url, suffix, ctx):
    """Fetch a cloud subdomain root with NO redirects, capturing the response
    body EVEN ON a non-200 status (a deleted-app error page is what we need to
    fingerprint — the generic _probe_https discards the 404 body). Returns
    (body_bytes, ok); ok is False on transport failure / 403 / 429 (=> NC)."""
    try:
        raw = vuln_feed._https_fetch(url, _CLOUD_BODY_MAX_BYTES,
                                     opener=_no_redirect_opener(),
                                     timeout=_call_timeout(ctx))
        return raw, True
    except urllib.error.HTTPError as e:
        code = getattr(e, "code", None)
        if code in (403, 429):
            ctx.breaker.trip(suffix)
            return None, False
        try:
            body = e.read(_CLOUD_BODY_MAX_BYTES + 1)
            if body and len(body) > _CLOUD_BODY_MAX_BYTES:
                body = body[:_CLOUD_BODY_MAX_BYTES]
        except Exception:
            body = b""
        return body or b"", True
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        return None, False


def probe_cloud_subdomain(subdomain, suffix, ctx, fingerprints=None):
    """Claimability for a free-tier cloud subdomain.

    The ONLY stand-alone high-confidence claimable signal is DNS NXDOMAIN. A
    resolving host is fetched and its body checked against STRICT provider
    deleted-app fingerprints; a bare 404/200 from a resolving host with no strict
    fingerprint stays LO (silent), never a false CRITICAL (error-soundness F2,
    integration F1). Biased hard toward silence over a false CRITICAL."""
    if ctx.offline:
        return "NC", None
    if not _DOMAIN_RE.match(subdomain or ""):
        return "NC", None
    key = f"cloud::{subdomain.lower()}"
    cached = ctx.cache_get(key)
    if cached is not None:
        return cached
    # DNS resolution (no HTTP equivalent). Counts against the total ceiling +
    # deadline, but is not a GH call. Breaker keyed on the registrable suffix.
    if ctx.deadline.expired() or ctx.breaker.is_tripped(suffix):
        return "NC", None
    if not ctx.budget.take(github=False):
        return "NC", None
    status, addrs = _resolve_with_timeout(subdomain, _call_timeout(ctx))
    if status == "nxdomain":
        ctx.cache_put(key, "CC", {"reason": "nxdomain"})
        return "CC", {"reason": "nxdomain"}
    if status != "ok":
        return "NC", None
    # Structural SSRF backstop, independent of the rulepack: never fetch a
    # subdomain that resolves into a private / loopback / link-local / metadata
    # range, whatever the suffix list says (security-sentinel F1/F4).
    if any(_is_internal_ip(a) for a in (addrs or [])):
        return "NC", None
    # Resolves & public: fetch and fingerprint. Second call — guard again.
    if not _pre_network_ok(ctx, suffix):
        return "NC", None
    body, ok = _cloud_http(f"https://{subdomain}", suffix, ctx)
    if not ok:
        return "NC", None
    fp = _fingerprint_match(body, suffix, fingerprints or {})
    if fp is not None:
        ctx.cache_put(key, "CC", {"reason": "fingerprint", "confidence": fp})
        return "CC", {"reason": "fingerprint", "confidence": fp}
    ctx.cache_put(key, "LO", None)
    return "LO", None


# ---- Enrichment helpers ----------------------------------------------------

def _github_owner_meta(data):
    """DA-10 owner-trust signals from the SAME users response (created_at,
    public_repos, bio). Never raises."""
    if not isinstance(data, dict):
        return None
    return {
        "created_at": data.get("created_at"),
        "public_repos": data.get("public_repos"),
        "bio": data.get("bio"),
    }


def _rdap_expiry_meta(data):
    """Return {'imminent_expiry': True} if the RDAP events array carries a past
    (already-elapsed) expiration date, else None."""
    if not isinstance(data, dict):
        return None
    events = data.get("events")
    if not isinstance(events, list):
        return None
    now = time.time()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if ev.get("eventAction") != "expiration":
            continue
        ts = _parse_iso8601(ev.get("eventDate"))
        if ts is not None and ts < now:
            return {"imminent_expiry": True}
    return None


def _parse_iso8601(s):
    if not isinstance(s, str) or not s:
        return None
    txt = s.strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            import datetime
            dt = datetime.datetime.strptime(txt, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.timestamp()
        except (ValueError, ImportError):
            continue
    return None


def _fingerprint_match(raw, suffix, fingerprints):
    """Return the confidence float if a STRICT provider deleted-app fingerprint
    for this suffix matches the response body, else None.

    Strictness (integration F1, error-soundness F2/F5): only entries explicitly
    marked "strict": true fire CC (generic phrases like 'project not found' /
    'Application not found' were removed from the pack and any without the flag
    are ignored), and the token must match on non-alphanumeric boundaries — not
    as a loose substring buried inside a larger word — so a live app that merely
    happens to contain the phrase as part of its own content does not trip it."""
    entries = fingerprints.get(suffix)
    if not isinstance(entries, list):
        return None
    try:
        if isinstance(raw, (bytes, bytearray)):
            body = raw.decode("utf-8", errors="replace")
        else:
            body = str(raw or "")
    except Exception:
        return None
    for ent in entries:
        if not isinstance(ent, dict):
            continue
        if ent.get("strict") is not True:
            continue
        needle = ent.get("s")
        if not isinstance(needle, str) or not needle:
            continue
        pattern = r"(?<![0-9A-Za-z])" + re.escape(needle) + r"(?![0-9A-Za-z])"
        if re.search(pattern, body):
            conf = ent.get("confidence")
            return float(conf) if isinstance(conf, (int, float)) else 0.8
    return None
