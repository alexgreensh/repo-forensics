#!/usr/bin/env python3
"""
ioc_manager.py - IOC (Indicators of Compromise) management for repo-forensics v2.
Handles loading, caching, and updating IOC lists from a hosted JSON feed.

Usage:
  from ioc_manager import get_iocs
  iocs = get_iocs(repo_path)  # returns merged hardcoded + cached IOCs

  # Or update from remote:
  python3 ioc_manager.py --update [--cache-dir /path]

IOC feed format (hosted JSON):
{
  "version": "2026-03-20",
  "c2_ips": ["1.2.3.4", ...],
  "malicious_domains": ["evil.com", ...],
  "malicious_packages": {"npm": [...], "pypi": [...]},
  "malicious_npm_packages": ["pkg1", ...],
  "malicious_pypi_packages": ["pkg1", ...]
}

Created by Alex Greenshpun
"""

import os
import sys
import json
import tempfile
import time

# Ensure sibling modules (forensics_core, etc.) are importable regardless of
# how this module gets loaded — direct CLI, hook subprocess, or daemon
# importlib bootstrap. Inserting our own dir at sys.path[0] is contained to
# this process and aligns with session_scan/auto_scan's existing pattern.
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

# Default IOC feed URL (GitHub raw from repo-forensics releases)
IOC_FEED_URL = "https://raw.githubusercontent.com/alexgreensh/repo-forensics/main/iocs/latest.json"

CACHE_FILENAME = ".forensics-iocs.json"
# Detached signature for verify-on-load (KTD-11). The signature is verified over
# the EXACT bytes of the .json cache that get parsed and trusted — NOT a separate
# .raw file. Verifying a sibling file that nobody parses leaves the trusted bytes
# unprotected (a same-user attacker could edit the .json and slip past the gate),
# so the two are deliberately one and the same byte stream now.
SIG_CACHE_FILENAME = ".forensics-iocs.sig"
PREVIOUS_CACHE_FILENAME = ".forensics-iocs.previous.json"
PREVIOUS_SIG_CACHE_FILENAME = ".forensics-iocs.previous.sig"
# Sentinel recording that this install has seen a signed feed at least once. Its
# presence means "a signature USED to be here": if the .sig later goes missing,
# we degrade rather than silently trusting an unsigned (possibly stripped) cache.
SIGNED_SEEN_FILENAME = ".forensics-iocs.signed-seen"
CACHE_MAX_AGE_HOURS = 24

# Pinned Ed25519 public key for the signed IOC feed (KTD-11). SAME keypair that
# signs the rule-pack bundle (symmetric trust model). The private seed is held
# OFFLINE; this module only ever VERIFIES.
IOC_FEED_PUBKEY_HEX = (
    "a6529e80619abaf38bec2b15154ca8f540f9a830e310f1a0c7a6771e85f1b76c"
)
# Detached-signature feed URL (sits beside IOC_FEED_URL).
_SIG_MAX_BYTES = 256
# Configurable TTL for the on-disk IOC cache. Adjusting this constant controls
# how long a successfully-fetched remote feed is trusted before the scanner
# considers itself degraded and emits a warning.
_IOC_CACHE_TTL_HOURS = 24

# Shipped IOC database (version-pinned compromises). Loaded from
# skills/repo-forensics/data/compromised_versions.json next to this script. This file ships
# with the tool and is reviewable in git history — it is NOT cached or
# downloaded at runtime. See --sync-osv (when implemented) for live updates.
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')
COMPROMISED_VERSIONS_FILE = os.path.normpath(
    os.path.join(_DATA_DIR, 'compromised_versions.json')
)
COMPROMISED_VERSIONS_SCHEMA_VERSION = '1.0'

# --- Hardcoded IOCs (fallback, always available) ---

HARDCODED_C2_IPS = [
    "91.92.242.30", "54.91.154.110", "157.245.55.238",
    "45.77.240.42", "104.248.30.47", "159.65.147.111",
    "142.11.206.73",  # Axios supply chain RAT C2 (March 2026)
    "83.142.209.11",   # TeamPCP Wave 1 C2 (March 2026)
    "91.195.240.123",  # TeamPCP Wave 3 C2 (April 2026)
    "94.154.172.43",   # TeamPCP Wave 3 audit endpoint (April 2026)
    "45.148.10.212",   # Trivy compromise exfil (March 2026)
    "83.142.209.203",  # Telnyx WAV steganography exfil (March 2026)
    "216.126.225.129",  # Megalodon CI campaign, May 2026
]

HARDCODED_MALICIOUS_DOMAINS = [
    "install.app-distribution.net",
    "dl.dropboxusercontent.com",
    # raw.githubusercontent.com intentionally excluded: legitimate CDN used by this
    # tool's own IOC feed. Flag only when combined with obfuscation/exec patterns
    # (handled by correlation engine rules 1, 2, 9).
    "socifiapp.com",
    "hackmoltrepeat.com",
    "giftshop.club",
    "glot.io",
    "api.telegram.org/bot",
    "discord.com/api/webhooks",
    "hooks.slack.com/services",
    # liteLLM supply chain attack C2 (March 2026)
    "eo1n0jq9qgggt.m.pipedream.net",
    "sfrclak.com",  # Axios supply chain RAT C2 domain (March 2026)
    "checkmarx.zone",          # TeamPCP Wave 1-2 C2 domain (March 2026)
    "models.litellm.cloud",    # LiteLLM supply chain compromise (March 2026)
    "checkmarx.cx",            # TeamPCP Wave 3 C2 domain (April 2026)
    "audit.checkmarx.cx",      # TeamPCP Wave 3 exfil endpoint (April 2026)
    "scan.aquasecurity.org",   # Trivy compromise exfil domain (March 2026)
    "npnjs.com",               # npm maintainer phishing (Chalk compromise, 2025)
    "npmjs.help",              # npm maintainer phishing (2025)
    "files.pypihosted.org",    # Fake PyPI mirror (top.gg attack, 2024)
    "filev2.getsession.org",   # TanStack worm: Session P2P exfiltration (May 2026)
    "seed1.getsession.org",    # TanStack worm: Session P2P seed node (May 2026)
    "seed2.getsession.org",    # TanStack worm: Session P2P seed node (May 2026)
    "seed3.getsession.org",    # TanStack worm: Session P2P seed node (May 2026)
    "api.cloud-aws.adc-e.uk",  # Mini Shai-Hulud: TeamPCP C2 domain (May 2026)
    "cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io",  # CanisterWorm ICP blockchain C2, Apr 2026
    "check.git-service.com",    # durabletask PyPI C2, May 2026
    "t.m-kosche.com",           # Shared @antv/actions-cool C2, May 2026
    "aab.sportsontheweb.net",   # vpmdhaj OpenSearch/Elastic typosquat C2, May 2026
]

HARDCODED_MALICIOUS_NPM = {
    "rimarf", "yarsg", "suport-color", "naniod", "opencraw",
    "claud-code", "cloude-code", "cloude", "mcp-cliient", "mcp-serever",
    "anthropic-sdk-node", "claude-code-cli", "clawclient",
    "plain-crypto-js",  # Axios supply chain RAT dropper (March 2026)
    "@tanstack/setup",  # TanStack worm: entirely malicious package (May 2026)
    "chalk-tempalte",   # Shai-Hulud copycat (May 2026)
    "@deadcode09284814/axios-util",  # Shai-Hulud copycat (May 2026)
    "axois-utils",      # Shai-Hulud copycat (May 2026)
    "color-style-utils",  # Shai-Hulud copycat (May 2026)
    "@vpmdhaj/elastic-helper",  # vpmdhaj OpenSearch/Elastic typosquat cluster (May 2026)
    "@vpmdhaj/devops-tools",
    "@vpmdhaj/opensearch-setup",
    "@vpmdhaj/search-setup",
    "opensearch-security-scanner",
    "opensearch-setup",
    "opensearch-setup-tool",
    "opensearch-config-utility",
    "search-engine-setup",
    "search-cluster-setup",
    "elastic-opensearch-helper",
    "vpmdhaj-opensearch-setup",
    "env-config-manager",
    "app-config-utility",
}

HARDCODED_MALICIOUS_PYPI = {
    "anthopic", "antrhopic", "claudes", "mcp-python-sdk",
}

HARDCODED_MALICIOUS_PTH_FILES = {
    "litellm_init.pth", "litellm-init.pth", "litellm.pth",
    "llm_init.pth", "init_hook.pth", "startup.pth",
}


# --- Shipped compromised-versions database loader ---

_COMPROMISED_VERSIONS_CACHE = None


def _load_compromised_versions_file(path=None):
    """Load and flatten the shipped compromised_versions.json into scanner-
    friendly structures.

    Returns a tuple (version_map, entirely_malicious_names, raw_data) where:
      - version_map: dict[str, dict[str, str]] keyed by lower-case package
        name -> {version_string: campaign_id}. Only includes packages with
        specific version entries (not wildcards).
      - entirely_malicious_names: set[str] of lower-case package names where
        ANY version is malicious (version list is ['*']).
      - raw_data: the original parsed JSON (for callers that need campaign
        metadata for reporting).

    Returns ({}, set(), None) if the file is missing, unreadable, or has
    an incompatible schema version. This is a soft failure — the scanner
    will fall back to in-module defaults in that case.
    """
    target = path or COMPROMISED_VERSIONS_FILE
    try:
        with open(target, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Could not load {target}: {e}", file=sys.stderr)
        return {}, set(), None

    # Top-level must be a dict (crafted JSON could be a list or scalar)
    if not isinstance(data, dict):
        print(f"[!] {target} top-level must be a JSON object", file=sys.stderr)
        return {}, set(), None

    # Schema version gate — future schema changes may add incompatible fields.
    # The schema_version field MUST be a string; non-string types (int, float,
    # null, list, dict from a hand-edited or poisoned feed) would crash the
    # .split() call with AttributeError, which is not caught by the outer
    # except clause and would kill the scanner. (Security review SS-F2,
    # 2026-04-05.)
    schema_version = data.get('schema_version', '')
    if not isinstance(schema_version, str):
        print(
            f"[!] {target} schema_version must be a string, "
            f"got {type(schema_version).__name__}",
            file=sys.stderr,
        )
        return {}, set(), None
    major = schema_version.split('.')[0] if schema_version else ''
    expected_major = COMPROMISED_VERSIONS_SCHEMA_VERSION.split('.')[0]
    if major != expected_major:
        print(
            f"[!] {target} schema version {schema_version!r} "
            f"incompatible with expected {COMPROMISED_VERSIONS_SCHEMA_VERSION!r}",
            file=sys.stderr,
        )
        return {}, set(), None

    version_map = {}
    entirely_malicious = set()
    campaigns = data.get('campaigns', {})
    if not isinstance(campaigns, dict):
        return {}, set(), None

    for campaign_id, campaign in campaigns.items():
        if not isinstance(campaign, dict):
            continue
        packages = campaign.get('packages', {})
        if not isinstance(packages, dict):
            continue
        for pkg_name, versions in packages.items():
            if not isinstance(pkg_name, str) or not isinstance(versions, list):
                continue
            pkg_lower = pkg_name.lower()
            if versions == ['*']:
                entirely_malicious.add(pkg_lower)
                continue
            if pkg_lower not in version_map:
                version_map[pkg_lower] = {}
            for v in versions:
                if not isinstance(v, str):
                    continue
                version_map[pkg_lower][v] = campaign_id

    return version_map, entirely_malicious, data


def _get_compromised_versions():
    """Return cached compromised-versions tuple, loading on first call."""
    global _COMPROMISED_VERSIONS_CACHE
    if _COMPROMISED_VERSIONS_CACHE is None:
        _COMPROMISED_VERSIONS_CACHE = _load_compromised_versions_file()
    return _COMPROMISED_VERSIONS_CACHE


def _reset_compromised_versions_cache():
    """Test helper: force a fresh load on next access."""
    global _COMPROMISED_VERSIONS_CACHE
    _COMPROMISED_VERSIONS_CACHE = None


def _cache_path(cache_dir=None):
    """Get path for IOC cache file."""
    if cache_dir:
        return os.path.join(cache_dir, CACHE_FILENAME)
    return os.path.join(os.path.expanduser("~"), ".cache", "repo-forensics", CACHE_FILENAME)


def _sig_cache_path(cache_dir=None):
    base = cache_dir if cache_dir else os.path.join(
        os.path.expanduser("~"), ".cache", "repo-forensics")
    return os.path.join(base, SIG_CACHE_FILENAME)


def _previous_cache_path(cache_dir=None):
    return os.path.join(os.path.dirname(_cache_path(cache_dir)), PREVIOUS_CACHE_FILENAME)


def _previous_sig_cache_path(cache_dir=None):
    return os.path.join(os.path.dirname(_cache_path(cache_dir)), PREVIOUS_SIG_CACHE_FILENAME)


def _signed_seen_path(cache_dir=None):
    base = cache_dir if cache_dir else os.path.join(
        os.path.expanduser("~"), ".cache", "repo-forensics")
    return os.path.join(base, SIGNED_SEEN_FILENAME)


def _mark_signed_seen(cache_dir=None):
    """Record that a valid signed feed was observed here at least once."""
    try:
        path = _signed_seen_path(cache_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _atomic_write_bytes(path, b"1", mode=0o600)
    except OSError:
        pass


def _has_seen_signed(cache_dir=None):
    return os.path.isfile(_signed_seen_path(cache_dir))


def _atomic_write_bytes(path, data, mode=0o600):
    """Atomic binary write (temp + fsync + rename) for the detached signature."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".sig")
    try:
        f = os.fdopen(fd, "wb")
    except BaseException:
        # fdopen never took ownership of fd: close it ourselves before unlink.
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        with f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _pair_signature_state(cache_path, sig_path):
    """Verify one on-disk IOC payload/signature pair."""
    if not (os.path.isfile(cache_path) and os.path.isfile(sig_path)):
        return None
    try:
        with open(cache_path, "rb") as f:
            raw = f.read()
        with open(sig_path, "rb") as f:
            sig = f.read()
    except OSError:
        return False
    return _verify_ioc_bytes(raw, sig)


def _restore_previous_signed_cache(cache_dir=None):
    """Restore the last complete signed generation after an interrupted commit."""
    previous_cache = _previous_cache_path(cache_dir)
    previous_sig = _previous_sig_cache_path(cache_dir)
    if _pair_signature_state(previous_cache, previous_sig) is not True:
        return False
    try:
        raw = open(previous_cache, "rb").read()
        sig = open(previous_sig, "rb").read()
        # Keep the previous files intact until both authoritative writes finish,
        # so another crash during recovery remains recoverable.
        _atomic_write_bytes(_cache_path(cache_dir), raw, mode=0o600)
        _atomic_write_bytes(_sig_cache_path(cache_dir), sig, mode=0o600)
        return True
    except OSError:
        return False


def _verify_ioc_cache_signature(cache_dir=None):
    """Verify the cached IOC feed's detached signature over the EXACT bytes of
    the .json cache that get parsed and trusted (KTD-11 verify-on-load). The
    signature now protects the SAME byte stream the read path loads, closing the
    gap where a separate .raw was signed but the .json was the file trusted.

    Returns:
        True  -> a valid signature is present over the .json cache (trusted)
        False -> a .sig is present but verification over the .json bytes failed
                 (tampered/invalid)
        None  -> no .sig present (genuinely-legacy unsigned feed; caller decides
                 whether that is acceptable via the signed-seen sentinel)
    """
    cache_path = _cache_path(cache_dir)
    sig_path = _sig_cache_path(cache_dir)
    state = _pair_signature_state(cache_path, sig_path)
    if state is False and _restore_previous_signed_cache(cache_dir):
        state = _pair_signature_state(cache_path, sig_path)
    return state


def _verify_ioc_bytes(raw, sig):
    """Verify freshly downloaded bytes before they can replace trusted cache."""
    if not isinstance(raw, (bytes, bytearray)) or not isinstance(sig, (bytes, bytearray)):
        return False
    try:
        import _ed25519
        return bool(_ed25519.verify(bytes(sig), bytes(raw),
                                    bytes.fromhex(IOC_FEED_PUBKEY_HEX)))
    except Exception:
        return False


def _load_cache(cache_dir=None, ttl_hours=None):
    """Load cached IOCs if fresh enough.

    ttl_hours overrides the module-level _IOC_CACHE_TTL_HOURS default.
    Returns None when the cache is absent, unreadable, or stale.

    Freshness source: the embedded `_cached_at` when present (legacy/unsigned
    caches), else the file mtime. Signed caches persist the EXACT signed bytes,
    which cannot carry a post-hoc `_cached_at` wrapper, so mtime is authoritative
    there.
    """
    # A power loss between the two authoritative renames can leave a mismatched
    # pair. Recover the prior complete generation before parsing trusted bytes.
    if _pair_signature_state(_cache_path(cache_dir), _sig_cache_path(cache_dir)) is False:
        _restore_previous_signed_cache(cache_dir)
    path = _cache_path(cache_dir)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        # Check freshness. A non-numeric or future-dated _cached_at is treated as
        # untrustworthy: an attacker with write access could otherwise set it just
        # behind "now" to make a stale, poisoned cache look perpetually fresh.
        # Fall back to the kernel-managed mtime in those cases (mirrors vuln_feed).
        now = time.time()
        cached_at = data.get('_cached_at')
        if not isinstance(cached_at, (int, float)) or cached_at > now + 300:
            try:
                cached_at = os.path.getmtime(path)
            except OSError:
                return None
        age_hours = (now - cached_at) / 3600
        max_age = ttl_hours if ttl_hours is not None else _IOC_CACHE_TTL_HOURS
        if age_hours > max_age:
            return None
        return data
    except (json.JSONDecodeError, OSError):
        return None


def _save_cache(data, cache_dir=None):
    """Save IOCs to local cache atomically. Delegates to forensics_core
    for the shared atomic-write implementation (temp + fsync + os.replace,
    mode 0o600, uuid-suffixed temp file)."""
    if not isinstance(data, dict):
        return
    import forensics_core
    to_save = dict(data)
    to_save['_cached_at'] = time.time()
    forensics_core.atomic_write_json(_cache_path(cache_dir), to_save, mode=0o600)


# Hardened fetcher: HTTPS only, hostname allowlist, strict size cap.
# Prevents SSRF / exfiltration via --feed-url on a shared CI runner.
_IOC_HOST_ALLOWLIST = {
    "raw.githubusercontent.com",
    "github.com",
    "objects.githubusercontent.com",
}
_IOC_MAX_BYTES = 5_000_000  # 5 MB


def _validate_feed_url(url):
    """Return True iff url is https:// and host is in the allowlist."""
    if not isinstance(url, str) or not url.startswith("https://"):
        return False
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
    except (ValueError, TypeError):
        return False
    return host in _IOC_HOST_ALLOWLIST


def _fetch_url_bytes(url, max_bytes):
    """Fetch `url` returning raw bytes (capped) or None. https + allowlist only."""
    if not _validate_feed_url(url):
        print(f"[!] IOC feed URL rejected (non-https or host not allowlisted): {url!r}",
              file=sys.stderr)
        return None
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url, headers={'User-Agent': 'repo-forensics/v2'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                print(f"[!] IOC feed exceeded {max_bytes} byte cap", file=sys.stderr)
                return None
            return raw
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"[!] IOC fetch failed: {e}", file=sys.stderr)
        return None


def fetch_remote_iocs(feed_url=None, _return_raw=False):
    """Fetch IOCs from remote feed. Returns dict or None on failure.

    Security: URL must be HTTPS and point to an allowlisted host. Any
    file://, http://, or unknown-host URL is rejected before the socket
    is opened. Response is byte-capped and JSON-parsed before use.

    When `_return_raw` is True, returns (dict, raw_bytes) so update_iocs can
    persist the EXACT signed bytes for verify-on-load (KTD-11).
    """
    url = feed_url or IOC_FEED_URL
    raw = _fetch_url_bytes(url, _IOC_MAX_BYTES)
    if raw is None:
        return (None, None) if _return_raw else None
    try:
        data = json.loads(raw.decode('utf-8'))
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[!] IOC fetch failed: {e}", file=sys.stderr)
        return (None, None) if _return_raw else None
    return (data, raw) if _return_raw else data


def _save_signed_cache(raw_bytes, sig_bytes, cache_dir=None):
    """Persist the EXACT signed feed bytes AS the .json cache (binary write, no
    decode/encode round-trip) plus the detached signature, so verify-on-load
    re-checks the signature over the very bytes that get parsed and trusted.

    The .json cache becomes byte-identical to the signed payload — this is the
    single-file collapse that closes the "sign one file, trust another" gap.
    """
    if raw_bytes is None or sig_bytes is None:
        return
    cache_path = _cache_path(cache_dir)
    sig_path = _sig_cache_path(cache_dir)

    # Snapshot the current *verified pair* before touching either authoritative
    # file. Read each file ONCE and verify those exact bytes, so the retained
    # recovery generation can never be a TOCTOU-swapped unsigned payload (the
    # old verify-then-reopen left a window to substitute the backup bytes).
    try:
        with open(cache_path, "rb") as f:
            current_raw = f.read()
        with open(sig_path, "rb") as f:
            current_sig = f.read()
    except OSError:
        current_raw = current_sig = None
    if (current_raw is not None and current_sig is not None
            and _verify_ioc_bytes(current_raw, current_sig) is True):
        _atomic_write_bytes(_previous_cache_path(cache_dir), current_raw, mode=0o600)
        _atomic_write_bytes(_previous_sig_cache_path(cache_dir), current_sig, mode=0o600)

    try:
        _atomic_write_bytes(cache_path, bytes(raw_bytes), mode=0o600)
        _atomic_write_bytes(sig_path, sig_bytes, mode=0o600)
    except OSError:
        _restore_previous_signed_cache(cache_dir)
        raise
    _mark_signed_seen(cache_dir)


def update_iocs(feed_url=None, cache_dir=None, sig_url=None):
    """Pull latest IOCs from remote feed and cache locally.
    Returns (success: bool, message: str).

    Also fetches and verifies the detached `.sig` before replacing any cache.
    Missing/invalid signatures fail closed and preserve the last known-good
    cache; the aggregate refresher must never call untrusted bytes "fresh".
    """
    data, raw = fetch_remote_iocs(feed_url, _return_raw=True)
    if data is None:
        return False, "Failed to fetch IOCs from remote feed (using hardcoded fallback)"

    # Fetch the detached signature. When present, persist the EXACT signed bytes
    # AS the .json cache so verify-on-load checks the same bytes it parses.
    sig = _fetch_url_bytes(sig_url or (feed_url or IOC_FEED_URL) + ".sig",
                           _SIG_MAX_BYTES)
    if sig is None or raw is None:
        return False, "IOC signature missing (last known-good cache preserved)"
    if not _verify_ioc_bytes(raw, sig):
        return False, "IOC signature invalid (last known-good cache preserved)"
    required_lists = ("c2_ips", "malicious_domains", "malicious_npm_packages",
                      "malicious_pypi_packages")
    if (not isinstance(data, dict) or not isinstance(data.get("version"), str)
            or any(not isinstance(data.get(key), list) for key in required_lists)
            or sum(len(data[key]) for key in required_lists) == 0):
        return False, "IOC feed structure invalid (last known-good cache preserved)"
    _save_signed_cache(raw, sig, cache_dir)
    version = data.get('version', 'unknown')
    c2_count = len(data.get('c2_ips', []))
    domain_count = len(data.get('malicious_domains', []))
    pkg_count = len(data.get('malicious_npm_packages', [])) + len(data.get('malicious_pypi_packages', []))
    return True, f"IOCs updated: v{version} ({c2_count} C2 IPs, {domain_count} domains, {pkg_count} packages)"


def get_iocs(cache_dir=None):
    """Get merged IOC set: shipped JSON + cached remote feed + hardcoded fallback.

    Returns dict with:
      - c2_ips: list[str]
      - malicious_domains: list[str]
      - malicious_npm: set[str] (includes both hardcoded and wildcard-version
        packages from the shipped compromised_versions.json)
      - malicious_pypi: set[str]
      - malicious_pth_files: set[str]
      - compromised_versions: dict[str, dict[str, str]] keyed by lower-case
        package name -> {version_string: campaign_id}. Only populated from
        the shipped JSON file; the hardcoded sets do not carry version info.
      - _ioc_degraded: bool — True when no fresh remote-feed cache is available.
        Callers should surface a warning to the user when this is True, since
        threat intelligence is limited to hardcoded fallback data only.
    """
    cached = _load_cache(cache_dir)

    # Track whether we are operating with a fresh remote feed. When degraded,
    # callers should emit a warning: new IOCs published since the last
    # successful update will not be detected.
    ioc_degraded = cached is None

    # KTD-11 verify-on-load: the detached .sig is verified over the EXACT bytes
    # of the .json cache that get parsed below (single byte stream — no separate
    # .raw). A cached feed whose .sig FAILS verification, OR whose .sig is MISSING
    # on an install that has previously seen a signature, is treated as degraded
    # (the intelligence channel may be poisoned or the .sig stripped, e.g. an
    # attacker editing the .json or deleting a malicious domain). Hardcoded
    # fallback IOCs still apply regardless.
    #
    # A sig that is simply absent on a genuinely-legacy install (one that has
    # NEVER seen a signature) is the backward-compat path — the cache still
    # merges. But a sig that USED to be present and is now gone must degrade.
    sig_state = _verify_ioc_cache_signature(cache_dir) if cached else None
    if sig_state is True and not _has_seen_signed(cache_dir):
        # First valid verification on this install: arm the strip-detection
        # sentinel so a later .sig removal degrades instead of silently trusting.
        _mark_signed_seen(cache_dir)
    sig_stripped = (sig_state is None and cached is not None
                    and _has_seen_signed(cache_dir))
    ioc_signature_invalid = (sig_state is False) or sig_stripped
    if ioc_signature_invalid:
        why = ("signature MISSING (previously signed; .sig stripped)"
               if sig_stripped else "signature INVALID")
        print(f"[!] Cached IOC feed {why} — intelligence channel "
              "untrusted (using hardcoded fallback IOCs).", file=sys.stderr)

    # Start with hardcoded
    result = {
        'c2_ips': list(HARDCODED_C2_IPS),
        'malicious_domains': list(HARDCODED_MALICIOUS_DOMAINS),
        'malicious_npm': set(HARDCODED_MALICIOUS_NPM),
        'malicious_pypi': set(HARDCODED_MALICIOUS_PYPI),
        'malicious_pth_files': set(HARDCODED_MALICIOUS_PTH_FILES),
        'compromised_versions': {},
        '_ioc_degraded': ioc_degraded or ioc_signature_invalid,
        # Distinct sub-flag so callers can emit the IOC-signature-specific
        # message (vs the plain "no fresh cache" degraded message).
        '_ioc_signature_invalid': ioc_signature_invalid,
    }

    # Merge remote IOCs if available. When the signature is INVALID we refuse to
    # trust the cached feed contents (an attacker could have DELETED a malicious
    # domain); only hardcoded IOCs are kept. A merely-absent signature (legacy)
    # still merges, preserving old-feed behavior.
    if cached and not ioc_signature_invalid:
        result['c2_ips'] = list(set(result['c2_ips'] + cached.get('c2_ips', [])))
        result['malicious_domains'] = list(set(result['malicious_domains'] + cached.get('malicious_domains', [])))
        result['malicious_npm'].update(cached.get('malicious_npm_packages', []))
        result['malicious_pypi'].update(cached.get('malicious_pypi_packages', []))

    # Merge shipped compromised_versions.json
    version_map, entirely_malicious, _raw = _get_compromised_versions()
    # Wildcard-version packages become name-only IOCs in the npm set
    result['malicious_npm'].update(entirely_malicious)
    # Version-pinned IOCs get their own key
    result['compromised_versions'] = version_map

    return result


def main():
    """CLI: python3 ioc_manager.py --update [--feed-url URL] [--cache-dir DIR]"""
    import argparse
    parser = argparse.ArgumentParser(description="repo-forensics IOC Manager")
    parser.add_argument('--update', action='store_true', help="Fetch latest IOCs from remote feed")
    parser.add_argument('--feed-url', default=None, help="Custom IOC feed URL")
    parser.add_argument('--cache-dir', default=None, help="Cache directory")
    parser.add_argument('--show', action='store_true', help="Show current IOC counts")
    args = parser.parse_args()

    if args.update:
        success, msg = update_iocs(args.feed_url, args.cache_dir)
        print(f"{'[+]' if success else '[!]'} {msg}")
        sys.exit(0 if success else 1)

    if args.show:
        iocs = get_iocs(args.cache_dir)
        print(f"C2 IPs: {len(iocs['c2_ips'])}")
        print(f"Malicious domains: {len(iocs['malicious_domains'])}")
        print(f"Malicious NPM: {len(iocs['malicious_npm'])}")
        print(f"Malicious PyPI: {len(iocs['malicious_pypi'])}")
        print(f"Malicious .pth files: {len(iocs.get('malicious_pth_files', set()))}")
        cached = _load_cache(args.cache_dir)
        if cached:
            age = (time.time() - cached.get('_cached_at', 0)) / 3600
            print(f"Cache age: {age:.1f}h (max {CACHE_MAX_AGE_HOURS}h)")
        else:
            print("Cache: none (using hardcoded only)")
        sys.exit(0)

    parser.print_help()


if __name__ == "__main__":
    main()
