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
import time

# Default IOC feed URL (GitHub raw from repo-forensics releases)
IOC_FEED_URL = "https://raw.githubusercontent.com/alexgreensh/repo-forensics/main/iocs/latest.json"

CACHE_FILENAME = ".forensics-iocs.json"
CACHE_MAX_AGE_HOURS = 24

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
    "checkmarx.cx",            # TeamPCP Wave 3 C2 domain (April 2026)
    "audit.checkmarx.cx",      # TeamPCP Wave 3 exfil endpoint (April 2026)
    "scan.aquasecurity.org",   # Trivy compromise exfil domain (March 2026)
    "npnjs.com",               # npm maintainer phishing (Chalk compromise, 2025)
    "npmjs.help",              # npm maintainer phishing (2025)
    "files.pypihosted.org",    # Fake PyPI mirror (top.gg attack, 2024)
]

HARDCODED_MALICIOUS_NPM = {
    "rimarf", "yarsg", "suport-color", "naniod", "opencraw",
    "claud-code", "cloude-code", "cloude", "mcp-cliient", "mcp-serever",
    "anthropic-sdk-node", "claude-code-cli", "clawclient",
    "plain-crypto-js",  # Axios supply chain RAT dropper (March 2026)
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


def _load_cache(cache_dir=None):
    """Load cached IOCs if fresh enough."""
    path = _cache_path(cache_dir)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        # Check freshness
        cached_at = data.get('_cached_at', 0)
        age_hours = (time.time() - cached_at) / 3600
        if age_hours > CACHE_MAX_AGE_HOURS:
            return None
        return data
    except (json.JSONDecodeError, OSError):
        return None


def _save_cache(data, cache_dir=None):
    """Save IOCs to local cache. Does not mutate the input dict."""
    if not isinstance(data, dict):
        return
    path = _cache_path(cache_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    to_save = dict(data)
    to_save['_cached_at'] = time.time()
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(to_save, f, indent=2)


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


def fetch_remote_iocs(feed_url=None):
    """Fetch IOCs from remote feed. Returns dict or None on failure.

    Security: URL must be HTTPS and point to an allowlisted host. Any
    file://, http://, or unknown-host URL is rejected before the socket
    is opened. Response is byte-capped and JSON-parsed before use.
    """
    url = feed_url or IOC_FEED_URL
    if not _validate_feed_url(url):
        print(f"[!] IOC feed URL rejected (non-https or host not allowlisted): {url!r}",
              file=sys.stderr)
        return None
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url, headers={'User-Agent': 'repo-forensics/v2'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read(_IOC_MAX_BYTES + 1)
            if len(raw) > _IOC_MAX_BYTES:
                print(f"[!] IOC feed exceeded {_IOC_MAX_BYTES} byte cap", file=sys.stderr)
                return None
            data = json.loads(raw.decode('utf-8'))
        return data
    except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError) as e:
        print(f"[!] IOC fetch failed: {e}", file=sys.stderr)
        return None


def update_iocs(feed_url=None, cache_dir=None):
    """Pull latest IOCs from remote feed and cache locally.
    Returns (success: bool, message: str)."""
    data = fetch_remote_iocs(feed_url)
    if data is None:
        return False, "Failed to fetch IOCs from remote feed (using hardcoded fallback)"

    _save_cache(data, cache_dir)
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
    """
    cached = _load_cache(cache_dir)

    # Start with hardcoded
    result = {
        'c2_ips': list(HARDCODED_C2_IPS),
        'malicious_domains': list(HARDCODED_MALICIOUS_DOMAINS),
        'malicious_npm': set(HARDCODED_MALICIOUS_NPM),
        'malicious_pypi': set(HARDCODED_MALICIOUS_PYPI),
        'malicious_pth_files': set(HARDCODED_MALICIOUS_PTH_FILES),
        'compromised_versions': {},
    }

    # Merge remote IOCs if available
    if cached:
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
