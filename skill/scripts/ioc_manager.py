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

# --- Hardcoded IOCs (fallback, always available) ---

HARDCODED_C2_IPS = [
    "91.92.242.30", "54.91.154.110", "157.245.55.238",
    "45.77.240.42", "104.248.30.47", "159.65.147.111",
]

HARDCODED_MALICIOUS_DOMAINS = [
    "install.app-distribution.net",
    "dl.dropboxusercontent.com",
    "raw.githubusercontent.com",
    "socifiapp.com",
    "hackmoltrepeat.com",
    "giftshop.club",
    "glot.io",
    "api.telegram.org/bot",
    "discord.com/api/webhooks",
    "hooks.slack.com/services",
    # liteLLM supply chain attack C2 (March 2026)
    "eo1n0jq9qgggt.m.pipedream.net",
]

HARDCODED_MALICIOUS_NPM = {
    "rimarf", "yarsg", "suport-color", "naniod", "opencraw",
    "claud-code", "cloude-code", "cloude", "mcp-cliient", "mcp-serever",
    "anthropic-sdk-node", "claude-code-cli", "clawclient",
}

HARDCODED_MALICIOUS_PYPI = {
    "anthopic", "antrhopic", "claudes", "mcp-python-sdk",
}

HARDCODED_MALICIOUS_PTH_FILES = {
    "litellm_init.pth", "litellm-init.pth", "litellm.pth",
    "llm_init.pth", "init_hook.pth", "startup.pth",
}


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
    path = _cache_path(cache_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    to_save = dict(data)
    to_save['_cached_at'] = time.time()
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(to_save, f, indent=2)


def fetch_remote_iocs(feed_url=None):
    """Fetch IOCs from remote feed. Returns dict or None on failure."""
    url = feed_url or IOC_FEED_URL
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url, headers={'User-Agent': 'repo-forensics/v2'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read(5_000_000).decode('utf-8'))  # 5MB max
        return data
    except Exception:
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
    """Get merged IOC set: cached remote IOCs + hardcoded fallback.
    Returns dict with: c2_ips, malicious_domains, malicious_npm, malicious_pypi."""
    cached = _load_cache(cache_dir)

    # Start with hardcoded
    result = {
        'c2_ips': list(HARDCODED_C2_IPS),
        'malicious_domains': list(HARDCODED_MALICIOUS_DOMAINS),
        'malicious_npm': set(HARDCODED_MALICIOUS_NPM),
        'malicious_pypi': set(HARDCODED_MALICIOUS_PYPI),
        'malicious_pth_files': set(HARDCODED_MALICIOUS_PTH_FILES),
    }

    # Merge remote IOCs if available
    if cached:
        result['c2_ips'] = list(set(result['c2_ips'] + cached.get('c2_ips', [])))
        result['malicious_domains'] = list(set(result['malicious_domains'] + cached.get('malicious_domains', [])))
        result['malicious_npm'].update(cached.get('malicious_npm_packages', []))
        result['malicious_pypi'].update(cached.get('malicious_pypi_packages', []))

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
