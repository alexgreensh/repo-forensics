"""Tests for ioc_manager.py.

Architecture reviewer (2026-04-05 plan review) flagged that ioc_manager.py
has zero direct test coverage despite being the single source of truth for
IOC data across all scanners. This file closes that gap.

Covers:
  - Hardcoded IOC set availability (fallback path)
  - Cache file round-trip (_save_cache / _load_cache)
  - Cache staleness (TTL handling)
  - fetch_remote_iocs error paths (no network, malformed JSON)
  - get_iocs() merge semantics
  - Shipped compromised_versions.json loader
  - Schema version gate
  - Wildcard merging into malicious_npm
"""

import json
import os
import time
import pytest

import ioc_manager


# ---------------------------------------------------------------------------
# Hardcoded IOC availability (fallback path)
# ---------------------------------------------------------------------------


class TestHardcodedFallback:
    """These sets must always be available even when no remote feed or
    shipped file is reachable. They're the last line of defense."""

    def test_hardcoded_c2_ips_not_empty(self):
        assert len(ioc_manager.HARDCODED_C2_IPS) > 0

    def test_hardcoded_malicious_npm_not_empty(self):
        assert len(ioc_manager.HARDCODED_MALICIOUS_NPM) > 0

    def test_hardcoded_malicious_pypi_not_empty(self):
        assert len(ioc_manager.HARDCODED_MALICIOUS_PYPI) > 0

    def test_hardcoded_malicious_domains_not_empty(self):
        assert len(ioc_manager.HARDCODED_MALICIOUS_DOMAINS) > 0

    def test_hardcoded_claud_code_present(self):
        """claud-code typosquat has been in the IOC list since v1."""
        assert "claud-code" in ioc_manager.HARDCODED_MALICIOUS_NPM

    def test_hardcoded_anthopic_present(self):
        assert "anthopic" in ioc_manager.HARDCODED_MALICIOUS_PYPI


# ---------------------------------------------------------------------------
# get_iocs() merge semantics
# ---------------------------------------------------------------------------


class TestGetIocs:
    def test_returns_all_expected_keys(self, tmp_path):
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        expected = {
            "c2_ips",
            "malicious_domains",
            "malicious_npm",
            "malicious_pypi",
            "malicious_pth_files",
            "compromised_versions",
        }
        assert expected.issubset(set(iocs.keys()))

    def test_malicious_npm_is_set(self, tmp_path):
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert isinstance(iocs["malicious_npm"], set)

    def test_compromised_versions_is_dict(self, tmp_path):
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert isinstance(iocs["compromised_versions"], dict)

    def test_returns_hardcoded_when_no_cache(self, tmp_path):
        """With an empty cache_dir, hardcoded fallback is used."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "claud-code" in iocs["malicious_npm"]

    def test_merges_cache_with_hardcoded(self, tmp_path):
        """Cached remote IOCs should be additive, not replace hardcoded."""
        cache = tmp_path / ioc_manager.CACHE_FILENAME
        cache.write_text(json.dumps({
            "malicious_npm_packages": ["newly-discovered-evil"],
            "_cached_at": time.time(),
        }))
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "claud-code" in iocs["malicious_npm"]  # hardcoded preserved
        assert "newly-discovered-evil" in iocs["malicious_npm"]  # remote added

    def test_includes_shipped_compromised_versions(self, tmp_path):
        """Marc Gadsdon's issue #5 fix: shipped JSON must be loaded."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "chalk" in iocs["compromised_versions"]
        assert "5.6.1" in iocs["compromised_versions"]["chalk"]

    def test_wildcard_packages_merged_into_malicious_npm(self, tmp_path):
        """Entirely-malicious packages (version=['*']) join malicious_npm set."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "darkslash" in iocs["malicious_npm"]  # ghost campaign
        assert "graphalgo" in iocs["malicious_npm"]  # Lazarus

    def test_version_pinned_not_in_malicious_npm(self, tmp_path):
        """Version-pinned packages stay in compromised_versions, not merged
        into the name-only set (otherwise clean versions would be flagged)."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        # chalk 5.6.1 is compromised but chalk is a legitimate package name
        assert "chalk" not in iocs["malicious_npm"]


# ---------------------------------------------------------------------------
# Cache round-trip (_save_cache / _load_cache)
# ---------------------------------------------------------------------------


class TestCacheRoundTrip:
    def test_save_load_round_trip(self, tmp_path):
        data = {
            "c2_ips": ["1.2.3.4"],
            "malicious_domains": ["evil.com"],
            "version": "test",
        }
        ioc_manager._save_cache(data, cache_dir=str(tmp_path))
        loaded = ioc_manager._load_cache(cache_dir=str(tmp_path))
        assert loaded is not None
        assert loaded["c2_ips"] == ["1.2.3.4"]
        assert loaded["version"] == "test"

    def test_save_does_not_mutate_input(self, tmp_path):
        """_save_cache must not add _cached_at to the caller's dict."""
        data = {"version": "x"}
        ioc_manager._save_cache(data, cache_dir=str(tmp_path))
        assert "_cached_at" not in data

    def test_load_returns_none_when_missing(self, tmp_path):
        assert ioc_manager._load_cache(cache_dir=str(tmp_path)) is None

    def test_load_returns_none_on_malformed_json(self, tmp_path):
        (tmp_path / ioc_manager.CACHE_FILENAME).write_text("not json{{{")
        assert ioc_manager._load_cache(cache_dir=str(tmp_path)) is None

    def test_stale_cache_returns_none(self, tmp_path):
        """Cache older than CACHE_MAX_AGE_HOURS must be treated as absent."""
        stale_time = time.time() - (ioc_manager.CACHE_MAX_AGE_HOURS + 1) * 3600
        cache = tmp_path / ioc_manager.CACHE_FILENAME
        cache.write_text(json.dumps({
            "version": "stale",
            "_cached_at": stale_time,
        }))
        assert ioc_manager._load_cache(cache_dir=str(tmp_path)) is None

    def test_fresh_cache_loads(self, tmp_path):
        cache = tmp_path / ioc_manager.CACHE_FILENAME
        cache.write_text(json.dumps({
            "version": "fresh",
            "_cached_at": time.time(),
        }))
        loaded = ioc_manager._load_cache(cache_dir=str(tmp_path))
        assert loaded is not None
        assert loaded["version"] == "fresh"


# ---------------------------------------------------------------------------
# fetch_remote_iocs error paths (do not touch the network in CI)
# ---------------------------------------------------------------------------


class TestFetchRemoteIocsErrors:
    def test_unreachable_url_returns_none(self):
        """An unreachable URL should return None, not raise."""
        result = ioc_manager.fetch_remote_iocs(
            feed_url="http://localhost:1/nonexistent"
        )
        assert result is None


# ---------------------------------------------------------------------------
# Shipped compromised_versions.json loader
# ---------------------------------------------------------------------------


class TestCompromisedVersionsLoader:
    def setup_method(self):
        """Reset the module-level cache before each test."""
        ioc_manager._reset_compromised_versions_cache()

    def test_loads_shipped_file(self):
        version_map, entirely_malicious, raw = (
            ioc_manager._load_compromised_versions_file()
        )
        assert len(version_map) > 0
        assert len(entirely_malicious) > 0
        assert raw is not None

    def test_chalk_is_version_pinned(self):
        version_map, _, _ = ioc_manager._load_compromised_versions_file()
        assert "chalk" in version_map
        assert "5.6.1" in version_map["chalk"]

    def test_darkslash_is_entirely_malicious(self):
        _, entirely_malicious, _ = ioc_manager._load_compromised_versions_file()
        assert "darkslash" in entirely_malicious

    def test_campaign_id_recorded_for_version_pinned(self):
        version_map, _, _ = ioc_manager._load_compromised_versions_file()
        assert version_map["chalk"]["5.6.1"] == "chalk_debug_sep_2025"

    def test_lowercase_keys(self):
        """All package keys should be lower-cased for case-insensitive lookup."""
        version_map, entirely_malicious, _ = (
            ioc_manager._load_compromised_versions_file()
        )
        for k in version_map.keys():
            assert k == k.lower()
        for k in entirely_malicious:
            assert k == k.lower()

    def test_missing_file_returns_empty(self, tmp_path):
        """Soft failure: missing file should not raise."""
        version_map, entirely_malicious, raw = (
            ioc_manager._load_compromised_versions_file(
                path=str(tmp_path / "nonexistent.json")
            )
        )
        assert version_map == {}
        assert entirely_malicious == set()
        assert raw is None

    def test_malformed_file_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json{{{")
        version_map, entirely_malicious, raw = (
            ioc_manager._load_compromised_versions_file(path=str(bad))
        )
        assert version_map == {}
        assert entirely_malicious == set()

    def test_schema_version_mismatch_rejected(self, tmp_path):
        """Incompatible schema version: refuse to load rather than misinterpret."""
        future = tmp_path / "future.json"
        future.write_text(json.dumps({
            "schema_version": "99.0",
            "campaigns": {
                "test": {
                    "packages": {"evil": ["1.0.0"]}
                }
            }
        }))
        version_map, entirely_malicious, _ = (
            ioc_manager._load_compromised_versions_file(path=str(future))
        )
        assert version_map == {}
        assert entirely_malicious == set()

    def test_missing_campaigns_field_returns_empty(self, tmp_path):
        no_campaigns = tmp_path / "no_campaigns.json"
        no_campaigns.write_text(json.dumps({"schema_version": "1.0"}))
        version_map, entirely_malicious, raw = (
            ioc_manager._load_compromised_versions_file(path=str(no_campaigns))
        )
        assert version_map == {}
        assert entirely_malicious == set()
        assert raw is not None  # file was parseable

    def test_malformed_campaign_skipped(self, tmp_path):
        """A single bad campaign entry should not abort the whole load."""
        mixed = tmp_path / "mixed.json"
        mixed.write_text(json.dumps({
            "schema_version": "1.0",
            "campaigns": {
                "bad": "this is not a dict",
                "good": {"packages": {"evil-pkg": ["1.0.0"]}},
            },
        }))
        version_map, _, _ = ioc_manager._load_compromised_versions_file(
            path=str(mixed)
        )
        # Bad campaign skipped, good campaign loaded
        assert "evil-pkg" in version_map

    def test_cache_memoizes_result(self):
        """Second call should return same object as first (cache hit)."""
        first = ioc_manager._get_compromised_versions()
        second = ioc_manager._get_compromised_versions()
        assert first is second

    def test_reset_cache_forces_reload(self):
        first = ioc_manager._get_compromised_versions()
        ioc_manager._reset_compromised_versions_cache()
        second = ioc_manager._get_compromised_versions()
        # Different objects after reset, but equal content
        assert first is not second
        assert first[0].keys() == second[0].keys()
