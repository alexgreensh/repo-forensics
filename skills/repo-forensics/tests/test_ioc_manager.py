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


class TestFeedURLHardening:
    """ADV-001: fetch_remote_iocs must reject non-https and non-allowlisted hosts."""

    def test_https_allowlisted_host_accepted(self):
        assert ioc_manager._validate_feed_url(
            "https://raw.githubusercontent.com/x/y/main/iocs.json"
        ) is True

    def test_http_rejected(self):
        assert ioc_manager._validate_feed_url(
            "http://raw.githubusercontent.com/x/y/main/iocs.json"
        ) is False

    def test_file_scheme_rejected(self):
        assert ioc_manager._validate_feed_url("file:///etc/passwd") is False

    def test_ftp_rejected(self):
        assert ioc_manager._validate_feed_url("ftp://example.com/iocs.json") is False

    def test_unknown_host_rejected(self):
        assert ioc_manager._validate_feed_url("https://evil.com/iocs.json") is False

    def test_private_ip_rejected(self):
        assert ioc_manager._validate_feed_url("https://127.0.0.1/iocs.json") is False

    def test_empty_url_rejected(self):
        assert ioc_manager._validate_feed_url("") is False
        assert ioc_manager._validate_feed_url(None) is False

    def test_fetch_rejects_bad_url_without_network(self, monkeypatch):
        # Ensure no socket is attempted
        def panic(*a, **kw):
            raise AssertionError("urlopen must not be called for rejected URL")
        import urllib.request
        monkeypatch.setattr(urllib.request, "urlopen", panic)
        assert ioc_manager.fetch_remote_iocs("http://evil.com/iocs.json") is None


# ---------------------------------------------------------------------------
# May 2026 IOC additions (U4 update)
# ---------------------------------------------------------------------------


class TestMay2026IocAdditions:
    """Verify that all IOCs added in the U4 May 2026 update are present."""

    def test_megalodon_c2_ip_in_hardcoded_list(self):
        """216.126.225.129 (Megalodon CI campaign, May 2026) must be present."""
        assert "216.126.225.129" in ioc_manager.HARDCODED_C2_IPS

    def test_canisterworm_icp_domain_in_hardcoded_list(self):
        """ICP blockchain C2 domain (CanisterWorm, Apr 2026) must be present."""
        assert "cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io" in ioc_manager.HARDCODED_MALICIOUS_DOMAINS

    def test_chalk_tempalte_in_hardcoded_malicious_npm(self):
        """chalk-tempalte typosquat (Shai-Hulud copycat) must be flagged by name."""
        assert "chalk-tempalte" in ioc_manager.HARDCODED_MALICIOUS_NPM

    def test_legitimate_chalk_not_in_malicious_npm(self):
        """chalk (the real package) must NOT be in the malicious npm set — only
        specific compromised versions are tracked via compromised_versions.json."""
        assert "chalk" not in ioc_manager.HARDCODED_MALICIOUS_NPM

    def test_megalodon_c2_ip_in_get_iocs(self, tmp_path):
        """get_iocs() must surface the Megalodon C2 IP in the merged result."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "216.126.225.129" in iocs["c2_ips"]

    def test_canisterworm_domain_in_get_iocs(self, tmp_path):
        """get_iocs() must surface the ICP C2 domain in the merged result."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io" in iocs["malicious_domains"]

    def test_chalk_tempalte_in_get_iocs_malicious_npm(self, tmp_path):
        """get_iocs() malicious_npm set must include the chalk-tempalte typosquat."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "chalk-tempalte" in iocs["malicious_npm"]


# ---------------------------------------------------------------------------
# KTD-11: signed IOC feed verify-on-load (additive, offline)
# ---------------------------------------------------------------------------

import sys as _sys  # noqa: E402

_REPO_SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))), "scripts")
_sys.path.insert(0, _REPO_SCRIPTS)
import _ed25519_sign  # noqa: E402

_IOC_TEST_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
_IOC_TEST_PRIV, _IOC_TEST_PUB = _ed25519_sign.keypair(_IOC_TEST_SEED)


def _write_signed_cache(cache_dir, feed_dict, priv=_IOC_TEST_PRIV,
                        pub=_IOC_TEST_PUB, sign=True, tamper=False,
                        mark_seen=None):
    """Write a fresh IOC cache (.json) whose EXACT bytes are what the detached
    signature covers — mirroring the production single-file collapse. The .json
    that gets parsed and trusted IS the signed byte stream. Returns those bytes.

    `mark_seen` defaults to True whenever a signature is written (so the strip-
    detection sentinel is armed, matching production). Set it explicitly to
    simulate a genuinely-legacy install that has never seen a signature.
    """
    cache = os.path.join(cache_dir, ioc_manager.CACHE_FILENAME)
    # The signed cache carries NO _cached_at wrapper (can't sign a post-hoc
    # field); freshness comes from the file mtime, which is "now" on write.
    raw = json.dumps(feed_dict).encode("utf-8")
    with open(cache, "wb") as f:
        f.write(raw)
    if sign:
        sig = _ed25519_sign.sign(raw, priv, pub)
        if tamper:
            sig = bytearray(sig)
            sig[0] ^= 0x01
            sig = bytes(sig)
        with open(os.path.join(cache_dir, ioc_manager.SIG_CACHE_FILENAME), "wb") as f:
            f.write(sig)
    if mark_seen is None:
        mark_seen = sign
    if mark_seen:
        with open(os.path.join(cache_dir, ioc_manager.SIGNED_SEEN_FILENAME), "wb") as f:
            f.write(b"1")
    return raw


class TestIocSignatureVerifyOnLoad:
    """New-client behavior for the signed IOC feed; old-client behavior must be
    unaffected by the extra .sig file existing."""

    def test_valid_signature_not_degraded(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "test", "malicious_domains": ["signed-evil.com"]}
        _write_signed_cache(str(tmp_path), feed)
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_degraded"] is False
        assert iocs["_ioc_signature_invalid"] is False
        assert "signed-evil.com" in iocs["malicious_domains"]

    def test_invalid_signature_degraded_but_hardcoded_applies(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "test", "malicious_domains": ["poisoned.com"]}
        _write_signed_cache(str(tmp_path), feed, tamper=True)
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_degraded"] is True
        assert iocs["_ioc_signature_invalid"] is True
        # Cached (untrusted) feed contents are NOT merged...
        assert "poisoned.com" not in iocs["malicious_domains"]
        # ...but the hardcoded fallback IOCs still apply.
        assert "claud-code" in iocs["malicious_npm"]

    def test_missing_sig_is_legacy_not_signature_degraded(self, tmp_path, monkeypatch):
        """A cache with NO .sig (old feed / old client) keeps merging and is not
        flagged signature-invalid — backward compatible."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "test", "malicious_domains": ["legacy-evil.com"]}
        _write_signed_cache(str(tmp_path), feed, sign=False)
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_signature_invalid"] is False
        assert iocs["_ioc_degraded"] is False  # fresh JSON cache present
        assert "legacy-evil.com" in iocs["malicious_domains"]

    def test_verify_helper_states(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        # None when no raw/sig present.
        assert ioc_manager._verify_ioc_cache_signature(str(tmp_path)) is None
        feed = {"version": "v", "malicious_domains": ["e.com"]}
        _write_signed_cache(str(tmp_path), feed)
        assert ioc_manager._verify_ioc_cache_signature(str(tmp_path)) is True

    def test_extra_sig_file_does_not_break_old_path(self, tmp_path, monkeypatch):
        """The presence of the .sig file must not break the plain cache-merge
        path that old clients rely on (they never read it)."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "v", "malicious_npm_packages": ["extra-evil"]}
        _write_signed_cache(str(tmp_path), feed)
        # Simulate old client: just load the JSON cache directly.
        cached = ioc_manager._load_cache(cache_dir=str(tmp_path))
        assert cached is not None
        assert "extra-evil" in cached.get("malicious_npm_packages", [])


class TestIocUpdateAcceptance:
    def test_invalid_signature_fails_without_replacing_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        previous = b'{"version":"previous","malicious_domains":[]}'
        (tmp_path / ioc_manager.CACHE_FILENAME).write_bytes(previous)
        feed = {"version": "new", "malicious_domains": ["bad.example"]}
        raw = json.dumps(feed, sort_keys=True).encode()
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs",
                            lambda *a, **k: (feed, raw))
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", lambda *a, **k: b"x" * 64)

        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))

        assert not ok
        assert "signature invalid" in msg
        assert (tmp_path / ioc_manager.CACHE_FILENAME).read_bytes() == previous

    def test_missing_signature_fails_without_unsigned_fallback(self, tmp_path, monkeypatch):
        feed = {"version": "new", "malicious_domains": []}
        raw = json.dumps(feed).encode()
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs",
                            lambda *a, **k: (feed, raw))
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", lambda *a, **k: None)

        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))

        assert not ok
        assert "signature missing" in msg
        assert not (tmp_path / ioc_manager.CACHE_FILENAME).exists()

    def test_interrupted_pair_commit_restores_last_known_good(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        old = {"version": "old", "c2_ips": [], "malicious_domains": ["old.example"],
               "malicious_npm_packages": [], "malicious_pypi_packages": []}
        new = {"version": "new", "c2_ips": [], "malicious_domains": ["new.example"],
               "malicious_npm_packages": [], "malicious_pypi_packages": []}
        old_raw = json.dumps(old, sort_keys=True).encode()
        new_raw = json.dumps(new, sort_keys=True).encode()
        old_sig = _ed25519_sign.sign(old_raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        new_sig = _ed25519_sign.sign(new_raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        ioc_manager._save_signed_cache(old_raw, old_sig, str(tmp_path))

        real_write = ioc_manager._atomic_write_bytes
        failed = {"done": False}

        def fail_current_signature_once(path, data, mode=0o600):
            if path == ioc_manager._sig_cache_path(str(tmp_path)) and not failed["done"]:
                failed["done"] = True
                raise OSError("injected signature rename failure")
            return real_write(path, data, mode=mode)

        monkeypatch.setattr(ioc_manager, "_atomic_write_bytes", fail_current_signature_once)
        with pytest.raises(OSError, match="injected"):
            ioc_manager._save_signed_cache(new_raw, new_sig, str(tmp_path))

        assert ioc_manager._verify_ioc_cache_signature(str(tmp_path)) is True
        assert ioc_manager._load_cache(str(tmp_path))["version"] == "old"

    def test_mismatched_current_pair_recovers_previous_after_crash(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        old = {"version": "old", "c2_ips": [], "malicious_domains": [],
               "malicious_npm_packages": [], "malicious_pypi_packages": []}
        new = dict(old, version="new")
        old_raw = json.dumps(old, sort_keys=True).encode()
        new_raw = json.dumps(new, sort_keys=True).encode()
        old_sig = _ed25519_sign.sign(old_raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        new_sig = _ed25519_sign.sign(new_raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        ioc_manager._save_signed_cache(old_raw, old_sig, str(tmp_path))
        ioc_manager._save_signed_cache(new_raw, new_sig, str(tmp_path))
        # Simulate power loss after the JSON rename but before its matching sig.
        ioc_manager._atomic_write_bytes(ioc_manager._cache_path(str(tmp_path)), old_raw)

        assert ioc_manager._verify_ioc_cache_signature(str(tmp_path)) is True
        assert ioc_manager._load_cache(str(tmp_path))["version"] == "old"


# ---------------------------------------------------------------------------
# Torture-room regressions: signature must protect the TRUSTED bytes (FIX 3)
# ---------------------------------------------------------------------------

class TestIocSignatureBindsTrustedBytes:
    """The .sig must verify over the SAME .json bytes that get parsed and
    trusted. A same-user attacker editing the .json must be caught, and a
    previously-signed install whose .sig is later stripped must degrade."""

    def test_editing_trusted_json_is_caught(self, tmp_path, monkeypatch):
        """Edit the .json that get_iocs actually parses; signature now covers
        those very bytes, so verification fails and the poisoned edit is NOT
        trusted (the old dual-file scheme verified a different file)."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "v", "malicious_domains": ["real-evil.com"]}
        _write_signed_cache(str(tmp_path), feed)
        # Attacker edits the TRUSTED .json in place: removes a known-malicious
        # domain (defanging) and injects a benign-looking allowlist entry.
        cache = os.path.join(str(tmp_path), ioc_manager.CACHE_FILENAME)
        with open(cache, "wb") as f:
            f.write(json.dumps({"version": "v", "malicious_domains": []}).encode())
        # Signature no longer matches the edited bytes -> invalid -> degraded.
        assert ioc_manager._verify_ioc_cache_signature(str(tmp_path)) is False
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_signature_invalid"] is True
        assert iocs["_ioc_degraded"] is True
        # The attacker-edited (untrusted) feed contents are not merged; only the
        # hardcoded fallback survives.
        assert "real-evil.com" not in iocs["malicious_domains"]
        assert "claud-code" in iocs["malicious_npm"]

    def test_stripped_signature_on_signed_install_degrades(self, tmp_path, monkeypatch):
        """A .sig that USED to be present and is now gone must degrade rather
        than silently trust the unsigned cache."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "v", "malicious_domains": ["was-signed.com"]}
        _write_signed_cache(str(tmp_path), feed)  # arms the signed-seen sentinel
        # Attacker strips the signature, leaving the (now unsigned) cache.
        os.unlink(os.path.join(str(tmp_path), ioc_manager.SIG_CACHE_FILENAME))
        assert ioc_manager._has_seen_signed(str(tmp_path)) is True
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_signature_invalid"] is True
        assert iocs["_ioc_degraded"] is True
        assert "was-signed.com" not in iocs["malicious_domains"]

    def test_genuinely_legacy_unsigned_install_still_trusts(self, tmp_path, monkeypatch):
        """An install that has NEVER seen a signature (no sentinel) keeps the
        backward-compatible merge for a plain unsigned cache."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "v", "malicious_domains": ["legacy.com"]}
        _write_signed_cache(str(tmp_path), feed, sign=False, mark_seen=False)
        assert ioc_manager._has_seen_signed(str(tmp_path)) is False
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_signature_invalid"] is False
        assert iocs["_ioc_degraded"] is False
        assert "legacy.com" in iocs["malicious_domains"]

    def test_valid_signature_arms_sentinel_on_read(self, tmp_path, monkeypatch):
        """First valid verification during a read arms the strip-detection
        sentinel even if it was not pre-written."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "v", "malicious_domains": ["e.com"]}
        _write_signed_cache(str(tmp_path), feed, mark_seen=False)
        assert ioc_manager._has_seen_signed(str(tmp_path)) is False
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_signature_invalid"] is False
        assert ioc_manager._has_seen_signed(str(tmp_path)) is True
