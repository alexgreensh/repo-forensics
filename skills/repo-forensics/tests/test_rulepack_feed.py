"""Tests for the U6 signed rule-pack feed + Ed25519 verify-only crypto.

Offline-first: NO test makes a real network call. The fetch is monkeypatched to
serve bundles from in-memory fixtures; all signing happens with a deterministic
TEST keypair (the published feed uses a DIFFERENT key, held offline).

Covers:
  - _ed25519 RFC 8032 test vectors + malformed-input rejection.
  - Raw-bytes signature discipline (canonicalization negative test).
  - Full acceptance chain: schema, freshness, persisted-floor rollback,
    per-pack self-tests, whole-bundle rejection.
  - Overlay semantics in rule_loader (newer overlays, equal/older ignored,
    silent-detection-removal guard).
  - Verify-on-load re-verification (cache tamper -> fall back to shipped).
  - URL hardening (http / non-allowlisted host / oversized body).
  - refresh_threat_dbs invokes the updater within hard-cap/lock discipline.
"""

import json
import os
import sys

import pytest

import _ed25519
import rulepack_feed
import rule_loader

# Deterministic TEST keypair (NOT the published feed key). Signing uses the
# dev-only sibling at repo-root scripts/_ed25519_sign.py.
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))), "scripts"))
import _ed25519_sign  # noqa: E402

TEST_SEED = bytes.fromhex(
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
TEST_PRIV, TEST_PUB = _ed25519_sign.keypair(TEST_SEED)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _sign(raw_bytes):
    return _ed25519_sign.sign(raw_bytes, TEST_PRIV, TEST_PUB)


def _today_iso():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def _make_bundle(packs=None, generated=None, schema="1.0",
                 bundle_version=1):
    """Build a minimal valid bundle dict. Default carries one tiny pack with a
    self-consistent regex rule.

    `generated` defaults to today (UTC): the freshness gate rejects both stale
    AND future-dated bundles, so a realistic recent date is the only one that
    passes cleanly."""
    if generated is None:
        generated = _today_iso()
    if packs is None:
        packs = {
            "demo": {
                "pack_version": 2,
                "schema_version": "1.0",
                "rules": [{
                    "id": "DEMO-001",
                    "type": "regex",
                    "pattern": "evilcorp",
                    "severity": "high",
                    "examples": {"match": ["evilcorp"], "no_match": ["safe"]},
                }],
            }
        }
    return {
        "schema_version": schema,
        "generated": generated,
        "bundle_version": bundle_version,
        "packs": packs,
    }


def _serialize(bundle):
    """Match the dev tooling's canonical serialization (sorted keys, indent=2)."""
    return json.dumps(bundle, indent=2, sort_keys=True).encode("utf-8")


def _accept(raw, sig, cache_dir, **kw):
    return rulepack_feed.accept_bundle(raw, sig, cache_dir=str(cache_dir),
                                       pubkey=TEST_PUB, **kw)


@pytest.fixture(autouse=True)
def _reset_loader_state():
    rule_loader._reset_overlay_state()
    rule_loader._reset_pack_cache()
    yield
    rule_loader._reset_overlay_state()
    rule_loader._reset_pack_cache()


# ---------------------------------------------------------------------------
# _ed25519 verify-only: RFC 8032 vectors + malformed inputs
# ---------------------------------------------------------------------------

class TestEd25519Vectors:
    # RFC 8032 section 7.1 (authoritative; fetched, not from memory).
    VECTORS = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]

    def test_rfc8032_vectors_verify(self):
        for _sk, pk, msg, sig in self.VECTORS:
            assert _ed25519.verify(
                bytes.fromhex(sig), bytes.fromhex(msg), bytes.fromhex(pk)
            ) is True

    def test_flipped_signature_rejected(self):
        _sk, pk, msg, sig = self.VECTORS[1]
        bad = bytearray(bytes.fromhex(sig))
        bad[0] ^= 0x01
        assert _ed25519.verify(bytes(bad), bytes.fromhex(msg), bytes.fromhex(pk)) is False

    def test_wrong_message_rejected(self):
        _sk, pk, _msg, sig = self.VECTORS[0]
        assert _ed25519.verify(bytes.fromhex(sig), b"tampered", bytes.fromhex(pk)) is False

    def test_malformed_lengths_rejected(self):
        assert _ed25519.verify(b"short", b"m", b"\x00" * 32) is False
        assert _ed25519.verify(b"\x00" * 64, b"m", b"short") is False
        assert _ed25519.verify("notbytes", b"m", b"\x00" * 32) is False

    def test_garbage_pubkey_rejected(self):
        _sk, _pk, msg, sig = self.VECTORS[2]
        assert _ed25519.verify(bytes.fromhex(sig), bytes.fromhex(msg), b"\xff" * 32) is False

    def test_non_canonical_S_rejected(self):
        # S >= L must be rejected (malleability guard).
        _sk, pk, msg, sig = self.VECTORS[0]
        sig_b = bytearray(bytes.fromhex(sig))
        sig_b[32:] = (b"\xff" * 32)  # S = 2^256-1 >> L
        assert _ed25519.verify(bytes(sig_b), bytes.fromhex(msg), bytes.fromhex(pk)) is False


# ---------------------------------------------------------------------------
# Raw-bytes discipline + acceptance chain
# ---------------------------------------------------------------------------

class TestAcceptanceChain:
    def test_valid_bundle_accepted_and_cached(self, tmp_path):
        raw = _serialize(_make_bundle())
        sig = _sign(raw)
        ok, msg, bundle = _accept(raw, sig, tmp_path)
        assert ok, msg
        assert bundle["bundle_version"] == 1
        # raw bytes + sig persisted exactly
        cached_raw = (tmp_path / "bundle.json").read_bytes()
        assert cached_raw == raw
        assert (tmp_path / "bundle.json.sig").read_bytes() == sig
        # floor advanced to the pack's version
        floor = rulepack_feed.load_floor(str(tmp_path))
        assert floor["demo"] == 2

    def test_flipped_byte_signature_failure_cache_untouched(self, tmp_path):
        raw = _serialize(_make_bundle())
        sig = _sign(raw)
        bad = bytearray(raw)
        bad[50] ^= 0x01
        ok, msg, _ = _accept(bytes(bad), sig, tmp_path)
        assert not ok
        assert "signature" in msg.lower()
        assert not (tmp_path / "bundle.json").exists()

    def test_canonicalization_negative(self, tmp_path):
        """A valid bundle parsed then RE-SERIALIZED must NOT verify — proving the
        verifier checks raw bytes, never a parse-and-reserialize round-trip."""
        raw = _serialize(_make_bundle())
        sig = _sign(raw)
        # round-trip through json with DIFFERENT formatting
        reserialized = json.dumps(json.loads(raw)).encode("utf-8")
        assert reserialized != raw
        assert rulepack_feed.verify_raw_bundle(reserialized, sig, pubkey=TEST_PUB) is False
        # ... but the original raw bytes still verify
        assert rulepack_feed.verify_raw_bundle(raw, sig, pubkey=TEST_PUB) is True

    def test_stale_generated_rejected(self, tmp_path):
        raw = _serialize(_make_bundle(generated="2000-01-01"))
        sig = _sign(raw)
        # now anchored well after 2000 so age > 30d
        import time as _t
        ok, msg, _ = _accept(raw, sig, tmp_path, now=_t.time())
        assert not ok
        assert "old" in msg.lower()
        assert not (tmp_path / "bundle.json").exists()

    def test_freshness_60_days_old_rejected(self, tmp_path):
        import datetime
        gen = (datetime.date.today() - datetime.timedelta(days=60)).isoformat()
        raw = _serialize(_make_bundle(generated=gen))
        sig = _sign(raw)
        ok, msg, _ = _accept(raw, sig, tmp_path)
        assert not ok
        assert "old" in msg.lower()

    def test_schema_major_mismatch_rejected(self, tmp_path):
        raw = _serialize(_make_bundle(schema="2.0"))
        sig = _sign(raw)
        ok, msg, _ = _accept(raw, sig, tmp_path)
        assert not ok
        assert "schema" in msg.lower()

    def test_persisted_floor_blocks_rollback(self, tmp_path):
        # Accept a v5 pack, advancing the floor.
        b5 = _make_bundle(packs={"demo": {
            "pack_version": 5, "schema_version": "1.0",
            "rules": [{"id": "DEMO-001", "type": "regex", "pattern": "x",
                       "examples": {"match": ["x"], "no_match": ["y"]}}],
        }})
        raw5 = _serialize(b5)
        ok, _, _ = _accept(raw5, _sign(raw5), tmp_path)
        assert ok
        assert rulepack_feed.load_floor(str(tmp_path))["demo"] == 5
        # Clear the cached bundle (but the floor file survives).
        (tmp_path / "bundle.json").unlink()
        (tmp_path / "bundle.json.sig").unlink()
        # A validly-signed v4 must now be rejected by the persisted floor.
        b4 = _make_bundle(packs={"demo": {
            "pack_version": 4, "schema_version": "1.0",
            "rules": [{"id": "DEMO-001", "type": "regex", "pattern": "x",
                       "examples": {"match": ["x"], "no_match": ["y"]}}],
        }})
        raw4 = _serialize(b4)
        ok, msg, _ = _accept(raw4, _sign(raw4), tmp_path)
        assert not ok
        assert "rollback" in msg.lower() or "floor" in msg.lower()

    def test_equal_version_identical_content_is_current_not_rollback(self, tmp_path):
        raw = _serialize(_make_bundle())
        sig = _sign(raw)
        assert _accept(raw, sig, tmp_path)[0]

        ok, msg, bundle = _accept(raw, sig, tmp_path)

        assert ok, msg
        assert bundle["packs"]["demo"]["pack_version"] == 2

    def test_equal_version_changed_content_is_equivocation(self, tmp_path):
        first = _serialize(_make_bundle())
        assert _accept(first, _sign(first), tmp_path)[0]
        changed_bundle = _make_bundle()
        changed_bundle["packs"]["demo"]["rules"][0].update({
            "pattern": "different",
            "examples": {"match": ["different"], "no_match": ["safe"]},
        })
        changed = _serialize(changed_bundle)

        ok, msg, _ = _accept(changed, _sign(changed), tmp_path)

        assert not ok
        assert "equivocation" in msg

    def test_failing_self_test_rejects_whole_bundle(self, tmp_path):
        # Valid signature, but one rule's example self-test fails -> whole bundle
        # rejected (no partial acceptance).
        bundle = _make_bundle(packs={"demo": {
            "pack_version": 2, "schema_version": "1.0",
            "rules": [
                {"id": "DEMO-OK", "type": "regex", "pattern": "good",
                 "examples": {"match": ["good"], "no_match": ["bad"]}},
                {"id": "DEMO-BAD", "type": "regex", "pattern": "needle",
                 # match example does NOT match the pattern -> self-test fail
                 "examples": {"match": ["haystack"], "no_match": []}},
            ],
        }})
        raw = _serialize(bundle)
        ok, msg, _ = _accept(raw, _sign(raw), tmp_path)
        assert not ok
        assert "self-test" in msg.lower()
        assert not (tmp_path / "bundle.json").exists()


# ---------------------------------------------------------------------------
# Torture-room regressions: byte-exact cache, future-date gate, floor survival
# ---------------------------------------------------------------------------

class TestSignedBytesAndFreshness:
    def test_cached_bundle_is_byte_identical_and_verifies_on_load(self, tmp_path):
        """FIX 2: the cache must hold the EXACT signed bytes (binary write, no
        text-mode \\n->\\r\\n rewrite), so the detached sig re-verifies on load."""
        raw = _serialize(_make_bundle())
        sig = _sign(raw)
        ok, _, _ = _accept(raw, sig, tmp_path)
        assert ok
        cached = (tmp_path / "bundle.json").read_bytes()
        assert cached == raw  # byte-for-byte, no CRLF translation
        cached_sig = (tmp_path / "bundle.json.sig").read_bytes()
        # Verify-on-load: signature checks against the cached bytes.
        assert rulepack_feed.verify_raw_bundle(cached, cached_sig, pubkey=TEST_PUB) is True

    def test_future_dated_bundle_rejected(self, tmp_path):
        """FIX 5: a bundle generated well in the future must be rejected, not
        sail through the 'too old' gate via a negative age."""
        import datetime
        future = (datetime.datetime.now(datetime.timezone.utc).date()
                  + datetime.timedelta(days=10)).isoformat()
        raw = _serialize(_make_bundle(generated=future))
        ok, msg, _ = _accept(raw, _sign(raw), tmp_path)
        assert not ok
        assert "future" in msg.lower()
        assert not (tmp_path / "bundle.json").exists()

    def test_malformed_generated_time_rejected(self, tmp_path):
        """FIX 5: a malformed time component must reject (not be silently
        truncated to the date prefix)."""
        raw = _serialize(_make_bundle(generated="2026-06-10T99:99:99"))
        ok, msg, _ = _accept(raw, _sign(raw), tmp_path)
        assert not ok
        assert "unparseable" in msg.lower()

    def test_one_day_future_skew_tolerated(self, tmp_path):
        """FIX 5: a tiny clock skew (<= 1 day ahead) is tolerated."""
        import datetime
        tomorrow = (datetime.datetime.now(datetime.timezone.utc).date()
                    + datetime.timedelta(days=1)).isoformat()
        raw = _serialize(_make_bundle(generated=tomorrow))
        ok, msg, _ = _accept(raw, _sign(raw), tmp_path)
        assert ok, msg

    def test_floor_survives_cache_clear(self, tmp_path):
        """FIX 4 (KTD-13): accept v10, then `rm -rf` the CACHE dir (not the
        floor's state dir); a replay of a validly-signed v3 must still be
        rejected by the persisted floor."""
        import shutil
        cache = tmp_path / "cache"
        b10 = _make_bundle(packs={"demo": {
            "pack_version": 10, "schema_version": "1.0",
            "rules": [{"id": "DEMO-001", "type": "regex", "pattern": "x",
                       "examples": {"match": ["x"], "no_match": ["y"]}}],
        }})
        raw10 = _serialize(b10)
        ok, _, _ = _accept(raw10, _sign(raw10), cache)
        assert ok
        assert rulepack_feed.load_floor(str(cache))["demo"] == 10
        # The floor lives OUTSIDE the cache dir (sibling state dir).
        floor_path = rulepack_feed._floor_path(str(cache))
        assert not floor_path.startswith(str(cache) + os.sep)
        assert os.path.exists(floor_path)
        # Wipe the ENTIRE cache dir, as a `rm -rf ~/.cache/repo-forensics` would.
        shutil.rmtree(str(cache))
        assert not os.path.exists(str(cache))
        # Floor file untouched.
        assert os.path.exists(rulepack_feed._floor_path(str(cache)))
        assert rulepack_feed.load_floor(str(cache))["demo"] == 10
        # Replay an older validly-signed v3 -> rejected by the surviving floor.
        b3 = _make_bundle(packs={"demo": {
            "pack_version": 3, "schema_version": "1.0",
            "rules": [{"id": "DEMO-001", "type": "regex", "pattern": "x",
                       "examples": {"match": ["x"], "no_match": ["y"]}}],
        }})
        raw3 = _serialize(b3)
        ok, msg, _ = _accept(raw3, _sign(raw3), cache)
        assert not ok
        assert "rollback" in msg.lower() or "floor" in msg.lower()

    def test_equal_version_recovers_after_cache_clear_from_persisted_digest(self, tmp_path):
        cache = tmp_path / "cache"
        raw = _serialize(_make_bundle())
        sig = _sign(raw)
        assert _accept(raw, sig, cache)[0]
        import shutil
        shutil.rmtree(cache)

        ok, msg, _ = _accept(raw, sig, cache)

        assert ok, msg
        assert (cache / "bundle.json").read_bytes() == raw

    def test_interrupted_pair_commit_restores_last_known_good(self, tmp_path, monkeypatch):
        first = _make_bundle()
        first_raw = _serialize(first)
        assert _accept(first_raw, _sign(first_raw), tmp_path)[0]
        second = _make_bundle()
        second["packs"]["demo"]["pack_version"] = 3
        second_raw = _serialize(second)
        second_sig = _sign(second_raw)
        real_write = rulepack_feed._atomic_write_bytes
        failed = {"done": False}

        def fail_current_signature_once(path, data, mode=0o600):
            if path == rulepack_feed._sig_path(str(tmp_path)) and not failed["done"]:
                failed["done"] = True
                raise OSError("injected signature rename failure")
            return real_write(path, data, mode=mode)

        monkeypatch.setattr(rulepack_feed, "_atomic_write_bytes", fail_current_signature_once)
        with pytest.raises(OSError, match="injected"):
            _accept(second_raw, second_sig, tmp_path)

        pair = rulepack_feed.read_verified_cached_pair(str(tmp_path), pubkey=TEST_PUB)
        assert pair is not None
        assert pair[0] == first_raw

    def test_loader_uses_previous_signed_generation_after_torn_commit(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(rulepack_feed, "RULEPACK_FEED_PUBKEY_HEX", TEST_PUB.hex())
        first = _make_bundle()
        first_raw = _serialize(first)
        assert _accept(first_raw, _sign(first_raw), tmp_path)[0]
        second = _make_bundle()
        second["packs"]["demo"]["pack_version"] = 3
        second_raw = _serialize(second)
        assert _accept(second_raw, _sign(second_raw), tmp_path)[0]
        # Torn current generation: new JSON paired with the previous signature.
        (tmp_path / "bundle.json.sig").write_bytes(_sign(first_raw))

        rule_loader._reset_overlay_state()
        recovered = rule_loader._verified_cache_bundle(str(tmp_path))

        assert recovered is not None
        assert recovered["packs"]["demo"]["pack_version"] == 2
        assert rule_loader.get_rulepack_degraded() is True


# ---------------------------------------------------------------------------
# Overlay semantics (rule_loader, using the cache_dir seam)
# ---------------------------------------------------------------------------

def _write_shipped_pack(dir_path, name, pack_version, rules):
    p = dir_path / f"{name}.json"
    p.write_text(json.dumps({
        "schema_version": "1.0", "pack": name,
        "pack_version": pack_version, "generated": "2099-01-01",
        "rules": rules,
    }))
    return p


def _cache_signed_bundle(cache_dir, bundle):
    raw = _serialize(bundle)
    sig = _sign(raw)
    rulepack_feed.accept_bundle(raw, sig, cache_dir=str(cache_dir), pubkey=TEST_PUB)


class TestOverlay:
    def _shipped_rule(self, rid="OVL-001", pat="alpha"):
        return {"id": rid, "type": "regex", "pattern": pat,
                "examples": {"match": [pat], "no_match": ["zzz"]}}

    def test_newer_overlay_replaces_shipped(self, tmp_path, monkeypatch):
        ship = tmp_path / "ship"
        ship.mkdir()
        _write_shipped_pack(ship, "ovl", 1, [self._shipped_rule(pat="alpha")])
        cache = tmp_path / "cache"
        _cache_signed_bundle(cache, _make_bundle(packs={"ovl": {
            "pack_version": 3, "schema_version": "1.0",
            "rules": [self._shipped_rule(pat="omega")],
        }}))
        # Point rule_loader at the test pubkey via the verify chokepoint.
        monkeypatch.setattr(rulepack_feed, "RULEPACK_FEED_PUBKEY_HEX", TEST_PUB.hex())
        pack = rule_loader.load_pack("ovl", base_dir=str(ship))
        # base_dir bypasses overlay by design; load shipped then overlay manually.
        shipped = rule_loader._load_pack_file(str(ship / "ovl.json"))
        overlaid = rule_loader._maybe_overlay("ovl", shipped, cache_dir=str(cache))
        assert overlaid.pack_version == 3
        assert any(r.regex.pattern == "omega" for r in overlaid.all_rules)
        assert pack is not None  # base_dir load still works

    def test_equal_or_older_overlay_ignored(self, tmp_path, monkeypatch):
        ship = tmp_path / "ship"
        ship.mkdir()
        _write_shipped_pack(ship, "ovl", 5, [self._shipped_rule(pat="alpha")])
        cache = tmp_path / "cache"
        monkeypatch.setattr(rulepack_feed, "RULEPACK_FEED_PUBKEY_HEX", TEST_PUB.hex())
        for cached_ver in (4, 5):
            rule_loader._reset_overlay_state()
            _cache_signed_bundle(cache, _make_bundle(packs={"ovl": {
                "pack_version": cached_ver, "schema_version": "1.0",
                "rules": [self._shipped_rule(pat="omega")],
            }}))
            shipped = rule_loader._load_pack_file(str(ship / "ovl.json"))
            overlaid = rule_loader._maybe_overlay("ovl", shipped, cache_dir=str(cache))
            assert overlaid.pack_version == 5  # shipped stays authoritative
            assert any(r.regex.pattern == "alpha" for r in overlaid.all_rules)

    def test_silent_detection_removal_surfaced(self, tmp_path, monkeypatch):
        ship = tmp_path / "ship"
        ship.mkdir()
        _write_shipped_pack(ship, "ovl", 1, [
            self._shipped_rule(rid="OVL-001", pat="alpha"),
            self._shipped_rule(rid="OVL-KEEP", pat="beta"),
        ])
        cache = tmp_path / "cache"
        monkeypatch.setattr(rulepack_feed, "RULEPACK_FEED_PUBKEY_HEX", TEST_PUB.hex())
        # Overlay flips shipped-active OVL-001 to retired:true.
        _cache_signed_bundle(cache, _make_bundle(packs={"ovl": {
            "pack_version": 2, "schema_version": "1.0",
            "rules": [
                {"id": "OVL-001", "type": "regex", "pattern": "alpha",
                 "retired": True,
                 "examples": {"match": ["alpha"], "no_match": []}},
                self._shipped_rule(rid="OVL-KEEP", pat="beta"),
            ],
        }}))
        rule_loader._reset_overlay_state()
        shipped = rule_loader._load_pack_file(str(ship / "ovl.json"))
        overlaid = rule_loader._maybe_overlay("ovl", shipped, cache_dir=str(cache))
        assert overlaid.pack_version == 2  # overlay accepted
        log = " ".join(rule_loader.get_overlay_log())
        assert "OVL-001" in log
        assert "silent-detection-removal" in log

    def test_cache_tamper_falls_back_to_shipped(self, tmp_path, monkeypatch):
        ship = tmp_path / "ship"
        ship.mkdir()
        _write_shipped_pack(ship, "ovl", 1, [self._shipped_rule(pat="alpha")])
        cache = tmp_path / "cache"
        monkeypatch.setattr(rulepack_feed, "RULEPACK_FEED_PUBKEY_HEX", TEST_PUB.hex())
        _cache_signed_bundle(cache, _make_bundle(packs={"ovl": {
            "pack_version": 9, "schema_version": "1.0",
            "rules": [self._shipped_rule(pat="omega")],
        }}))
        # Tamper with the cached bundle AFTER a successful fetch.
        bundle_file = cache / "bundle.json"
        content = json.loads(bundle_file.read_text())
        content["packs"]["ovl"]["rules"][0]["pattern"] = "INJECTED"
        bundle_file.write_text(json.dumps(content, indent=2, sort_keys=True))
        rule_loader._reset_overlay_state()
        shipped = rule_loader._load_pack_file(str(ship / "ovl.json"))
        overlaid = rule_loader._maybe_overlay("ovl", shipped, cache_dir=str(cache))
        # Re-verify on load rejects the tampered cache -> shipped authoritative.
        assert overlaid.pack_version == 1
        assert any(r.regex.pattern == "alpha" for r in overlaid.all_rules)
        assert rule_loader.get_rulepack_degraded() is True


# ---------------------------------------------------------------------------
# URL hardening (mirror ioc_manager tests)
# ---------------------------------------------------------------------------

class TestFeedURLHardening:
    def test_https_allowlisted_accepted(self):
        assert rulepack_feed._validate_feed_url(
            "https://raw.githubusercontent.com/x/y/main/iocs/rulepacks.json") is True

    def test_http_rejected(self):
        assert rulepack_feed._validate_feed_url(
            "http://raw.githubusercontent.com/x/y/rulepacks.json") is False

    def test_non_allowlisted_host_rejected(self):
        assert rulepack_feed._validate_feed_url("https://evil.com/rulepacks.json") is False

    def test_file_scheme_rejected(self):
        assert rulepack_feed._validate_feed_url("file:///etc/passwd") is False

    def test_empty_and_none_rejected(self):
        assert rulepack_feed._validate_feed_url("") is False
        assert rulepack_feed._validate_feed_url(None) is False

    def test_oversized_body_rejected(self, monkeypatch):
        # A response larger than the cap returns None before parse.
        class _FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): return b"x" * n  # always returns cap+1 bytes

        def _fake_urlopen(req, timeout=10):
            return _FakeResp()
        import urllib.request
        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
        out = rulepack_feed._fetch_raw(
            "https://raw.githubusercontent.com/x/y/rulepacks.json",
            rulepack_feed._FEED_MAX_BYTES)
        assert out is None

    def test_http_url_rejected_before_socket(self, monkeypatch):
        called = {"hit": False}

        def _boom(*a, **k):
            called["hit"] = True
            raise AssertionError("socket should not open for rejected URL")
        import urllib.request
        monkeypatch.setattr(urllib.request, "urlopen", _boom)
        assert rulepack_feed._fetch_raw(
            "http://evil.com/x", rulepack_feed._FEED_MAX_BYTES) is None
        assert called["hit"] is False


# ---------------------------------------------------------------------------
# update_rulepacks end-to-end (mocked fetch, offline)
# ---------------------------------------------------------------------------

class TestUpdateRulepacks:
    def test_update_fetches_verifies_caches(self, tmp_path, monkeypatch):
        raw = _serialize(_make_bundle())
        sig = _sign(raw)

        def _fake_fetch(url, max_bytes):
            return sig if url.endswith(".sig") else raw
        monkeypatch.setattr(rulepack_feed, "_fetch_raw", _fake_fetch)
        ok, msg = rulepack_feed.update_rulepacks(
            cache_dir=str(tmp_path), pubkey=TEST_PUB, force=True)
        assert ok, msg
        assert (tmp_path / "bundle.json").exists()

    def test_update_fetch_failure_is_degraded(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rulepack_feed, "_fetch_raw", lambda u, m: None)
        ok, msg = rulepack_feed.update_rulepacks(
            cache_dir=str(tmp_path), pubkey=TEST_PUB, force=True)
        assert not ok
        assert "fetch failed" in msg.lower()
        assert not (tmp_path / "bundle.json").exists()
