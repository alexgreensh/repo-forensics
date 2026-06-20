#!/usr/bin/env python3
"""
rulepack_feed.py - Signed rule-pack bundle fetch / verify / cache (repo-forensics v2, U6).

Daily-refreshed, Ed25519-verified rule-pack bundle so new behavioral rules reach
users WITHOUT code releases. Tampered / invalid / stale / rolled-back bundles are
rejected and the SHIPPED packs stay authoritative. Offline-first: scanning never
requires the network — this updater runs only from the daily background refresher.

Mirrors ioc_manager.py discipline EXACTLY:
  - https-only + host allowlist (shared {raw.githubusercontent.com, github.com,
    objects.githubusercontent.com})
  - 5 MB body cap
  - atomic temp+rename writes
  - 24h cache TTL
  - cache under ~/.cache/repo-forensics/rulepacks/ (created mode 0700)

Acceptance chain (EXACT ORDER, KTD-6/13):
  1. Ed25519 signature verified over the EXACT raw fetched bytes, BEFORE any decode.
  2. JSON parse.
  3. schema major-version gate.
  4. `generated` freshness gate: reject (degraded) if older than 30 days.
  5. pack_version vs PERSISTED FLOOR: strictly-increasing integer per pack;
     floor persisted OUTSIDE the cache (under ~/.local/state/repo-forensics/, a
     sibling of the cache dir) so `rm -rf ~/.cache/repo-forensics` cannot reset
     it and re-admit a replayed older bundle (KTD-13).
  6. per-pack example self-tests (reuse rule_loader.self_test_pack incl. ReDoS timeout).
  7. atomic cache write (dir mode 0700) + floor update.
Any link fails -> reject WHOLE bundle (no partial acceptance), keep prior cache,
set a rule-pack-degraded flag (DISTINCT from IOC-degraded, KTD-11).

The cache stores the EXACT raw verified bundle bytes (bundle.json) plus the
detached signature (bundle.json.sig). rule_loader re-verifies that signature on
EVERY load (KTD-12). This module owns fetch + accept; rule_loader owns the
verify-on-load overlay.

Created by Alex Greenshpun.
"""

import hashlib
import json
import os
import sys
import time

_SCRIPTS_DIR = os.path.dirname(os.path.realpath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

# --- Pinned public key (verify-only) ----------------------------------------
# Published-feed Ed25519 public key. The matching private seed is held OFFLINE
# (never in this repo). Rotation = ship a new pubkey in a release.
RULEPACK_FEED_PUBKEY_HEX = (
    "a6529e80619abaf38bec2b15154ca8f540f9a830e310f1a0c7a6771e85f1b76c"
)

# --- Feed location ----------------------------------------------------------
RULEPACK_FEED_URL = (
    "https://raw.githubusercontent.com/alexgreensh/repo-forensics/main/iocs/rulepacks.json"
)
RULEPACK_FEED_SIG_URL = RULEPACK_FEED_URL + ".sig"

# --- Fetch hardening (mirror ioc_manager.py) --------------------------------
_FEED_HOST_ALLOWLIST = {
    "raw.githubusercontent.com",
    "github.com",
    "objects.githubusercontent.com",
}
_FEED_MAX_BYTES = 5_000_000  # 5 MB
_SIG_MAX_BYTES = 256  # an Ed25519 sig is 64 bytes; cap generously but tightly

# --- Cache layout -----------------------------------------------------------
_CACHE_ROOT = os.path.join(os.path.expanduser("~"), ".cache", "repo-forensics")
CACHE_RULEPACK_DIR = os.path.join(_CACHE_ROOT, "rulepacks")
# The version floor (rollback guard, KTD-13) lives in a STATE dir that is a
# sibling of the cache, NOT inside it: `rm -rf ~/.cache/repo-forensics` (the
# canonical "clear my cache" gesture) must NOT reset the floor, otherwise a
# replay of an older validly-signed bundle would be re-accepted.
_STATE_ROOT = os.path.join(os.path.expanduser("~"), ".local", "state", "repo-forensics")
STATE_RULEPACK_DIR = os.path.join(_STATE_ROOT, "rulepacks")
BUNDLE_FILENAME = "bundle.json"
BUNDLE_SIG_FILENAME = "bundle.json.sig"
PREVIOUS_BUNDLE_FILENAME = "bundle.previous.json"
PREVIOUS_BUNDLE_SIG_FILENAME = "bundle.previous.json.sig"
FLOOR_FILENAME = "floor.json"
FLOOR_DIGEST_FILENAME = "floor-digests.json"
_BUNDLE_CACHE_TTL_HOURS = 24

# --- Acceptance gates -------------------------------------------------------
BUNDLE_SCHEMA_VERSION = "1.0"
FRESHNESS_MAX_DAYS = 30


def _cache_dir(cache_dir=None):
    return cache_dir if cache_dir else CACHE_RULEPACK_DIR


def _bundle_path(cache_dir=None):
    return os.path.join(_cache_dir(cache_dir), BUNDLE_FILENAME)


def _sig_path(cache_dir=None):
    return os.path.join(_cache_dir(cache_dir), BUNDLE_SIG_FILENAME)


def _previous_bundle_path(cache_dir=None):
    return os.path.join(_cache_dir(cache_dir), PREVIOUS_BUNDLE_FILENAME)


def _previous_sig_path(cache_dir=None):
    return os.path.join(_cache_dir(cache_dir), PREVIOUS_BUNDLE_SIG_FILENAME)


def _state_dir(cache_dir=None):
    """Directory that holds the rollback floor. It must survive a cache wipe, so
    it is NEVER the cache dir itself.

    - Production (cache_dir=None): the dedicated state dir under
      ~/.local/state/repo-forensics/rulepacks/.
    - Tests / explicit cache_dir: a SIBLING dir (`<cache_dir>-state`) so that
      removing `cache_dir` (the bundle's directory) leaves the floor intact,
      while still being deterministically resolvable from cache_dir.
    """
    if cache_dir:
        parent = os.path.dirname(os.path.normpath(cache_dir)) or "."
        base = os.path.basename(os.path.normpath(cache_dir))
        return os.path.join(parent, base + "-state")
    return STATE_RULEPACK_DIR


def _floor_path(cache_dir=None):
    return os.path.join(_state_dir(cache_dir), FLOOR_FILENAME)


def _floor_digest_path(cache_dir=None):
    return os.path.join(_state_dir(cache_dir), FLOOR_DIGEST_FILENAME)


def _pubkey_bytes():
    return bytes.fromhex(RULEPACK_FEED_PUBKEY_HEX)


def _ensure_cache_dir(cache_dir=None):
    """Create the cache dir with mode 0700 (cross-platform; mode is a no-op on
    Windows but the call is harmless)."""
    d = _cache_dir(cache_dir)
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


# --- Persisted floor (rollback guard, KTD-13) -------------------------------

def load_floor(cache_dir=None):
    """Return {pack_name: int} persisted version floor, or {} if absent/invalid."""
    path = _floor_path(cache_dir)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    out = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool):
            out[k] = v
    return out


def _ensure_state_dir(cache_dir=None):
    """Create the floor's state dir (mode 0700 where supported)."""
    d = _state_dir(cache_dir)
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _save_floor(floor, cache_dir=None):
    import forensics_core
    _ensure_state_dir(cache_dir)
    forensics_core.atomic_write_json(_floor_path(cache_dir), floor, mode=0o600)


def _pack_digest(pack):
    raw = json.dumps(pack, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load_floor_digests(cache_dir=None):
    try:
        with open(_floor_digest_path(cache_dir), "r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {name: digest for name, digest in value.items()
            if isinstance(name, str) and isinstance(digest, str) and len(digest) == 64}


def _save_floor_digests(bundle, cache_dir=None):
    import forensics_core
    _ensure_state_dir(cache_dir)
    digests = {name: _pack_digest(pack)
               for name, pack in bundle.get("packs", {}).items()
               if isinstance(name, str) and isinstance(pack, dict)}
    forensics_core.atomic_write_json(_floor_digest_path(cache_dir), digests, mode=0o600)


# --- URL validation (mirror ioc_manager._validate_feed_url) -----------------

def _validate_feed_url(url):
    """True iff url is https:// and host is in the shared allowlist."""
    if not isinstance(url, str) or not url.startswith("https://"):
        return False
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
    except (ValueError, TypeError):
        return False
    return host in _FEED_HOST_ALLOWLIST


def _fetch_raw(url, max_bytes):
    """Fetch `url` returning raw bytes (capped) or None. https + allowlist only."""
    if not _validate_feed_url(url):
        print(f"[!] rule-pack feed URL rejected (non-https or host not allowlisted): {url!r}",
              file=sys.stderr)
        return None
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url, headers={"User-Agent": "repo-forensics/v2"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                print(f"[!] rule-pack feed exceeded {max_bytes} byte cap", file=sys.stderr)
                return None
            return raw
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"[!] rule-pack feed fetch failed: {e}", file=sys.stderr)
        return None


# --- Verification over raw bytes (acceptance step 1) ------------------------

def _trusted_ed25519():
    """Load the Ed25519 verifier from THIS module's own directory by absolute
    path, so it can never be shadowed by an earlier sys.path entry. The verifier
    must come from trusted-installed code, never from a candidate payload."""
    import importlib.util
    trusted_path = os.path.join(_SCRIPTS_DIR, "_ed25519.py")
    cached = sys.modules.get("_ed25519")
    if cached is not None and getattr(cached, "__file__", None) == trusted_path:
        return cached
    spec = importlib.util.spec_from_file_location("_ed25519", trusted_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules["_ed25519"] = module
    return module


def verify_raw_bundle(raw_bytes, sig_bytes, pubkey=None):
    """Verify the Ed25519 signature over the EXACT raw bundle bytes.

    This is the single chokepoint: callers MUST pass the literal fetched/cached
    bytes, never a parse-and-reserialize round-trip. Returns True/False.
    """
    if not isinstance(raw_bytes, (bytes, bytearray)):
        return False
    if not isinstance(sig_bytes, (bytes, bytearray)):
        return False
    key = pubkey if pubkey is not None else _pubkey_bytes()
    return _trusted_ed25519().verify(bytes(sig_bytes), bytes(raw_bytes), key)


def _read_verified_pair(bundle_path, sig_path, pubkey=None):
    """Return exact bytes for one valid on-disk pair, else None."""
    try:
        raw = open(bundle_path, "rb").read(_FEED_MAX_BYTES + 1)
        sig = open(sig_path, "rb").read(_SIG_MAX_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _FEED_MAX_BYTES or len(sig) > _SIG_MAX_BYTES:
        return None
    return (raw, sig) if verify_raw_bundle(raw, sig, pubkey=pubkey) else None


def read_verified_cached_pair(cache_dir=None, pubkey=None, allow_previous=True):
    """Read the current signed generation, falling back to last-known-good."""
    pair = _read_verified_pair(_bundle_path(cache_dir), _sig_path(cache_dir), pubkey)
    if pair is not None or not allow_previous:
        return pair
    return _read_verified_pair(
        _previous_bundle_path(cache_dir), _previous_sig_path(cache_dir), pubkey
    )


def _restore_previous_pair(cache_dir=None, pubkey=None):
    pair = _read_verified_pair(
        _previous_bundle_path(cache_dir), _previous_sig_path(cache_dir), pubkey
    )
    if pair is None:
        return False
    raw, sig = pair
    try:
        _atomic_write_bytes(_bundle_path(cache_dir), raw, mode=0o600)
        _atomic_write_bytes(_sig_path(cache_dir), sig, mode=0o600)
        return True
    except OSError:
        return False


# --- Acceptance chain (steps 2-6) -------------------------------------------

def _check_schema(bundle):
    sv = bundle.get("schema_version", "")
    if not isinstance(sv, str):
        return False, "schema_version not a string"
    major = sv.split(".")[0] if sv else ""
    expected = BUNDLE_SCHEMA_VERSION.split(".")[0]
    if major != expected:
        return False, f"schema major {major!r} != expected {expected!r}"
    return True, ""


def _check_freshness(bundle, now=None):
    gen = bundle.get("generated", "")
    if not isinstance(gen, str) or not gen:
        return False, "missing 'generated' timestamp"
    import datetime
    # Validate the WHOLE timestamp parses, not just the leading date slice: a
    # malformed time component must reject (not be silently truncated away).
    # Accept a trailing 'Z' (UTC) which date/datetime.fromisoformat rejects on
    # older Pythons.
    iso = gen[:-1] + "+00:00" if gen.endswith("Z") else gen
    try:
        if len(gen) <= 10:
            gen_date = datetime.date.fromisoformat(gen)
        else:
            gen_date = datetime.datetime.fromisoformat(iso).date()
    except ValueError:
        return False, f"unparseable 'generated' {gen!r}"
    today = (datetime.datetime.fromtimestamp(now, datetime.timezone.utc).date()
             if now is not None
             else datetime.datetime.now(datetime.timezone.utc).date())
    age_days = (today - gen_date).days
    # Reject future-dated bundles beyond a tiny clock-skew tolerance: a negative
    # age would otherwise sail through the "too old" check unchallenged.
    if age_days < -1:
        return False, f"bundle dated {-age_days}d in the future (clock skew or forgery)"
    if age_days > FRESHNESS_MAX_DAYS:
        return False, f"bundle {age_days}d old (> {FRESHNESS_MAX_DAYS}d)"
    return True, ""


def _check_floor(bundle, floor, cached_bundle=None, floor_digests=None):
    """Reject rollback and equal-version equivocation.

    A valid feed is commonly unchanged for several days.  Equal version with
    byte-equivalent pack content is therefore a successful CURRENT result, not
    rollback.  Equal version with different content is rejected because a
    publisher must increment pack_version for every content change.
    """
    packs = bundle.get("packs", {})
    if not isinstance(packs, dict) or not packs:
        return False, "bundle has no packs"
    for name, pack in packs.items():
        if not isinstance(pack, dict):
            return False, f"pack {name!r} not an object"
        pv = pack.get("pack_version")
        if isinstance(pv, bool) or not isinstance(pv, int):
            return False, f"pack {name!r} pack_version not an integer"
        floor_v = floor.get(name)
        if floor_v is not None and pv < floor_v:
            return False, f"pack {name!r} v{pv} < floor v{floor_v} (rollback rejected)"
        if floor_v is not None and pv == floor_v:
            accepted_digest = (floor_digests or {}).get(name)
            cached_pack = ((cached_bundle or {}).get("packs") or {}).get(name)
            if accepted_digest is not None:
                if _pack_digest(pack) != accepted_digest:
                    return False, (f"pack {name!r} v{pv} equals floor but content digest differs "
                                   "(equivocation rejected)")
            elif cached_pack is not None:
                if cached_pack != pack:
                    return False, (f"pack {name!r} v{pv} equals floor but content differs "
                                   "(equivocation rejected)")
            else:
                # Equal version but NO trusted reference (persisted digest or cached
                # bundle) survives to prove content equivalence. Fail closed rather
                # than accept a same-version pack whose content we cannot vouch for.
                return False, (f"pack {name!r} v{pv} equals floor but no reference remains "
                               "to verify content equivalence (equivocation rejected)")
    return True, ""


def _self_test_bundle(bundle):
    """Run every rule's example self-test in every pack (reuse rule_loader).
    Whole-bundle acceptance: ANY rule self-test failure rejects the bundle."""
    import rule_loader
    packs = bundle.get("packs", {})
    for name, pack in packs.items():
        rules = pack.get("rules", [])
        if not isinstance(rules, list):
            return False, f"pack {name!r} rules not a list"
        compiled = []
        for raw in rules:
            rule, reason = rule_loader._compile_rule(raw)
            if rule is None:
                # Retired rules legitimately compile to None; skip silently.
                if reason and reason.endswith(": retired"):
                    continue
                return False, f"pack {name!r}: rule rejected: {reason}"
            compiled.append(rule)
        cp = rule_loader.CompiledPack(name, pack.get("pack_version", 0),
                                      pack.get("schema_version", "1.0"),
                                      "<bundle>", compiled)
        for result in rule_loader.self_test_pack(cp):
            if not result.passed:
                return False, (f"pack {name!r}: rule {result.rule_id} self-test "
                               f"failed: {'; '.join(result.failures)}")
    return True, ""


def _new_floor(bundle, floor):
    """Updated floor = max(existing, each pack's pack_version)."""
    out = dict(floor)
    for name, pack in bundle.get("packs", {}).items():
        pv = pack.get("pack_version", 0)
        out[name] = max(out.get(name, 0), pv)
    return out


def accept_bundle(raw_bytes, sig_bytes, cache_dir=None, pubkey=None, now=None):
    """Run the full acceptance chain on freshly-fetched raw bytes + signature.

    Returns (accepted: bool, message: str, bundle: dict | None). On acceptance,
    the raw bytes + signature are written to the cache atomically and the floor
    is advanced. On any failure the cache is left UNTOUCHED.
    """
    # 1. signature over EXACT raw bytes, before any decode.
    if not verify_raw_bundle(raw_bytes, sig_bytes, pubkey=pubkey):
        return False, "signature verification failed", None
    # 2. JSON parse.
    try:
        bundle = json.loads(bytes(raw_bytes).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        return False, f"JSON parse failed: {e}", None
    if not isinstance(bundle, dict):
        return False, "bundle top-level not an object", None
    # 3. schema major gate.
    ok, why = _check_schema(bundle)
    if not ok:
        return False, why, None
    # 4. freshness gate.
    ok, why = _check_freshness(bundle, now=now)
    if not ok:
        return False, why, None
    # 5. persisted-floor rollback gate.
    floor = load_floor(cache_dir)
    cached_bundle = None
    try:
        with open(_bundle_path(cache_dir), "r", encoding="utf-8") as handle:
            value = json.load(handle)
        if isinstance(value, dict):
            cached_bundle = value
    except (OSError, ValueError):
        pass
    ok, why = _check_floor(bundle, floor, cached_bundle=cached_bundle,
                           floor_digests=load_floor_digests(cache_dir))
    if not ok:
        return False, why, None
    # 6. per-pack example self-tests (incl. ReDoS timeout).
    ok, why = _self_test_bundle(bundle)
    if not ok:
        return False, why, None
    # 7. transactional pair commit + floor update.
    _ensure_cache_dir(cache_dir)
    current_pair = read_verified_cached_pair(cache_dir, pubkey=pubkey, allow_previous=False)
    if current_pair is not None:
        current_raw, current_sig = current_pair
        _atomic_write_bytes(_previous_bundle_path(cache_dir), current_raw, mode=0o600)
        _atomic_write_bytes(_previous_sig_path(cache_dir), current_sig, mode=0o600)
    # Persist the EXACT signed bytes (binary write, no decode/encode round-trip)
    # so rule_loader's verify-on-load sees byte-identical content. Routing these
    # through a text-mode writer would let Windows rewrite \n -> \r\n and break
    # the detached-signature check on a legitimate bundle.
    try:
        _atomic_write_bytes(_bundle_path(cache_dir), bytes(raw_bytes), mode=0o600)
        # signature is binary: write atomically via temp+rename ourselves.
        _atomic_write_bytes(_sig_path(cache_dir), bytes(sig_bytes), mode=0o600)
    except OSError:
        _restore_previous_pair(cache_dir, pubkey=pubkey)
        raise
    _save_floor(_new_floor(bundle, floor), cache_dir)
    _save_floor_digests(bundle, cache_dir)
    return True, f"rule-pack bundle accepted (bundle_version={bundle.get('bundle_version')})", bundle


def _atomic_write_bytes(path, data, mode=0o600):
    """Atomic binary write (temp + fsync + rename), mirroring forensics_core."""
    import tempfile
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".sig")
    try:
        f = os.fdopen(fd, "wb")
    except BaseException:
        # fdopen never took ownership of fd: close it ourselves.
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


def _cache_is_fresh(cache_dir=None, ttl_hours=None):
    """True if the cached bundle file exists and is within TTL."""
    path = _bundle_path(cache_dir)
    if not os.path.exists(path):
        return False
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return False
    age_hours = (time.time() - mtime) / 3600
    max_age = ttl_hours if ttl_hours is not None else _BUNDLE_CACHE_TTL_HOURS
    return 0 <= age_hours <= max_age


def _validate_cached_bundle(cache_dir=None, pubkey=None, now=None):
    """Prove the supposedly-fresh cache is signed, valid, and loadable."""
    pair = read_verified_cached_pair(cache_dir, pubkey=pubkey)
    if pair is None:
        return False, "cached rule-pack pair unavailable or signature invalid"
    raw, sig = pair
    try:
        bundle = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return False, f"cached rule-pack JSON invalid: {exc}"
    if not isinstance(bundle, dict):
        return False, "cached rule-pack top-level not an object"
    for check in (_check_schema,):
        ok, why = check(bundle)
        if not ok:
            return False, why
    ok, why = _check_freshness(bundle, now=now)
    if not ok:
        return False, why
    ok, why = _self_test_bundle(bundle)
    if not ok:
        return False, why
    floor = load_floor(cache_dir)
    ok, why = _check_floor(bundle, floor, cached_bundle=bundle,
                           floor_digests=load_floor_digests(cache_dir))
    return (True, "cached rule-pack verified") if ok else (False, why)


# --- Public entry point -----------------------------------------------------

def update_rulepacks(feed_url=None, sig_url=None, cache_dir=None,
                     pubkey=None, now=None, force=False):
    """Fetch + verify + cache the signed rule-pack bundle.

    Mirrors ioc_manager.update_iocs() signature/return contract.

    Returns (success: bool, message: str). On success the verified bundle is
    cached (verify-on-load in rule_loader picks it up). On any failure the prior
    cache is untouched and the caller treats it as rule-pack-degraded.

    Cross-platform: runs anywhere (no macOS assumptions). Called by the daily
    refresher within its lock + 60s hard-cap discipline.
    """
    if not force and _cache_is_fresh(cache_dir):
        ok, why = _validate_cached_bundle(cache_dir, pubkey=pubkey, now=now)
        if ok:
            return True, "rule-pack cache current and verified (skipped fetch)"

    raw = _fetch_raw(feed_url or RULEPACK_FEED_URL, _FEED_MAX_BYTES)
    if raw is None:
        return False, "rule-pack feed fetch failed (shipped packs authoritative)"
    sig = _fetch_raw(sig_url or RULEPACK_FEED_SIG_URL, _SIG_MAX_BYTES)
    if sig is None:
        return False, "rule-pack signature fetch failed (shipped packs authoritative)"

    accepted, msg, _bundle = accept_bundle(
        raw, sig, cache_dir=cache_dir, pubkey=pubkey, now=now
    )
    return accepted, msg


def main():
    import argparse
    ap = argparse.ArgumentParser(description="repo-forensics signed rule-pack feed")
    ap.add_argument("--update", action="store_true", help="Fetch + verify + cache")
    ap.add_argument("--feed-url", default=None)
    ap.add_argument("--cache-dir", default=None)
    ap.add_argument("--force", action="store_true", help="Ignore cache TTL")
    args = ap.parse_args()
    if args.update:
        ok, msg = update_rulepacks(feed_url=args.feed_url, cache_dir=args.cache_dir,
                                   force=args.force)
        print(f"{'[+]' if ok else '[!]'} {msg}")
        sys.exit(0 if ok else 1)
    ap.print_help()


if __name__ == "__main__":
    main()
