"""U6 refresh-wiring tests: refresh_threat_dbs invokes update_rulepacks() within
its hard-cap/lock discipline, and the loader's self-test SIGALRM save/restore
composes with an outer 60s-style alarm (so the rule-pack self-tests inside the
feed updater never clobber the refresher's hard cap).

Offline: the network fetch is mocked; no real socket is opened.
"""

import importlib.util
import os
import sys

import pytest

import rule_loader

_SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")


# ---------------------------------------------------------------------------
# Composability: self-test alarm must not clobber an outer hard cap (POSIX).
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not hasattr(__import__("signal"), "SIGALRM"),
                    reason="SIGALRM-only composability check")
def test_self_test_preserves_outer_alarm():
    """refresh_threat_dbs arms a 60s SIGALRM then calls the feed updater, whose
    self-test step calls run_with_timeout. The save/restore logic must leave the
    outer alarm still pending (debited), never disarmed."""
    import signal
    fired = {"outer": False}

    def _outer_handler(signum, frame):
        fired["outer"] = True

    prev = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _outer_handler)
    signal.alarm(30)  # stand-in for the refresher's 60s hard cap
    try:
        # Run a fast self-test through the loader's timeout wrapper.
        rule_loader.run_with_timeout(lambda: 42, timeout=1)
        remaining = signal.alarm(0)  # read + clear the outer alarm
        # The outer alarm must still have been pending (not zeroed by the inner
        # self-test). It was debited by the (sub-second) inner run, so it is
        # > 0 and <= 30.
        assert 0 < remaining <= 30
        assert fired["outer"] is False
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, prev)


# ---------------------------------------------------------------------------
# refresh_threat_dbs._refresh_rulepacks wiring (darwin-only module).
# ---------------------------------------------------------------------------

def _load_refresh_module(monkeypatch):
    """Import refresh_threat_dbs with platform forced to darwin (its top-level
    bails on non-darwin). Returns the module."""
    monkeypatch.setattr(sys, "platform", "darwin")
    path = os.path.join(_SCRIPTS_DIR, "refresh_threat_dbs.py")
    spec = importlib.util.spec_from_file_location("refresh_threat_dbs_test", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pytest.skip("refresh_threat_dbs bailed at import (non-POSIX fcntl)")
    return mod


def _load_refresh_module_for_platform(monkeypatch, platform):
    monkeypatch.setattr(sys, "platform", platform)
    path = os.path.join(_SCRIPTS_DIR, "refresh_threat_dbs.py")
    spec = importlib.util.spec_from_file_location(
        f"refresh_threat_dbs_{platform}_test", path
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeFeed:
    """Stand-in for the rulepack_feed module loaded by the refresher."""
    def __init__(self, result):
        self._result = result
        self.calls = 0

    def update_rulepacks(self, *a, **k):
        self.calls += 1
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def _stub_feed_import(mod, monkeypatch, fake):
    """Patch the refresher's by-path importer so loading 'rulepack_feed' returns
    our fake (offline; no network)."""
    real = mod._import_module_by_path

    def _patched(name, path):
        if name == "rulepack_feed":
            return fake
        return real(name, path)
    monkeypatch.setattr(mod, "_import_module_by_path", _patched)
    monkeypatch.setattr(mod, "_log", lambda message: None)


@pytest.mark.skipif(sys.platform == "win32", reason="refresh uses fcntl (POSIX)")
def test_refresh_invokes_update_rulepacks(monkeypatch, tmp_path):
    mod = _load_refresh_module(monkeypatch)
    assert hasattr(mod, "_refresh_rulepacks"), "U6 wiring missing"
    fake = _FakeFeed((True, "mocked"))
    _stub_feed_import(mod, monkeypatch, fake)
    ok = mod._refresh_rulepacks(_SCRIPTS_DIR)
    assert ok is True
    assert fake.calls == 1


@pytest.mark.skipif(sys.platform == "win32", reason="refresh uses fcntl (POSIX)")
def test_refresh_rulepacks_swallows_exceptions(monkeypatch, tmp_path):
    mod = _load_refresh_module(monkeypatch)
    fake = _FakeFeed(RuntimeError("network exploded"))
    _stub_feed_import(mod, monkeypatch, fake)
    # Must NOT propagate (refresher always exits 0).
    assert mod._refresh_rulepacks(_SCRIPTS_DIR) is False


@pytest.mark.skipif(sys.platform == "win32", reason="refresh uses fcntl (POSIX)")
def test_refresh_main_calls_all_three(monkeypatch, tmp_path):
    """main() wires ioc + kev + rulepacks together under the lock + cap."""
    mod = _load_refresh_module(monkeypatch)
    seen = {"ioc": 0, "kev": 0, "rp": 0}
    monkeypatch.setattr(mod, "_refresh_iocs", lambda d: seen.__setitem__("ioc", seen["ioc"] + 1) or True)
    monkeypatch.setattr(mod, "_refresh_kev", lambda d: seen.__setitem__("kev", seen["kev"] + 1) or True)
    monkeypatch.setattr(mod, "_refresh_rulepacks", lambda d: seen.__setitem__("rp", seen["rp"] + 1) or True)
    monkeypatch.setattr(mod, "_resolve_scripts_dir", lambda: _SCRIPTS_DIR)
    monkeypatch.setattr(mod, "_acquire_lock", lambda: 999)
    monkeypatch.setattr(mod, "_write_marker", lambda forensics_core=None: None)
    monkeypatch.setattr(mod, "_write_state", lambda **updates: None)
    monkeypatch.setattr(mod, "LAST_ATTEMPT_MARKER", str(tmp_path / ".last-attempt"))
    monkeypatch.setattr(mod, "DISABLED_MARKER", str(tmp_path / "refresh.disabled"))
    monkeypatch.setattr(mod, "_log", lambda message: None)
    # Neutralize lock teardown (fd 999 is fake).
    import fcntl as _fcntl
    monkeypatch.setattr(_fcntl, "flock", lambda *a, **k: None)
    monkeypatch.setattr(os, "close", lambda fd: None)
    mod._worker_main()
    assert seen == {"ioc": 1, "kev": 1, "rp": 1}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX lock teardown fixture")
def test_refresh_main_does_not_mark_partial_failure_fresh(monkeypatch, tmp_path):
    mod = _load_refresh_module(monkeypatch)
    marker_writes = []
    monkeypatch.setattr(mod, "_refresh_iocs", lambda d: True)
    monkeypatch.setattr(mod, "_refresh_kev", lambda d: False)
    monkeypatch.setattr(mod, "_refresh_rulepacks", lambda d: True)
    monkeypatch.setattr(mod, "_resolve_scripts_dir", lambda: _SCRIPTS_DIR)
    monkeypatch.setattr(mod, "_acquire_lock", lambda: 999)
    monkeypatch.setattr(
        mod, "_write_marker", lambda forensics_core=None: marker_writes.append(True)
    )
    monkeypatch.setattr(mod, "_log", lambda message: None)
    monkeypatch.setattr(mod, "_write_state", lambda **updates: None)
    monkeypatch.setattr(mod, "LAST_ATTEMPT_MARKER", str(tmp_path / ".last-attempt"))
    monkeypatch.setattr(mod, "DISABLED_MARKER", str(tmp_path / "refresh.disabled"))
    import fcntl as _fcntl
    monkeypatch.setattr(_fcntl, "flock", lambda *a, **k: None)
    monkeypatch.setattr(os, "close", lambda fd: None)

    mod._worker_main()

    assert marker_writes == []


def test_refresh_resolver_prefers_invoked_plugin_over_stale_claude_cache(
        monkeypatch, tmp_path):
    mod = _load_refresh_module(monkeypatch)
    stale = (
        tmp_path / ".claude" / "plugins" / "cache" / "market" /
        "repo-forensics" / "99.0.0" / "skills" / "repo-forensics" / "scripts"
    )
    stale.mkdir(parents=True)
    for name in ("ioc_manager.py", "forensics_core.py", "vuln_feed.py"):
        (stale / name).write_text("# stale cache\n")
    monkeypatch.setenv("HOME", str(tmp_path))

    resolved = mod._resolve_scripts_dir()

    assert resolved == os.path.dirname(os.path.abspath(mod.__file__))


def test_refresh_module_loads_on_linux(monkeypatch):
    mod = _load_refresh_module_for_platform(monkeypatch, "linux")
    assert callable(mod.main)


def test_native_lock_roundtrip(monkeypatch, tmp_path):
    mod = _load_refresh_module_for_platform(monkeypatch, sys.platform)
    monkeypatch.setattr(mod, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(mod, "LOCK_FILE", str(tmp_path / "refresh.lock"))
    monkeypatch.setattr(mod, "LOG_FILE", str(tmp_path / "refresh.log"))

    first = mod._acquire_lock()
    assert first is not None
    try:
        assert mod._acquire_lock() is None
    finally:
        mod._release_lock(first)


def test_supervisor_records_cross_platform_timeout(monkeypatch, tmp_path):
    mod = _load_refresh_module_for_platform(monkeypatch, sys.platform)
    states = []
    monkeypatch.setattr(mod, "_log", lambda message: None)
    monkeypatch.setattr(mod, "_write_state", lambda **updates: states.append(updates))
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(mod.subprocess.TimeoutExpired(a[0], 0.01)),
    )

    assert mod.main([]) == 0
    assert states[-1]["status"] == "timeout"
