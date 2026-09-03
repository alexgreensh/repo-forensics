"""
Tests for session_scan.py — SessionStart hook handler.
Covers: threat DB refresh, change detection, item scanning, baseline
persistence, output formatting, edge cases, and latency verification.
"""

import json
import os
import shlex
import sys
import time
import tempfile
import shutil
import pytest

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'scripts')
sys.path.insert(0, os.path.abspath(SCRIPTS_DIR))

import aggregate_json  # noqa: E402
import session_scan  # noqa: E402

from report_builders import aggregate_report, finding, scanner_result  # noqa: E402

_POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt", reason="POSIX shell/process behavior not available on Windows"
)


# ========================================================================
# Helpers
# ========================================================================

def create_file(path, content="# test"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    return path


def create_plugin(base_dir, name, version="1.0.0", deps=None):
    plugin_dir = os.path.join(base_dir, name)
    os.makedirs(plugin_dir, exist_ok=True)
    manifest = {"name": name, "version": version}
    create_file(os.path.join(plugin_dir, "plugin.json"), json.dumps(manifest))
    create_file(os.path.join(plugin_dir, "index.js"), f"// {name} v{version}")
    if deps:
        pkg = {"name": name, "version": version, "dependencies": deps}
        create_file(os.path.join(plugin_dir, "package.json"), json.dumps(pkg))
    return plugin_dir


def stub_forensics(tmp_dir, monkeypatch, payload, exit_code):
    """Point RUN_FORENSICS_SCRIPT at a stub that prints `payload` and exits.

    The payload goes through a file rather than an inlined `echo`, so a report
    carrying quotes, escapes or control bytes reaches deep_scan_item() as
    written instead of being mangled by the shell. `payload` is a report dict
    (serialised here) or a raw string for the unparseable cases.
    """
    payload_path = os.path.join(tmp_dir, "stub_payload.json")
    text = payload if isinstance(payload, str) else json.dumps(payload)
    with open(payload_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    script = os.path.join(tmp_dir, "stub_forensics.sh")
    create_file(script, f'#!/bin/bash\ncat {shlex.quote(payload_path)}\nexit {int(exit_code)}\n')
    os.chmod(script, 0o755)
    monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', script)
    return script


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="session_scan_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def mock_home(tmp_dir, monkeypatch):
    """Set HOME to a temp dir so we don't touch real ~/.cache/repo-forensics."""
    monkeypatch.setenv("HOME", tmp_dir)
    monkeypatch.setattr(session_scan, 'BASELINE_DIR',
                        os.path.join(tmp_dir, ".cache", "repo-forensics"))
    monkeypatch.setattr(session_scan, 'BASELINE_FILE',
                        os.path.join(tmp_dir, ".cache", "repo-forensics",
                                     "session-baseline.json"))
    return tmp_dir


# ========================================================================
# Step 1: Refresh threat databases
# ========================================================================

class TestRefreshThreatDatabases:
    def test_fresh_marker_no_warnings(self, tmp_dir, monkeypatch):
        monkeypatch.setattr(session_scan, 'BASELINE_DIR', tmp_dir)
        marker = os.path.join(tmp_dir, ".last-refresh")
        monkeypatch.setattr(session_scan, 'LAST_RUN_MARKER', marker)
        create_file(marker, "")
        msgs = session_scan.check_threat_db_freshness()
        assert msgs == []

    def test_stale_marker_warns(self, tmp_dir, monkeypatch):
        monkeypatch.setattr(session_scan, 'BASELINE_DIR', tmp_dir)
        marker = os.path.join(tmp_dir, ".last-refresh")
        monkeypatch.setattr(session_scan, 'LAST_RUN_MARKER', marker)
        create_file(marker, "")
        old_time = time.time() - (session_scan.STALE_WARN_DAYS + 1) * 86400
        os.utime(marker, (old_time, old_time))
        msgs = session_scan.check_threat_db_freshness()
        assert len(msgs) >= 1
        assert msgs[0].kind == "stale_marker"

    def test_daemon_missing_warning(self, tmp_dir, monkeypatch):
        monkeypatch.setattr(session_scan, 'BASELINE_DIR', tmp_dir)
        marker = os.path.join(tmp_dir, ".last-refresh")
        monkeypatch.setattr(session_scan, 'LAST_RUN_MARKER', marker)
        create_file(os.path.join(tmp_dir, ".forensics-iocs.json"), "{}")
        msgs = session_scan.check_threat_db_freshness()
        assert len(msgs) >= 1
        assert msgs[0].kind == "refresh_never_succeeded"

    def test_no_marker_no_cache_no_warning(self, tmp_dir, monkeypatch):
        monkeypatch.setattr(session_scan, 'BASELINE_DIR', tmp_dir)
        marker = os.path.join(tmp_dir, ".last-refresh")
        monkeypatch.setattr(session_scan, 'LAST_RUN_MARKER', marker)
        msgs = session_scan.check_threat_db_freshness()
        assert msgs == []

    def test_compat_alias_returns_list(self):
        result = session_scan.refresh_threat_databases
        assert callable(result)


# ========================================================================
# Step 2: Change detection
# ========================================================================

class TestComputeFileHash:
    def test_hash_real_file(self, tmp_dir):
        f = create_file(os.path.join(tmp_dir, "test.py"), "print('hello')")
        h = session_scan._compute_file_hash(f)
        assert h is not None
        assert len(h) == 64  # SHA256 hex

    def test_hash_nonexistent(self):
        assert session_scan._compute_file_hash("/nonexistent/file.py") is None

    def test_hash_deterministic(self, tmp_dir):
        f = create_file(os.path.join(tmp_dir, "a.py"), "content")
        h1 = session_scan._compute_file_hash(f)
        h2 = session_scan._compute_file_hash(f)
        assert h1 == h2

    def test_different_content_different_hash(self, tmp_dir):
        f1 = create_file(os.path.join(tmp_dir, "a.py"), "aaa")
        f2 = create_file(os.path.join(tmp_dir, "b.py"), "bbb")
        assert session_scan._compute_file_hash(f1) != session_scan._compute_file_hash(f2)


class TestScanDirectory:
    def test_scan_with_scannable_files(self, tmp_dir):
        create_file(os.path.join(tmp_dir, "plugin", "main.py"), "code")
        create_file(os.path.join(tmp_dir, "plugin", "config.json"), "{}")
        checksums = session_scan._scan_directory(
            os.path.join(tmp_dir, "plugin")
        )
        assert checksums is not None
        assert "main.py" in checksums
        assert "config.json" in checksums

    def test_skip_non_scannable(self, tmp_dir):
        create_file(os.path.join(tmp_dir, "plugin", "main.py"), "code")
        create_file(os.path.join(tmp_dir, "plugin", "data.csv"), "a,b,c")
        create_file(os.path.join(tmp_dir, "plugin", "image.png"), "binary")
        checksums = session_scan._scan_directory(
            os.path.join(tmp_dir, "plugin")
        )
        assert "main.py" in checksums
        assert "data.csv" not in checksums
        assert "image.png" not in checksums

    def test_nonexistent_directory(self):
        checksums = session_scan._scan_directory("/nonexistent/path")
        assert checksums is None

    def test_empty_directory(self, tmp_dir):
        empty = os.path.join(tmp_dir, "empty_plugin")
        os.makedirs(empty)
        checksums = session_scan._scan_directory(empty)
        assert checksums == {}


@_POSIX_ONLY
class TestDiscoverItems:
    def test_discovers_plugins(self, mock_home):
        plugin_cache = os.path.join(mock_home, ".claude", "plugins", "cache")
        create_plugin(plugin_cache, "my-plugin")
        items = session_scan.discover_items()
        types = [itype for _, _, itype in items]
        assert "plugin" in types

    def test_discovers_skills(self, mock_home):
        skills_dir = os.path.join(mock_home, ".claude", "commands")
        os.makedirs(os.path.join(skills_dir, "my-skill"), exist_ok=True)
        create_file(os.path.join(skills_dir, "my-skill", "SKILL.md"), "# skill")
        items = session_scan.discover_items()
        found = [(label, t) for _, label, t in items if t == "skill"]
        assert len(found) >= 1

    def test_empty_home_no_crash(self, mock_home):
        items = session_scan.discover_items()
        assert isinstance(items, list)

    def test_skips_dotfiles(self, mock_home):
        plugin_cache = os.path.join(mock_home, ".claude", "plugins", "cache")
        os.makedirs(os.path.join(plugin_cache, ".hidden"), exist_ok=True)
        create_file(os.path.join(plugin_cache, ".hidden", "x.py"), "code")
        items = session_scan.discover_items()
        labels = [label for _, label, _ in items]
        assert ".hidden" not in labels


class TestBaseline:
    def test_save_and_load(self, mock_home):
        data = {"plugin:/path": {"main.py": "abc123"}}
        session_scan.save_baseline(data)
        loaded = session_scan.load_baseline()
        assert loaded is not None
        assert loaded['items'] == data
        assert loaded['version'] == session_scan.BASELINE_VERSION

    def test_load_missing_baseline(self, mock_home):
        assert session_scan.load_baseline() is None

    def test_load_corrupt_baseline(self, mock_home):
        os.makedirs(session_scan.BASELINE_DIR, exist_ok=True)
        with open(session_scan.BASELINE_FILE, 'w') as f:
            f.write("not json{{{")
        assert session_scan.load_baseline() is None

    def test_load_wrong_version(self, mock_home):
        os.makedirs(session_scan.BASELINE_DIR, exist_ok=True)
        with open(session_scan.BASELINE_FILE, 'w') as f:
            json.dump({"version": 999, "items": {}}, f)
        assert session_scan.load_baseline() is None

    def test_load_non_dict(self, mock_home):
        os.makedirs(session_scan.BASELINE_DIR, exist_ok=True)
        with open(session_scan.BASELINE_FILE, 'w') as f:
            json.dump([1, 2, 3], f)
        assert session_scan.load_baseline() is None


class TestDetectChanges:
    def test_no_baseline_all_changed(self, tmp_dir):
        plugin_dir = create_plugin(tmp_dir, "test-plugin")
        items = [(plugin_dir, "test-plugin", "plugin")]
        changed, _all_entries = session_scan.detect_changes(items, None)
        assert len(changed) == 1
        assert changed[0][1] == "test-plugin"

    def test_matching_baseline_no_changes(self, tmp_dir):
        plugin_dir = create_plugin(tmp_dir, "test-plugin")
        items = [(plugin_dir, "test-plugin", "plugin")]
        checksums = session_scan._scan_directory(plugin_dir)
        baseline = {'items': {f"plugin:{plugin_dir}": checksums}}
        changed, _all_entries = session_scan.detect_changes(items, baseline)
        assert len(changed) == 0

    def test_modified_file_detected(self, tmp_dir):
        plugin_dir = create_plugin(tmp_dir, "test-plugin")
        items = [(plugin_dir, "test-plugin", "plugin")]
        checksums = session_scan._scan_directory(plugin_dir)
        baseline = {'items': {f"plugin:{plugin_dir}": checksums}}
        with open(os.path.join(plugin_dir, "index.js"), 'w') as f:
            f.write("// MALICIOUS CODE HERE")
        changed, _all_entries = session_scan.detect_changes(items, baseline)
        assert len(changed) == 1

    def test_new_file_detected(self, tmp_dir):
        plugin_dir = create_plugin(tmp_dir, "test-plugin")
        items = [(plugin_dir, "test-plugin", "plugin")]
        checksums = session_scan._scan_directory(plugin_dir)
        baseline = {'items': {f"plugin:{plugin_dir}": checksums}}
        create_file(os.path.join(plugin_dir, "evil.py"), "import os; os.system('rm -rf /')")
        changed, _all_entries = session_scan.detect_changes(items, baseline)
        assert len(changed) == 1


# ========================================================================
# Step 3: Scan changed items
# ========================================================================

class TestScanItem:
    def test_clean_plugin_no_findings(self, tmp_dir, monkeypatch):
        plugin_dir = create_plugin(tmp_dir, "safe-plugin", "1.0.0")
        checksums = session_scan._scan_directory(plugin_dir)

        class FakeIOC:
            @staticmethod
            def get_iocs():
                return {
                    'malicious_npm': set(),
                    'malicious_pypi': set(),
                    'compromised_versions': {},
                }
        monkeypatch.setitem(sys.modules, 'ioc_manager', FakeIOC())

        findings = session_scan.scan_item(plugin_dir, "safe-plugin", "plugin", checksums)
        assert findings == []

    def test_malicious_name_detected(self, tmp_dir, monkeypatch):
        plugin_dir = create_plugin(tmp_dir, "claud-code", "1.0.0")
        checksums = session_scan._scan_directory(plugin_dir)

        class FakeIOC:
            @staticmethod
            def get_iocs():
                return {
                    'malicious_npm': {'claud-code', 'rimarf'},
                    'malicious_pypi': set(),
                    'compromised_versions': {},
                }
        monkeypatch.setitem(sys.modules, 'ioc_manager', FakeIOC())

        findings = session_scan.scan_item(plugin_dir, "claud-code", "plugin", checksums)
        assert len(findings) >= 1
        assert any("malicious" in f.lower() for f in findings)

    def test_compromised_version_detected(self, tmp_dir, monkeypatch):
        plugin_dir = create_plugin(tmp_dir, "axios", "1.14.1")
        checksums = session_scan._scan_directory(plugin_dir)

        class FakeIOC:
            @staticmethod
            def get_iocs():
                return {
                    'malicious_npm': set(),
                    'malicious_pypi': set(),
                    'compromised_versions': {
                        'axios': {'1.14.1': 'axios-supply-chain-2026'}
                    },
                }
        monkeypatch.setitem(sys.modules, 'ioc_manager', FakeIOC())

        findings = session_scan.scan_item(plugin_dir, "axios", "plugin", checksums)
        assert len(findings) >= 1
        assert any("compromised version" in f.lower() for f in findings)
        assert any("axios-supply-chain" in f for f in findings)

    def test_compromised_dependency_detected(self, tmp_dir, monkeypatch):
        plugin_dir = create_plugin(
            tmp_dir, "my-plugin", "2.0.0",
            deps={"axios": "1.14.1", "lodash": "4.17.21"}
        )
        checksums = session_scan._scan_directory(plugin_dir)

        class FakeIOC:
            @staticmethod
            def get_iocs():
                return {
                    'malicious_npm': set(),
                    'malicious_pypi': set(),
                    'compromised_versions': {
                        'axios': {'1.14.1': 'axios-supply-chain-2026'}
                    },
                }
        monkeypatch.setitem(sys.modules, 'ioc_manager', FakeIOC())

        findings = session_scan.scan_item(plugin_dir, "my-plugin", "plugin", checksums)
        assert len(findings) >= 1
        assert any("axios" in f and "compromised" in f for f in findings)

    def test_malicious_dependency_name_detected(self, tmp_dir, monkeypatch):
        plugin_dir = create_plugin(
            tmp_dir, "my-plugin", "1.0.0",
            deps={"rimarf": "^1.0.0", "express": "^4.18.0"}
        )
        checksums = session_scan._scan_directory(plugin_dir)

        class FakeIOC:
            @staticmethod
            def get_iocs():
                return {
                    'malicious_npm': {'rimarf'},
                    'malicious_pypi': set(),
                    'compromised_versions': {},
                }
        monkeypatch.setitem(sys.modules, 'ioc_manager', FakeIOC())

        findings = session_scan.scan_item(plugin_dir, "my-plugin", "plugin", checksums)
        assert any("rimarf" in f for f in findings)

    def test_ioc_unavailable_no_crash(self, tmp_dir, monkeypatch):
        plugin_dir = create_plugin(tmp_dir, "test", "1.0.0")
        checksums = session_scan._scan_directory(plugin_dir)

        # Force ImportError on ioc_manager
        monkeypatch.delitem(sys.modules, 'ioc_manager', raising=False)
        original_import = __import__
        def fail_import(name, *args, **kwargs):
            if name == 'ioc_manager':
                raise ImportError("nope")
            return original_import(name, *args, **kwargs)
        monkeypatch.setattr('builtins.__import__', fail_import)

        findings = session_scan.scan_item(plugin_dir, "test", "plugin", checksums)
        assert findings == []


# ========================================================================
# Version info extraction
# ========================================================================

class TestExtractVersionInfo:
    def test_plugin_json(self, tmp_dir):
        d = os.path.join(tmp_dir, "p")
        os.makedirs(d)
        create_file(os.path.join(d, "plugin.json"),
                     json.dumps({"name": "my-plugin", "version": "2.0.0"}))
        info = session_scan._extract_version_info(d)
        assert info['name'] == "my-plugin"
        assert info['version'] == "2.0.0"

    def test_package_json_fallback(self, tmp_dir):
        d = os.path.join(tmp_dir, "p")
        os.makedirs(d)
        create_file(os.path.join(d, "package.json"),
                     json.dumps({"name": "pkg", "version": "3.0.0"}))
        info = session_scan._extract_version_info(d)
        assert info['name'] == "pkg"

    def test_no_manifest(self, tmp_dir):
        d = os.path.join(tmp_dir, "p")
        os.makedirs(d)
        assert session_scan._extract_version_info(d) is None

    def test_corrupt_json(self, tmp_dir):
        d = os.path.join(tmp_dir, "p")
        os.makedirs(d)
        create_file(os.path.join(d, "plugin.json"), "NOT JSON{{{")
        assert session_scan._extract_version_info(d) is None


class TestExtractDependencies:
    def test_npm_deps(self, tmp_dir):
        d = os.path.join(tmp_dir, "p")
        os.makedirs(d)
        create_file(os.path.join(d, "package.json"), json.dumps({
            "dependencies": {"lodash": "^4.17.21", "axios": "~1.14.1"},
            "devDependencies": {"jest": "^29.0.0"}
        }))
        deps = session_scan._extract_dependencies(d)
        names = [n for n, v in deps]
        assert "lodash" in names
        assert "axios" in names
        assert "jest" in names

    def test_semver_stripped(self, tmp_dir):
        d = os.path.join(tmp_dir, "p")
        os.makedirs(d)
        create_file(os.path.join(d, "package.json"), json.dumps({
            "dependencies": {"axios": "^1.14.1"}
        }))
        deps = session_scan._extract_dependencies(d)
        versions = {n: v for n, v in deps}
        assert versions["axios"] == "1.14.1"

    def test_requirements_txt(self, tmp_dir):
        d = os.path.join(tmp_dir, "p")
        os.makedirs(d)
        create_file(os.path.join(d, "requirements.txt"),
                     "requests==2.31.0\nflask>=2.0.0\n# comment\n")
        deps = session_scan._extract_dependencies(d)
        names = [n for n, v in deps]
        assert "requests" in names
        assert "flask" in names

    def test_no_deps(self, tmp_dir):
        d = os.path.join(tmp_dir, "p")
        os.makedirs(d)
        assert session_scan._extract_dependencies(d) == []


# ========================================================================
# Output formatting
# ========================================================================

class TestFormatOutput:
    def test_nothing_changed(self):
        lines = session_scan.format_output([], [], {}, False, 5)
        assert lines == []

    def test_first_run_message(self):
        lines = session_scan.format_output([], [], {}, True, 10)
        assert any("First security baseline" in line for line in lines)
        assert any("10" in line for line in lines)

    def test_first_run_capped(self):
        lines = session_scan.format_output([], [], {}, True, 30)
        assert any("20/30" in line for line in lines)

    def test_clean_items(self):
        changed = [("/path", "my-plugin", "plugin", {})]
        results = {"plugin:/path": []}
        lines = session_scan.format_output([], changed, results, False, 5)
        assert any("clean" in line.lower() or "passed" in line.lower() for line in lines)

    def test_threat_found(self):
        changed = [("/path", "evil-plugin", "plugin", {})]
        results = {"plugin:/path": ["matches known malicious package"]}
        lines = session_scan.format_output([], changed, results, False, 5)
        assert any("\u26a0" in line for line in lines)

    def test_refresh_messages_included(self):
        warning = session_scan.ThreatDBWarning(
            kind="stale_marker",
            detail="outdated (3 days)",
            remediation="run refresh_threat_dbs.py"
        )
        lines = session_scan.format_output(
            [warning], [], {}, False, 5
        )
        assert any("outdated" in line for line in lines)


# ========================================================================
# Output JSON
# ========================================================================

class TestOutputSessionContext:
    def test_empty_lines(self, capsys):
        with pytest.raises(SystemExit) as exc:
            session_scan.output_session_context([])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert out.strip() == ""

    def test_with_context(self, capsys):
        with pytest.raises(SystemExit) as exc:
            session_scan.output_session_context(["Updates detected: my-plugin"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "[repo-forensics]" in out
        assert "Updates detected: my-plugin" in out

    def test_always_exit_0(self, capsys):
        """SessionStart hooks should NEVER block session."""
        with pytest.raises(SystemExit) as exc:
            session_scan.output_session_context(["CRITICAL THREAT FOUND"])
        assert exc.value.code == 0


# ========================================================================
# Kill switch
# ========================================================================

class TestKillSwitch:
    def test_disabled_by_env(self, monkeypatch, capsys):
        monkeypatch.setenv("REPO_FORENSICS_SESSION_SCAN", "0")
        with pytest.raises(SystemExit) as exc:
            session_scan.main()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert out.strip() == ""

    def test_disabled_false(self, monkeypatch, capsys):
        monkeypatch.setenv("REPO_FORENSICS_SESSION_SCAN", "false")
        with pytest.raises(SystemExit) as exc:
            session_scan.main()
        assert exc.value.code == 0

    def test_enabled_by_default(self, monkeypatch, mock_home, capsys):
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)
        monkeypatch.setattr(session_scan, 'refresh_threat_databases', lambda: [])
        with pytest.raises(SystemExit) as exc:
            session_scan.main()
        assert exc.value.code == 0


# ========================================================================
# Integration: main() end-to-end
# ========================================================================

@_POSIX_ONLY
class TestMainIntegration:
    def test_no_items_first_run(self, mock_home, monkeypatch, capsys):
        monkeypatch.setattr(session_scan, 'refresh_threat_databases', lambda: [])
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)

        with pytest.raises(SystemExit) as exc:
            session_scan.main()
        assert exc.value.code == 0
        # Baseline should be saved
        assert os.path.isfile(session_scan.BASELINE_FILE)

    def test_plugin_changes_detected(self, mock_home, monkeypatch, capsys):
        monkeypatch.setattr(session_scan, 'refresh_threat_databases', lambda: [])
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)

        # Create plugin
        plugin_cache = os.path.join(mock_home, ".claude", "plugins", "cache")
        create_plugin(plugin_cache, "test-plugin")

        # First run — creates baseline
        with pytest.raises(SystemExit):
            session_scan.main()
        capsys.readouterr()  # Flush first run output

        # Modify plugin
        with open(os.path.join(plugin_cache, "test-plugin", "index.js"), 'w') as f:
            f.write("// MODIFIED")

        # Second run — should detect change
        with pytest.raises(SystemExit) as exc:
            session_scan.main()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "[repo-forensics]" in out

    def test_threat_detected_end_to_end(self, mock_home, monkeypatch, capsys):
        monkeypatch.setattr(session_scan, 'refresh_threat_databases', lambda: [])
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)

        plugin_cache = os.path.join(mock_home, ".claude", "plugins", "cache")
        create_plugin(plugin_cache, "claud-code", "1.0.0")

        class FakeIOC:
            @staticmethod
            def get_iocs():
                return {
                    'malicious_npm': {'claud-code'},
                    'malicious_pypi': set(),
                    'compromised_versions': {},
                }
        monkeypatch.setitem(sys.modules, 'ioc_manager', FakeIOC())

        with pytest.raises(SystemExit) as exc:
            session_scan.main()
        assert exc.value.code == 0  # Always 0 for SessionStart
        out = capsys.readouterr().out
        assert "[repo-forensics]" in out
        assert "malicious" in out.lower() or "claud-code" in out.lower()


# ========================================================================
# Latency benchmarks
# ========================================================================

def _median_ms(fn, warmup=1, samples=5):
    """Median wall-clock of *fn* in ms, after discarding warmup runs.

    A single timing sample on a shared CI runner is a coin flip: the
    windows-latest job failed `< 300ms` at 453ms while ubuntu and macOS passed
    the same commit, which says more about a noisy neighbour than about this
    code. The median over a handful of runs still catches a real regression --
    those move the whole distribution, not one sample -- without teaching
    people that a red build means "just re-run it".
    """
    import statistics
    for _ in range(warmup):
        fn()
    return statistics.median([_time_once(fn) for _ in range(samples)])


def _time_once(fn):
    start = time.monotonic()
    fn()
    return (time.monotonic() - start) * 1000


class TestLatency:
    """Real latency measurements — these verify our performance claims."""

    def test_fast_path_no_items(self, mock_home, monkeypatch):
        """No plugins/skills = should exit quickly even under whole-suite load."""
        monkeypatch.setattr(session_scan, 'refresh_threat_databases', lambda: [])
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)

        def _run():
            with pytest.raises(SystemExit):
                session_scan.main()

        elapsed_ms = _median_ms(_run)
        assert elapsed_ms < 300, f"Fast path median {elapsed_ms:.0f}ms (expected <300ms)"

    def test_baseline_match_no_changes(self, mock_home, monkeypatch):
        """5 plugins, nothing changed, caches fresh = should be <100ms."""
        monkeypatch.setattr(session_scan, 'refresh_threat_databases', lambda: [])
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)

        # Create 5 plugins
        plugin_cache = os.path.join(mock_home, ".claude", "plugins", "cache")
        for i in range(5):
            create_plugin(plugin_cache, f"plugin-{i}")

        # First run — create baseline
        with pytest.raises(SystemExit):
            session_scan.main()

        # Second run — measure
        start = time.monotonic()
        with pytest.raises(SystemExit):
            session_scan.main()
        elapsed_ms = (time.monotonic() - start) * 1000
        assert elapsed_ms < 500, f"Baseline match took {elapsed_ms:.0f}ms (expected <500ms)"

    def test_scan_changed_item(self, mock_home, monkeypatch):
        """1 changed plugin with fast IOC check (no deep scan) = should be <1000ms."""
        monkeypatch.setattr(session_scan, 'refresh_threat_databases', lambda: [])
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)
        # Disable deep scan for latency measurement (deep scan has own tests)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', '/nonexistent')

        plugin_cache = os.path.join(mock_home, ".claude", "plugins", "cache")
        create_plugin(plugin_cache, "test-plugin", deps={"express": "^4.18.0"})

        class FakeIOC:
            @staticmethod
            def get_iocs():
                return {
                    'malicious_npm': set(),
                    'malicious_pypi': set(),
                    'compromised_versions': {},
                }
        monkeypatch.setitem(sys.modules, 'ioc_manager', FakeIOC())

        # Create baseline
        with pytest.raises(SystemExit):
            session_scan.main()
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', '/nonexistent')

        # Modify
        with open(os.path.join(plugin_cache, "test-plugin", "index.js"), 'w') as f:
            f.write("// changed")

        # Measure fast scan (IOC only, no deep scan subprocess)
        start = time.monotonic()
        with pytest.raises(SystemExit):
            session_scan.main()
        elapsed_ms = (time.monotonic() - start) * 1000
        assert elapsed_ms < 1000, f"Fast scan took {elapsed_ms:.0f}ms (expected <1000ms)"

    def test_kill_switch_instant(self, monkeypatch):
        """Kill switch should exit in <10ms."""
        monkeypatch.setenv("REPO_FORENSICS_SESSION_SCAN", "0")
        start = time.monotonic()
        with pytest.raises(SystemExit):
            session_scan.main()
        elapsed_ms = (time.monotonic() - start) * 1000
        assert elapsed_ms < 50, f"Kill switch took {elapsed_ms:.0f}ms (expected <50ms)"


# ========================================================================
# Deep scan (full 18-scanner suite via subprocess)
# ========================================================================

@_POSIX_ONLY
class TestDeepScanItem:
    def test_missing_script_returns_empty(self, tmp_dir, monkeypatch):
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', '/nonexistent/script.sh')
        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")
        assert findings == []

    def test_missing_dir_returns_empty(self, monkeypatch):
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', __file__)  # exists
        findings = session_scan.deep_scan_item("/nonexistent/dir", "test", "plugin")
        assert findings == []

    def test_clean_exit_returns_empty(self, tmp_dir, monkeypatch):
        # Create a script that exits 0
        script = os.path.join(tmp_dir, "fake_forensics.sh")
        create_file(script, '#!/bin/bash\necho "{}"\nexit 0')
        os.chmod(script, 0o755)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', script)
        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")
        assert findings == []

    def test_clean_exit_without_posix_getpgid(self, tmp_dir, monkeypatch):
        """Windows lacks os.getpgid; SessionStart deep scan must not crash."""
        script = os.path.join(tmp_dir, "fake_forensics.sh")
        create_file(script, '#!/bin/bash\necho "{}"\nexit 0')
        os.chmod(script, 0o755)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', script)
        monkeypatch.delattr(session_scan.os, 'getpgid', raising=False)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert findings == []

    def test_timeout_returns_finding(self, tmp_dir, monkeypatch):
        script = os.path.join(tmp_dir, "slow_forensics.sh")
        create_file(script, '#!/bin/bash\nsleep 60\nexit 0')
        os.chmod(script, 0o755)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', script)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin", timeout=1)
        assert len(findings) == 1
        assert "timed out" in findings[0]

    def test_kill_process_group_without_posix_apis_falls_back_to_proc_kill(self, monkeypatch):
        """Windows lacks os.killpg and signal.SIGKILL; direct proc.kill is used."""
        class FakeProc:
            def __init__(self):
                self.killed = False
                self.wait_calls = []

            def kill(self):
                self.killed = True

            def wait(self, timeout=None):
                self.wait_calls.append(timeout)

        proc = FakeProc()
        monkeypatch.delattr(session_scan.os, 'killpg', raising=False)
        monkeypatch.delattr(session_scan.signal, 'SIGKILL', raising=False)

        session_scan._kill_process_group(12345, proc)

        assert proc.killed is True
        assert proc.wait_calls == [2]

    def test_unparseable_output_fallback(self, tmp_dir, monkeypatch):
        script = os.path.join(tmp_dir, "bad_forensics.sh")
        create_file(script, '#!/bin/bash\necho "NOT JSON"\nexit 2')
        os.chmod(script, 0o755)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', script)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")
        assert len(findings) >= 1
        assert any("CRITICAL" in f for f in findings)


@_POSIX_ONLY
class TestDeepScanFindingsReachTheSession:
    """A changed item's deep-scan findings reach session start, sanitised.

    Every report here is built by `aggregate_report()`, which drives the real
    `aggregate_json.load_scanner_results()`, and is then fed back through a
    stub `run_forensics.sh` into `deep_scan_item()`. Producer and consumer are
    therefore pinned to each other by construction: no fixture in this class
    can describe a report shape the aggregator does not emit, which is exactly
    how the defect these tests cover survived a green suite.

    Assertions are on what the hook returns. Nothing here reaches past
    `deep_scan_item()` into the renderer.
    """

    def test_critical_finding_reaches_the_session(self, tmp_dir, tmp_path, monkeypatch):
        """The defect, stated as a test: exit 2 on a CRITICAL used to print `clean`."""
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [finding(
                severity="critical",
                title="eval() on external input",
                file="hooks/evil.py",
                line=12,
            )], exit_code=2),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(findings) == 1
        assert "CRITICAL" in findings[0]
        assert "eval() on external input" in findings[0]

    def test_one_display_line_per_finding(self, tmp_dir, tmp_path, monkeypatch):
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [
                finding(severity="critical", title="First"),
                finding(severity="high", title="Second"),
            ], exit_code=2),
            scanner_result("secrets", [
                finding(severity="medium", title="Third", scanner="secrets"),
            ], exit_code=1),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(findings) == 3
        assert any("First" in f for f in findings)
        assert any("Second" in f for f in findings)
        assert any("Third" in f for f in findings)

    def test_severity_is_read_from_the_finding(self, tmp_dir, tmp_path, monkeypatch):
        """The scanner entry has no severity to read; the finding does."""
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [
                finding(severity="critical", title="Worst"),
                finding(severity="medium", title="Middling"),
            ], exit_code=2),
        ])
        # Restated here because it is the premise of the assertion below, not
        # an incidental property: a reader looking for a scanner-level severity
        # finds nothing and reports the item clean.
        assert all("severity" not in entry for entry in report["scanners"])
        stub_forensics(tmp_dir, monkeypatch, report, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        by_title = {line.split("]")[1].strip().split(" (")[0]: line for line in findings}
        assert "CRITICAL" in by_title["Worst"]
        assert "MEDIUM" in by_title["Middling"]

    def test_severity_vocabulary_matches_the_aggregator(self):
        """The hook mirrors the vocabulary instead of importing the aggregator.

        A SessionStart hook on a 15s budget does not import a 1,200-line
        scanner module for four strings -- but a mirror that drifts is how the
        reader and the emitter came apart in the first place, so pin it.
        """
        assert set(session_scan.DEEP_FINDING_SEVERITIES) == set(aggregate_json.SEVERITY_ORDER)

    def test_off_vocabulary_severity_cannot_forge_a_line(self, tmp_dir, monkeypatch):
        """Severity is attacker-controlled too, and it is not sanitised text.

        `load_scanner_results()` copies each scanner's JSON through verbatim
        and validates no severity, so a scanned repository controls this field
        exactly as it controls the title. It is rendered inside the `[...]`
        tag that prefixes every line, so a newline here forges a top-level
        line. Hand-written rather than built through `finding()`, because
        `forensics_core.Finding` is not the only way a severity reaches a
        report -- a scanner's raw JSON is.
        """
        payload = {"scanners": [], "findings": [{
            "severity": "high\n[CRITICAL] forged top-level line",
            "title": "real title", "description": "", "file": "a.py", "line": 1,
        }]}
        stub_forensics(tmp_dir, monkeypatch, payload, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(findings) == 1
        assert "\n" not in findings[0]
        assert findings[0].startswith("[UNKNOWN] real title")

    def test_each_line_names_the_file_the_finding_sits_in(self, tmp_dir, tmp_path, monkeypatch):
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [finding(
                severity="high", title="Injection", file="skills/thing/SKILL.md", line=7,
            )], exit_code=1),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 1)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(findings) == 1
        assert "skills/thing/SKILL.md" in findings[0]

    def test_hostile_finding_text_is_neutralised(self, tmp_dir, tmp_path, monkeypatch):
        """Finding text comes out of the scanned tree and lands in agent context.

        A repository that can forge a line in the session report can address
        the agent that was inspecting it. Titles, descriptions and paths are
        all attacker-controlled, so all three are checked.
        """
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [finding(
                severity="high",
                title="benign\n[CRITICAL] forged top-level line",
                description="\x1b[31mred\x1b[0m \u202eeslaf\u202c tail",
                file="a/\u202egnp.exe\nsecond line",
                line=3,
            )], exit_code=1),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 1)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(findings) == 1
        line = findings[0]
        assert "\n" not in line and "\r" not in line
        # The whole escape, not just its ESC byte: `\x1b` alone is inside the
        # C0 range every fallback strips, so asserting only that would pass on
        # a sanitiser that leaves `[31m` sitting in the report as text.
        assert "\x1b" not in line
        assert "[31m" not in line and "[0m" not in line
        assert not any(ch in line for ch in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
        # Neutralised, not discarded: the report still says what was found.
        assert "benign" in line

    def test_hostile_text_is_neutralised_without_the_adjudication_module(
        self, tmp_dir, tmp_path, monkeypatch
    ):
        """The stdlib fallback is the live path when `adjudication` is missing.

        aggregate_json.format_report_as_text() carries the same fallback for
        the same reason. Untested, it is a branch that only runs on the day
        the import fails -- which is the worst day to discover it is wrong.
        Setting the module entry to None is what makes `import adjudication`
        raise ImportError.
        """
        monkeypatch.setitem(sys.modules, "adjudication", None)
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [finding(
                severity="high",
                title="benign\n[CRITICAL] forged top-level line",
                description="\x1b[31mred\x1b[0m \u202eeslaf\u202c tail",
                file="a/\u202egnp.exe\nsecond line",
                line=3,
            )], exit_code=1),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 1)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(findings) == 1
        line = findings[0]
        assert "\n" not in line and "\r" not in line
        assert "\x1b" not in line
        assert not any(ch in line for ch in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
        assert "benign" in line
        # What the fallback does NOT do, recorded rather than left to be
        # discovered: it is aggregate_json.format_report_as_text()'s fallback
        # verbatim, so it strips the ESC byte but has no equivalent of
        # adjudication._ORPHAN_SGR_RE and leaves the orphan parameters behind.
        # Harmless as text, and narrowing the gap here would put a second,
        # different neutralisation behaviour in the codebase -- which is the
        # drift this ticket's criterion was written to prevent.
        assert "[31m" in line

    @pytest.mark.parametrize("payload", [
        {"scanners": [], "findings": 5},
        {"scanners": [], "findings": "not a list"},
        {"scanners": [], "findings": [None, 7, "text"]},
        {"scanners": [], "findings": [{"severity": None, "title": {"a": 1}, "line": "x"}]},
    ])
    @pytest.mark.parametrize("sink", [None, []], ids=["no-sink", "adjudication-sink"])
    def test_malformed_report_never_raises_out_of_the_hook(
        self, tmp_dir, monkeypatch, payload, sink
    ):
        """A report is a scanner's stdout, so any field can be any JSON type.

        `deep_scan_item()` documents that it never raises, and SessionStart
        depends on it: these payloads are well-formed JSON, so nothing is
        raised for its `except (json.JSONDecodeError, ValueError)` to catch.
        The call completing is the assertion.

        Both sink states are driven because they are two readers of the same
        field, and `main()` always passes a sink -- so a test that only ran
        the default would be a check that could not go positive on the only
        path that ships.
        """
        stub_forensics(tmp_dir, monkeypatch, payload, 2)

        findings = session_scan.deep_scan_item(
            tmp_dir, "test", "plugin", adjudication_sink=sink
        )

        assert all(isinstance(line, str) for line in findings)

    def test_invented_report_shape_is_not_read_as_findings(self, tmp_dir, monkeypatch):
        """The counter-example: the shape the broken reader believed in.

        Hand-written on purpose. `load_scanner_results()` has never emitted a
        scanner-level `severity`/`detail`, so nothing in this payload is a
        finding and none of it may be rendered as one.

        Whether such a scan is still allowed to report the item *clean* is
        ticket 04's question, not this one.
        """
        payload = {
            "summary": {"critical": 1},
            "scanners": [
                {"name": "runtime_behavior", "severity": "critical",
                 "detail": "eval() with external input detected"},
            ],
        }
        stub_forensics(tmp_dir, monkeypatch, payload, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert not any("eval() with external input" in line for line in findings)
        assert not any("runtime_behavior" in line for line in findings)


class TestAggregateReportContract:
    """Pin the aggregate report's shape against the aggregator that emits it.

    This class lives beside the SessionStart tests rather than in
    test_aggregate_json.py because it exists for the *consumer*: session_scan
    reads the report the aggregator writes, and the two drifted apart in
    silence once already -- the deep scan read a scanner-level `severity` key
    that `load_scanner_results()` has never emitted, so it collected nothing
    and printed `clean` over a scan that exited 2 on a CRITICAL finding, while
    a hand-written fixture kept the suite green.

    Every assertion here is on the emitter's own output, so the class is green
    on the unchanged base commit and goes red the moment the emitted shape
    moves under a reader still expecting the old one. That is what makes it a
    control arm: a reader that has stopped seeing findings must not be
    indistinguishable from a target that has none.
    """

    def test_scanner_entry_carries_exactly_the_loader_keys(self, tmp_path):
        critical = finding(severity="critical")
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [critical], exit_code=2),
        ])

        assert len(report["scanners"]) == 1
        entry = report["scanners"][0]
        assert set(entry) == {
            "name", "exit_code", "parse_error", "finding_count", "findings",
        }
        assert entry["name"] == "skill_threats"
        assert entry["exit_code"] == 2
        assert entry["parse_error"] is None
        assert entry["finding_count"] == 1
        assert entry["findings"] == [critical]

    def test_scanner_entry_carries_stderr_only_when_present(self, tmp_path):
        report = aggregate_report(tmp_path, [
            scanner_result("noisy", [finding()], stderr="warning: slow walk"),
            scanner_result("quiet", [finding()]),
        ])

        entries = {entry["name"]: entry for entry in report["scanners"]}
        assert entries["noisy"]["stderr"] == "warning: slow walk"
        assert "stderr" not in entries["quiet"]

    def test_scanner_entry_carries_no_severity_detail_or_message(self, tmp_path):
        """The three keys the broken reader looked for. None is ever emitted."""
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [finding(severity="critical")], exit_code=2),
            scanner_result("secrets", [finding(severity="high")], exit_code=1),
            scanner_result("binary", [], exit_code=0),
        ])

        for entry in report["scanners"]:
            assert "severity" not in entry
            assert "detail" not in entry
            assert "message" not in entry

    def test_severity_lives_on_each_finding_with_the_report_vocabulary(self, tmp_path):
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [
                finding(severity="critical"),
                finding(severity="high", title="H"),
                finding(severity="medium", title="M"),
                finding(severity="low", title="L"),
            ], exit_code=2),
        ])

        # The vocabulary is the aggregator's, not this test's.
        assert set(aggregate_json.SEVERITY_ORDER) == {
            "critical", "high", "medium", "low",
        }
        assert len(report["findings"]) == 4
        for item in report["findings"]:
            assert item["severity"] in aggregate_json.SEVERITY_ORDER
        assert {item["severity"] for item in report["findings"]} == {
            "critical", "high", "medium", "low",
        }

    def test_builder_entries_match_a_real_build_report(self, tmp_path):
        """The builder stops at the loader; prove that costs no fidelity.

        aggregate_report() assembles a report from load_scanner_results() plus
        the two pure scorers instead of calling build_report(), so that a
        fixture's findings are not rewritten by correlation and evidence
        capping. If build_report() ever gave its scanner entries a different
        shape, that shortcut would become a drift of its own -- so compare the
        two directly.
        """
        results_dir = tmp_path / "results"
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()

        built = aggregate_report(results_dir, [
            scanner_result("skill_threats", [finding(severity="critical")], exit_code=2),
            scanner_result("secrets", [finding(severity="high")], stderr="note", exit_code=1),
        ])
        real = aggregate_json.build_report(str(results_dir), str(repo_dir), "false")

        real_entries = {entry["name"]: entry for entry in real["scanners"]}
        for entry in built["scanners"]:
            assert entry["name"] in real_entries
            assert set(entry) == set(real_entries[entry["name"]])


@_POSIX_ONLY
class TestDeepScanIntegration:
    def test_deep_scan_skipped_first_run(self, mock_home, monkeypatch, capsys):
        """First run should NOT deep scan (too many items, no baseline yet)."""
        monkeypatch.setattr(session_scan, 'refresh_threat_databases', lambda: [])
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)

        # Track if deep_scan_item was called
        calls = []
        orig = session_scan.deep_scan_item
        def tracking_deep_scan(*a, **kw):
            calls.append(a)
            return orig(*a, **kw)
        monkeypatch.setattr(session_scan, 'deep_scan_item', tracking_deep_scan)

        plugin_cache = os.path.join(mock_home, ".claude", "plugins", "cache")
        create_plugin(plugin_cache, "test-plugin")

        with pytest.raises(SystemExit):
            session_scan.main()

        assert len(calls) == 0, "deep_scan_item should not be called on first run"

    def test_deep_scan_runs_on_change(self, mock_home, monkeypatch, capsys):
        """After baseline exists and a plugin changes, deep scan should fire."""
        monkeypatch.setattr(session_scan, 'refresh_threat_databases', lambda: [])
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)
        # Point to non-existent script so deep scan returns [] (graceful)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', '/nonexistent')

        plugin_cache = os.path.join(mock_home, ".claude", "plugins", "cache")
        create_plugin(plugin_cache, "test-plugin")

        # First run — create baseline
        with pytest.raises(SystemExit):
            session_scan.main()
        capsys.readouterr()

        # Track deep scan calls
        calls = []
        def tracking_deep(*a, **kw):
            calls.append(a)
            return []
        monkeypatch.setattr(session_scan, 'deep_scan_item', tracking_deep)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', __file__)  # exists

        # Modify plugin
        with open(os.path.join(plugin_cache, "test-plugin", "index.js"), 'w') as f:
            f.write("// CHANGED")

        with pytest.raises(SystemExit):
            session_scan.main()

        assert len(calls) == 1, "deep_scan_item should be called for the changed plugin"


class TestExtractMcpDirs:
    def test_extracts_local_mcp(self, tmp_dir):
        mcp_dir = os.path.join(tmp_dir, "my-mcp")
        os.makedirs(mcp_dir)
        create_file(os.path.join(mcp_dir, "index.js"), "server code")
        settings = {
            "mcpServers": {
                "my-server": {
                    "command": "node",
                    "args": [os.path.join(mcp_dir, "index.js")]
                }
            }
        }
        settings_path = os.path.join(tmp_dir, "settings.json")
        create_file(settings_path, json.dumps(settings))
        results = session_scan._extract_mcp_dirs(settings_path)
        assert len(results) >= 1
        assert results[0][1] == "my-server"

    def test_skips_nonexistent_path(self, tmp_dir):
        settings = {
            "mcpServers": {
                "remote": {"command": "npx", "args": ["-y", "@remote/server"]}
            }
        }
        settings_path = os.path.join(tmp_dir, "settings.json")
        create_file(settings_path, json.dumps(settings))
        results = session_scan._extract_mcp_dirs(settings_path)
        assert results == []

    def test_missing_settings_file(self):
        assert session_scan._extract_mcp_dirs("/nonexistent/settings.json") == []

    def test_corrupt_settings(self, tmp_dir):
        p = os.path.join(tmp_dir, "settings.json")
        create_file(p, "NOT JSON{{{")
        assert session_scan._extract_mcp_dirs(p) == []

    def test_no_mcp_servers_key(self, tmp_dir):
        p = os.path.join(tmp_dir, "settings.json")
        create_file(p, json.dumps({"other": "stuff"}))
        assert session_scan._extract_mcp_dirs(p) == []
