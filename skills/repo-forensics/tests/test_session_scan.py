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

        Whether such a scan is still allowed to report the item *clean* is a
        separate question, answered by
        `TestNonzeroScanSpeaksInsteadOfGoingQuiet.test_the_invented_report_shape_is_not_read_as_clean`:
        it is not.
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


def rendered_findings(lines):
    """The severity-tagged lines: every rendered finding starts with `[`."""
    return [line for line in lines if line.startswith("[")]


def overflow_lines(lines):
    """Everything the renderer emitted that is not a finding line."""
    return [line for line in lines if not line.startswith("[")]


def unsorted_report(tmp_path, findings, exit_code=2):
    """An emitter-built report whose finding order is deliberately wrong.

    `aggregate_report()` sorts worst-first because `build_report()` does. The
    reader may not rely on that: the report is a scanner's stdout, and the
    reader is the last thing between it and the user. Reversing the list is
    what makes "sorted in the reader" an assertion rather than a coincidence
    inherited from the producer.
    """
    report = aggregate_report(tmp_path, [
        scanner_result("skill_threats", findings, exit_code=exit_code),
    ])
    report["findings"].reverse()
    return report


class TestSessionReportFrictionBudget:
    """The session report is spent only on what could change what the owner does.

    Two costs are bounded here, and they are different costs. The **floor**
    bounds what is worth a line at all: an informational note must not turn
    every plugin update into a warning line, or the report stops being read,
    and an ignored report is an alibi rather than a control. The **cap** bounds
    what one noisy target can spend: the return value of this hook is echoed
    into the agent's session context, so a report with no ceiling pushes the
    rest of the session out of the window.

    Both are lossy, so both are made visible: a capped report says how much it
    is hiding and at what severities, and the reader sorts before it truncates
    so what survives the cut is the worst of what was found.

    Assertions are on what `deep_scan_item()` returns. Nothing here reaches
    past it into the renderer.
    """

    def test_reporting_floor_is_the_vocabulary_minus_low(self):
        """The floor is a named constant, and `low` is the only thing under it.

        Written against the vocabulary rather than as a second literal, so a
        severity added upstream lands above the floor by default -- reported
        and argued about -- instead of being silently dropped by a floor that
        was spelled out once and never revisited.
        """
        assert session_scan.DEEP_FINDING_REPORT_FLOOR == ("critical", "high", "medium")
        assert (set(session_scan.DEEP_FINDING_REPORT_FLOOR)
                == set(session_scan.DEEP_FINDING_SEVERITIES) - {"low"})

    def test_severity_vocabulary_is_ordered_worst_first(self):
        """The mirror carries the aggregator's *ranking*, not just its members.

        `test_severity_vocabulary_matches_the_aggregator` pins the set. The
        reader now sorts by position in this tuple, so its order became
        load-bearing too: a vocabulary that drifted into a different order
        would silently invert the truncation and hide the worst result.
        """
        assert list(session_scan.DEEP_FINDING_SEVERITIES) == sorted(
            aggregate_json.SEVERITY_ORDER,
            key=lambda severity: -aggregate_json.SEVERITY_ORDER[severity],
        )

    def test_a_low_only_report_produces_no_finding_lines(self, tmp_dir, tmp_path, monkeypatch):
        """LOW is a note, and a note is not worth a line in this budget."""
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [
                finding(severity="low", title="Informational note"),
                finding(severity="low", title="Second note"),
            ], exit_code=1),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 1)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert rendered_findings(findings) == []
        assert not any("Informational note" in line for line in findings)

    def test_low_is_dropped_while_the_floor_is_reported(self, tmp_dir, tmp_path, monkeypatch):
        """The floor is a filter on a mixed report, not only on an all-LOW one."""
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [
                finding(severity="critical", title="Critical one"),
                finding(severity="high", title="High one"),
                finding(severity="medium", title="Medium one"),
                finding(severity="low", title="Low one"),
            ], exit_code=2),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(rendered_findings(findings)) == 3
        assert not any("Low one" in line for line in findings)
        for title in ("Critical one", "High one", "Medium one"):
            assert any(title in line for line in findings)

    def test_at_most_five_finding_lines_from_one_changed_item(
        self, tmp_dir, tmp_path, monkeypatch
    ):
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [
                finding(severity="high", title=f"Finding {n}") for n in range(9)
            ], exit_code=1),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 1)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(rendered_findings(findings)) == 5

    def test_the_cap_is_not_paid_when_it_does_not_bite(self, tmp_dir, tmp_path, monkeypatch):
        """No overflow line on a report that fits, so it cannot become noise."""
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [
                finding(severity="high", title=f"Finding {n}") for n in range(5)
            ], exit_code=1),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 1)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(rendered_findings(findings)) == 5
        assert overflow_lines(findings) == []

    def test_overflow_line_carries_the_hidden_count_and_breakdown(
        self, tmp_dir, tmp_path, monkeypatch
    ):
        """A capped report must never be mistakable for a complete one.

        Two CRITICAL and three HIGH fill the cap exactly, so the four MEDIUM
        are the hidden set and the breakdown is checkable rather than
        approximate.
        """
        report = aggregate_report(tmp_path, [
            scanner_result(
                "skill_threats",
                [finding(severity="critical", title=f"Crit {n}") for n in range(2)]
                + [finding(severity="high", title=f"High {n}") for n in range(3)]
                + [finding(severity="medium", title=f"Med {n}") for n in range(4)],
                exit_code=2,
            ),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        overflow = overflow_lines(findings)
        assert len(overflow) == 1
        assert findings[-1] == overflow[0]
        assert "4" in overflow[0]
        assert "MEDIUM" in overflow[0]
        # The breakdown describes what was hidden, not what was shown.
        assert "CRITICAL" not in overflow[0] and "HIGH" not in overflow[0]

    def test_findings_are_sorted_by_severity_in_the_reader(
        self, tmp_dir, tmp_path, monkeypatch
    ):
        """Worst first, and not because the producer happened to say so."""
        report = unsorted_report(tmp_path, [
            finding(severity="medium", title="Middling"),
            finding(severity="high", title="Bad"),
            finding(severity="critical", title="Worst"),
        ])
        # The premise of the assertion below, not an incidental property: a
        # reader that took the producer's order would render MEDIUM first.
        assert report["findings"][0]["title"] == "Middling"
        stub_forensics(tmp_dir, monkeypatch, report, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert [line.split("]")[0] + "]" for line in rendered_findings(findings)] == [
            "[CRITICAL]", "[HIGH]", "[MEDIUM]",
        ]

    def test_truncation_never_hides_the_worst_result(self, tmp_dir, tmp_path, monkeypatch):
        """The cap bites on a report whose producer put the worst finding last."""
        report = unsorted_report(tmp_path, (
            [finding(severity="medium", title=f"Med {n}") for n in range(5)]
            + [finding(severity="critical", title="The worst")]
        ))
        stub_forensics(tmp_dir, monkeypatch, report, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        shown = rendered_findings(findings)
        assert len(shown) == 5
        assert shown[0].startswith("[CRITICAL]")
        assert "The worst" in shown[0]
        overflow = overflow_lines(findings)
        assert len(overflow) == 1
        assert "1" in overflow[0] and "MEDIUM" in overflow[0]

    def test_an_unrankable_severity_is_reported_rather_than_dropped(
        self, tmp_dir, monkeypatch
    ):
        """A severity off the vocabulary must not be a way to go quiet.

        Hand-written rather than built through `finding()`, because
        `forensics_core.Finding` is not the only way a severity reaches a
        report -- a scanner's raw JSON is, and `load_scanner_results()` copies
        it through verbatim. If an unrecognised severity fell below the floor,
        a scanned repository could suppress its own worst finding by writing
        one, trading the false clean this work removes for a narrower one.
        """
        payload = {"scanners": [], "findings": [
            {"severity": "sev-9", "title": "unrankable finding",
             "description": "", "file": "a.py", "line": 1},
            {"severity": "low", "title": "informational note",
             "description": "", "file": "b.py", "line": 2},
        ]}
        stub_forensics(tmp_dir, monkeypatch, payload, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(rendered_findings(findings)) == 1
        assert findings[0].startswith("[UNKNOWN] unrankable finding")
        assert not any("informational note" in line for line in findings)

    def test_an_unrankable_severity_sorts_below_every_ranked_one(
        self, tmp_dir, monkeypatch
    ):
        """Reported, but never ahead of a finding the aggregator could rank.

        The other half of the rule above: showing an unrankable severity must
        not hand a scanned repository the top of the report, or the cap becomes
        the suppression channel the floor was not.
        """
        payload = {"scanners": [], "findings": [
            {"severity": "sev-9", "title": "unrankable finding",
             "description": "", "file": "a.py", "line": 1},
            {"severity": "medium", "title": "ranked finding",
             "description": "", "file": "b.py", "line": 2},
        ]}
        stub_forensics(tmp_dir, monkeypatch, payload, 2)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        shown = rendered_findings(findings)
        assert len(shown) == 2
        assert shown[0].startswith("[MEDIUM]")
        assert shown[1].startswith("[UNKNOWN]")


# ========================================================================
# Ticket 04: a nonzero scan that renders nothing says so, and is not cleared
# ========================================================================

def session_start(monkeypatch, capsys):
    """One SessionStart run of the hook. Returns what it printed.

    `main()` is the only entry point that writes the baseline, so the
    baseline half of this behaviour cannot be observed anywhere below it.
    """
    monkeypatch.setattr(session_scan, 'refresh_threat_databases', lambda: [])
    monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)
    with pytest.raises(SystemExit) as exc:
        session_scan.main()
    assert exc.value.code == 0
    return capsys.readouterr().out


def baselined_items():
    """The item keys the saved baseline currently holds."""
    with open(session_scan.BASELINE_FILE, "r", encoding="utf-8") as handle:
        return set(json.load(handle).get("items", {}))


def change_plugin(plugin_dir, content):
    """Move a plugin's content so the next run sees it as changed."""
    with open(os.path.join(plugin_dir, "index.js"), "w", encoding="utf-8") as handle:
        handle.write(content)


@_POSIX_ONLY
class TestNonzeroScanSpeaksInsteadOfGoingQuiet:
    """A scan that ended nonzero and rendered nothing says exactly that.

    This is the one deliberate behaviour change in this work, and it is a
    change rather than a fix: a deep scan ending in 99 previously returned no
    lines at all, so `format_output()` printed `clean` over it. A shape
    problem inside the tool reached the owner disguised as a clean item --
    the same false clean the rest of this spine removes, arriving through the
    reader's silence rather than through its blindness.

    Every early return above this point has already handled the two cases
    that legitimately render nothing: exit 0, which is the scanner saying it
    found nothing, and a signal death, which already speaks for itself.
    Reaching the end with an empty list past both of them means the aggregate
    carried something the reader could not turn into a line.

    Assertions are on what `deep_scan_item()` returns and on what
    `format_output()` prints. The baseline is a separate subject and lives in
    `TestAnUnclearedItemStaysOutOfTheBaseline`, one seam up, because
    `deep_scan_item()` does not write it.
    """

    def test_a_nonzero_scan_that_renders_nothing_names_its_exit_code(
        self, tmp_dir, tmp_path, monkeypatch
    ):
        """Exit 99 with an empty report: the infrastructure-failure case."""
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [], exit_code=0),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 99)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert len(findings) == 1
        assert "99" in findings[0]
        # Not a finding line: it reports the scan, not something found in the
        # tree, and must not be mistakable for one.
        assert rendered_findings(findings) == []

    def test_the_item_is_never_reported_as_clean(self, tmp_dir, tmp_path, monkeypatch):
        """Driven through the function that produces the word `clean`.

        A line the reader emitted that the formatter then ignored would still
        be a false clean on the owner's screen, so the assertion is made where
        the word is written rather than one seam below it.
        """
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [], exit_code=0),
        ])
        stub_forensics(tmp_dir, monkeypatch, report, 99)
        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        lines = session_scan.format_output(
            [], [(tmp_dir, "test-plugin", "plugin", {})],
            {f"plugin:{tmp_dir}": findings}, False, 1,
        )

        assert not any("clean" in line for line in lines)
        assert not any("Security check passed" in line for line in lines)
        assert any("99" in line for line in lines)

    def test_the_invented_report_shape_is_not_read_as_clean(self, tmp_dir, monkeypatch):
        """The other half of `test_invented_report_shape_is_not_read_as_findings`.

        That test pins that nothing in this payload is rendered as a finding.
        The question it left open -- whether a scan carrying it may still
        report the item clean -- is answered here: it may not. Same
        hand-written shape, at the exit code the defect was first seen at.
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

        assert len(findings) == 1
        assert "2" in findings[0]
        assert not any("eval() with external input" in line for line in findings)

    def test_a_report_below_the_floor_still_surfaces_its_nonzero_exit(
        self, tmp_dir, tmp_path, monkeypatch
    ):
        """The silence ticket 03 opened by dropping LOW below the floor.

        Reachable rather than theoretical: an unexpected scanner exit code
        becomes a `parse_error`, and `calculate_report_exit_code()` returns 99
        on any `parse_error` whatever the findings say. So a report whose only
        finding is a note can still end nonzero, and the reader renders
        nothing from it.
        """
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [
                finding(severity="low", title="Informational note"),
            ], exit_code=7),
        ])
        # The premise of the assertions below, not an incidental property: the
        # report really does end nonzero, and its only finding really is a note.
        assert report["exit_code"] == 99
        assert [item["severity"] for item in report["findings"]] == ["low"]
        stub_forensics(tmp_dir, monkeypatch, report, 99)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert rendered_findings(findings) == []
        assert len(findings) == 1
        assert "99" in findings[0]
        assert "Informational note" not in findings[0]

    def test_a_clean_exit_stays_silent_even_when_nothing_is_rendered(
        self, tmp_dir, tmp_path, monkeypatch
    ):
        """Exit 0 is the scanner saying it found nothing, and is still believed.

        The sharp version of "the existing early returns keep their
        behaviour": this report carries a LOW finding, so the reader renders
        nothing from it either -- but the exit code is 0, so this is not the
        silence the new line exists to break, and adding a line here would
        turn every note into a warning.
        """
        report = aggregate_report(tmp_path, [
            scanner_result("skill_threats", [
                finding(severity="low", title="Informational note"),
            ], exit_code=0),
        ])
        assert report["exit_code"] == 0
        stub_forensics(tmp_dir, monkeypatch, report, 0)

        assert session_scan.deep_scan_item(tmp_dir, "test", "plugin") == []

    def test_a_signal_death_keeps_its_own_line(self, tmp_dir, monkeypatch):
        """A killed scan already says so, and must not say it twice."""
        script = os.path.join(tmp_dir, "stub_forensics.sh")
        create_file(script, '#!/bin/bash\nkill -TERM $$\n')
        os.chmod(script, 0o755)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', script)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")

        assert findings == ["deep scan killed by signal 15"]


@_POSIX_ONLY
class TestAnUnclearedItemStaysOutOfTheBaseline:
    """A silent failure is not made permanent by the next run.

    The baseline is what makes a session report stop repeating: `main()`
    writes every scanned item's checksums and `detect_changes()` then reports
    only items whose hashes moved. That is right for an item that was looked
    at and found clean, and wrong for one whose scan ended nonzero and
    rendered nothing -- baselining that one turns a single silent failure into
    a permanent one, because the same result is not reported at the next
    session start either.

    Driven through `main()`, the only place the baseline is written.
    """

    def _stub_scan(self, tmp_path, monkeypatch, exit_code):
        """A stub scanner emitting an emitter-built empty report at *exit_code*.

        The report goes through `aggregate_report()` like every other fixture
        in this file rather than being written by hand: `report_builders`
        exists precisely so no test can describe a shape the product does not
        emit, and an empty report is one call away. What is under test here is
        the exit code, not the report.
        """
        stub_forensics(str(tmp_path), monkeypatch, aggregate_report(tmp_path, []), exit_code)

    def _changed_plugin(self, mock_home, monkeypatch, capsys):
        """A plugin already in the baseline, then changed. Returns its dir and key."""
        plugin_cache = os.path.join(mock_home, ".claude", "plugins", "cache")
        plugin_dir = create_plugin(plugin_cache, "test-plugin")
        session_start(monkeypatch, capsys)
        item_key = f"plugin:{plugin_dir}"
        # Control arm for every assertion below: the first run really does
        # baseline this item, so "absent from the baseline" cannot pass
        # because nothing is ever written there.
        assert item_key in baselined_items()
        change_plugin(plugin_dir, "// CHANGED")
        return plugin_dir, item_key

    def test_the_uncleared_item_is_not_written_into_the_baseline(
        self, mock_home, tmp_path, monkeypatch, capsys
    ):
        _, item_key = self._changed_plugin(mock_home, monkeypatch, capsys)
        self._stub_scan(tmp_path, monkeypatch, 99)

        out = session_start(monkeypatch, capsys)

        assert "99" in out
        assert "clean" not in out
        assert item_key not in baselined_items()

    def test_the_same_result_surfaces_again_at_the_next_session_start(
        self, mock_home, tmp_path, monkeypatch, capsys
    ):
        """Nothing moves on disk between the two runs, and it still re-reports.

        That is the whole value of leaving it unbaselined: the owner sees the
        failure again next session instead of once and never again.
        """
        self._changed_plugin(mock_home, monkeypatch, capsys)
        self._stub_scan(tmp_path, monkeypatch, 99)
        session_start(monkeypatch, capsys)

        out = session_start(monkeypatch, capsys)

        assert "Updates detected" in out
        assert "99" in out

    def test_an_item_that_really_was_cleared_is_still_baselined(
        self, mock_home, tmp_path, monkeypatch, capsys
    ):
        """The control arm, and the behaviour that must not regress.

        A scan that exited 0 cleared the item, so it is baselined and stops
        being reported. Without this, "uncleared items are absent from the
        baseline" would also pass on a change that stopped baselining
        anything, and every session would re-report every changed item
        forever.
        """
        _, item_key = self._changed_plugin(mock_home, monkeypatch, capsys)
        self._stub_scan(tmp_path, monkeypatch, 0)

        out = session_start(monkeypatch, capsys)
        assert "clean" in out
        assert item_key in baselined_items()

        assert "Updates detected" not in session_start(monkeypatch, capsys)


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
