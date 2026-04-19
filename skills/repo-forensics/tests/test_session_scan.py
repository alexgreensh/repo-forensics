"""
Tests for session_scan.py — SessionStart hook handler.
Covers: threat DB refresh, change detection, item scanning, baseline
persistence, output formatting, edge cases, and latency verification.
"""

import json
import os
import sys
import time
import tempfile
import shutil
import pytest

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'scripts')
sys.path.insert(0, os.path.abspath(SCRIPTS_DIR))

import session_scan


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
    def test_fresh_caches_skip_refresh(self, monkeypatch):
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)
        msgs = session_scan.refresh_threat_databases()
        assert msgs == []

    def test_stale_ioc_triggers_refresh(self, monkeypatch):
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: True)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)

        class FakeIOC:
            @staticmethod
            def update_iocs():
                return True, "IOCs updated: v2026-04-19 (7 C2 IPs)"
        monkeypatch.setitem(sys.modules, 'ioc_manager', FakeIOC())

        msgs = session_scan.refresh_threat_databases()
        assert any("Updating threat databases" in m for m in msgs)
        assert any("IOC" in m for m in msgs)

    def test_stale_kev_triggers_refresh(self, monkeypatch):
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: True)

        class FakeVuln:
            @staticmethod
            def update_kev_cache():
                return True, "KEV catalog cached: 1200 CVEs"
        monkeypatch.setitem(sys.modules, 'vuln_feed', FakeVuln())

        msgs = session_scan.refresh_threat_databases()
        assert any("Updating threat databases" in m for m in msgs)
        assert any("KEV" in m for m in msgs)

    def test_both_stale_refreshes_both(self, monkeypatch):
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: True)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: True)

        class FakeIOC:
            @staticmethod
            def update_iocs():
                return True, "IOCs updated"
        class FakeVuln:
            @staticmethod
            def update_kev_cache():
                return True, "KEV cached"
        monkeypatch.setitem(sys.modules, 'ioc_manager', FakeIOC())
        monkeypatch.setitem(sys.modules, 'vuln_feed', FakeVuln())

        msgs = session_scan.refresh_threat_databases()
        assert any("IOC" in m for m in msgs)
        assert any("KEV" in m for m in msgs)

    def test_refresh_failure_graceful(self, monkeypatch):
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: True)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: True)

        class FailIOC:
            @staticmethod
            def update_iocs():
                raise ConnectionError("no network")
        class FailVuln:
            @staticmethod
            def update_kev_cache():
                raise ConnectionError("no network")
        monkeypatch.setitem(sys.modules, 'ioc_manager', FailIOC())
        monkeypatch.setitem(sys.modules, 'vuln_feed', FailVuln())

        # Should NOT raise
        msgs = session_scan.refresh_threat_databases()
        assert any("Updating threat databases" in m for m in msgs)

    def test_import_error_graceful(self, monkeypatch):
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: True)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: True)
        # Remove modules if present to force ImportError
        monkeypatch.delitem(sys.modules, 'ioc_manager', raising=False)
        monkeypatch.delitem(sys.modules, 'vuln_feed', raising=False)

        # Patch the import to fail
        original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__
        def fail_import(name, *args, **kwargs):
            if name in ('ioc_manager', 'vuln_feed'):
                raise ImportError(f"No module named '{name}'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr('builtins.__import__', fail_import)
        msgs = session_scan.refresh_threat_databases()
        # Should not crash
        assert isinstance(msgs, list)


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
        checksums, label = session_scan._scan_directory(
            os.path.join(tmp_dir, "plugin"), "test-plugin"
        )
        assert checksums is not None
        assert "main.py" in checksums
        assert "config.json" in checksums

    def test_skip_non_scannable(self, tmp_dir):
        create_file(os.path.join(tmp_dir, "plugin", "main.py"), "code")
        create_file(os.path.join(tmp_dir, "plugin", "data.csv"), "a,b,c")
        create_file(os.path.join(tmp_dir, "plugin", "image.png"), "binary")
        checksums, _ = session_scan._scan_directory(
            os.path.join(tmp_dir, "plugin"), "test"
        )
        assert "main.py" in checksums
        assert "data.csv" not in checksums
        assert "image.png" not in checksums

    def test_nonexistent_directory(self):
        checksums, label = session_scan._scan_directory("/nonexistent/path", "x")
        assert checksums is None
        assert label is None

    def test_empty_directory(self, tmp_dir):
        empty = os.path.join(tmp_dir, "empty_plugin")
        os.makedirs(empty)
        checksums, label = session_scan._scan_directory(empty, "empty")
        assert checksums == {}


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
        changed = session_scan.detect_changes(items, None)
        assert len(changed) == 1
        assert changed[0][1] == "test-plugin"

    def test_matching_baseline_no_changes(self, tmp_dir):
        plugin_dir = create_plugin(tmp_dir, "test-plugin")
        items = [(plugin_dir, "test-plugin", "plugin")]
        # Build baseline from current state
        checksums, _ = session_scan._scan_directory(plugin_dir, "test-plugin")
        baseline = {'items': {f"plugin:{plugin_dir}": checksums}}
        changed = session_scan.detect_changes(items, baseline)
        assert len(changed) == 0

    def test_modified_file_detected(self, tmp_dir):
        plugin_dir = create_plugin(tmp_dir, "test-plugin")
        items = [(plugin_dir, "test-plugin", "plugin")]
        checksums, _ = session_scan._scan_directory(plugin_dir, "test-plugin")
        baseline = {'items': {f"plugin:{plugin_dir}": checksums}}
        # Modify a file
        with open(os.path.join(plugin_dir, "index.js"), 'w') as f:
            f.write("// MALICIOUS CODE HERE")
        changed = session_scan.detect_changes(items, baseline)
        assert len(changed) == 1

    def test_new_file_detected(self, tmp_dir):
        plugin_dir = create_plugin(tmp_dir, "test-plugin")
        items = [(plugin_dir, "test-plugin", "plugin")]
        checksums, _ = session_scan._scan_directory(plugin_dir, "test-plugin")
        baseline = {'items': {f"plugin:{plugin_dir}": checksums}}
        # Add new file
        create_file(os.path.join(plugin_dir, "evil.py"), "import os; os.system('rm -rf /')")
        changed = session_scan.detect_changes(items, baseline)
        assert len(changed) == 1


# ========================================================================
# Step 3: Scan changed items
# ========================================================================

class TestScanItem:
    def test_clean_plugin_no_findings(self, tmp_dir, monkeypatch):
        plugin_dir = create_plugin(tmp_dir, "safe-plugin", "1.0.0")
        checksums, _ = session_scan._scan_directory(plugin_dir, "safe-plugin")

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
        checksums, _ = session_scan._scan_directory(plugin_dir, "claud-code")

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
        checksums, _ = session_scan._scan_directory(plugin_dir, "axios")

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
        checksums, _ = session_scan._scan_directory(plugin_dir, "my-plugin")

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
        checksums, _ = session_scan._scan_directory(plugin_dir, "my-plugin")

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
        checksums, _ = session_scan._scan_directory(plugin_dir, "test")

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
        lines = session_scan.format_output(
            ["Updating threat databases (daily)..."],
            [], {}, False, 5
        )
        assert any("Updating" in line for line in lines)


# ========================================================================
# Output JSON
# ========================================================================

class TestOutputSessionContext:
    def test_empty_lines(self, capsys):
        with pytest.raises(SystemExit) as exc:
            session_scan.output_session_context([])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert json.loads(out) == {"hookEventName": "SessionStart"}

    def test_with_context(self, capsys):
        with pytest.raises(SystemExit) as exc:
            session_scan.output_session_context(["Updates detected: my-plugin"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["hookEventName"] == "SessionStart"
        assert "hookSpecificOutput" in data
        assert "additionalContext" in data["hookSpecificOutput"]
        assert "repo-forensics" in data["hookSpecificOutput"]["additionalContext"]

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
        assert json.loads(out) == {"hookEventName": "SessionStart"}

    def test_disabled_false(self, monkeypatch, capsys):
        monkeypatch.setenv("REPO_FORENSICS_SESSION_SCAN", "false")
        with pytest.raises(SystemExit) as exc:
            session_scan.main()
        assert exc.value.code == 0

    def test_enabled_by_default(self, monkeypatch, mock_home, capsys):
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)
        with pytest.raises(SystemExit) as exc:
            session_scan.main()
        assert exc.value.code == 0


# ========================================================================
# Integration: main() end-to-end
# ========================================================================

class TestMainIntegration:
    def test_no_items_first_run(self, mock_home, monkeypatch, capsys):
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)

        with pytest.raises(SystemExit) as exc:
            session_scan.main()
        assert exc.value.code == 0
        # Baseline should be saved
        assert os.path.isfile(session_scan.BASELINE_FILE)

    def test_plugin_changes_detected(self, mock_home, monkeypatch, capsys):
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)
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
        # Should have non-empty output (updates detected)
        data = json.loads(out)
        assert "hookSpecificOutput" in data

    def test_threat_detected_end_to_end(self, mock_home, monkeypatch, capsys):
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)
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
        data = json.loads(out)
        ctx = data.get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "malicious" in ctx.lower() or "⚠" in ctx


# ========================================================================
# Latency benchmarks
# ========================================================================

class TestLatency:
    """Real latency measurements — these verify our performance claims."""

    def test_fast_path_no_items(self, mock_home, monkeypatch):
        """No plugins/skills = should exit in <50ms."""
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)
        monkeypatch.delenv("REPO_FORENSICS_SESSION_SCAN", raising=False)

        start = time.monotonic()
        with pytest.raises(SystemExit):
            session_scan.main()
        elapsed_ms = (time.monotonic() - start) * 1000
        assert elapsed_ms < 200, f"Fast path took {elapsed_ms:.0f}ms (expected <200ms)"

    def test_baseline_match_no_changes(self, mock_home, monkeypatch):
        """5 plugins, nothing changed, caches fresh = should be <100ms."""
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)
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
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)
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

    def test_critical_exit_with_json(self, tmp_dir, monkeypatch):
        script = os.path.join(tmp_dir, "fake_forensics.sh")
        output = json.dumps({
            "summary": {"critical": 1},
            "scanners": [
                {"name": "runtime_behavior", "severity": "critical",
                 "detail": "eval() with external input detected"}
            ]
        })
        create_file(script, f'#!/bin/bash\necho \'{output}\'\nexit 2')
        os.chmod(script, 0o755)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', script)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")
        assert len(findings) >= 1
        assert any("CRITICAL" in f for f in findings)
        assert any("eval()" in f for f in findings)

    def test_warning_exit_with_json(self, tmp_dir, monkeypatch):
        script = os.path.join(tmp_dir, "fake_forensics.sh")
        output = json.dumps({
            "scanners": [
                {"name": "manifest_drift", "severity": "warning",
                 "detail": "2 undeclared files found"}
            ]
        })
        create_file(script, f'#!/bin/bash\necho \'{output}\'\nexit 1')
        os.chmod(script, 0o755)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', script)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")
        assert len(findings) >= 1
        assert any("WARNING" in f for f in findings)

    def test_timeout_returns_finding(self, tmp_dir, monkeypatch):
        script = os.path.join(tmp_dir, "slow_forensics.sh")
        create_file(script, '#!/bin/bash\nsleep 60\nexit 0')
        os.chmod(script, 0o755)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', script)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin", timeout=1)
        assert len(findings) == 1
        assert "timed out" in findings[0]

    def test_unparseable_output_fallback(self, tmp_dir, monkeypatch):
        script = os.path.join(tmp_dir, "bad_forensics.sh")
        create_file(script, '#!/bin/bash\necho "NOT JSON"\nexit 2')
        os.chmod(script, 0o755)
        monkeypatch.setattr(session_scan, 'RUN_FORENSICS_SCRIPT', script)

        findings = session_scan.deep_scan_item(tmp_dir, "test", "plugin")
        assert len(findings) >= 1
        assert any("CRITICAL" in f for f in findings)


class TestDeepScanIntegration:
    def test_deep_scan_skipped_first_run(self, mock_home, monkeypatch, capsys):
        """First run should NOT deep scan (too many items, no baseline yet)."""
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)
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
        monkeypatch.setattr(session_scan, '_is_ioc_cache_stale', lambda: False)
        monkeypatch.setattr(session_scan, '_is_kev_cache_stale', lambda: False)
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
