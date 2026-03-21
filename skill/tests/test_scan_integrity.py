"""Tests for scan_integrity.py - File Integrity Monitor."""

import os
import json
import stat
import pytest
import scan_integrity as scanner


class TestCriticalFileDiscovery:
    def test_finds_settings_json(self, repo_with_hooks):
        files = scanner.find_critical_files(str(repo_with_hooks))
        assert '.claude/settings.json' in files

    def test_finds_claude_md(self, repo_with_hooks):
        files = scanner.find_critical_files(str(repo_with_hooks))
        assert 'CLAUDE.md' in files

    def test_empty_repo(self, clean_repo):
        files = scanner.find_critical_files(str(clean_repo))
        assert len(files) == 0


class TestHooksDetection:
    def test_detects_dangerous_hook(self, repo_with_hooks):
        settings = str(repo_with_hooks / ".claude" / "settings.json")
        findings = scanner.check_hooks_in_settings(settings, ".claude/settings.json")
        dangerous = [f for f in findings if f.severity == "critical"]
        assert len(dangerous) > 0
        assert any("curl" in f.snippet.lower() or "Dangerous" in f.title for f in dangerous)

    def test_detects_all_registered_hooks(self, repo_with_hooks):
        settings = str(repo_with_hooks / ".claude" / "settings.json")
        findings = scanner.check_hooks_in_settings(settings, ".claude/settings.json")
        hook_findings = [f for f in findings if "Hook registered" in f.title]
        assert len(hook_findings) == 2  # PreToolUse + PostToolUse


class TestExecutableConfigs:
    def test_flags_executable_json(self, repo_with_hooks):
        settings_path = repo_with_hooks / ".claude" / "settings.json"
        settings_path.chmod(0o755)
        files = {'.claude/settings.json': str(settings_path)}
        findings = scanner.check_executable_configs(str(repo_with_hooks), files)
        assert len(findings) == 1
        assert "permission" in findings[0].category


class TestWatchMode:
    def test_creates_baseline(self, repo_with_hooks):
        files = scanner.find_critical_files(str(repo_with_hooks))
        findings = scanner.watch_mode(str(repo_with_hooks), files)
        assert len(findings) == 0  # first run = no drift
        baseline_path = repo_with_hooks / scanner.BASELINE_FILENAME
        assert baseline_path.exists()

    def test_detects_drift(self, repo_with_hooks):
        files = scanner.find_critical_files(str(repo_with_hooks))
        # Create baseline
        scanner.watch_mode(str(repo_with_hooks), files)
        # Modify a file
        claude_md = repo_with_hooks / "CLAUDE.md"
        claude_md.write_text("# MODIFIED by attacker\n")
        # Re-scan
        files = scanner.find_critical_files(str(repo_with_hooks))
        findings = scanner.watch_mode(str(repo_with_hooks), files)
        assert len(findings) > 0
        assert any("modified" in f.title.lower() for f in findings)

    def test_detects_new_file(self, repo_with_hooks):
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files)
        # Add a new critical file
        mcp_json = repo_with_hooks / ".mcp.json"
        mcp_json.write_text('{"mcpServers": {}}')
        files = scanner.find_critical_files(str(repo_with_hooks))
        findings = scanner.watch_mode(str(repo_with_hooks), files)
        assert any("New critical file" in f.title for f in findings)

    def test_detects_removed_file(self, repo_with_hooks):
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files)
        # Remove CLAUDE.md
        (repo_with_hooks / "CLAUDE.md").unlink()
        files = scanner.find_critical_files(str(repo_with_hooks))
        findings = scanner.watch_mode(str(repo_with_hooks), files)
        assert any("removed" in f.title.lower() for f in findings)


class TestSHA256:
    def test_hash_consistency(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h1 = scanner.sha256_file(str(f))
        h2 = scanner.sha256_file(str(f))
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex length

    def test_hash_changes_on_modification(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("original")
        h1 = scanner.sha256_file(str(f))
        f.write_text("modified")
        h2 = scanner.sha256_file(str(f))
        assert h1 != h2

    def test_nonexistent_file(self):
        assert scanner.sha256_file("/nonexistent/path") is None


class TestHMACSigning:
    """Tests for HMAC-SHA256 baseline signing and verification."""

    def test_baseline_includes_hmac(self, repo_with_hooks):
        """Saving a baseline should produce a JSON file with an _hmac field."""
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files)
        baseline_path = repo_with_hooks / scanner.BASELINE_FILENAME
        with open(str(baseline_path), 'r') as f:
            data = json.load(f)
        assert '_hmac' in data
        assert len(data['_hmac']) == 64  # SHA256 hex length

    def test_signing_key_created(self, repo_with_hooks):
        """Saving a baseline should create the signing key file with 0600 permissions."""
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files)
        key_path = repo_with_hooks / scanner.SIGNING_KEY_FILENAME
        assert key_path.exists()
        mode = key_path.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_valid_hmac_no_findings(self, repo_with_hooks):
        """Loading an untampered baseline should produce no HMAC findings."""
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files)
        # Load again - should verify cleanly
        _, integrity_findings = scanner.load_baseline(str(repo_with_hooks))
        hmac_findings = [f for f in integrity_findings if f.category == "integrity-hmac"]
        assert len(hmac_findings) == 0

    def test_tampered_baseline_critical_finding(self, repo_with_hooks):
        """Modifying the baseline file should trigger a CRITICAL finding."""
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files)
        # Tamper with the baseline
        baseline_path = repo_with_hooks / scanner.BASELINE_FILENAME
        with open(str(baseline_path), 'r') as f:
            data = json.load(f)
        data['files']['injected_file'] = 'deadbeef' * 8
        with open(str(baseline_path), 'w') as f:
            json.dump(data, f)
        # Load should detect tampering
        _, integrity_findings = scanner.load_baseline(str(repo_with_hooks))
        critical = [f for f in integrity_findings if f.severity == "critical"]
        assert len(critical) == 1
        assert "Baseline integrity compromised" in critical[0].title

    def test_missing_key_high_finding(self, repo_with_hooks):
        """Deleting the signing key when baseline has HMAC should trigger a HIGH finding."""
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files)
        # Delete the signing key
        key_path = repo_with_hooks / scanner.SIGNING_KEY_FILENAME
        key_path.unlink()
        # Load should detect missing key
        _, integrity_findings = scanner.load_baseline(str(repo_with_hooks))
        high = [f for f in integrity_findings if f.severity == "high"]
        assert len(high) == 1
        assert "Signing key missing" in high[0].title

    def test_unsigned_baseline_high_finding(self, repo_with_hooks):
        """A baseline without _hmac (legacy) should trigger a HIGH finding."""
        # Write a baseline manually without HMAC
        baseline_path = repo_with_hooks / scanner.BASELINE_FILENAME
        legacy_baseline = {
            'files': {'CLAUDE.md': 'abc123'},
            '_meta': {'created': '2025-01-01T00:00:00Z', 'tool': 'legacy', 'version': 'v0'}
        }
        with open(str(baseline_path), 'w') as f:
            json.dump(legacy_baseline, f)
        # Load should flag as unsigned
        _, integrity_findings = scanner.load_baseline(str(repo_with_hooks))
        high = [f for f in integrity_findings if f.severity == "high"]
        assert len(high) == 1
        assert "Unsigned baseline detected" in high[0].title

    def test_signing_key_reused_across_saves(self, repo_with_hooks):
        """The same signing key should be reused for subsequent baseline saves."""
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files)
        key_path = repo_with_hooks / scanner.SIGNING_KEY_FILENAME
        with open(str(key_path), 'rb') as f:
            key1 = f.read()
        # Save again (simulates re-run)
        scanner.watch_mode(str(repo_with_hooks), files)
        with open(str(key_path), 'rb') as f:
            key2 = f.read()
        assert key1 == key2
