"""Tests for scan_integrity.py - File Integrity Monitor."""

import os
import json
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
