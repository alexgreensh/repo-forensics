"""Tests for scan_integrity.py - File Integrity Monitor."""

import os
import json
import stat
import hmac
import hashlib
import subprocess
import sys
import pytest
import scan_integrity as scanner


@pytest.fixture(autouse=True)
def isolate_signing_key(monkeypatch, tmp_path):
    """Redirect HOME so _get_signing_key_path() resolves under tmp_path.

    This prevents tests from writing to or deleting the real
    ~/.cache/repo-forensics/forensics-key on the developer's machine.
    The repo fixture (repo_with_hooks, etc.) lives under tmp_path directly,
    while the fake home lives at tmp_path / 'home' -- a sibling, not a child,
    so key-outside-repo assertions remain valid.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    # os.path.expanduser("~") on Windows consults USERPROFILE (then
    # HOMEDRIVE/HOMEPATH), NEVER HOME -- so setting only HOME leaves
    # _get_signing_key_path() pointing at the real profile, breaking per-test
    # isolation and letting one test's migrated key leak into the next. Redirect
    # the Windows home vars too so the fake home wins on every platform.
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOMEDRIVE", "")
    monkeypatch.setenv("HOMEPATH", str(fake_home))


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


_NO_POSIX_EXEC_BIT = pytest.mark.skipif(
    os.name == "nt",
    reason="needs the POSIX executable bit; Windows derives X_OK from the file extension, so chmod(0o755) is a no-op and the finding cannot fire")


class TestExecutableConfigs:
    @_NO_POSIX_EXEC_BIT
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
        findings = scanner.watch_mode(str(repo_with_hooks), files, "text")
        assert len(findings) == 0  # first run = no drift
        baseline_path = repo_with_hooks / scanner.BASELINE_FILENAME
        assert baseline_path.exists()

    def test_detects_drift(self, repo_with_hooks):
        files = scanner.find_critical_files(str(repo_with_hooks))
        # Create baseline
        scanner.watch_mode(str(repo_with_hooks), files, "text")
        # Modify a file
        claude_md = repo_with_hooks / "CLAUDE.md"
        claude_md.write_text("# MODIFIED by attacker\n")
        # Re-scan
        files = scanner.find_critical_files(str(repo_with_hooks))
        findings = scanner.watch_mode(str(repo_with_hooks), files, "text")
        assert len(findings) > 0
        assert any("modified" in f.title.lower() for f in findings)

    def test_detects_new_file(self, repo_with_hooks):
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files, "text")
        # Add a new critical file
        mcp_json = repo_with_hooks / ".mcp.json"
        mcp_json.write_text('{"mcpServers": {}}')
        files = scanner.find_critical_files(str(repo_with_hooks))
        findings = scanner.watch_mode(str(repo_with_hooks), files, "text")
        assert any("New critical file" in f.title for f in findings)

    def test_detects_removed_file(self, repo_with_hooks):
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files, "text")
        # Remove CLAUDE.md
        (repo_with_hooks / "CLAUDE.md").unlink()
        files = scanner.find_critical_files(str(repo_with_hooks))
        findings = scanner.watch_mode(str(repo_with_hooks), files, "text")
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
        scanner.watch_mode(str(repo_with_hooks), files, "text")
        baseline_path = repo_with_hooks / scanner.BASELINE_FILENAME
        with open(str(baseline_path), 'r') as f:
            data = json.load(f)
        assert '_hmac' in data
        assert len(data['_hmac']) == 64  # SHA256 hex length

    def test_signing_key_created(self, repo_with_hooks):
        """Saving a baseline should create the signing key outside the repo with 0600 permissions."""
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files, "text")
        key_path = scanner._get_signing_key_path()
        assert os.path.exists(key_path)
        if os.name == "nt":
            return  # POSIX file modes not enforced on Windows
        mode = os.stat(key_path).st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_valid_hmac_no_findings(self, repo_with_hooks):
        """Loading an untampered baseline should produce no HMAC findings."""
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files, "text")
        # Load again - should verify cleanly
        _, integrity_findings = scanner.load_baseline(str(repo_with_hooks))
        hmac_findings = [f for f in integrity_findings if f.category == "integrity-hmac"]
        assert len(hmac_findings) == 0

    def test_tampered_baseline_critical_finding(self, repo_with_hooks):
        """Modifying the baseline file should trigger a CRITICAL finding."""
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files, "text")
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
        scanner.watch_mode(str(repo_with_hooks), files, "text")
        # Delete the signing key at its new out-of-repo location
        key_path = scanner._get_signing_key_path()
        os.unlink(key_path)
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
        scanner.watch_mode(str(repo_with_hooks), files, "text")
        key_path = scanner._get_signing_key_path()
        with open(key_path, 'rb') as f:
            key1 = f.read()
        # Save again (simulates re-run)
        scanner.watch_mode(str(repo_with_hooks), files, "text")
        with open(key_path, 'rb') as f:
            key2 = f.read()
        assert key1 == key2

    @staticmethod
    def _plant_repo_key_baseline(repo, key):
        (repo / scanner.SIGNING_KEY_FILENAME).write_bytes(key)
        files = scanner.find_critical_files(str(repo))
        baseline = {
            'files': {rel: scanner.sha256_file(full) for rel, full in files.items()},
            '_meta': {'created': '2026-01-01T00:00:00Z', 'tool': 'legacy', 'version': 'v1'},
        }
        content = json.dumps(baseline, sort_keys=True)
        baseline['_hmac'] = hmac.new(key, content.encode('utf-8'), hashlib.sha256).hexdigest()
        path = repo / scanner.BASELINE_FILENAME
        path.write_text(json.dumps(baseline))
        return path

    def test_repo_key_baseline_is_refused_and_key_never_copied(self, repo_with_hooks):
        """A repo can ship a key plus a matching baseline; that proves nothing."""
        key = b"planted signing key shipped in the repo"
        baseline_path = self._plant_repo_key_baseline(repo_with_hooks, key)
        before = baseline_path.read_bytes()

        loaded, findings = scanner.load_baseline(str(repo_with_hooks))

        assert loaded is None
        assert any("key stored in the repository" in f.title and f.severity == "high"
                   for f in findings)
        assert not os.path.exists(scanner._get_signing_key_path())
        assert (repo_with_hooks / scanner.SIGNING_KEY_FILENAME).read_bytes() == key
        assert baseline_path.read_bytes() == before

    def test_repo_key_baseline_refused_even_when_home_key_exists(self, repo_with_hooks):
        scanner._get_or_create_signing_key(str(repo_with_hooks))
        home_key = open(scanner._get_signing_key_path(), 'rb').read()
        self._plant_repo_key_baseline(repo_with_hooks, b"planted key, home key already set")
        findings = scanner.watch_mode(str(repo_with_hooks),
                                      scanner.find_critical_files(str(repo_with_hooks)), "text")
        assert any("key stored in the repository" in f.title for f in findings)
        assert open(scanner._get_signing_key_path(), 'rb').read() == home_key

    def test_planted_repo_key_is_never_used_to_sign(self, repo_with_hooks):
        planted = b"planted key without any baseline yet"
        (repo_with_hooks / scanner.SIGNING_KEY_FILENAME).write_bytes(planted)
        scanner.watch_mode(str(repo_with_hooks),
                           scanner.find_critical_files(str(repo_with_hooks)), "text")
        home_key = open(scanner._get_signing_key_path(), 'rb').read()
        assert home_key != planted and len(home_key) == 32
        loaded, findings = scanner.load_baseline(str(repo_with_hooks))
        assert loaded is not None and findings == []

    def test_unreadable_home_key_is_reported_not_called_tampering(self, repo_with_hooks):
        scanner.watch_mode(str(repo_with_hooks), {}, "text")
        key_path = scanner._get_signing_key_path()
        os.remove(key_path)
        os.mkdir(key_path)
        loaded, findings = scanner.load_baseline(str(repo_with_hooks))
        assert loaded is None
        assert [f.title for f in findings] == ["Signing key unreadable"]


class TestSigningKeyOutsideRepo:
    """Verify that the HMAC signing key is stored outside the repository root.

    These tests create the repo under tmp_path / "repo" so that the fake HOME
    (tmp_path / "home", set by the autouse isolate_signing_key fixture) and
    the repo root are siblings -- neither is a parent of the other.  This
    prevents a false failure where both paths start with the same tmp_path prefix.
    """

    def _make_repo(self, tmp_path):
        """Create a minimal repo directory as a sibling of the fake HOME."""
        import json
        repo = tmp_path / "repo"
        repo.mkdir()
        claude_dir = repo / ".claude"
        claude_dir.mkdir()
        (claude_dir / "settings.json").write_text(json.dumps({
            "hooks": {"PreToolUse": [{"command": "echo ok"}]}
        }))
        (repo / "CLAUDE.md").write_text("# Project\n")
        return repo

    def test_key_path_is_outside_repo_root(self, tmp_path):
        """The signing key must not be stored inside the repo directory."""
        repo = self._make_repo(tmp_path)
        repo_root = str(repo)
        key_path = scanner._get_signing_key_path()
        # Key path must not be inside the repo root
        assert not key_path.startswith(repo_root), (
            f"Signing key path '{key_path}' is inside the repo root '{repo_root}'. "
            "The key would be readable by anyone with repo access."
        )
        # Key path must not be the bare .forensics-key filename directly in the repo root
        assert not (
            os.path.basename(key_path) == scanner.SIGNING_KEY_FILENAME and
            os.path.dirname(os.path.abspath(key_path)) == os.path.abspath(repo_root)
        ), "Signing key is stored as .forensics-key directly in the repo root."

    def test_key_file_permissions_are_0600(self, tmp_path):
        """After creating a baseline, the signing key must have 0600 permissions."""
        repo = self._make_repo(tmp_path)
        files = scanner.find_critical_files(str(repo))
        scanner.watch_mode(str(repo), files, "text")
        key_path = scanner._get_signing_key_path()
        assert os.path.exists(key_path), "Signing key was not created"
        if os.name == "nt":
            return  # POSIX file modes not enforced on Windows
        mode = os.stat(key_path).st_mode
        assert stat.S_IMODE(mode) == 0o600, (
            f"Signing key has permissions {oct(stat.S_IMODE(mode))}, expected 0o600"
        )


class TestUntrustedBaselinePreservation:
    @pytest.mark.parametrize('damage', ['tampered', 'missing-key', 'unsigned'])
    def test_watch_preserves_untrusted_baseline_across_runs(self, repo_with_hooks, damage, capsys):
        files = scanner.find_critical_files(str(repo_with_hooks))
        scanner.watch_mode(str(repo_with_hooks), files, 'text')
        path = repo_with_hooks / scanner.BASELINE_FILENAME
        data = json.loads(path.read_text())
        if damage == 'tampered':
            data['files']['CLAUDE.md'] = '0' * 64
            path.write_text(json.dumps(data))
        elif damage == 'missing-key':
            os.unlink(scanner._get_signing_key_path())
        else:
            data.pop('_hmac')
            path.write_text(json.dumps(data))
        before = path.read_bytes()
        capsys.readouterr()
        for _ in range(2):
            findings = scanner.watch_mode(str(repo_with_hooks), files, 'text')
            assert any(f.category == 'integrity-hmac' for f in findings)
            assert path.read_bytes() == before
        if damage == 'missing-key':
            assert not os.path.exists(scanner._get_signing_key_path())
        output = capsys.readouterr().out
        assert 'Baseline created' not in output
        assert 'Baseline updated' not in output

    @pytest.mark.parametrize('contents', [
        b'{broken', b'\xff', b'null', b'[]', b'42', b'{}',
        b'{"files":[]}', b'{"files":{"CLAUDE.md":null}}',
        b'{"files":{},"_meta":null}', b'{"files":{},"_meta":{"created":[]}}',
        b'{"files":{},"_hmac":123}', b'{"files":{},"_hmac":[]}', b'{"files":{},"_hmac":null}',
        b'{"files":{},"_hmac":"not-a-signature"}',
        b'{"files":{},"_hmac":"\\u00e9"}',
    ])
    def test_invalid_baseline_reports_and_never_resets(self, repo_with_hooks, contents, capsys):
        path = repo_with_hooks / scanner.BASELINE_FILENAME
        path.write_bytes(contents)
        files = scanner.find_critical_files(str(repo_with_hooks))
        for _ in range(2):
            findings = scanner.watch_mode(str(repo_with_hooks), files, 'text')
            assert any(f.category == 'integrity-baseline-format' and f.severity == 'high'
                       for f in findings)
            assert path.read_bytes() == contents
            assert not os.path.exists(scanner._get_signing_key_path())
        output = capsys.readouterr().out
        assert 'Baseline created' not in output
        assert 'Baseline updated' not in output


    @pytest.mark.parametrize('contents', ['{broken', 'null', '{"files":{},"_hmac":null}'])
    def test_invalid_baseline_cli_reports_valid_json_and_preserves_evidence(self, repo_with_hooks, contents):
        path = repo_with_hooks / scanner.BASELINE_FILENAME
        path.write_text(contents)
        result = subprocess.run(
            [sys.executable, scanner.__file__, str(repo_with_hooks), '--watch', '--format', 'json'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        assert result.returncode == 0  # Scanner CLIs report findings; the orchestrator sets exit codes.
        report = json.loads(result.stdout)
        assert any(f['category'] == 'integrity-baseline-format' for f in report)
        assert path.read_text() == contents

    def test_valid_signed_empty_baseline_still_updates(self, repo_with_hooks):
        scanner.save_baseline(str(repo_with_hooks), {'files': {}})
        findings = scanner.watch_mode(str(repo_with_hooks),
                                      scanner.find_critical_files(str(repo_with_hooks)), 'text')
        assert any(f.category == 'integrity-new-file' for f in findings)
        loaded, errors = scanner.load_baseline(str(repo_with_hooks))
        assert not errors
        assert 'CLAUDE.md' in loaded['files']

    def test_valid_baseline_without_optional_metadata_still_loads(self, repo_with_hooks):
        key = scanner._get_or_create_signing_key(str(repo_with_hooks))
        baseline = {'files': {}}
        content = json.dumps(baseline, sort_keys=True)
        baseline['_hmac'] = hmac.new(key, content.encode('utf-8'), hashlib.sha256).hexdigest()
        (repo_with_hooks / scanner.BASELINE_FILENAME).write_text(json.dumps(baseline))
        loaded, findings = scanner.load_baseline(str(repo_with_hooks))
        assert loaded == {'files': {}}
        assert not findings

    def test_read_error_is_not_first_run(self, repo_with_hooks, monkeypatch):
        path = repo_with_hooks / scanner.BASELINE_FILENAME
        path.write_text('{"files":{}}')
        before = path.read_bytes()
        real_open = open
        def unreadable(filename, *args, **kwargs):
            if os.fspath(filename) == str(path) and args and args[0] == 'r':
                raise PermissionError('injected read refusal')
            return real_open(filename, *args, **kwargs)
        def refused_fdopen(fd, *args, **kwargs):
            raise PermissionError('injected read refusal')
        monkeypatch.setattr(scanner.os, 'fdopen', refused_fdopen)
        findings = scanner.watch_mode(str(repo_with_hooks), {}, 'text')
        assert any(f.category == 'integrity-baseline-io' for f in findings)
        assert path.read_bytes() == before
        assert not os.path.exists(scanner._get_signing_key_path())

    @pytest.mark.parametrize('contents', ['[' * 1500 + '0' + ']' * 1500, '1' * 5000])
    def test_parser_limit_failure_is_visible_and_preserved(self, repo_with_hooks, contents):
        path = repo_with_hooks / scanner.BASELINE_FILENAME
        path.write_text(contents)
        findings = scanner.watch_mode(str(repo_with_hooks), {}, 'text')
        assert any(f.category == 'integrity-baseline-format' for f in findings)
        assert path.read_text() == contents


class TestBaselineSafeIO:
    def test_save_refuses_symlink_without_clobbering(self, tmp_path):
        victim = tmp_path / 'victim'
        victim.write_text('keep me')
        repo = tmp_path / 'repo'
        repo.mkdir()
        (repo / scanner.BASELINE_FILENAME).symlink_to(victim)
        with pytest.raises(OSError):
            scanner.save_baseline(str(repo), {'files': {}})
        assert victim.read_text() == 'keep me'

    def test_save_is_atomic_on_serialization_failure(self, tmp_path):
        path = tmp_path / scanner.BASELINE_FILENAME
        path.write_text('old baseline')
        with pytest.raises(TypeError):
            scanner.save_baseline(str(tmp_path), {'files': {'bad': object()}})
        assert path.read_text() == 'old baseline'

    @pytest.mark.skipif(os.name == 'nt', reason='POSIX symlink')
    def test_repo_reached_through_symlinked_parent_still_works(self, tmp_path):
        """~/code -> /Volumes/x or /home -> var/home must not disable --watch."""
        real = tmp_path / 'real'
        (real / 'repo').mkdir(parents=True)
        link = tmp_path / 'link'
        link.symlink_to(real, target_is_directory=True)
        repo = str(link / 'repo')
        scanner.save_baseline(repo, {'files': {}})
        loaded, findings = scanner.load_baseline(repo)
        assert loaded['files'] == {} and findings == []
        assert (real / 'repo' / scanner.BASELINE_FILENAME).is_file()

    @pytest.mark.skipif(os.name == 'nt' or not (hasattr(os, 'O_PATH') or hasattr(os, 'O_SEARCH'))
                        or os.geteuid() == 0, reason='needs search-only opens, non-root')
    def test_repo_under_execute_only_parent_still_works(self, tmp_path):
        parent = tmp_path / 'xonly'
        (parent / 'repo').mkdir(parents=True)
        parent.chmod(0o111)
        try:
            scanner.save_baseline(str(parent / 'repo'), {'files': {}})
            loaded, findings = scanner.load_baseline(str(parent / 'repo'))
            assert loaded['files'] == {} and findings == []
        finally:
            parent.chmod(0o755)

    @pytest.mark.skipif(os.name == 'nt', reason='POSIX temp sweep')
    def test_stale_temp_from_killed_writer_is_removed(self, tmp_path):
        stale = tmp_path / ('.forensics-baseline-' + 'a' * 32 + '.tmp')
        fresh = tmp_path / ('.forensics-baseline-' + 'b' * 32 + '.tmp')
        victim = tmp_path / 'victim'
        victim.write_text('keep')
        linked = tmp_path / ('.forensics-baseline-' + 'c' * 32 + '.tmp')
        linked.symlink_to(victim)
        lookalike = tmp_path / '.forensics-baseline-notours.tmp'
        for path in (stale, fresh, lookalike):
            path.write_text('x')
        old = scanner.time.time() - 2 * scanner._STALE_AFTER_SECONDS
        for path in (stale, lookalike):
            os.utime(path, (old, old))
        os.utime(linked, (old, old), follow_symlinks=False)
        scanner.save_baseline(str(tmp_path), {'files': {}})
        assert not stale.exists()
        assert fresh.exists() and lookalike.exists() and linked.is_symlink()
        assert victim.read_text() == 'keep'

    def test_save_replaces_hardlink_not_victim(self, tmp_path):
        victim = tmp_path / 'victim'
        victim.write_text('keep')
        os.link(victim, tmp_path / scanner.BASELINE_FILENAME)
        scanner.save_baseline(str(tmp_path), {'files': {}})
        assert victim.read_text() == 'keep'

    @pytest.mark.skipif(os.name == 'nt', reason='POSIX FIFO')
    def test_special_file_refused_before_open(self, tmp_path):
        os.mkfifo(tmp_path / scanner.BASELINE_FILENAME)
        loaded, findings = scanner.load_baseline(str(tmp_path))
        assert loaded is None
        assert any(f.category == 'integrity-baseline-io' for f in findings)
        with pytest.raises(OSError):
            scanner.save_baseline(str(tmp_path), {'files': {}})

    def test_watch_reports_unsafe_destination_without_replacing(self, tmp_path):
        victim = tmp_path / 'victim'
        victim.write_text('keep')
        repo = tmp_path / 'repo'
        repo.mkdir()
        link = repo / scanner.BASELINE_FILENAME
        link.symlink_to(victim)
        findings = scanner.watch_mode(str(repo), {}, 'json')
        assert any(f.category == 'integrity-baseline-io' for f in findings)
        assert victim.read_text() == 'keep'
        assert link.is_symlink()

    @pytest.mark.skipif(os.name == 'nt', reason='POSIX directory fd race')
    def test_parent_swap_cannot_redirect_write(self, tmp_path, monkeypatch):
        repo = tmp_path / 'repo'
        repo.mkdir()
        moved = tmp_path / 'moved'
        outside = tmp_path / 'outside'
        outside.mkdir()
        (outside / scanner.BASELINE_FILENAME).write_text('keep')
        original = scanner.os.replace
        def swap(*args, **kwargs):
            repo.rename(moved)
            repo.symlink_to(outside, target_is_directory=True)
            return original(*args, **kwargs)
        monkeypatch.setattr(scanner.os, 'replace', swap)
        scanner.save_baseline(str(repo), {'files': {}})
        assert (outside / scanner.BASELINE_FILENAME).read_text() == 'keep'
        assert json.loads((moved / scanner.BASELINE_FILENAME).read_text())['files'] == {}

    @pytest.mark.skipif(os.name == 'nt', reason='POSIX replace injection; Windows tested separately')
    def test_replace_failure_preserves_baseline_and_cleans_temp(self, tmp_path, monkeypatch):
        baseline = tmp_path / scanner.BASELINE_FILENAME
        baseline.write_text('old')
        def fail(*args, **kwargs):
            raise OSError('injected replace failure')
        monkeypatch.setattr(scanner.os, 'replace', fail)
        with pytest.raises(OSError):
            scanner.save_baseline(str(tmp_path), {'files': {}})
        assert baseline.read_text() == 'old'
        assert list(tmp_path.glob('.forensics-baseline-*.tmp')) == []

    def test_interrupt_preserves_baseline_and_cleans_temp(self, tmp_path, monkeypatch):
        baseline = tmp_path / scanner.BASELINE_FILENAME
        baseline.write_text('old')
        def interrupt(*args):
            raise KeyboardInterrupt()
        monkeypatch.setattr(scanner.os, 'fsync', interrupt)
        with pytest.raises(KeyboardInterrupt):
            scanner.save_baseline(str(tmp_path), {'files': {}})
        assert baseline.read_text() == 'old'
        assert list(tmp_path.glob('.forensics-baseline-*.tmp')) == []

    def test_watch_save_error_is_visible(self, tmp_path, monkeypatch, capsys):
        def fail(*args):
            raise PermissionError('denied')
        monkeypatch.setattr(scanner, 'save_baseline', fail)
        findings = scanner.watch_mode(str(tmp_path), {}, 'json')
        assert any(f.category == 'integrity-baseline-io' for f in findings)
        assert 'Baseline created' not in capsys.readouterr().err

    def test_saved_baseline_has_private_mode(self, tmp_path):
        scanner.save_baseline(str(tmp_path), {'files': {}})
        if os.name != 'nt':
            assert stat.S_IMODE((tmp_path / scanner.BASELINE_FILENAME).stat().st_mode) == 0o600

    @pytest.mark.skipif(os.name != 'nt', reason='native Windows handles')
    def test_windows_parent_rename_cannot_redirect_write(self, tmp_path, monkeypatch):
        repo = tmp_path / 'repo'
        repo.mkdir()
        moved = tmp_path / 'moved'
        outside = tmp_path / 'outside'
        outside.mkdir()
        (outside / scanner.BASELINE_FILENAME).write_text('keep')
        original = scanner._WindowsBaselineIO.rename
        rename_blocked = []
        def swap(api, handle, directory, name):
            try:
                repo.rename(moved)
            except PermissionError:
                # Windows may prevent renaming a directory while its temporary
                # child is open. That is also a safe boundary, not a test skip.
                rename_blocked.append(True)
                assert repo.is_dir() and not moved.exists()
            else:
                repo.symlink_to(outside, target_is_directory=True)
            return original(api, handle, directory, name)
        monkeypatch.setattr(scanner._WindowsBaselineIO, 'rename', swap)
        scanner.save_baseline(str(repo), {'files': {}})
        assert (outside / scanner.BASELINE_FILENAME).read_text() == 'keep'
        destination = repo if rename_blocked else moved
        assert json.loads((destination / scanner.BASELINE_FILENAME).read_text())['files'] == {}

    @pytest.mark.skipif(os.name != 'nt', reason='native Windows handles')
    def test_windows_rename_failure_cleans_temp(self, tmp_path, monkeypatch):
        baseline = tmp_path / scanner.BASELINE_FILENAME
        baseline.write_text('old')
        def fail(*args):
            raise OSError('injected native rename failure')
        monkeypatch.setattr(scanner._WindowsBaselineIO, 'rename', fail)
        with pytest.raises(OSError):
            scanner.save_baseline(str(tmp_path), {'files': {}})
        assert baseline.read_text() == 'old'
        assert list(tmp_path.glob('.forensics-baseline-*.tmp')) == []

    @pytest.mark.skipif(scanner.sys.platform != 'darwin', reason='native macOS system aliases')
    def test_macos_system_tmp_alias_is_supported(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir='/tmp') as repo:
            scanner.save_baseline(repo, {'files': {}})
            loaded, findings = scanner.load_baseline(repo)
            assert loaded['files'] == {}
            assert not findings

    def test_windows_rename_uses_native_relative_handle_contract(self):
        """Check marshaling off-platform; native CI still owns filesystem behavior."""
        import ctypes as c
        class RenameInfo(c.Structure):
            _fields_ = [('Flags', c.c_uint32), ('RootDirectory', c.c_void_p),
                        ('FileNameLength', c.c_uint32), ('FileName', c.c_uint16 * 1)]
        class IOStatus(c.Structure):
            _fields_ = [('Status', c.c_void_p), ('Information', c.c_size_t)]
        calls = []
        class Native:
            def NtSetInformationFile(self, handle, status, buffer, length, kind):
                info = RenameInfo.from_buffer(buffer)
                name = c.string_at(c.addressof(buffer) + RenameInfo.FileName.offset,
                                   info.FileNameLength).decode('utf-16-le')
                calls.append((handle, info.RootDirectory, name, kind, info.Flags))
                assert length == RenameInfo.FileName.offset + info.FileNameLength
                return 0
        api = object.__new__(scanner._WindowsBaselineIO)
        api.c, api.RenameInfo, api.IOStatus, api.nt = c, RenameInfo, IOStatus, Native()
        api.rename(10, 20, scanner.BASELINE_FILENAME)
        assert calls == [(10, 20, scanner.BASELINE_FILENAME, 10, 1)]


class TestSigningKeyFileSafety:
    @pytest.mark.skipif(os.name == 'nt', reason='POSIX FIFO')
    def test_fifo_key_is_refused_without_waiting_for_writer(self, tmp_path):
        import subprocess
        import sys
        key = tmp_path / scanner.SIGNING_KEY_FILENAME
        os.mkfifo(key)
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import scan_integrity as s; "
                "s._read_signing_key(sys.argv[2])")
        result = subprocess.run(
            [sys.executable, '-c', code, os.path.dirname(scanner.__file__), str(key)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        assert result.returncode != 0
        assert b'OSError' in result.stderr


    def test_regular_key_bytes_are_preserved(self, tmp_path):
        key = tmp_path / scanner.SIGNING_KEY_FILENAME
        key.write_bytes(b'legacy short key remains supported')
        assert scanner._read_signing_key(str(key)) == key.read_bytes()

    def test_directory_key_is_refused(self, tmp_path):
        with pytest.raises(OSError):
            scanner._read_signing_key(str(tmp_path))

    @pytest.mark.skipif(os.name == 'nt', reason='POSIX no-follow')
    def test_link_key_is_refused_without_reading_target(self, tmp_path):
        target = tmp_path / 'target'
        target.write_bytes(b'keep')
        key = tmp_path / scanner.SIGNING_KEY_FILENAME
        key.symlink_to(target)
        with pytest.raises(OSError):
            scanner._read_signing_key(str(key))
        assert target.read_bytes() == b'keep'


    def test_new_key_writer_never_follows_dangling_link(self, tmp_path):
        target = tmp_path / 'victim'
        key = tmp_path / 'key'
        key.symlink_to(target)
        with pytest.raises(OSError):
            scanner._write_signing_key(str(key), b'test')
        assert not target.exists()
        assert key.is_symlink()

    def test_failed_key_creation_does_not_sign_ephemeral_baseline(self, repo_with_hooks, monkeypatch):
        def refused(*args):
            raise PermissionError('injected key creation refusal')
        monkeypatch.setattr(scanner, '_write_signing_key', refused)
        for _ in range(2):
            findings = scanner.watch_mode(str(repo_with_hooks), {}, 'text')
            assert any(f.category == 'integrity-baseline-io' for f in findings)
            assert not (repo_with_hooks / scanner.BASELINE_FILENAME).exists()

    def test_concurrent_creator_uses_persisted_winner(self, repo_with_hooks, monkeypatch):
        winner = b'winner key for concurrent creation'
        path = scanner._get_signing_key_path()
        def concurrent_create(*args):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as stream:
                stream.write(winner)
            raise FileExistsError('another creator won')
        monkeypatch.setattr(scanner, '_write_signing_key', concurrent_create)
        assert scanner._get_or_create_signing_key(str(repo_with_hooks)) == winner

    def test_existing_key_is_never_overwritten(self, tmp_path):
        path = tmp_path / 'key'
        path.write_bytes(b'old')
        with pytest.raises(FileExistsError):
            scanner._write_signing_key(str(path), b'new')
        assert path.read_bytes() == b'old'

    def test_key_fsync_failure_removes_partial_creation(self, tmp_path, monkeypatch):
        path = tmp_path / 'key'
        def fail(*args):
            raise OSError('injected fsync failure')
        monkeypatch.setattr(scanner.os, 'fsync', fail)
        with pytest.raises(OSError):
            scanner._write_signing_key(str(path), b'new')
        assert not path.exists()


    def test_key_not_visible_until_all_bytes_are_synced(self, tmp_path, monkeypatch):
        path = tmp_path / 'key'
        real_fsync = scanner.os.fsync
        def inspect(fd):
            assert not path.exists()
            real_fsync(fd)
        monkeypatch.setattr(scanner.os, 'fsync', inspect)
        scanner._write_signing_key(str(path), b'complete key')
        assert path.read_bytes() == b'complete key'
        assert list(tmp_path.glob('.forensics-key-*.tmp')) == []

    def test_empty_key_is_never_accepted(self, tmp_path):
        path = tmp_path / 'key'
        path.write_bytes(b'')
        with pytest.raises(OSError):
            scanner._read_signing_key(str(path))


class TestHostileSettingsShapes:
    @pytest.mark.parametrize('contents', [
        '{"hooks": 1}', '[1, 2]', '{"hooks": {"E": [5, null, "x"]}}',
        '{"hooks": {"E": [{"hooks": 7}]}}', '{"hooks": {"E": [{"command": 9}]}}',
        '"text"',
    ])
    def test_malformed_settings_never_crash_the_scanner(self, tmp_path, contents):
        (tmp_path / '.claude').mkdir()
        settings = tmp_path / '.claude' / 'settings.json'
        settings.write_text(contents)
        files = scanner.find_critical_files(str(tmp_path))
        assert '.claude/settings.json' in {p.replace(os.sep, '/') for p in files}
        scanner.check_hooks_in_settings(str(settings), '.claude/settings.json')
        scanner.watch_mode(str(tmp_path), files, 'text')

    def test_nested_hook_script_is_tracked_for_drift(self, tmp_path):
        (tmp_path / '.claude').mkdir()
        (tmp_path / 'hooks').mkdir()
        (tmp_path / 'hooks' / 'start.sh').write_text('echo hi\n')
        (tmp_path / '.claude' / 'settings.json').write_text(json.dumps({'hooks': {
            'SessionStart': [{'matcher': '', 'hooks': [
                {'type': 'command', 'command': 'bash hooks/start.sh'}]}]}}))
        files = scanner.find_critical_files(str(tmp_path))
        assert os.path.join('hooks', 'start.sh') in files
        scanner.watch_mode(str(tmp_path), files, 'text')
        (tmp_path / 'hooks' / 'start.sh').write_text('echo changed\n')
        findings = scanner.watch_mode(str(tmp_path), scanner.find_critical_files(str(tmp_path)), 'text')
        assert any(f.category == 'integrity-drift' for f in findings)


class TestRetiredKeyAndRemovedBaseline:
    """Up to 2.14.18 a repo's key could be copied into ~/.cache/.../forensics-key."""

    @staticmethod
    def _sign_with(repo, key):
        files = scanner.find_critical_files(str(repo))
        baseline = {'files': {r: scanner.sha256_file(p) for r, p in files.items()},
                    '_meta': {'created': '2026-01-01T00:00:00Z', 'tool': 't', 'version': 'v1'}}
        content = json.dumps(baseline, sort_keys=True)
        baseline['_hmac'] = hmac.new(key, content.encode('utf-8'), hashlib.sha256).hexdigest()
        (repo / scanner.BASELINE_FILENAME).write_text(json.dumps(baseline))

    @staticmethod
    def _plant_retired(key):
        path = scanner._get_retired_signing_key_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(key)

    def test_new_key_never_reuses_the_retired_file(self, repo_with_hooks):
        assert scanner._get_signing_key_path() != scanner._get_retired_signing_key_path()
        self._plant_retired(b'imported from a hostile repo')
        scanner.watch_mode(str(repo_with_hooks), scanner.find_critical_files(str(repo_with_hooks)), 'text')
        assert open(scanner._get_signing_key_path(), 'rb').read() != b'imported from a hostile repo'

    def test_baseline_signed_with_retired_key_is_not_trusted(self, repo_with_hooks):
        """Forged baseline approving a malicious CLAUDE.md must not read as clean."""
        imported = b'key an old version copied from a hostile repo'
        self._plant_retired(imported)
        (repo_with_hooks / 'CLAUDE.md').write_text('# malicious\n')
        self._sign_with(repo_with_hooks, imported)
        findings = scanner.watch_mode(str(repo_with_hooks),
                                      scanner.find_critical_files(str(repo_with_hooks)), 'text')
        assert [f.title for f in findings] == ['Baseline signed with a retired key']

    def test_repo_shipping_the_retired_key_is_critical(self, repo_with_hooks):
        imported = b'key an old version copied from a hostile repo'
        self._plant_retired(imported)
        (repo_with_hooks / scanner.SIGNING_KEY_FILENAME).write_bytes(imported)
        findings = scanner.watch_mode(str(repo_with_hooks),
                                      scanner.find_critical_files(str(repo_with_hooks)), 'text')
        assert any(f.severity == 'critical' and 'ships the key' in f.title for f in findings)

    def test_removed_baseline_is_reported_then_recreated(self, repo_with_hooks):
        files = scanner.find_critical_files(str(repo_with_hooks))
        assert scanner.watch_mode(str(repo_with_hooks), files, 'text') == []
        (repo_with_hooks / scanner.BASELINE_FILENAME).unlink()
        (repo_with_hooks / 'CLAUDE.md').write_text('# tampered after the pull\n')
        findings = scanner.watch_mode(str(repo_with_hooks), scanner.find_critical_files(str(repo_with_hooks)), 'text')
        assert [f.title for f in findings] == ['Integrity baseline was removed']
        assert (repo_with_hooks / scanner.BASELINE_FILENAME).exists()
        assert scanner.watch_mode(str(repo_with_hooks), scanner.find_critical_files(str(repo_with_hooks)), 'text') == []

    def test_first_run_without_marker_is_quiet(self, repo_with_hooks):
        assert scanner.watch_mode(str(repo_with_hooks), scanner.find_critical_files(str(repo_with_hooks)), 'text') == []

    def test_deeply_nested_settings_never_crash(self, tmp_path):
        (tmp_path / '.claude').mkdir()
        settings = tmp_path / '.claude' / 'settings.json'
        settings.write_text('[' * 100000)
        scanner.find_critical_files(str(tmp_path))
        scanner.check_hooks_in_settings(str(settings), '.claude/settings.json')
