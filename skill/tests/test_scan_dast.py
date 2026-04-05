"""Tests for scan_dast.py - Dynamic Analysis Security Testing."""

import os
import json
import pytest
import scan_dast as scanner


class TestHookDiscovery:
    def test_finds_registered_hooks(self, repo_with_hook_scripts):
        hooks = scanner.find_hook_scripts(str(repo_with_hook_scripts))
        assert len(hooks) >= 1
        events = [h['event'] for h in hooks]
        assert 'PreToolUse' in events

    def test_finds_standalone_scripts(self, repo_with_hook_scripts):
        hooks = scanner.find_hook_scripts(str(repo_with_hook_scripts))
        standalone = [h for h in hooks if h['event'] == 'standalone']
        assert len(standalone) >= 1

    def test_empty_repo(self, clean_repo):
        hooks = scanner.find_hook_scripts(str(clean_repo))
        assert len(hooks) == 0


class TestSafeEnv:
    def test_minimal_env(self):
        env = scanner.build_safe_env()
        assert 'PATH' in env
        assert 'HOME' in env
        # Should NOT inherit real environment
        assert len(env) <= 6

    def test_extra_vars_merged(self):
        env = scanner.build_safe_env({'MY_VAR': 'test'})
        assert env['MY_VAR'] == 'test'
        assert 'PATH' in env


class TestPayloadExecution:
    def test_detects_env_leak(self, repo_with_hook_scripts):
        hooks = scanner.find_hook_scripts(str(repo_with_hook_scripts))
        # Find the leaky hook
        leaky = [h for h in hooks if 'leaky' in h.get('source', '') or 'leaky' in h.get('command', '')]
        if not leaky:
            # Use the registered hook (which points to leaky-hook.sh)
            leaky = [h for h in hooks if h['event'] == 'PreToolUse']
        assert len(leaky) > 0

        env_payload = scanner.PAYLOADS[5]  # env_exfiltration
        findings = scanner.execute_hook_with_payload(leaky[0], env_payload, str(repo_with_hook_scripts))
        assert any("leaked" in f.title.lower() or "canary" in f.snippet.lower() for f in findings)

    def test_detects_timeout(self, repo_with_hook_scripts):
        # The hang-hook.sh sleeps for 30s, should timeout at 5s
        hooks = scanner.find_hook_scripts(str(repo_with_hook_scripts))
        hang = [h for h in hooks if 'hang' in h.get('source', '') or 'hang' in h.get('command', '')]
        if hang:
            findings = scanner.execute_hook_with_payload(hang[0], scanner.PAYLOADS[0], str(repo_with_hook_scripts))
            assert any("timeout" in f.title.lower() for f in findings)

    def test_clean_hook_no_findings(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        safe_hook = claude_dir / "safe-hook.sh"
        safe_hook.write_text("#!/bin/bash\nexit 0\n")
        safe_hook.chmod(0o755)
        settings = claude_dir / "settings.json"
        settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"command": str(safe_hook)}]}}))

        hooks = scanner.find_hook_scripts(str(tmp_path))
        all_findings = []
        for hook in hooks:
            for payload in scanner.PAYLOADS:
                all_findings.extend(scanner.execute_hook_with_payload(hook, payload, str(tmp_path)))
        critical = [f for f in all_findings if f.severity == "critical"]
        assert len(critical) == 0


class TestPayloads:
    def test_all_payloads_have_required_fields(self):
        for p in scanner.PAYLOADS:
            assert 'name' in p
            assert 'description' in p
            assert 'env_extra' in p
            assert 'stdin' in p
            assert 'severity_on_fail' in p

    def test_payload_count(self):
        assert len(scanner.PAYLOADS) == 8


class TestSandboxHookExecution:
    """Regression: the macOS Seatbelt profile denies /Users reads broadly,
    which means a hook living under /Users/... would fail to load at all
    (bash: Operation not permitted, exit 126). The fix re-allows reads on
    the specific hook path via sandbox-exec -D params. These tests catch
    any regression of that bug by asserting the hook ACTUALLY executes.
    """

    @pytest.mark.skipif(
        not scanner.SANDBOX_AVAILABLE,
        reason="macOS Seatbelt sandbox only",
    )
    def test_sandbox_reads_hook_under_users_path(self, tmp_path):
        """Hook lives under a /Users-shaped path and leaks a canary;
        sandbox must permit the hook to LOAD so the canary leaks."""
        # tmp_path on macOS is typically under /var/folders/... which is
        # already allowed. Mirror the /Users shape so the deny rule applies.
        users_dir = tmp_path / "Users" / "alice" / "repo" / ".claude"
        users_dir.mkdir(parents=True)
        hook = users_dir / "leaky-hook.sh"
        hook.write_text(
            "#!/bin/bash\n"
            "echo \"TOKEN=$SECRET_TOKEN\"\n"
        )
        hook.chmod(0o755)

        hook_info = {
            'event': 'standalone',
            'command': str(hook),
            'source': str(hook),
        }
        # env_exfiltration payload injects SECRET_TOKEN=CANARY_12345
        env_payload = next(p for p in scanner.PAYLOADS if p['name'] == 'env_exfiltration')
        findings = scanner.execute_hook_with_payload(hook_info, env_payload, str(tmp_path))

        # If the hook LOADED, the canary leaked to stdout, so a critical
        # finding is produced. If the sandbox blocked the load (old bug),
        # no canary reaches stdout and no finding is produced.
        canary_findings = [f for f in findings if 'CANARY' in f.snippet or 'leaked' in f.title.lower()]
        assert len(canary_findings) >= 1, (
            "Sandbox blocked hook execution under /Users-shaped path — "
            "regression of P0 bug (HOOK_PATH/HOOK_DIR params not working). "
            f"Got findings: {[f.title for f in findings]}"
        )

    @pytest.mark.skipif(
        not scanner.SANDBOX_AVAILABLE,
        reason="macOS Seatbelt sandbox only",
    )
    def test_sandbox_still_denies_other_users_reads(self, tmp_path):
        """The fix re-allows reads on HOOK_DIR only, not all of /Users.
        A hook trying to read an unrelated /Users path must still be denied."""
        hook_dir = tmp_path / "Users" / "alice" / "repo" / ".claude"
        hook_dir.mkdir(parents=True)
        hook = hook_dir / "curious-hook.sh"
        # Try to read a file under a DIFFERENT /Users path (outside HOOK_DIR).
        # We use /Users/alexgreenshpun/.zshrc as a known-existing file since
        # tests run under that user; the sandbox should still block it.
        probe_path = os.path.expanduser("~/.zshrc")
        hook.write_text(
            "#!/bin/bash\n"
            f"cat '{probe_path}' 2>&1 || echo 'BLOCKED'\n"
        )
        hook.chmod(0o755)

        hook_info = {
            'event': 'standalone',
            'command': str(hook),
            'source': str(hook),
        }
        # Invoke the sandbox directly so we can inspect stdout/stderr
        import subprocess
        real = os.path.realpath(str(hook))
        cmd = [
            '/usr/bin/sandbox-exec',
            '-D', f'HOOK_PATH={real}',
            '-D', f'HOOK_DIR={os.path.dirname(real)}',
            '-f', scanner.SANDBOX_PROFILE,
            '/bin/bash', str(hook),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        combined = proc.stdout + proc.stderr
        # Must NOT leak .zshrc contents; must see the blocked marker OR
        # a permission denied error from cat.
        assert 'BLOCKED' in combined or 'Operation not permitted' in combined or 'denied' in combined.lower(), (
            f"Sandbox allowed read of unrelated /Users path. stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
