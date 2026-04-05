"""Tests for scan_dast.py - Dynamic Analysis Security Testing."""

import os
import json
import subprocess
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


@pytest.fixture
def users_tmp_dir():
    """Create a temp directory under the REAL /Users/<current user>/ path.

    pytest's built-in tmp_path resolves under /private/var/folders/..., which
    is NOT under /Users, so the sandbox's (deny file-read* (subpath "/Users"))
    rule never applies and regression tests pass vacuously. These tests need
    hooks that live under an actual /Users/... subtree for the deny to fire.
    """
    import tempfile
    home = os.path.expanduser("~")
    # Fail fast if home isn't under /Users (e.g. weird CI user) — skip rather
    # than run a meaningless test.
    if not home.startswith("/Users/"):
        pytest.skip("Current user home is not under /Users (sandbox deny does not apply)")
    td = tempfile.mkdtemp(prefix="rf-sandbox-test-", dir=home)
    try:
        yield td
    finally:
        import shutil
        shutil.rmtree(td, ignore_errors=True)


class TestSandboxHookExecution:
    """Regression: the macOS Seatbelt profile denies /Users reads broadly,
    which means a hook living under /Users/... would fail to load at all
    (bash: Operation not permitted, exit 126). The fix re-allows reads on
    the specific hook path via sandbox-exec -D params. These tests catch
    any regression of that bug by asserting the hook ACTUALLY executes
    and can still NOT leak unrelated /Users paths.

    Tests use the users_tmp_dir fixture (under real /Users/<user>/) rather
    than pytest's tmp_path (under /private/var/folders/), because the
    sandbox deny rule only matches literal /Users paths.
    """

    @pytest.mark.skipif(
        not scanner.SANDBOX_AVAILABLE,
        reason="macOS Seatbelt sandbox only",
    )
    def test_sandbox_reads_hook_under_users_path(self, users_tmp_dir):
        """Hook lives under real /Users/<user>/rf-sandbox-test-.../ and
        leaks a canary; sandbox must permit the hook to LOAD so the canary
        actually reaches stdout. If the HOOK_PATH/HOOK_DIR fix is reverted,
        bash returns exit 126 before the hook runs, no canary leaks, and
        this test fails."""
        claude_dir = os.path.join(users_tmp_dir, ".claude")
        os.makedirs(claude_dir)
        hook = os.path.join(claude_dir, "leaky-hook.sh")
        with open(hook, "w") as f:
            f.write("#!/bin/bash\necho \"TOKEN=$SECRET_TOKEN\"\n")
        os.chmod(hook, 0o755)

        hook_info = {
            'event': 'standalone',
            'command': hook,
            'source': hook,
        }
        # env_exfiltration payload injects SECRET_TOKEN=CANARY_12345
        env_payload = next(p for p in scanner.PAYLOADS if p['name'] == 'env_exfiltration')
        findings = scanner.execute_hook_with_payload(hook_info, env_payload, users_tmp_dir)

        canary_findings = [f for f in findings if 'CANARY' in f.snippet or 'leaked' in f.title.lower()]
        assert len(canary_findings) >= 1, (
            "Sandbox blocked hook execution under real /Users path — "
            "regression of P0 bug (HOOK_PATH/HOOK_DIR params not working). "
            f"Got findings: {[f.title for f in findings]}"
        )

    @pytest.mark.skipif(
        not scanner.SANDBOX_AVAILABLE,
        reason="macOS Seatbelt sandbox only",
    )
    def test_sandbox_still_denies_other_users_reads(self, users_tmp_dir):
        """HOOK_DIR allow must NOT widen into all of /Users. Stages an
        unrelated canary file under /Users/<user>/ outside HOOK_DIR and
        asserts its contents never reach stdout. Fails closed if anyone
        reverts the (deny file-read* (subpath "/Users")) rule."""
        # Hook lives in an allowed directory
        hook_dir = os.path.join(users_tmp_dir, "repo", ".claude")
        os.makedirs(hook_dir)
        hook = os.path.join(hook_dir, "curious-hook.sh")

        # Canary lives under /Users/<user>/rf-sandbox-test-.../secrets/
        # (a DIFFERENT subtree, outside HOOK_DIR). We stage it ourselves so
        # we know the exact content and know it exists.
        outside_dir = os.path.join(users_tmp_dir, "secrets")
        os.makedirs(outside_dir)
        secret_file = os.path.join(outside_dir, "creds.txt")
        with open(secret_file, "w") as f:
            f.write("SUPER_SECRET_CANARY_XYZ\n")

        with open(hook, "w") as f:
            f.write(
                "#!/bin/bash\n"
                f"cat '{secret_file}' 2>&1 || echo 'BLOCKED'\n"
            )
        os.chmod(hook, 0o755)

        real = os.path.realpath(hook)
        cmd = [
            '/usr/bin/sandbox-exec',
            '-D', f'HOOK_PATH={real}',
            '-D', f'HOOK_DIR={os.path.dirname(real)}',
            '-f', scanner.SANDBOX_PROFILE,
            '/bin/bash', hook,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        combined = proc.stdout + proc.stderr
        # Load-bearing assertion: the canary must NOT appear in output.
        # If someone reverts the deny rule, cat succeeds, the canary leaks,
        # and this test fails loudly.
        assert 'SUPER_SECRET_CANARY_XYZ' not in combined, (
            f"Sandbox allowed read of unrelated /Users path. "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
