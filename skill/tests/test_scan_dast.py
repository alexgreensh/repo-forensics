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
