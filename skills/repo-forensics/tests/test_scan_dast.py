"""Tests for scan_dast.py - Dynamic Analysis Security Testing."""

import os
import sys
import json
import io
import shutil
import signal
import subprocess
import time
from types import SimpleNamespace
import pytest
import scan_dast as scanner


_NEEDS_POSIX_HOOKS = pytest.mark.skipif(
    os.name == "nt",
    reason="hook discovery and DAST execution rely on the POSIX executable bit and on running .sh directly; Windows has neither")

_NEEDS_WORKING_SANDBOX = pytest.mark.skipif(
    not (scanner.SANDBOX_AVAILABLE or scanner.BWRAP_AVAILABLE),
    reason="DAST needs a usable Seatbelt or bubblewrap sandbox",
)


_NEEDS_BWRAP = pytest.mark.skipif(
    not scanner.BWRAP_AVAILABLE,
    reason="Linux bubblewrap sandbox only",
)


_NEEDS_LINUX = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux bubblewrap sandbox semantics; the unit tests assert POSIX "
           "paths that realpath rewrites elsewhere (macOS firmlinks, "
           "Windows drive prefixes)",
)


def _host_pids_with_marker(marker):
    """Host pids whose command line carries the marker. Marker-based lookup
    is the only safe way to spot an escaped sandbox descendant: a pid read
    from inside a PID namespace means nothing on the host and may name an
    unrelated process."""
    out = subprocess.run(["ps", "ax", "-o", "pid=,args="],
                         capture_output=True, text=True, timeout=2)
    pids = []
    for line in out.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and marker in parts[1] and "ps ax" not in parts[1]:
            pids.append(int(parts[0]))
    return pids


class TestHookDiscovery:
    def test_finds_registered_hooks(self, repo_with_hook_scripts):
        hooks = scanner.find_hook_scripts(str(repo_with_hook_scripts))
        assert len(hooks) >= 1
        events = [h['event'] for h in hooks]
        assert 'PreToolUse' in events

    @_NEEDS_POSIX_HOOKS
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
    @_NEEDS_POSIX_HOOKS
    def test_without_sandbox_hook_is_not_executed(self, tmp_path, monkeypatch):
        hook = tmp_path / "hook.sh"
        marker = tmp_path / "executed"
        hook.write_text(f"#!/bin/sh\nprintf executed > '{marker}'\n")
        hook.chmod(0o755)
        monkeypatch.setattr(scanner, "SANDBOX_AVAILABLE", False)
        monkeypatch.setattr(scanner, "BWRAP_AVAILABLE", False)
        findings = scanner.execute_hook_with_payload(
            {"event": "test", "command": str(hook), "source": "hook.sh"},
            scanner.PAYLOADS[0], str(tmp_path),
        )
        assert not marker.exists()
        assert any(f.category == "scan-incomplete" for f in findings)

    @_NEEDS_POSIX_HOOKS
    def test_sandbox_launch_failure_is_incomplete(self, tmp_path, monkeypatch):
        hook = tmp_path / "hook.sh"
        hook.write_text("#!/bin/sh\nexit 0\n")
        hook.chmod(0o755)
        monkeypatch.setattr(scanner, "SANDBOX_AVAILABLE", True)
        monkeypatch.setattr(scanner.subprocess, "Popen", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("sandbox unavailable")))
        findings = scanner.execute_hook_with_payload(
            {"event": "test", "command": str(hook), "source": "hook.sh"},
            scanner.PAYLOADS[0], str(tmp_path),
        )
        assert any(f.category == "scan-incomplete" for f in findings)

    @_NEEDS_POSIX_HOOKS
    def test_sandbox_exit_127_is_incomplete(self, tmp_path, monkeypatch):
        hook = tmp_path / "hook.sh"
        hook.write_text("#!/bin/sh\nexit 0\n")
        hook.chmod(0o755)
        monkeypatch.setattr(scanner, "SANDBOX_AVAILABLE", True)
        monkeypatch.setattr(scanner, "_run_hook_process", lambda *args, **kwargs: (
            subprocess.CompletedProcess(args[0], 127, "", "sandbox-exec: invalid profile"), False, ""))
        findings = scanner.execute_hook_with_payload(
            {"event": "test", "command": str(hook), "source": "hook.sh"},
            scanner.PAYLOADS[0], str(tmp_path),
        )
        assert any(f.category == "scan-incomplete" for f in findings)

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_WORKING_SANDBOX
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

    @_NEEDS_WORKING_SANDBOX
    def test_detects_timeout(self, repo_with_hook_scripts):
        # The hang-hook.sh sleeps for 30s, should timeout at 5s
        hooks = scanner.find_hook_scripts(str(repo_with_hook_scripts))
        hang = [h for h in hooks if 'hang' in h.get('source', '') or 'hang' in h.get('command', '')]
        if hang:
            findings = scanner.execute_hook_with_payload(hang[0], scanner.PAYLOADS[0], str(repo_with_hook_scripts))
            assert any("timeout" in f.title.lower() for f in findings)

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_WORKING_SANDBOX
    @pytest.mark.parametrize("wait_for_child", [True, False])
    def test_hook_descendants_are_stopped(self, tmp_path, monkeypatch, wait_for_child):
        hook = tmp_path / "spawn.sh"
        # Descendants are tracked by a unique marker in their command line,
        # NOT by the pid the hook reports: under a PID namespace ($! is a
        # namespace-local pid) that number can collide with an unrelated
        # host process, and signalling it on the host is a bug, not a check.
        marker = f"rf-dast-marker-{os.getpid()}-{int(wait_for_child)}"
        # The second case closes the child's pipes so the leader exits cleanly;
        # cleanup must still stop its background child.
        background = (f"sh -c 'sleep 30' {marker} &" if wait_for_child
                      else f"(exec 1>&- 2>&-; exec sh -c 'sleep 30' {marker}) &")
        hook.write_text(f"#!/bin/sh\n{background}\nprintf 'CHILD=%s\\n' \"$!\"\n" +
                        ("wait\n" if wait_for_child else "exit 0\n"))
        hook.chmod(0o755)
        monkeypatch.setattr(scanner, "EXEC_TIMEOUT", 0.5)
        observed = []
        run_hook = scanner._run_hook_process

        def capture(*args):
            result = run_hook(*args)
            observed.append(result[0])
            return result

        monkeypatch.setattr(scanner, "_run_hook_process", capture)
        try:
            start = time.monotonic()
            findings = scanner.execute_hook_with_payload(
                {"event": "test", "command": str(hook), "source": "spawn.sh"},
                scanner.PAYLOADS[0], str(tmp_path),
            )
            assert time.monotonic() - start < 4
            output = observed[0].stdout
            assert output.startswith("CHILD="), (output, observed[0].stderr, findings)
            assert any(f.category == "dast-timeout" for f in findings) == wait_for_child
            assert not any(f.snippet == "process-cleanup-failed" for f in findings)
            if not wait_for_child:
                assert findings == []
            deadline = time.monotonic() + 3
            while _host_pids_with_marker(marker):
                assert time.monotonic() < deadline, f"child with {marker} survived cleanup"
                time.sleep(0.02)
        finally:
            for pid in _host_pids_with_marker(marker):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass

    @_NEEDS_POSIX_HOOKS
    def test_cleanup_failure_is_reported_for_every_payload(self, tmp_path, monkeypatch):
        hook = tmp_path / "hook.sh"
        hook.write_text("exit 0\n")
        monkeypatch.setattr(scanner, "SANDBOX_AVAILABLE", True)
        monkeypatch.setattr(scanner, "_run_hook_process", lambda *args: (
            subprocess.CompletedProcess(args[0], -9, "", ""), True, "group kill denied"))
        findings = scanner.execute_hook_with_payload(
            {"event": "test", "command": str(hook), "source": "hook.sh"},
            scanner.PAYLOADS[5], str(tmp_path),
        )
        assert any(f.category == "scan-incomplete" and f.severity == "high" and
                   "group kill denied" in f.description for f in findings)

    @_NEEDS_POSIX_HOOKS
    def test_failed_cleanup_drain_is_bounded_and_launcher_is_reaped(self, monkeypatch):
        class StuckProcess:
            pid = 123456789
            returncode = None

            def __init__(self):
                self.stdin, self.stdout, self.stderr = (io.StringIO() for _ in range(3))
                self.timeouts = []
                self.killed = False
                self.reaped = False

            def communicate(self, *args, timeout):
                self.timeouts.append(timeout)
                raise subprocess.TimeoutExpired("hook", timeout, output=b"partial")

            def kill(self):
                self.killed = True

            def wait(self, timeout):
                assert timeout == scanner.PROCESS_CLEANUP_TIMEOUT
                self.reaped = True
                self.returncode = -9
                return -9

        proc = StuckProcess()

        def launch(*args, **kwargs):
            assert kwargs["start_new_session"] is True
            return proc

        def denied_group_kill(*args):
            raise PermissionError("group kill denied")

        monkeypatch.setattr(scanner.subprocess, "Popen", launch)
        monkeypatch.setattr(scanner.os, "killpg", denied_group_kill)
        completed, timed_out, error = scanner._run_hook_process(["hook"], "", {})
        assert timed_out and completed.stdout == "partial"
        assert proc.timeouts == [scanner.EXEC_TIMEOUT, scanner.PROCESS_CLEANUP_TIMEOUT]
        assert proc.killed and proc.reaped
        assert all(pipe.closed for pipe in (proc.stdin, proc.stdout, proc.stderr))
        assert "group kill denied" in error and "cleanup did not complete" in error

    def test_cleanup_failure_stops_further_hook_execution(self, monkeypatch):
        failure = scanner.core.Finding(
            scanner="dast", severity="high", title="cleanup failed", description="failed",
            file="hook.sh", line=0, snippet="process-cleanup-failed", category="scan-incomplete")
        calls, emitted = [], []
        monkeypatch.setattr(scanner.core, "parse_common_args", lambda *args:
                            SimpleNamespace(repo_path="repo", format="json"))
        monkeypatch.setattr(scanner.core, "emit_status", lambda *args: None)
        monkeypatch.setattr(scanner, "find_hook_scripts", lambda *args:
                            [{"event": "test", "source": "hook.sh"}] * 2)
        monkeypatch.setattr(scanner, "execute_hook_with_payload", lambda *args:
                            calls.append(args) or [failure])
        monkeypatch.setattr(scanner.core, "output_findings", lambda findings, *args:
                            emitted.extend(findings))
        scanner.main()
        assert len(calls) == 1
        assert emitted == [failure]

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
    def test_sandbox_denies_system_config_reads(self):
        # /private/etc lies outside /Users and was readable with allow-default.
        # Require proof bash starts, so an invalid profile cannot pass the test.
        profile = os.path.realpath(scanner.SANDBOX_PROFILE)
        proc = subprocess.run([
            scanner._SANDBOX_EXEC,
            '-D', f'HOOK_PATH={profile}',
            '-D', f'HOOK_DIR={os.path.dirname(profile)}',
            '-f', profile,
            '/bin/bash', '-c', 'echo STARTED; /bin/cat /private/etc/hosts',
        ], capture_output=True, text=True, timeout=5)
        assert proc.stdout == "STARTED\n"
        assert proc.returncode != 0
        assert "Operation not permitted" in proc.stderr

    @pytest.mark.skipif(
        not scanner.SANDBOX_AVAILABLE,
        reason="macOS Seatbelt sandbox only",
    )
    def test_sandbox_denies_writes_outside_users(self, tmp_path):
        target = tmp_path.resolve() / "outside-users-canary"
        if str(target).startswith('/Users/'):
            pytest.skip("Probe target must be outside /Users")
        profile = os.path.realpath(scanner.SANDBOX_PROFILE)
        proc = subprocess.run([
            scanner._SANDBOX_EXEC,
            '-D', f'HOOK_PATH={profile}',
            '-D', f'HOOK_DIR={os.path.dirname(profile)}',
            '-f', profile,
            '/bin/sh', '-c', 'printf canary > "$1"', 'sh', str(target),
        ], capture_output=True, text=True, timeout=5)
        assert proc.returncode != 0
        assert not target.exists()

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
            scanner._SANDBOX_EXEC,
            '-D', f'HOOK_PATH={real}',
            '-D', f'HOOK_DIR={os.path.dirname(real)}',
            '-f', scanner.SANDBOX_PROFILE,
            shutil.which('bash') or '/bin/bash', hook,
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


@_NEEDS_LINUX
class TestLinuxBwrapSandbox:
    """The Linux sandbox must rebuild its root from minimal read-only binds,
    never expose the host filesystem to an executed hook, and fail closed
    when the sandbox cannot be enforced. Mirrors the Seatbelt class above."""

    def test_no_host_root_bind(self):
        cmd = scanner._build_bwrap_exec_cmd(["/usr/bin/bash", "/x/hook.sh"],
                                            "/x/hook.sh")
        binds = [cmd[i + 1] for i, a in enumerate(cmd[:-1])
                 if a == "--ro-bind"]
        assert "/" not in binds, "host root must never be bound"
        allowed = set(scanner._bwrap_system_roots()) | {"/x"}
        for src in binds:
            assert src in allowed, f"unexpected ro-bind source {src}"

    def test_every_bound_root_is_readonly(self):
        cmd = scanner._build_bwrap_exec_cmd(["/usr/bin/bash", "/x/hook.sh"],
                                            "/x/hook.sh")
        assert "--bind" not in cmd, "writable binds are never used"
        assert "--tmpfs" in cmd  # only /tmp is writable, and it is a tmpfs

    def test_namespaces_unshared(self):
        cmd = scanner._build_bwrap_exec_cmd(["/usr/bin/bash", "/x/hook.sh"],
                                            "/x/hook.sh")
        for flag in ("--unshare-net", "--unshare-pid", "--unshare-ipc",
                     "--die-with-parent"):
            assert flag in cmd

    def test_hook_dir_bound_after_tmpfs(self):
        # A repo cloned under /tmp must stay readable: the hook dir re-bind
        # has to come after --tmpfs /tmp or the tmpfs shadows it.
        cmd = scanner._build_bwrap_exec_cmd(["/usr/bin/bash", "/t/r/h.sh"],
                                            "/t/r/h.sh")
        assert cmd.index("--tmpfs") < cmd.index("/t/r")

    @_NEEDS_POSIX_HOOKS
    def test_interpreter_resolved_into_bound_tree(self, tmp_path):
        # shutil.which can return a symlink chain whose target lives
        # elsewhere; the command must use the resolved path.
        real = tmp_path / "real-interp"
        real.write_text("")
        link = tmp_path / "link-interp"
        link.symlink_to(real)
        cmd = scanner._build_bwrap_exec_cmd([str(link), "/x/hook.sh"],
                                            "/x/hook.sh")
        assert cmd[-2] == str(real)

    def test_extra_binds_cover_pyenv_prefix_only(self, monkeypatch):
        monkeypatch.setenv("HOME", "/home/u")
        monkeypatch.setattr(os.path, "isdir", lambda p: True)
        binds = scanner._bwrap_extra_binds(
            "/home/u/.pyenv/versions/3.11.2/bin/python3")
        assert binds == ["/home/u/.pyenv/versions/3.11.2"]

    def test_extra_binds_never_bind_home(self, monkeypatch):
        monkeypatch.setenv("HOME", "/home/u")
        monkeypatch.setattr(os.path, "isdir", lambda p: True)
        # Interpreter directly in $HOME: nothing is bound; the run fails
        # closed (exit 127 -> scan-incomplete) rather than expose ~.
        assert scanner._bwrap_extra_binds("/home/u/python3") == []
        # Interpreter in ~/bin: the bin dir binds, $HOME itself never does.
        binds = scanner._bwrap_extra_binds("/home/u/bin/python3")
        assert binds == ["/home/u/bin"]

    def test_extra_binds_skip_system_interpreters(self):
        assert scanner._bwrap_extra_binds("/usr/bin/bash") == []

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_BWRAP
    def test_hook_executes_and_writes_nothing_host_side(self, tmp_path):
        hook = tmp_path / "hook.sh"
        hook.write_text("#!/bin/sh\necho HOOK_RAN\n")
        hook.chmod(0o755)
        findings = scanner.execute_hook_with_payload(
            {"event": "test", "command": str(hook), "source": "hook.sh"},
            scanner.PAYLOADS[0], str(tmp_path))
        assert findings == []

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_BWRAP
    def test_hook_cannot_read_host_file_outside_hook_dir(self, tmp_path):
        # Canary in a sibling subtree: with --ro-bind / / the hook could cat
        # it and smuggle the contents into captured output (and from there
        # into findings). The canary must never appear.
        hook_dir = tmp_path / "repo" / ".claude"
        hook_dir.mkdir(parents=True)
        hook = hook_dir / "curious.sh"
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        canary = secrets / "creds.txt"
        canary.write_text("SUPER_SECRET_CANARY_XYZ\n")
        hook.write_text(f"#!/bin/sh\ncat '{canary}' 2>&1 || echo BLOCKED\n")
        hook.chmod(0o755)
        cmd = scanner._build_bwrap_exec_cmd(
            [shutil.which("bash") or "/bin/bash", str(hook)],
            os.path.realpath(str(hook)))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        combined = proc.stdout + proc.stderr
        assert "SUPER_SECRET_CANARY_XYZ" not in combined
        assert "BLOCKED" in combined

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_BWRAP
    def test_hook_cannot_read_etc_or_home(self, tmp_path):
        hook = tmp_path / "hook.sh"
        hook.write_text(
            "#!/bin/sh\n"
            "cat /etc/passwd 2>/dev/null && echo ETC_READ || echo ETC_DENIED\n"
            "ls /home/*/ 2>/dev/null && echo HOME_READ || echo HOME_DENIED\n"
            "cat /etc/shadow 2>/dev/null && echo SHADOW_READ || echo SHADOW_DENIED\n")
        hook.chmod(0o755)
        cmd = scanner._build_bwrap_exec_cmd(
            [shutil.which("bash") or "/bin/bash", str(hook)],
            os.path.realpath(str(hook)))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        assert "ETC_DENIED" in proc.stdout and "ETC_READ" not in proc.stdout
        assert "SHADOW_DENIED" in proc.stdout
        assert "HOME_READ" not in proc.stdout
        assert "root:" not in proc.stdout

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_BWRAP
    def test_hook_cannot_signal_or_escape_to_host(self, tmp_path):
        # A setsid escapee leaves the launcher's process group; without a PID
        # namespace it survives group cleanup on the host. It must die with
        # the sandbox instead.
        marker = f"rf-dast-escape-{os.getpid()}"
        hook = tmp_path / "hook.sh"
        hook.write_text(
            "#!/bin/sh\n"
            f"setsid sh -c 'sleep 30' {marker} >/dev/null 2>&1 <&- &\n"
            "echo LAUNCHED\n")
        hook.chmod(0o755)
        cmd = scanner._build_bwrap_exec_cmd(
            [shutil.which("bash") or "/bin/bash", str(hook)],
            os.path.realpath(str(hook)))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            assert "LAUNCHED" in proc.stdout
            deadline = time.monotonic() + 3
            while _host_pids_with_marker(marker):
                assert time.monotonic() < deadline, \
                    f"setsid escapee with {marker} survived sandbox teardown"
                time.sleep(0.02)
        finally:
            for pid in _host_pids_with_marker(marker):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_BWRAP
    def test_hook_under_tmp_executes(self, tmp_path):
        # pytest tmp_path is under /tmp: regression guard for the tmpfs
        # shadowing bug (hook dir must be re-bound after --tmpfs /tmp).
        assert os.path.realpath(str(tmp_path)).startswith("/tmp")
        hook = tmp_path / "h.sh"
        hook.write_text("#!/bin/sh\necho TMP_HOOK_RAN\n")
        hook.chmod(0o755)
        cmd = scanner._build_bwrap_exec_cmd(
            [shutil.which("bash") or "/bin/bash", str(hook)],
            os.path.realpath(str(hook)))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        assert "TMP_HOOK_RAN" in proc.stdout

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_BWRAP
    def test_hook_directly_in_tmp_binds_file_not_dir(self):
        # A hook at the tmpfs mountpoint: only the file is bound, host /tmp
        # siblings stay invisible.
        import tempfile
        canary = tempfile.NamedTemporaryFile(
            mode="w", prefix="rf-cred-", suffix=".txt", dir="/tmp", delete=False)
        canary.write("TMP_CANARY_ZZZ\n")
        canary.close()
        hook = tempfile.NamedTemporaryFile(
            mode="w", prefix="rf-hook-", suffix=".sh", dir="/tmp", delete=False)
        hook.write(f"#!/bin/sh\ncat '{canary.name}' 2>&1 || echo BLOCKED\n")
        hook.close()
        os.chmod(hook.name, 0o755)
        try:
            cmd = scanner._build_bwrap_exec_cmd(
                [shutil.which("bash") or "/bin/bash", hook.name],
                os.path.realpath(hook.name))
            assert ["--ro-bind", "/tmp", "/tmp"] != cmd[1:3]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            combined = proc.stdout + proc.stderr
            assert "TMP_CANARY_ZZZ" not in combined
            assert "BLOCKED" in combined
        finally:
            os.unlink(canary.name)
            os.unlink(hook.name)

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_BWRAP
    def test_hook_runs_from_foreign_cwd(self, tmp_path):
        # The launcher sets cwd=tempfile.gettempdir(); with TMPDIR pointing
        # anywhere, that path need not exist in the sandbox. --chdir /tmp
        # keeps the hook startable instead of silently producing nothing.
        foreign = tmp_path / "scratch"
        foreign.mkdir()
        hook = tmp_path / "h.sh"
        hook.write_text("#!/bin/sh\necho CWD_OK\n")
        hook.chmod(0o755)
        cmd = scanner._build_bwrap_exec_cmd(
            [shutil.which("bash") or "/bin/bash", str(hook)],
            os.path.realpath(str(hook)))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5,
                              cwd=str(foreign))
        assert "CWD_OK" in proc.stdout

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_BWRAP
    def test_opt_not_bound(self, tmp_path):
        hook = tmp_path / "h.sh"
        hook.write_text(
            "#!/bin/sh\nls /opt/ 2>/dev/null && echo OPT_READ || echo OPT_DENIED\n")
        hook.chmod(0o755)
        cmd = scanner._build_bwrap_exec_cmd(
            [shutil.which("bash") or "/bin/bash", str(hook)],
            os.path.realpath(str(hook)))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        assert "OPT_READ" not in proc.stdout

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_BWRAP
    def test_env_leak_detection_still_fires(self, tmp_path):
        # Tightening the rootfs must not blind the scanner: a hook leaking
        # the injected canary is still caught.
        hook = tmp_path / "leaky.sh"
        hook.write_text("#!/bin/sh\necho \"TOKEN=$SECRET_TOKEN\"\n")
        hook.chmod(0o755)
        payload = next(p for p in scanner.PAYLOADS
                       if p['name'] == 'env_exfiltration')
        findings = scanner.execute_hook_with_payload(
            {"event": "test", "command": str(hook), "source": "leaky.sh"},
            payload, str(tmp_path))
        assert any(f.category == "dast-env-leak" for f in findings)

    @_NEEDS_POSIX_HOOKS
    @_NEEDS_BWRAP
    def test_py_hook_executes(self, tmp_path):
        hook = tmp_path / "hook.py"
        hook.write_text("print('PY_HOOK_RAN')\n")
        findings = scanner.execute_hook_with_payload(
            {"event": "test", "command": str(hook), "source": "hook.py"},
            scanner.PAYLOADS[0], str(tmp_path))
        assert findings == []
