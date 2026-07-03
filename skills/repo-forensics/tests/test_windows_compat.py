import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_FORENSICS = REPO_ROOT / "skills" / "repo-forensics" / "scripts" / "run_forensics.sh"
PYTHON_LAUNCHER = REPO_ROOT / "hooks" / "python-launcher.sh"


def _write_shim(path: Path, banner: str | None, *, executable: bool = True) -> None:
    """Write a fake interpreter. If banner is None it exits 0 on --version but
    prints nothing (the non-Python exit-0 pretender); otherwise it echoes the
    banner. Any non --version invocation just marks that it ran."""
    path.parent.mkdir(parents=True, exist_ok=True)
    version_line = f'echo "{banner}"' if banner is not None else "true"
    path.write_text(
        "#!/bin/bash\n"
        f'[ "$1" = "--version" ] && {{ {version_line}; exit 0; }}\n'
        'echo "SHIM_RAN:$*"\n'
    )
    if executable:
        path.chmod(0o755)


def _run_codex_finder(env: dict) -> subprocess.CompletedProcess:
    """Source only the launcher's function defs (not its exec tail) and call
    find_codex_runtime_python in isolation, so the Codex-runtime fallback is
    exercised without the machine's real system Python short-circuiting it."""
    script = (
        'set -u\n'
        f'''eval "$(sed -n '1,/^if py3=/p' "{PYTHON_LAUNCHER}" | sed '$d')"\n'''
        'set +e\n'
        'out=$(find_codex_runtime_python); rc=$?\n'
        'printf "OUT=%s\\nRC=%s\\n" "$out" "$rc"\n'
    )
    return subprocess.run(
        ["/bin/bash", "-c", script],
        text=True, capture_output=True, env=env, timeout=20, check=False,
    )


def test_codex_runtime_fallback_finds_bundled_python(tmp_path):
    """Codex Desktop's bundled Python (never on PATH) is discovered under the
    user's cache dir derived from HOME."""
    py = tmp_path / ".cache/codex-runtimes/rt/dependencies/python/python.exe"
    _write_shim(py, "Python 3.12.13")
    env = {"HOME": str(tmp_path), "XDG_CACHE_HOME": "", "LOCALAPPDATA": "",
           "CODEX_RUNTIME_PYTHON": "", "PATH": "/usr/bin:/bin"}
    result = _run_codex_finder(env)
    assert f"OUT={py}" in result.stdout, result.stdout + result.stderr
    assert "RC=0" in result.stdout


def test_codex_runtime_rejects_exit0_non_python(tmp_path):
    """A planted binary that exits 0 on --version but is NOT Python must be
    rejected — the fallback searches user-writable dirs outside the safe-prefix
    whitelist, so exit-zero alone must never stand in for the interpreter."""
    evil = tmp_path / ".cache/codex-runtimes/rt/dependencies/python/python3"
    _write_shim(evil, None)  # exits 0, prints no Python banner
    env = {"HOME": str(tmp_path), "XDG_CACHE_HOME": "", "LOCALAPPDATA": "",
           "CODEX_RUNTIME_PYTHON": "", "PATH": "/usr/bin:/bin"}
    result = _run_codex_finder(env)
    assert "RC=1" in result.stdout, result.stdout + result.stderr
    assert "OUT=\n" in result.stdout or "OUT=" == result.stdout.splitlines()[0]


def test_codex_runtime_handles_space_in_home(tmp_path):
    """Windows home dirs contain spaces (C:\\Users\\First Last); the fallback
    must not word-split them into garbage and silently find nothing."""
    home = tmp_path / "First Last"
    py = home / ".cache/codex-runtimes/rt/dependencies/python/python.exe"
    _write_shim(py, "Python 3.11.9")
    env = {"HOME": str(home), "XDG_CACHE_HOME": "", "LOCALAPPDATA": "",
           "CODEX_RUNTIME_PYTHON": "", "PATH": "/usr/bin:/bin"}
    result = _run_codex_finder(env)
    assert f"OUT={py}" in result.stdout, result.stdout + result.stderr
    assert "RC=0" in result.stdout


def test_codex_runtime_absent_returns_nonzero(tmp_path):
    """No bundled runtime and unset cache vars: clean non-zero, no set -u abort."""
    env = {"HOME": str(tmp_path), "XDG_CACHE_HOME": "", "LOCALAPPDATA": "",
           "CODEX_RUNTIME_PYTHON": "", "PATH": "/usr/bin:/bin"}
    result = _run_codex_finder(env)
    assert "RC=1" in result.stdout, result.stdout + result.stderr


def test_git_checkout_keeps_integrity_tracked_text_as_lf(tmp_path):
    """Windows core.autocrlf must not rewrite signed marketplace payloads."""
    attributes = REPO_ROOT / ".gitattributes"
    assert attributes.is_file()

    probe = tmp_path / "checkout"
    probe.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=probe, check=True)
    subprocess.run(["git", "config", "core.autocrlf", "true"], cwd=probe, check=True)
    (probe / ".gitattributes").write_bytes(attributes.read_bytes())
    sample = probe / "payload.py"
    sample.write_bytes(b"print('safe')\n")
    subprocess.run(["git", "add", ".gitattributes", "payload.py"], cwd=probe, check=True)

    sample.unlink()
    subprocess.run(["git", "checkout-index", "--", "payload.py"], cwd=probe, check=True)

    assert sample.read_bytes() == b"print('safe')\n"


def test_cli_skips_broken_windows_python_alias(tmp_path):
    """The CLI must fall through a failing Store alias to a working Python 3."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "python-used"

    broken_python3 = fake_bin / "python3"
    broken_python3.write_text("#!/bin/sh\nexit 41\n")
    broken_python3.chmod(0o755)

    working_python = fake_bin / "python"
    working_python.write_text(
        f'#!/bin/sh\nprintf used > "{marker}"\nexec "{sys.executable}" "$@"\n'
    )
    working_python.chmod(0o755)

    env = {
        **os.environ,
        "PATH": f"{fake_bin}:/usr/bin:/bin",
    }
    result = subprocess.run(
        ["/bin/bash", str(RUN_FORENSICS), "--inventory", "--list-ecosystems"],
        text=True,
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert marker.is_file()


def test_cli_skips_zero_byte_python_stub(tmp_path):
    """A zero-byte App Execution Alias stub must not be accepted as Python."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "python-used"

    zero_byte_python3 = fake_bin / "python3"
    zero_byte_python3.write_bytes(b"")
    zero_byte_python3.chmod(0o755)

    working_python = fake_bin / "python"
    working_python.write_text(
        f'#!/bin/sh\nprintf used > "{marker}"\nexec "{sys.executable}" "$@"\n'
    )
    working_python.chmod(0o755)

    env = {**os.environ, "PATH": f"{fake_bin}:/usr/bin:/bin"}
    result = subprocess.run(
        ["/bin/bash", str(RUN_FORENSICS), "--inventory", "--list-ecosystems"],
        text=True, capture_output=True, env=env, timeout=20, check=False,
    )

    assert result.returncode == 0, result.stderr
    assert marker.is_file(), "resolver accepted zero-byte stub instead of falling through"


def test_cli_skips_non_python_exit0_pretender(tmp_path):
    """A non-Python binary that exits 0 must not pass the Python probe."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "python-used"

    pretender = fake_bin / "python3"
    pretender.write_text("#!/bin/sh\nexit 0\n")
    pretender.chmod(0o755)

    working_python = fake_bin / "python"
    working_python.write_text(
        f'#!/bin/sh\nprintf used > "{marker}"\nexec "{sys.executable}" "$@"\n'
    )
    working_python.chmod(0o755)

    env = {**os.environ, "PATH": f"{fake_bin}:/usr/bin:/bin"}
    result = subprocess.run(
        ["/bin/bash", str(RUN_FORENSICS), "--inventory", "--list-ecosystems"],
        text=True, capture_output=True, env=env, timeout=20, check=False,
    )

    assert result.returncode == 0, result.stderr
    assert marker.is_file(), "resolver accepted non-Python pretender instead of falling through"


def test_cli_bypasses_hanging_python_stub(tmp_path):
    """A hanging python3 stub must be timed out and bypassed, not block forever."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "python-used"

    hanging_python3 = fake_bin / "python3"
    hanging_python3.write_text("#!/bin/sh\nsleep 3600\n")
    hanging_python3.chmod(0o755)

    working_python = fake_bin / "python"
    working_python.write_text(
        f'#!/bin/sh\nprintf used > "{marker}"\nexec "{sys.executable}" "$@"\n'
    )
    working_python.chmod(0o755)

    env = {**os.environ, "PATH": f"{fake_bin}:/usr/bin:/bin"}
    # 20s is generous: the resolver's internal timeout (5s) must kick in
    # well before this outer subprocess timeout fires.
    result = subprocess.run(
        ["/bin/bash", str(RUN_FORENSICS), "--inventory", "--list-ecosystems"],
        text=True, capture_output=True, env=env, timeout=20, check=False,
    )

    assert result.returncode == 0, result.stderr
    assert marker.is_file(), "resolver hung on sleeping stub instead of timing out and falling through"


def test_cli_falls_back_to_py_launcher(tmp_path):
    """When python3 and python are absent, py -3 must be used."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "py-used"

    py_launcher = fake_bin / "py"
    # Simulate the Windows py launcher: consume -3, exec the real interpreter.
    py_launcher.write_text(
        f'#!/bin/sh\nshift  # consume -3\nprintf used > "{marker}"\nexec "{sys.executable}" "$@"\n'
    )
    py_launcher.chmod(0o755)

    # Broken python3 and python so the loop fails and py -3 is exercised.
    for name in ("python3", "python"):
        stub = fake_bin / name
        stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(0o755)

    env = {**os.environ, "PATH": f"{fake_bin}:/usr/bin:/bin"}
    result = subprocess.run(
        ["/bin/bash", str(RUN_FORENSICS), "--inventory", "--list-ecosystems"],
        text=True, capture_output=True, env=env, timeout=20, check=False,
    )

    assert result.returncode == 0, result.stderr
    assert marker.is_file(), "py -3 fallback was not exercised"
