#!/usr/bin/env python3
"""Cross-platform installer, repair controller, and status CLI for threat refresh.

The controller is invoked by SessionStart from an installed plugin.  It promotes
the plugin's integrity-checked skill payload into stable per-user storage, then
points the native scheduler at that stable copy.  Promotion is monotonic: an
older Claude/Codex/OpenClaw install can never repoint the shared scheduler away
from a newer payload.

Schedulers:
  * macOS: per-user launchd LaunchAgent
  * Linux: systemd user timer (detached, throttled fallback when unavailable)
  * Windows: per-user Task Scheduler task (detached, throttled fallback on error)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional


# v2 names intentionally differ from the v2.11.4 launchd label.  A still-old
# agent may recreate the legacy job, but it cannot replace or downgrade this
# controller-owned scheduler.  Both jobs share the refresher lock, and every
# new-controller ensure retires the legacy job again.
LABEL = "com.alexgreenshpun.repo-forensics-refresh-v2"
LEGACY_LABEL = "com.alexgreenshpun.repo-forensics-refresh"
SYSTEMD_BASENAME = "repo-forensics-refresh-v2"
WINDOWS_TASK = "RepoForensicsThreatRefreshV2"
LEGACY_WINDOWS_TASK = "RepoForensicsThreatRefresh"
REFRESH_INTERVAL_SECONDS = 24 * 60 * 60
RETRY_INTERVAL_SECONDS = 60 * 60
FUTURE_SKEW_SECONDS = 5 * 60
DISABLE_VALUES = {"1", "true", "yes", "on"}
CHECKSUMS_PUBKEY_HEX = "c86f717c5f3293da397435cde3d8ab49cddba2165eddbd47c6fb62aad3e9526a"
REQUIRED_PAYLOAD_FILES = {
    "scripts/_ed25519.py",
    "scripts/forensics_core.py",
    "scripts/ioc_manager.py",
    "scripts/refresh_controller.py",
    "scripts/refresh_threat_dbs.py",
    "scripts/rule_loader.py",
    "scripts/rulepack_feed.py",
    "scripts/vuln_feed.py",
}
IGNORED_PAYLOAD_DIRS = {"tests", "__pycache__", ".pytest_cache", ".ruff_cache"}
IGNORED_PAYLOAD_FILES = {
    ".DS_Store", "checksums.json", "checksums.json.sig", "VERSION",
    ".forensics-baseline.json", ".forensics-iocs.json",
}

HOME = Path.home()
CACHE_DIR = HOME / ".cache" / "repo-forensics"
DATA_DIR = HOME / ".local" / "share" / "repo-forensics"
VERSIONS_DIR = DATA_DIR / "versions"
ACTIVE_STATE = DATA_DIR / "active.json"
REFRESH_STATE = CACHE_DIR / "refresh-state.json"
SUCCESS_MARKER = CACHE_DIR / ".last-refresh-v2"
ATTEMPT_MARKER = CACHE_DIR / ".last-refresh-attempt"
DISABLED_MARKER = CACHE_DIR / "refresh.disabled"
CONTROLLER_LOCK = CACHE_DIR / "controller.lock"
BOOTSTRAP_LOG = CACHE_DIR / "scheduler.log"
REFRESH_STDIO_LOG = CACHE_DIR / "refresh-stdio.log"


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _atomic_json(path: Path, value: dict) -> None:
    _atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _log(message: str) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CACHE_DIR, 0o700)
        if BOOTSTRAP_LOG.exists() and BOOTSTRAP_LOG.stat().st_size > 256 * 1024:
            tail = BOOTSTRAP_LOG.read_bytes()[-128 * 1024 :]
            _atomic_write(BOOTSTRAP_LOG, b"[truncated]\n" + tail)
        safe = "".join(ch if ch == "\t" or 32 <= ord(ch) < 127 else "?" for ch in str(message))
        with BOOTSTRAP_LOG.open("a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {safe[:1000]}\n")
    except OSError:
        pass


def _rotate_log(path: Path, maximum: int = 512 * 1024) -> None:
    """Bound native-scheduler logs without depending on platform logrotate."""
    try:
        if path.exists() and path.stat().st_size > maximum:
            _atomic_write(path, b"[truncated]\n" + path.read_bytes()[-maximum // 2 :])
    except OSError:
        pass


def _version_tuple(value: str) -> tuple[int, ...]:
    if not isinstance(value, str):
        return ()
    try:
        parts = tuple(int(part) for part in value.split("."))
    except (TypeError, ValueError):
        return ()
    return parts if parts and all(part >= 0 for part in parts) else ()


def _candidate(skill_root: Optional[Path] = None) -> tuple[Path, str]:
    skill_root = (skill_root or Path(__file__).resolve().parents[1]).resolve()
    version_file = skill_root / "VERSION"
    if version_file.is_file():
        version = version_file.read_text(encoding="utf-8").strip()
        if _version_tuple(version):
            return skill_root, version
    repo_root = skill_root.parents[1]
    for manifest in (repo_root / ".claude-plugin" / "plugin.json",
                     repo_root / ".codex-plugin" / "plugin.json"):
        data = _load_json(manifest)
        version = data.get("version")
        if isinstance(version, str) and _version_tuple(version):
            return skill_root, version
    raise RuntimeError("plugin version could not be resolved")


_TRUSTED_SCRIPTS_DIR = Path(__file__).resolve().parent


def _trusted_ed25519():
    """Load the Ed25519 verifier from THIS controller's own (trusted) scripts
    directory, resolved by absolute path.

    The verifier must never be imported from the candidate payload being
    verified: a hostile payload ships its own ``_ed25519.py`` (it is a required
    payload file) whose ``verify()`` returns True and whose import runs
    arbitrary code, defeating the signature check entirely. Pinning to this
    file's sibling — and never placing a candidate dir on sys.path — keeps the
    verifier trusted regardless of sys.path ordering.
    """
    import importlib.util
    trusted_path = _TRUSTED_SCRIPTS_DIR / "_ed25519.py"
    cached = sys.modules.get("_ed25519")
    if cached is not None and getattr(cached, "__file__", None) == str(trusted_path):
        return cached
    spec = importlib.util.spec_from_file_location("_ed25519", trusted_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules["_ed25519"] = module
    return module


def _verify_skill(skill_root: Path) -> tuple[bool, str]:
    manifest_path = skill_root / "checksums.json"
    signature_path = skill_root / "checksums.json.sig"
    try:
        manifest_raw = manifest_path.read_bytes()
        signature = signature_path.read_bytes()
        ed25519 = _trusted_ed25519()
        if not ed25519.verify(signature, manifest_raw,
                              bytes.fromhex(CHECKSUMS_PUBKEY_HEX)):
            return False, "checksum manifest signature invalid"
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return False, f"signed checksum manifest unavailable: {exc}"
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        return False, "checksum manifest missing or empty"
    if manifest.get("file_count") != len(files):
        return False, "checksum manifest file_count mismatch"
    if not REQUIRED_PAYLOAD_FILES.issubset(files):
        missing = sorted(REQUIRED_PAYLOAD_FILES - set(files))
        return False, f"checksum manifest missing required files: {', '.join(missing)}"
    expected_paths = set()
    for rel, expected in files.items():
        if not isinstance(rel, str) or not isinstance(expected, str):
            return False, "invalid checksum manifest entry"
        rel_path = Path(rel)
        if rel_path.is_absolute() or ".." in rel_path.parts or rel in ("", "."):
            return False, f"unsafe checksum manifest path: {rel!r}"
        path = skill_root / rel_path
        expected_paths.add(rel_path.as_posix())
        try:
            if not path.is_file() or path.is_symlink():
                return False, f"integrity check missing file: {rel}"
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            return False, f"integrity read failed for {rel}: {exc}"
        if digest != expected:
            return False, f"integrity mismatch: {rel}"
    actual_paths = set()
    for path in skill_root.rglob("*"):
        relative = path.relative_to(skill_root)
        if any(part in IGNORED_PAYLOAD_DIRS for part in relative.parts):
            continue
        if not path.is_file() or path.is_symlink() or path.name in IGNORED_PAYLOAD_FILES:
            continue
        actual_paths.add(relative.as_posix())
    unexpected = sorted(actual_paths - expected_paths)
    if unexpected:
        return False, f"integrity check unexpected files: {', '.join(unexpected[:5])}"
    return True, "verified"


def _active_is_usable(active: dict) -> bool:
    path = active.get("refresh_script")
    version = active.get("version")
    if not isinstance(path, str) or not isinstance(version, str):
        return False
    script = Path(path)
    try:
        skill_root = script.parents[1]
        controller = Path(active.get("controller", ""))
        version_ok = (skill_root / "VERSION").read_text(encoding="utf-8").strip() == version
        integrity_ok, _detail = _verify_skill(skill_root)
        return (script.is_file() and not script.is_symlink()
                and controller.is_file() and not controller.is_symlink()
                and version_ok and integrity_ok)
    except OSError:
        return False


def _copy_ignore(_directory: str, names: list[str]) -> set[str]:
    ignored = {"tests", "__pycache__", ".pytest_cache", ".ruff_cache", ".DS_Store"}
    return {name for name in names if name in ignored or name.endswith((".pyc", ".pyo"))}


def promote_payload(candidate_root: Optional[Path] = None) -> dict:
    """Promote this plugin payload without allowing cross-agent downgrade."""
    # Keep the no-argument call for the normal path.  Besides being simpler, it
    # preserves the small seam used by downstream packagers/tests that replace
    # the candidate resolver.
    if candidate_root is None:
        candidate_root, candidate_version = _candidate()
    else:
        candidate_root, candidate_version = _candidate(candidate_root)
    ok, detail = _verify_skill(candidate_root)
    if not ok:
        raise RuntimeError(detail)

    active = _load_json(ACTIVE_STATE)
    active_version = active.get("version", "")
    if _active_is_usable(active) and _version_tuple(active_version) >= _version_tuple(candidate_version):
        return active

    VERSIONS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    manifest_digest = hashlib.sha256((candidate_root / "checksums.json").read_bytes()).hexdigest()
    destination = VERSIONS_DIR / f"{candidate_version}-{manifest_digest[:12]}"
    previous = VERSIONS_DIR / f".{destination.name}.previous"
    if not destination.exists() and previous.exists():
        os.replace(previous, destination)
    stage = VERSIONS_DIR / f".{destination.name}.tmp-{os.getpid()}"
    try:
        shutil.copytree(candidate_root, stage, symlinks=False, ignore=_copy_ignore)
        (stage / "VERSION").write_text(candidate_version + "\n", encoding="utf-8")
        ok, detail = _verify_skill(stage)
        if not ok:
            raise RuntimeError(f"promoted payload failed verification: {detail}")
        check = subprocess.run(
            [sys.executable, str(stage / "scripts" / "refresh_threat_dbs.py"), "--self-check"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20, check=False,
            env=_sanitized_env(),
        )
        if check.returncode != 0:
            raise RuntimeError(f"promoted payload self-check failed: {(check.stderr or check.stdout).strip()[:500]}")
        # Validate entry points on the STAGE before any destructive move, so a
        # malformed payload can never displace the working one.
        if (not (stage / "scripts" / "refresh_threat_dbs.py").is_file()
                or not (stage / "scripts" / "refresh_controller.py").is_file()):
            raise RuntimeError("promoted payload lacks refresh entry points")
        if destination.exists():
            if previous.exists():
                shutil.rmtree(previous)
            os.replace(destination, previous)
        try:
            os.replace(stage, destination)
        except BaseException:
            if previous.exists() and not destination.exists():
                os.replace(previous, destination)
            raise
        # Commit point: publish ACTIVE_STATE immediately after the payload lands,
        # while `previous` still holds the prior payload as a recoverable
        # fallback. Only then retire `previous`. A crash before this write leaves
        # the old payload intact; the next ensure() re-promotes deterministically.
        active = {
            "version": candidate_version,
            "refresh_script": str(destination / "scripts" / "refresh_threat_dbs.py"),
            "controller": str(destination / "scripts" / "refresh_controller.py"),
            "promoted_at": time.time(),
            "source": str(candidate_root),
        }
        _atomic_json(ACTIVE_STATE, active)
        if previous.exists():
            shutil.rmtree(previous, ignore_errors=True)
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
    return active


# POSIX flock is granted to the PROCESS, so two threads in the same process can
# both pass the file lock. This in-process mutex serializes them before the file
# lock is even attempted, so a multi-threaded host calling ensure() concurrently
# cannot corrupt active.json.
_PROCESS_LOCK = threading.Lock()


class _ControllerLock:
    def __init__(self) -> None:
        self.fd: Optional[int] = None
        self._holds_process_lock = False

    def __enter__(self):
        if not _PROCESS_LOCK.acquire(blocking=False):
            raise BlockingIOError("another refresh controller thread is active")
        self._holds_process_lock = True
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CACHE_DIR, 0o700)
        try:
            self.fd = os.open(CONTROLLER_LOCK, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                if os.name == "nt":
                    import msvcrt
                    if os.fstat(self.fd).st_size == 0:
                        os.write(self.fd, b"\0")
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(self.fd)
                self.fd = None
                raise BlockingIOError("another refresh controller is active")
        except BaseException:
            _PROCESS_LOCK.release()
            self._holds_process_lock = False
            raise
        return self

    def __exit__(self, *_exc):
        try:
            if self.fd is not None:
                try:
                    if os.name == "nt":
                        import msvcrt
                        os.lseek(self.fd, 0, os.SEEK_SET)
                        msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(self.fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(self.fd)
                self.fd = None
        finally:
            if self._holds_process_lock:
                _PROCESS_LOCK.release()
                self._holds_process_lock = False


def _trusted_command(name: str) -> Optional[str]:
    candidates = []
    if os.name == "nt":
        try:
            import ctypes
            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buffer, len(buffer))
            if not length or length >= len(buffer):
                return None
            candidates.append(Path(buffer.value) / "System32" / f"{name}.exe")
        except (AttributeError, OSError):
            return None
    else:
        candidates.extend(Path(prefix) / name for prefix in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _run(args: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=timeout, check=False)


def _mac_plist(active: dict) -> dict:
    return {
        "Label": LABEL,
        "ProgramArguments": [sys.executable, active["controller"], "run"],
        "StartInterval": REFRESH_INTERVAL_SECONDS,
        "RunAtLoad": True,
        "KeepAlive": False,
        "ThrottleInterval": 300,
        "ProcessType": "Background",
        "Nice": 10,
        "LowPriorityIO": True,
        "LowPriorityBackgroundIO": True,
        "StandardOutPath": str(CACHE_DIR / "launchd-stdout.log"),
        "StandardErrorPath": str(CACHE_DIR / "launchd-stderr.log"),
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    }


def _ensure_macos(active: dict) -> tuple[bool, str]:
    launchctl = _trusted_command("launchctl")
    if not launchctl:
        return False, "launchctl unavailable"
    plist_path = HOME / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    expected = _mac_plist(active)
    _rotate_log(Path(expected["StandardOutPath"]))
    _rotate_log(Path(expected["StandardErrorPath"]))
    current = None
    try:
        with plist_path.open("rb") as handle:
            current = plistlib.load(handle)
    except (OSError, ValueError):
        pass
    service = f"gui/{os.getuid()}/{LABEL}"
    printed = _run([launchctl, "print", service])
    loaded_exact = printed.returncode == 0 and active["controller"] in printed.stdout
    if current == expected and loaded_exact:
        return True, "launchd healthy"

    plist_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(plist_path, plistlib.dumps(expected, fmt=plistlib.FMT_XML), 0o600)
    _run([launchctl, "bootout", f"gui/{os.getuid()}", str(plist_path)])
    result = _run([launchctl, "bootstrap", f"gui/{os.getuid()}", str(plist_path)])
    if result.returncode != 0:
        return False, f"launchd bootstrap failed: {(result.stderr or result.stdout).strip()[:500]}"
    return True, "launchd installed"


def _systemd_quote(value: str) -> str:
    # A newline or carriage return in the value would terminate the ExecStart=
    # line and let a following byte sequence inject an additional systemd
    # directive (e.g. a second ExecStart). Escape line breaks alongside the
    # quote/backslash metacharacters so the value stays a single shell token.
    return '"' + (value.replace("\\", "\\\\").replace('"', '\\"')
                  .replace("\n", "\\n").replace("\r", "\\r")) + '"'


def _ensure_linux(active: dict) -> tuple[bool, str]:
    systemctl = _trusted_command("systemctl")
    if not systemctl:
        return False, "systemctl unavailable"
    # Defence in depth: refuse to emit a unit file if either interpolated path
    # still carries a line break the quoting could not neutralise.
    for unsafe in (sys.executable, active.get("controller", "")):
        if "\n" in unsafe or "\r" in unsafe:
            return False, "refusing to write systemd unit: path contains a line break"
    unit_dir = HOME / ".config" / "systemd" / "user"
    service_path = unit_dir / f"{SYSTEMD_BASENAME}.service"
    timer_path = unit_dir / f"{SYSTEMD_BASENAME}.timer"
    service = (
        "[Unit]\nDescription=Repo Forensics threat intelligence refresh\n\n"
        "[Service]\nType=oneshot\nNice=10\n"
        f"ExecStart={_systemd_quote(sys.executable)} {_systemd_quote(active['controller'])} run\n"
    )
    timer = (
        "[Unit]\nDescription=Daily Repo Forensics threat intelligence refresh\n\n"
        "[Timer]\nOnBootSec=5m\nOnUnitActiveSec=1d\nPersistent=true\nRandomizedDelaySec=15m\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )
    changed = (not service_path.exists() or service_path.read_text(encoding="utf-8") != service
               or not timer_path.exists() or timer_path.read_text(encoding="utf-8") != timer)
    if changed:
        _atomic_write(service_path, service.encode(), 0o600)
        _atomic_write(timer_path, timer.encode(), 0o600)
        reload_result = _run([systemctl, "--user", "daemon-reload"])
        if reload_result.returncode != 0:
            return False, f"systemd user manager unavailable: {reload_result.stderr.strip()[:500]}"
    enabled = _run([systemctl, "--user", "enable", "--now", f"{SYSTEMD_BASENAME}.timer"])
    if enabled.returncode != 0:
        return False, f"systemd timer enable failed: {enabled.stderr.strip()[:500]}"
    return True, "systemd user timer healthy"


def _windows_task_command(active: dict) -> str:
    def quote(value: str) -> str:
        return '"' + value.replace('"', '\\"') + '"'
    return f"{quote(sys.executable)} {quote(active['controller'])} run"


def _ensure_windows(active: dict) -> tuple[bool, str]:
    schtasks = _trusted_command("schtasks")
    if not schtasks:
        return False, "schtasks unavailable"
    query = _run([schtasks, "/Query", "/TN", WINDOWS_TASK, "/XML"])
    desired = _windows_task_command(active)
    normalized = " ".join(query.stdout.lower().split())
    if (query.returncode == 0
            and str(active["controller"]).lower() in normalized
            and sys.executable.lower() in normalized
            and "schedulebyday" in normalized):
        return True, "Windows scheduled task healthy"
    created = _run([
        schtasks, "/Create", "/TN", WINDOWS_TASK, "/SC", "DAILY", "/ST", "03:00",
        "/RL", "LIMITED", "/TR", desired, "/F",
    ])
    if created.returncode != 0:
        return False, f"Task Scheduler create failed: {(created.stderr or created.stdout).strip()[:500]}"
    return True, "Windows scheduled task installed"


def _platform_name() -> str:
    if sys.platform == "darwin":
        return "macos"
    if os.name == "nt" or sys.platform == "win32":
        return "windows"
    return "linux"


def _ensure_scheduler(active: dict) -> tuple[bool, str, str]:
    platform_name = _platform_name()
    try:
        if platform_name == "macos":
            ok, detail = _ensure_macos(active)
        elif platform_name == "windows":
            ok, detail = _ensure_windows(active)
        else:
            ok, detail = _ensure_linux(active)
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        ok, detail = False, f"scheduler adapter failed: {type(exc).__name__}: {exc}"
    return ok, platform_name, detail


def _timestamp_is_due(path: Path, interval: int) -> bool:
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return True
    return age < -FUTURE_SKEW_SECONDS or age >= interval


def _attempt_due() -> bool:
    state = _load_json(REFRESH_STATE)
    last_attempt = state.get("last_attempt")
    if isinstance(last_attempt, (int, float)):
        age = time.time() - float(last_attempt)
        return age < -FUTURE_SKEW_SECONDS or age >= RETRY_INTERVAL_SECONDS
    return True


def _mark_attempt() -> None:
    now = time.time()
    state = _load_json(REFRESH_STATE)
    state.update({"last_attempt": now, "trigger_status": "requested"})
    _atomic_json(REFRESH_STATE, state)


def _trigger_scheduler(platform_name: str) -> bool:
    if platform_name == "macos":
        cmd = _trusted_command("launchctl")
        args = [cmd, "kickstart", f"gui/{os.getuid()}/{LABEL}"] if cmd else []
    elif platform_name == "windows":
        cmd = _trusted_command("schtasks")
        args = [cmd, "/Run", "/TN", WINDOWS_TASK] if cmd else []
    else:
        cmd = _trusted_command("systemctl")
        args = [cmd, "--user", "start", "--no-block", f"{SYSTEMD_BASENAME}.service"] if cmd else []
    return bool(args and _run(args).returncode == 0)


# Interpreter-control variables that let a caller redirect imports or inject a
# native library into a child Python. They are stripped before spawning any
# refresh worker so the worker cannot be hijacked via a poisoned parent env —
# the trusted-import guarantee on the controller side is worthless if the child
# honours an attacker's PYTHONPATH/LD_PRELOAD.
_UNSAFE_CHILD_ENV = (
    "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONOPTIMIZE",
    "PYTHONDONTWRITEBYTECODE", "PYTHONEXECUTABLE",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
)


def _sanitized_env(extra: Optional[dict] = None) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in _UNSAFE_CHILD_ENV}
    if extra:
        env.update(extra)
    return env


def _detached_fallback(active: dict) -> bool:
    log = None
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _rotate_log(REFRESH_STDIO_LOG)
        log = REFRESH_STDIO_LOG.open("ab", buffering=0)
        kwargs = {"stdin": subprocess.DEVNULL, "stdout": log, "stderr": log,
                  "close_fds": True, "env": _sanitized_env()}
        if os.name == "nt":
            kwargs["creationflags"] = (getattr(subprocess, "DETACHED_PROCESS", 0)
                                       | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen([sys.executable, active["controller"], "run"], **kwargs)
        return True
    except OSError as exc:
        _log(f"detached fallback failed: {exc}")
        return False
    finally:
        if log is not None:
            log.close()


def _remove_all_schedulers() -> tuple[bool, str]:
    errors = []
    platform_name = _platform_name()
    if platform_name == "macos":
        launchctl = _trusted_command("launchctl")
        for label in (LABEL, LEGACY_LABEL):
            plist = HOME / "Library" / "LaunchAgents" / f"{label}.plist"
            if launchctl:
                result = _run([launchctl, "bootout", f"gui/{os.getuid()}", str(plist)])
                if result.returncode not in (0, 3, 113) and plist.exists():
                    errors.append(f"bootout {label}: {(result.stderr or result.stdout).strip()[:200]}")
            try:
                plist.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                errors.append(f"remove {plist}: {exc}")
    elif platform_name == "windows":
        schtasks = _trusted_command("schtasks")
        if schtasks:
            for task in (WINDOWS_TASK, LEGACY_WINDOWS_TASK):
                result = _run([schtasks, "/Delete", "/TN", task, "/F"])
                if result.returncode not in (0, 1):
                    errors.append(f"delete task {task}: {(result.stderr or result.stdout).strip()[:200]}")
        else:
            errors.append("schtasks unavailable")
    else:
        systemctl = _trusted_command("systemctl")
        if systemctl:
            result = _run([systemctl, "--user", "disable", "--now", f"{SYSTEMD_BASENAME}.timer"])
            if result.returncode not in (0, 1):
                errors.append(f"disable systemd timer: {result.stderr.strip()[:200]}")
        for suffix in ("service", "timer"):
            try:
                (HOME / ".config" / "systemd" / "user" / f"{SYSTEMD_BASENAME}.{suffix}").unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                errors.append(f"remove systemd unit: {exc}")
        if systemctl:
            _run([systemctl, "--user", "daemon-reload"])
    return not errors, "; ".join(errors) if errors else "all schedulers removed"


def _retire_legacy_scheduler() -> None:
    """Best-effort migration cleanup; v2 uses distinct authoritative names."""
    platform_name = _platform_name()
    if platform_name == "macos":
        launchctl = _trusted_command("launchctl")
        legacy_plist = HOME / "Library" / "LaunchAgents" / f"{LEGACY_LABEL}.plist"
        if launchctl:
            _run([launchctl, "bootout", f"gui/{os.getuid()}", str(legacy_plist)])
        try:
            legacy_plist.unlink()
        except OSError:
            pass
    elif platform_name == "windows":
        schtasks = _trusted_command("schtasks")
        if schtasks:
            _run([schtasks, "/Delete", "/TN", LEGACY_WINDOWS_TASK, "/F"])


def _scheduler_status(active: dict) -> tuple[bool, str]:
    platform_name = _platform_name()
    try:
        if platform_name == "macos":
            launchctl = _trusted_command("launchctl")
            if not launchctl:
                return False, "launchctl unavailable"
            result = _run([launchctl, "print", f"gui/{os.getuid()}/{LABEL}"])
            return (result.returncode == 0 and active.get("controller", "") in result.stdout,
                    "launchd loaded" if result.returncode == 0 else "launchd not loaded")
        if platform_name == "windows":
            schtasks = _trusted_command("schtasks")
            if not schtasks:
                return False, "schtasks unavailable"
            result = _run([schtasks, "/Query", "/TN", WINDOWS_TASK, "/XML"])
            normalized = " ".join(result.stdout.lower().split())
            exact = all(token.lower() in normalized for token in (
                active.get("controller", ""), sys.executable, "schedulebyday"
            ))
            return result.returncode == 0 and exact, "Task Scheduler queried"
        systemctl = _trusted_command("systemctl")
        if not systemctl:
            return False, "systemctl unavailable"
        enabled = _run([systemctl, "--user", "is-enabled", f"{SYSTEMD_BASENAME}.timer"])
        service = HOME / ".config" / "systemd" / "user" / f"{SYSTEMD_BASENAME}.service"
        exact = service.is_file() and active.get("controller", "") in service.read_text(encoding="utf-8")
        return enabled.returncode == 0 and exact, "systemd timer queried"
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        return False, f"scheduler status failed: {type(exc).__name__}: {exc}"


def _delegate_to_stable(candidate_root: Path) -> Optional[dict]:
    """Ask the already-trusted stable controller to authenticate a candidate.

    The marketplace copy is necessarily the trust root on first install.  Once
    a signed stable payload exists, later marketplace/cache copies no longer
    promote themselves: the stable controller verifies and adopts them using
    its pinned release key.
    """
    active = _load_json(ACTIVE_STATE)
    if not _active_is_usable(active):
        return None
    stable_controller = Path(active["controller"]).resolve()
    if stable_controller == Path(__file__).resolve():
        return None
    try:
        completed = subprocess.run(
            [sys.executable, str(stable_controller), "adopt", "--candidate",
             str(candidate_root), "--json"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=45, check=False,
        )
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        result = json.loads(lines[-1]) if lines else {}
        if not isinstance(result, dict):
            raise ValueError("stable controller returned non-object JSON")
        if completed.returncode != 0:
            result.setdefault("ok", False)
            result.setdefault("operation_ok", False)
        result["delegated_to_stable"] = True
        return result
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {"ok": False, "operation_ok": False, "status": "repair-needed",
                "delegated_to_stable": True, "platform": _platform_name(),
                "error": f"stable controller delegation failed: {type(exc).__name__}: {exc}"}


def ensure(candidate_root: Optional[Path] = None) -> dict:
    # Kill switch FIRST, before any filesystem side effects. A user who disabled
    # refresh (env var or marker) expects ensure() to be inert. Only the
    # env-driven path needs to materialise CACHE_DIR, and only to persist the
    # marker so the disable outlives the env var.
    disabled_by_env = (os.environ.get("REPO_FORENSICS_DISABLE_REFRESH", "")
                       .strip().lower() in DISABLE_VALUES)
    if disabled_by_env or DISABLED_MARKER.exists():
        if disabled_by_env:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            os.chmod(CACHE_DIR, 0o700)
            _atomic_write(DISABLED_MARKER, b"disabled by REPO_FORENSICS_DISABLE_REFRESH\n")
        removed, detail = _remove_all_schedulers()
        return {"ok": removed, "operation_ok": removed, "status": "disabled",
                "scheduler_healthy": False, "refresh_healthy": False,
                "scheduler": detail, "platform": _platform_name()}
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CACHE_DIR, 0o700)
    try:
        trigger_needed = False
        launched = False
        with _ControllerLock():
            active = promote_payload(candidate_root)
            _retire_legacy_scheduler()
            scheduler_ok, platform_name, detail = _ensure_scheduler(active)
            if _timestamp_is_due(SUCCESS_MARKER, REFRESH_INTERVAL_SECONDS) and _attempt_due():
                _mark_attempt()
                trigger_needed = True
        if trigger_needed:
            launched = (_trigger_scheduler(platform_name) if scheduler_ok else False)
            if not launched:
                launched = _detached_fallback(active)
        _retire_legacy_scheduler()
        refresh = _load_json(REFRESH_STATE)
        operation_ok = scheduler_ok or launched
        result = {
            "ok": operation_ok,
            "operation_ok": operation_ok,
            "status": "ready" if scheduler_ok else ("fallback" if launched else "repair-needed"),
            "payload_healthy": _active_is_usable(active),
            "scheduler_healthy": scheduler_ok,
            "refresh_healthy": refresh.get("status") == "healthy",
            "refresh_status": refresh.get("status", "never-succeeded"),
            "platform": platform_name,
            "scheduler": detail,
            "active_version": active["version"],
            "refresh_script": active["refresh_script"],
            "launched": launched,
        }
        _log(json.dumps(result, sort_keys=True))
        return result
    except BlockingIOError:
        # Another controller instance holds the lock and is actively working.
        # The operation did not fail, but THIS call verified nothing — do not
        # report a clean health pass it never performed.
        return {"ok": False, "operation_ok": True, "status": "controller-busy",
                "scheduler_healthy": False, "refresh_healthy": False,
                "platform": _platform_name()}
    except Exception as exc:
        _log(f"ensure failed: {type(exc).__name__}: {exc}")
        return {"ok": False, "status": "repair-needed", "platform": _platform_name(),
                "error": f"{type(exc).__name__}: {exc}"}


def status() -> dict:
    active = _load_json(ACTIVE_STATE)
    refresh = _load_json(REFRESH_STATE)
    disabled = DISABLED_MARKER.exists()
    success_age = None
    clock_skew = False
    try:
        raw_age = time.time() - SUCCESS_MARKER.stat().st_mtime
        clock_skew = raw_age < -FUTURE_SKEW_SECONDS
        success_age = raw_age if raw_age >= 0 else None
    except OSError:
        pass
    payload_healthy = _active_is_usable(active)
    scheduler_healthy, scheduler_detail = (
        _scheduler_status(active) if payload_healthy else (False, "payload invalid")
    )
    feeds = refresh.get("feeds", {})
    feeds_healthy = bool(feeds) and all(
        isinstance(value, dict) and value.get("ok") for value in feeds.values()
    )
    refresh_healthy = bool(refresh.get("status") == "healthy" and feeds_healthy
                           and success_age is not None
                           and success_age < REFRESH_INTERVAL_SECONDS * 2
                           and not clock_skew)
    return {
        "ok": bool(not disabled and payload_healthy and scheduler_healthy and refresh_healthy),
        "operation_ok": True,
        "status": "disabled" if disabled else refresh.get("status", "never-succeeded"),
        "payload_healthy": payload_healthy,
        "scheduler_healthy": scheduler_healthy,
        "scheduler": scheduler_detail,
        "refresh_healthy": refresh_healthy,
        "clock_skew": clock_skew,
        "platform": _platform_name(),
        "active_version": active.get("version"),
        "refresh_script": active.get("refresh_script"),
        "last_attempt": refresh.get("last_attempt"),
        "last_success": refresh.get("last_success"),
        "success_age_seconds": success_age,
        "feeds": feeds,
        "scheduler_log": str(BOOTSTRAP_LOG),
        "refresh_log": str(CACHE_DIR / "refresh.log"),
    }


def run_active() -> dict:
    """Scheduler entry point: verify the stable payload, then run its worker."""
    if DISABLED_MARKER.exists():
        return {"ok": True, "operation_ok": True, "status": "disabled",
                "refresh_healthy": False, "platform": _platform_name()}
    try:
        # Validate the stable payload under the controller lock, then RELEASE it
        # before the long worker subprocess. The worker self-serializes via its
        # own refresh.lock, so holding controller.lock for the full ~60s would
        # only block concurrent ensure()/status() — and make them report a busy
        # state they never verified — for no safety gain.
        with _ControllerLock():
            active = _load_json(ACTIVE_STATE)
            if not _active_is_usable(active):
                result = {"ok": False, "operation_ok": False,
                          "status": "repair-needed", "error": "active payload invalid"}
                _log(json.dumps(result, sort_keys=True))
                return result
            refresh_script = active["refresh_script"]
            started = time.time()
            run_id = f"{int(started * 1000)}-{os.getpid()}"
            env = _sanitized_env({"REPO_FORENSICS_RUN_ID": run_id})

        try:
            completed = subprocess.run(
                [sys.executable, refresh_script, "--worker"],
                stdin=subprocess.DEVNULL, timeout=60, check=False, env=env,
            )
        except subprocess.TimeoutExpired:
            state = _load_json(REFRESH_STATE)
            state.update({"status": "timeout", "run_id": run_id,
                          "last_attempt": started,
                          "last_error": "controller hard cap exceeded (60s)"})
            _atomic_json(REFRESH_STATE, state)
            return {"ok": False, "operation_ok": False, "status": "timeout",
                    "refresh_healthy": False, "run_id": run_id}
        state = _load_json(REFRESH_STATE)
        terminal = state.get("status", "error")
        same_run = state.get("run_id") == run_id
        healthy = bool(same_run and terminal == "healthy")
        return {"ok": healthy, "operation_ok": completed.returncode == 0 and same_run,
                "status": terminal if same_run else "already-running",
                "refresh_healthy": healthy, "returncode": completed.returncode,
                "run_id": run_id, "feeds": state.get("feeds", {})}
    except BlockingIOError:
        result = {"ok": False, "operation_ok": False, "status": "already-running",
                  "refresh_healthy": False}
        _log(json.dumps(result, sort_keys=True))
        return result
    except Exception as exc:
        result = {"ok": False, "operation_ok": False, "status": "error",
                  "refresh_healthy": False,
                  "error": f"{type(exc).__name__}: {exc}"}
        _log(json.dumps(result, sort_keys=True))
        return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Repo Forensics refresh automation controller")
    parser.add_argument("command", choices=("ensure", "adopt", "run", "status", "disable", "enable", "uninstall"),
                        nargs="?", default="ensure")
    parser.add_argument("--json", action="store_true", help="emit machine-readable status")
    parser.add_argument("--candidate", type=Path,
                        help="candidate skill root (stable-controller adopt only)")
    args = parser.parse_args(argv)

    if args.command == "run":
        result = run_active()
    elif args.command == "adopt":
        if args.candidate is None:
            result = {"ok": False, "operation_ok": False, "status": "repair-needed",
                      "error": "adopt requires --candidate"}
        else:
            result = ensure(args.candidate.resolve())
    elif args.command == "disable":
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _atomic_write(DISABLED_MARKER, b"disabled by user\n")
        removed, detail = _remove_all_schedulers()
        result = {"ok": removed, "operation_ok": removed, "status": "disabled",
                  "scheduler_healthy": False, "refresh_healthy": False,
                  "scheduler": detail, "platform": _platform_name()}
    elif args.command == "enable":
        try:
            DISABLED_MARKER.unlink()
        except FileNotFoundError:
            # Already enabled (no marker). Proceed to (re)establish the scheduler;
            # otherwise `result` is left unbound and the call crashes downstream.
            result = ensure()
        except OSError as exc:
            result = {"ok": False, "operation_ok": False, "status": "disabled",
                      "error": f"could not remove disable marker: {exc}"}
        else:
            result = ensure()
    elif args.command == "uninstall":
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _atomic_write(DISABLED_MARKER, b"disabled by uninstall\n")
        removed, detail = _remove_all_schedulers()
        result = {"ok": removed, "operation_ok": removed,
                  "status": "uninstalled" if removed else "uninstall-failed",
                  "scheduler": detail, "platform": _platform_name()}
    elif args.command == "status":
        result = status()
    else:
        candidate_root, _candidate_version = _candidate()
        result = _delegate_to_stable(candidate_root)
        if result is None:
            result = ensure(candidate_root)

    if args.json:
        print(json.dumps(result, sort_keys=True))
    elif args.command != "ensure" or not result.get("ok"):
        print(f"repo-forensics refresh: {result.get('status')}")
        for key in ("platform", "active_version", "scheduler", "last_success", "error"):
            if result.get(key) is not None:
                print(f"  {key}: {result[key]}")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
