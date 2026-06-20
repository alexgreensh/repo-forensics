#!/usr/bin/env python3
"""
refresh_threat_dbs.py - Daily background refresher for repo-forensics threat DBs.

Designed to run in the background once per day: through launchd on macOS or a
detached SessionStart kick on other platforms. Refreshes IOC + KEV caches
without making SessionStart wait on network calls.

Safety properties (post-review hardening):
  - Lock file in ~/.cache (NOT /tmp) with O_NOFOLLOW (no symlink follow).
  - Single-instance via fcntl.flock or msvcrt.locking.
  - Cross-platform hard wall-clock cap via a supervising parent process.
  - Atomic writes: ioc_manager and vuln_feed must use temp+rename internally.
  - Modules loaded by absolute path via importlib (sys.path NOT polluted).
  - Log inputs sanitized (no CR/LF injection from remote feed).
  - Log rotation at 256KB.
  - Always exits 0 (no launchd retry storms).
  - Kill switch: REPO_FORENSICS_DISABLE_REFRESH=1.
  - No tool calls, no scanner invocation = no recursion path.

Created by Alex Greenshpun.
"""

import errno
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

try:
    import fcntl  # POSIX
except ImportError:  # pragma: no cover - exercised on Windows
    fcntl = None

try:
    import msvcrt  # Windows
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None

# ---------------------------------------------------------------------------
# Hard limits
# ---------------------------------------------------------------------------
REFRESH_HARD_CAP_SEC = 60
SOCKET_DEFAULT_TIMEOUT = 15
LOG_MAX_BYTES = 256 * 1024
LOG_MSG_MAX_LEN = 512
ENV_KILL_SWITCH = "REPO_FORENSICS_DISABLE_REFRESH"

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "repo-forensics")
LOG_FILE = os.path.join(CACHE_DIR, "refresh.log")
LAST_RUN_MARKER = os.path.join(CACHE_DIR, ".last-refresh-v2")
LAST_ATTEMPT_MARKER = os.path.join(CACHE_DIR, ".last-refresh-attempt")
STATE_FILE = os.path.join(CACHE_DIR, "refresh-state.json")
DISABLED_MARKER = os.path.join(CACHE_DIR, "refresh.disabled")
LOCK_FILE = os.path.join(CACHE_DIR, "refresh.lock")  # In CACHE_DIR, NOT /tmp


def _sanitize(s):
    """Allowlist printable ASCII + tab. Defeats log forging via terminal escapes
    (ESC, BEL, BS, ANSI cursor controls) embedded in attacker-controlled feed
    text that an analyst might `cat` from refresh.log."""
    s = str(s)
    if len(s) > LOG_MSG_MAX_LEN:
        s = s[:LOG_MSG_MAX_LEN] + "...[truncated]"
    out = []
    for ch in s:
        code = ord(ch)
        if code == 9:  # tab
            out.append(ch)
        elif 32 <= code < 127:
            out.append(ch)
        else:
            out.append(f"\\x{code:02x}")
    return "".join(out)


def _log(msg):
    """Append a timestamped line to LOG_FILE. Rotates when oversized.
    Never raises."""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        try:
            if os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
                with open(LOG_FILE, "rb") as f:
                    f.seek(-(LOG_MAX_BYTES // 2), os.SEEK_END)
                    tail = f.read()
                with open(LOG_FILE, "wb") as f:
                    f.write(b"[truncated]\n")
                    f.write(tail)
        except OSError:
            pass
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ts} {_sanitize(msg)}\n")
    except Exception:
        pass


def _alarm_handler(signum, frame):
    # Async-signal-safe: only os.write to a pre-opened fd, then os._exit.
    # _log() opens files / calls strftime / does malloc — none safe inside a
    # signal handler. Skip logging the alarm; the launchd ExitTimeOut entry
    # in the plist + the absence of a refresh marker is sufficient signal.
    try:
        os.write(2, b"[refresh] HARD CAP reached\n")
    except OSError:
        pass
    os._exit(0)


def _atomic_json(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            value = json.load(f)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(**updates):
    try:
        state = _load_state()
        state.update(updates)
        _atomic_json(STATE_FILE, state)
    except OSError as e:
        _log(f"state write failed: {e}")


def _acquire_lock():
    """Open lock file with O_NOFOLLOW (no symlink) inside CACHE_DIR.
    Returns fd or None."""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
    except OSError as e:
        _log(f"cache dir create failed: {e}")
        return None

    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(LOCK_FILE, flags, 0o600)
    except OSError as e:
        _log(f"lock open failed: {e}")
        return None

    # Refuse to flock anything that's not a regular file
    try:
        st = os.fstat(fd)
        import stat as _stat
        if not _stat.S_ISREG(st.st_mode):
            _log("lock file is not a regular file — aborting")
            os.close(fd)
            return None
    except OSError as e:
        _log(f"fstat failed: {e}")
        try:
            os.close(fd)
        except OSError:
            pass
        return None

    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt is not None:  # pragma: no cover - Windows
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            raise OSError(errno.ENOSYS, "no supported file-lock API")
        return fd
    except OSError as e:
        if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            _log("another refresher is running — exiting")
        else:
            _log(f"flock failed: {e}")
        try:
            os.close(fd)
        except OSError:
            pass
        return None


def _release_lock(fd):
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        elif msvcrt is not None:  # pragma: no cover - Windows
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def _write_marker(forensics_core=None):
    """Atomic marker write. Uses forensics_core.atomic_write_text when the
    helper is available; otherwise falls back to inline temp+rename. The
    feature-check (hasattr) handles the case where an older forensics_core
    is loaded from a stale plugin cache during version transitions."""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        if forensics_core is not None and hasattr(forensics_core, "atomic_write_text"):
            forensics_core.atomic_write_text(
                LAST_RUN_MARKER, str(time.time()), mode=0o600
            )
            return True
        tmp = LAST_RUN_MARKER + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(str(time.time()))
        os.replace(tmp, LAST_RUN_MARKER)
        os.chmod(LAST_RUN_MARKER, 0o600)
        return True
    except OSError as e:
        _log(f"marker write failed: {e}")
        return False


def _resolve_scripts_dir():
    """Use only this integrity-checked stable payload; never cross-load agents."""
    here = os.path.dirname(os.path.abspath(__file__))
    required = ("ioc_manager.py", "forensics_core.py", "vuln_feed.py",
                "rulepack_feed.py", "rule_loader.py", "_ed25519.py")
    if all(os.path.isfile(os.path.join(here, name)) for name in required):
        return here
    return None


def _import_module_by_path(name, path):
    """Load a module by absolute path without modifying sys.path globally.
    Catches BaseException (not just Exception) so SIGALRM/KeyboardInterrupt
    can't leave a half-imported module wedged in sys.modules."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return mod


def _refresh_iocs(scripts_dir):
    """Refresh IOC cache. Returns True on success.
    Imports under canonical name 'ioc_manager' so any internal self-imports
    or module-level state stays consistent across the codebase."""
    try:
        ioc_path = os.path.join(scripts_dir, "ioc_manager.py")
        ioc_manager = _import_module_by_path("ioc_manager", ioc_path)
        if ioc_manager is None:
            _log("ioc_manager module not found")
            return False
        ok, msg = ioc_manager.update_iocs()
        _log(f"IOC: ok={ok} msg={msg}")
        return bool(ok)
    except Exception as e:
        _log(f"IOC refresh exception: {type(e).__name__}: {e}")
        return False


def _refresh_kev(scripts_dir):
    """Refresh KEV cache. Returns True on success."""
    try:
        kev_path = os.path.join(scripts_dir, "vuln_feed.py")
        vuln_feed = _import_module_by_path("vuln_feed", kev_path)
        if vuln_feed is None:
            _log("vuln_feed module not found")
            return False
        ok, msg = vuln_feed.update_kev_cache()
        _log(f"KEV: ok={ok} msg={msg}")
        return bool(ok)
    except Exception as e:
        _log(f"KEV refresh exception: {type(e).__name__}: {e}")
        return False


def _refresh_rulepacks(scripts_dir):
    """Fetch + verify + cache the signed rule-pack bundle (U6). Returns True on
    success. Runs WITHIN the existing 60s SIGALRM hard cap and the single-
    instance lock — its self-test step reuses rule_loader's save/restore SIGALRM
    so it never clobbers our cap. Cross-platform updater with no scheduler
    assumptions."""
    try:
        feed_path = os.path.join(scripts_dir, "rulepack_feed.py")
        rulepack_feed = _import_module_by_path("rulepack_feed", feed_path)
        if rulepack_feed is None:
            _log("rulepack_feed module not found")
            return False
        ok, msg = rulepack_feed.update_rulepacks()
        _log(f"RULEPACKS: ok={ok} msg={msg}")
        return bool(ok)
    except Exception as e:
        _log(f"rule-pack refresh exception: {type(e).__name__}: {e}")
        return False


def self_check():
    scripts_dir = _resolve_scripts_dir()
    if scripts_dir is None:
        return False
    for name in ("ioc_manager.py", "forensics_core.py", "vuln_feed.py",
                 "rulepack_feed.py", "rule_loader.py", "_ed25519.py"):
        try:
            with open(os.path.join(scripts_dir, name), encoding="utf-8") as f:
                compile(f.read(), name, "exec")
        except (OSError, SyntaxError):
            return False
    return True


def _worker_main():
    if (os.environ.get(ENV_KILL_SWITCH, "").lower() in ("1", "true", "yes", "on")
            or os.path.exists(DISABLED_MARKER)):
        _log("kill switch active — exiting")
        _write_state(status="disabled")
        return

    # Defense in depth for hung TLS/DNS
    try:
        socket.setdefaulttimeout(SOCKET_DEFAULT_TIMEOUT)
    except Exception:
        pass

    lock_fd = _acquire_lock()
    if lock_fd is None:
        return

    # Inner POSIX hard cap. The parent supervises with subprocess timeout, but a
    # worker invoked directly (tests, manual runs) would otherwise have no cap at
    # all — wire the handler that was previously dead code. Windows lacks SIGALRM
    # and relies solely on the parent's subprocess timeout.
    _alarm_armed = hasattr(signal, "SIGALRM")
    if _alarm_armed:
        signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(REFRESH_HARD_CAP_SEC)

    try:
        started = time.time()
        run_id = os.environ.get("REPO_FORENSICS_RUN_ID") or f"{int(started * 1000)}-{os.getpid()}"
        try:
            with open(LAST_ATTEMPT_MARKER, "w", encoding="utf-8") as f:
                f.write(str(started))
            os.chmod(LAST_ATTEMPT_MARKER, 0o600)
        except OSError:
            pass
        _write_state(status="refreshing", last_attempt=started, pid=os.getpid(), run_id=run_id)
        scripts_dir = _resolve_scripts_dir()
        if scripts_dir is None:
            _log("scripts dir not found — exiting")
            _write_state(status="repair-needed", last_error="scripts dir not found")
            return
        _log(f"refresh start (scripts_dir={scripts_dir})")
        # Pre-load forensics_core for the shared atomic-write helper used by marker.
        try:
            fc_path = os.path.join(scripts_dir, "forensics_core.py")
            forensics_core = _import_module_by_path("forensics_core", fc_path)
        except Exception:
            forensics_core = None
        ok_ioc = _refresh_iocs(scripts_dir)
        if os.path.exists(DISABLED_MARKER):
            _write_state(status="disabled", last_attempt=started, run_id=run_id,
                         last_error="disabled during refresh")
            return
        ok_kev = _refresh_kev(scripts_dir)
        if os.path.exists(DISABLED_MARKER):
            _write_state(status="disabled", last_attempt=started, run_id=run_id,
                         last_error="disabled during refresh")
            return
        ok_rulepacks = _refresh_rulepacks(scripts_dir)
        finished = time.time()
        if os.path.exists(DISABLED_MARKER):
            _write_state(status="disabled", last_attempt=started, run_id=run_id,
                         last_error="disabled during refresh")
            return
        previous_feeds = _load_state().get("feeds") or {}
        def feed_state(name, ok):
            previous = previous_feeds.get(name) if isinstance(previous_feeds, dict) else {}
            prior_success = previous.get("last_success") if isinstance(previous, dict) else None
            return {"ok": ok, "last_attempt": finished,
                    "last_success": finished if ok else prior_success}
        feeds = {
            "ioc": feed_state("ioc", ok_ioc),
            "kev": feed_state("kev", ok_kev),
            "rulepacks": feed_state("rulepacks", ok_rulepacks),
        }
        if ok_ioc and ok_kev and ok_rulepacks:
            marker_ok = _write_marker(forensics_core=forensics_core)
            _write_state(status="healthy" if marker_ok else "degraded",
                         last_success=finished if marker_ok else _load_state().get("last_success"),
                         last_attempt=started, duration_ms=int((finished - started) * 1000),
                         feeds=feeds, marker_written=marker_ok,
                         run_id=run_id,
                         last_error=None if marker_ok else "success marker write failed")
        else:
            _log("refresh incomplete — success marker not updated")
            failed = [name for name, result in feeds.items() if not result["ok"]]
            _write_state(status="degraded", last_attempt=started,
                         duration_ms=int((finished - started) * 1000), feeds=feeds,
                         marker_written=False, run_id=run_id,
                         last_error="failed feeds: " + ", ".join(failed))
        _log(f"refresh done (ioc={ok_ioc}, kev={ok_kev}, rulepacks={ok_rulepacks})")
    finally:
        if _alarm_armed:
            signal.alarm(0)
        _release_lock(lock_fd)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--self-check" in argv:
        return 0 if self_check() else 1
    if "--worker" not in argv:
        try:
            completed = subprocess.run(
                [sys.executable, os.path.abspath(__file__), "--worker"],
                stdin=subprocess.DEVNULL, timeout=REFRESH_HARD_CAP_SEC,
                check=False,
            )
            return completed.returncode
        except subprocess.TimeoutExpired:
            now = time.time()
            _log("refresh timeout — worker terminated by supervisor")
            _write_state(status="timeout", last_attempt=now,
                         last_error=f"hard cap exceeded ({REFRESH_HARD_CAP_SEC}s)")
            return 0
    _worker_main()
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except SystemExit:
        raise
    except BaseException as e:
        _log(f"top-level exception: {type(e).__name__}: {e}")
        _write_state(status="error", last_error=f"{type(e).__name__}: {e}")
        exit_code = 0
    sys.exit(exit_code)
