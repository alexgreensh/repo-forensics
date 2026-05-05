#!/usr/bin/env python3
"""
refresh_threat_dbs.py - Daily background refresher for repo-forensics threat DBs.

Designed to be invoked by launchd once per day, NEVER from inside a Claude Code
session. Refreshes IOC + KEV caches in the background so SessionStart hooks can
run in milliseconds instead of waiting on network calls.

Safety properties (post-review hardening):
  - Lock file in ~/.cache (NOT /tmp) with O_NOFOLLOW (no symlink follow).
  - Single-instance via fcntl.flock (LOCK_EX | LOCK_NB).
  - Hard wall-clock cap via SIGALRM + socket.setdefaulttimeout (defense-in-depth).
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
import os
import signal
import socket
import sys
import time

# macOS-only by design (launchd-invoked). Bail cleanly elsewhere.
if sys.platform != "darwin":
    sys.exit(0)

import fcntl  # POSIX-only; macOS guaranteed by guard above

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
LAST_RUN_MARKER = os.path.join(CACHE_DIR, ".last-refresh")
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
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
            return
        tmp = LAST_RUN_MARKER + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(str(time.time()))
        os.replace(tmp, LAST_RUN_MARKER)
        os.chmod(LAST_RUN_MARKER, 0o600)
    except OSError as e:
        _log(f"marker write failed: {e}")


def _resolve_scripts_dir():
    """Find scripts dir without polluting sys.path.

    Resolution order:
      1. Newest installed version under ~/.claude/plugins/cache that has all
         required siblings. This wins so a stale launchd plist registered
         against an old version still picks up newly-installed code after
         the user runs `claude /plugins update repo-forensics`.
      2. This script's own directory if it has the expected siblings —
         covers source-repo dogfood and standalone-copy installs.
    """
    home = os.path.expanduser("~")
    plugin_root = os.path.join(home, ".claude", "plugins", "cache")
    if os.path.isdir(plugin_root):
        candidates = []
        try:
            for marketplace in os.listdir(plugin_root):
                rf_dir = os.path.join(plugin_root, marketplace, "repo-forensics")
                if not os.path.isdir(rf_dir):
                    continue
                for ver in os.listdir(rf_dir):
                    scripts = os.path.join(
                        rf_dir, ver, "skills", "repo-forensics", "scripts"
                    )
                    if (os.path.isdir(scripts)
                            and os.path.isfile(os.path.join(scripts, "ioc_manager.py"))
                            and os.path.isfile(os.path.join(scripts, "forensics_core.py"))
                            and os.path.isfile(os.path.join(scripts, "vuln_feed.py"))):
                        try:
                            mtime = os.path.getmtime(scripts)
                        except OSError:
                            mtime = 0
                        candidates.append((mtime, scripts))
        except OSError:
            pass
        if candidates:
            candidates.sort(reverse=True)
            return candidates[0][1]

    here = os.path.dirname(os.path.abspath(__file__))
    if (os.path.isfile(os.path.join(here, "ioc_manager.py"))
            and os.path.isfile(os.path.join(here, "forensics_core.py"))):
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


def main():
    if os.environ.get(ENV_KILL_SWITCH, "").lower() in ("1", "true", "yes", "on"):
        _log("kill switch active — exiting")
        return

    # Defense in depth for hung TLS/DNS
    try:
        socket.setdefaulttimeout(SOCKET_DEFAULT_TIMEOUT)
    except Exception:
        pass

    try:
        signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(REFRESH_HARD_CAP_SEC)
    except (AttributeError, OSError):
        pass

    lock_fd = _acquire_lock()
    if lock_fd is None:
        return

    try:
        scripts_dir = _resolve_scripts_dir()
        if scripts_dir is None:
            _log("scripts dir not found — exiting")
            return
        _log(f"refresh start (scripts_dir={scripts_dir})")
        # Pre-load forensics_core for the shared atomic-write helper used by marker.
        try:
            fc_path = os.path.join(scripts_dir, "forensics_core.py")
            forensics_core = _import_module_by_path("forensics_core", fc_path)
        except Exception:
            forensics_core = None
        ok_ioc = _refresh_iocs(scripts_dir)
        ok_kev = _refresh_kev(scripts_dir)
        _write_marker(forensics_core=forensics_core)
        _log(f"refresh done (ioc={ok_ioc}, kev={ok_kev})")
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(lock_fd)
        except OSError:
            pass
        try:
            signal.alarm(0)
        except (AttributeError, OSError):
            pass


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as e:
        _log(f"top-level exception: {type(e).__name__}: {e}")
    sys.exit(0)
