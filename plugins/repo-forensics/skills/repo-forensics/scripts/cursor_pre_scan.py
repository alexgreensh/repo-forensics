#!/usr/bin/env python3
"""Cursor beforeShellExecution gate -- cross-platform Python entrypoint.

This is the Python port of hooks/cursor/run_pre_scan.sh. It exists because the
bash wrapper cannot run on Windows: Cursor's hooks.json invoked it via `bash`,
which on Windows resolves to C:\\Windows\\System32\\bash.exe (the WSL launcher).
With no WSL distro installed that prints a UTF-16 error and exits 1, so a
failClosed gate would DENY every shell command. This module replicates the EXACT
security semantics of the bash wrapper with no bash dependency at all.

Contract (identical to the bash wrapper):
  * STDOUT is the verdict channel -- Cursor parses stdout as JSON. Every
    diagnostic goes to stderr. A valid JSON verdict is emitted on stdout on
    EVERY path: {"permission": "<allow|ask|deny>", "user_message": "...",
    "agent_message": "..."}. Exit 0 = allow/ask, exit 2 = deny.
  * R8 tamper-aware degrade is consulted BEFORE the allow branch:
      - a MISSING pre_scan.py is reconciled against install-manifest.json
        (manifest claims it / an absent file -> DENY tamper; no manifest claim
        -> loud warn + ALLOW "not installed here").
      - a MODIFIED trust base is caught by hashing every present trust-base file
        against checksums.json BEFORE trusting any verdict.
  * Session bootstrap (K1) is best-effort and never crashes the verdict path.
  * The opt-in evidence log (REPO_FORENSICS_HOOK_LOG) redacts user_email,
    transcript_path, session_id, and bare emails before anything reaches disk.

Integrity note: the checksum verification hashes files IN-PROCESS with hashlib.
That deliberately removes the shasum/sha256sum external-tool dependency AND the
PATH-planted-hasher problem the bash wrapper had to defend against by resolving
the hasher via absolute path -- hashlib reads no PATH, so a planted fake hasher
is structurally irrelevant here.

SCOPE, stated honestly (unchanged from the bash wrapper): this is a
tamper-EVIDENT tripwire, not a tamper-PROOF boundary. checksums.json lives in
the same writable directory as the scanner, so a same-user attacker who can
rewrite the scanner can also rewrite its hash. The authoritative defenses are
the OFFLINE signed audit (verify_install.py --verify-signature, ed25519 against
a pinned key) plus OS file permissions. What this DOES close: accidental
corruption, and an attacker who modifies one scanner file / the launcher / the
IOC feed without also forging the manifest -- the common, cheap attacks.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

# One-process latch window: a burst of parallel commands bootstraps the refresh
# daemon once, not N times (mirrors the bash wrapper's 4h window).
_REFRESH_WINDOW_SEC = 14400
_STDIN_CAP = 1_048_576  # 1 MB, same bound pre_scan.py uses.


# --------------------------------------------------------------------------- #
# Plugin-root resolution
# --------------------------------------------------------------------------- #
def _plugin_root():
    """CLAUDE_PLUGIN_ROOT if set (cursor_install.py bakes an absolute path into
    the installed command), else derive it from this file's location.
    This file lives at <plugin_root>/skills/repo-forensics/scripts/cursor_pre_scan.py.
    """
    env_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if env_root:
        return env_root
    here = os.path.dirname(os.path.abspath(__file__))
    # scripts -> repo-forensics -> skills -> <plugin_root>
    return os.path.abspath(os.path.join(here, "..", "..", ".."))


def _warn(msg):
    print(msg, file=sys.stderr)


def _emit_verdict(permission, message=""):
    """Print the Cursor JSON verdict on STDOUT and exit. json.dumps handles all
    escaping (quotes, backslashes, control chars) for the path-derived message."""
    sys.stdout.write(json.dumps({
        "permission": permission,
        "user_message": message,
        "agent_message": message,
    }) + "\n")
    sys.stdout.flush()
    sys.exit(2 if permission == "deny" else 0)


# --------------------------------------------------------------------------- #
# (K1) once-per-session refresh bootstrap -- best-effort, never fatal
# --------------------------------------------------------------------------- #
def _bootstrap_refresh(plugin_root):
    """Best-effort refresh-daemon kick. Latched on a time window so it costs one
    stat() per command rather than a fork. MUST NOT crash the verdict path:
    HOME unset (devcontainers, launchd, broken-dotfile SSH) must not raise, and
    a missing/unrunnable bootstrap script is a silent no-op (e.g. on Windows,
    where there is no ensure_refresh_daemon.sh equivalent to run)."""
    try:
        ensure = os.path.join(plugin_root, "hooks", "ensure_refresh_daemon.sh")
        if not os.path.isfile(ensure):
            return
        # HOME may be unset; fall back to a temp dir so the non-critical latch
        # never crashes the wrapper before it can emit a verdict.
        cache_base = os.environ.get("XDG_CACHE_HOME")
        if not cache_base:
            home = os.environ.get("HOME") or os.environ.get("USERPROFILE")
            cache_base = os.path.join(home, ".cache") if home else tempfile.gettempdir()
        latch_dir = os.path.join(cache_base, "repo-forensics")
        latch = os.path.join(latch_dir, "cursor-session.latch")
        try:
            mtime = os.path.getmtime(latch)
            import time
            if (time.time() - mtime) < _REFRESH_WINDOW_SEC:
                return  # already bootstrapped this session window
        except OSError:
            pass
        try:
            os.makedirs(latch_dir, exist_ok=True)
            with open(latch, "w"):
                pass
        except OSError:
            return
        # Running the *nix bootstrap needs bash. We DELIBERATELY do not resolve
        # `bash` from PATH here (that is exactly the WSL-bash-first hazard this
        # port removes); we only use an interpreter-free spawn when a POSIX shell
        # is the platform default. On Windows this stays a no-op.
        if os.name != "nt":
            try:
                subprocess.Popen(
                    ["/bin/sh", ensure],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL, start_new_session=True,
                )
            except OSError:
                return
    except Exception:
        # A bootstrap failure must never brick the gate.
        return


# --------------------------------------------------------------------------- #
# Opt-in evidence recorder
# --------------------------------------------------------------------------- #
_REDACT_KEYS = ("user_email", "transcript_path", "session_id")


def _redact(text):
    """Redact PII before anything reaches disk. A real Cursor
    beforeShellExecution envelope carries user_email (the signed-in account),
    transcript_path (the conversation log), and session_id (a user-correlatable
    id) alongside the command. None is needed to prove the hook fired, and a
    debug log is exactly the artifact people paste into issues -- so it must not
    contain them. The replacement collapses any whitespace after the colon so
    the output is exactly `"<key>":"<redacted>"`."""
    for key in _REDACT_KEYS:
        text = re.sub(
            r'"%s"\s*:\s*"[^"]*"' % re.escape(key),
            '"%s":"<redacted>"' % key,
            text,
        )
    # Bare emails anywhere else.
    text = re.sub(
        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
        '<redacted-email>',
        text,
    )
    return text


def _process_chain():
    """Walk up a few processes and record only each one's NAME. The ancestry is
    the proof -- if `cursor` is in this chain, Cursor invoked us and no test
    harness can claim otherwise. Full command lines are deliberately NOT logged.
    Best-effort: psutil is not a dependency, so this uses /proc or `ps`."""
    names = []
    try:
        pid = os.getppid()
        depth = 0
        while depth < 6 and pid and pid > 1:
            comm = None
            proc_comm = "/proc/%d/comm" % pid
            try:
                with open(proc_comm, "r") as fh:
                    comm = fh.read().strip()
            except OSError:
                try:
                    out = subprocess.run(
                        ["ps", "-o", "comm=", "-p", str(pid)],
                        capture_output=True, text=True, timeout=2, check=False,
                    )
                    comm = (out.stdout or "").strip().splitlines()[0].strip() \
                        if out.stdout.strip() else None
                except Exception:
                    comm = None
            if not comm:
                break
            names.append(os.path.basename(comm))
            # Parent of pid.
            try:
                with open("/proc/%d/stat" % pid, "r") as fh:
                    pid = int(fh.read().split()[3])
            except (OSError, IndexError, ValueError):
                break
            depth += 1
    except Exception:
        pass
    return " <- ".join(names) if names else "<unknown>"


def _evidence(log_path, stdin_text, verdict_perm, rc):
    """Append process-chain + redacted stdin + verdict. Off unless
    REPO_FORENSICS_HOOK_LOG names a file. Never raises."""
    try:
        safe = _redact(stdin_text)
        new = not (os.path.exists(log_path) and os.path.getsize(log_path) > 0)
        with open(log_path, "a", encoding="utf-8") as fh:
            if new:
                fh.write(
                    "# repo-forensics hook evidence log\n"
                    "# user_email, transcript_path and session_id are redacted "
                    "automatically.\n"
                    "# PRIVACY: \"stdin\" below still contains the VERBATIM shell "
                    "command\n"
                    "# the agent was about to run. Review before sharing. Delete "
                    "when\n"
                    "# done, and unset REPO_FORENSICS_HOOK_LOG to stop recording.\n\n"
                )
            ts = datetime.now(timezone.utc).isoformat()
            fh.write("=== %s ===\n" % ts)
            fh.write("process chain  : %s\n" % _process_chain())
            fh.write("stdin          : %s\n" % safe)
            fh.write("verdict        : %s (exit %s)\n\n" % (verdict_perm, rc))
    except Exception:
        return


# --------------------------------------------------------------------------- #
# (R8) tamper-aware degrade
# --------------------------------------------------------------------------- #
def _manifest_claims_missing_file(plugin_root, manifest_path):
    """If install-manifest.json lists a file that is absent under plugin_root,
    return that relpath; else None. Pure-Python parse of the "files" array."""
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, list):
        return None
    for entry in files:
        if not isinstance(entry, str) or not entry:
            continue
        if not os.path.exists(os.path.join(plugin_root, entry)):
            return entry
    return None


def _sha256_file(path):
    """In-process sha256 (hex). Returns None if the file cannot be read. Reads
    no PATH, so a PATH-planted fake hasher is structurally irrelevant."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# Sentinel: integrity could not be established because checksums.json is ABSENT
# (a legitimately checksums-less / pre-signing install) -> caller DEGRADES loudly.
_CANNOT_VERIFY = "__CANNOT_VERIFY__"
# Sentinel: checksums.json is PRESENT but unreadable/unparseable/wrong-shape ->
# caller DENIES as tamper. This must NOT collapse into _CANNOT_VERIFY: the bash
# original only degrades on ABSENCE and still denies a modified scanner when the
# manifest is present-but-corrupt (it line-extracts intact hashes). Conflating
# the two would let an attacker who can write the scanner simply CORRUPT the
# integrity file (append one byte) -- far cheaper than forging a 64-hex hash --
# to turn the whole R8 modification check into a degrade-and-allow.
_CHECKSUMS_CORRUPT = "__CHECKSUMS_CORRUPT__"


def _load_checksum_map(checksums_path):
    """Flatten every str->str entry across checksums.json's sub-dicts (files,
    repo_hooks, repo_manifests, ...) into ONE lookup. Skill files are
    skill-root-relative; hooks/python-launcher.sh lives under repo_hooks and is
    plugin-root-relative.

    Returns None if the file is ABSENT (caller degrades); the _CHECKSUMS_CORRUPT
    sentinel if it is PRESENT but unreadable/unparseable/wrong-shape (caller
    DENIES as tamper); otherwise the flattened key->hash map."""
    if not os.path.isfile(checksums_path):
        return None  # genuinely absent -> _CANNOT_VERIFY degrade path
    try:
        with open(checksums_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        # Present but cannot be read/parsed -> treat as tamper, never degrade.
        return _CHECKSUMS_CORRUPT
    if not isinstance(data, dict):
        return _CHECKSUMS_CORRUPT  # valid JSON but not a manifest object
    flat = {}
    for value in data.values():
        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(k, str) and isinstance(v, str):
                    flat.setdefault(k, v)
    return flat


def _critical_file_tampered(plugin_root, skill_dir, checksums_path):
    """Return a tampered/unverifiable relpath (caller DENIES); _CANNOT_VERIFY
    when integrity cannot be established (caller decides degrade vs deny); or ""
    when everything present verified.

    STRICT: with checksums.json present, every PRESENT trust-base file must have
    a listed hash AND a computed hash AND they must match. A missing key, an
    unreadable file, or a mismatch all DENY. A trust-base file that is simply
    ABSENT is skipped (a missing launcher is a legit python3-fallback config,
    not tamper)."""
    checks = _load_checksum_map(checksums_path)
    if checks == _CHECKSUMS_CORRUPT:
        return _CHECKSUMS_CORRUPT  # present-but-unusable manifest -> DENY as tamper
    if checks is None:
        return _CANNOT_VERIFY

    # (checksums.json key, absolute path). Skill files are skill-root-relative;
    # python-launcher.sh is plugin-root-relative and RUNS the scanner (it can
    # emit a verdict itself), so it is in the trust base.
    trust_base = [
        ("scripts/pre_scan.py", os.path.join(skill_dir, "scripts", "pre_scan.py")),
        ("scripts/hook_adapter.py", os.path.join(skill_dir, "scripts", "hook_adapter.py")),
        ("scripts/ioc_manager.py", os.path.join(skill_dir, "scripts", "ioc_manager.py")),
        ("scripts/forensics_core.py", os.path.join(skill_dir, "scripts", "forensics_core.py")),
        ("scripts/rule_loader.py", os.path.join(skill_dir, "scripts", "rule_loader.py")),
        ("data/compromised_versions.json", os.path.join(skill_dir, "data", "compromised_versions.json")),
        ("hooks/python-launcher.sh", os.path.join(plugin_root, "hooks", "python-launcher.sh")),
    ]

    for key, abspath in trust_base:
        if not os.path.isfile(abspath):
            continue  # absent -> skipped (not tamper)
        want = checks.get(key)
        got = _sha256_file(abspath)
        if not want or not got or got != want:
            return key
    return ""


# --------------------------------------------------------------------------- #
# Interpreter resolution + running the gate
# --------------------------------------------------------------------------- #
def _resolve_python():
    """The interpreter to run pre_scan.py. We are already executing under a
    resolved Python, so sys.executable is the correct, cross-platform choice
    (never hardcode "python3", which does not exist on Windows). Fall back to a
    PATH probe only if sys.executable is somehow unavailable."""
    if sys.executable and os.path.isfile(sys.executable):
        return [sys.executable]
    import shutil
    for name in ("python3", "python"):
        found = shutil.which(name)
        if found:
            return [found]
    py = shutil.which("py")
    if py:
        return [py, "-3"]
    return None


def _run_gate(script_path, stdin_bytes):
    """Run pre_scan.py --adapter cursor with the resolved interpreter, feeding it
    the original stdin. Returns (stdout_text, returncode). We DO NOT route
    through hooks/python-launcher.sh at runtime: we are already under a resolved
    interpreter, and shelling out to bash would reintroduce the WSL-bash-first
    hazard this port exists to remove. The launcher stays in the trust base and
    is hash-verified above, so a swapped launcher is still denied before we get
    here."""
    interp = _resolve_python()
    if interp is None:
        return "", 127
    try:
        proc = subprocess.run(
            interp + [script_path, "--adapter", "cursor"],
            input=stdin_bytes,
            stdout=subprocess.PIPE,
            stderr=None,  # inherit: scanner diagnostics go to our stderr
            timeout=None,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "", 127
    out = (proc.stdout or b"").decode("utf-8", errors="replace")
    return out, proc.returncode


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    plugin_root = _plugin_root()
    skill_dir = os.path.join(plugin_root, "skills", "repo-forensics")
    script = os.path.join(skill_dir, "scripts", "pre_scan.py")
    manifest = os.path.join(plugin_root, "install-manifest.json")
    checksums = os.path.join(skill_dir, "checksums.json")

    _bootstrap_refresh(plugin_root)

    # --- (R8) missing scanner ------------------------------------------------
    if not os.path.isfile(script):
        missing = _manifest_claims_missing_file(plugin_root, manifest)
        if os.path.isfile(manifest):
            manifest_names_prescan = False
            try:
                with open(manifest, "r", encoding="utf-8") as fh:
                    manifest_names_prescan = "pre_scan.py" in fh.read()
            except OSError:
                manifest_names_prescan = False
            if missing or manifest_names_prescan:
                shown = missing or "skills/repo-forensics/scripts/pre_scan.py"
                _warn("[repo-forensics] TAMPER: install manifest %s expects files "
                      "that are absent at runtime (e.g. %s)." % (manifest, shown))
                _warn("[repo-forensics] Refusing to approve while the install is "
                      "inconsistent. Reinstall repo-forensics.")
                _emit_verdict("deny",
                              "[repo-forensics] TAMPER: the install manifest expects "
                              "%s, which is absent at runtime. The pre-execution gate "
                              "cannot vouch for this command; reinstall repo-forensics "
                              "or remove the stale hook." % (missing or "pre_scan.py"))
        _warn("[repo-forensics] WARNING: pre_scan.py not found at: %s" % script)
        _warn("[repo-forensics] No install manifest claims it, so this is treated "
              "as 'not installed here' rather than tampering.")
        _warn("[repo-forensics] The pre-execution gate is NOT protecting this command.")
        _emit_verdict("allow", "")

    # --- (R8) present-but-modified scanner -----------------------------------
    tampered = _critical_file_tampered(plugin_root, skill_dir, checksums)
    if tampered == _CANNOT_VERIFY:
        _warn("[repo-forensics] WARNING: cannot verify scanner integrity "
              "(no checksums.json).")
        _warn("[repo-forensics] Proceeding on existence checks only. Run "
              "'verify_install.py --verify-signature' to audit the install.")
    elif tampered == _CHECKSUMS_CORRUPT:
        _warn("[repo-forensics] TAMPER: checksums.json is present but unreadable "
              "or corrupt. This is not a valid install state.")
        _warn("[repo-forensics] Refusing to approve: a corrupt integrity manifest "
              "cannot vouch for the scanner. Reinstall repo-forensics.")
        _emit_verdict("deny",
                      "[repo-forensics] TAMPER: the integrity manifest "
                      "(checksums.json) is present but corrupt/unreadable. "
                      "Corrupting the manifest instead of forging a hash cannot be "
                      "allowed to disable the check; the pre-execution gate will "
                      "not trust the scanner. Reinstall repo-forensics.")
    elif tampered:
        _warn("[repo-forensics] TAMPER: %s does not match checksums.json "
              "(modified since install)." % tampered)
        _warn("[repo-forensics] Refusing to trust a modified scanner. Reinstall "
              "repo-forensics.")
        _emit_verdict("deny",
                      "[repo-forensics] TAMPER: a decision-critical scanner file (%s) "
                      "has been modified since install (checksum mismatch). The "
                      "pre-execution gate will not trust a modified scanner to vouch "
                      "for this command; reinstall repo-forensics." % tampered)

    # --- run the gate --------------------------------------------------------
    try:
        stdin_bytes = sys.stdin.buffer.read(_STDIN_CAP)
    except (OSError, ValueError):
        stdin_bytes = b""

    out, rc = _run_gate(script, stdin_bytes)

    log_path = os.environ.get("REPO_FORENSICS_HOOK_LOG")
    if log_path:
        perm = "<unparsed>"
        m = re.search(r'"permission"\s*:\s*"([a-z]*)"', out)
        if m:
            perm = m.group(1)
        _evidence(log_path, stdin_bytes.decode("utf-8", errors="replace"), perm, rc)

    if rc in (0, 2) and out.strip():
        sys.stdout.write(out if out.endswith("\n") else out + "\n")
        sys.stdout.flush()
        sys.exit(rc)

    _warn("[repo-forensics] FAIL-CLOSED: the pre-execution gate exited %s without "
          "a verdict." % rc)
    _warn("[repo-forensics] A gate that cannot answer must not approve. Check the "
          "Python interpreter and the install.")
    _emit_verdict("deny",
                  "[repo-forensics] FAIL-CLOSED: the repo-forensics pre-execution gate "
                  "could not run (exit %s, no verdict). The command was not checked, so "
                  "it is denied rather than waved through." % rc)


if __name__ == "__main__":
    main()
