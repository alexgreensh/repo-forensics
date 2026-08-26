#!/usr/bin/env python3
"""Install repo-forensics hooks into Cursor.

Wires the same three hooks the other adapters use, mapped onto Cursor's event
names (PRD v3 §4, M3):

    beforeShellExecution  -> hooks/cursor/run_pre_scan.sh     (blocking IOC gate)
    afterShellExecution   -> hooks/cursor/run_auto_scan.sh    (deep audit, observe-only)
    sessionStart          -> hooks/cursor/run_session_scan.sh (baseline + feed refresh)

Scope is USER (`~/.cursor/hooks.json`), matching openclaw_install.py. That is
also what makes forensify's `~/.cursor/` audit meaningful: a project-scope
install would be invisible to a machine-wide inventory.

Root resolution (§4.2): the absolute plugin root is BAKED into each installed
command, exactly as openclaw_install.py:77-100 does it. Cursor does not set
CLAUDE_PLUGIN_ROOT, and self-resolving wrappers are strictly more code for a
strictly worse failure mode (a wrapper that guesses wrong resolves to somebody
else's tree). The wrappers keep a dirname-based fallback for hand-wired
configs, but the installed path never depends on it.

Merge safety (R6a): Cursor's hooks.json is a shared file. This installer
refuses to write a config that would drop the required `version` field or
clobber hooks it does not own; it writes to a temp file, re-reads and validates
it, keeps a `.bak`, and restores from that backup if validation fails.
`--uninstall` removes only entries carrying the ownership marker.

Usage:
    python3 cursor_install.py [--uninstall] [--verify] [--scope user|project]
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

MARKER = "repo-forensics"
OWNERSHIP_MARKER = "REPO_FORENSICS_MANAGED=1"
MANAGED_SCRIPTS = ("run_pre_scan.sh", "run_auto_scan.sh", "run_session_scan.sh")

# Cursor requires a schema version in hooks.json. Dropping it silently disables
# every hook in the file, including the ones we did not write, so it is treated
# as a hard invariant rather than a default we fill in on the way out.
HOOKS_SCHEMA_VERSION = 1

# Cursor event -> (wrapper script, timeout seconds, blocking?)
# Timeouts mirror hooks/hooks.json (10 / 30 / 25) so the four adapters agree on
# the latency budget per event (O7).
HOOK_EVENTS = (
    ("beforeShellExecution", "run_pre_scan.sh", 10, True),
    ("afterShellExecution", "run_auto_scan.sh", 30, False),
    ("sessionStart", "run_session_scan.sh", 25, False),
)

# Files the installed hooks depend on at runtime, relative to the plugin root.
# This is the R8 tamper oracle: if one of these is gone while the manifest still
# claims it, the blocking wrapper denies instead of degrading to approve.
INSTALL_MANIFEST_NAME = "install-manifest.json"
MANIFEST_FILES = (
    "hooks/cursor/run_pre_scan.sh",
    "hooks/cursor/run_auto_scan.sh",
    "hooks/cursor/run_session_scan.sh",
    "hooks/python-launcher.sh",
    "hooks/ensure_refresh_daemon.sh",
    # The blocking beforeShellExecution gate is now this cross-platform Python
    # entrypoint (the port of run_pre_scan.sh). It is the file the failClosed
    # hook actually launches, so it belongs in the R8 tamper oracle: deleting it
    # while the manifest claims it must DENY, not silently degrade to approve.
    "skills/repo-forensics/scripts/cursor_pre_scan.py",
    "skills/repo-forensics/scripts/pre_scan.py",
    "skills/repo-forensics/scripts/auto_scan.py",
    "skills/repo-forensics/scripts/session_scan.py",
    "skills/repo-forensics/scripts/hook_adapter.py",
    "skills/repo-forensics/scripts/ioc_manager.py",
)


def _repo_root():
    return Path(__file__).resolve().parents[1]


def _dq(value):
    """Escape a value for safe interpolation inside a double-quoted shell string.

    The install path is embedded into a command Cursor stores and evaluates on
    every hook event; an unescaped `"`, `$`, or backtick would break the quoting
    and allow command injection if the repo lives at a hostile path. Identical
    treatment to openclaw_install._dq — same threat, same answer.
    """
    return (str(value).replace("\\", "\\\\").replace('"', '\\"')
            .replace("$", "\\$").replace("`", "\\`")
            .replace("\n", "\\n").replace("\r", "\\r"))


def _cursor_config_path(scope="user"):
    if scope == "project":
        return Path.cwd() / ".cursor" / "hooks.json"
    home = Path(os.environ.get("CURSOR_HOME", Path.home() / ".cursor"))
    return home / "hooks.json"


# The cross-platform Python gate that replaces the bash-only
# hooks/cursor/run_pre_scan.sh for the blocking event. Plugin-root-relative.
CURSOR_GATE_REL = "skills/repo-forensics/scripts/cursor_pre_scan.py"


def _gate_interpreter():
    """Absolute path to the interpreter that ran this installer, baked into the
    installed blocking-gate command.

    The shipped hooks.json template launches the gate via a literal `python3`,
    which is fine on CI (actions/setup-python provides a `python3` shim) and on
    POSIX, but the dominant Windows Python -- the python.org installer -- ships
    only `python.exe` and the `py` launcher, no `python3.exe`. On such a box a
    failClosed gate launched as `python3` cannot start and would DENY every
    shell command (the same failure class as the WSL-`bash` bug this port
    fixes). The user necessarily ran cursor_install.py with a WORKING Python, so
    sys.executable is guaranteed valid on that machine, Windows included. Baking
    it makes the residual vanish for every installer-based install; a hand-wired
    hooks.json keeps the `python3` default, which is the advanced user's choice.

    Baking (not a `python3 || python || py` fallback chain) is deliberate: a
    legit exit-2 DENY from the gate would trip a `||` chain and double-run the
    scanner. A single baked, guaranteed-valid interpreter avoids that entirely.
    """
    return sys.executable


def _managed_hooks(root=None):
    """The hook entries this installer owns, with the plugin root baked in.

    The blocking beforeShellExecution gate launches the cross-platform Python
    entrypoint via the baked absolute interpreter (see _gate_interpreter). The
    non-blocking events keep their POSIX bash wrappers unchanged.
    """
    raw_root = _repo_root() if root is None else Path(root)
    quoted = _dq(raw_root)
    interp = _dq(_gate_interpreter())
    hooks = {}
    for event, script, timeout, blocking in HOOK_EVENTS:
        if blocking:
            command = (f'{OWNERSHIP_MARKER} CLAUDE_PLUGIN_ROOT="{quoted}" '
                       f'"{interp}" "{quoted}/{CURSOR_GATE_REL}"')
        else:
            command = (f'{OWNERSHIP_MARKER} CLAUDE_PLUGIN_ROOT="{quoted}" '
                       f'bash "{quoted}/hooks/cursor/{script}"')
        entry = {"command": command, "timeout": timeout}
        if blocking:
            # Declared per R7. A gate that cannot answer must not approve; the
            # wrapper enforces this itself too, because a config flag is only as
            # trustworthy as the config file it lives in.
            entry["failClosed"] = True
        hooks[event] = [entry]
    return hooks


# --- ownership --------------------------------------------------------------

def _command_is_ours(command):
    """True when *command* is an entry this installer wrote.

    The ownership marker is authoritative. The structural fallback recognises
    pre-marker installs so an upgrade replaces them instead of stacking a second
    copy of every hook.
    """
    if not isinstance(command, str):
        return False
    if OWNERSHIP_MARKER in command:
        return True
    normalized = command.replace("\\", "/")
    managed_path = ("/hooks/" in normalized
                    and any(f"/{name}" in normalized for name in MANAGED_SCRIPTS))
    return managed_path and (
        "CLAUDE_PLUGIN_ROOT=" in normalized or MARKER in normalized.lower()
    )


def _entry_is_ours(entry):
    if isinstance(entry, dict):
        return _command_is_ours(entry.get("command", ""))
    return False


def _strip_ours(hooks):
    """Drop only our entries, preserving every foreign hook and event key.

    An event whose list becomes empty is removed entirely so uninstall leaves no
    empty scaffolding behind, but an event that still holds someone else's hook
    keeps both the key and that hook.
    """
    if not isinstance(hooks, dict):
        raise ValueError("refusing to replace a non-object 'hooks' value in Cursor hooks.json")
    cleaned = {}
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            # Not ours to interpret — carry it through untouched rather than
            # normalising someone else's shape.
            cleaned[event] = entries
            continue
        kept = [e for e in entries if not _entry_is_ours(e)]
        if kept:
            cleaned[event] = kept
    return cleaned


# --- config IO --------------------------------------------------------------

def _load_config(path):
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"refusing to overwrite unreadable Cursor config {path}: {exc}")
    if not isinstance(data, dict):
        raise ValueError(f"refusing to overwrite non-object Cursor config {path}")
    return data


def _validate_config(config):
    """Return a list of reasons *config* must not be written."""
    errors = []
    if not isinstance(config, dict):
        return ["hooks.json must be a JSON object"]

    # The invariant is that `version` is PRESENT and plausible — not that it
    # equals the version we know about. Dropping it disables every hook in the
    # file, so that is the failure worth refusing over. A version we do not
    # recognise (a newer Cursor, or a deliberate choice by the user) is theirs
    # to keep: rewriting it would be us asserting knowledge of a schema we have
    # never seen.
    version = config.get("version")
    if version is None:
        errors.append(
            f"hooks.json must carry a \"version\" field; refusing to write a "
            f"config that Cursor would ignore entirely (expected "
            f"{HOOKS_SCHEMA_VERSION})")
    elif not isinstance(version, int) or isinstance(version, bool) or version < 1:
        errors.append(
            f"hooks.json \"version\" must be a positive integer, got {version!r}")
    hooks = config.get("hooks")
    if not isinstance(hooks, dict):
        errors.append("hooks.json 'hooks' must be an object")
        return errors
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            errors.append(f"hooks.{event} must be a list")
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or not isinstance(entry.get("command"), str):
                errors.append(f"hooks.{event}[{index}] must be an object with a string 'command'")
    return errors


def _atomic_write_config(path, config):
    """Write *config* to *path* atomically, with a validated read-back.

    Order matters: back up the existing file, write a temp file in the same
    directory, re-read the temp file and validate what actually landed on disk,
    and only then rename. If validation fails the temp file is discarded and the
    original is restored from the backup, so a botched merge can never leave the
    user with a hooks.json that Cursor silently ignores.
    """
    target = os.fspath(path)
    directory = os.path.dirname(target) or "."
    os.makedirs(directory, exist_ok=True)

    backup = target + ".bak"
    had_original = os.path.exists(target)
    if had_original:
        shutil.copy2(target, backup)

    fd, tmp = tempfile.mkstemp(prefix=".repo-forensics.", dir=directory)
    fd_owned = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd_owned = True
            json.dump(config, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        # Validate what is ON DISK, not what we think we serialised.
        with open(tmp, "r", encoding="utf-8") as handle:
            written = json.load(handle)
        errors = _validate_config(written)
        if errors:
            raise ValueError("refusing to install; the merged config is invalid:\n  - "
                             + "\n  - ".join(errors))

        os.replace(tmp, target)
    except BaseException:
        if not fd_owned:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if had_original and os.path.exists(backup):
            try:
                shutil.copy2(backup, target)
            except OSError:
                pass
        raise
    return backup if had_original else None


# --- install manifest (R8) --------------------------------------------------

def write_install_manifest(root=None):
    """Record which files the installed hooks expect to find at runtime.

    Only files that actually exist are recorded. A manifest that claims a file
    the installer never shipped would turn every subsequent command into a
    tamper denial, which is a self-inflicted outage rather than a security
    control.
    """
    plugin_root = Path(root) if root else _repo_root()
    present = [rel for rel in MANIFEST_FILES if (plugin_root / rel).is_file()]
    payload = {
        "schema_version": "1.0",
        "plugin": "repo-forensics",
        "adapter": "cursor",
        "files": present,
    }
    manifest_path = plugin_root / INSTALL_MANIFEST_NAME
    fd, tmp = tempfile.mkstemp(prefix=".repo-forensics.", dir=os.fspath(plugin_root))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        os.replace(tmp, os.fspath(manifest_path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    missing = [rel for rel in MANIFEST_FILES if rel not in present]
    return manifest_path, missing


# --- commands ---------------------------------------------------------------

def install(scope="user", root=None):
    path = _cursor_config_path(scope)
    config = _load_config(path)

    hooks = _strip_ours(config.get("hooks", {}))
    for event, entries in _managed_hooks(root).items():
        hooks.setdefault(event, [])
        if not isinstance(hooks[event], list):
            raise ValueError(f"refusing to install: existing hooks.{event} is not a list")
        hooks[event].extend(entries)

    config["hooks"] = hooks
    # Set the schema version only if absent: never silently rewrite a version
    # the user (or a newer Cursor) put there deliberately.
    config.setdefault("version", HOOKS_SCHEMA_VERSION)

    errors = _validate_config(config)
    if errors:
        raise ValueError("refusing to install; the merged config is invalid:\n  - "
                         + "\n  - ".join(errors))

    backup = _atomic_write_config(path, config)

    manifest_path, missing = write_install_manifest(root)

    print(f"[repo-forensics] Hooks installed to {path}")
    print("[repo-forensics] 3 hooks active: beforeShellExecution (IOC gate, blocking), "
          "afterShellExecution (deep audit), sessionStart (security scan)")
    print(f"[repo-forensics] Install manifest written to {manifest_path} "
          f"({len(MANIFEST_FILES) - len(missing)}/{len(MANIFEST_FILES)} files present)")
    if missing:
        print("[repo-forensics] NOTE: not recorded (absent at install time): "
              + ", ".join(missing))
    if backup:
        print(f"[repo-forensics] Previous config backed up to {backup}")
    print("[repo-forensics] Kill switches: REPO_FORENSICS_PRE_SCAN=0 disables detection "
          "on the blocking path; =unsafe-off additionally disables tamper and "
          "schema-drift denials. Tamper and drift outrank the plain switch by design.")
    return 0


def uninstall(scope="user", root=None):
    path = _cursor_config_path(scope)
    if not path.exists():
        print(f"[repo-forensics] No Cursor hooks.json found at {path}")
        return 0

    config = _load_config(path)
    config["hooks"] = _strip_ours(config.get("hooks", {}))
    config.setdefault("version", HOOKS_SCHEMA_VERSION)

    _atomic_write_config(path, config)

    manifest_path = (Path(root) if root else _repo_root()) / INSTALL_MANIFEST_NAME
    if manifest_path.exists():
        try:
            manifest_path.unlink()
        except OSError as exc:
            print(f"[repo-forensics] WARNING: could not remove {manifest_path}: {exc}",
                  file=sys.stderr)

    remaining = sum(len(v) for v in config["hooks"].values() if isinstance(v, list))
    print(f"[repo-forensics] repo-forensics hooks removed from {path}")
    print(f"[repo-forensics] {remaining} non-repo-forensics hook(s) preserved")
    return 0


def _verify_config(config, root=None):
    errors = _validate_config(config)
    hooks = config.get("hooks", {})
    if not isinstance(hooks, dict):
        return errors

    managed = _managed_hooks(root)
    for event, entries in managed.items():
        actual_entries = hooks.get(event)
        if not isinstance(actual_entries, list):
            errors.append(f"missing Cursor hook list: hooks.{event}")
            continue
        expected = {entry["command"] for entry in entries}
        actual = {e.get("command") for e in actual_entries if isinstance(e, dict)}
        if expected - actual:
            errors.append(f"current repo-forensics hook not present in hooks.{event}")
        stale = {c for c in actual if _command_is_ours(c)} - expected
        if stale:
            errors.append(f"stale repo-forensics hook present in hooks.{event}")

    plugin_root = Path(root) if root else _repo_root()
    for _event, script, _timeout, _blocking in HOOK_EVENTS:
        wrapper = plugin_root / "hooks" / "cursor" / script
        if not wrapper.is_file():
            errors.append(f"managed hook script missing: {wrapper}")

    manifest_path = plugin_root / INSTALL_MANIFEST_NAME
    if not manifest_path.is_file():
        errors.append(f"install manifest missing: {manifest_path} "
                      f"(the blocking hook cannot tell tampering from absence without it)")
    return errors


def verify(scope="user", root=None):
    path = _cursor_config_path(scope)
    if not path.exists():
        print(f"[repo-forensics] Cursor config not found: {path}", file=sys.stderr)
        return 1
    try:
        config = _load_config(path)
    except ValueError as exc:
        print(f"[repo-forensics] {exc}", file=sys.stderr)
        return 1
    errors = _verify_config(config, root)
    if errors:
        print("[repo-forensics] Cursor hook verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"[repo-forensics] Cursor hooks verified: {path}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Install repo-forensics hooks for Cursor")
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove only repo-forensics-owned hooks")
    parser.add_argument("--verify", action="store_true",
                        help="Verify repo-forensics hooks are wired and current")
    parser.add_argument("--scope", choices=("user", "project"), default="user",
                        help="user: ~/.cursor/hooks.json (default). project: ./.cursor/hooks.json")
    parser.add_argument("--root", default=None,
                        help="Plugin root to bake into the hook commands "
                             "(defaults to this checkout)")
    args = parser.parse_args(argv)

    try:
        if args.verify:
            return verify(args.scope, args.root)
        if args.uninstall:
            return uninstall(args.scope, args.root)
        return install(args.scope, args.root)
    except ValueError as exc:
        print(f"[repo-forensics] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
