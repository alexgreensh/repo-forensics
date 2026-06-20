#!/usr/bin/env python3
"""Install repo-forensics hooks into Codex CLI.

Wires the same PreToolUse, PostToolUse, and SessionStart hooks that
Claude Code uses, adapted for Codex's hook system. Hooks are installed
globally to ~/.codex/hooks.json.

Usage:
    python3 codex_install.py [--uninstall]
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MARKER = "repo-forensics"
OWNERSHIP_MARKER = "REPO_FORENSICS_MANAGED=1"
MANAGED_SCRIPTS = ("run_pre_scan.sh", "run_auto_scan.sh", "run_session_scan.sh",
                   "first-run-nudge.sh")
HOOK_EVENTS = ("PreToolUse", "PostToolUse", "SessionStart")
CODEX_STATE_EVENTS = {
    "PreToolUse": "pre_tool_use",
    "PostToolUse": "post_tool_use",
    "SessionStart": "session_start",
}


def _repo_root():
    return Path(__file__).resolve().parents[1]


def _dq(value):
    """Escape a value for safe interpolation inside a double-quoted shell string.
    The install path is embedded into a command Codex stores and evaluates on
    every hook event; an unescaped `"`, `$`, or backtick would break the quoting
    and allow command injection if the repo lives at a hostile path."""
    return (str(value).replace("\\", "\\\\").replace('"', '\\"')
            .replace("$", "\\$").replace("`", "\\`")
            .replace("\n", "\\n").replace("\r", "\\r"))


def _hook_command(script_name):
    root = _repo_root()
    script = root / "hooks" / script_name
    if not script.exists():
        print(f"[repo-forensics] WARNING: {script} not found", file=sys.stderr)
    return f'{OWNERSHIP_MARKER} CLAUDE_PLUGIN_ROOT="{_dq(root)}" bash "{_dq(script)}"'


def _managed_hooks():
    return {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": _hook_command("run_pre_scan.sh"),
                        "timeout": 10,
                    }
                ],
            }
        ],
        "PostToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": _hook_command("run_auto_scan.sh"),
                        "timeout": 30,
                    }
                ],
            }
        ],
        "SessionStart": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": _hook_command("run_session_scan.sh"),
                        "timeout": 25,
                    },
                    {
                        "type": "command",
                        "command": _hook_command("first-run-nudge.sh"),
                    }
                ],
            }
        ],
    }


def _codex_hooks_path():
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    codex_home.mkdir(parents=True, exist_ok=True)
    return codex_home / "hooks.json"


def _codex_config_path():
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    return codex_home / "config.toml"


def _load_existing(path):
    if not path.exists():
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"refusing to overwrite unreadable Codex hooks {path}: {exc}")


def _command_is_ours(cmd):
    if not isinstance(cmd, str):
        return False
    normalized = cmd.replace("\\", "/")
    managed_path = ("/hooks/" in normalized
                    and any(f"/{name}" in normalized for name in MANAGED_SCRIPTS))
    legacy_structure = managed_path and (
        "CLAUDE_PLUGIN_ROOT=" in normalized or MARKER in normalized.lower()
    )
    return OWNERSHIP_MARKER in cmd or legacy_structure


def _is_ours(hook_entry):
    if not isinstance(hook_entry, dict):
        return False
    if _command_is_ours(hook_entry.get("command", "")):
        return True

    for h in hook_entry.get("hooks", []):
        if _is_ours(h):
            return True
    return False


def _remove_owned_from_entry(entry):
    """Remove only owned inner commands, preserving a shared matcher entry."""
    if not isinstance(entry, dict):
        return entry
    if _command_is_ours(entry.get("command", "")):
        return None
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return entry
    kept = [hook for hook in hooks
            if not (isinstance(hook, dict)
                    and _command_is_ours(hook.get("command", "")))]
    if not kept:
        return None
    cleaned = dict(entry)
    cleaned["hooks"] = kept
    return cleaned


def _remove_ours_from_event_map(event_map):
    cleaned = {}
    if not isinstance(event_map, dict):
        return cleaned

    for event, entries in event_map.items():
        if not isinstance(entries, list):
            cleaned[event] = entries
            continue

        kept = [cleaned for entry in entries
                for cleaned in [_remove_owned_from_entry(entry)]
                if cleaned is not None]
        if kept:
            cleaned[event] = kept
    return cleaned


def _remove_ours(existing):
    """Remove repo-forensics hooks from both current and legacy Codex layouts.

    Codex reads hooks from the nested {"hooks": {...}} schema. Early versions of
    this installer wrote Claude-style top-level event keys, which Codex ignores.
    Reinstall/uninstall must clean up those dead repo-forensics entries without
    promoting unrelated third-party top-level commands into live hooks.
    """
    if not isinstance(existing, dict):
        return {}

    cleaned = {}
    for key, value in existing.items():
        if key == "hooks":
            nested_hooks = _remove_ours_from_event_map(value)
            if nested_hooks:
                cleaned["hooks"] = nested_hooks
            continue

        if key in HOOK_EVENTS and isinstance(value, list):
            legacy_kept = [cleaned for entry in value
                           for cleaned in [_remove_owned_from_entry(entry)]
                           if cleaned is not None]
            if legacy_kept:
                cleaned[key] = legacy_kept
            continue

        cleaned[key] = value

    return cleaned


def _write_config(path, data):
    # Atomic write: a crash between truncate and final write would otherwise
    # leave an empty config that the fail-closed loader refuses to touch,
    # permanently stranding the user's other (non-forensics) hooks.
    import tempfile
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".repo-forensics.", dir=directory)
    fd_owned = False
    try:
        with os.fdopen(fd, "w") as f:
            fd_owned = True  # fdopen now owns fd; its context manager will close it
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
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
        raise


def _schema_errors(data):
    errors = []
    if not isinstance(data, dict):
        return ["hooks file is not a JSON object"]

    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return ['hooks file must use Codex nested schema: {"hooks": {...}}']

    managed = _managed_hooks()
    for event in HOOK_EVENTS:
        entries = hooks.get(event)
        if not isinstance(entries, list):
            errors.append(f"missing Codex hook list: hooks.{event}")
            continue
        expected = {
            hook["command"]
            for entry in managed[event]
            for hook in entry.get("hooks", [])
        }
        actual = {
            hook.get("command")
            for entry in entries if isinstance(entry, dict)
            for hook in entry.get("hooks", []) if isinstance(hook, dict)
        }
        missing_commands = expected - actual
        if missing_commands:
            errors.append(f"missing current repo-forensics command in hooks.{event}")
        stale_owned = {
            hook.get("command")
            for entry in entries if isinstance(entry, dict)
            for hook in entry.get("hooks", [])
            if isinstance(hook, dict) and _command_is_ours(hook.get("command", ""))
        } - expected
        if stale_owned:
            errors.append(f"stale repo-forensics command in hooks.{event}")

        legacy_entries = data.get(event, [])
        if isinstance(legacy_entries, list) and any(_is_ours(entry) for entry in legacy_entries):
            errors.append(f"repo-forensics command still present in legacy top-level {event}")

    root = _repo_root()
    expected_scripts = {
        Path(command.rsplit('"', 2)[1])
        for event in managed.values()
        for entry in event
        for hook in entry.get("hooks", [])
        for command in [hook.get("command", "")]
        if command.count('"') >= 2
    }
    for script in expected_scripts:
        if not script.is_file() or root not in script.parents:
            errors.append(f"managed hook script missing: {script}")
    return errors


def _run_refresh_controller(command):
    controller = _repo_root() / "skills" / "repo-forensics" / "scripts" / "refresh_controller.py"
    if not controller.is_file():
        print(f"[repo-forensics] Refresh controller not found: {controller}", file=sys.stderr)
        return 1
    try:
        result = subprocess.run(
            [sys.executable, str(controller), command, "--json"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[repo-forensics] Refresh controller {command} failed: {exc}", file=sys.stderr)
        return 1
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        print(f"[repo-forensics] Refresh controller {command} failed"
              + (f": {detail[:500]}" if detail else ""), file=sys.stderr)
    return result.returncode


def _registered_events(path=None, config_path=None):
    path = Path(path or _codex_hooks_path())
    config_path = Path(config_path or _codex_config_path())
    if not config_path.exists():
        return set()

    try:
        text = config_path.read_text()
    except OSError:
        return set()

    registered = set()
    prefix = f"{path}:"
    for match in re.finditer(r'^\[hooks\.state\."([^"]+)"\]\s*$', text, re.MULTILINE):
        key = match.group(1)
        if key.startswith(prefix):
            registered.add(key[len(prefix):].split(":", 1)[0])
    return registered


def verify(require_registered=False):
    path = _codex_hooks_path()
    if not path.exists():
        print(f"[repo-forensics] Codex hooks file not found: {path}", file=sys.stderr)
        return 1

    data = _load_existing(path)
    errors = _schema_errors(data)

    expected_state_events = set(CODEX_STATE_EVENTS.values())
    registered = _registered_events(path)
    missing_registered = expected_state_events - registered
    if require_registered and missing_registered:
        missing = ", ".join(sorted(missing_registered))
        errors.append(f"Codex has not registered these hook events yet: {missing}")

    if errors:
        print("[repo-forensics] Codex hook verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"[repo-forensics] Codex hook schema verified: {path}")
    if registered:
        seen = ", ".join(sorted(registered & expected_state_events))
        print(f"[repo-forensics] Codex registration state seen: {seen}")
    else:
        print("[repo-forensics] Codex registration state not seen yet; restart Codex, then run --verify --require-registered")
    return 0


def install():
    path = _codex_hooks_path()
    existing = _load_existing(path)

    cleaned = _remove_ours(existing)
    hooks = cleaned.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        cleaned["hooks"] = hooks

    managed = _managed_hooks()
    for event, entries in managed.items():
        if not isinstance(hooks.get(event), list):
            hooks[event] = []
        hooks[event].extend(entries)

    _write_config(path, cleaned)

    print(f"[repo-forensics] Hooks installed to {path}")
    print("[repo-forensics] 3 hook events active: PreToolUse (IOC gate), PostToolUse (auto-scan), SessionStart (security scan + first-run nudge)")
    return verify(require_registered=False)


def uninstall():
    path = _codex_hooks_path()
    existing = _load_existing(path) if path.exists() else None
    cleaned = _remove_ours(existing) if existing is not None else None
    if _run_refresh_controller("uninstall") != 0:
        return 1
    if cleaned is None:
        print("[repo-forensics] No hooks.json found; refresh scheduler removed")
        return 0
    _write_config(path, cleaned)
    print(f"[repo-forensics] Hooks and refresh scheduler removed from {path}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Install repo-forensics hooks for Codex CLI")
    parser.add_argument("--uninstall", action="store_true", help="Remove repo-forensics hooks")
    parser.add_argument("--verify", action="store_true", help="Verify Codex hook schema and registration state")
    parser.add_argument(
        "--require-registered",
        action="store_true",
        help="With --verify, fail until Codex config.toml shows the hooks were registered",
    )
    args = parser.parse_args()

    try:
        if args.verify:
            return verify(require_registered=args.require_registered)
        if args.uninstall:
            return uninstall()
        return install()
    except ValueError as exc:
        print(f"[repo-forensics] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
