#!/usr/bin/env python3
"""Install repo-forensics hooks into OpenClaw.

Wires the same PreToolUse, PostToolUse, and SessionStart hooks that
Claude Code uses, adapted for OpenClaw's hook system in openclaw.json.

Usage:
    python3 openclaw_install.py [--uninstall] [--verify]
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

MARKER = "repo-forensics"
OWNERSHIP_MARKER = "REPO_FORENSICS_MANAGED=1"
MANAGED_SCRIPTS = ("run_pre_scan.sh", "run_auto_scan.sh", "run_session_scan.sh",
                   "first-run-nudge.sh")
HOOK_EVENTS = ("PreToolUse", "PostToolUse", "SessionStart")


def _repo_root():
    return Path(__file__).resolve().parents[1]


def _dq(value):
    """Escape a value for safe interpolation inside a double-quoted shell string.
    The install path is embedded into a command OpenClaw stores and evaluates on
    every hook event; an unescaped `"`, `$`, or backtick would break the quoting
    and allow command injection if the repo lives at a hostile path."""
    return (str(value).replace("\\", "\\\\").replace('"', '\\"')
            .replace("$", "\\$").replace("`", "\\`"))


def _atomic_write_config(path, config):
    # Atomic write so a crash mid-write cannot leave an empty config that the
    # fail-closed loader then refuses to touch, stranding the user's other hooks.
    import tempfile
    target = os.fspath(path)
    directory = os.path.dirname(target) or "."
    fd, tmp = tempfile.mkstemp(prefix=".repo-forensics.", dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _managed_hooks():
    root = _dq(_repo_root())
    return {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": f'{OWNERSHIP_MARKER} CLAUDE_PLUGIN_ROOT="{root}" bash "{root}/hooks/run_pre_scan.sh"',
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
                        "command": f'{OWNERSHIP_MARKER} CLAUDE_PLUGIN_ROOT="{root}" bash "{root}/hooks/run_auto_scan.sh"',
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
                        "command": f'{OWNERSHIP_MARKER} CLAUDE_PLUGIN_ROOT="{root}" bash "{root}/hooks/run_session_scan.sh"',
                        "timeout": 25,
                    }
                ],
            }
        ],
    }


def _openclaw_config_path():
    return Path(os.environ.get("OPENCLAW_HOME", Path.home() / ".openclaw")) / "openclaw.json"


def _load_config(path):
    if not path.exists():
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"refusing to overwrite unreadable OpenClaw config {path}: {exc}")


def _command_is_ours(command):
    if not isinstance(command, str):
        return False
    normalized = command.replace("\\", "/")
    managed_path = ("/hooks/" in normalized
                    and any(f"/{name}" in normalized for name in MANAGED_SCRIPTS))
    legacy_structure = managed_path and (
        "CLAUDE_PLUGIN_ROOT=" in normalized or MARKER in normalized.lower()
    )
    return OWNERSHIP_MARKER in command or legacy_structure


def _is_ours(hook_entry):
    if not isinstance(hook_entry, dict):
        return False
    for h in hook_entry.get("hooks", []):
        if not isinstance(h, dict):
            continue
        if _command_is_ours(h.get("command", "")):
            return True
    return False


def _remove_owned_from_entry(entry):
    if not isinstance(entry, dict):
        return entry
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


def _remove_ours(hooks_dict):
    if not isinstance(hooks_dict, dict):
        raise ValueError("refusing to replace non-object OpenClaw hooks configuration")
    cleaned = {}
    for event, entries in hooks_dict.items():
        kept = [cleaned for entry in entries
                for cleaned in [_remove_owned_from_entry(entry)]
                if cleaned is not None]
        if kept:
            cleaned[event] = kept
    return cleaned


def _get_dotted(config, key):
    cur = config
    for part in key.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _policy_message(config):
    install_policy = _get_dotted(config, "security.installPolicy")
    if install_policy:
        return (
            "[repo-forensics] OpenClaw security.installPolicy detected: "
            f"{install_policy}. This installer writes hooks directly to "
            "openclaw.json and does not use --dangerously-force-unsafe-install."
        )
    return (
        "[repo-forensics] OpenClaw install policy not set in openclaw.json. "
        "No force-install bypass flags are used."
    )


def _verify_config(config):
    errors = []
    hooks = config.get("hooks", {})
    if not isinstance(hooks, dict):
        return ["openclaw.json hooks must be an object"]
    managed = _managed_hooks()
    for event in HOOK_EVENTS:
        entries = hooks.get(event)
        if not isinstance(entries, list):
            errors.append(f"missing OpenClaw hook list: hooks.{event}")
        else:
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
            if expected - actual:
                errors.append(f"current repo-forensics hook not present in hooks.{event}")
            stale_owned = {
                hook.get("command")
                for entry in entries if isinstance(entry, dict)
                for hook in entry.get("hooks", [])
                if isinstance(hook, dict) and _command_is_ours(hook.get("command", ""))
            } - expected
            if stale_owned:
                errors.append(f"stale repo-forensics hook present in hooks.{event}")
    for event in managed.values():
        for entry in event:
            for hook in entry.get("hooks", []):
                command = hook.get("command", "")
                if command.count('"') >= 2:
                    script = Path(command.rsplit('"', 2)[1])
                    if not script.is_file() or _repo_root() not in script.parents:
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


def install():
    path = _openclaw_config_path()
    config = _load_config(path)

    hooks = config.get("hooks", {})
    hooks = _remove_ours(hooks)

    managed = _managed_hooks()
    for event, entries in managed.items():
        if event not in hooks:
            hooks[event] = []
        hooks[event].extend(entries)

    config["hooks"] = hooks

    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_config(path, config)

    print(f"[repo-forensics] Hooks installed to {path}")
    print("[repo-forensics] 3 hooks active: PreToolUse (IOC gate), PostToolUse (auto-scan), SessionStart (security scan)")
    print(_policy_message(config))
    return 0


def uninstall():
    path = _openclaw_config_path()
    config = _load_config(path) if path.exists() else None
    if config is not None:
        cleaned_hooks = _remove_ours(config.get("hooks", {}))
    if _run_refresh_controller("uninstall") != 0:
        return 1
    if config is None:
        print("[repo-forensics] No openclaw.json found; refresh scheduler removed")
        return 0
    config["hooks"] = cleaned_hooks
    _atomic_write_config(path, config)
    print(f"[repo-forensics] Hooks and refresh scheduler removed from {path}")
    return 0


def verify():
    path = _openclaw_config_path()
    if not path.exists():
        print(f"[repo-forensics] OpenClaw config not found: {path}", file=sys.stderr)
        return 1
    config = _load_config(path)
    errors = _verify_config(config)
    if errors:
        print("[repo-forensics] OpenClaw hook verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        print(_policy_message(config), file=sys.stderr)
        return 1
    print(f"[repo-forensics] OpenClaw hooks verified: {path}")
    print(_policy_message(config))
    return 0


def main():
    parser = argparse.ArgumentParser(description="Install repo-forensics hooks for OpenClaw")
    parser.add_argument("--uninstall", action="store_true", help="Remove repo-forensics hooks")
    parser.add_argument("--verify", action="store_true", help="Verify repo-forensics hooks are present")
    args = parser.parse_args()

    try:
        if args.verify:
            return verify()
        if args.uninstall:
            return uninstall()
        return install()
    except ValueError as exc:
        print(f"[repo-forensics] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
