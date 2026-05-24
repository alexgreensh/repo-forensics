#!/usr/bin/env python3
"""Install repo-forensics hooks into OpenClaw.

Wires the same PreToolUse, PostToolUse, and SessionStart hooks that
Claude Code uses, adapted for OpenClaw's hook system in openclaw.json.

Usage:
    python3 openclaw_install.py [--uninstall]
"""

import argparse
import json
import os
import sys
from pathlib import Path

MARKER = "repo-forensics"


def _repo_root():
    return Path(__file__).resolve().parents[1]


def _managed_hooks():
    root = _repo_root()
    return {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": f'CLAUDE_PLUGIN_ROOT="{root}" bash "{root}/hooks/run_pre_scan.sh"',
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
                        "command": f'CLAUDE_PLUGIN_ROOT="{root}" bash "{root}/hooks/run_auto_scan.sh"',
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
                        "command": f'CLAUDE_PLUGIN_ROOT="{root}" bash "{root}/hooks/run_session_scan.sh"',
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
    except (json.JSONDecodeError, OSError):
        return {}


def _is_ours(hook_entry):
    for h in hook_entry.get("hooks", []):
        if MARKER in h.get("command", ""):
            return True
    return False


def _remove_ours(hooks_dict):
    cleaned = {}
    for event, entries in hooks_dict.items():
        kept = [e for e in entries if not _is_ours(e)]
        if kept:
            cleaned[event] = kept
    return cleaned


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
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")

    print(f"[repo-forensics] Hooks installed to {path}")
    print("[repo-forensics] 3 hooks active: PreToolUse (IOC gate), PostToolUse (auto-scan), SessionStart (security scan)")
    return 0


def uninstall():
    path = _openclaw_config_path()
    if not path.exists():
        print("[repo-forensics] No openclaw.json found, nothing to uninstall")
        return 0

    config = _load_config(path)
    hooks = config.get("hooks", {})
    config["hooks"] = _remove_ours(hooks)

    with open(path, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")

    print(f"[repo-forensics] Hooks removed from {path}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Install repo-forensics hooks for OpenClaw")
    parser.add_argument("--uninstall", action="store_true", help="Remove repo-forensics hooks")
    args = parser.parse_args()

    if args.uninstall:
        return uninstall()
    return install()


if __name__ == "__main__":
    sys.exit(main())
