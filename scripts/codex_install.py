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
import sys
from pathlib import Path

MARKER = "repo-forensics"


def _repo_root():
    return Path(__file__).resolve().parents[1]


def _hook_command(script_rel_path):
    root = _repo_root()
    script = root / script_rel_path
    if not script.exists():
        print(f"[repo-forensics] WARNING: {script} not found", file=sys.stderr)
    return f'CLAUDE_PLUGIN_ROOT="{root}" bash "{root / "hooks" / script_rel_path.split("/")[-1]}"'


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


def _codex_hooks_path():
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    codex_home.mkdir(parents=True, exist_ok=True)
    return codex_home / "hooks.json"


def _load_existing(path):
    if not path.exists():
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _is_ours(hook_entry):
    for h in hook_entry.get("hooks", []):
        cmd = h.get("command", "")
        if MARKER in cmd:
            return True
    return False


def _remove_ours(existing):
    cleaned = {}
    for event, entries in existing.items():
        if event == "hooks":
            continue
        kept = [e for e in entries if not _is_ours(e)]
        if kept:
            cleaned[event] = kept
    return cleaned


def install():
    path = _codex_hooks_path()
    existing = _load_existing(path)

    cleaned = _remove_ours(existing)

    managed = _managed_hooks()
    for event, entries in managed.items():
        if event not in cleaned:
            cleaned[event] = []
        cleaned[event].extend(entries)

    with open(path, "w") as f:
        json.dump(cleaned, f, indent=2)
        f.write("\n")

    print(f"[repo-forensics] Hooks installed to {path}")
    print("[repo-forensics] 3 hooks active: PreToolUse (IOC gate), PostToolUse (auto-scan), SessionStart (security scan)")
    return 0


def uninstall():
    path = _codex_hooks_path()
    if not path.exists():
        print("[repo-forensics] No hooks.json found, nothing to uninstall")
        return 0

    existing = _load_existing(path)
    cleaned = _remove_ours(existing)

    with open(path, "w") as f:
        json.dump(cleaned, f, indent=2)
        f.write("\n")

    print(f"[repo-forensics] Hooks removed from {path}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Install repo-forensics hooks for Codex CLI")
    parser.add_argument("--uninstall", action="store_true", help="Remove repo-forensics hooks")
    args = parser.parse_args()

    if args.uninstall:
        return uninstall()
    return install()


if __name__ == "__main__":
    sys.exit(main())
