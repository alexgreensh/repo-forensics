#!/usr/bin/env bash
# Compatibility entry point: install/repair native refresh automation.

set -u
CALLER_PATH="${PATH:-}"
PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"
export PATH
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)" || exit 1
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CONTROLLER="$PLUGIN_ROOT/skills/repo-forensics/scripts/refresh_controller.py"
LAUNCHER="$PLUGIN_ROOT/hooks/python-launcher.sh"
PATH="${CALLER_PATH:+$CALLER_PATH:}$PATH" \
    exec "${BASH:-/bin/bash}" "$LAUNCHER" "$CONTROLLER" ensure --json
