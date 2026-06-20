#!/usr/bin/env bash
# SessionStart adapter for the cross-platform refresh controller.

set -u
CALLER_PATH="${PATH:-}"
PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"
export PATH

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)" || exit 0
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CONTROLLER="$PLUGIN_ROOT/skills/repo-forensics/scripts/refresh_controller.py"
LAUNCHER="$PLUGIN_ROOT/hooks/python-launcher.sh"

[ -f "$CONTROLLER" ] || exit 0
[ -f "$LAUNCHER" ] || exit 0

# Preserve caller PATH only for the interpreter launcher: it independently
# allowlists every Python location, including standard Windows installs. The
# wrapper's own utilities above resolve exclusively through trusted paths.
# Repair is detached so a slow/broken scheduler API cannot block SessionStart.
PATH="${CALLER_PATH:+$CALLER_PATH:}$PATH" \
    "${BASH:-/bin/bash}" "$LAUNCHER" "$CONTROLLER" ensure \
    </dev/null >/dev/null 2>&1 &
exit 0
