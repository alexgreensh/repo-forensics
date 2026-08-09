#!/usr/bin/env bash
# Wrapper for PreToolUse pre-scan that fails gracefully if the target script
# is missing — same pattern as run_auto_scan.sh.
#
# IMPORTANT: This is a PreToolUse hook. If pre_scan.py is missing, we MUST
# exit 0 (approve) to avoid silently blocking every Bash command. A broken
# security hook that blocks all work is worse than a temporarily absent one.

set -u

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-${KIMI_PLUGIN_ROOT:-}}"
SCRIPT="$PLUGIN_ROOT/skills/repo-forensics/scripts/pre_scan.py"
LAUNCHER="$PLUGIN_ROOT/hooks/python-launcher.sh"

if [ ! -f "$SCRIPT" ]; then
    echo "[repo-forensics] WARNING: pre_scan.py not found at: $SCRIPT"
    echo "[repo-forensics] Plugin install may be corrupt, or the skill layout may have changed."
    echo "[repo-forensics] Pre-scan hook disabled for this command. Update or reinstall repo-forensics."
    # exit 0 = approve. NEVER exit 2 when the script is missing — that would
    # block every Bash command.
    exit 0
fi

if [ -f "$LAUNCHER" ]; then
    exec "${BASH:-$(command -v bash || echo /bin/bash)}" "$LAUNCHER" "$SCRIPT"
fi

exec python3 "$SCRIPT"
