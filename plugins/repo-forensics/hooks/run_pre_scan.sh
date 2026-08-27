#!/usr/bin/env bash
# Wrapper for PreToolUse pre-scan that fails gracefully if the target script
# is missing — same pattern as run_auto_scan.sh.
#
# IMPORTANT: This is a PreToolUse hook. If pre_scan.py is missing, we MUST
# exit 0 (approve) to avoid silently blocking every Bash command. A broken
# security hook that blocks all work is worse than a temporarily absent one.

set -u

SCRIPT="${CLAUDE_PLUGIN_ROOT}/skills/repo-forensics/scripts/pre_scan.py"
LAUNCHER="${CLAUDE_PLUGIN_ROOT}/hooks/python-launcher.sh"

if [ ! -f "$SCRIPT" ]; then
    echo "[repo-forensics] WARNING: pre_scan.py not found at: $SCRIPT"
    echo "[repo-forensics] Plugin install may be corrupt, or the skill layout may have changed."
    echo "[repo-forensics] Pre-scan hook disabled for this command. Update or reinstall repo-forensics."
    # exit 0 = approve. NEVER exit 2 when the script is missing — that would
    # block every Bash command.
    exit 0
fi

# Bound how often this scan may run (2.14.7). PreToolUse/PostToolUse fire on
# every Bash command and each scan fans out into eight scanners, which stacked
# into 16 concurrent trees and a load average of 175 before this guard existed.
# A MISSING guard file degrades to the old unbounded behaviour on purpose: for a
# security tool, silently not scanning is worse than scanning too often.
GUARD="${CLAUDE_PLUGIN_ROOT}/hooks/scan_guard.sh"
if [ -f "$GUARD" ]; then
    # shellcheck source=/dev/null
    . "$GUARD"
    if ! rf_scan_guard pre 0; then
        exit 0
    fi
fi

if [ -f "$LAUNCHER" ]; then
    exec "${BASH:-/bin/bash}" "$LAUNCHER" "$SCRIPT"
fi

exec python3 "$SCRIPT"
