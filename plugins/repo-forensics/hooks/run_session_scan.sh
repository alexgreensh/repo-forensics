#!/usr/bin/env bash
# Wrapper for SessionStart session_scan.py — same safety pattern as the
# other hook wrappers.
#
# SessionStart hooks should NEVER prevent a session from starting.
# If session_scan.py is missing, we log a warning and exit cleanly.

set -u

SCRIPT="${CLAUDE_PLUGIN_ROOT}/skills/repo-forensics/scripts/session_scan.py"
LAUNCHER="${CLAUDE_PLUGIN_ROOT}/hooks/python-launcher.sh"

if [ ! -f "$SCRIPT" ]; then
    echo "[repo-forensics] WARNING: session_scan.py not found at: $SCRIPT"
    echo "[repo-forensics] Session security scan disabled. Update or reinstall repo-forensics."
    exit 0
fi

if [ -f "$LAUNCHER" ]; then
    exec "${BASH:-/bin/bash}" "$LAUNCHER" "$SCRIPT"
fi

exec python3 "$SCRIPT"
