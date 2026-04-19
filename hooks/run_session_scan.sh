#!/usr/bin/env bash
# Wrapper for SessionStart session_scan.py — same safety pattern as the
# other hook wrappers.
#
# SessionStart hooks should NEVER prevent a session from starting.
# If session_scan.py is missing, we log a warning and exit cleanly.

set -u

SCRIPT="${CLAUDE_PLUGIN_ROOT}/skills/repo-forensics/scripts/session_scan.py"

if [ ! -f "$SCRIPT" ]; then
    echo "[repo-forensics] WARNING: session_scan.py not found at: $SCRIPT" >&2
    echo "[repo-forensics] Session security scan disabled. Run: /plugin update repo-forensics" >&2
    exit 0
fi

exec python3 "$SCRIPT"
