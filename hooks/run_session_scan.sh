#!/usr/bin/env bash
# Wrapper for SessionStart session_scan.py — same safety pattern as the
# other hook wrappers.
#
# SessionStart hooks should NEVER prevent a session from starting.
# If session_scan.py is missing, we log a warning and exit cleanly.

set -u

SCRIPT="${CLAUDE_PLUGIN_ROOT}/skills/repo-forensics/scripts/session_scan.py"
LAUNCHER="${CLAUDE_PLUGIN_ROOT}/hooks/python-launcher.sh"
ENSURE_REFRESH="${CLAUDE_PLUGIN_ROOT}/hooks/ensure_refresh_daemon.sh"

# Bootstrap or repair the background updater before checking freshness. This
# stays silent and never blocks SessionStart if the platform scheduler fails.
if [ -f "$ENSURE_REFRESH" ]; then
    "${BASH:-/bin/bash}" "$ENSURE_REFRESH" || true
fi

if [ ! -f "$SCRIPT" ]; then
    echo "[repo-forensics] WARNING: session_scan.py not found at: $SCRIPT"
    echo "[repo-forensics] Session security scan disabled. Update or reinstall repo-forensics."
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
    if ! rf_scan_guard session 60; then
        exit 0
    fi
fi

if [ -f "$LAUNCHER" ]; then
    exec "${BASH:-/bin/bash}" "$LAUNCHER" "$SCRIPT"
fi

exec python3 "$SCRIPT"
