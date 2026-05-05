#!/usr/bin/env bash
# uninstall_refresh_daemon.sh — Remove the repo-forensics threat DB refresh daemon.
# Safe to run even if not installed.

set -euo pipefail

LABEL="com.alexgreenshpun.repo-forensics-refresh"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"

launchctl bootout "gui/$UID" "$PLIST_PATH" 2>/dev/null || true
rm -f "$PLIST_PATH"

echo "[uninstall] OK: ${LABEL} removed"
echo "[uninstall] (Cache files in ~/.cache/repo-forensics left intact)"
