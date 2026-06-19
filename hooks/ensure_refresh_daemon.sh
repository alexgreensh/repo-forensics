#!/usr/bin/env bash
# Ensure threat intelligence refreshes automatically without slowing SessionStart.
# macOS uses launchd; other platforms kick a detached refresh at most once/day.

set -u

# GUI-launched hooks may inherit a stripped PATH. Preserve explicit test/user
# entries while guaranteeing the standard system utilities remain reachable.
PATH="${PATH:+$PATH:}/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

if [ "${REPO_FORENSICS_DISABLE_REFRESH:-0}" = "1" ]; then
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
REFRESH_SCRIPT="$PLUGIN_ROOT/skills/repo-forensics/scripts/refresh_threat_dbs.py"
LAUNCHER="$PLUGIN_ROOT/hooks/python-launcher.sh"
CACHE_DIR="$HOME/.cache/repo-forensics"
MARKER="$CACHE_DIR/.last-refresh"
INSTALL_LOG="$CACHE_DIR/daemon-install.log"

[ -f "$REFRESH_SCRIPT" ] || exit 0
[ -f "$LAUNCHER" ] || exit 0

marker_is_stale() {
    [ -f "$MARKER" ] || return 0
    local now mtime
    now="$(date +%s 2>/dev/null)" || return 0
    if mtime="$(stat -f '%m' "$MARKER" 2>/dev/null)"; then
        :
    elif mtime="$(stat -c '%Y' "$MARKER" 2>/dev/null)"; then
        :
    else
        return 0
    fi
    [ $((now - mtime)) -ge 86400 ]
}

mkdir -p "$CACHE_DIR" 2>/dev/null || exit 0
chmod 0700 "$CACHE_DIR" 2>/dev/null || true

if [ "$(uname 2>/dev/null)" = "Darwin" ]; then
    LABEL="com.alexgreenshpun.repo-forensics-refresh"
    PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
    SERVICE="gui/$UID/$LABEL"
    INSTALLER="$PLUGIN_ROOT/hooks/install_refresh_daemon.sh"

    if [ ! -f "$PLIST" ] \
            || ! grep -Fq "$REFRESH_SCRIPT" "$PLIST" 2>/dev/null \
            || ! launchctl print "$SERVICE" >/dev/null 2>&1; then
        if [ -f "$INSTALLER" ]; then
            bash "$INSTALLER" >>"$INSTALL_LOG" 2>&1 || true
        fi
        exit 0
    fi

    if marker_is_stale; then
        launchctl kickstart -k "$SERVICE" >/dev/null 2>&1 || true
    fi
    exit 0
fi

if marker_is_stale; then
    if command -v nohup >/dev/null 2>&1; then
        nohup bash "$LAUNCHER" "$REFRESH_SCRIPT" >/dev/null 2>&1 &
    else
        bash "$LAUNCHER" "$REFRESH_SCRIPT" >/dev/null 2>&1 &
    fi
fi

exit 0
