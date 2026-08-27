#!/usr/bin/env bash
# Cursor sessionStart wrapper (PRD v3 O1/K1, M2).
#
# Same shape as hooks/run_session_scan.sh: bootstrap or repair the background
# refresh daemon FIRST, then run the session scan. The order matters — the
# scanner-absent branch still has to leave a working updater behind, or an
# install that lost its scanner also silently stops refreshing threat feeds.
#
# Cursor does not reliably dispatch sessionStart in cloud/agent contexts (K1),
# so hooks/cursor/run_pre_scan.sh performs the same daemon bootstrap behind a
# time-window latch. This wrapper is the cheap path when sessionStart IS
# dispatched; the latch keeps the two from doing the work twice.
#
# Never blocks a session from starting. stdout is Cursor's channel, so
# diagnostics go to stderr.

set -u

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}"
if [ -z "$PLUGIN_ROOT" ]; then
    _self_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || _self_dir=""
    if [ -n "$_self_dir" ]; then
        PLUGIN_ROOT="$(cd "$_self_dir/../.." 2>/dev/null && pwd)" || PLUGIN_ROOT=""
    fi
fi

SCRIPT="$PLUGIN_ROOT/skills/repo-forensics/scripts/session_scan.py"
LAUNCHER="$PLUGIN_ROOT/hooks/python-launcher.sh"
ENSURE_REFRESH="$PLUGIN_ROOT/hooks/ensure_refresh_daemon.sh"

warn() { printf '%s\n' "$*" >&2; }

# Bootstrap/repair the background updater before checking freshness. Silent,
# detached, and never blocks sessionStart.
if [ -f "$ENSURE_REFRESH" ]; then
    "${BASH:-/bin/bash}" "$ENSURE_REFRESH" >/dev/null 2>&1 || true
fi

# Mark the session latch so the beforeShellExecution wrapper does not repeat
# the bootstrap it just performed (K1).
_latch_dir="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/repo-forensics"
mkdir -p "$_latch_dir" 2>/dev/null && : > "$_latch_dir/cursor-session.latch" 2>/dev/null || true

if [ ! -f "$SCRIPT" ]; then
    warn "[repo-forensics] WARNING: session_scan.py not found at: $SCRIPT"
    warn "[repo-forensics] Session security scan disabled. Update or reinstall repo-forensics."
    # sessionStart answers with additional_context, never a permission (R4).
    # Nothing to add to the agent's context here, so: an empty object.
    printf '{}\n'
    exit 0
fi

# Bound how often this scan may run (2.14.7). PreToolUse/PostToolUse fire on
# every Bash command and each scan fans out into eight scanners, which stacked
# into 16 concurrent trees and a load average of 175 before this guard existed.
# A MISSING guard file degrades to the old unbounded behaviour on purpose: for a
# security tool, silently not scanning is worse than scanning too often.
GUARD="$PLUGIN_ROOT/hooks/scan_guard.sh"
if [ -f "$GUARD" ]; then
    # shellcheck source=/dev/null
    . "$GUARD"
    if ! rf_scan_guard session 60; then
        # sessionStart answers with additional_context, never a permission (R4).
        printf '{}\n'
        exit 0
    fi
fi

if [ -f "$LAUNCHER" ]; then
    exec "${BASH:-/bin/bash}" "$LAUNCHER" "$SCRIPT" --adapter cursor
fi

exec python3 "$SCRIPT" --adapter cursor
