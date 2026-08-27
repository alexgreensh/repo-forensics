#!/usr/bin/env bash
# Cursor afterShellExecution wrapper (PRD v3 R2, M2).
#
# OBSERVE-ONLY. The deep 27-scanner audit runs here, after the command, exactly
# as it does on Claude Code's PostToolUse. It is deliberately NOT on the
# beforeShellExecution wire: only the <10ms IOC gate is admissible in front of
# the agent's inner loop (R2), and a 30s deep scan there would be ripped out by
# the first user who noticed.
#
# Because nothing here can block, a missing scanner degrades to allow+warn with
# no manifest consultation — the tamper policy in hooks/cursor/run_pre_scan.sh
# exists because that wrapper's verdict is load-bearing; this one's is not.
#
# stdout is Cursor's channel, so diagnostics go to stderr and the wrapper emits
# an explicit allow verdict rather than leaving stdout empty.

set -u

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}"
if [ -z "$PLUGIN_ROOT" ]; then
    _self_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || _self_dir=""
    if [ -n "$_self_dir" ]; then
        PLUGIN_ROOT="$(cd "$_self_dir/../.." 2>/dev/null && pwd)" || PLUGIN_ROOT=""
    fi
fi

SCRIPT="$PLUGIN_ROOT/skills/repo-forensics/scripts/auto_scan.py"
LAUNCHER="$PLUGIN_ROOT/hooks/python-launcher.sh"

warn() { printf '%s\n' "$*" >&2; }

if [ ! -f "$SCRIPT" ]; then
    warn "[repo-forensics] WARNING: auto_scan.py not found at: $SCRIPT"
    warn "[repo-forensics] Plugin install may be corrupt, or the skill layout may have changed."
    warn "[repo-forensics] Post-execution audit disabled for this command. Update or reinstall repo-forensics."
    printf '{"permission": "allow", "user_message": "", "agent_message": ""}\n'
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
    if ! rf_scan_guard auto 90; then
        # Guard declined: another scan is live or one just ran. Answer the
        # adapter contract so the command is not left hanging.
        printf '{"permission": "allow", "user_message": "", "agent_message": ""}\n'
        exit 0
    fi
fi

if [ -f "$LAUNCHER" ]; then
    exec "${BASH:-/bin/bash}" "$LAUNCHER" "$SCRIPT" --adapter cursor
fi

exec python3 "$SCRIPT" --adapter cursor
