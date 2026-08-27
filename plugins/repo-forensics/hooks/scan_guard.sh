#!/usr/bin/env bash
# Shared concurrency + debounce guard for the scan hooks. Sourced, not executed.
#
# WHY THIS EXISTS (2026-08-28)
# PreToolUse and PostToolUse both fire on EVERY Bash command, and each scan fans
# out into eight scanner processes. Nothing bounded that. On a real machine an
# agent running commands back to back stacked 16 concurrent scan trees, ~64% CPU
# each, load average 175. The scans outlive the gap between commands, so they
# pile up instead of queueing.
#
# DESIGN NOTES
#   * mkdir is the lock primitive. It is atomic on macOS, Linux and Git Bash;
#     flock exists on none of them reliably (absent on macOS, absent in Git Bash).
#   * No trap-based cleanup. These hooks exec() into python, so the shell is
#     replaced and any EXIT trap never runs. The lock is released by LIVENESS
#     (the PID survives exec, so `kill -0` tracks the real scanner) and by a
#     stale TTL for the crash case.
#   * No `stat`. Git Bash reports /c/ paths that broke a previous comparison
#     (2.14.5), so timestamps are written to files we control instead.
#
# USAGE
#   . "$PLUGIN_ROOT/hooks/scan_guard.sh"
#   rf_scan_guard auto 90  || <emit the platform's bail response>; exit 0
#
# rf_scan_guard <name> <debounce_seconds>
#   returns 0 -> caller should proceed with the scan
#   returns 1 -> caller should skip (another scan is live, or one just ran)
#   debounce_seconds of 0 means concurrency-only: never skip for recency, only
#   when a scan is genuinely in flight. Used by the PreToolUse gate, where
#   skipping on recency would let a command through unscanned.
#
# Escape hatches: REPO_FORENSICS_DISABLE_SCAN_GUARD=1 restores the old
# unbounded behaviour; REPO_FORENSICS_SCAN_DEBOUNCE overrides the window;
# REPO_FORENSICS_SCAN_STALE overrides the crash-recovery TTL (default 600s).

rf_scan_guard() {
    [ "${REPO_FORENSICS_DISABLE_SCAN_GUARD:-0}" = "1" ] && return 0

    _rf_name="${1:-scan}"
    _rf_debounce="${REPO_FORENSICS_SCAN_DEBOUNCE:-${2:-90}}"
    _rf_stale="${REPO_FORENSICS_SCAN_STALE:-600}"

    # Per-user state dir so two accounts on one host never share a lock.
    _rf_uid="$(id -u 2>/dev/null)" || _rf_uid="user"
    _rf_dir="${TMPDIR:-/tmp}/repo-forensics-${_rf_uid}"
    mkdir -p "$_rf_dir" 2>/dev/null || return 0   # cannot guard -> scan anyway
    _rf_lock="${_rf_dir}/${_rf_name}.lock"

    _rf_now="$(date +%s 2>/dev/null)" || return 0  # no clock -> do not block scans

    if mkdir "$_rf_lock" 2>/dev/null; then
        # Uncontended. $$ survives the caller's exec(), so this PID stays valid
        # for the whole life of the scanner it is about to become.
        printf '%s\n' "$$" > "${_rf_lock}/pid" 2>/dev/null
        printf '%s\n' "$_rf_now" > "${_rf_lock}/started" 2>/dev/null
        return 0
    fi

    _rf_holder="$(cat "${_rf_lock}/pid" 2>/dev/null)" || _rf_holder=""
    _rf_started="$(cat "${_rf_lock}/started" 2>/dev/null)" || _rf_started=""
    case "$_rf_started" in ''|*[!0-9]*) _rf_started=0 ;; esac
    _rf_age=$(( _rf_now - _rf_started ))

    # A live holder inside the TTL means a scan is genuinely running. Skip.
    if [ -n "$_rf_holder" ] && kill -0 "$_rf_holder" 2>/dev/null \
       && [ "$_rf_age" -lt "$_rf_stale" ]; then
        return 1
    fi

    # Holder is gone. Recency debounce only applies when the caller asked for one.
    if [ "$_rf_debounce" -gt 0 ] && [ "$_rf_age" -lt "$_rf_debounce" ]; then
        return 1
    fi

    # Stale or finished: take it over. Losing the race is fine — whoever won is
    # scanning, so this caller has nothing useful to add.
    rm -rf "$_rf_lock" 2>/dev/null
    if mkdir "$_rf_lock" 2>/dev/null; then
        printf '%s\n' "$$" > "${_rf_lock}/pid" 2>/dev/null
        printf '%s\n' "$_rf_now" > "${_rf_lock}/started" 2>/dev/null
        return 0
    fi
    return 1
}
