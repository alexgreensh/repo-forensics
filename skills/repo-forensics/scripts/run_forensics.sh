#!/bin/bash

# Repo Forensics Suite Runner v2
# Created by Alex Greenshpun
# Usage: ./run_forensics.sh <repo_path> [--skill-scan] [--format text|json|summary]

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <repo_path> [options]"
    echo ""
    echo "Modes:"
    echo "  (default)              Full audit - all 25 scanners"
    echo "  --skill-scan           Focused on AI skill threats (15 scanners, faster)"
    echo "  --inventory            Enumerate installed AI-agent stacks (zero-LLM, JSON output)"
    echo ""
    echo "Options:"
    echo "  --format text          Human-readable with severity colors (default)"
    echo "  --format json          Machine-readable JSON"
    echo "  --format summary       Counts only (for CI/CD)"
    echo "  --update-iocs          Pull latest IOC database before scanning"
    echo "  --update-vulns         Refresh CISA KEV catalog before scanning (CVE enrichment)"
    echo "  --no-vulns             Skip OSV + KEV vulnerability enrichment"
    echo "  --offline              No network fetches (use cached KEV/OSV data only)"
    echo "  --watch                Enable file integrity baseline tracking"
    echo "  --package-list=FILE    Load user-supplied IOC list (absolute path, see docs)"
    echo "  --include-shadows      Include shadow surfaces in inventory (backups, caches)"
    echo "  --max-jobs=N           Max parallel scanners (default: clamp(ncpu, 4, 8), env: REPO_FORENSICS_MAX_JOBS)"
    exit 1
fi

# Resolve one working Python 3 interpreter for the whole run. Executing each
# candidate is intentional: Windows can expose zero-byte/App Execution Alias
# stubs named python or python3 that exist on PATH but are not interpreters.
#
# The probe requires the candidate to emit a unique sentinel ("PY3OK") via
# actual Python 3.8+ code. Exit status alone is insufficient: a zero-byte stub
# is treated by bash as an empty shell script (exit 0), and a non-Python binary
# can exit 0 without ever evaluating the -c argument. Only a real Python 3.8+
# interpreter can print the sentinel, so impostors are rejected.
#
# A 5-second timeout prevents a hanging candidate from blocking the CLI
# indefinitely. The timeout wrapper is selected in priority order:
#   1. timeout   (Linux, coreutils)
#   2. gtimeout  (macOS with Homebrew coreutils)
#   3. a Perl process-group supervisor (macOS ships /usr/bin/perl; the full Git
#      for Windows installer bundles perl, though minimal distributions such as
#      MinGit deliberately omit it)
# Only if NONE of these are available does the probe run unbounded — a residual
# risk on minimal environments (e.g. MinGit, which ships neither perl nor
# coreutils), where a hanging Store-alias stub could block the probe. Adding a
# bash-only timeout tier is tracked as follow-up.
#
# This resolver intentionally differs from hooks/python-launcher.sh, which runs
# in a stripped/untrusted GUI hook PATH (Codex, GUI-launched agent apps) and so
# uses a safe-prefix allowlist, size checks, WindowsApps timeouts, and
# direct-path fallbacks. This resolver instead relies on a bounded sentinel
# probe. Note run_forensics.sh is ALSO reachable from that hook PATH — session
# hook deep scans (session_scan.py) spawn it via subprocess without a sanitized
# env, so the probe inherits the caller's PATH rather than a guaranteed-trusted
# one; the bounded sentinel + timeout is the safety boundary here. Extending the
# launcher's allowlist to this path is tracked as follow-up. Do not collapse the
# two without accounting for that environment.
_rf_bounded() {
    # Run "$@" with a 5-second alarm. Uses timeout/gtimeout/perl in priority order.
    # Returns the candidate's exit status (124 if timed out).
    if [ -n "$_RF_TIMEOUT_CMD" ]; then
        "$_RF_TIMEOUT_CMD" 5 "$@"
    elif [ -n "$_RF_USE_PERL" ]; then
        # Perl supervisor: fork child into its own process group, alarm in
        # parent, TERM then KILL the whole process group on timeout. This
        # kills the candidate AND any children it spawned (e.g. a shell stub
        # that runs sleep). Plain alarm+exec only kills the exec'd process,
        # leaving orphaned children holding the capture pipe open.
        perl -e '
use POSIX qw(setpgid);
my $s=shift; my $p=fork;
if(!defined $p){die"fork:$!"}
if($p==0){setpgid(0,0)||die"setpgid:$!";exec @ARGV or die"exec:$!"}
$SIG{ALRM}=sub{kill 15,-$p;select undef,undef,undef,0.5;kill 9,-$p;exit 124};
alarm $s;
waitpid($p,0);
alarm 0;
exit($?&127?128+($?&127):$?>>8)
' 5 "$@"
    else
        "$@"  # residual unbounded fallback (no timeout utility available)
    fi
}
_RF_TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
    _RF_TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    _RF_TIMEOUT_CMD="gtimeout"
fi
_RF_USE_PERL=""
if [ -z "$_RF_TIMEOUT_CMD" ] && command -v perl >/dev/null 2>&1; then
    _RF_USE_PERL=1
fi
_PY_PROBE='import sys; print("PY3OK") if sys.version_info >= (3, 8) else print("NO")'
_py_check() {
    # $1 = candidate command (single word like python3)
    local out
    out=$(_rf_bounded "$1" -c "$_PY_PROBE" 2>/dev/null) || return 1
    [ "$out" = "PY3OK" ]
}
PYTHON=()
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && _py_check "$candidate"; then
        PYTHON=("$candidate")
        break
    fi
done
if [ ${#PYTHON[@]} -eq 0 ] && command -v py >/dev/null 2>&1; then
    if _rf_bounded py -3 -c "$_PY_PROBE" 2>/dev/null | grep -q '^PY3OK$'; then
        PYTHON=(py -3)
    fi
fi
if [ ${#PYTHON[@]} -eq 0 ]; then
    echo "[repo-forensics] ERROR: Python 3.8+ not found (tried python3, python, py -3)" >&2
    exit 127
fi

# Check for --inventory before consuming positional arg
if [ "$1" = "--inventory" ]; then
    shift
    INVENTORY_ARGS=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --target) INVENTORY_ARGS+=("--target" "$2"); shift 2 ;;
            --include-shadows) INVENTORY_ARGS+=("--include-shadows"); shift ;;
            --list-ecosystems) INVENTORY_ARGS+=("--list-ecosystems"); shift ;;
            *) echo "Unknown inventory arg: $1"; exit 1 ;;
        esac
    done
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    FORENSIFY_DIR="$(cd "$SCRIPT_DIR/../../forensify/scripts" 2>/dev/null && pwd)" || {
        echo "Error: forensify scripts not found at $SCRIPT_DIR/../../forensify/scripts" >&2
        exit 1
    }
    exec "${PYTHON[@]}" "$FORENSIFY_DIR/build_inventory.py" "${INVENTORY_ARGS[@]}"
fi

REPO_PATH=$(realpath "$1")
shift

# Parse remaining args
SKILL_SCAN=false
FORMAT="text"
UPDATE_IOCS=false
UPDATE_VULNS=false
NO_VULNS=false
OFFLINE=false
WATCH_MODE=false
VERIFY_INSTALL=false
PACKAGE_LIST_FILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skill-scan) SKILL_SCAN=true; shift ;;
        --format) [[ $# -ge 2 ]] || { echo "Error: --format requires a value"; exit 1; }; FORMAT="$2"; shift 2 ;;
        --update-iocs) UPDATE_IOCS=true; shift ;;
        --update-vulns) UPDATE_VULNS=true; shift ;;
        --no-vulns) NO_VULNS=true; shift ;;
        --offline) OFFLINE=true; shift ;;
        --watch) WATCH_MODE=true; shift ;;
        --verify-install) VERIFY_INSTALL=true; shift ;;
        --package-list=*) PACKAGE_LIST_FILE="${1#*=}"; shift ;;
        --package-list)
            [[ $# -ge 2 ]] || { echo "Error: --package-list requires a FILE argument"; exit 1; }
            PACKAGE_LIST_FILE="$2"; shift 2 ;;
        --max-jobs=*) MAX_JOBS="${1#*=}"; shift ;;
        --max-jobs)
            [[ $# -ge 2 ]] || { echo "Error: --max-jobs requires a number"; exit 1; }
            MAX_JOBS="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Validate --package-list is an absolute path BEFORE passing to Python
if [ -n "$PACKAGE_LIST_FILE" ]; then
    case "$PACKAGE_LIST_FILE" in
        /*) : ;;  # absolute, OK
        *) echo "Error: --package-list must be an absolute path, got: $PACKAGE_LIST_FILE"; exit 1 ;;
    esac
    if [ ! -f "$PACKAGE_LIST_FILE" ]; then
        echo "Error: --package-list file not found: $PACKAGE_LIST_FILE"; exit 1
    fi
fi

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"

# Kill orphaned scanners from previous runs (stuck beyond SCANNER_TIMEOUT)
# shellcheck disable=SC2009  # pgrep can't provide etime; we need ps output for age filtering
_stale_pids=$(ps ax -o pid=,etime=,command= 2>/dev/null | grep '[r]epo-forensics/.*scan_.*\.py' | awk '{
    split($2, t, "[-:]"); n = length(t)
    secs = t[n]+0 + (t[n-1]+0)*60
    if (n >= 3) secs += (t[n-2]+0)*3600
    if (n >= 4) secs += (t[n-3]+0)*86400
    if (secs > 150) print $1
}' || true)
if [ -n "$_stale_pids" ]; then
    echo "[repo-forensics] Cleaning up stale scanner processes from a previous run..." >&2
    echo "$_stale_pids" | xargs kill 2>/dev/null || true
fi

# Handle --verify-install (standalone, exits after)
if $VERIFY_INSTALL; then
    "${PYTHON[@]}" "$SKILL_DIR/verify_install.py" --verify
    exit $?
fi

# Handle --update-iocs before scanning
if $UPDATE_IOCS; then
    echo "[*] Updating IOC database..."
    "${PYTHON[@]}" "$SKILL_DIR/ioc_manager.py" --update || echo "[!] IOC update failed, scanning with cached data" >&2
fi

# Handle --update-vulns (CISA KEV) before scanning
if $UPDATE_VULNS && ! $OFFLINE; then
    echo "[*] Updating CISA KEV catalog..."
    "${PYTHON[@]}" "$SKILL_DIR/vuln_feed.py" --update || true
fi
TMPDIR=$(mktemp -d)
# shellcheck disable=SC2329  # invoked indirectly via trap
cleanup() { local _saved=$?; trap - EXIT INT TERM; set +e; jobs -p | xargs kill 2>/dev/null; wait 2>/dev/null; exec 3>&- 2>/dev/null; rm -rf "$TMPDIR"; exit "$_saved"; }
trap cleanup EXIT INT TERM

if [ "$FORMAT" != "json" ]; then
    echo "=========================================="
    echo "  REPO FORENSICS v2"
    echo "  Target: $REPO_PATH"
    echo "  Mode: $(if $SKILL_SCAN; then echo 'Skill Scan (focused)'; else echo 'Full Audit'; fi)"
    echo "  Format: $FORMAT"
    echo "  Date: $(date)"
    echo "=========================================="
fi

SCANNER_TIMEOUT=120

# Concurrency limiter: cap parallel scanners to avoid CPU storms
# Priority: --max-jobs flag > REPO_FORENSICS_MAX_JOBS env > auto-detect
MAX_JOBS=${MAX_JOBS:-${REPO_FORENSICS_MAX_JOBS:-0}}
if [ -n "$MAX_JOBS" ] && ! [[ "$MAX_JOBS" =~ ^[0-9]+$ ]]; then
    echo "Error: --max-jobs must be a positive integer, got: $MAX_JOBS" >&2
    exit 1
fi
if [ "$MAX_JOBS" -le 0 ] 2>/dev/null; then
    MAX_JOBS=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)
    [ "$MAX_JOBS" -gt 8 ] && MAX_JOBS=8
    [ "$MAX_JOBS" -lt 4 ] && MAX_JOBS=4
fi
[ "$MAX_JOBS" -gt 20 ] && MAX_JOBS=20

# FIFO semaphore: N tokens pre-fill the pipe. throttled_run blocks on
# read until a token is available, returns it after the job completes.
SEMAPHORE_FIFO="$TMPDIR/.job_semaphore"
mkfifo -m 600 "$SEMAPHORE_FIFO"
exec 3<>"$SEMAPHORE_FIFO"
for ((i=0; i<MAX_JOBS; i++)); do echo >&3; done

throttled_run() {
    read -r -u 3
    trap 'echo >&3' RETURN
    local _rc=0
    "$@" || _rc=$?
    return $_rc
}

# Portable timeout (macOS lacks GNU timeout)
TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
fi

# TTY autodetect for per-scanner progress lines
PROGRESS=false
if [ -t 2 ] && [ "$FORMAT" != "json" ]; then
    PROGRESS=true
fi

# Staleness detection for Path B (git-clone) users
STALENESS_DAYS=30
if [ -d "$SKILL_DIR/.git" ] || [ -f "$SKILL_DIR/../../.git" ] || [ -f "$SKILL_DIR/../../../.git" ]; then
    LAST_COMMIT_DATE=$(git -C "$SKILL_DIR" log -1 --format=%ct 2>/dev/null || echo "0")
    NOW=$(date +%s)
    if [ "$LAST_COMMIT_DATE" -gt 0 ]; then
        AGE_DAYS=$(( (NOW - LAST_COMMIT_DATE) / 86400 ))
        if [ "$AGE_DAYS" -ge "$STALENESS_DAYS" ]; then
            echo "[repo-forensics] Install is ${AGE_DAYS} days old. Run 'git pull' for latest IOCs and detection rules." >&2
        fi
    fi
fi

# shellcheck disable=SC2329  # invoked indirectly via throttled_run
run_scanner() {
    local name="$1"
    local script="$2"
    local extra_args="${3:-}"
    local output_file="$TMPDIR/$name.out"
    local exit_file="$TMPDIR/$name.exit"
    local error_file="$TMPDIR/$name.err"
    local start_time
    start_time=$(date +%s)

    local internal_format="json"

    local -a scanner_args=()
    [ -n "$extra_args" ] && scanner_args+=("$extra_args")

    if [ "$name" = "dependencies" ]; then
        [ -n "$PACKAGE_LIST_FILE" ] && scanner_args+=("--package-list=$PACKAGE_LIST_FILE")
        $NO_VULNS && scanner_args+=("--no-vulns")
        $OFFLINE && scanner_args+=("--offline")
    fi

    if [ -n "$TIMEOUT_CMD" ]; then
        $TIMEOUT_CMD "$SCANNER_TIMEOUT" "${PYTHON[@]}" "$SKILL_DIR/$script" "$REPO_PATH" --format "$internal_format" ${scanner_args[@]+"${scanner_args[@]}"} 3>&- > "$output_file" 2>> "$error_file"
    else
        "${PYTHON[@]}" "$SKILL_DIR/$script" "$REPO_PATH" --format "$internal_format" ${scanner_args[@]+"${scanner_args[@]}"} 3>&- > "$output_file" 2>> "$error_file"
    fi
    local exit_code=$?
    echo "$exit_code" > "$exit_file"

    # Per-scanner progress line (TTY only, silent in CI/piped output)
    if $PROGRESS; then
        local elapsed=$(( $(date +%s) - start_time ))
        local findings=0
        if [ -f "$output_file" ] && [ -s "$output_file" ]; then
            findings=$("${PYTHON[@]}" -c "
import json, sys
try:
    d = json.load(open('$output_file'))
    print(len(d.get('findings', d.get('results', []))))
except: print(0)
" 2>/dev/null || echo 0)
        fi
        if [ "$exit_code" -eq 0 ]; then
            echo "[OK] $name: $findings findings (${elapsed}s)" >&2
        else
            echo "[!!] $name: exit $exit_code (${elapsed}s)" >&2
        fi
    fi
}

if $SKILL_SCAN; then
    # Focused mode: 10 scanners most relevant to vetting skills
    if [ "$FORMAT" != "json" ]; then
        echo ""
        echo "[*] Running focused skill scan (15 scanners)..."
    fi

    throttled_run run_scanner "skill_threats" "scan_skill_threats.py" &
    throttled_run run_scanner "secrets" "scan_secrets.py" &
    throttled_run run_scanner "dataflow" "scan_dataflow.py" &
    throttled_run run_scanner "sast" "scan_sast.py" &
    throttled_run run_scanner "lifecycle" "scan_lifecycle.py" &
    throttled_run run_scanner "mcp_security" "scan_mcp_security.py" &
    throttled_run run_scanner "runtime_dynamism" "scan_runtime_dynamism.py" &
    throttled_run run_scanner "manifest_drift" "scan_manifest_drift.py" &
    throttled_run run_scanner "agent_skills" "scan_agent_skills.py" &
    throttled_run run_scanner "devcontainer" "scan_devcontainer.py" &
    throttled_run run_scanner "oversize" "scan_oversize.py" &
    throttled_run run_scanner "bytecode" "scan_bytecode.py" &
    throttled_run run_scanner "archive" "scan_archive.py" &
    throttled_run run_scanner "splitstream" "scan_splitstream.py" &
    throttled_run run_scanner "provenance" "scan_provenance.py" &
    wait

else
    # Full audit: all scanners in parallel
    if [ "$FORMAT" != "json" ]; then
        echo ""
        echo "[*] Running all 25 scanners in parallel..."
    fi
    throttled_run run_scanner "entropy" "scan_entropy.py" &
    throttled_run run_scanner "binary" "scan_binary.py" &
    throttled_run run_scanner "git_forensics" "scan_git_forensics.py" &
    throttled_run run_scanner "dependencies" "scan_dependencies.py" &
    throttled_run run_scanner "secrets" "scan_secrets.py" &
    throttled_run run_scanner "sast" "scan_sast.py" &
    throttled_run run_scanner "infra" "scan_infra.py" &
    throttled_run run_scanner "lifecycle" "scan_lifecycle.py" &
    throttled_run run_scanner "skill_threats" "scan_skill_threats.py" &
    throttled_run run_scanner "dataflow" "scan_dataflow.py" &
    throttled_run run_scanner "mcp_security" "scan_mcp_security.py" &
    throttled_run run_scanner "ast_analysis" "scan_ast.py" &
    throttled_run run_scanner "runtime_dynamism" "scan_runtime_dynamism.py" &
    throttled_run run_scanner "manifest_drift" "scan_manifest_drift.py" &
    throttled_run run_scanner "agent_skills" "scan_agent_skills.py" &
    if $WATCH_MODE; then
        throttled_run run_scanner "integrity" "scan_integrity.py" "--watch" &
    else
        throttled_run run_scanner "integrity" "scan_integrity.py" &
    fi
    throttled_run run_scanner "dast" "scan_dast.py" &
    throttled_run run_scanner "post_incident" "scan_post_incident.py" &
    throttled_run run_scanner "devcontainer" "scan_devcontainer.py" &
    throttled_run run_scanner "entrypoint" "scan_entrypoint.py" &
    throttled_run run_scanner "oversize" "scan_oversize.py" &
    throttled_run run_scanner "bytecode" "scan_bytecode.py" &
    throttled_run run_scanner "archive" "scan_archive.py" &
    throttled_run run_scanner "splitstream" "scan_splitstream.py" &
    throttled_run run_scanner "provenance" "scan_provenance.py" &
    wait
fi

# Scanners ran in JSON format internally so the correlation engine can see
# every scanner's findings together (security review A5 fix, 2026-04-05).
# aggregate_json.py runs forensics_core.correlate() on the merged findings
# and emits either JSON (for --format json) or text (for --format text /
# --format summary) output. This is the single aggregation path.

EXIT_CODE_FILE="$TMPDIR/aggregate.exit"
echo "99" > "$EXIT_CODE_FILE"

if [ "$FORMAT" = "json" ]; then
    if ! "${PYTHON[@]}" "$SKILL_DIR/aggregate_json.py" "$TMPDIR" "$REPO_PATH" "$SKILL_SCAN" "$EXIT_CODE_FILE"; then
        :
    fi
else
    # text and summary modes both use text output from the aggregator
    if ! "${PYTHON[@]}" "$SKILL_DIR/aggregate_json.py" --text "$TMPDIR" "$REPO_PATH" "$SKILL_SCAN" "$EXIT_CODE_FILE"; then
        :
    fi
fi

_rc=$(cat "$EXIT_CODE_FILE" 2>/dev/null || echo "99")
case "$_rc" in
    0|1|2) exit "$_rc" ;;
    *) exit 99 ;;
esac
