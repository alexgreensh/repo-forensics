#!/bin/bash

# Repo Forensics Suite Runner v2
# Created by Alex Greenshpun
# Usage: ./run_forensics.sh <repo_path> [--skill-scan] [--format text|json|summary]

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <repo_path> [options]"
    echo ""
    echo "Modes:"
    echo "  (default)              Full audit - all 18 scanners"
    echo "  --skill-scan           Focused on AI skill threats (9 scanners, faster)"
    echo "  --inventory            Enumerate installed AI-agent stacks (zero-LLM, JSON output)"
    echo ""
    echo "Options:"
    echo "  --format text          Human-readable with severity colors (default)"
    echo "  --format json          Machine-readable JSON"
    echo "  --format summary       Counts only (for CI/CD)"
    echo "  --update-iocs          Pull latest IOC database before scanning"
    echo "  --watch                Enable file integrity baseline tracking"
    echo "  --package-list=FILE    Load user-supplied IOC list (absolute path, see docs)"
    echo "  --include-shadows      Include shadow surfaces in inventory (backups, caches)"
    exit 1
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
    exec python3 "$FORENSIFY_DIR/build_inventory.py" "${INVENTORY_ARGS[@]}"
fi

REPO_PATH=$(realpath "$1")
shift

# Parse remaining args
SKILL_SCAN=false
FORMAT="text"
UPDATE_IOCS=false
WATCH_MODE=false
VERIFY_INSTALL=false
PACKAGE_LIST_FILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skill-scan) SKILL_SCAN=true; shift ;;
        --format) [[ $# -ge 2 ]] || { echo "Error: --format requires a value"; exit 1; }; FORMAT="$2"; shift 2 ;;
        --update-iocs) UPDATE_IOCS=true; shift ;;
        --watch) WATCH_MODE=true; shift ;;
        --verify-install) VERIFY_INSTALL=true; shift ;;
        --package-list=*) PACKAGE_LIST_FILE="${1#*=}"; shift ;;
        --package-list)
            [[ $# -ge 2 ]] || { echo "Error: --package-list requires a FILE argument"; exit 1; }
            PACKAGE_LIST_FILE="$2"; shift 2 ;;
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

# Handle --verify-install (standalone, exits after)
if $VERIFY_INSTALL; then
    python3 "$SKILL_DIR/verify_install.py" --verify
    exit $?
fi

# Handle --update-iocs before scanning
if $UPDATE_IOCS; then
    echo "[*] Updating IOC database..."
    python3 "$SKILL_DIR/ioc_manager.py" --update
fi
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

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

# Portable timeout (macOS lacks GNU timeout)
TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
fi

run_scanner() {
    local name="$1"
    local script="$2"
    local extra_args="${3:-}"
    local output_file="$TMPDIR/$name.out"
    local exit_file="$TMPDIR/$name.exit"
    local error_file="$TMPDIR/$name.err"

    # Always run scanners in JSON format internally so aggregate_json.py can
    # run the correlation engine across all of them. In text mode we convert
    # JSON -> text at the aggregation step instead of letting each scanner
    # emit text directly. This is what fixes security review A5 (correlation
    # rules 1-19 were dead code in the primary workflow prior to 2026-04-05).
    local internal_format="json"

    # Build the scanner-specific arg array. Using a bash array avoids the
    # word-split/quoting bug in the old ${extra_args:+"$extra_args"} pattern.
    local -a scanner_args=()
    [ -n "$extra_args" ] && scanner_args+=($extra_args)

    # Wire dependency-scanner-specific flags
    if [ "$name" = "dependencies" ]; then
        [ -n "$PACKAGE_LIST_FILE" ] && scanner_args+=("--package-list=$PACKAGE_LIST_FILE")
    fi

    # `${arr[@]+"${arr[@]}"}` is the canonical `set -u`-safe expansion for
    # bash arrays that may be empty. Without this, an empty scanner_args
    # triggers "unbound variable" under `set -euo pipefail`.
    if [ -n "$TIMEOUT_CMD" ]; then
        $TIMEOUT_CMD "$SCANNER_TIMEOUT" python3 "$SKILL_DIR/$script" "$REPO_PATH" --format "$internal_format" ${scanner_args[@]+"${scanner_args[@]}"} > "$output_file" 2>> "$error_file"
    else
        python3 "$SKILL_DIR/$script" "$REPO_PATH" --format "$internal_format" ${scanner_args[@]+"${scanner_args[@]}"} > "$output_file" 2>> "$error_file"
    fi
    echo $? > "$exit_file"
}

if $SKILL_SCAN; then
    # Focused mode: 9 scanners most relevant to vetting skills
    if [ "$FORMAT" != "json" ]; then
        echo ""
        echo "[*] Running focused skill scan (9 scanners)..."
    fi

    run_scanner "skill_threats" "scan_skill_threats.py" &
    run_scanner "secrets" "scan_secrets.py" &
    run_scanner "dataflow" "scan_dataflow.py" &
    run_scanner "sast" "scan_sast.py" &
    run_scanner "lifecycle" "scan_lifecycle.py" &
    run_scanner "mcp_security" "scan_mcp_security.py" &
    run_scanner "runtime_dynamism" "scan_runtime_dynamism.py" &
    run_scanner "manifest_drift" "scan_manifest_drift.py" &
    run_scanner "openclaw_skills" "scan_openclaw_skills.py" &
    wait

else
    # Full audit: all scanners in parallel
    if [ "$FORMAT" != "json" ]; then
        echo ""
        echo "[*] Running all 18 scanners in parallel..."
    fi
    run_scanner "entropy" "scan_entropy.py" &
    run_scanner "binary" "scan_binary.py" &
    run_scanner "git_forensics" "scan_git_forensics.py" &
    run_scanner "dependencies" "scan_dependencies.py" &
    run_scanner "secrets" "scan_secrets.py" &
    run_scanner "sast" "scan_sast.py" &
    run_scanner "infra" "scan_infra.py" &
    run_scanner "lifecycle" "scan_lifecycle.py" &
    run_scanner "skill_threats" "scan_skill_threats.py" &
    run_scanner "dataflow" "scan_dataflow.py" &
    run_scanner "mcp_security" "scan_mcp_security.py" &
    run_scanner "ast_analysis" "scan_ast.py" &
    run_scanner "runtime_dynamism" "scan_runtime_dynamism.py" &
    run_scanner "manifest_drift" "scan_manifest_drift.py" &
    run_scanner "openclaw_skills" "scan_openclaw_skills.py" &
    if $WATCH_MODE; then
        run_scanner "integrity" "scan_integrity.py" "--watch" &
    else
        run_scanner "integrity" "scan_integrity.py" &
    fi
    run_scanner "dast" "scan_dast.py" &
    run_scanner "post_incident" "scan_post_incident.py" &
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
    if ! python3 "$SKILL_DIR/aggregate_json.py" "$TMPDIR" "$REPO_PATH" "$SKILL_SCAN" "$EXIT_CODE_FILE"; then
        :
    fi
else
    # text and summary modes both use text output from the aggregator
    if ! python3 "$SKILL_DIR/aggregate_json.py" --text "$TMPDIR" "$REPO_PATH" "$SKILL_SCAN" "$EXIT_CODE_FILE"; then
        :
    fi
fi

_rc=$(cat "$EXIT_CODE_FILE" 2>/dev/null || echo "99")
case "$_rc" in
    0|1|2) exit "$_rc" ;;
    *) exit 99 ;;
esac
