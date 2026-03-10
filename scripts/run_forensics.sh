#!/bin/bash

# Repo Forensics Suite Runner v3
# Created by Alex Greenshpun
# Usage: ./run_forensics.sh <repo_path> [--skill-scan] [--format text|json|summary]

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <repo_path> [--skill-scan] [--format text|json|summary]"
    echo ""
    echo "Modes:"
    echo "  (default)      Full audit - all 12 scanners"
    echo "  --skill-scan   Focused on AI skill threats (6 scanners, faster)"
    echo ""
    echo "Output formats:"
    echo "  --format text     Human-readable with severity colors (default)"
    echo "  --format json     Machine-readable JSON"
    echo "  --format summary  Counts only (for CI/CD)"
    exit 1
fi

REPO_PATH=$(realpath "$1")
shift

# Parse remaining args
SKILL_SCAN=false
FORMAT="text"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skill-scan) SKILL_SCAN=true; shift ;;
        --format) FORMAT="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "=========================================="
echo "  REPO FORENSICS v3"
echo "  Target: $REPO_PATH"
echo "  Mode: $(if $SKILL_SCAN; then echo 'Skill Scan (focused)'; else echo 'Full Audit'; fi)"
echo "  Format: $FORMAT"
echo "  Date: $(date)"
echo "=========================================="

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
    local output_file="$TMPDIR/$name.out"
    local exit_file="$TMPDIR/$name.exit"

    if [ -n "$TIMEOUT_CMD" ]; then
        $TIMEOUT_CMD "$SCANNER_TIMEOUT" python3 "$SKILL_DIR/$script" "$REPO_PATH" --format "$FORMAT" > "$output_file" 2>&1
    else
        python3 "$SKILL_DIR/$script" "$REPO_PATH" --format "$FORMAT" > "$output_file" 2>&1
    fi
    echo $? > "$exit_file"
}

if $SKILL_SCAN; then
    # Focused mode: 6 scanners most relevant to vetting skills
    echo ""
    echo "[*] Running focused skill scan (6 scanners)..."

    run_scanner "skill_threats" "scan_skill_threats.py" &
    run_scanner "secrets" "scan_secrets.py" &
    run_scanner "dataflow" "scan_dataflow.py" &
    run_scanner "sast" "scan_sast.py" &
    run_scanner "lifecycle" "scan_lifecycle.py" &
    run_scanner "mcp_security" "scan_mcp_security.py" &
    wait

else
    # Full audit: all scanners in parallel
    echo ""
    echo "[*] Running all 12 scanners in parallel..."
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
    wait
fi

# Collect and display results
echo ""
echo "=========================================="
echo "  RESULTS"
echo "=========================================="

MAX_EXIT=0
TOTAL_C=0
TOTAL_H=0
TOTAL_M=0
TOTAL_L=0

for out_file in "$TMPDIR"/*.out; do
    name=$(basename "$out_file" .out)
    exit_code=$(cat "$TMPDIR/$name.exit" 2>/dev/null || echo "1")

    echo ""
    echo "--- [$name] ---"
    cat "$out_file"

    if [ "$exit_code" -gt "$MAX_EXIT" ]; then
        MAX_EXIT=$exit_code
    fi

    # Count severity from output (supports both text and summary formats)
    # Text format: lines with [CRITICAL], [HIGH], [MEDIUM], [LOW]
    # Summary format: "scanner: N findings (XC YH ZM WL)"
    if [ "$FORMAT" = "summary" ]; then
        # Parse summary line: "scanner: N findings (29C 13H 0M 0L)"
        summary_line=$(grep -E '[0-9]+C [0-9]+H [0-9]+M [0-9]+L' "$out_file" 2>/dev/null || true)
        if [ -n "$summary_line" ]; then
            c_count=$(echo "$summary_line" | grep -oE '[0-9]+C' | grep -oE '[0-9]+')
            h_count=$(echo "$summary_line" | grep -oE '[0-9]+H' | grep -oE '[0-9]+')
            m_count=$(echo "$summary_line" | grep -oE '[0-9]+M' | grep -oE '[0-9]+')
            l_count=$(echo "$summary_line" | grep -oE '[0-9]+L' | grep -oE '[0-9]+')
        else
            c_count=0; h_count=0; m_count=0; l_count=0
        fi
    else
        c_count=$(grep -c '\[CRITICAL\]' "$out_file" 2>/dev/null || true)
        h_count=$(grep -c '\[HIGH\]' "$out_file" 2>/dev/null || true)
        m_count=$(grep -c '\[MEDIUM\]' "$out_file" 2>/dev/null || true)
        l_count=$(grep -c '\[LOW\]' "$out_file" 2>/dev/null || true)
    fi
    TOTAL_C=$((TOTAL_C + ${c_count:-0}))
    TOTAL_H=$((TOTAL_H + ${h_count:-0}))
    TOTAL_M=$((TOTAL_M + ${m_count:-0}))
    TOTAL_L=$((TOTAL_L + ${l_count:-0}))
done

echo ""
echo "=========================================="
TOTAL=$((TOTAL_C + TOTAL_H + TOTAL_M + TOTAL_L))
echo "  VERDICT: $TOTAL findings ($TOTAL_C critical, $TOTAL_H high, $TOTAL_M medium, $TOTAL_L low)"

if [ "$TOTAL_C" -gt 0 ]; then
    echo "  EXIT CODE: 2 (critical findings)"
    exit 2
elif [ "$TOTAL_H" -gt 0 ] || [ "$TOTAL_M" -gt 0 ]; then
    echo "  EXIT CODE: 1 (high/medium findings)"
    exit 1
else
    echo "  EXIT CODE: 0 (clean)"
    exit 0
fi
