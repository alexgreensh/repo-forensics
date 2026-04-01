#!/bin/bash

# Repo Forensics Suite Runner v2
# Created by Alex Greenshpun
# Usage: ./run_forensics.sh <repo_path> [--skill-scan] [--format text|json|summary]

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <repo_path> [--skill-scan] [--format text|json|summary] [--update-iocs] [--watch]"
    echo ""
    echo "Modes:"
    echo "  (default)      Full audit - all 17 scanners"
    echo "  --skill-scan   Focused on AI skill threats (9 scanners, faster)"
    echo ""
    echo "Options:"
    echo "  --format text     Human-readable with severity colors (default)"
    echo "  --format json     Machine-readable JSON"
    echo "  --format summary  Counts only (for CI/CD)"
    echo "  --update-iocs     Pull latest IOC database before scanning"
    echo "  --watch           Enable file integrity baseline tracking"
    exit 1
fi

REPO_PATH=$(realpath "$1")
shift

# Parse remaining args
SKILL_SCAN=false
FORMAT="text"
UPDATE_IOCS=false
WATCH_MODE=false
VERIFY_INSTALL=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skill-scan) SKILL_SCAN=true; shift ;;
        --format) [[ $# -ge 2 ]] || { echo "Error: --format requires a value"; exit 1; }; FORMAT="$2"; shift 2 ;;
        --update-iocs) UPDATE_IOCS=true; shift ;;
        --watch) WATCH_MODE=true; shift ;;
        --verify-install) VERIFY_INSTALL=true; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

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

    if [ -n "$TIMEOUT_CMD" ]; then
        $TIMEOUT_CMD "$SCANNER_TIMEOUT" python3 "$SKILL_DIR/$script" "$REPO_PATH" --format "$FORMAT" ${extra_args:+"$extra_args"} > "$output_file" 2>&1
    else
        python3 "$SKILL_DIR/$script" "$REPO_PATH" --format "$FORMAT" ${extra_args:+"$extra_args"} > "$output_file" 2>&1
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

# Collect and display results
if [ "$FORMAT" = "json" ]; then
    EXIT_CODE_FILE="$TMPDIR/aggregate.exit"
    python3 - "$TMPDIR" "$REPO_PATH" "$SKILL_SCAN" "$EXIT_CODE_FILE" <<'PY'
import json
import os
import sys

tmpdir, repo_path, skill_scan, exit_code_file = sys.argv[1:5]
severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
scanners = []
all_findings = []

def extract_payload(raw_text):
    candidates = []
    offset = 0
    for line in raw_text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith('[') or stripped.startswith('{'):
            candidates.append(offset + len(line) - len(stripped))
        offset += len(line)
    if raw_text.startswith('[') or raw_text.startswith('{'):
        candidates.append(0)

    for position in reversed(candidates):
        candidate = raw_text[position:].strip()
        if not candidate:
            continue
        try:
            return json.loads(candidate), None
        except json.JSONDecodeError:
            continue
    return [], "Could not extract JSON payload from scanner output"

for filename in sorted(name for name in os.listdir(tmpdir) if name.endswith(".out")):
    name = filename[:-4]
    out_path = os.path.join(tmpdir, filename)
    exit_path = os.path.join(tmpdir, f"{name}.exit")

    with open(out_path, "r", encoding="utf-8") as handle:
        raw_output = handle.read()

    exit_code = 1
    if os.path.exists(exit_path):
        with open(exit_path, "r", encoding="utf-8") as handle:
            try:
                exit_code = int(handle.read().strip() or "1")
            except ValueError:
                exit_code = 1

    findings, parse_error = extract_payload(raw_output)
    if not isinstance(findings, list):
        findings = []
        parse_error = parse_error or "Scanner JSON payload was not a list"

    scanners.append({
        "name": name,
        "exit_code": exit_code,
        "parse_error": parse_error,
        "finding_count": len(findings),
        "findings": findings,
    })
    all_findings.extend(findings)

for finding in all_findings:
    severity = finding.get("severity", "low")
    if severity in summary:
        summary[severity] += 1
    summary["total"] += 1

all_findings.sort(key=lambda item: -severity_order.get(item.get("severity", "low"), 0))

if summary["critical"] > 0:
    exit_code = 2
elif summary["high"] > 0 or summary["medium"] > 0:
    exit_code = 1
else:
    exit_code = 0

print(json.dumps({
    "target": repo_path,
    "mode": "skill" if skill_scan == "true" else "full",
    "scanner_count": len(scanners),
    "scanners": scanners,
    "summary": summary,
    "exit_code": exit_code,
    "findings": all_findings,
}, indent=2))

with open(exit_code_file, "w", encoding="utf-8") as handle:
    handle.write(str(exit_code))
PY
    exit "$(cat "$EXIT_CODE_FILE")"
fi

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
