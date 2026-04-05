#!/usr/bin/env python3
"""
aggregate_json.py - Aggregate scanner JSON outputs for run_forensics.sh.

Reads per-scanner stdout/stderr files from a temp directory, validates JSON payloads,
builds a machine-readable aggregate document, and writes a fail-closed exit code file.
"""

import json
import os
import sys

# Make forensics_core importable so we can run the correlation engine on
# aggregated findings. Without this step, Rules 1-19 in forensics_core.
# correlate() never fire during a real scan — they previously only ran
# from auto_scan.py's PostToolUse hook. See security review A5 (2026-04-05).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
VALID_EXIT_CODES = {0, 1, 2}

# Text-mode severity colors (match forensics_core.py)
SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[96m",
    "low": "\033[37m",
}
RESET = "\033[0m"


def load_text(path):
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def parse_scanner_payload(raw_output):
    if not raw_output.strip():
        return [], None

    try:
        payload = json.loads(raw_output.strip())
    except json.JSONDecodeError as exc:
        return [], f"Invalid JSON output: {exc.msg}"

    if not isinstance(payload, list):
        return [], "Scanner JSON payload was not a list"

    return payload, None


def load_scanner_results(tmpdir):
    scanners = []
    all_findings = []

    for filename in sorted(name for name in os.listdir(tmpdir) if name.endswith(".out")):
        name = filename[:-4]
        out_path = os.path.join(tmpdir, filename)
        err_path = os.path.join(tmpdir, f"{name}.err")
        exit_path = os.path.join(tmpdir, f"{name}.exit")

        raw_output = load_text(out_path)
        stderr_output = load_text(err_path).strip()
        findings, parse_error = parse_scanner_payload(raw_output)

        if os.path.exists(exit_path):
            try:
                exit_code = int(load_text(exit_path).strip() or "1")
            except ValueError:
                exit_code = 1
        else:
            exit_code = 1

        if exit_code not in VALID_EXIT_CODES and parse_error is None:
            parse_error = f"Unexpected scanner exit code: {exit_code}"
        if exit_code != 0 and not raw_output.strip() and parse_error is None:
            parse_error = "No JSON output captured from scanner"

        scanner_info = {
            "name": name,
            "exit_code": exit_code,
            "parse_error": parse_error,
            "finding_count": len(findings),
            "findings": findings,
        }
        if stderr_output:
            scanner_info["stderr"] = stderr_output[:4000]

        scanners.append(scanner_info)
        all_findings.extend(findings)

    return scanners, all_findings


def build_summary(findings):
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

    for finding in findings:
        severity = finding.get("severity", "low")
        if severity in summary:
            summary[severity] += 1
        summary["total"] += 1

    return summary


def calculate_report_exit_code(summary, scanners):
    if any(scanner["parse_error"] for scanner in scanners):
        return 99
    if any(scanner["exit_code"] not in VALID_EXIT_CODES for scanner in scanners):
        return 99
    if summary["critical"] > 0:
        return 2
    if summary["high"] > 0 or summary["medium"] > 0:
        return 1
    return 0


def run_correlation_pass(all_findings):
    """Run the forensics_core.correlate() engine on aggregated findings.

    Rules 1-19 operate on cross-scanner findings in the same file (e.g.
    env read from secrets + network call from dataflow = Rule 1 Data
    Exfiltration, or exec + network + credential read = Rule 19 Lethal
    Trifecta). These rules previously only fired from the PostToolUse
    hook in auto_scan.py — they were silently dead code in the primary
    `run_forensics.sh` workflow until 2026-04-05 (security review A5).

    Returns a list of correlated finding dicts to append to all_findings.
    Soft-fails on any error: correlation is additive value, should never
    block the primary report.
    """
    if not all_findings:
        return []
    try:
        import forensics_core as core
    except ImportError as e:
        print(f"[!] Correlation pass skipped: {e}", file=sys.stderr)
        return []

    # Delegate dict->Finding conversion to the shared helper so this path
    # stays in sync with auto_scan.run_targeted_scan. Previously both files
    # hand-rolled this conversion with subtly different int-coercion logic;
    # Finding.__post_init__ now handles line coercion centrally. (PR-F1.)
    finding_objs = core.findings_from_dicts(all_findings)

    try:
        correlated = core.correlate(finding_objs)
    except (AttributeError, KeyError, TypeError, ValueError) as e:
        # Narrow the except to expected types so NameError / ImportError bugs
        # in new correlation rules fail loud during development instead of
        # silently dropping the correlation pass. (PL-F4 / PR-F10 / SS-F11.)
        import traceback
        print(f"[!] Correlation engine error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return []

    return [c.to_dict() for c in correlated]


def build_report(tmpdir, repo_path, skill_scan):
    scanners, all_findings = load_scanner_results(tmpdir)

    # Raw-content fallback for Rule 19 Lethal Trifecta. Specialized scanners
    # (secrets, dataflow) often miss low-level primitives like direct
    # open('~/.ssh/id_rsa') or raw http.client.HTTPSConnection. The trifecta
    # raw scanner greps files directly and synthesizes primitive findings so
    # Rule 19 fires in correlate() below regardless of sub-scanner coverage.
    # (Fix for 2026-04-05 security review A6.)
    try:
        import forensics_core as _core_raw
        raw_trifecta = _core_raw.detect_trifecta_raw(repo_path)
        if raw_trifecta:
            raw_dicts = [f.to_dict() for f in raw_trifecta]
            all_findings.extend(raw_dicts)
            scanners.append({
                "name": "trifecta_raw",
                "exit_code": 0,
                "parse_error": None,
                "finding_count": len(raw_dicts),
                "findings": raw_dicts,
            })
    except (ImportError, OSError) as e:
        print(f"[!] Trifecta raw-scan failed: {e}", file=sys.stderr)

    # Run correlation engine on aggregated findings. Correlated findings
    # (Rules 1-19) are added AFTER the scanner loop so they can see every
    # scanner's output together. Without this, Rule 19 Lethal Trifecta
    # (exec + network + credential read) and the other 18 rules never fire
    # in the primary run_forensics.sh workflow.
    correlated_findings = run_correlation_pass(all_findings)
    if correlated_findings:
        all_findings.extend(correlated_findings)
        # Add a synthetic scanner entry so the aggregate output shows
        # correlation ran and how many findings it produced.
        scanners.append({
            "name": "correlation",
            "exit_code": 0,
            "parse_error": None,
            "finding_count": len(correlated_findings),
            "findings": correlated_findings,
        })

    all_findings.sort(key=lambda item: -SEVERITY_ORDER.get(item.get("severity", "low"), 0))
    summary = build_summary(all_findings)
    exit_code = calculate_report_exit_code(summary, scanners)

    return {
        "target": repo_path,
        "mode": "skill" if skill_scan == "true" else "full",
        "scanner_count": len(scanners),
        "scanners": scanners,
        "summary": summary,
        "exit_code": exit_code,
        "findings": all_findings,
    }


def format_report_as_text(report):
    """Render an aggregated report in the text format mirrored from
    forensics_core.format_findings() and the existing run_forensics.sh
    output. Used when the caller asked for text output but we still need
    the JSON-internal pipeline to run correlation."""
    lines = []
    lines.append("")
    lines.append("==========================================")
    lines.append("  RESULTS")
    lines.append("==========================================")
    for scanner in report["scanners"]:
        name = scanner["name"]
        findings = scanner.get("findings", [])
        lines.append("")
        lines.append(f"--- [{name}] ---")
        if scanner.get("parse_error"):
            lines.append(f"[!] Scanner parse error: {scanner['parse_error']}")
        if not findings:
            lines.append("  No findings.")
        else:
            for f in findings:
                sev = f.get("severity", "low")
                color = SEVERITY_COLORS.get(sev, "")
                loc = f"{f.get('file', '')}:{f.get('line', 0)}" if f.get('line', 0) > 0 else f.get('file', '')
                lines.append(f"  {color}[{sev.upper()}]{RESET} {f.get('title', '')}")
                lines.append(f"         {loc}")
                lines.append(f"         {f.get('description', '')}")
                snip = f.get("snippet", "")
                if snip:
                    lines.append(f"         {snip[:120]}")
    summary = report["summary"]
    lines.append("")
    lines.append("==========================================")
    lines.append(
        f"  VERDICT: {summary['total']} findings "
        f"({summary['critical']} critical, {summary['high']} high, "
        f"{summary['medium']} medium, {summary['low']} low)"
    )
    exit_code = report["exit_code"]
    if exit_code == 2:
        lines.append("  EXIT CODE: 2 (critical findings)")
    elif exit_code == 1:
        lines.append("  EXIT CODE: 1 (high/medium findings)")
    elif exit_code == 0:
        lines.append("  EXIT CODE: 0 (clean)")
    else:
        lines.append(f"  EXIT CODE: {exit_code}")
    return "\n".join(lines)


def main(argv):
    # Support two CLI shapes:
    #   aggregate_json.py <tmpdir> <repo_path> <skill_scan> <exit_code_file>  [JSON output, original]
    #   aggregate_json.py --text <tmpdir> <repo_path> <skill_scan> <exit_code_file>  [text output]
    if len(argv) == 6 and argv[1] == "--text":
        text_mode = True
        _, _, tmpdir, repo_path, skill_scan, exit_code_file = argv
    elif len(argv) == 5:
        text_mode = False
        _, tmpdir, repo_path, skill_scan, exit_code_file = argv
    else:
        raise SystemExit(
            "Usage: aggregate_json.py [--text] <tmpdir> <repo_path> "
            "<skill_scan> <exit_code_file>"
        )

    report = build_report(tmpdir, repo_path, skill_scan)

    if text_mode:
        print(format_report_as_text(report))
    else:
        print(json.dumps(report, indent=2))

    exit_code = report["exit_code"]
    with open(exit_code_file, "w", encoding="utf-8") as handle:
        handle.write(str(exit_code if exit_code in VALID_EXIT_CODES else 99))


if __name__ == "__main__":
    main(sys.argv)
