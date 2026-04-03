#!/usr/bin/env python3
"""
aggregate_json.py - Aggregate scanner JSON outputs for run_forensics.sh.

Reads per-scanner stdout/stderr files from a temp directory, validates JSON payloads,
builds a machine-readable aggregate document, and writes a fail-closed exit code file.
"""

import json
import os
import sys


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
VALID_EXIT_CODES = {0, 1, 2}


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


def build_report(tmpdir, repo_path, skill_scan):
    scanners, all_findings = load_scanner_results(tmpdir)
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


def main(argv):
    if len(argv) != 5:
        raise SystemExit("Usage: aggregate_json.py <tmpdir> <repo_path> <skill_scan> <exit_code_file>")

    _, tmpdir, repo_path, skill_scan, exit_code_file = argv
    report = build_report(tmpdir, repo_path, skill_scan)

    print(json.dumps(report, indent=2))

    exit_code = report["exit_code"]
    with open(exit_code_file, "w", encoding="utf-8") as handle:
        handle.write(str(exit_code if exit_code in VALID_EXIT_CODES else 99))


if __name__ == "__main__":
    main(sys.argv)
