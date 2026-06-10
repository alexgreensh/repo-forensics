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

# Verdict tiers by confidence (KTD-7 / R4). These shape messaging and the
# adjudication flow only; severity still drives the 0/1/2/99 exit code.
# SUPPRESSED is also assigned to any user-suppressed finding regardless of
# its confidence.
VERDICT_BLOCK_MIN = 0.92
VERDICT_WARN_MIN = 0.60
VERDICT_INFO_MIN = 0.30

# Threshold above which suppressing rules via `rule:` lines is treated as a
# mass-suppression abuse signal (HIGH). Mirrors the DANGEROUS_IGNORE_PATTERNS
# escalation in forensics_core for path globs.
MASS_SUPPRESSION_THRESHOLD = 5


def verdict_tier(confidence, suppressed=False):
    """Map a confidence score (and suppression flag) to a verdict tier."""
    if suppressed:
        return "suppressed"
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        conf = 0.0
    if conf >= VERDICT_BLOCK_MIN:
        return "block"
    if conf >= VERDICT_WARN_MIN:
        return "warn"
    if conf >= VERDICT_INFO_MIN:
        return "info"
    return "suppressed"

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


_SEVERITY_CONFIDENCE = {
    "critical": 0.95,
    "high": 0.80,
    "medium": 0.60,
    "low": 0.40,
}


def _finding_confidence(finding):
    """Return a finding's confidence, filling from severity when absent/zero.

    Legacy scanners emit dicts without a `confidence` key; their findings get
    the severity-derived default so verdict tiering is consistent with
    forensics_core.Finding.__post_init__ (KTD-8).
    """
    conf = finding.get("confidence")
    if conf is None:
        return _SEVERITY_CONFIDENCE.get(finding.get("severity", "low"), 0.40)
    try:
        conf = float(conf)
    except (TypeError, ValueError):
        return _SEVERITY_CONFIDENCE.get(finding.get("severity", "low"), 0.40)
    if conf == 0.0:
        return _SEVERITY_CONFIDENCE.get(finding.get("severity", "low"), 0.40)
    if conf < 0.0:
        return 0.0
    if conf > 1.0:
        return 1.0
    return conf


def apply_suppressions(all_findings, repo_path):
    """Partition findings into active vs user-suppressed and emit abuse guards.

    Reads `rule:<id>[:<glob>]` directives from <repo_path>/.forensicsignore and
    suppresses any finding whose rule_id (and path glob, if present) matches.

    Abuse guards (mirroring DANGEROUS_IGNORE_PATTERNS):
      - Suppressing a CRITICAL-severity rule -> a CRITICAL "suppression
        tampering" finding (active, counts toward exit code).
      - Suppressing MORE THAN MASS_SUPPRESSION_THRESHOLD rules via `rule:`
        lines -> a HIGH "mass-suppression" finding.

    Returns (active_findings, suppressed_findings). Every applied suppression
    appears among the suppressed findings; none is silently dropped. The guard
    findings themselves are appended to active_findings.
    """
    suppressions = []
    try:
        import forensics_core as core
        suppressions = core.load_rule_suppressions(repo_path)
    except (ImportError, OSError) as exc:
        print(f"[!] Rule-suppression load skipped: {exc}", file=sys.stderr)
        return list(all_findings), []

    if not suppressions:
        return list(all_findings), []

    active = []
    suppressed = []
    critical_rules_suppressed = set()

    for finding in all_findings:
        rule_id = finding.get("rule_id", "") or ""
        matched = None
        if rule_id:
            for supp in suppressions:
                if core.suppression_matches(supp, rule_id, finding.get("file", "")):
                    matched = supp
                    break
        if matched is not None:
            if finding.get("severity") == "critical":
                critical_rules_suppressed.add(rule_id)
            suppressed.append(finding)
        else:
            active.append(finding)

    guard_findings = []

    # Guard 1: suppression of a critical-severity rule = tampering (CRITICAL).
    for rule_id in sorted(critical_rules_suppressed):
        guard_findings.append({
            "scanner": "meta",
            "severity": "critical",
            "title": ".forensicsignore: Critical Rule Suppression",
            "description": (
                f"Suppresses critical-severity rule '{rule_id}'. Suppressing a "
                f"critical rule is the shape of attacker-planted tampering."
            ),
            "file": ".forensicsignore",
            "line": 0,
            "snippet": f"rule:{rule_id}",
            "category": "configuration",
            "rule_id": "",
            "confidence": 0.95,
        })

    # Guard 2: mass suppression (HIGH) regardless of suppressed rules' severity.
    if len(suppressions) > MASS_SUPPRESSION_THRESHOLD:
        guard_findings.append({
            "scanner": "meta",
            "severity": "high",
            "title": ".forensicsignore: Mass Rule Suppression",
            "description": (
                f"Suppresses {len(suppressions)} rules via rule: lines "
                f"(threshold {MASS_SUPPRESSION_THRESHOLD}). Mass suppression of "
                f"WARN-tier rules silently empties the adjudication pipeline."
            ),
            "file": ".forensicsignore",
            "line": 0,
            "snippet": f"{len(suppressions)} rule: suppressions",
            "category": "configuration",
            "rule_id": "",
            "confidence": 0.80,
        })

    active.extend(guard_findings)
    return active, suppressed


def mark_adjudication(active_findings):
    """Set needs_adjudication=true on WARN-tier, non-correlation findings (U8).

    Only WARN-tier findings (VERDICT_WARN_MIN <= conf < VERDICT_BLOCK_MIN) are
    marked. BLOCK / INFO / SUPPRESSED are NOT marked (BLOCK acts on its own,
    INFO/SUPPRESSED never reach the adjudicator). Correlation-synthesized
    findings (scanner == "correlation") are excluded: their "[compound: ...]"
    snippets carry nothing quotable.

    needs_adjudication is an ADDITIVE per-finding key — it never affects severity
    counts, verdict tiers, or the 0/1/2/99 exit-code contract. Mutates findings
    in place and returns the same list.
    """
    for finding in active_findings:
        if finding.get("scanner") == "correlation":
            continue
        tier = verdict_tier(_finding_confidence(finding))
        if tier == "warn":
            finding["needs_adjudication"] = True
    return active_findings


def build_summary(findings):
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

    for finding in findings:
        severity = finding.get("severity", "low")
        if severity in summary:
            summary[severity] += 1
        summary["total"] += 1

    return summary


def build_verdicts(active_findings, suppressed_findings):
    """Count findings by verdict tier.

    Active findings tier by confidence; all user-suppressed findings count as
    SUPPRESSED. Low-confidence (<0.30) active findings also land in SUPPRESSED.
    """
    verdicts = {"block": 0, "warn": 0, "info": 0, "suppressed": 0}
    for finding in active_findings:
        tier = verdict_tier(_finding_confidence(finding))
        verdicts[tier] += 1
    verdicts["suppressed"] += len(suppressed_findings)
    return verdicts


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

    # Pass a lazy iterator so correlate() builds its by_file dict without
    # a separate intermediate Finding list existing alongside all_findings.
    try:
        correlated = core.correlate(core.findings_from_dicts_iter(all_findings))
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

    # Per-finding suppression (U1). User-suppressed findings are pulled out of
    # the active set BEFORE summary/exit-code computation so they cannot affect
    # severity counts or the 0/1/2/99 contract, but they remain visible under
    # the top-level `suppressed` key for auditability. Abuse-guard findings
    # (critical-rule suppression, mass suppression) are added to the active set.
    all_findings, suppressed_findings = apply_suppressions(all_findings, repo_path)

    # Mark WARN-tier (non-correlation) findings for LLM adjudication (U8).
    # Additive per-finding flag; does not touch severity counts or exit code.
    mark_adjudication(all_findings)

    all_findings.sort(key=lambda item: -SEVERITY_ORDER.get(item.get("severity", "low"), 0))
    summary = build_summary(all_findings)
    verdicts = build_verdicts(all_findings, suppressed_findings)
    exit_code = calculate_report_exit_code(summary, scanners)

    return {
        "target": repo_path,
        "mode": "skill" if skill_scan == "true" else "full",
        "scanner_count": len(scanners),
        "scanners": scanners,
        "summary": summary,
        "verdicts": verdicts,
        "exit_code": exit_code,
        "findings": all_findings,
        "suppressed": suppressed_findings,
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

    # Adjudication block (U8) — emitted AFTER the verdict line, in the text
    # output path only (never in the JSON schema). Empty on a clean scan.
    try:
        import adjudication
        block = adjudication.build_adjudication_block(report.get("findings", []))
        if block:
            lines.append(block)
    except ImportError:
        pass

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
