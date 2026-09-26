#!/usr/bin/env python3
"""
aggregate_json.py - Aggregate scanner JSON outputs for run_forensics.sh.

Reads per-scanner stdout/stderr files from a temp directory, validates JSON payloads,
builds a machine-readable aggregate document, and writes a fail-closed exit code file.
"""

import json
import os
import subprocess
import sys

# Make forensics_core importable so we can run the correlation engine on
# aggregated findings. Without this step, Rules 1-19 in forensics_core.
# correlate() never fire during a real scan — they previously only ran
# from auto_scan.py's PostToolUse hook. See security review A5 (2026-04-05).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
VALID_EXIT_CODES = {0, 1, 2}

# Verdict tiers by confidence (KTD-7). These shape messaging and the
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
    # Calibration: only CRITICAL-rule suppression and MASS suppression are
    # guarded. A scoped `rule:<id>:<glob>` suppression of a high/medium finding
    # is a SUPPORTED feature (a first-party repo silencing a known-benign match
    # in its own tree); re-emitting a same-severity guard for it made every
    # legitimate scoped suppression a no-op. The exploit it was aimed at —
    # hiding a critical — is already blocked by the critical-rule guard below,
    # and every suppressed finding stays visible under the report's
    # `suppressed` key regardless of tier.

    for finding in all_findings:
        rule_id = finding.get("rule_id", "") or ""
        matched = None
        if rule_id:
            for supp in suppressions:
                if core.suppression_matches(
                    supp, rule_id, finding.get("file", ""), repo_path=repo_path
                ):
                    matched = supp
                    break
        if matched is not None:
            if finding.get("severity") == "critical":
                critical_rules_suppressed.add(rule_id)
            suppressed.append(finding)
        else:
            active.append(finding)

    guard_findings = []

    invalid_structured = [s for s in suppressions if s.get("structured") and not any(
        core.suppression_matches(s, s.get("rule_id", ""), f.get("file", ""), repo_path=repo_path)
        for f in all_findings
    )]
    for suppression in invalid_structured:
        guard_findings.append({
            "scanner": "meta", "severity": "high",
            "title": ".forensicsignore: Invalid Structured Suppression",
            "description": "A structured suppression is expired, unsigned, out of scope, or content-mismatched.",
            "file": ".forensicsignore", "line": 0,
            "snippet": suppression.get("raw", "")[:120],
            "category": "configuration", "rule_id": "", "confidence": 0.80,
        })

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


# Coverage-honesty categories. These categories are emitted by scanners
# when they cannot fully inspect the target. They are classified into two tiers:
#   UNSUPPORTED = the format/surface is not analysable by this scanner
#   INCOMPLETE  = the scanner started but hit a budget/cap/depth/uncheckable
#                 limit before finishing, or the subprocess produced no JSON /
#                 an unexpected exit code.
_UNSUPPORTED_COVERAGE_CATEGORIES = {
    "unsupported-archive-type",
    "opaque-archive",
    "unanalyzable-bytecode",
    "opaque-bytecode-with-source",
    "unsupported-file-type",
}

_INCOMPLETE_COVERAGE_CATEGORIES = {
    # An oversized file is only head/tail sampled (1 MB each end), so
    # the middle is UNINSPECTED. It was not registered as a coverage category at
    # all, which let a payload padded past the 10 MB walk cap report
    # coverage=COMPLETE and exit 0.
    "oversized-file",
    "archive-scan-incomplete",
    "decode-scan-incomplete",
    "decode-max-depth",
    "scan-incomplete",
    "provenance-unchecked",
    "nc",
    "NC",
    "unchecked",
}

# Prefix shorthands so the registry is closed under future scanner additions.
_COVERAGE_UNSUPPORTED_PREFIXES = ("unsupported-", "opaque-")
_COVERAGE_INCOMPLETE_SUFFIXES = ("-incomplete", "-max-depth")

# Coverage gaps that sit over an EXECUTABLE / LOADABLE / ARCHIVE / ENCODED
# artifact. A gap here is not a benign "we skipped a README": something that can
# run or unpack was left uninspected, and the report must not be able to say
# exit 0 over it. Everything else (provenance-unchecked, offline feeds,
# generic scan-incomplete) stays purely informational.
_BLOCKING_COVERAGE_CATEGORIES = {
    "unsupported-archive-type",
    "opaque-archive",
    "archive-scan-incomplete",
    "unanalyzable-bytecode",
    "opaque-bytecode-with-source",
    "decode-max-depth",
    "decode-scan-incomplete",
    "unsupported-file-type",
    "oversized-file",
}


def build_coverage_gap_findings(coverage_status):
    """Turn blocking coverage gaps into visible MEDIUM findings.

    `calculate_report_exit_code` reads only the severity summary, so a coverage
    gap could never influence the exit code no matter how loud coverage_status
    was. Emitting a real finding per (scanner, category) blocking gap floors the
    exit code at 1 through the existing contract — no second exit-code path to
    keep in sync — and makes the uninspected surface visible in the findings
    list rather than only in an additive status block.

    MEDIUM, not HIGH: an uninspected indirection is a KNOWN UNKNOWN (review
    required), not a confirmed payload.
    """
    findings = []
    seen = set()
    for gap in coverage_status.get("gaps", []):
        category = gap.get("category", "")
        if category not in _BLOCKING_COVERAGE_CATEGORIES:
            continue
        key = (gap.get("scanner", ""), category)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "scanner": "meta",
            "severity": "medium",
            "title": "Uninspected executable indirection",
            "description": (
                f"The {gap.get('scanner', '?')} scanner could not fully inspect "
                f"a runnable/loadable/encoded artifact ({category}): "
                f"{gap.get('reason', '')} Contents behind this gap were never "
                f"analysed, so a clean verdict cannot be claimed over them."
            ),
            "file": "", "line": 0,
            "snippet": category,
            "category": "coverage-gap",
            "rule_id": "", "confidence": 0.60,
            "evidence_class": "direct",
        })
    return findings


# Dependency findings do not follow the per-file scan_file coverage contract.
# DAST can emit scan-incomplete when no sandbox is available, so its findings
# must participate in coverage classification.
_NO_COVERAGE_SCANNER_NAMES = {"dependencies"}


def _coverage_status_for_category(category):
    """Classify a finding category into a coverage tier.

    Returns one of ("UNSUPPORTED", "INCOMPLETE", None).
    """
    if category in _UNSUPPORTED_COVERAGE_CATEGORIES:
        return "UNSUPPORTED"
    if category in _INCOMPLETE_COVERAGE_CATEGORIES:
        return "INCOMPLETE"
    cat = category.lower()
    if any(cat.startswith(p) for p in _COVERAGE_UNSUPPORTED_PREFIXES):
        return "UNSUPPORTED"
    if any(cat.endswith(s) for s in _COVERAGE_INCOMPLETE_SUFFIXES):
        return "INCOMPLETE"
    if cat in ("nc", "unchecked"):
        return "INCOMPLETE"
    return None


def build_coverage_status(scanners, all_findings):
    """Aggregate per-scanner coverage honesty into a report-level coverage_status.

    coverage_status itself is a pure report: it reports COMPLETE/INCOMPLETE/
    UNSUPPORTED per scanner and overall, with a gaps[] list of (scanner,
    category, human_reason), and never mutates a scanner finding.

    It is NOT inert, though: build_report feeds the gaps through
    build_coverage_gap_findings(), so a gap over a runnable/loadable/encoded
    artifact becomes a MEDIUM finding and floors the exit code at 1.
    Gaps outside _BLOCKING_COVERAGE_CATEGORIES stay informational.

    Args:
        scanners: the per-run scanner info list from load_scanner_results().
        all_findings: flat list of finding dicts (used only to sanity-check
                      scanner entry counts; per-scanner status is built from
                      scanner["findings"]).

    Returns:
        dict with keys: overall, per_scanner, gaps.
    """
    del all_findings  # intentional; status is per scanner

    per_scanner = {}
    gaps = []
    overall = "COMPLETE"

    # Severity ordering: UNSUPPORTED > INCOMPLETE > COMPLETE.
    status_rank = {"COMPLETE": 0, "INCOMPLETE": 1, "UNSUPPORTED": 2}

    for scanner in scanners:
        name = scanner["name"]
        findings = scanner.get("findings", [])
        parse_error = scanner.get("parse_error")
        exit_code = scanner.get("exit_code", 1)

        # Subprocess-level failure is always an INCOMPLETE coverage signal.
        if parse_error is not None:
            gaps.append({
                "scanner": name,
                "category": "parse-error",
                "reason": f"Scanner produced no parseable JSON: {parse_error}",
            })
            per_scanner[name] = {"status": "INCOMPLETE", "reasons": ["parse-error"]}
            overall = _worse_status(overall, "INCOMPLETE", status_rank)
            continue

        if exit_code not in VALID_EXIT_CODES:
            gaps.append({
                "scanner": name,
                "category": "unexpected-exit",
                "reason": f"Scanner exited with unexpected code {exit_code}",
            })
            per_scanner[name] = {"status": "INCOMPLETE", "reasons": ["unexpected-exit"]}
            overall = _worse_status(overall, "INCOMPLETE", status_rank)
            continue

        # DAST and dependencies don't follow the scan_file contract; their own
        # finding categories are findings, not coverage-honesty gaps.
        if name in _NO_COVERAGE_SCANNER_NAMES:
            per_scanner[name] = {"status": "COMPLETE", "reasons": []}
            continue

        reasons = []
        scanner_status = "COMPLETE"

        for finding in findings:
            category = finding.get("category", "")
            tier = _coverage_status_for_category(category)
            if tier is None:
                continue
            if tier == "UNSUPPORTED":
                scanner_status = _worse_status(scanner_status, "UNSUPPORTED", status_rank)
                if category not in reasons:
                    reasons.append(category)
                gaps.append({
                    "scanner": name,
                    "category": category,
                    "reason": f"Scanner could not analyse {category} surface",
                })
            elif tier == "INCOMPLETE":
                scanner_status = _worse_status(scanner_status, "INCOMPLETE", status_rank)
                if category not in reasons:
                    reasons.append(category)
                gaps.append({
                    "scanner": name,
                    "category": category,
                    "reason": f"Scanner hit a budget/cap/uncheckable limit: {category}",
                })

        per_scanner[name] = {"status": scanner_status, "reasons": reasons}
        overall = _worse_status(overall, scanner_status, status_rank)

    return {
        "overall": overall,
        "per_scanner": per_scanner,
        "gaps": gaps,
    }


def _worse_status(a, b, rank):
    """Return the worse of two coverage status strings."""
    return a if rank.get(a, 0) >= rank.get(b, 0) else b


def build_core_verdict(summary, verdicts, exit_code):
    """Re-express the deterministic verdict as an additive top-level key.

    `core_verdict` is a *view* of the already-computed deterministic result.
    It grants no new authority: the `exit_code` is the same value that appears
    at the report level, and the counts come from the existing `verdicts` dict.
    The tier is derived from the deterministic exit_code so it always matches
    the fail-closed 0/1/2/99 contract.
    """
    if exit_code == 0:
        tier = "clean"
    elif exit_code == 1:
        tier = "warn"
    else:
        # 2 (critical) or 99 (scanner failure) are both deterministic BLOCKs.
        tier = "block"

    return {
        "tier": tier,
        "exit_code": exit_code,
        "block": verdicts.get("block", 0),
        "warn": verdicts.get("warn", 0),
        "info": verdicts.get("info", 0),
        "suppressed": verdicts.get("suppressed", 0),
        "total": summary.get("total", 0),
    }


def _invoke_adjudication_bridge(all_findings):
    """Run scripts/adjudication_bridge.py out-of-process when adjudication
    commands are configured.  Returns a JSON result dict or None when the
    feature is not enabled (env vars unset).  Failures are swallowed and
    reported as status='unavailable' so they never affect exit code."""
    confirm_cmd = os.environ.get("REPO_FORENSICS_CONFIRM_COMMAND")
    refute_cmd = os.environ.get("REPO_FORENSICS_REFUTE_COMMAND")
    if not confirm_cmd and not refute_cmd:
        return None

    bridge_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "adjudication_bridge.py")
    if not os.path.exists(bridge_path):
        return {"status": "unavailable", "annotations": []}

    payload = json.dumps({"findings": all_findings}, separators=(",", ":"))
    # Sanitized environment: PATH plus the two opt-in command variables.
    env = {"PATH": os.environ.get("PATH", "")}
    if confirm_cmd:
        env["REPO_FORENSICS_CONFIRM_COMMAND"] = confirm_cmd
    if refute_cmd:
        env["REPO_FORENSICS_REFUTE_COMMAND"] = refute_cmd

    try:
        proc = subprocess.run(
            [sys.executable, bridge_path],
            input=payload, capture_output=True, text=True,
            timeout=30, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[!] Adjudication bridge failed: {exc}", file=sys.stderr)
        return {"status": "unavailable", "annotations": []}

    if proc.returncode != 0:
        return {"status": "unavailable", "annotations": []}

    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"status": "unavailable", "annotations": []}

    if not isinstance(result, dict):
        return {"status": "unavailable", "annotations": []}

    annotations = result.get("annotations", [])
    if not isinstance(annotations, list):
        annotations = []
    return {
        "status": result.get("status", "unavailable"),
        "annotations": annotations,
    }


def build_enrichment_status(scanners, all_findings):
    """Aggregate scanner-level enrichment-degraded signals into a report key.

    enrichment_status is advisory and additive: it may escalate or annotate, but
    it must never downgrade a BLOCK, clear a finding, or lower exit_code.
    It surfaces dependency-vuln and rulepack-feed degradation.
    """
    vulns = "complete"
    rulepack_feed = "ok"
    dead_anchors = "complete"
    capability_gaps = []
    seen_gaps = set()

    gap_categories = {
        "NC", "nc", "unchecked", "provenance-unchecked",
        "unsupported-archive-type", "archive-scan-incomplete",
        "decode-scan-incomplete", "unanalyzable-bytecode",
        "opaque-bytecode-with-source", "opaque-archive",
    }

    def add_gap(scanner, reason, category="capability"):
        key = (str(scanner), str(reason), str(category))
        if key in seen_gaps:
            return
        seen_gaps.add(key)
        capability_gaps.append({
            "scanner": key[0], "reason": key[1], "category": key[2],
        })

    for scanner in scanners:
        name = scanner.get("name", "unknown")
        if scanner.get("parse_error"):
            add_gap(name, scanner["parse_error"], "scanner-error")
        stderr = (scanner.get("stderr") or "").lower()
        for marker, reason in (
            ("rate limit", "rate-limited"), ("429", "rate-limited"),
            ("github_token", "missing-github-token"),
            ("not found", "missing-tool"), ("offline", "offline"),
        ):
            if marker in stderr:
                add_gap(name, reason)

    degraded_findings = [
        f for f in all_findings
        if f.get("category") == "enrichment-degraded"
    ]

    for f in degraded_findings:
        title = (f.get("title") or "").lower()
        desc = (f.get("description") or "").lower()
        scanner = f.get("scanner", "unknown")
        add_gap(scanner, f.get("title", "enrichment degraded"), f.get("category"))

        if "offline" in title or "offline" in desc:
            vulns = "offline"
        elif "vulnerability" in title or "vulnerability" in desc:
            vulns = "degraded"
        if "rulepack" in title or "rulepack" in desc:
            rulepack_feed = "degraded"
        if "dead" in title or "dead-anchor" in title or "dead_anchor" in title:
            dead_anchors = "offline"

    for finding in all_findings:
        category = finding.get("category", "")
        description = (finding.get("description") or "").lower()
        if category in gap_categories:
            add_gap(finding.get("scanner", "unknown"), category, category)
        elif "couldn't check" in description or "could not check" in description:
            add_gap(finding.get("scanner", "unknown"), "could-not-check", category or "capability")
        freshness = finding.get("freshness_status")
        if freshness in ("STALE", "RECHECK_REQUIRED"):
            add_gap(finding.get("scanner", "unknown"), freshness.lower(), "freshness")
            scanner = finding.get("scanner", "unknown")
            if scanner == "dead_anchors":
                dead_anchors = freshness
            elif scanner == "dependencies" and vulns != "offline":
                vulns = freshness

    needs_adjudication = any(f.get("needs_adjudication") for f in all_findings)
    adjudication = "pending" if needs_adjudication else "available"
    advisory_annotations = []

    if needs_adjudication:
        bridge_result = _invoke_adjudication_bridge(all_findings)
        if bridge_result is not None:
            advisory_annotations = bridge_result.get("annotations", []) or []
            bridge_status = bridge_result.get("status", "unavailable")
            if bridge_status == "unavailable":
                adjudication = "unavailable"
                advisory_annotations = []
            elif any(
                any(lane.get("error") == "unavailable"
                    for lane in a.get("lanes", {}).values())
                for a in advisory_annotations
            ):
                # One or both advisory lanes failed (command absent / non-zero /
                # timeout / JSON parse failure). Treat the whole bridge as
                # unavailable and discard the partial error annotations.
                adjudication = "unavailable"
                advisory_annotations = []
            elif bridge_status == "available" and advisory_annotations:
                if any(a.get("outcome") == "agree_real" for a in advisory_annotations):
                    adjudication = "available"
                else:
                    adjudication = "unresolved"
            else:
                adjudication = "unresolved"

    if vulns == "offline" or dead_anchors == "offline":
        overall = "OFFLINE"
    elif capability_gaps or vulns != "complete" or rulepack_feed != "ok" or dead_anchors != "complete":
        overall = "DEGRADED"
    else:
        overall = "COMPLETE"

    return {
        "overall": overall,
        "vulns": vulns,
        "rulepack_feed": rulepack_feed,
        "dead_anchors": dead_anchors,
        "adjudication": adjudication,
        "adjudication_annotations": advisory_annotations,
        "capability_gaps": capability_gaps,
    }


def apply_evidence_caps(all_findings):
    """Cap finding severity based on evidence_class (Track A / P0).

    Rules:
      - inferred:    cap at LOW  (descriptions, mentions, comments, prose)
      - structural:  cap at LOW  (manifest drift, integrity, provenance, dead
                                  anchors, oversize — structure anomalies only)
      - direct:      no cap      (real code, config, agent directives)

    A finding whose evidence_class is empty or unrecognised is treated as
    direct (backward compat: legacy scanner JSON predating Track A has no
    evidence_class key, and those findings were already severity-correct by
    construction). This means the cap only ever LOWERS severity for findings
    the central inferer tagged as inferred/structural — it never raises.

    The original severity is preserved in an `original_severity` key (added
    only when a cap was applied) so the report is auditable: a reader can see
    what the scanner originally claimed and what the evidence model allowed.

    NO SILENT CAP: capping a critical/high was the last demotion path
    that left no trace of its own (suppression re-emits a guard, capability
    declarations are annotation-only). Every such demotion now appends one
    aggregated `meta` guard finding naming what was demoted, so a reader can
    always see that a real finding was graded down and why.

    Operates in-place on dict findings. Returns all_findings for chaining.
    """
    demoted = []
    for f in all_findings:
        ec = f.get("evidence_class", "")
        if ec not in ("inferred", "structural"):
            # direct or unknown -> no cap (backward compat).
            continue
        sev = f.get("severity", "low")
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER["low"]:
            f["original_severity"] = sev
            f["severity"] = "low"
            # Confidence follows severity so verdict-tier messaging stays
            # consistent with the capped severity (KTD-7 / KTD-8).
            conf = f.get("confidence")
            if conf is None or float(conf) > _SEVERITY_CONFIDENCE["low"]:
                f["confidence"] = _SEVERITY_CONFIDENCE["low"]
            if sev in ("critical", "high"):
                demoted.append((sev, ec, f.get("file", ""),
                                f.get("rule_id", "") or f.get("title", "")))

    if demoted:
        listing = "; ".join(
            f"{sev} {ident or '?'} in {path or '?'} ({ec})"
            for sev, ec, path, ident in demoted[:10])
        more = f" (+{len(demoted) - 10} more)" if len(demoted) > 10 else ""
        all_findings.append({
            "scanner": "meta",
            # LOW on purpose: the evidence model exists so prose that MENTIONS
            # a dangerous pattern does not drive the exit code, and this guard
            # fires on every such mention. Its job is visibility, not the
            # verdict — the exploitable demotion paths (attacker-chosen folder
            # and archive-member names) are closed at the source, in
            # _context_gate and scan_archive.
            "severity": "low",
            "title": "Evidence model capped a critical/high finding",
            "description": (
                f"{len(demoted)} finding(s) were graded down to LOW because "
                f"their evidence class is inferred/structural (prose, comment, "
                f"or structure-only signal) rather than direct executable "
                f"evidence. Review each: {listing}{more}."
            ),
            "file": "", "line": 0,
            "snippet": f"{len(demoted)} evidence-capped finding(s)",
            "category": "configuration",
            "rule_id": "", "confidence": _SEVERITY_CONFIDENCE["low"],
            "evidence_class": "direct",
        })
    return all_findings


def apply_capability_declarations(all_findings, repo_path):
    """Annotate findings whose behavior matches a declared capability.

    Report-only: a capability declaration NEVER changes a finding's severity,
    verdict tier, or the report exit code. It may only add `declared_capability`
    and `declared_capability_reason` to a matching finding for the human report.
    A self-declared capability therefore cannot soften a BLOCK; every
    attacker-controlled declaration that previously downgraded a real
    exfiltration / shell-injection / obfuscation / secret finding now leaves
    the verdict untouched.

    Non-downgradable findings (directive-class, known-IOC, CVE/KEV, and the
    high-signal malicious-behavior categories and primary scanners enumerated
    in forensics_core._is_non_downgradable) are never annotated, because a
    self-declared capability does not reframe confirmed malicious behavior.

    Returns (all_findings, capability_ledger) where capability_ledger is a
    dict with the declaration source, declared capabilities, and a list of
    annotations (each with finding_id, capability, and reason).
    """
    try:
        import forensics_core as core
    except ImportError:
        return all_findings, {"declared": False, "source": "",
                              "capabilities": [], "annotations": [], "error": None}

    declaration = core.load_capability_declaration(repo_path)
    ledger = {
        "declared": len(declaration["capabilities"]) > 0,
        "source": declaration["source"],
        "capabilities": declaration["capabilities"],
        "annotations": [],
        "error": declaration.get("error"),
    }

    if not declaration["capabilities"]:
        return all_findings, ledger

    cap_names = {c["name"] for c in declaration["capabilities"]}
    cap_reasons = {c["name"]: c["reason"] for c in declaration["capabilities"]}

    for f in all_findings:
        if core._is_non_downgradable(f):
            continue
        matched_cap = None
        for cap in cap_names:
            if core._capability_matches_finding(cap, f):
                matched_cap = cap
                break
        if matched_cap is None:
            continue
        f["declared_capability"] = matched_cap
        f["declared_capability_reason"] = cap_reasons.get(matched_cap, "")
        ledger["annotations"].append({
            "finding_id": f.get("finding_id", ""),
            "capability": matched_cap,
            "reason": cap_reasons.get(matched_cap, ""),
            "file": f.get("file", ""),
            "rule_id": f.get("rule_id", ""),
            "severity": f.get("severity", ""),
        })

    return all_findings, ledger


def run_correlation_pass(all_findings, repo_path=None):
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
        correlated = core.correlate(
            core.findings_from_dicts_iter(all_findings), repo_path=repo_path
        )
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

    # Registry-hijack raw correlation (GAP 3). Reads config/script files directly
    # to flag package-registry redirection (MEDIUM) and escalate to HIGH when it
    # co-occurs with reviewer-assurance prose or an install-time script. The
    # assurance signal is computed here, never emitted standalone, so benign
    # "standard practice" prose never produces a finding on its own.
    try:
        import forensics_core as _core_reg
        registry_hits = _core_reg.detect_registry_hijack_raw(repo_path)
        if registry_hits:
            reg_dicts = [f.to_dict() for f in registry_hits]
            all_findings.extend(reg_dicts)
            scanners.append({
                "name": "registry_hijack",
                "exit_code": 0,
                "parse_error": None,
                "finding_count": len(reg_dicts),
                "findings": reg_dicts,
            })
    except (ImportError, OSError) as e:
        print(f"[!] Registry-hijack scan failed: {e}", file=sys.stderr)

    # Run correlation engine on aggregated findings. Correlated findings
    # (Rules 1-19) are added AFTER the scanner loop so they can see every
    # scanner's output together. Without this, Rule 19 Lethal Trifecta
    # (exec + network + credential read) and the other 18 rules never fire
    # in the primary run_forensics.sh workflow.
    correlated_findings = run_correlation_pass(all_findings, repo_path=repo_path)
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

    # Raw trifecta leaves exist solely to feed correlation. They must never
    # affect user-visible findings, counts, verdicts, or scanner sections.
    all_findings = [
        finding for finding in all_findings
        if finding.get("scanner") != "trifecta_raw"
    ]
    scanners = [scanner for scanner in scanners if scanner.get("name") != "trifecta_raw"]

    # Per-finding suppression (U1). User-suppressed findings are pulled out of
    # the active set BEFORE summary/exit-code computation so they cannot affect
    # severity counts or the 0/1/2/99 contract, but they remain visible under
    # the top-level `suppressed` key for auditability. Abuse-guard findings
    # (critical-rule suppression, mass suppression) are added to the active set.
    all_findings, suppressed_findings = apply_suppressions(all_findings, repo_path)

    # Path-glob .forensicsignore suppression is INVISIBLE to apply_suppressions:
    # globs are consumed silently inside each scanner's walk_repo, so the hidden
    # findings never exist to partition. Surface them here as live meta findings
    # so a broad suppressor (`*`, `skills/`, `*.[s]h`) becomes a CRITICAL that
    # drives exit 2, and any path-glob ignore leaves a counted, visible trace.
    # Without this wiring a planted .forensicsignore silently zeroes the report
    # (warn_forensicsignore was previously never called by any scan path).
    try:
        import forensics_core as _core_ign
        all_findings.extend(f.to_dict() for f in _core_ign.warn_forensicsignore(repo_path))
    except (ImportError, OSError) as e:
        print(f"[!] .forensicsignore warning skipped: {e}", file=sys.stderr)

    # Mark WARN-tier (non-correlation) findings for LLM adjudication (U8).
    # Additive per-finding flag; does not touch severity counts or exit code.
    mark_adjudication(all_findings)

    # Evidence model severity capping. Inferred and structural findings cap
    # at LOW; direct findings (including directive-class detectors like
    # prompt-injection) are unaffected. Runs AFTER suppression and
    # adjudication marking so the cap shapes the final severity that drives
    # summary/exit-code, but BEFORE sort/summary so counts reflect the cap.
    apply_evidence_caps(all_findings)

    # Capability declaration ledger. A first-party .forensics-capabilities
    # file is parsed and used ONLY to annotate matching findings for the human
    # report. It never changes severity, verdict tier, or exit code, so an
    # attacker-controlled declaration cannot soften a BLOCK. Runs AFTER
    # evidence caps so the annotation is stamped on the final severity, and
    # BEFORE sort/summary so the ledger reflects every annotated finding.
    all_findings, capability_ledger = apply_capability_declarations(
        all_findings, repo_path
    )

    # Coverage-honesty gate. coverage_status is computed BEFORE the
    # summary so a blocking gap — an unopened .7z, a zip nested past MAX_DEPTH,
    # a .pyc padded past the size cap, base64 nested past the decode limit, the
    # unsampled middle of an oversized file — becomes a real MEDIUM finding and
    # therefore floors the exit code at 1. Previously each of these emitted only
    # a LOW note and the report exited 0 over a live, uninspected payload.
    coverage_status = build_coverage_status(scanners, all_findings)
    all_findings.extend(build_coverage_gap_findings(coverage_status))

    all_findings.sort(key=lambda item: -SEVERITY_ORDER.get(item.get("severity", "low"), 0))
    summary = build_summary(all_findings)
    verdicts = build_verdicts(all_findings, suppressed_findings)
    exit_code = calculate_report_exit_code(summary, scanners)

    # Purely additive enrichment verdicts.
    core_verdict = build_core_verdict(summary, verdicts, exit_code)
    enrichment_status = build_enrichment_status(scanners, all_findings)

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
        "coverage_status": coverage_status,
        "core_verdict": core_verdict,
        "enrichment_status": enrichment_status,
        "capability_ledger": capability_ledger,
    }


def format_report_as_text(report):
    """Render an aggregated report in the text format mirrored from
    forensics_core.format_findings() and the existing run_forensics.sh
    output. Used when the caller asked for text output but we still need
    the JSON-internal pipeline to run correlation."""

    # B1 fix: all finding-derived text must be sanitized before embedding in the
    # text report.  adjudication.sanitize_snippet strips control chars, BIDI,
    # ANSI sequences, and collapses line-breaks so attacker content in snippets,
    # titles, or descriptions cannot produce an unprefixed top-level line above
    # the adjudication block.
    try:
        import adjudication as _adj
        _sanitize = _adj.sanitize_snippet
    except ImportError:
        import re as _re
        def _sanitize(text, max_len=300):
            if not isinstance(text, str):
                return ""
            cleaned = _re.sub(r"[\x00-\x1f\x7f\x80-\x9f\r\n‪-‮⁦-⁩]", "", text)
            cleaned = _re.sub(r"\s+", " ", cleaned).strip()
            return cleaned[:max_len]

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
                title = _sanitize(f.get('title', '') or '', max_len=160)
                desc = _sanitize(f.get('description', '') or '', max_len=300)
                lines.append(f"  {color}[{sev.upper()}]{RESET} {title}")
                lines.append(f"         {loc}")
                lines.append(f"         {desc}")
                snip = f.get("snippet", "")
                if snip:
                    lines.append(f"         {_sanitize(snip, max_len=120)}")
                tm = []
                if f.get("attacker"):
                    tm.append(f"attacker={f['attacker']}")
                if f.get("boundary"):
                    tm.append(f"boundary={f['boundary']}")
                if f.get("asset"):
                    tm.append(f"asset={f['asset']}")
                if tm:
                    lines.append(f"         threat model: {' | '.join(tm)}")
    summary = report["summary"]
    lines.append("")
    lines.append("==========================================")
    lines.append(
        f"  VERDICT: {summary['total']} findings "
        f"({summary['critical']} critical, {summary['high']} high, "
        f"{summary['medium']} medium, {summary['low']} low)"
    )

    core_verdict = report.get("core_verdict")
    if core_verdict:
        lines.append(
            f"  CORE VERDICT: {core_verdict['tier']} "
            f"(exit_code={core_verdict['exit_code']})"
        )

    coverage_status = report.get("coverage_status")
    if coverage_status:
        overall = coverage_status["overall"]
        lines.append(f"  COVERAGE: {overall}")
        for name, status in coverage_status.get("per_scanner", {}).items():
            lines.append(f"    {name}: {status['status']}")
        if overall not in ("COMPLETE",):
            guidance = "  Deep scan guidance: re-run with the full pipeline"
            if overall == "UNSUPPORTED":
                guidance += " after extracting unsupported archives"
            elif overall == "INCOMPLETE":
                guidance += " after removing budget caps or expanding file support"
            lines.append(guidance)

    enrichment_status = report.get("enrichment_status")
    if enrichment_status:
        lines.append(f"  ENRICHMENT: {enrichment_status['overall']}")
        es = enrichment_status
        lines.append(
            f"    vulns={es['vulns']} rulepack_feed={es['rulepack_feed']} "
            f"dead_anchors={es['dead_anchors']} adjudication={es['adjudication']}"
        )

    capability_ledger = report.get("capability_ledger")
    if capability_ledger and capability_ledger.get("declared"):
        lines.append(f"  CAPABILITIES: declared ({capability_ledger.get('source', '')})")
        for cap in capability_ledger.get("capabilities", []):
            reason = cap.get("reason", "")
            lines.append(f"    {cap['name']}: {reason}" if reason else f"    {cap['name']}")
        annotations = capability_ledger.get("annotations", [])
        if annotations:
            lines.append(f"    annotations: {len(annotations)}")
            for dg in annotations:
                lines.append(
                    f"      {dg.get('rule_id', '')} -> {dg['capability']}"
                    f" ({dg.get('file', '')})"
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
    # Support three CLI shapes:
    #   aggregate_json.py <tmpdir> <repo_path> <skill_scan> <exit_code_file>  [JSON output, original]
    #   aggregate_json.py --text <tmpdir> <repo_path> <skill_scan> <exit_code_file>  [text output]
    #   aggregate_json.py --sarif <tmpdir> <repo_path> <skill_scan> <exit_code_file>  [SARIF 2.1.0 output]
    if len(argv) == 6 and argv[1] == "--text":
        text_mode = True
        sarif_mode = False
        _, _, tmpdir, repo_path, skill_scan, exit_code_file = argv
    elif len(argv) == 6 and argv[1] == "--sarif":
        text_mode = False
        sarif_mode = True
        _, _, tmpdir, repo_path, skill_scan, exit_code_file = argv
    elif len(argv) == 5:
        text_mode = False
        sarif_mode = False
        _, tmpdir, repo_path, skill_scan, exit_code_file = argv
    else:
        raise SystemExit(
            "Usage: aggregate_json.py [--text|--sarif] <tmpdir> <repo_path> "
            "<skill_scan> <exit_code_file>"
        )

    report = build_report(tmpdir, repo_path, skill_scan)

    if os.environ.get("REPO_FORENSICS_HISTORY") == "1":
        try:
            import scan_history
            scan_history.record_report_safely(
                repo_path, report, os.environ.get("REPO_FORENSICS_HISTORY_DB")
            )
        except ImportError as exc:
            print(f"[!] Scan history unavailable: {exc}", file=sys.stderr)

    if text_mode:
        print(format_report_as_text(report))
    elif sarif_mode:
        # Lazy import so the rule_loader dependency stays out of the text/json
        # paths (KTD-14 leaf rule: sarif_export owns the rule_loader import).
        import sarif_export
        print(json.dumps(sarif_export.report_to_sarif(report), indent=2))
    else:
        print(json.dumps(report, indent=2))

    exit_code = report["exit_code"]
    with open(exit_code_file, "w", encoding="utf-8") as handle:
        handle.write(str(exit_code if exit_code in VALID_EXIT_CODES else 99))


if __name__ == "__main__":
    main(sys.argv)
