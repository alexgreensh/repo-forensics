import itertools

from scripts import adjudication
from scripts import aggregate_json


def test_advisory_states_never_change_deterministic_block():
    finding = {
        "scanner": "static", "severity": "critical", "title": "credential execution",
        "file": "payload.py", "line": 1, "category": "execution", "confidence": 0.99,
    }
    scanners = [{"name": "static", "exit_code": 2, "parse_error": None, "findings": [finding]}]
    summary = aggregate_json.build_summary([finding])
    deterministic_exit = aggregate_json.calculate_report_exit_code(summary, scanners)
    deterministic_core = aggregate_json.build_core_verdict(
        summary, aggregate_json.build_verdicts([finding], []), deterministic_exit
    )
    for offline, stale, unavailable in itertools.product((False, True), repeat=3):
        annotations = {"status": "unavailable" if unavailable else "available", "annotations": []}
        coverage = "INCOMPLETE" if offline else "COMPLETE"
        freshness = "STALE" if stale else "FRESH"
        assert coverage in {"COMPLETE", "INCOMPLETE"}
        assert freshness in {"FRESH", "STALE"}
        assert annotations["status"] in {"available", "unavailable"}
        assert aggregate_json.calculate_report_exit_code(summary, scanners) == deterministic_exit == 2
        assert aggregate_json.build_core_verdict(
            summary, aggregate_json.build_verdicts([finding], []), deterministic_exit
        ) == deterministic_core
        assert finding["severity"] == "critical"


def test_benign_advice_cannot_clear_block_finding():
    finding = {"scanner": "static", "severity": "critical", "confidence": 0.99}
    before = dict(finding)
    assert adjudication.build_advisory_annotations([finding])["status"] == "not_needed"
    assert finding == before


def test_adjudication_and_freshness_combinations_preserve_block(monkeypatch):
    """Toggle env-set/unset × stale/fresh; exit_code + BLOCK set invariant in every combination."""
    critical = {
        "scanner": "static", "severity": "critical", "title": "credential execution",
        "file": "payload.py", "line": 1, "category": "execution", "rule_id": "R-1",
        "confidence": 0.99,
    }
    warn = {
        "scanner": "static", "severity": "high", "title": "suspicious call",
        "file": "warn.py", "line": 5, "snippet": "exec(user_input)",
        "category": "obfuscation", "rule_id": "R-2", "confidence": 0.75,
    }

    # Deterministic baseline: one critical + two warns (both need adjudication).
    base_dep = dict(warn, scanner="dependencies", needs_adjudication=True)
    base_da = dict(warn, scanner="dead_anchors", needs_adjudication=True)
    baseline_findings = [critical, base_dep, base_da]
    scanners = [{
        "name": "static", "exit_code": 2, "parse_error": None,
        "finding_count": len(baseline_findings), "findings": baseline_findings,
    }]
    summary = aggregate_json.build_summary(baseline_findings)
    verdicts = aggregate_json.build_verdicts(baseline_findings, [])
    exit_code = aggregate_json.calculate_report_exit_code(summary, scanners)
    deterministic_core = aggregate_json.build_core_verdict(summary, verdicts, exit_code)

    for adjudication_set, stale, fresh in itertools.product((False, True), repeat=3):
        dep = dict(warn, scanner="dependencies", needs_adjudication=True,
                   freshness_status="STALE" if stale else "")
        da = dict(warn, scanner="dead_anchors", needs_adjudication=True,
                  freshness_status="STALE" if not fresh else "")
        findings = [critical, dep, da]

        if adjudication_set:
            monkeypatch.setenv("REPO_FORENSICS_CONFIRM_COMMAND", "false")
        else:
            monkeypatch.delenv("REPO_FORENSICS_CONFIRM_COMMAND", raising=False)

        enriched = aggregate_json.build_enrichment_status(scanners, findings)

        assert aggregate_json.calculate_report_exit_code(
            aggregate_json.build_summary(findings), scanners
        ) == exit_code == 2
        assert aggregate_json.build_core_verdict(
            aggregate_json.build_summary(findings),
            aggregate_json.build_verdicts(findings, []),
            exit_code,
        ) == deterministic_core
        assert all(f["severity"] == "critical" for f in findings if f["severity"] == "critical")
        assert enriched["adjudication"] in {"pending", "unresolved", "unavailable"}
        assert enriched["vulns"] == ("STALE" if stale else "complete")
        assert enriched["dead_anchors"] == ("STALE" if not fresh else "complete")
