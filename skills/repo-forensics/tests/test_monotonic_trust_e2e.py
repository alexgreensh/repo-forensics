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
