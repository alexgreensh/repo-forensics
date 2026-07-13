from scripts import aggregate_json


def test_capability_reasons_are_deduplicated():
    scanners = [{"name": "anchors", "stderr": "HTTP 429 rate limit"}]
    findings = [
        {"scanner": "anchors", "category": "NC", "description": "couldn't check"},
        {"scanner": "anchors", "category": "NC", "description": "couldn't check"},
    ]
    status = aggregate_json.build_enrichment_status(scanners, findings)
    assert status["overall"] == "DEGRADED"
    keys = [(gap["scanner"], gap["reason"], gap["category"]) for gap in status["capability_gaps"]]
    assert len(keys) == len(set(keys))
    assert ("anchors", "rate-limited", "capability") in keys


def test_capability_gaps_do_not_mutate_findings():
    findings = [{"scanner": "deps", "category": "unchecked", "severity": "critical"}]
    before = [dict(findings[0])]
    aggregate_json.build_enrichment_status([], findings)
    assert findings == before
