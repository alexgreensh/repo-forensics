import json

from scripts import adjudication


def warn(snippet="call(input())"):
    return {
        "scanner": "static", "rule_id": "R-1", "title": "dynamic call",
        "description": "executes input", "file": "a.py", "line": 1,
        "snippet": snippet, "confidence": 0.8, "needs_adjudication": True,
    }


def response(decision):
    def run(role, prompt):
        evidence = json.loads(prompt.split("EVIDENCE=", 1)[1])
        return {"evidence_id": evidence["evidence_id"], "decision": decision(role), "reason": "evidence"}
    return run


def test_confirmed_annotation_remains_advisory():
    finding = warn()
    before = dict(finding)
    result = adjudication.build_advisory_annotations(
        [finding], response(lambda role: "real" if role == "confirm" else "unresolved")
    )
    assert result["annotations"][0]["outcome"] == "agree_real"
    assert finding == before


def test_refuter_disagreement_is_unresolved():
    result = adjudication.build_advisory_annotations(
        [warn()], response(lambda role: "real" if role == "confirm" else "not_real")
    )
    assert result["annotations"][0]["outcome"] == "UNRESOLVED"


def test_missing_service_is_unavailable():
    assert adjudication.build_advisory_annotations([warn()])["status"] == "unavailable"
