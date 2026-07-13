import json

from scripts import adjudication_bridge


def test_missing_lane_fails_closed_to_unavailable(monkeypatch):
    monkeypatch.delenv("REPO_FORENSICS_CONFIRM_COMMAND", raising=False)
    try:
        adjudication_bridge.command_runner("confirm", "evidence")
    except RuntimeError as exc:
        assert "unavailable" in str(exc)
    else:
        raise AssertionError("missing command must not produce an annotation")


def test_lane_receives_prompt_on_standard_input(monkeypatch):
    monkeypatch.setenv(
        "REPO_FORENSICS_CONFIRM_COMMAND",
        "python3 -c 'import json,sys; print(json.dumps({\"evidence_id\": \"x\", \"decision\": \"real\", \"reason\": sys.stdin.read()}))'",
    )
    result = adjudication_bridge.command_runner("confirm", "bounded evidence")
    assert result["reason"] == "bounded evidence"
