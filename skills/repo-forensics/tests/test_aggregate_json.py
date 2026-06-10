"""Unit tests for aggregate_json.py."""

import json
import os

import aggregate_json as module


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def test_parse_scanner_payload_empty_output():
    findings, error = module.parse_scanner_payload("")
    assert findings == []
    assert error is None


def test_parse_scanner_payload_valid_json_list():
    raw = json.dumps([{"severity": "high", "title": "A"}], indent=2)
    findings, error = module.parse_scanner_payload(raw)
    assert error is None
    assert findings[0]["title"] == "A"


def test_parse_scanner_payload_with_leading_banner_fails():
    raw = "[*] Scanning repo...\n" + json.dumps([{"severity": "high", "title": "A"}], indent=2)
    findings, error = module.parse_scanner_payload(raw)
    assert findings == []
    assert "Invalid JSON output" in error


def test_parse_scanner_payload_malformed_json():
    findings, error = module.parse_scanner_payload("{not json")
    assert findings == []
    assert "Invalid JSON output" in error


def test_build_report_multiple_scanners_with_mixed_results(tmp_path):
    _write(tmp_path / "a.out", json.dumps([{"severity": "high", "title": "A"}]))
    _write(tmp_path / "a.err", "")
    _write(tmp_path / "a.exit", "1")

    _write(tmp_path / "b.out", json.dumps([{"severity": "critical", "title": "B"}]))
    _write(tmp_path / "b.err", "debug warning")
    _write(tmp_path / "b.exit", "2")

    report = module.build_report(str(tmp_path), "/repo", "false")

    assert report["mode"] == "full"
    assert report["scanner_count"] == 2
    assert report["summary"]["critical"] == 1
    assert report["summary"]["high"] == 1
    assert report["exit_code"] == 2
    assert report["findings"][0]["severity"] == "critical"
    assert report["scanners"][1]["stderr"] == "debug warning"


def test_build_report_malformed_scanner_output_surfaces_parse_error(tmp_path):
    _write(tmp_path / "bad.out", "{oops")
    _write(tmp_path / "bad.err", "")
    _write(tmp_path / "bad.exit", "1")

    report = module.build_report(str(tmp_path), "/repo", "true")

    assert report["mode"] == "skill"
    assert report["summary"]["total"] == 0
    assert report["exit_code"] == 99
    assert report["scanners"][0]["parse_error"] == "Invalid JSON output: Expecting property name enclosed in double quotes"


def test_build_report_missing_output_with_nonzero_exit_fails_closed(tmp_path):
    _write(tmp_path / "bad.out", "")
    _write(tmp_path / "bad.err", "Traceback")
    _write(tmp_path / "bad.exit", "1")

    report = module.build_report(str(tmp_path), "/repo", "false")

    assert report["exit_code"] == 99
    assert report["scanners"][0]["parse_error"] == "No JSON output captured from scanner"


# ---------------------------------------------------------------------------
# U1: verdict tiers
# ---------------------------------------------------------------------------


def test_verdict_tier_thresholds():
    assert module.verdict_tier(0.95) == "block"
    assert module.verdict_tier(0.92) == "block"
    assert module.verdict_tier(0.75) == "warn"
    assert module.verdict_tier(0.60) == "warn"
    assert module.verdict_tier(0.45) == "info"
    assert module.verdict_tier(0.30) == "info"
    assert module.verdict_tier(0.20) == "suppressed"


def test_verdict_tier_user_suppressed_overrides():
    assert module.verdict_tier(0.99, suppressed=True) == "suppressed"


def test_build_verdicts_counts_by_tier():
    active = [
        {"severity": "critical", "confidence": 0.95},
        {"severity": "high", "confidence": 0.75},
        {"severity": "medium", "confidence": 0.45},
        {"severity": "low", "confidence": 0.20},
    ]
    verdicts = module.build_verdicts(active, [])
    assert verdicts == {"block": 1, "warn": 1, "info": 1, "suppressed": 1}


def test_build_verdicts_includes_user_suppressed():
    active = [{"severity": "critical", "confidence": 0.95}]
    suppressed = [{"severity": "high", "confidence": 0.80}, {"severity": "low"}]
    verdicts = module.build_verdicts(active, suppressed)
    assert verdicts["block"] == 1
    assert verdicts["suppressed"] == 2


def test_finding_confidence_fills_from_severity():
    assert module._finding_confidence({"severity": "critical"}) == 0.95
    assert module._finding_confidence({"severity": "low", "confidence": 0.0}) == 0.40
    assert module._finding_confidence({"severity": "low", "confidence": 0.7}) == 0.7


def test_report_has_verdicts_and_suppressed_keys(tmp_path):
    _write(tmp_path / "a.out", json.dumps([
        {"scanner": "secrets", "severity": "critical", "title": "Key",
         "file": "x.py", "line": 1, "confidence": 0.95},
    ]))
    _write(tmp_path / "a.err", "")
    _write(tmp_path / "a.exit", "2")
    report = module.build_report(str(tmp_path), str(tmp_path), "false")
    assert "verdicts" in report
    assert "suppressed" in report
    assert report["verdicts"]["block"] >= 1
    assert report["suppressed"] == []


# ---------------------------------------------------------------------------
# U1: per-finding suppression + abuse guards
# ---------------------------------------------------------------------------


def _scan_dir(tmp_path):
    """A separate empty repo dir used as the scan target (no trifecta noise)."""
    d = tmp_path / "repo"
    d.mkdir()
    return d


def test_suppression_excludes_from_summary_and_exit_but_keeps_audit(tmp_path):
    repo = _scan_dir(tmp_path)
    (repo / ".forensicsignore").write_text("rule:SC-KEY-001:src/**\n")
    _write(tmp_path / "a.out", json.dumps([
        {"scanner": "secrets", "severity": "high", "title": "Suppress me",
         "file": "src/app.py", "line": 1, "rule_id": "SC-KEY-001", "confidence": 0.80},
        {"scanner": "secrets", "severity": "critical", "title": "Stays",
         "file": "src/db.py", "line": 2, "rule_id": "SC-CRIT-001", "confidence": 0.95},
    ]))
    _write(tmp_path / "a.err", "")
    _write(tmp_path / "a.exit", "2")
    report = module.build_report(str(tmp_path), str(repo), "false")

    # Suppressed finding gone from summary + active findings
    assert report["summary"]["high"] == 0
    suppressed_titles = [f["title"] for f in report["suppressed"]]
    assert "Suppress me" in suppressed_titles
    active_titles = [f["title"] for f in report["findings"]]
    assert "Suppress me" not in active_titles
    # Critical still fires => exit 2
    assert "Stays" in active_titles
    assert report["exit_code"] == 2
    assert report["summary"]["critical"] == 1


def test_suppression_glob_scopes_to_path(tmp_path):
    repo = _scan_dir(tmp_path)
    (repo / ".forensicsignore").write_text("rule:SC-KEY-001:tests/**\n")
    _write(tmp_path / "a.out", json.dumps([
        {"scanner": "secrets", "severity": "low", "title": "In tests",
         "file": "tests/fixture.py", "line": 1, "rule_id": "SC-KEY-001", "confidence": 0.40},
        {"scanner": "secrets", "severity": "low", "title": "In src",
         "file": "src/app.py", "line": 1, "rule_id": "SC-KEY-001", "confidence": 0.40},
    ]))
    _write(tmp_path / "a.err", "")
    _write(tmp_path / "a.exit", "1")
    report = module.build_report(str(tmp_path), str(repo), "false")

    suppressed_titles = [f["title"] for f in report["suppressed"]]
    active_titles = [f["title"] for f in report["findings"]]
    assert "In tests" in suppressed_titles
    assert "In src" in active_titles


def test_suppressing_critical_rule_raises_tampering_finding(tmp_path):
    repo = _scan_dir(tmp_path)
    (repo / ".forensicsignore").write_text("rule:SC-CRIT-001\n")
    _write(tmp_path / "a.out", json.dumps([
        {"scanner": "secrets", "severity": "critical", "title": "Critical thing",
         "file": "src/db.py", "line": 2, "rule_id": "SC-CRIT-001", "confidence": 0.95},
    ]))
    _write(tmp_path / "a.err", "")
    _write(tmp_path / "a.exit", "2")
    report = module.build_report(str(tmp_path), str(repo), "false")

    titles = [f["title"] for f in report["findings"]]
    assert ".forensicsignore: Critical Rule Suppression" in titles
    tamper = [f for f in report["findings"]
              if f["title"] == ".forensicsignore: Critical Rule Suppression"][0]
    assert tamper["severity"] == "critical"
    # The original critical finding is suppressed; the tampering guard keeps exit 2
    assert report["exit_code"] == 2


def test_mass_suppression_raises_high_finding(tmp_path):
    repo = _scan_dir(tmp_path)
    lines = "".join(f"rule:R-LOW-{i:03d}\n" for i in range(1, 7))  # 6 rule: lines
    (repo / ".forensicsignore").write_text(lines)
    _write(tmp_path / "a.out", json.dumps([
        {"scanner": "secrets", "severity": "low", "title": "noise",
         "file": "src/a.py", "line": 1, "rule_id": "R-LOW-001", "confidence": 0.40},
    ]))
    _write(tmp_path / "a.err", "")
    _write(tmp_path / "a.exit", "1")
    report = module.build_report(str(tmp_path), str(repo), "false")

    titles = [f["title"] for f in report["findings"]]
    assert ".forensicsignore: Mass Rule Suppression" in titles
    mass = [f for f in report["findings"]
            if f["title"] == ".forensicsignore: Mass Rule Suppression"][0]
    assert mass["severity"] == "high"


def test_no_suppression_file_no_suppressed_findings(tmp_path):
    repo = _scan_dir(tmp_path)
    _write(tmp_path / "a.out", json.dumps([
        {"scanner": "secrets", "severity": "high", "title": "x",
         "file": "src/a.py", "line": 1, "rule_id": "SC-KEY-001", "confidence": 0.80},
    ]))
    _write(tmp_path / "a.err", "")
    _write(tmp_path / "a.exit", "1")
    report = module.build_report(str(tmp_path), str(repo), "false")
    assert report["suppressed"] == []
    assert report["summary"]["high"] == 1
