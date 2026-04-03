"""Unit tests for aggregate_json.py."""

import json
import os
import sys

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
