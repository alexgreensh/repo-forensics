"""Coverage-honesty aggregation tests."""

import json
import os

import aggregate_json as module


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _scan_dir(tmp_path):
    """A separate empty repo dir used as the scan target."""
    d = tmp_path / "repo"
    d.mkdir()
    return d


def _scanner(name, findings, exit_code=0, parse_error=None):
    return {
        "name": name,
        "exit_code": exit_code,
        "parse_error": parse_error,
        "finding_count": len(findings),
        "findings": findings,
    }


class TestBuildCoverageStatus:
    def test_all_clean_returns_complete(self):
        scanners = [
            _scanner("secrets", [{"severity": "high", "category": "secret"}]),
            _scanner("sast", [{"severity": "medium", "category": "sql-injection"}]),
        ]
        status = module.build_coverage_status(scanners, [])
        assert status["overall"] == "COMPLETE"
        assert status["gaps"] == []
        assert status["per_scanner"]["secrets"]["status"] == "COMPLETE"
        assert status["per_scanner"]["sast"]["status"] == "COMPLETE"

    def test_unsupported_archive_type(self):
        scanners = [
            _scanner("archive", [
                {"severity": "low", "category": "unsupported-archive-type",
                 "file": "payload.7z", "line": 0, "title": "Unsupported archive type"},
            ]),
            _scanner("secrets", [{"severity": "high", "category": "secret"}]),
        ]
        status = module.build_coverage_status(scanners, [])
        assert status["overall"] == "UNSUPPORTED"
        assert status["per_scanner"]["archive"]["status"] == "UNSUPPORTED"
        assert status["per_scanner"]["secrets"]["status"] == "COMPLETE"
        assert any(g["category"] == "unsupported-archive-type" for g in status["gaps"])

    def test_incomplete_budget(self):
        scanners = [
            _scanner("oversize", [
                {"severity": "low", "category": "archive-scan-incomplete",
                 "file": "big.bin", "line": 0, "title": "Oversize scan incomplete"},
            ]),
        ]
        status = module.build_coverage_status(scanners, [])
        assert status["overall"] == "INCOMPLETE"
        assert status["per_scanner"]["oversize"]["status"] == "INCOMPLETE"

    def test_parse_error_marks_incomplete(self):
        scanners = [
            _scanner("archive", [], parse_error="Invalid JSON output: foo"),
        ]
        status = module.build_coverage_status(scanners, [])
        assert status["overall"] == "INCOMPLETE"
        assert status["per_scanner"]["archive"]["status"] == "INCOMPLETE"
        assert any(g["category"] == "parse-error" for g in status["gaps"])

    def test_unexpected_exit_code_marks_incomplete(self):
        scanners = [
            _scanner("sast", [], exit_code=7),
        ]
        status = module.build_coverage_status(scanners, [])
        assert status["overall"] == "INCOMPLETE"
        assert status["per_scanner"]["sast"]["status"] == "INCOMPLETE"

    def test_dependencies_and_dast_ignored_for_coverage_categories(self):
        # dependencies may emit enrichment-degraded; dast may emit dast-unsandboxed.
        # Those are findings, not coverage gaps.
        scanners = [
            _scanner("dependencies", [
                {"severity": "medium", "category": "enrichment-degraded"},
            ]),
            _scanner("dast", [
                {"severity": "medium", "category": "dast-unsandboxed"},
            ]),
        ]
        status = module.build_coverage_status(scanners, [])
        assert status["overall"] == "COMPLETE"
        assert status["gaps"] == []

    def test_dependencies_parse_error_still_incomplete(self):
        scanners = [
            _scanner("dependencies", [], parse_error="No JSON output captured from scanner"),
        ]
        status = module.build_coverage_status(scanners, [])
        assert status["overall"] == "INCOMPLETE"

    def test_worst_status_unsupported_wins_over_incomplete(self):
        scanners = [
            _scanner("archive", [
                {"severity": "low", "category": "unsupported-archive-type"},
            ]),
            _scanner("oversize", [
                {"severity": "low", "category": "archive-scan-incomplete"},
            ]),
        ]
        status = module.build_coverage_status(scanners, [])
        assert status["overall"] == "UNSUPPORTED"


class TestCoverageStatusInReport:
    def test_build_report_includes_coverage_status(self, tmp_path):
        repo = _scan_dir(tmp_path)
        _write(tmp_path / "a.out", json.dumps([
            {"severity": "high", "category": "secret", "title": "Key",
             "file": "x.py", "line": 1, "confidence": 0.80},
        ]))
        _write(tmp_path / "a.err", "")
        _write(tmp_path / "a.exit", "1")
        report = module.build_report(str(tmp_path), str(repo), "false")
        assert "coverage_status" in report
        assert report["coverage_status"]["overall"] == "COMPLETE"
        assert report["coverage_status"]["per_scanner"]["a"]["status"] == "COMPLETE"

    def test_build_report_unsupported_archive_surfaces_in_coverage_status(self, tmp_path):
        repo = _scan_dir(tmp_path)
        _write(tmp_path / "archive.out", json.dumps([
            {"scanner": "archive", "severity": "low", "category": "unsupported-archive-type",
             "title": "Unsupported archive type", "file": "payload.7z", "line": 0,
             "snippet": "payload.7z", "description": "Cannot open .7z"},
        ]))
        _write(tmp_path / "archive.err", "")
        _write(tmp_path / "archive.exit", "0")
        report = module.build_report(str(tmp_path), str(repo), "false")
        assert report["coverage_status"]["overall"] == "UNSUPPORTED"
        assert report["coverage_status"]["per_scanner"]["archive"]["status"] == "UNSUPPORTED"
        assert report["exit_code"] == 0  # coverage does not change exit code

    def test_build_report_coverage_does_not_change_exit_code(self, tmp_path):
        repo = _scan_dir(tmp_path)
        # A critical secret plus an unsupported archive: core exit code stays 2.
        _write(tmp_path / "secrets.out", json.dumps([
            {"scanner": "secrets", "severity": "critical", "category": "secret",
             "title": "Key", "file": "x.py", "line": 1, "confidence": 0.95},
        ]))
        _write(tmp_path / "secrets.err", "")
        _write(tmp_path / "secrets.exit", "0")
        _write(tmp_path / "archive.out", json.dumps([
            {"scanner": "archive", "severity": "low", "category": "unsupported-archive-type",
             "title": "Unsupported archive type", "file": "payload.7z", "line": 0},
        ]))
        _write(tmp_path / "archive.err", "")
        _write(tmp_path / "archive.exit", "0")
        report = module.build_report(str(tmp_path), str(repo), "false")
        assert report["exit_code"] == 2
        assert report["coverage_status"]["overall"] == "UNSUPPORTED"
