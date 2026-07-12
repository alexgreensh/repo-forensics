"""Torture fixtures for coverage-honesty and monotonic trust."""

import json
import os
import zipfile

import pytest

import aggregate_json as module
import scan_archive
import scan_oversize


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _scan_dir(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    return d


class TestUnsupportedArchiveCoverage:
    def test_seven_zip_archive_is_unsupported(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "payload.7z").write_bytes(b"7z\xbc\xaf\'\x1c" + b"\x00" * 100)

        findings = scan_archive.scan_repo(str(repo))
        cats = {f.category for f in findings}
        assert "unsupported-archive-type" in cats

    def test_seven_zip_surfaces_unsupported_coverage_status(self, tmp_path):
        repo = _scan_dir(tmp_path)
        (repo / "payload.7z").write_bytes(b"7z\xbc\xaf\'\x1c" + b"\x00" * 100)

        findings = scan_archive.scan_repo(str(repo))
        # Write the archive scanner output and feed it through the aggregator.
        _write(tmp_path / "archive.out", json.dumps([f.to_dict() for f in findings]))
        _write(tmp_path / "archive.err", "")
        _write(tmp_path / "archive.exit", "0")
        report = module.build_report(str(tmp_path), str(repo), "false")

        assert report["coverage_status"]["overall"] == "UNSUPPORTED"
        assert report["coverage_status"]["per_scanner"]["archive"]["status"] == "UNSUPPORTED"
        assert report["exit_code"] == 0


class TestBudgetExhaustionCoverage:
    def test_oversize_budget_exhaustion_is_incomplete(self, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()
        # Make the budget tiny so two files trip it.
        monkeypatch.setattr(scan_oversize, "MAX_FILES", 1)
        (repo / "a.bin").write_bytes(b"x" * 1024)
        (repo / "b.bin").write_bytes(b"y" * 1024)

        findings = scan_oversize.scan_repo(str(repo))
        cats = {f.category for f in findings}
        assert "archive-scan-incomplete" in cats

    def test_incomplete_coverage_status_from_budget_exhaustion(self, tmp_path, monkeypatch):
        repo = _scan_dir(tmp_path)
        monkeypatch.setattr(scan_oversize, "MAX_FILES", 1)
        (repo / "a.bin").write_bytes(b"x" * 1024)
        (repo / "b.bin").write_bytes(b"y" * 1024)

        findings = scan_oversize.scan_repo(str(repo))
        _write(tmp_path / "oversize.out", json.dumps([f.to_dict() for f in findings]))
        _write(tmp_path / "oversize.err", "")
        _write(tmp_path / "oversize.exit", "0")
        report = module.build_report(str(tmp_path), str(repo), "false")

        assert report["coverage_status"]["overall"] == "INCOMPLETE"
        assert report["coverage_status"]["per_scanner"]["oversize"]["status"] == "INCOMPLETE"


class TestMonotonicPoisoning:
    def test_degraded_coverage_cannot_downgrade_block(self, tmp_path):
        repo = _scan_dir(tmp_path)
        _write(tmp_path / "secrets.out", json.dumps([
            {"scanner": "secrets", "severity": "critical", "category": "secret",
             "title": "Key", "file": "x.py", "line": 1, "confidence": 0.95},
        ]))
        _write(tmp_path / "secrets.err", "")
        _write(tmp_path / "secrets.exit", "0")
        _write(tmp_path / "archive.out", json.dumps([
            {"scanner": "archive", "severity": "low", "category": "unsupported-archive-type",
             "title": "Unsupported archive", "file": "payload.7z", "line": 0,
             "snippet": "payload.7z", "description": "Cannot open .7z"},
        ]))
        _write(tmp_path / "archive.err", "")
        _write(tmp_path / "archive.exit", "0")

        report = module.build_report(str(tmp_path), str(repo), "false")
        assert report["exit_code"] == 2
        assert report["core_verdict"]["tier"] == "block"
        assert report["coverage_status"]["overall"] == "UNSUPPORTED"

    def test_enrichment_degraded_does_not_remove_findings(self, tmp_path):
        repo = _scan_dir(tmp_path)
        _write(tmp_path / "secrets.out", json.dumps([
            {"scanner": "secrets", "severity": "high", "category": "secret",
             "title": "Key", "file": "x.py", "line": 1, "confidence": 0.80},
        ]))
        _write(tmp_path / "secrets.err", "")
        _write(tmp_path / "secrets.exit", "0")
        _write(tmp_path / "dependencies.out", json.dumps([
            {"scanner": "dependencies", "severity": "low", "category": "enrichment-degraded",
             "title": "Vulnerability enrichment disabled (`--no-vulns`)",
             "description": "OSV + CISA KEV checks not performed.",
             "file": "", "line": 0, "confidence": 0.0},
        ]))
        _write(tmp_path / "dependencies.err", "")
        _write(tmp_path / "dependencies.exit", "0")

        report = module.build_report(str(tmp_path), str(repo), "false")
        assert report["exit_code"] == 1
        assert any(f["title"] == "Key" for f in report["findings"])
        assert report["enrichment_status"]["overall"] == "DEGRADED"


class TestTextRendering:
    def test_format_report_renders_coverage_and_enrichment(self, tmp_path):
        repo = _scan_dir(tmp_path)
        _write(tmp_path / "archive.out", json.dumps([
            {"scanner": "archive", "severity": "low", "category": "unsupported-archive-type",
             "title": "Unsupported archive", "file": "payload.7z", "line": 0,
             "snippet": "payload.7z", "description": "Cannot open .7z"},
        ]))
        _write(tmp_path / "archive.err", "")
        _write(tmp_path / "archive.exit", "0")
        _write(tmp_path / "dependencies.out", json.dumps([
            {"scanner": "dependencies", "severity": "low", "category": "enrichment-degraded",
             "title": "Vulnerability enrichment disabled (`--no-vulns`)",
             "description": "OSV + CISA KEV checks not performed.",
             "file": "", "line": 0, "confidence": 0.0},
        ]))
        _write(tmp_path / "dependencies.err", "")
        _write(tmp_path / "dependencies.exit", "0")

        report = module.build_report(str(tmp_path), str(repo), "false")
        text = module.format_report_as_text(report)
        assert "COVERAGE: UNSUPPORTED" in text
        assert "ENRICHMENT: DEGRADED" in text
        assert "Deep scan guidance" in text

    def test_format_report_renders_threat_model_fields(self, tmp_path):
        repo = _scan_dir(tmp_path)
        _write(tmp_path / "secrets.out", json.dumps([
            {"scanner": "secrets", "severity": "critical", "category": "private-key",
             "title": "Private Key", "file": "x.pem", "line": 1,
             "snippet": "-----BEGIN RSA PRIVATE KEY-----", "description": "Key leaked",
             "confidence": 0.95,
             "attacker": "anyone with repo access",
             "boundary": "source repository",
             "asset": "asymmetric private key"},
        ]))
        _write(tmp_path / "secrets.err", "")
        _write(tmp_path / "secrets.exit", "0")

        report = module.build_report(str(tmp_path), str(repo), "false")
        text = module.format_report_as_text(report)
        assert "threat model:" in text
        assert "attacker=anyone with repo access" in text
        assert "asset=asymmetric private key" in text
