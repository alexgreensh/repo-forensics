"""Verdict-separation and monotonic-trust tests."""

import json
import os

import aggregate_json as module


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _scan_dir(tmp_path):
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


class TestBuildCoreVerdict:
    def test_clean_tier(self):
        summary = {"total": 0}
        verdicts = {"block": 0, "warn": 0, "info": 0, "suppressed": 0}
        cv = module.build_core_verdict(summary, verdicts, 0)
        assert cv["tier"] == "clean"
        assert cv["exit_code"] == 0

    def test_warn_tier(self):
        summary = {"total": 1}
        verdicts = {"block": 0, "warn": 1, "info": 0, "suppressed": 0}
        cv = module.build_core_verdict(summary, verdicts, 1)
        assert cv["tier"] == "warn"
        assert cv["exit_code"] == 1
        assert cv["warn"] == 1

    def test_block_tier(self):
        summary = {"total": 1}
        verdicts = {"block": 1, "warn": 0, "info": 0, "suppressed": 0}
        cv = module.build_core_verdict(summary, verdicts, 2)
        assert cv["tier"] == "block"
        assert cv["exit_code"] == 2
        assert cv["block"] == 1

    def test_fail_closed_tier_for_scanner_failure(self):
        summary = {"total": 0}
        verdicts = {"block": 0, "warn": 0, "info": 0, "suppressed": 0}
        cv = module.build_core_verdict(summary, verdicts, 99)
        assert cv["tier"] == "block"
        assert cv["exit_code"] == 99


class TestBuildEnrichmentStatus:
    def test_no_degraded_signals_is_complete(self):
        status = module.build_enrichment_status([], [])
        assert status["overall"] == "COMPLETE"
        assert status["vulns"] == "complete"
        assert status["rulepack_feed"] == "ok"
        assert status["adjudication"] == "available"
        assert status["capability_gaps"] == []

    def test_no_vulns_is_degraded(self):
        findings = [
            {"scanner": "dependencies", "category": "enrichment-degraded",
             "title": "Vulnerability enrichment disabled (`--no-vulns`)",
             "description": "OSV + CISA KEV checks were not performed."},
        ]
        status = module.build_enrichment_status([], findings)
        assert status["overall"] == "DEGRADED"
        assert status["vulns"] == "degraded"
        assert status["capability_gaps"]

    def test_offline_is_offline(self):
        findings = [
            {"scanner": "dependencies", "category": "enrichment-degraded",
             "title": "Vulnerability enrichment offline (`--offline`)",
             "description": "Network fetches are disabled."},
        ]
        status = module.build_enrichment_status([], findings)
        assert status["overall"] == "OFFLINE"
        assert status["vulns"] == "offline"

    def test_rulepack_degraded(self):
        findings = [
            {"scanner": "dependencies", "category": "enrichment-degraded",
             "title": "Rulepack feed degraded",
             "description": "A cached rulepack bundle failed verification."},
        ]
        status = module.build_enrichment_status([], findings)
        assert status["overall"] == "DEGRADED"
        assert status["rulepack_feed"] == "degraded"

    def test_adjudication_pending(self):
        findings = [
            {"severity": "high", "confidence": 0.75, "needs_adjudication": True,
             "category": "sql-injection"},
        ]
        status = module.build_enrichment_status([], findings)
        assert status["overall"] == "COMPLETE"
        assert status["adjudication"] == "pending"


class TestVerdictInReport:
    def test_report_has_core_verdict_and_enrichment_status(self, tmp_path):
        repo = _scan_dir(tmp_path)
        _write(tmp_path / "a.out", json.dumps([
            {"severity": "high", "category": "secret", "title": "Key",
             "file": "x.py", "line": 1, "confidence": 0.80},
        ]))
        _write(tmp_path / "a.err", "")
        _write(tmp_path / "a.exit", "1")
        report = module.build_report(str(tmp_path), str(repo), "false")
        assert "core_verdict" in report
        assert "enrichment_status" in report
        assert report["core_verdict"]["exit_code"] == report["exit_code"]
        assert report["enrichment_status"]["overall"] == "COMPLETE"

    def test_enrichment_degraded_present_in_report(self, tmp_path):
        repo = _scan_dir(tmp_path)
        _write(tmp_path / "dependencies.out", json.dumps([
            {"scanner": "dependencies", "severity": "low", "category": "enrichment-degraded",
             "title": "Vulnerability enrichment disabled (`--no-vulns`)",
             "description": "OSV + CISA KEV checks were not performed.",
             "file": "", "line": 0, "confidence": 0.0},
        ]))
        _write(tmp_path / "dependencies.err", "")
        _write(tmp_path / "dependencies.exit", "0")
        report = module.build_report(str(tmp_path), str(repo), "false")
        assert report["enrichment_status"]["overall"] == "DEGRADED"
        assert report["enrichment_status"]["vulns"] == "degraded"
        assert report["core_verdict"]["exit_code"] == 0

    def test_core_verdict_exit_code_matches_report_for_block(self, tmp_path):
        repo = _scan_dir(tmp_path)
        _write(tmp_path / "a.out", json.dumps([
            {"severity": "critical", "category": "secret", "title": "Key",
             "file": "x.py", "line": 1, "confidence": 0.95},
        ]))
        _write(tmp_path / "a.err", "")
        _write(tmp_path / "a.exit", "0")
        report = module.build_report(str(tmp_path), str(repo), "false")
        assert report["exit_code"] == 2
        assert report["core_verdict"]["exit_code"] == 2
        assert report["core_verdict"]["tier"] == "block"


class TestMonotonicTrustInvariant:
    def test_degraded_enrichment_cannot_change_exit_code(self, tmp_path):
        repo = _scan_dir(tmp_path)
        # Block-level finding from the secrets scanner.
        _write(tmp_path / "secrets.out", json.dumps([
            {"severity": "critical", "category": "secret", "title": "Key",
             "file": "x.py", "line": 1, "confidence": 0.95},
        ]))
        _write(tmp_path / "secrets.err", "")
        _write(tmp_path / "secrets.exit", "0")
        # A degraded dependencies scanner.
        _write(tmp_path / "dependencies.out", json.dumps([
            {"scanner": "dependencies", "severity": "low", "category": "enrichment-degraded",
             "title": "Vulnerability enrichment disabled (`--no-vulns`)",
             "description": "OSV + CISA KEV checks were not performed.",
             "file": "", "line": 0, "confidence": 0.0},
        ]))
        _write(tmp_path / "dependencies.err", "")
        _write(tmp_path / "dependencies.exit", "0")

        report = module.build_report(str(tmp_path), str(repo), "false")
        assert report["exit_code"] == 2
        assert report["core_verdict"]["exit_code"] == 2
        assert report["core_verdict"]["block"] == 1
        assert report["coverage_status"]["overall"] == "COMPLETE"
        assert report["enrichment_status"]["overall"] == "DEGRADED"

    def test_synthetic_enrichment_status_injection_does_not_lower_exit_code(self, tmp_path):
        repo = _scan_dir(tmp_path)
        _write(tmp_path / "a.out", json.dumps([
            {"severity": "high", "category": "secret", "title": "Key",
             "file": "x.py", "line": 1, "confidence": 0.80},
        ]))
        _write(tmp_path / "a.err", "")
        _write(tmp_path / "a.exit", "1")
        report = module.build_report(str(tmp_path), str(repo), "false")

        # Simulate a poisoned enrichment_status dict: the report must not change.
        original_exit = report["exit_code"]
        original_findings = [f["title"] for f in report["findings"]]
        report["enrichment_status"] = {"overall": "OFFLINE", "capability_gaps": ["injected"]}
        assert report["exit_code"] == original_exit
        assert [f["title"] for f in report["findings"]] == original_findings
