"""Evidence-freshness integration tests.

Seed stale evidence_state / vuln cache and assert a later scan emits
freshness_status on findings and that it flows into enrichment_status without
changing the deterministic security verdict.
"""

import io
import json
import os
import sys
import time

import pytest

import scan_dead_anchors as scanner
import dead_anchors_extract as extract
import scan_history
import aggregate_json
import vuln_feed


def _use_tmp_cache(monkeypatch, tmp_path):
    import dead_anchors_probe as probe
    monkeypatch.setattr(probe, "_default_cache_dir", lambda: str(tmp_path / "cache"))


def _install_network(monkeypatch, router):
    import urllib.error
    import socket
    import vuln_feed
    import dead_anchors_probe as probe

    class _FakeResp:
        def __init__(self, body):
            self._body = body if isinstance(body, bytes) else body.encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self, n):
            return self._body[:n]

    class _Net:
        def __init__(self, router):
            self.router = router
        def urlopen(self, req, timeout=None):
            url = getattr(req, "full_url", req)
            outcome = self.router(url)
            if isinstance(outcome, BaseException):
                raise outcome
            if len(outcome) == 3:
                code, body, final_url = outcome
            else:
                code, body = outcome
                final_url = url
            if code == 200:
                return _FakeResp(body)
            fp = io.BytesIO(body.encode("utf-8") if isinstance(body, str) else body)
            raise urllib.error.HTTPError(final_url, code, "err", {}, fp)

    def _fake_getaddrinfo(ip):
        return lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    net = _Net(router)
    monkeypatch.setattr(vuln_feed.urllib.request, "urlopen", net.urlopen)
    monkeypatch.setattr(probe, "_no_redirect_opener", lambda: probe._DirectOpener())
    monkeypatch.setattr(probe, "_bounded_redirect_opener", lambda: probe._DirectOpener())
    monkeypatch.setattr(probe.socket, "getaddrinfo", _fake_getaddrinfo("1.2.3.4"))


def test_dead_anchor_freshness_recheck_required(tmp_path, monkeypatch):
    """Seeded stale evidence_state produces RECHECK_REQUIRED on the finding."""
    _use_tmp_cache(monkeypatch, tmp_path)
    _install_network(monkeypatch, lambda u: (404, ""))

    db_path = str(tmp_path / "history.db")
    monkeypatch.setenv("REPO_FORENSICS_HISTORY", "1")
    monkeypatch.setenv("REPO_FORENSICS_HISTORY_DB", db_path)

    # Seed stale evidence for the npm anchor we will extract.
    key = "dead_anchor:package:npm:ghostpkg"
    ttl = 24 * 3600
    stale_ts = time.time() - 2 * ttl
    scan_history.put_evidence_state_safely(
        key, "dead_anchor", "CLAIMABLE", stale_ts, ttl,
        {"type": "package", "target": "npm:ghostpkg", "verdict": "CC"},
        db_path=db_path,
    )

    (tmp_path / "SKILL.md").write_text("npm install ghostpkg", encoding="utf-8")
    findings = scanner.scan_repo(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].freshness_status == "RECHECK_REQUIRED"


def test_dead_anchor_freshness_aggregate_flow():
    """freshness_status on a dead_anchor finding reaches enrichment_status."""
    finding = {
        "scanner": "dead_anchors",
        "severity": "critical",
        "title": "Phantom / claimable npm package: ghostpkg",
        "description": "npm registry 404",
        "file": "SKILL.md",
        "line": 1,
        "snippet": "npm install ghostpkg",
        "category": "dead-anchor",
        "rule_id": "",
        "confidence": 0.90,
        "freshness_status": "RECHECK_REQUIRED",
    }
    scanners = [{"name": "dead_anchors", "exit_code": 0, "parse_error": None,
                 "finding_count": 1, "findings": [finding], "stderr": ""}]
    status = aggregate_json.build_enrichment_status(scanners, [finding])
    assert status["dead_anchors"] == "RECHECK_REQUIRED"
    assert status["overall"] == "DEGRADED"
    assert any(g["reason"] == "recheck_required" for g in status["capability_gaps"])


def test_dependency_freshness_status(tmp_path, monkeypatch, capsys):
    """scan_dependencies surfaces stale vuln cache on CVE findings."""
    monkeypatch.setenv("REPO_FORENSICS_HISTORY", "")
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "fresh-test",
        "dependencies": {"zzztst": "1.0.0"},
    }), encoding="utf-8")

    monkeypatch.setattr(vuln_feed, "get_kev_cves", lambda *a, **k: set())
    monkeypatch.setattr(vuln_feed, "fetch_npm_freshness", lambda *a, **k: None)
    monkeypatch.setattr(vuln_feed, "fetch_pypi_freshness", lambda *a, **k: None)
    monkeypatch.setattr(vuln_feed, "cache_freshness", lambda *a, **k: {"status": "STALE", "checked_at": 0, "age_seconds": 0})

    def fake_check_vulns(*a, **k):
        return [{
            "id": "GHSA-0000-0000",
            "aliases": ["CVE-2024-0001"],
            "summary": "test vuln",
            "severity": {"type": "CVSS_V3", "score": "7.5"},
            "fixed_in": ["2.0.0"],
            "in_kev": False,
            "suggested_severity": "high",
        }]

    monkeypatch.setattr(vuln_feed, "check_package_vulnerabilities", fake_check_vulns)

    monkeypatch.setattr(sys, "argv", ["scan_dependencies", str(tmp_path), "--format", "json"])

    import scan_dependencies
    scan_dependencies.main()

    captured = capsys.readouterr()
    findings = json.loads(captured.out)
    cve = [f for f in findings if f.get("category") in ("cve", "cve-kev")]
    assert cve
    assert all(f.get("freshness_status") == "STALE" for f in cve)


def test_history_db_failure_does_not_break_scan(tmp_path, monkeypatch):
    """Broken history DB path is swallowed and scan returns findings unchanged."""
    _use_tmp_cache(monkeypatch, tmp_path)
    _install_network(monkeypatch, lambda u: (404, ""))

    monkeypatch.setenv("REPO_FORENSICS_HISTORY", "1")
    monkeypatch.setenv("REPO_FORENSICS_HISTORY_DB", "/dev/null/cannot_write/history.db")

    (tmp_path / "SKILL.md").write_text("npm install ghostpkg", encoding="utf-8")
    findings = scanner.scan_repo(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].freshness_status == ""
