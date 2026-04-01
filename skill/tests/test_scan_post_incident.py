"""Tests for scan_post_incident.py - Post-Incident Artifact Scanner."""

import os
import json
import pytest
import scan_post_incident as scanner


class TestNodeModulesArtifacts:
    def test_detects_malicious_package_dir(self, tmp_path):
        """plain-crypto-js directory in node_modules should be flagged."""
        nm = tmp_path / "node_modules" / "plain-crypto-js"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text('{"name":"plain-crypto-js","version":"4.2.0"}')
        findings = scanner.scan_node_modules(str(tmp_path))
        assert any(f.severity == "critical" and "plain-crypto-js" in f.title for f in findings)

    def test_clean_node_modules_no_findings(self, tmp_path):
        """Normal node_modules should produce no findings."""
        nm = tmp_path / "node_modules" / "express"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text('{"name":"express","version":"4.18.0"}')
        findings = scanner.scan_node_modules(str(tmp_path))
        assert len(findings) == 0

    def test_detects_sandworm_package_dir(self, tmp_path):
        """SANDWORM campaign package directory should be flagged."""
        nm = tmp_path / "node_modules" / "claud-code"
        nm.mkdir(parents=True)
        findings = scanner.scan_node_modules(str(tmp_path))
        assert any("claud-code" in f.title for f in findings)


class TestHostArtifacts:
    def test_no_rat_binary(self):
        """On a clean machine, no RAT binaries should be found."""
        findings = scanner.scan_host_artifacts()
        rat_findings = [f for f in findings if "RAT Binary" in f.title]
        # May or may not find persistence items, but should not find RAT binary
        assert not any("act.mond" in f.snippet for f in rat_findings)


