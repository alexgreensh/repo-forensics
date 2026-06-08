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


class TestNpmCacheArtifacts:
    def test_detects_malicious_package_in_cache_pre_key_substring(self, tmp_path, monkeypatch):
        """npm cache index entry with package name before the 'key' token is flagged.

        This test exercises the second OR branch exclusively:
            f"/{pkg_name}" in content.split('"key"')[0]
        The content intentionally omits the '/-/' tarball URL pattern so the
        first branch cannot fire. With the buggy '[0:1]' slice the branch
        returns a list and 'in' checks element equality (always False). With
        the correct '[0]' it returns a string and substring matching works.
        """
        fake_cache = tmp_path / ".npm" / "_cacache"
        index_dir = fake_cache / "index-v5" / "ab"
        index_dir.mkdir(parents=True)
        # content-v2 dir must exist for scan_npm_cache to proceed
        (fake_cache / "content-v2").mkdir(parents=True)

        # Package name appears BEFORE '"key"' and NO '/-/' tarball pattern present.
        # content.split('"key"')[0] == '\t{"path":"/plain-crypto-js","'
        # which contains '/plain-crypto-js', triggering the finding.
        cache_entry = index_dir / "abc123"
        cache_entry.write_text(
            '\t{"path":"/plain-crypto-js","key":"some-cache-key","integrity":"sha512-abc"}'
        )

        monkeypatch.setattr(
            scanner.os.path, "expanduser",
            lambda p: str(tmp_path) if p == "~" else p.replace("~", str(tmp_path))
        )

        findings = scanner.scan_npm_cache()
        assert any(
            "plain-crypto-js" in f.title and f.severity == "critical"
            for f in findings
        ), f"Expected critical finding for plain-crypto-js in npm cache, got: {findings}"

    def test_clean_npm_cache_no_findings(self, tmp_path, monkeypatch):
        """npm cache index with only legitimate packages produces no findings."""
        fake_cache = tmp_path / ".npm" / "_cacache"
        index_dir = fake_cache / "index-v5" / "cd"
        index_dir.mkdir(parents=True)
        (fake_cache / "content-v2").mkdir(parents=True)

        cache_entry = index_dir / "def456"
        cache_entry.write_text(
            '\t{"path":"/lodash","key":"some-cache-key","integrity":"sha512-xyz"}'
        )

        monkeypatch.setattr(
            scanner.os.path, "expanduser",
            lambda p: str(tmp_path) if p == "~" else p.replace("~", str(tmp_path))
        )

        findings = scanner.scan_npm_cache()
        assert len(findings) == 0, f"Expected no findings for clean cache, got: {findings}"


class TestHostArtifacts:
    def test_no_rat_binary(self):
        """On a clean machine, no RAT binaries should be found."""
        findings = scanner.scan_host_artifacts()
        rat_findings = [f for f in findings if "RAT Binary" in f.title]
        # May or may not find persistence items, but should not find RAT binary
        assert not any("act.mond" in f.snippet for f in rat_findings)


