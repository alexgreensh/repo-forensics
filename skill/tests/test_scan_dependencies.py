"""Tests for scan_dependencies.py - Dependency Scanner."""

import json
import pytest
import scan_dependencies as scanner


class TestTyposquatting:
    def test_detects_npm_typosquat(self):
        typos = scanner.check_typosquatting(["reacct", "expresss"], scanner.POPULAR_NPM)
        assert len(typos) > 0
        suspects = [t[0] for t in typos]
        assert "reacct" in suspects or "expresss" in suspects

    def test_legitimate_packages_pass(self):
        typos = scanner.check_typosquatting(["react", "express", "lodash"], scanner.POPULAR_NPM)
        assert len(typos) == 0

    def test_l33t_normalization(self):
        assert scanner._apply_l33t("r3act") == "react"
        assert scanner._apply_l33t("l0d@sh") == "lodash"


class TestKnownIOC:
    def test_detects_sandworm_packages(self, repo_with_malicious_deps):
        findings = scanner.scan_package_json(
            str(repo_with_malicious_deps / "package.json"),
            "package.json"
        )
        ioc_findings = [f for f in findings if f.category == "known-ioc"]
        assert len(ioc_findings) > 0
        assert any("claud-code" in f.title for f in ioc_findings)


class TestVersionAnomaly:
    def test_detects_high_version(self):
        assert scanner.check_version_anomaly("99.0.0") is True
        assert scanner.check_version_anomaly("^99.1.0") is True

    def test_normal_versions_pass(self):
        assert scanner.check_version_anomaly("^18.0.0") is False
        assert scanner.check_version_anomaly("~4.17.21") is False
        assert scanner.check_version_anomaly("1.0.0") is False


class TestPackageJsonScan:
    def test_full_scan(self, repo_with_malicious_deps):
        findings = scanner.scan_package_json(
            str(repo_with_malicious_deps / "package.json"),
            "package.json"
        )
        assert len(findings) > 0
        categories = {f.category for f in findings}
        assert "known-ioc" in categories or "typosquatting" in categories

    def test_handles_malformed_json(self, tmp_path):
        bad = tmp_path / "package.json"
        bad.write_text("not valid json{{{")
        findings = scanner.scan_package_json(str(bad), "package.json")
        # Should not crash, should report parse error
        assert any(f.category == "parse-error" for f in findings)


class TestPythonDeps:
    def test_detects_pypi_typosquat(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("reqeusts==2.28.0\nnumpy==1.24.0\n")
        findings = scanner.scan_python_deps(str(req), "requirements.txt")
        typos = [f for f in findings if f.category == "typosquatting"]
        assert len(typos) > 0

    def test_detects_pypi_ioc(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("anthopic==1.0.0\n")
        findings = scanner.scan_python_deps(str(req), "requirements.txt")
        assert any(f.category == "known-ioc" for f in findings)


class TestLockfile:
    def test_detects_untrusted_registry(self, tmp_path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "packages": {
                "evil-pkg": {
                    "resolved": "https://evil-registry.com/evil-pkg-1.0.0.tgz"
                }
            }
        }))
        findings = scanner.scan_lockfile(str(lock), "package-lock.json")
        assert any("untrusted" in f.title.lower() for f in findings)

    def test_trusted_registries_pass(self, tmp_path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "packages": {
                "react": {
                    "resolved": "https://registry.npmjs.org/react/-/react-18.0.0.tgz"
                }
            }
        }))
        findings = scanner.scan_lockfile(str(lock), "package-lock.json")
        assert len(findings) == 0
