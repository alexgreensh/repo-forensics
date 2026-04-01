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

    def test_hostname_bypass_evil_subdomain(self, tmp_path):
        """Evil subdomain like evil-registry.npmjs.org.attacker.com must be flagged."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "packages": {
                "evil-pkg": {
                    "resolved": "https://evil-registry.npmjs.org.attacker.com/pkg.tgz"
                }
            }
        }))
        findings = scanner.scan_lockfile(str(lock), "package-lock.json")
        assert any("untrusted" in f.title.lower() for f in findings), \
            "Hostname substring bypass: evil-registry.npmjs.org.attacker.com should be flagged"

    def test_hostname_bypass_path_trick(self, tmp_path):
        """evil.com/registry.npmjs.org/ should be flagged (path-based bypass)."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "packages": {
                "evil-pkg": {
                    "resolved": "https://evil.com/registry.npmjs.org/pkg.tgz"
                }
            }
        }))
        findings = scanner.scan_lockfile(str(lock), "package-lock.json")
        assert any("untrusted" in f.title.lower() for f in findings)

    def test_git_dependency_flagged(self, tmp_path):
        """git+ dependencies should be flagged as HIGH."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {
                "private-lib": "git+https://github.com/org/repo.git"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        assert any(f.category == "git-dependency" for f in findings)

    def test_http_dependency_flagged_critical(self, tmp_path):
        """http:// dependencies should be flagged as CRITICAL."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {
                "unsafe-lib": "http://example.com/lib.tgz"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        assert any(f.severity == "critical" and f.category == "insecure-protocol" for f in findings)

    def test_file_dependency_flagged(self, tmp_path):
        """file: dependencies should be flagged as MEDIUM."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {
                "local-lib": "file:../lib"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        assert any(f.category == "local-dependency" for f in findings)


class TestMissingLockfile:
    def test_no_lockfile_flagged(self, tmp_path):
        """package.json with deps but no lockfile should be flagged."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"react": "^18.0.0"}
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        assert any(f.category == "missing-lockfile" for f in findings)

    def test_lockfile_present_no_flag(self, tmp_path):
        """package.json with a sibling lockfile should NOT be flagged."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"react": "^18.0.0"}
        }))
        lock = tmp_path / "package-lock.json"
        lock.write_text("{}")
        findings = scanner.scan_package_json(str(pkg), "package.json")
        assert not any(f.category == "missing-lockfile" for f in findings)

    def test_monorepo_parent_lockfile_ok(self, tmp_path):
        """Monorepo: lockfile in parent dir should suppress the finding."""
        sub = tmp_path / "packages" / "sub"
        sub.mkdir(parents=True)
        pkg = sub / "package.json"
        pkg.write_text(json.dumps({
            "name": "sub",
            "dependencies": {"lodash": "^4.0.0"}
        }))
        # Parent lockfile
        lock = tmp_path / "package-lock.json"
        lock.write_text("{}")
        findings = scanner.scan_package_json(str(pkg), "packages/sub/package.json")
        assert not any(f.category == "missing-lockfile" for f in findings)


class TestPythonUnboundedRanges:
    def test_unbounded_gte_flagged(self, tmp_path):
        """>=X.Y.Z with no upper bound should be flagged as MEDIUM."""
        req = tmp_path / "requirements.txt"
        req.write_text("requests>=2.28.0\n")
        findings = scanner.scan_python_deps(str(req), "requirements.txt")
        assert any(f.category == "unbounded-range" for f in findings)

    def test_compatible_release_not_flagged(self, tmp_path):
        """~=X.Y.Z (compatible release) should NOT be flagged."""
        req = tmp_path / "requirements.txt"
        req.write_text("requests~=2.28.0\n")
        findings = scanner.scan_python_deps(str(req), "requirements.txt")
        assert not any(f.category == "unbounded-range" for f in findings)

    def test_pinned_not_flagged(self, tmp_path):
        """==X.Y.Z should NOT be flagged."""
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n")
        findings = scanner.scan_python_deps(str(req), "requirements.txt")
        assert not any(f.category == "unbounded-range" for f in findings)

    def test_bare_package_flagged(self, tmp_path):
        """Bare package name with no version should be flagged HIGH."""
        req = tmp_path / "requirements.txt"
        req.write_text("requests\n")
        findings = scanner.scan_python_deps(str(req), "requirements.txt")
        assert any(f.category == "no-version-constraint" for f in findings)
