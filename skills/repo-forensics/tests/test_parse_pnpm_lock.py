"""Tests for parse_pnpm_lock.py.

Covers lockfile v6 and v9 formats, peer-dep suffix handling, malformed
content, unsupported versions, and integration with check_compromised_versions.

Created 2026-04-05 as part of PR#A.
"""

import pytest
import parse_pnpm_lock
import scan_dependencies as scanner


V6_FIXTURE = """lockfileVersion: '6.0'

dependencies:
  chalk:
    specifier: ^5.6.1
    version: 5.6.1

packages:

  /chalk@5.6.1:
    resolution: {integrity: sha512-fake}
    engines: {node: '>=16'}
    dev: false

  /debug@4.4.2:
    resolution: {integrity: sha512-fake}
    dependencies:
      ms: 2.1.3
    dev: false

  /@nx/devkit@20.9.0:
    resolution: {integrity: sha512-fake}
    dev: false

  /clean-package@1.0.0:
    resolution: {integrity: sha512-fake}
    dev: false
"""


V9_FIXTURE = """lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      chalk:
        specifier: ^5.6.1
        version: 5.6.1

packages:
  chalk@5.6.1:
    resolution: {integrity: sha512-fake}

  debug@4.4.2:
    resolution: {integrity: sha512-fake}

  '@nx/devkit@20.9.0':
    resolution: {integrity: sha512-fake}

  '@ctrl/tinycolor@4.1.1(react@18.2.0)':
    resolution: {integrity: sha512-fake}

  'react@18.2.0(peer-dep@1.0.0)':
    resolution: {integrity: sha512-fake}

snapshots:
  chalk@5.6.1: {}
"""


class TestDetectVersion:
    def test_v6_detected(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V6_FIXTURE)
        assert parse_pnpm_lock.detect_lockfile_version(V6_FIXTURE) == "6.0"

    def test_v9_detected(self):
        assert parse_pnpm_lock.detect_lockfile_version(V9_FIXTURE) == "9.0"

    def test_missing_version_returns_none(self):
        assert parse_pnpm_lock.detect_lockfile_version("no version here") is None

    def test_supported_check(self):
        assert parse_pnpm_lock.is_supported_version("6.0") is True
        assert parse_pnpm_lock.is_supported_version("6.1") is True
        assert parse_pnpm_lock.is_supported_version("9.0") is True
        assert parse_pnpm_lock.is_supported_version("9.1") is True
        assert parse_pnpm_lock.is_supported_version("5.4") is False
        assert parse_pnpm_lock.is_supported_version("10.0") is False
        assert parse_pnpm_lock.is_supported_version(None) is False
        assert parse_pnpm_lock.is_supported_version("") is False
        assert parse_pnpm_lock.is_supported_version("invalid") is False


class TestParsePnpmLockV6:
    def test_extracts_bare_package(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V6_FIXTURE)
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert "chalk" in result
        assert result["chalk"] == "5.6.1"

    def test_extracts_debug(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V6_FIXTURE)
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert result["debug"] == "4.4.2"

    def test_extracts_scoped_package(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V6_FIXTURE)
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert "@nx/devkit" in result
        assert result["@nx/devkit"] == "20.9.0"

    def test_all_four_packages_found(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V6_FIXTURE)
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert len(result) == 4
        assert set(result.keys()) == {"chalk", "debug", "@nx/devkit", "clean-package"}


class TestParsePnpmLockV9:
    def test_extracts_quoted_scoped_package(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V9_FIXTURE)
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert result["@nx/devkit"] == "20.9.0"

    def test_peer_dep_suffix_stripped(self, tmp_path):
        """'@ctrl/tinycolor@4.1.1(react@18.2.0)' -> ('@ctrl/tinycolor', '4.1.1')"""
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V9_FIXTURE)
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert result["@ctrl/tinycolor"] == "4.1.1"

    def test_peer_dep_on_unscoped_package(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V9_FIXTURE)
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert result["react"] == "18.2.0"

    def test_snapshots_section_ignored(self, tmp_path):
        """Only `packages:` should be scanned, not `snapshots:`."""
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V9_FIXTURE)
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        # snapshots: has chalk@5.6.1 too but we should only count it once
        assert len(result) == 5  # chalk, debug, @nx/devkit, @ctrl/tinycolor, react


class TestChainedAndNestedPeerDepSuffixes:
    """Regression tests for BLOCKER 2 from the 2026-04-05 code review.

    Real-world pnpm v9 monorepos emit chained peer suffixes like
    'chalk@5.6.1(foo@1.0.0)(bar@2.0.0)' and nested suffixes like
    '@babel/runtime@7.22.15(foo@1.0.0(bar@2.0.0))'. The previous regex
    silently dropped these, causing chalk@5.6.1 (the flagship Marc IOC)
    to vanish from detection in real monorepos.
    """

    def test_chained_peer_suffixes(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(
            "lockfileVersion: '9.0'\npackages:\n"
            "  'chalk@5.6.1(foo@1.0.0)(bar@2.0.0)':\n"
            "    resolution: {integrity: sha512-x}\n"
        )
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert "chalk" in result
        assert result["chalk"] == "5.6.1"

    def test_nested_peer_suffixes(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(
            "lockfileVersion: '9.0'\npackages:\n"
            "  '@babel/runtime@7.22.15(foo@1.0.0(bar@2.0.0))':\n"
            "    resolution: {integrity: sha512-x}\n"
        )
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert "@babel/runtime" in result
        assert result["@babel/runtime"] == "7.22.15"

    def test_mixed_chained_and_nested_in_same_file(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(
            "lockfileVersion: '9.0'\npackages:\n"
            "  'chalk@5.6.1(foo@1.0.0)(bar@2.0.0)':\n"
            "    resolution: {integrity: sha512-x}\n"
            "  '@babel/runtime@7.22.15(foo@1.0.0(bar@2.0.0))':\n"
            "    resolution: {integrity: sha512-x}\n"
            "  clean@1.0.0:\n"
            "    resolution: {integrity: sha512-x}\n"
        )
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert result["chalk"] == "5.6.1"
        assert result["@babel/runtime"] == "7.22.15"
        assert result["clean"] == "1.0.0"
        assert len(result) == 3

    def test_chalk_with_peer_suffix_still_flags_as_compromised(self, tmp_path):
        """Integration: chained peer suffix must not hide Marc's chalk@5.6.1 IOC."""
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(
            "lockfileVersion: '9.0'\npackages:\n"
            "  'chalk@5.6.1(foo@1.0.0)(bar@2.0.0)':\n"
            "    resolution: {integrity: sha512-x}\n"
        )
        deps = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        findings = scanner.check_compromised_versions(deps, "pnpm-lock.yaml")
        assert any("chalk@5.6.1" in f.title for f in findings)


class TestErrorPaths:
    def test_missing_file(self, tmp_path):
        result = parse_pnpm_lock.parse_pnpm_lock(str(tmp_path / "nonexistent.yaml"))
        assert result == {}

    def test_malformed_content(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text("this is not a pnpm lockfile at all")
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert result == {}

    def test_unsupported_version_v5(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text("lockfileVersion: '5.4'\npackages:\n  /chalk@5.6.1:\n")
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert result == {}

    def test_empty_file(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text("")
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert result == {}

    def test_no_packages_section(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text("lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies: {}\n")
        result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        assert result == {}

    def test_size_limit_enforced(self, tmp_path):
        """Oversized lockfiles are refused to prevent DoS."""
        lock = tmp_path / "pnpm-lock.yaml"
        # Write a file larger than the 50MB limit
        # Use a minimal header then a stream of entries
        big = "lockfileVersion: '9.0'\npackages:\n" + "  chalk@5.6.1:\n    x: y\n" * 20
        lock.write_text(big)
        # Monkey-patch the limit to force the rejection path
        original = parse_pnpm_lock._MAX_LOCKFILE_BYTES
        parse_pnpm_lock._MAX_LOCKFILE_BYTES = 10  # absurdly small
        try:
            result = parse_pnpm_lock.parse_pnpm_lock(str(lock))
            assert result == {}
        finally:
            parse_pnpm_lock._MAX_LOCKFILE_BYTES = original


class TestIntegrationWithCompromisedVersions:
    """Parsed pnpm lockfile output feeds check_compromised_versions()."""

    def test_v6_chalk_compromised(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V6_FIXTURE)
        deps = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        findings = scanner.check_compromised_versions(deps, "pnpm-lock.yaml")
        # V6_FIXTURE has chalk@5.6.1 and debug@4.4.2 and @nx/devkit@20.9.0 — all compromised
        assert len(findings) >= 3
        flagged = {f.title for f in findings}
        assert any("chalk@5.6.1" in t for t in flagged)
        assert any("debug@4.4.2" in t for t in flagged)
        assert any("@nx/devkit@20.9.0" in t for t in flagged)

    def test_v9_nx_compromised(self, tmp_path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V9_FIXTURE)
        deps = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        findings = scanner.check_compromised_versions(deps, "pnpm-lock.yaml")
        flagged = {f.title for f in findings}
        assert any("@nx/devkit@20.9.0" in t for t in flagged)
        assert any("@ctrl/tinycolor@4.1.1" in t for t in flagged)

    def test_clean_packages_not_flagged(self, tmp_path):
        """The clean-package@1.0.0 in V6_FIXTURE must NOT be flagged."""
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(V6_FIXTURE)
        deps = parse_pnpm_lock.parse_pnpm_lock(str(lock))
        findings = scanner.check_compromised_versions(deps, "pnpm-lock.yaml")
        flagged = {f.title for f in findings}
        assert not any("clean-package" in t for t in flagged)
