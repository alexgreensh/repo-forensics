"""Tests for compromised-version detection in scan_dependencies.py.

This file starts with characterization tests that lock in the CURRENT behavior
of check_compromised_versions() before any refactoring. Then adds tests for
Marc Gadsdon's issue #5 (version-pinned IOCs for chalk/debug/nx/etc) and all
the P0 security mitigations from the plan review (normalize_version,
overrides/resolutions, --package-list hardening, --osv opt-in).

Created 2026-04-05 as part of the version-pinned IOC upgrade (PR#A).
"""

import json
import pytest
import scan_dependencies as scanner


# ---------------------------------------------------------------------------
# Characterization tests — lock in CURRENT behavior before refactor.
# These should all pass against the unchanged scanner.
# ---------------------------------------------------------------------------


class TestCharacterizationCurrentIocs:
    """Pin down what scanner.COMPROMISED_PACKAGE_VERSIONS currently matches.

    Current dict (as of 2026-04-05 pre-refactor) contains 5 packages with
    9 version entries total:
      - axios: 1.14.1, 0.30.4
      - plain-crypto-js: 4.2.1
      - @shadanai/openclaw: 2026.3.28-2, 2026.3.28-3, 2026.3.31-1, 2026.3.31-2
      - @qqbrowser/openclaw-qbot: 0.0.130
      - litellm: 1.82.7, 1.82.8
    """

    def test_axios_known_compromised_flagged(self):
        findings = scanner.check_compromised_versions(
            {"axios": "1.14.1"}, "package.json"
        )
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "axios" in findings[0].title
        assert findings[0].category == "supply-chain"

    def test_axios_other_compromised_version(self):
        findings = scanner.check_compromised_versions(
            {"axios": "0.30.4"}, "package.json"
        )
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_axios_clean_version_not_flagged(self):
        findings = scanner.check_compromised_versions(
            {"axios": "1.6.0"}, "package.json"
        )
        assert len(findings) == 0

    def test_plain_crypto_js_flagged(self):
        findings = scanner.check_compromised_versions(
            {"plain-crypto-js": "4.2.1"}, "package.json"
        )
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_scoped_package_shadanai_openclaw(self):
        findings = scanner.check_compromised_versions(
            {"@shadanai/openclaw": "2026.3.28-2"}, "package.json"
        )
        assert len(findings) == 1

    def test_qqbrowser_flagged(self):
        findings = scanner.check_compromised_versions(
            {"@qqbrowser/openclaw-qbot": "0.0.130"}, "package.json"
        )
        assert len(findings) == 1

    def test_litellm_flagged(self):
        findings = scanner.check_compromised_versions(
            {"litellm": "1.82.7"}, "package.json"
        )
        assert len(findings) == 1

    def test_prefix_stripped_caret(self):
        """Current behavior: leading ^ is stripped before lookup."""
        findings = scanner.check_compromised_versions(
            {"axios": "^1.14.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_prefix_stripped_tilde(self):
        findings = scanner.check_compromised_versions(
            {"axios": "~1.14.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_prefix_stripped_gte(self):
        findings = scanner.check_compromised_versions(
            {"axios": ">=1.14.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_unknown_package_not_flagged(self):
        findings = scanner.check_compromised_versions(
            {"safe-package": "1.0.0"}, "package.json"
        )
        assert len(findings) == 0

    def test_empty_deps(self):
        findings = scanner.check_compromised_versions({}, "package.json")
        assert len(findings) == 0

    def test_case_insensitive_package_name(self):
        """Lookup uses lower() on the package name."""
        findings = scanner.check_compromised_versions(
            {"AXIOS": "1.14.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_finding_fields_populated(self):
        findings = scanner.check_compromised_versions(
            {"axios": "1.14.1"}, "package.json"
        )
        f = findings[0]
        assert f.scanner == "dependencies"
        assert f.severity == "critical"
        assert f.category == "supply-chain"
        assert f.file == "package.json"
        assert "axios" in f.snippet
        assert "1.14.1" in f.snippet


class TestCharacterizationCompromisedPackageVersionsDict:
    """Pin down the dict structure itself — if we move this data out of the
    module, these tests verify the new location preserves the old shape."""

    def test_dict_has_axios(self):
        assert "axios" in scanner.COMPROMISED_PACKAGE_VERSIONS

    def test_dict_has_litellm(self):
        assert "litellm" in scanner.COMPROMISED_PACKAGE_VERSIONS

    def test_dict_has_plain_crypto_js(self):
        assert "plain-crypto-js" in scanner.COMPROMISED_PACKAGE_VERSIONS

    def test_dict_has_shadanai(self):
        assert "@shadanai/openclaw" in scanner.COMPROMISED_PACKAGE_VERSIONS

    def test_dict_has_qqbrowser(self):
        assert "@qqbrowser/openclaw-qbot" in scanner.COMPROMISED_PACKAGE_VERSIONS

    def test_axios_has_both_known_versions(self):
        versions = scanner.COMPROMISED_PACKAGE_VERSIONS["axios"]
        assert "1.14.1" in versions
        assert "0.30.4" in versions

    def test_shadanai_has_four_versions(self):
        versions = scanner.COMPROMISED_PACKAGE_VERSIONS["@shadanai/openclaw"]
        assert len(versions) == 4

    def test_total_entry_count_minimum(self):
        """After refactor this grows — but the 5 original keys must remain."""
        required_keys = {
            "axios", "plain-crypto-js", "@shadanai/openclaw",
            "@qqbrowser/openclaw-qbot", "litellm",
        }
        assert required_keys.issubset(set(scanner.COMPROMISED_PACKAGE_VERSIONS.keys()))


class TestCharacterizationTransitiveCallsites:
    """check_compromised_versions() is called from 4 different call sites in
    scan_dependencies.py. All must keep working after refactor."""

    def test_called_from_package_json_scan(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"axios": "1.14.1"},
        }))
        # Add lockfile to suppress the missing-lockfile finding so we can
        # isolate the supply-chain finding.
        (tmp_path / "package-lock.json").write_text("{}")
        findings = scanner.scan_package_json(str(pkg), "package.json")
        supply_chain = [f for f in findings if f.category == "supply-chain"]
        assert len(supply_chain) == 1

    def test_called_from_yarn_lock_parse(self, tmp_path):
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '"axios@^1.14.1":\n'
            '  version "1.14.1"\n'
            '  resolved "https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz"\n'
        )
        findings = scanner.parse_yarn_lock(str(lock), "yarn.lock")
        supply_chain = [f for f in findings if f.category == "supply-chain"]
        assert len(supply_chain) == 1

    def test_called_from_poetry_lock_parse(self, tmp_path):
        lock = tmp_path / "poetry.lock"
        lock.write_text(
            '[[package]]\n'
            'name = "litellm"\n'
            'version = "1.82.7"\n'
        )
        findings = scanner.parse_poetry_lock(str(lock), "poetry.lock")
        supply_chain = [f for f in findings if f.category == "supply-chain"]
        assert len(supply_chain) == 1

    def test_called_from_pipfile_lock_parse(self, tmp_path):
        lock = tmp_path / "Pipfile.lock"
        lock.write_text(json.dumps({
            "default": {
                "litellm": {"version": "==1.82.7"},
            },
            "develop": {},
        }))
        findings = scanner.parse_pipfile_lock(str(lock), "Pipfile.lock")
        supply_chain = [f for f in findings if f.category == "supply-chain"]
        assert len(supply_chain) == 1


class TestParsePackageLockJsonCompromisedVersions:
    """Regression tests for BLOCKER 1 from the 2026-04-05 code review.

    parse_package_lock_json() had an INLINE version-check loop that read the
    legacy COMPROMISED_PACKAGE_VERSIONS in-module dict directly, bypassing
    the new ioc_manager seam. Result: chalk@5.6.1 (the flagship Marc IOC) in
    a package-lock.json transitive dep produced ZERO findings — defeating
    the entire PR for the most common npm lockfile format. Fixed by
    rerouting through check_compromised_versions() which goes through
    the merged DB.
    """

    def _lockfile_v3(self, packages):
        """Build a v3 package-lock.json with given {path: version} mapping."""
        packages_dict = {"": {"name": "test", "version": "1.0.0"}}
        for path, version in packages.items():
            packages_dict[path] = {"version": version, "integrity": "sha512-fake"}
        return {
            "name": "test",
            "lockfileVersion": 3,
            "packages": packages_dict,
        }

    def test_chalk_in_v3_lockfile_flagged(self, tmp_path):
        """chalk@5.6.1 as transitive dep in package-lock.json v3 must flag."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(self._lockfile_v3({
            "node_modules/chalk": "5.6.1",
        })))
        findings = scanner.parse_package_lock_json(
            str(lock), "package-lock.json"
        )
        supply_chain = [f for f in findings if f.category == "supply-chain"]
        assert len(supply_chain) == 1
        assert "chalk@5.6.1" in supply_chain[0].title

    def test_nx_devkit_in_v3_lockfile_flagged(self, tmp_path):
        """Scoped package in transitive deps must flag."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(self._lockfile_v3({
            "node_modules/@nx/devkit": "20.9.0",
        })))
        findings = scanner.parse_package_lock_json(
            str(lock), "package-lock.json"
        )
        supply_chain = [f for f in findings if f.category == "supply-chain"]
        assert any("@nx/devkit@20.9.0" in f.title for f in supply_chain)

    def test_debug_in_v3_lockfile_flagged(self, tmp_path):
        """Another Marc campaign package (Chalk/Debug Sep 2025)."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(self._lockfile_v3({
            "node_modules/debug": "4.4.2",
        })))
        findings = scanner.parse_package_lock_json(
            str(lock), "package-lock.json"
        )
        supply_chain = [f for f in findings if f.category == "supply-chain"]
        assert any("debug@4.4.2" in f.title for f in supply_chain)

    def test_clean_package_in_lockfile_not_flagged(self, tmp_path):
        """Legitimate packages at non-compromised versions must not flag."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(self._lockfile_v3({
            "node_modules/chalk": "5.5.0",  # clean version
            "node_modules/react": "18.2.0",
        })))
        findings = scanner.parse_package_lock_json(
            str(lock), "package-lock.json"
        )
        supply_chain = [f for f in findings if f.category == "supply-chain"]
        assert len(supply_chain) == 0

    def test_v_prefix_bypass_in_lockfile(self, tmp_path):
        """Version bypass attempts through lockfile parsing path."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(self._lockfile_v3({
            "node_modules/chalk": "v5.6.1",  # v-prefix bypass
        })))
        findings = scanner.parse_package_lock_json(
            str(lock), "package-lock.json"
        )
        supply_chain = [f for f in findings if f.category == "supply-chain"]
        assert len(supply_chain) == 1

    def test_campaign_attribution_in_lockfile_findings(self, tmp_path):
        """Findings from lockfile path must carry campaign ID like other paths."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(self._lockfile_v3({
            "node_modules/chalk": "5.6.1",
        })))
        findings = scanner.parse_package_lock_json(
            str(lock), "package-lock.json"
        )
        supply_chain = [f for f in findings if f.category == "supply-chain"]
        assert "chalk_debug_sep_2025" in supply_chain[0].snippet


class TestBypassAttackRegressions:
    """Regression tests for bypass vectors flagged in the security review.

    Each test here represents an attack technique a real adversary could use
    to evade version-pinned IOC detection. If any of these start failing,
    a P0 security regression has been introduced.
    """

    def test_v_prefix_bypass_caught(self):
        """'v5.6.1' must match 'chalk@5.6.1' after normalize_version()."""
        findings = scanner.check_compromised_versions(
            {"chalk": "v5.6.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_capital_v_prefix_bypass_caught(self):
        findings = scanner.check_compromised_versions(
            {"chalk": "V5.6.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_leading_zero_bypass_caught(self):
        """'5.06.1' must normalize to '5.6.1' and match."""
        findings = scanner.check_compromised_versions(
            {"chalk": "5.06.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_leading_zero_major_bypass_caught(self):
        findings = scanner.check_compromised_versions(
            {"chalk": "05.6.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_whitespace_padding_caught(self):
        """'  5.6.1  ' (common in CSV/YAML imports) must normalize."""
        findings = scanner.check_compromised_versions(
            {"chalk": "  5.6.1  "}, "package.json"
        )
        assert len(findings) == 1

    def test_semver_inclusion_operators_flag(self):
        """Operators that INCLUDE the target version must flag:
           ^5.6.1, ~5.6.1, >=5.6.1, <=5.6.1 all contain 5.6.1 in their range."""
        for op in ("^", "~", ">=", "<="):
            findings = scanner.check_compromised_versions(
                {"chalk": f"{op}5.6.1"}, "package.json"
            )
            assert len(findings) == 1, f"inclusion operator {op} bypassed detection"

    def test_semver_exclusion_operators_dont_flag(self):
        """Operators that EXCLUDE the target version must NOT flag (B1 fix):
           >5.6.1 means "above 5.6.1" (excludes it)
           <5.6.1 means "below 5.6.1" (excludes it)
           !=5.6.1 / !5.6.1 mean "not 5.6.1" (excludes it)"""
        for op in (">", "<", "!=", "!"):
            findings = scanner.check_compromised_versions(
                {"chalk": f"{op}5.6.1"}, "package.json"
            )
            assert len(findings) == 0, (
                f"exclusion operator {op}5.6.1 must not false-positive flag "
                f"(it excludes the compromised version)"
            )

    def test_prerelease_does_not_false_positive(self):
        """Pre-release versions are semantically distinct from release."""
        findings = scanner.check_compromised_versions(
            {"chalk": "5.6.1-beta.0"}, "package.json"
        )
        assert len(findings) == 0

    def test_prerelease_does_not_false_positive_rc(self):
        findings = scanner.check_compromised_versions(
            {"chalk": "5.6.1-rc.1"}, "package.json"
        )
        assert len(findings) == 0

    def test_build_metadata_still_matches_ioc(self):
        """Per SemVer 2.0.0 §10, build metadata (+sha.abc...) MUST be ignored
        when determining version precedence — 5.6.1+mirror is the same
        version as 5.6.1. An attacker installing chalk@5.6.1+evil from a
        private mirror should still trip the chalk@5.6.1 IOC. Security
        review SS-F3, 2026-04-05."""
        findings = scanner.check_compromised_versions(
            {"chalk": "5.6.1+sha.abc123"}, "package.json"
        )
        assert len(findings) == 1
        assert "chalk@5.6.1" in findings[0].title

    def test_unparseable_version_not_crashed(self):
        """Non-version strings must not crash or flag."""
        for bad in ("latest", "main", "git://foo.com/bar#abc", "*", "x.y.z"):
            findings = scanner.check_compromised_versions(
                {"chalk": bad}, "package.json"
            )
            assert len(findings) == 0, f"non-version {bad!r} should not crash or flag"

    def test_non_string_version_handled(self):
        """Numeric or None version values must not crash."""
        findings = scanner.check_compromised_versions(
            {"chalk": None, "debug": 42, "nx": True}, "package.json"
        )
        assert len(findings) == 0

    def test_control_char_injected_version(self):
        """Version with embedded control chars is rejected (log injection defense)."""
        findings = scanner.check_compromised_versions(
            {"chalk": "5.6.1\n[INFO] fake log line"}, "package.json"
        )
        assert len(findings) == 0


class TestNormalizeVersionHelper:
    """Direct tests for the normalize_version() helper function."""

    def test_basic_semver(self):
        assert scanner.normalize_version("5.6.1") == "5.6.1"

    def test_two_part(self):
        assert scanner.normalize_version("5.6") == "5.6"

    def test_one_part(self):
        assert scanner.normalize_version("5") == "5"

    def test_v_prefix(self):
        assert scanner.normalize_version("v5.6.1") == "5.6.1"
        assert scanner.normalize_version("V5.6.1") == "5.6.1"

    def test_caret_prefix(self):
        assert scanner.normalize_version("^5.6.1") == "5.6.1"

    def test_tilde_prefix(self):
        assert scanner.normalize_version("~5.6.1") == "5.6.1"

    def test_gte_prefix(self):
        assert scanner.normalize_version(">=5.6.1") == "5.6.1"

    def test_leading_zero_stripped_minor(self):
        assert scanner.normalize_version("5.06.1") == "5.6.1"

    def test_leading_zero_stripped_patch(self):
        assert scanner.normalize_version("5.6.01") == "5.6.1"

    def test_leading_zero_stripped_major(self):
        assert scanner.normalize_version("05.6.1") == "5.6.1"

    def test_whitespace_stripped(self):
        assert scanner.normalize_version("  5.6.1  ") == "5.6.1"

    def test_prerelease_preserved(self):
        assert scanner.normalize_version("5.6.1-beta.0") == "5.6.1-beta.0"
        assert scanner.normalize_version("5.6.1-rc.1") == "5.6.1-rc.1"
        assert scanner.normalize_version("5.6.1-next.0") == "5.6.1-next.0"

    def test_build_metadata_stripped(self):
        """Per SemVer §10 build metadata is not part of version precedence;
        normalize_version drops it so 5.6.1+mirror matches the 5.6.1 IOC.
        (SS-F3, 2026-04-05.)"""
        assert scanner.normalize_version("5.6.1+sha.abc") == "5.6.1"

    def test_combined_prerelease_and_build(self):
        """Pre-release (-) is preserved, build metadata (+) is stripped."""
        assert scanner.normalize_version("5.6.1-beta.0+sha.abc") == "5.6.1-beta.0"

    def test_none_returns_none(self):
        assert scanner.normalize_version(None) is None

    def test_non_string_returns_none(self):
        assert scanner.normalize_version(42) is None
        assert scanner.normalize_version(True) is None
        assert scanner.normalize_version([]) is None

    def test_empty_string_returns_none(self):
        assert scanner.normalize_version("") is None

    def test_unparseable_returns_none(self):
        assert scanner.normalize_version("not-a-version") is None
        assert scanner.normalize_version("git://foo.com/bar") is None
        assert scanner.normalize_version("x.y.z") is None

    def test_control_char_rejected(self):
        assert scanner.normalize_version("5.6.1\nFAKE") is None
        assert scanner.normalize_version("5.6.1\x00") is None

    def test_idempotent_on_already_normalized(self):
        assert scanner.normalize_version("5.6.1") == "5.6.1"
        assert (
            scanner.normalize_version(scanner.normalize_version("v5.06.01"))
            == "5.6.1"
        )


class TestMarcCampaignsChalkDebug:
    """Chalk/Debug supply chain compromise (Sep 2025). Issue #5 — Marc Gadsdon."""

    def test_chalk_5_6_1_flagged(self):
        findings = scanner.check_compromised_versions(
            {"chalk": "5.6.1"}, "package.json"
        )
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "chalk_debug_sep_2025" in findings[0].snippet

    def test_debug_4_4_2_flagged(self):
        findings = scanner.check_compromised_versions(
            {"debug": "4.4.2"}, "package.json"
        )
        assert len(findings) == 1

    def test_ansi_regex_6_2_1_flagged(self):
        findings = scanner.check_compromised_versions(
            {"ansi-regex": "6.2.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_chalk_clean_version_not_flagged(self):
        findings = scanner.check_compromised_versions(
            {"chalk": "5.6.0"}, "package.json"
        )
        assert len(findings) == 0


class TestMarcCampaignsNxS1ngularity:
    """Nx / S1ngularity supply chain (Aug 2025). 8 packages, 19 versions."""

    def test_nx_20_9_0_flagged(self):
        findings = scanner.check_compromised_versions(
            {"nx": "20.9.0"}, "package.json"
        )
        assert len(findings) == 1

    def test_nx_devkit_21_5_0_scoped(self):
        findings = scanner.check_compromised_versions(
            {"@nx/devkit": "21.5.0"}, "package.json"
        )
        assert len(findings) == 1

    def test_nx_workspace_21_5_0(self):
        findings = scanner.check_compromised_versions(
            {"@nx/workspace": "21.5.0"}, "package.json"
        )
        assert len(findings) == 1

    def test_nx_21_4_0_clean_not_flagged(self):
        """21.4.0 is not in the compromised range."""
        findings = scanner.check_compromised_versions(
            {"nx": "21.4.0"}, "package.json"
        )
        assert len(findings) == 0


class TestMarcCampaignsOthers:
    """Spot checks for remaining campaigns in compromised_versions.json."""

    def test_eslint_config_prettier_8_10_1(self):
        findings = scanner.check_compromised_versions(
            {"eslint-config-prettier": "8.10.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_duckdb_1_3_3(self):
        findings = scanner.check_compromised_versions(
            {"duckdb": "1.3.3"}, "package.json"
        )
        assert len(findings) == 1

    def test_shai_hulud_tinycolor(self):
        findings = scanner.check_compromised_versions(
            {"@ctrl/tinycolor": "4.1.1"}, "package.json"
        )
        assert len(findings) == 1

    def test_react_native_country_select(self):
        findings = scanner.check_compromised_versions(
            {"react-native-country-select": "0.3.91"}, "package.json"
        )
        assert len(findings) == 1


class TestEntirelyMaliciousPackagesViaKnownIocPath:
    """Entirely-malicious packages (wildcard '*' in JSON) should surface via
    the existing check_known_ioc_packages() path, not check_compromised_versions.

    This verifies the ioc_manager bridge: wildcard entries in
    compromised_versions.json are merged into the malicious_npm set that
    check_known_ioc_packages uses.
    """

    def test_ghost_campaign_darkslash(self):
        findings = scanner.check_known_ioc_packages(["darkslash"], "package.json")
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_nk_wave3_jsonpacks(self):
        findings = scanner.check_known_ioc_packages(["jsonpacks"], "package.json")
        assert len(findings) == 1

    def test_lazarus_graphalgo(self):
        findings = scanner.check_known_ioc_packages(["graphalgo"], "package.json")
        assert len(findings) == 1

    def test_credential_harvester_etherdjs(self):
        findings = scanner.check_known_ioc_packages(["etherdjs"], "package.json")
        assert len(findings) == 1

    def test_rat_typosquat_buildrunner_dev(self):
        findings = scanner.check_known_ioc_packages(["buildrunner-dev"], "package.json")
        assert len(findings) == 1


class TestCampaignAttribution:
    """Findings should carry campaign ID for incident response / reporting."""

    def test_campaign_id_in_snippet(self):
        findings = scanner.check_compromised_versions(
            {"chalk": "5.6.1"}, "package.json"
        )
        assert "chalk_debug_sep_2025" in findings[0].snippet

    def test_campaign_id_in_description(self):
        findings = scanner.check_compromised_versions(
            {"nx": "20.9.0"}, "package.json"
        )
        assert "nx_s1ngularity" in findings[0].description


class TestFlattenOverrides:
    """Direct tests for the _flatten_overrides helper."""

    def test_flat_overrides(self):
        result = scanner._flatten_overrides({"chalk": "5.6.1", "debug": "4.4.2"})
        assert result == {"chalk": "5.6.1", "debug": "4.4.2"}

    def test_nested_with_dot_key(self):
        """npm format: {'foo': {'.': '1.0.0', 'bar': '2.0.0'}}"""
        result = scanner._flatten_overrides(
            {"chalk": {".": "5.6.1", "inner": "1.2.3"}}
        )
        assert result["chalk"] == "5.6.1"
        assert result["inner"] == "1.2.3"

    def test_yarn_resolutions_glob_prefix_stripped(self):
        """Yarn: {'**/chalk': '5.6.1'}"""
        result = scanner._flatten_overrides({"**/chalk": "5.6.1"})
        assert result == {"chalk": "5.6.1"}

    def test_non_string_values_skipped(self):
        result = scanner._flatten_overrides(
            {"chalk": "5.6.1", "bad": 123, "also_bad": None}
        )
        assert result == {"chalk": "5.6.1"}

    def test_empty_map_returns_empty(self):
        assert scanner._flatten_overrides({}) == {}

    def test_non_dict_input_returns_empty(self):
        assert scanner._flatten_overrides("not a dict") == {}
        assert scanner._flatten_overrides(None) == {}


class TestOverridesBypassDetection:
    """End-to-end: compromised versions inserted via overrides/resolutions
    must be flagged. This is the #1 bypass vector identified in the security
    review (the 'single-field PR to a monorepo' attack)."""

    def test_npm_overrides_chalk_flagged(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"react": "18.0.0"},
            "overrides": {"chalk": "5.6.1"},
        }))
        (tmp_path / "package-lock.json").write_text("{}")  # suppress missing-lockfile
        findings = scanner.scan_package_json(str(pkg), "package.json")
        override_findings = [f for f in findings if f.category == "supply-chain-override"]
        assert len(override_findings) == 1
        assert "overrides" in override_findings[0].description.lower()

    def test_yarn_resolutions_debug_flagged(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"react": "18.0.0"},
            "resolutions": {"**/debug": "4.4.2"},
        }))
        (tmp_path / "yarn.lock").write_text("")
        findings = scanner.scan_package_json(str(pkg), "package.json")
        override_findings = [f for f in findings if f.category == "supply-chain-override"]
        assert len(override_findings) == 1
        assert "debug" in override_findings[0].title

    def test_pnpm_overrides_nx_flagged(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"react": "18.0.0"},
            "pnpm": {
                "overrides": {"@nx/devkit": "20.9.0"},
            },
        }))
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\npackages: {}\n")
        findings = scanner.scan_package_json(str(pkg), "package.json")
        override_findings = [f for f in findings if f.category == "supply-chain-override"]
        assert len(override_findings) == 1

    def test_npm_overrides_nested_dot_form(self, tmp_path):
        """npm's nested override: {'chalk': {'.': '5.6.1', 'inner': 'x'}}"""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"react": "18.0.0"},
            "overrides": {
                "chalk": {".": "5.6.1", "inner-dep": "1.0.0"}
            },
        }))
        (tmp_path / "package-lock.json").write_text("{}")
        findings = scanner.scan_package_json(str(pkg), "package.json")
        override_findings = [f for f in findings if f.category == "supply-chain-override"]
        assert len(override_findings) == 1

    def test_catalog_entry_flagged(self, tmp_path):
        """pnpm catalog: in package.json also gets scanned."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"react": "18.0.0"},
            "catalog": {"chalk": "5.6.1"},
        }))
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\npackages: {}\n")
        findings = scanner.scan_package_json(str(pkg), "package.json")
        override_findings = [f for f in findings if f.category == "supply-chain-override"]
        assert len(override_findings) == 1

    def test_pnpmfile_cjs_flagged(self, tmp_path):
        """.pnpmfile.cjs is an install-time rewriter — advisory finding."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"react": "18.0.0"},
        }))
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\npackages: {}\n")
        (tmp_path / ".pnpmfile.cjs").write_text("module.exports = { hooks: {} }")
        findings = scanner.scan_package_json(str(pkg), "package.json")
        pnpmfile_findings = [f for f in findings if f.category == "install-time-rewriter"]
        assert len(pnpmfile_findings) == 1

    def test_clean_package_no_overrides_no_false_positive(self, tmp_path):
        """Repos without overrides and without compromised deps stay clean."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"react": "18.0.0", "express": "4.18.0"},
        }))
        (tmp_path / "package-lock.json").write_text("{}")
        findings = scanner.scan_package_json(str(pkg), "package.json")
        assert not any(f.category == "supply-chain-override" for f in findings)
        assert not any(f.category == "install-time-rewriter" for f in findings)


class TestPackageListHardening:
    """Tests for load_package_list() security hardening.

    Every test here represents a P0 bypass vector from the 2026-04-05
    security review. If any of these start passing (allowing the attack),
    a P0 regression has been introduced.
    """

    def test_valid_absolute_path_loads(self, tmp_path):
        list_file = tmp_path / "iocs.txt"
        list_file.write_text(
            "# Test IOC list\n"
            "chalk@5.6.1\n"
            "debug@4.4.2\n"
            "evil-package@*\n"
        )
        version_pinned, wildcards = scanner.load_package_list(str(list_file))
        assert version_pinned["chalk"]["5.6.1"] == "user-list-file"
        assert version_pinned["debug"]["4.4.2"] == "user-list-file"
        assert "evil-package" in wildcards

    def test_relative_path_rejected(self, tmp_path):
        """Relative paths are rejected to prevent cwd confusion."""
        (tmp_path / "iocs.txt").write_text("chalk@5.6.1\n")
        with pytest.raises(ValueError, match="must be absolute"):
            scanner.load_package_list("iocs.txt")

    def test_missing_file_raises(self, tmp_path):
        """Missing file is a hard error, never silently proceeds."""
        with pytest.raises(ValueError, match="not found|unreadable"):
            scanner.load_package_list(str(tmp_path / "nonexistent.txt"))

    def test_symlink_rejected(self, tmp_path):
        """Symlinks are refused to prevent redirection attacks."""
        real = tmp_path / "real.txt"
        real.write_text("chalk@5.6.1\n")
        link = tmp_path / "link.txt"
        link.symlink_to(real)
        with pytest.raises(ValueError, match="symlink"):
            scanner.load_package_list(str(link))

    def test_file_inside_scanned_repo_rejected(self, tmp_path):
        """Files inside the scanned repo are refused (planted-file defense)."""
        repo = tmp_path / "repo"
        repo.mkdir()
        planted = repo / "iocs.txt"
        planted.write_text("chalk@5.6.1\n")
        with pytest.raises(ValueError, match="inside the scanned repo"):
            scanner.load_package_list(str(planted), scanned_repo_path=str(repo))

    def test_file_outside_scanned_repo_allowed(self, tmp_path):
        """Files outside the scanned repo work fine."""
        outside = tmp_path / "outside.txt"
        outside.write_text("chalk@5.6.1\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        version_pinned, _ = scanner.load_package_list(
            str(outside), scanned_repo_path=str(repo)
        )
        assert "chalk" in version_pinned

    def test_oversize_file_rejected(self, tmp_path):
        """Files over 256KB are rejected (DoS defense)."""
        big = tmp_path / "big.txt"
        # Write something that fits but then monkey-patch the limit
        big.write_text("chalk@5.6.1\n" * 100)
        original = scanner._PACKAGE_LIST_MAX_BYTES
        scanner._PACKAGE_LIST_MAX_BYTES = 10  # absurdly low
        try:
            with pytest.raises(ValueError, match="too large"):
                scanner.load_package_list(str(big))
        finally:
            scanner._PACKAGE_LIST_MAX_BYTES = original

    def test_comments_and_blanks_skipped(self, tmp_path):
        list_file = tmp_path / "iocs.txt"
        list_file.write_text(
            "# This is a comment\n"
            "\n"
            "chalk@5.6.1\n"
            "# Another comment\n"
            "   \n"
            "debug@4.4.2\n"
        )
        version_pinned, wildcards = scanner.load_package_list(str(list_file))
        assert len(version_pinned) == 2
        assert len(wildcards) == 0

    def test_strict_parser_rejects_shell_metacharacters(self, tmp_path):
        """Shell metacharacters must not appear in package names."""
        list_file = tmp_path / "bad.txt"
        list_file.write_text("chalk; rm -rf /@5.6.1\n")
        with pytest.raises(ValueError, match="invalid entry"):
            scanner.load_package_list(str(list_file))

    def test_strict_parser_rejects_path_separators(self, tmp_path):
        """Path separators in package names are rejected (unless scoped)."""
        list_file = tmp_path / "bad.txt"
        list_file.write_text("../../../etc/passwd@1.0.0\n")
        with pytest.raises(ValueError, match="invalid entry"):
            scanner.load_package_list(str(list_file))

    def test_wildcard_cap_enforced(self, tmp_path):
        """Max 100 wildcards per list (prevents name-space DoS)."""
        list_file = tmp_path / "many.txt"
        # Write 101 wildcards
        list_file.write_text("\n".join(f"pkg{i}@*" for i in range(101)))
        with pytest.raises(ValueError, match="too many wildcard"):
            scanner.load_package_list(str(list_file))

    def test_wildcard_cap_ok_at_limit(self, tmp_path):
        list_file = tmp_path / "many.txt"
        list_file.write_text("\n".join(f"pkg{i}@*" for i in range(100)))
        _, wildcards = scanner.load_package_list(str(list_file))
        assert len(wildcards) == 100

    def test_entry_cap_enforced(self, tmp_path):
        """Max 10,000 total entries."""
        list_file = tmp_path / "huge.txt"
        original = scanner._PACKAGE_LIST_MAX_ENTRIES
        scanner._PACKAGE_LIST_MAX_ENTRIES = 5
        try:
            list_file.write_text("\n".join(f"pkg{i}@1.0.0" for i in range(10)))
            with pytest.raises(ValueError, match="too many entries"):
                scanner.load_package_list(str(list_file))
        finally:
            scanner._PACKAGE_LIST_MAX_ENTRIES = original

    def test_scoped_package_name_parsed(self, tmp_path):
        list_file = tmp_path / "scoped.txt"
        list_file.write_text("@nx/devkit@20.9.0\n")
        version_pinned, _ = scanner.load_package_list(str(list_file))
        assert "@nx/devkit" in version_pinned
        assert "20.9.0" in version_pinned["@nx/devkit"]

    def test_wildcard_with_no_version_is_wildcard(self, tmp_path):
        """'package-name' (no @version) should be treated as entirely-malicious."""
        list_file = tmp_path / "nv.txt"
        list_file.write_text("just-a-name\n")
        _, wildcards = scanner.load_package_list(str(list_file))
        assert "just-a-name" in wildcards

    def test_explicit_wildcard_at_star(self, tmp_path):
        list_file = tmp_path / "star.txt"
        list_file.write_text("evil@*\n")
        _, wildcards = scanner.load_package_list(str(list_file))
        assert "evil" in wildcards

    def test_case_insensitive_name_normalization(self, tmp_path):
        list_file = tmp_path / "case.txt"
        list_file.write_text("CHALK@5.6.1\n")
        version_pinned, _ = scanner.load_package_list(str(list_file))
        assert "chalk" in version_pinned  # lowercased
        assert "CHALK" not in version_pinned

    def test_version_normalized_in_user_list(self, tmp_path):
        """User-supplied versions go through normalize_version too."""
        list_file = tmp_path / "v.txt"
        list_file.write_text("chalk@v5.06.01\n")
        version_pinned, _ = scanner.load_package_list(str(list_file))
        # Normalized to 5.6.1
        assert "5.6.1" in version_pinned["chalk"]


class TestStrictPinPackageJsonFalsePositives:
    """Regression tests for CRC-F1 (2026-04-05 torture review).

    A package.json writing "chalk": "<=5.6.1" or "chalk": "~5.6.1" is a range
    constraint that INCLUDES 5.6.1 but does not pin it. The lockfile may or
    may not resolve to 5.6.1. Flagging these as CRITICAL chalk@5.6.1 IOC hits
    was a false positive that would embarrass us on day-1 reviews.

    strict_pin=True (passed from scan_package_json) rejects any range operator
    so only BARE exact version strings like "5.6.1" or "v5.6.1" match. The
    lockfile path still uses strict_pin=False (default) because its values
    are always resolved versions.
    """

    def test_lte_constraint_does_not_flag_with_strict_pin(self):
        findings = scanner.check_compromised_versions(
            {"chalk": "<=5.6.1"}, "package.json", strict_pin=True
        )
        assert len(findings) == 0, (
            "<=5.6.1 is a range constraint, not a pin — must not flag"
        )

    def test_gte_constraint_does_not_flag_with_strict_pin(self):
        findings = scanner.check_compromised_versions(
            {"chalk": ">=5.6.1"}, "package.json", strict_pin=True
        )
        assert len(findings) == 0

    def test_tilde_constraint_does_not_flag_with_strict_pin(self):
        findings = scanner.check_compromised_versions(
            {"chalk": "~5.6.1"}, "package.json", strict_pin=True
        )
        assert len(findings) == 0

    def test_caret_constraint_does_not_flag_with_strict_pin(self):
        findings = scanner.check_compromised_versions(
            {"chalk": "^5.6.1"}, "package.json", strict_pin=True
        )
        assert len(findings) == 0

    def test_exact_version_still_flags_with_strict_pin(self):
        """Bare exact versions must still match IOCs."""
        findings = scanner.check_compromised_versions(
            {"chalk": "5.6.1"}, "package.json", strict_pin=True
        )
        assert len(findings) == 1
        assert "chalk@5.6.1" in findings[0].title

    def test_v_prefix_exact_version_still_flags_with_strict_pin(self):
        """v-prefixed exact version is an exact pin, just GitHub-release style."""
        findings = scanner.check_compromised_versions(
            {"chalk": "v5.6.1"}, "package.json", strict_pin=True
        )
        assert len(findings) == 1

    def test_exclusion_operators_still_rejected_with_strict_pin(self):
        """Exclusion operators (<, >, !, !=) are rejected with OR without strict_pin."""
        for op in ("<", ">", "!", "!="):
            findings = scanner.check_compromised_versions(
                {"chalk": f"{op}5.6.1"}, "package.json", strict_pin=True
            )
            assert len(findings) == 0, f"exclusion op {op} must not flag under strict_pin"

    def test_lockfile_path_still_flags_raw_versions(self):
        """strict_pin=False (the default) still allows lockfile callers to
        match exact resolved versions like "5.6.1" without the range guard."""
        findings = scanner.check_compromised_versions(
            {"chalk": "5.6.1"}, "package-lock.json", strict_pin=False
        )
        assert len(findings) == 1

    def test_scan_package_json_end_to_end_does_not_false_positive_on_range(self, tmp_path):
        """End-to-end: a package.json with chalk@^5.6.1 as a normal dependency
        constraint must not fire CRITICAL IOC. Only bare exact pins do."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"chalk": "^5.6.1"}}))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        criticals = [f for f in findings if f.severity == "critical" and "chalk" in f.title.lower()]
        assert len(criticals) == 0, (
            f"package.json with chalk@^5.6.1 range should not flag CRITICAL IOC; "
            f"got {[f.title for f in criticals]}"
        )

    def test_scan_package_json_end_to_end_flags_exact_pin(self, tmp_path):
        """End-to-end: a package.json that exactly pins chalk@5.6.1 MUST fire."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"chalk": "5.6.1"}}))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        criticals = [f for f in findings if f.severity == "critical" and "chalk" in f.title.lower()]
        assert len(criticals) == 1


class TestOverridesRecursionGuard:
    """Regression tests for SS-F1 (2026-04-05 security review).

    A malicious package.json with deeply nested overrides previously
    crashed _flatten_overrides with RecursionError, which was not caught
    and aborted the entire scanner walk. All subsequent IOC / compromised /
    typosquat checks for the rest of the repo were silently lost. The
    depth guard + RecursionError catch in scan_package_json closes it.
    """

    def test_deeply_nested_overrides_do_not_crash(self):
        """2000 levels of nesting must not raise RecursionError."""
        nested = {}
        cur = nested
        for _ in range(2000):
            cur["next"] = {"nested": {}}
            cur = cur["next"]["nested"]
        # Must not raise
        result = scanner._flatten_overrides({"root": nested})
        # Depth guard returns partial result rather than crashing
        assert isinstance(result, dict)

    def test_deeply_nested_overrides_scan_package_json(self, tmp_path):
        """End-to-end: recursion-bomb package.json must surface a high
        'Adversarial package.json' finding AND must not suppress IOC checks
        for other files in the same repo."""
        nested = {}
        cur = nested
        for _ in range(1000):
            cur["next"] = {"nested": {}}
            cur = cur["next"]["nested"]
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"chalk": "5.6.1"},
            "overrides": {"root": nested},
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        # The IOC check for chalk@5.6.1 MUST still fire
        criticals = [f for f in findings if f.severity == "critical" and "chalk" in f.title.lower()]
        assert len(criticals) == 1, (
            "chalk@5.6.1 IOC must still be detected despite recursion-bomb overrides"
        )

    def test_circular_override_dict_does_not_loop(self):
        """Circular references in Python dicts (future YAML-anchor loaders)
        must not infinite-loop."""
        a = {"pkg_a": "1.0.0"}
        b = {"pkg_b": "2.0.0"}
        a["ref_b"] = b
        b["ref_a"] = a  # circular
        result = scanner._flatten_overrides({"top": a})
        assert isinstance(result, dict)
        # No specific assertion on content — the win is not crashing
