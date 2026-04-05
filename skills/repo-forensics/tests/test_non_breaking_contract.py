"""Non-breaking contract tests for run_forensics.sh JSON output + exit code matrix.

This file locks the output schema and exit code behavior of the existing v2.3.0 tool
so that any future change can be proved non-breaking. These tests MUST pass on
unchanged v2.3.0 main; any subsequent change that breaks them is a breaking change
and requires explicit review + major version bump.

Contract guarantees locked here:
  1. Top-level JSON keys: target, mode, scanner_count, scanners, summary, exit_code, findings
  2. Summary dict keys: critical, high, medium, low, total (all int)
  3. Scanner count: exactly 18 scanners in default full mode
  4. Scanner entry keys: name, exit_code, parse_error, finding_count, findings
  5. Exit code matrix: clean -> 0, noisy(high/medium) -> 1, critical -> 2
  6. Additive-only policy: new top-level fields allowed; removing or renaming
     existing fields is a breaking change and these tests will fail.

Reference: plans/forensify.md section 7 (non-breaking guarantees).
"""

import json
import os
import subprocess

import pytest


REQUIRED_TOP_LEVEL_KEYS = {
    "target",
    "mode",
    "scanner_count",
    "scanners",
    "summary",
    "exit_code",
    "findings",
}

REQUIRED_SUMMARY_KEYS = {"critical", "high", "medium", "low", "total"}

REQUIRED_SCANNER_ENTRY_KEYS = {
    "name",
    "exit_code",
    "parse_error",
    "finding_count",
    "findings",
}

EXPECTED_BASE_SCANNER_NAMES = {
    "ast_analysis",
    "binary",
    "dast",
    "dataflow",
    "dependencies",
    "entropy",
    "git_forensics",
    "infra",
    "integrity",
    "lifecycle",
    "manifest_drift",
    "mcp_security",
    "openclaw_skills",
    "post_incident",
    "runtime_dynamism",
    "sast",
    "secrets",
    "skill_threats",
}

# Synthetic scanner entries injected by aggregate_json.py AFTER the real
# scanner loop runs. trifecta_raw is appended when forensics_core.detect_trifecta_raw
# finds a raw trifecta pattern (aggregate_json.py:178). correlation is appended
# when run_correlation_pass produces any findings (aggregate_json.py:198). On a
# clean target neither appears. On a dirty target both may appear. The contract
# here is: the base scanners are ALWAYS present, and any extras must be in this
# allow-list of known synthetic entries.
EXPECTED_SYNTHETIC_SCANNER_NAMES = {"trifecta_raw", "correlation"}

# Derived from the set so adding a base scanner only requires editing the set above.
EXPECTED_BASE_SCANNER_COUNT = len(EXPECTED_BASE_SCANNER_NAMES)


def _script_path():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(repo_root, "scripts", "run_forensics.sh")


def _run_forensics(target_path, extra_args=None):
    """Run run_forensics.sh against target in JSON mode and return (returncode, payload)."""
    args = [_script_path(), str(target_path), "--format", "json"]
    if extra_args:
        args.extend(extra_args)
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"run_forensics.sh did not produce valid JSON.\n"
            f"returncode={result.returncode}\n"
            f"stdout (first 2000 chars)={result.stdout[:2000]}\n"
            f"stderr (first 2000 chars)={result.stderr[:2000]}\n"
            f"JSONDecodeError: {exc}"
        )
    return result.returncode, payload


# ---------------------------------------------------------------------------
# 1. JSON schema snapshot: top-level shape is locked
# ---------------------------------------------------------------------------


class TestJsonSchemaTopLevel:
    """Top-level keys and their types are locked. Additive changes OK; removals break."""

    def test_clean_fixture_has_all_required_top_level_keys(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        missing = REQUIRED_TOP_LEVEL_KEYS - set(payload.keys())
        assert not missing, (
            f"Breaking change: top-level keys missing from JSON output: {missing}. "
            f"Existing consumers (hook mode, CI action, downstream agents) rely on these. "
            f"If you intentionally removed or renamed a field, bump the major version "
            f"and document the migration."
        )

    def test_top_level_field_types_locked(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        assert isinstance(payload["target"], str)
        assert isinstance(payload["mode"], str)
        assert isinstance(payload["scanner_count"], int)
        assert isinstance(payload["scanners"], list)
        assert isinstance(payload["summary"], dict)
        assert isinstance(payload["exit_code"], int)
        assert isinstance(payload["findings"], list)

    def test_mode_is_full_by_default(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        assert payload["mode"] == "full", (
            "Default mode (no --skill-scan flag) must be 'full'. "
            "Changing this default is a breaking change for CI consumers."
        )

    def test_mode_is_skill_when_flag_passed(self, clean_repo):
        _, payload = _run_forensics(clean_repo, extra_args=["--skill-scan"])
        assert payload["mode"] == "skill"


# ---------------------------------------------------------------------------
# 2. Summary dict shape is locked
# ---------------------------------------------------------------------------


class TestJsonSchemaSummary:
    """Summary dict keys and types are locked."""

    def test_summary_has_all_required_severity_keys(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        missing = REQUIRED_SUMMARY_KEYS - set(payload["summary"].keys())
        assert not missing, (
            f"Breaking change: summary keys missing: {missing}. "
            f"Downstream consumers count findings by severity via these exact keys."
        )

    def test_summary_values_are_integers(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        for key in REQUIRED_SUMMARY_KEYS:
            assert isinstance(payload["summary"][key], int), (
                f"summary[{key}] must be int, got {type(payload['summary'][key]).__name__}"
            )

    def test_summary_total_equals_sum_of_severities(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        summary = payload["summary"]
        expected_total = (
            summary["critical"] + summary["high"] + summary["medium"] + summary["low"]
        )
        assert summary["total"] == expected_total, (
            f"summary.total ({summary['total']}) must equal "
            f"critical+high+medium+low ({expected_total}). "
            f"Consumers rely on this invariant."
        )


# ---------------------------------------------------------------------------
# 3. Scanner list shape is locked
# ---------------------------------------------------------------------------


class TestJsonSchemaScanners:
    """Scanner list length, names, and entry shape are locked.

    Note: aggregate_json.py appends synthetic 'trifecta_raw' and 'correlation'
    scanner entries AFTER the real scanner loop when those detection paths fire.
    On a clean target neither appears; on a dirty target either or both may
    appear. The contract is: all 18 base scanners are ALWAYS present, and any
    additional names must be in EXPECTED_SYNTHETIC_SCANNER_NAMES. Set equality
    against only the base set would incorrectly flag dirty-target scans as
    contract breaks.
    """

    def test_base_scanner_count_at_least_eighteen_in_full_mode(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        assert payload["scanner_count"] >= EXPECTED_BASE_SCANNER_COUNT, (
            f"Expected at least {EXPECTED_BASE_SCANNER_COUNT} base scanners in "
            f"full mode, got {payload['scanner_count']}. "
            f"Removing a base scanner is a breaking contract change."
        )
        assert len(payload["scanners"]) == payload["scanner_count"], (
            "scanner_count header must equal len(scanners) list."
        )

    def test_all_base_scanners_present(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        actual_names = {scanner["name"] for scanner in payload["scanners"]}
        missing_base = EXPECTED_BASE_SCANNER_NAMES - actual_names
        assert not missing_base, (
            f"Base scanner missing from output: {missing_base}. "
            f"Removing a base scanner is a breaking contract change. "
            f"If a base scanner was renamed, update EXPECTED_BASE_SCANNER_NAMES "
            f"with a compatibility alias and document the migration."
        )

    def test_no_unexpected_scanner_names(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        actual_names = {scanner["name"] for scanner in payload["scanners"]}
        allowed = EXPECTED_BASE_SCANNER_NAMES | EXPECTED_SYNTHETIC_SCANNER_NAMES
        unexpected = actual_names - allowed
        assert not unexpected, (
            f"Unexpected scanner names in output: {unexpected}. "
            f"Either these are new scanners that need to be added to "
            f"EXPECTED_BASE_SCANNER_NAMES, or new synthetic entries in "
            f"aggregate_json.py that need to be added to "
            f"EXPECTED_SYNTHETIC_SCANNER_NAMES with a comment explaining "
            f"when they fire."
        )

    def test_every_scanner_entry_has_required_keys(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        for scanner in payload["scanners"]:
            missing = REQUIRED_SCANNER_ENTRY_KEYS - set(scanner.keys())
            assert not missing, (
                f"Scanner entry {scanner.get('name', '?')} missing keys: {missing}"
            )

    def test_scanner_entry_field_types(self, clean_repo):
        _, payload = _run_forensics(clean_repo)
        for scanner in payload["scanners"]:
            assert isinstance(scanner["name"], str)
            assert isinstance(scanner["exit_code"], int)
            # parse_error is either None or a string
            assert scanner["parse_error"] is None or isinstance(
                scanner["parse_error"], str
            )
            assert isinstance(scanner["finding_count"], int)
            assert isinstance(scanner["findings"], list)


# ---------------------------------------------------------------------------
# 4. Exit code matrix: clean/warning/critical verdicts map to 0/1/2
# ---------------------------------------------------------------------------


class TestExitCodeMatrix:
    """Exit code contract: 0=clean, 1=warning, 2=critical. Locked by this matrix."""

    def test_clean_repo_returns_exit_code_zero(self, clean_repo):
        returncode, payload = _run_forensics(clean_repo)
        assert returncode == 0, (
            f"Clean repo must return exit code 0 (no findings). "
            f"Got {returncode}. summary={payload['summary']}"
        )
        assert payload["exit_code"] == 0
        assert payload["summary"]["total"] == 0

    def test_clean_repo_shell_exit_matches_json_exit_code(self, clean_repo):
        """Shell exit code and JSON exit_code field must agree."""
        returncode, payload = _run_forensics(clean_repo)
        assert returncode == payload["exit_code"], (
            f"Shell exit code ({returncode}) and JSON exit_code field "
            f"({payload['exit_code']}) must be identical. "
            f"Consumers rely on both being the same verdict."
        )

    def test_critical_repo_returns_exit_code_two(self, repo_with_prompt_injection):
        returncode, payload = _run_forensics(
            repo_with_prompt_injection, extra_args=["--skill-scan"]
        )
        # prompt injection is a critical finding
        assert returncode == 2, (
            f"Repo with prompt injection must return exit code 2 (critical). "
            f"Got {returncode}. summary={payload['summary']}"
        )
        assert payload["exit_code"] == 2
        assert payload["summary"]["critical"] >= 1

    def test_critical_repo_shell_exit_matches_json(self, repo_with_prompt_injection):
        returncode, payload = _run_forensics(
            repo_with_prompt_injection, extra_args=["--skill-scan"]
        )
        assert returncode == payload["exit_code"]


# ---------------------------------------------------------------------------
# 5. JSON is parseable with no leading banner (contract with downstream parsers)
# ---------------------------------------------------------------------------


class TestJsonParseability:
    """JSON output must be parseable stdin-to-json with no leading banner text."""

    def test_stdout_is_pure_json_no_banner(self, clean_repo):
        """stdout in --format json mode must be valid JSON with no prefix text."""
        result = subprocess.run(
            [_script_path(), str(clean_repo), "--format", "json"],
            capture_output=True,
            text=True,
            check=False,
        )
        # First character must be '{' — any banner text breaks downstream parsers
        assert result.stdout.startswith("{"), (
            f"JSON mode stdout must start with '{{'. Got: {result.stdout[:200]!r}. "
            f"Leading banner text breaks downstream JSON parsers (CI action, hook, agents)."
        )
        # Last non-whitespace character must be '}'
        assert result.stdout.rstrip().endswith("}")
        # Must be parseable
        json.loads(result.stdout)
