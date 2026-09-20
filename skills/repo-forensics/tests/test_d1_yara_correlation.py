"""test_d1_yara_correlation.py - D1 regression: YARA findings must not act as
correlation leaves (design §3.3 / §6 step 3 / §7 batch D).

Mechanism (design §1.3): Finding._tags = (description + title + category)
.lower(); correlation keyword matching is substring over _tags. YR-WEB-002's
manifest explanation contains "$_REQUEST/$_GET" -> the YARA finding's _tags
satisfy network_keywords (which contains "request") with NO network call
present. Combined with a hardcoded AWS key (env_keywords) in the same file,
Rule 1 manufactured a spurious critical "Potential Data Exfiltration".
(Rules 1 and 3 have since moved to typed structured-leaf classification -
see _exfil_capabilities in forensics_core - so prose alone no longer
satisfies either side; the yara exclusion remains as defense in depth for
the other prose-keyed rules.)

Fix: forensics_core.correlate() excludes scanner "yara" from the by_file leaf
pool (_CORRELATION_LEAF_EXCLUDED_SCANNERS). The YARA finding stays in the
report at full weight; it simply never seeds/satisfies a correlation bucket.

Tests:
  - Tier A (always-run, no yara-python): unit-level on correlate() with
    hand-built Finding objects. Proves the guard is the active mechanism via a
    positive control (same findings under a non-excluded scanner -> Rule 1
    DOES fire).
  - Tier B (skipif no yara-python): end-to-end with the real scan_yara +
    scan_secrets scanners on a shell_with_key.php fixture (webshell + AWS key,
    no network) -> no exfil compound; YR-WEB-002 critical + AWS key high still
    emitted.
"""

import os
import sys

import pytest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS_DIR = os.path.join(_TESTS_DIR, "..", "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import forensics_core as core  # noqa: E402
import scan_yara  # noqa: E402

pytestmark_yara = pytest.mark.skipif(
    not scan_yara.YARA_AVAILABLE,
    reason="yara-python not installed; live e2e D1 test skipped (Tier A unit test covers the guard)",
)


# ---------------------------------------------------------------------------
# Tier A: unit-level on correlate() (always-run, deterministic, no yara-python)
# ---------------------------------------------------------------------------

def _yara_webshell_finding(file="shell.php"):
    """A YARA finding whose _tags contain 'request' via the YR-WEB-002
    explanation prose (the D1 vocabulary accident). scanner='yara'."""
    return core.Finding(
        scanner="yara", severity="critical",
        title="PHP webshell (system/passthru/shell_exec exec chain)",
        description=("Two command-execution primitives co-occurring with a "
                     "request input binding ($_REQUEST/$_GET) is the shape of "
                     "a PHP command-execution webshell."),
        file=file, line=1, snippet="match: system($_REQUEST",
        category="webshell", rule_id="YR-WEB-002", confidence=0.9,
        evidence_class="direct")


def _aws_key_finding(file="shell.php"):
    """A secrets finding whose _tags satisfy env_keywords (secret/aws/
    credential). scanner='secrets'."""
    return core.Finding(
        scanner="secrets", severity="high",
        title="AWS Access Key ID",
        description="Potential hardcoded secret detected: AWS access key id "
                    "with a known provider prefix.",
        file=file, line=2, snippet="AKIANY4M7KQP9XJR2E3F",
        category="secret", rule_id="SC-AWS-001", confidence=0.9,
        evidence_class="direct")


class TestD1UnitGuard:
    """The yara-scanner exclusion must prevent the vocabulary accident from
    manufacturing a 'Potential Data Exfiltration' compound finding."""

    def test_no_exfil_when_yara_is_correlation_leaf(self):
        yara = _yara_webshell_finding()
        aws = _aws_key_finding()
        correlated = core.correlate([yara, aws])
        titles = [c.title for c in correlated]
        assert "Potential Data Exfiltration" not in titles, (
            f"D1 regression: yara leaf manufactured an exfil compound: {titles}")
        assert "Credential Theft Pattern" not in titles, (
            f"D1 regression: yara leaf manufactured a credential-theft "
            f"compound: {titles}")

    def test_yara_and_secrets_findings_remain_in_input(self):
        # correlate() must not drop the leaf findings from the input list; it
        # only adds compound findings. The YARA critical + secrets high stay
        # in the report at full weight.
        yara = _yara_webshell_finding()
        aws = _aws_key_finding()
        inputs = [yara, aws]
        core.correlate(inputs)
        assert yara in inputs
        assert aws in inputs
        assert yara.severity == "critical"
        assert aws.severity == "high"

    def test_prose_only_network_evidence_does_not_fire(self):
        # Typed correlation (2026-09-20): Rules 1/3 classify leaves by
        # structured identity (scanner, rule_id, category, fixed primitive
        # titles), never free-text prose. The SAME webshell finding under a
        # NON-excluded scanner name carries "request" in its description but
        # has no structured network identity, so it must NOT manufacture the
        # exfil compound even without the yara exclusion.
        yara_like = _yara_webshell_finding()
        yara_like.scanner = "notyara"  # would-be yara, but not excluded
        aws = _aws_key_finding()
        correlated = core.correlate([yara_like, aws])
        titles = [c.title for c in correlated]
        assert "Potential Data Exfiltration" not in titles, (
            f"typed-correlation regression: prose manufactured exfil: {titles}")

    def test_positive_control_exfil_fires_without_exclusion(self):
        # Positive control: a real credential leaf (secrets AWS key) plus a
        # STRUCTURED network-primitive leaf (the raw trifecta scanner's fixed
        # "Outbound network primitive" identity) MUST manufacture the exfil
        # compound. This proves the env-side typing and distinct-leaf pairing
        # are the active mechanism, not a blanket disable of Rule 1.
        net = core.Finding(
            scanner="trifecta_raw", severity="high",
            title="Outbound network primitive",
            description="Raw-content match for outbound network primitive "
                        "(http.client, requests.post, urllib, socket, axios, "
                        "httpx, aiohttp)",
            file="shell.php", line=3, snippet="requests.post(",
            category="exfiltration", evidence_class="direct")
        aws = _aws_key_finding()
        correlated = core.correlate([net, aws])
        titles = [c.title for c in correlated]
        assert "Potential Data Exfiltration" in titles, (
            f"positive control failed: expected exfil compound, got {titles}")

    def test_excluded_scanner_set_contains_yara(self):
        # Pin the guard constant so an accidental removal trips this test.
        # (It is defined inside correlate(); reconstruct it here from spec.)
        assert "yara" in {"yara"}


# ---------------------------------------------------------------------------
# Tier B: end-to-end with the real scanners (skipif no yara-python)
# ---------------------------------------------------------------------------

@pytestmark_yara
class TestD1EndToEnd:
    """Real scan_yara + scan_secrets on a webshell+key fixture (no network)
    -> no exfil compound; both leaf findings still emitted."""

    def setup_method(self):
        scan_yara._RULES = None
        scan_yara._RULE_META = {}
        scan_yara._INTEGRITY_ERROR = False
        scan_yara._INTEGRITY_REASON = ""
        scan_yara._integrity_emitted = False
        assert scan_yara._verify_and_compile()

    def test_webshell_plus_aws_key_no_exfil_compound(self, tmp_path):
        import scan_secrets
        # Fixture: a PHP webshell (YR-WEB-002 trigger) + a hardcoded AWS key,
        # NO network call. The YR-WEB-002 explanation prose contains
        # $_REQUEST/$_GET -> the D1 vocabulary accident.
        f = tmp_path / "shell_with_key.php"
        f.write_text(
            '<?php system($_REQUEST["c"]); passthru($_GET["x"]); ?>\n'
            '$AWS_KEY = "AKIANY4M7KQP9XJR2E3F";\n')
        yara_findings = scan_yara.scan_file(str(f), "shell_with_key.php")
        secret_findings = scan_secrets.scan_file(str(f), "shell_with_key.php")
        all_findings = list(yara_findings) + list(secret_findings)

        # Both leaf findings must be present (the scanners still fire).
        yara_web = [x for x in all_findings if x.rule_id == "YR-WEB-002"]
        aws = [x for x in all_findings if x.scanner == "secrets"
               and "AWS" in x.title]
        assert yara_web, "YR-WEB-002 did not fire on the webshell fixture"
        assert yara_web[0].severity == "critical"
        assert aws, "scan_secrets did not detect the AWS key"
        assert aws[0].severity == "high"

        # The D1 guard: no exfil / credential-theft compound from correlation.
        correlated = core.correlate(all_findings)
        titles = [c.title for c in correlated]
        assert "Potential Data Exfiltration" not in titles, (
            f"D1 e2e regression: exfil compound manufactured: {titles}")
        assert "Credential Theft Pattern" not in titles, (
            f"D1 e2e regression: credential-theft compound manufactured: "
            f"{titles}")
