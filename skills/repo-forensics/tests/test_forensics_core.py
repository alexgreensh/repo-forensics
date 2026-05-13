"""Tests for forensics_core.py - shared infrastructure."""

import os
import json
import tempfile
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

    def test_long_line_skip(self):
        import re
        patterns = [(re.compile(r'secret'), "secret found")]
        long_line = "secret " + "x" * (core.MAX_LINE_LENGTH + 1)
        findings = core.scan_patterns(long_line, "test.py", patterns, "sast", "high", "test")
        assert len(findings) == 0

    def test_scanner_name_propagated(self):
        import re
        patterns = [(re.compile(r'test'), "match")]
        findings = core.scan_patterns("test\n", "f.py", patterns, "c", "low", "my_scanner")
        assert findings[0].scanner == "my_scanner"


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
