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
