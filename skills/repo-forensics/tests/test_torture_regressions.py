"""
test_torture_regressions.py - regression gate for the torture-room findings
(2026-06-17) against the scanner-bypass scanners. Each test pins a specific
attacker technique the 5-agent gauntlet found; the green 1618-test suite hid
all of them because no test exercised the hostile path.

T1  zlib.error from a corrupt-deflate zip member must not crash the scan.
T5  fan-out decoy must not silently starve later archives (named fail-loud).
T6  a member with no/forged extension must not dodge SAST.
T7  a lone-surrogate string constant must not crash the .pyc disassembly child.
T8  a string constant cannot forge fake NAME/OP protocol lines (no false exec),
    and a marker after a newline inside a constant is still detected.
T10 a Unicode line-boundary char must not split a single-line regex match.
T11 a dotted source filename resolves to the right sibling (no false orphan).
"""

import importlib.util
import io
import marshal
import os
import zipfile

import forensics_core as core
import scan_archive
import scan_bytecode
import scan_oversize


def _cats(findings):
    return {f.category for f in findings}


def _pyc_from_source(src, path):
    """Compile a Python source STRING (may contain lone surrogates, unlike a
    file) to a code object and write a real 3.7+ .pyc with a 16-byte header."""
    code = compile(src, "m.py", "exec")
    header = importlib.util.MAGIC_NUMBER + b"\x00" * 12
    path.write_bytes(header + marshal.dumps(code))


# --- T1: corrupt-deflate zip member must not crash the whole scan -----------

class TestT1ZlibCrash:
    def test_corrupt_deflate_member_no_crash(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("a.txt", "x" * 5000)  # actually compresses
        raw = bytearray(buf.getvalue())
        for i in range(40, 70):  # corrupt the DEFLATE payload, keep central dir
            raw[i] ^= 0xFF
        (tmp_path / "corrupt.zip").write_bytes(raw)
        # Must NOT raise; the corrupt member degrades to a fail-loud finding.
        findings = scan_archive.scan_repo(str(tmp_path))
        assert "opaque-archive" in _cats(findings)

    def test_corrupt_archive_does_not_lose_sibling_findings(self, tmp_path):
        # A clean archive with a real payload + a crashing archive: the clean
        # archive's finding must survive (isolation).
        with zipfile.ZipFile(tmp_path / "aaa_clean.zip", "w") as z:
            z.writestr("evil.py", "import os\nos.system('id')\n")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("a.txt", "x" * 5000)
        raw = bytearray(buf.getvalue())
        for i in range(40, 70):
            raw[i] ^= 0xFF
        (tmp_path / "zzz_crash.zip").write_bytes(raw)
        findings = scan_archive.scan_repo(str(tmp_path))
        assert "archive-indirection" in _cats(findings), "clean archive payload lost to sibling crash"


# --- T5: fan-out decoy must name later starved archives ---------------------

class TestT5FanoutStarvation:
    def test_later_archive_named_when_budget_starved(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_archive, "MAX_TOTAL_FILES", 3)
        # Decoy fans out past the global file cap...
        with zipfile.ZipFile(tmp_path / "aaa_decoy.zip", "w") as z:
            for i in range(10):
                z.writestr(f"f{i}.txt", "x")
        # ...then a payload archive that gets starved.
        with zipfile.ZipFile(tmp_path / "zzz_payload.zip", "w") as z:
            z.writestr("evil.py", "import os\nos.system('id')\n")
        findings = scan_archive.scan_repo(str(tmp_path))
        # The starved archive must be NAMED in a fail-loud finding, not silently dropped.
        incompletes = [f for f in findings if f.category == "archive-scan-incomplete"]
        assert any("zzz_payload.zip" in f.file or "zzz_payload.zip" in f.description
                   for f in incompletes), "starved archive not named (silent skip)"


# --- T6: extension-gating bypass --------------------------------------------

class TestT6ExtensionBypass:
    def test_payload_in_extensionless_member_still_caught(self, tmp_path):
        # SAST deserialization payload in a member named with NO extension.
        with zipfile.ZipFile(tmp_path / "evil.zip", "w") as z:
            z.writestr("payload_no_ext", "import pickle\npickle.loads(data)\n")
        findings = scan_archive.scan_repo(str(tmp_path))
        assert "archive-indirection" in _cats(findings), "extensionless member dodged SAST"


# --- T7 / T8: .pyc disassembly robustness -----------------------------------

class TestT7SurrogateConst:
    def test_surrogate_const_does_not_block_analysis(self, tmp_path):
        # A lone-surrogate const beside a real exec primitive: must still analyze.
        # compile() rejects a surrogate in source, so inject it into a real code
        # object's co_consts (marshal round-trips lone surrogates fine).
        base = compile("import os\nos.system('id')\n", "m.py", "exec")
        code = base.replace(co_consts=base.co_consts + ("\ud800payload",))
        header = importlib.util.MAGIC_NUMBER + b"\x00" * 12
        (tmp_path / "surr.pyc").write_bytes(header + marshal.dumps(code))
        findings = scan_bytecode.scan_repo(str(tmp_path))
        assert "bytecode-hidden-logic" in _cats(findings), "surrogate const downgraded analysis"
        assert "unanalyzable-bytecode" not in _cats(findings)


class TestT8BlobForgery:
    def test_const_cannot_forge_import_line(self, tmp_path):
        # A benign module whose ONLY notable content is a const crafted to look
        # like protocol lines. It must NOT be detected as a code-execution prim.
        src = "x = 'a\\nNAME Popen\\nOP IMPORT_NAME subprocess'\n"
        _pyc_from_source(src, tmp_path / "forge.pyc")
        # keep a sibling .py so orphan logic stays quiet
        (tmp_path / "forge.py").write_text("x = 1\n")
        findings = scan_bytecode.scan_repo(str(tmp_path))
        assert "bytecode-hidden-logic" not in _cats(findings), "forged protocol line produced false exec"

    def test_marker_after_newline_in_const_still_detected(self, tmp_path):
        # A multi-line const with a credential path AFTER a newline must still be
        # seen (no truncation at the first newline).
        src = "def f():\n    p = 'open this file:\\n/home/u/.ssh/id_rsa'\n    return p\n"
        _pyc_from_source(src, tmp_path / "cred.pyc")
        findings = scan_bytecode.scan_repo(str(tmp_path))
        assert "bytecode-hidden-logic" in _cats(findings), "marker after newline truncated away"


# --- T10: Unicode line-boundary split evasion -------------------------------

class TestT10LineSplit:
    def test_vertical_tab_does_not_split_trifecta_line(self):
        # \x0b would split under splitlines() but not split('\n'); the exec
        # primitive on one physical line must still match.
        text = "a = 1\x0b os.system('id')\n"
        findings = core.scan_text_trifecta(text, "blob")
        assert any(f.category == "code-execution" for f in findings)


# --- T11: dotted source filename sibling resolution -------------------------

class TestT11SiblingResolution:
    def test_dotted_filename_resolves_correctly(self, tmp_path):
        pyc = "/x/__pycache__/my.helper.cpython-314.pyc"
        assert scan_bytecode._sibling_py(pyc) == os.path.join("/x", "my.helper.py")

    def test_optimized_dotted_filename(self):
        pyc = "/x/__pycache__/a.b.cpython-314.opt-1.pyc"
        assert scan_bytecode._sibling_py(pyc) == os.path.join("/x", "a.b.py")

    def test_plain_pyc(self):
        assert scan_bytecode._sibling_py("/x/mod.pyc") == os.path.join("/x", "mod.py")


# --- T3: oversize wall-clock budget -----------------------------------------

class TestT3OversizeBudget:
    def test_budget_emits_incomplete(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_oversize, "TOTAL_BUDGET_SEC", -1)  # already over budget
        (tmp_path / "a.txt").write_text("hello")
        findings = scan_oversize.scan_repo(str(tmp_path))
        assert "archive-scan-incomplete" in _cats(findings)

    def test_vectorized_whitespace_matches_semantics(self):
        # The vectorized analysis must agree with the simple definition.
        data = b"ab   cd\n\n\n\nef"
        max_run, ws, total = scan_oversize._whitespace_analysis(data)
        assert max_run == 4   # the "\n\n\n\n" run
        assert ws == 7        # 3 spaces + 4 newlines
        assert total == len(data)
