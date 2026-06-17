"""Tests for scan_bytecode.py — U2 isolated .pyc disassembly scanner."""

import os
import py_compile
import pytest
import scan_bytecode as scanner


def _compile_to_pyc(src_code, directory, name="mod"):
    src = directory / f"{name}.py"
    src.write_text(src_code)
    pyc = directory / f"{name}.pyc"
    py_compile.compile(str(src), cfile=str(pyc), doraise=True)
    return src, pyc


def _cats(findings):
    return {f.category for f in findings}


class TestHeaderLen:
    def test_modern_pyc_header_16(self):
        # 3.7+ magic: version int >= 3390, followed by \r\n.
        magic = bytes([0x50, 0x0D]) + b"\r\n"  # 0x0D50 = 3408 -> 16
        assert scanner.pyc_header_len(magic) == 16

    def test_legacy_header_12(self):
        n = 3200
        magic = bytes([n & 0xFF, (n >> 8) & 0xFF]) + b"\r\n"
        assert scanner.pyc_header_len(magic) == 12

    def test_unrecognized_magic_none(self):
        assert scanner.pyc_header_len(b"\x00\x00\x00\x00") is None
        assert scanner.pyc_header_len(b"PK\x03\x04") is None
        assert scanner.pyc_header_len(b"ab") is None


class TestBytecodeDetection:
    def test_exec_primitive_in_function_body_orphan_elevated(self, tmp_path):
        # os.system inside a function -> lives in a NESTED code object, which the
        # recursive co_consts walk must reach. .py deleted -> orphan.
        code = "def run():\n    import os\n    os.system('id')\n"
        src, _pyc = _compile_to_pyc(code, tmp_path)
        src.unlink()
        findings = scanner.scan_repo(str(tmp_path))
        assert "bytecode-hidden-logic" in _cats(findings)
        assert "orphan-bytecode" in _cats(findings)
        assert any(f.category == "orphan-bytecode" and f.severity == "high"
                   for f in findings), "orphan + primitive must elevate to high"

    def test_credential_path_in_constants(self, tmp_path):
        code = "def f():\n    p = '/home/u/.ssh/id_rsa'\n    return open(p).read()\n"
        _compile_to_pyc(code, tmp_path)
        findings = scanner.scan_repo(str(tmp_path))
        cats = _cats(findings)
        assert "bytecode-hidden-logic" in cats

    def test_url_in_constants(self, tmp_path):
        code = "def f():\n    return 'http://evil.example/payload'\n"
        _compile_to_pyc(code, tmp_path)
        findings = scanner.scan_repo(str(tmp_path))
        assert "bytecode-hidden-logic" in _cats(findings)

    def test_benign_pyc_with_sibling_no_finding(self, tmp_path):
        code = "def add(a, b):\n    return a + b\n\n\nclass C:\n    x = 1\n"
        _compile_to_pyc(code, tmp_path)  # leaves the .py in place (has sibling)
        findings = scanner.scan_repo(str(tmp_path))
        assert findings == []

    def test_benign_orphan_outside_vendor_is_low_note(self, tmp_path):
        code = "def add(a, b):\n    return a + b\n"
        src, _pyc = _compile_to_pyc(code, tmp_path)
        src.unlink()
        findings = scanner.scan_repo(str(tmp_path))
        # Orphan but benign -> low note, never critical/high.
        assert "orphan-bytecode" in _cats(findings)
        assert all(f.severity == "low" for f in findings if f.category == "orphan-bytecode")
        assert not any(f.severity in ("critical", "high") for f in findings)

    def test_benign_orphan_in_vendor_suppressed(self, tmp_path):
        # Source-stripped wheel: loose .pyc under site-packages, no .py, benign.
        vendor = tmp_path / "site-packages" / "pkg"
        vendor.mkdir(parents=True)
        code = "def util():\n    return 42\n"
        src, _pyc = _compile_to_pyc(code, vendor)
        src.unlink()
        findings = scanner.scan_repo(str(tmp_path))
        # Benign orphan in a vendor root produces NO finding (R9 FP guard).
        assert findings == []


class TestGracefulDegradation:
    def test_corrupt_pyc_unanalyzable_no_crash(self, tmp_path):
        # Valid 3.7+ magic header but garbage marshal body -> child fails ->
        # parent records 'unanalyzable', scan survives. This is the safety test.
        pyc = tmp_path / "evil.pyc"
        magic = bytes([0x50, 0x0D]) + b"\r\n"  # 16-byte header
        pyc.write_bytes(magic + b"\x00" * 12 + b"\xff\xfe\xfd garbage marshal body")
        findings = scanner.scan_repo(str(tmp_path))
        assert "unanalyzable-bytecode" in _cats(findings)

    def test_unrecognized_magic_unanalyzable(self, tmp_path):
        pyc = tmp_path / "weird.pyc"
        pyc.write_bytes(b"\x00\x00\x00\x00" + b"x" * 64)
        findings = scanner.scan_repo(str(tmp_path))
        assert "unanalyzable-bytecode" in _cats(findings)

    def test_oversized_pyc_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scanner, "MAX_PYC_BYTES", 100)
        pyc = tmp_path / "big.pyc"
        magic = bytes([0x50, 0x0D]) + b"\r\n"
        pyc.write_bytes(magic + b"\x00" * 200)
        findings = scanner.scan_repo(str(tmp_path))
        assert "unanalyzable-bytecode" in _cats(findings)


class TestBudget:
    def test_pyc_count_cap_emits_incomplete(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scanner, "MAX_PYC", 1)
        for i in range(3):
            code = f"x = {i}\n"
            _compile_to_pyc(code, tmp_path, name=f"m{i}")
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-scan-incomplete" in _cats(findings)


class TestSiblingResolution:
    def test_pycache_sibling_mapping(self, tmp_path):
        pkg = tmp_path / "pkg"
        cache = pkg / "__pycache__"
        cache.mkdir(parents=True)
        (pkg / "mod.py").write_text("x = 1\n")
        pyc = cache / "mod.cpython-314.pyc"
        assert scanner._sibling_py(str(pyc)) == str(pkg / "mod.py")
