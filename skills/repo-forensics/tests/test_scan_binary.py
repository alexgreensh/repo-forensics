"""Tests for scan_binary.py - Binary Camouflage Scanner."""

import struct
import scan_binary as scanner


def _make_valid_pe_bytes():
    """Build a minimal but structurally valid MZ+PE stub (no actual code)."""
    # DOS header: MZ magic + e_lfanew at offset 0x3C pointing to offset 0x40
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 0x3C, 0x40)  # e_lfanew = 0x40

    # PE signature at offset 0x40
    pe_sig = b'PE\x00\x00'

    # Pad to make a recognizable blob
    padding = bytes(32)
    return bytes(dos_header) + pe_sig + padding


class TestEmbeddedPe:
    def test_png_with_embedded_pe_is_critical(self, tmp_path):
        """PNG file with a valid PE at a non-zero offset should trigger a CRITICAL finding."""
        png_header = bytes([
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,  # PNG magic
            0x00, 0x00, 0x00, 0x0d,                              # IHDR length
            0x49, 0x48, 0x44, 0x52,                              # IHDR type
        ])
        # Pad PNG area then embed PE at offset 256
        filler = bytes(256 - len(png_header))
        pe_blob = _make_valid_pe_bytes()
        content = png_header + filler + pe_blob

        evil_png = tmp_path / "image.png"
        evil_png.write_bytes(content)

        findings = scanner.scan_embedded_pe(str(evil_png), "image.png")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1, f"Expected CRITICAL embedded PE finding, got: {[f.title for f in findings]}"
        assert any("embedded pe" in f.title.lower() for f in critical)
        assert any(f.category == "embedded-executable" for f in critical)

    def test_normal_png_no_finding(self, tmp_path):
        """A clean PNG file without any PE content should produce no findings."""
        png_header = bytes([
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
            0x00, 0x00, 0x00, 0x0d,
            0x49, 0x48, 0x44, 0x52,
        ])
        content = png_header + bytes(512)

        clean_png = tmp_path / "clean.png"
        clean_png.write_bytes(content)

        findings = scanner.scan_embedded_pe(str(clean_png), "clean.png")
        assert len(findings) == 0, f"Expected no findings for clean PNG, got: {[f.title for f in findings]}"

    def test_exe_is_skipped(self, tmp_path):
        """A normal .exe file (MZ at offset 0) should not trigger embedded PE detection."""
        pe_blob = _make_valid_pe_bytes()
        exe_file = tmp_path / "normal.exe"
        exe_file.write_bytes(pe_blob)

        findings = scanner.scan_embedded_pe(str(exe_file), "normal.exe")
        assert len(findings) == 0, f"Expected no findings for .exe, got: {[f.title for f in findings]}"

    def test_dll_is_skipped(self, tmp_path):
        """A .dll file should be skipped regardless of content."""
        pe_blob = _make_valid_pe_bytes()
        dll_file = tmp_path / "lib.dll"
        dll_file.write_bytes(pe_blob)

        findings = scanner.scan_embedded_pe(str(dll_file), "lib.dll")
        assert len(findings) == 0, f"Expected no findings for .dll, got: {[f.title for f in findings]}"

    def test_pdf_with_embedded_pe_is_critical(self, tmp_path):
        """A PDF containing an embedded PE should also be detected."""
        pdf_header = b'%PDF-1.4\n'
        filler = bytes(128)
        pe_blob = _make_valid_pe_bytes()
        content = pdf_header + filler + pe_blob

        evil_pdf = tmp_path / "document.pdf"
        evil_pdf.write_bytes(content)

        findings = scanner.scan_embedded_pe(str(evil_pdf), "document.pdf")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1, f"Expected CRITICAL finding in PDF, got: {[f.title for f in findings]}"

    def test_mz_without_valid_pe_sig_no_finding(self, tmp_path):
        """MZ bytes without a valid PE signature should not trigger a finding."""
        # MZ at offset 64 but e_lfanew points to garbage (no PE\x00\x00)
        content = bytes(64) + b'MZ' + bytes(256)
        fake_bin = tmp_path / "fake.bin"
        fake_bin.write_bytes(content)

        findings = scanner.scan_embedded_pe(str(fake_bin), "fake.bin")
        assert len(findings) == 0, f"Expected no finding for MZ-only (no PE sig), got: {[f.title for f in findings]}"

    def test_tiny_file_skipped(self, tmp_path):
        """Files under 64 bytes should be skipped entirely."""
        tiny = tmp_path / "tiny.png"
        tiny.write_bytes(b'MZ' + bytes(30))

        findings = scanner.scan_embedded_pe(str(tiny), "tiny.png")
        assert len(findings) == 0, "Expected no findings for tiny file"
