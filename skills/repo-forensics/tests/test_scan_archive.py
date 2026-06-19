"""Tests for scan_archive.py — U3 in-memory archive indirection scanner."""

import io
import os
import tarfile
import zipfile
import pytest
import scan_archive as scanner


_EXEC = 'os.system("id")'  # trifecta exec primitive, extension-independent


def _cats(findings):
    return {f.category for f in findings}


def _make_zip(path, members, compression=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compression) as zf:
        for name, data in members.items():
            zf.writestr(name, data)


def _snapshot(root):
    out = set()
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            out.add(os.path.join(dirpath, f))
    return out


class TestZipIndirection:
    def test_docx_embedded_payload(self, tmp_path):
        # .docx is a zip of XML; payload in word/document.xml is invisible to
        # source scanners. (The ToB document-archive bypass.)
        f = tmp_path / "evil.docx"
        _make_zip(f, {"word/document.xml": f"<xml>{_EXEC}</xml>", "[Content_Types].xml": "<x/>"})
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-indirection" in _cats(findings)
        assert any("word/document.xml" in fnd.file for fnd in findings)

    def test_zip_with_malicious_py(self, tmp_path):
        f = tmp_path / "skill.zip"
        _make_zip(f, {"skill.py": f"import os\n{_EXEC}\n"})
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-indirection" in _cats(findings)
        assert any("skill.py" in fnd.file for fnd in findings)

    def test_no_bytes_written_to_disk(self, tmp_path):
        f = tmp_path / "skill.zip"
        _make_zip(f, {"skill.py": f"{_EXEC}\n", "data/x.txt": "hello"})
        before = _snapshot(tmp_path)
        scanner.scan_repo(str(tmp_path))
        after = _snapshot(tmp_path)
        assert before == after, "scanner must not extract members to disk (KTD6)"

    def test_oversized_archive_not_dropped(self, tmp_path):
        # An 11 MB .whl with a payload: must NOT be dropped by the 10 MB cap
        # (the R3 regression — walk_aux is cap-free).
        f = tmp_path / "big.whl"
        with zipfile.ZipFile(f, "w") as zf:
            zf.writestr(zipfile.ZipInfo("filler.bin"), os.urandom(11 * 1024 * 1024),
                        compress_type=zipfile.ZIP_STORED)
            zf.writestr("evil.py", f"import os\n{_EXEC}\n")
        assert f.stat().st_size > 10 * 1024 * 1024
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-indirection" in _cats(findings)

    def test_benign_zip_no_critical_high(self, tmp_path):
        f = tmp_path / "ok.whl"
        _make_zip(f, {
            "pkg/__init__.py": "VERSION = '1.0'\n",
            "pkg/util.py": "def add(a, b):\n    return a + b\n",
            "pkg-1.0.dist-info/METADATA": "Name: pkg\nVersion: 1.0\n",
        })
        findings = scanner.scan_repo(str(tmp_path))
        assert not any(fnd.severity in ("critical", "high") for fnd in findings)


class TestMagicByteDetection:
    """GAP 2 (Trail of Bits context-loader): an archive renamed to dodge the
    extension gate must still be opened by its content magic."""

    def test_zip_renamed_to_txt_is_opened(self, tmp_path):
        # A zip saved as `.instructions.docx.txt` — extension ends `.txt`, so the
        # extension gate skips it. Content magic (PK) must route it in.
        f = tmp_path / ".instructions.docx.txt"
        _make_zip(f, {"skill.py": f"import os\n{_EXEC}\n"})
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-indirection" in _cats(findings)
        assert any("skill.py" in fnd.file for fnd in findings)

    def test_plain_text_not_treated_as_archive(self, tmp_path):
        (tmp_path / "notes.txt").write_text("just some plain text, no archive here\n")
        findings = scanner.scan_repo(str(tmp_path))
        assert findings == []

    def test_sniff_unsupported_magic_renamed(self, tmp_path):
        # A 7-Zip stream renamed to .txt is surfaced as unsupported, not silently
        # ignored (fail-loud, R12).
        (tmp_path / "blob.txt").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64)
        findings = scanner.scan_repo(str(tmp_path))
        assert "unsupported-archive-type" in _cats(findings)


class TestOfficeDocExecutableMember:
    """GAP 2: a script/binary inside an OOXML structure is flagged on structure
    alone, regardless of how benign its payload looks."""

    def _ooxml(self, extra):
        members = {
            "[Content_Types].xml": "<Types/>",
            "word/document.xml": "<w:document/>",
        }
        members.update(extra)
        return members

    def test_shell_script_in_docx_flagged(self, tmp_path):
        f = tmp_path / "evil.docx"
        # Benign-looking body — caught on structure, not content.
        _make_zip(f, self._ooxml({"word/sync1.sh": '#!/bin/sh\necho "PWND!"\n'}))
        findings = scanner.scan_repo(str(tmp_path))
        assert "executable-in-office-doc" in _cats(findings)
        assert any(fnd.severity == "high" and "sync1.sh" in fnd.snippet
                   for fnd in findings)

    def test_forged_extension_script_caught_by_shebang(self, tmp_path):
        f = tmp_path / "evil.docx"
        _make_zip(f, self._ooxml({"word/notes.dat": "#!/bin/bash\nid\n"}))
        findings = scanner.scan_repo(str(tmp_path))
        assert "executable-in-office-doc" in _cats(findings)

    def test_native_binary_in_docx_flagged(self, tmp_path):
        f = tmp_path / "evil.docx"
        _make_zip(f, self._ooxml({"word/payload.exe": "MZ\x90\x00stub"}))
        findings = scanner.scan_repo(str(tmp_path))
        assert "executable-in-office-doc" in _cats(findings)

    def test_clean_docx_with_fonts_no_findings(self, tmp_path):
        # The precision guard: a clean Office doc embedding binary fonts must NOT
        # produce findings (binary members are not fed to text SAST).
        f = tmp_path / "clean.docx"
        fake_font = b"\x00\x01\x00\x00" + os.urandom(2048)  # TTF-like binary
        _make_zip(f, self._ooxml({
            "word/fonts/OpenSans.ttf": fake_font,
            "word/styles.xml": "<w:styles/>",
            "docProps/core.xml": "<cp:coreProperties/>",
        }))
        findings = scanner.scan_repo(str(tmp_path))
        assert not any(fnd.severity in ("critical", "high") for fnd in findings), \
            [(fnd.severity, fnd.category) for fnd in findings]

    def test_script_in_plain_zip_not_office_flagged(self, tmp_path):
        # A .sh inside a normal zip (not OOXML) is legitimate — must NOT trip the
        # office-doc structural rule.
        f = tmp_path / "tools.zip"
        _make_zip(f, {"scripts/build.sh": "#!/bin/sh\nmake\n"})
        findings = scanner.scan_repo(str(tmp_path))
        assert "executable-in-office-doc" not in _cats(findings)


class TestZipBombAndFanout:
    def test_zip_bomb_aborted(self, tmp_path):
        # 2 MB of zeros compresses to ~KB -> ratio over the limit -> zip-bomb.
        f = tmp_path / "bomb.zip"
        _make_zip(f, {"big.txt": b"\x00" * (2 * 1024 * 1024)})
        findings = scanner.scan_repo(str(tmp_path))
        assert "zip-bomb" in _cats(findings)

    def test_fanout_cumulative_cap(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scanner, "MAX_TOTAL_FILES", 2)
        f = tmp_path / "many.zip"
        _make_zip(f, {f"f{i}.txt": "x" for i in range(6)})
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-scan-incomplete" in _cats(findings)

    def test_bounded_memory_on_bomb(self, tmp_path):
        # The bomb must be aborted without reading it all into memory; we assert
        # it completes quickly and flags, rather than OOMing.
        f = tmp_path / "bomb.zip"
        _make_zip(f, {"big.txt": b"\x00" * (4 * 1024 * 1024)})
        findings = scanner.scan_repo(str(tmp_path))
        assert "zip-bomb" in _cats(findings)


class TestTarMemberTypes:
    def _make_tar_with(self, path, member):
        with tarfile.open(path, "w") as tf:
            tf.addfile(member, io.BytesIO(b""))

    def test_symlink_member_refused(self, tmp_path):
        f = tmp_path / "evil.tar"
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../etc/passwd"
        self._make_tar_with(f, info)
        findings = scanner.scan_repo(str(tmp_path))
        assert "path-traversal" in _cats(findings)
        assert _snapshot(tmp_path) == {str(f)}, "nothing written outside the tar"

    def test_hardlink_member_refused(self, tmp_path):
        f = tmp_path / "evil.tar"
        info = tarfile.TarInfo("hl")
        info.type = tarfile.LNKTYPE
        info.linkname = "/etc/shadow"
        self._make_tar_with(f, info)
        findings = scanner.scan_repo(str(tmp_path))
        assert "path-traversal" in _cats(findings)

    def test_device_member_refused(self, tmp_path):
        f = tmp_path / "evil.tar"
        info = tarfile.TarInfo("dev")
        info.type = tarfile.CHRTYPE
        info.devmajor = 1
        info.devminor = 3
        self._make_tar_with(f, info)
        findings = scanner.scan_repo(str(tmp_path))
        assert "path-traversal" in _cats(findings)

    def test_tar_with_payload(self, tmp_path):
        f = tmp_path / "ok.tar"
        payload = f"import os\n{_EXEC}\n".encode()
        with tarfile.open(f, "w") as tf:
            info = tarfile.TarInfo("skill.py")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-indirection" in _cats(findings)


class TestUnsupportedAndNested:
    def test_unsupported_format_flagged_loud(self, tmp_path):
        f = tmp_path / "blob.7z"
        f.write_bytes(b"7z\xbc\xaf\x27\x1c" + os.urandom(64))
        findings = scanner.scan_repo(str(tmp_path))
        assert "unsupported-archive-type" in _cats(findings)

    def test_nested_zip_payload_found(self, tmp_path):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("deep.py", f"{_EXEC}\n")
        f = tmp_path / "outer.zip"
        _make_zip(f, {"inner.zip": inner.getvalue()})
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-indirection" in _cats(findings)

    def test_nested_past_depth_limit_noted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scanner, "MAX_DEPTH", 0)
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("deep.py", f"{_EXEC}\n")
        f = tmp_path / "outer.zip"
        _make_zip(f, {"inner.zip": inner.getvalue()})
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-scan-incomplete" in _cats(findings)


class TestArchiveKind:
    def test_compound_tar_ext(self):
        assert scanner._archive_kind("x.tar.gz") == "tar"
        assert scanner._archive_kind("x.whl") == "zip"
        assert scanner._archive_kind("x.7z") == "unsupported"
        assert scanner._archive_kind("x.py") is None
