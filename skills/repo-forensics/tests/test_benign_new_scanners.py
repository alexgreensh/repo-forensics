"""
test_benign_new_scanners.py - R9 benign-corpus gate for the 2026-06
scanner-bypass scanners (oversize, bytecode, archive).

These scanners reach file classes the text scanners skip (oversized/padded
files, .pyc bytecode, archives), so they need their own false-positive gate on
realistic benign inputs: a normal .docx, a real wheel, a SOURCE-STRIPPED wheel
that ships only .pyc, a populated __pycache__, and a large benign asset.

R9 requires ZERO new critical/high on these inputs. We assert at the source
(pre-adjudication) level, which is stricter than R9's post-adjudication bar — if
a benign fixture trips a critical/high here, it is a real false positive to fix.
The only signals allowed on benign inputs are low/medium notes (e.g. the
oversized-file low note, an orphan-bytecode low note outside vendor dirs).

Pure stdlib + project imports; no network, no subprocess except the bytecode
scanner's own isolated child.
"""

import io
import os
import py_compile
import zipfile

import scan_archive
import scan_bytecode
import scan_oversize


def _crit_high(findings):
    return [f for f in findings if f.severity in ("critical", "high")]


def _titles(findings):
    return [f"{f.severity}:{f.category}:{f.title}" for f in findings]


def _build_real_wheel(path):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("pkg/__init__.py", "__version__ = '1.2.3'\n")
        zf.writestr("pkg/core.py",
                    "import json\n\n\ndef load(s):\n    return json.loads(s)\n")
        zf.writestr("pkg-1.2.3.dist-info/METADATA",
                    "Metadata-Version: 2.1\nName: pkg\nVersion: 1.2.3\n")
        zf.writestr("pkg-1.2.3.dist-info/RECORD", "pkg/__init__.py,,\n")
        zf.writestr("pkg-1.2.3.dist-info/WHEEL", "Wheel-Version: 1.0\n")


def _build_normal_docx(path):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        zf.writestr("word/document.xml",
                    '<?xml version="1.0"?><document><body>'
                    '<p>Quarterly results were strong this period.</p>'
                    '</body></document>')
        zf.writestr("docProps/core.xml", "<coreProperties/>")


class TestBenignArchives:
    def test_real_wheel_no_critical_high(self, tmp_path):
        _build_real_wheel(tmp_path / "pkg-1.2.3-py3-none-any.whl")
        findings = scan_archive.scan_repo(str(tmp_path))
        assert _crit_high(findings) == [], _titles(findings)

    def test_normal_docx_no_findings(self, tmp_path):
        _build_normal_docx(tmp_path / "report.docx")
        findings = scan_archive.scan_repo(str(tmp_path))
        assert _crit_high(findings) == [], _titles(findings)

    def test_empty_zip_no_critical_high(self, tmp_path):
        with zipfile.ZipFile(tmp_path / "empty.zip", "w"):
            pass
        findings = scan_archive.scan_repo(str(tmp_path))
        assert _crit_high(findings) == [], _titles(findings)


class TestBenignBytecode:
    def test_normal_pycache_with_sibling_no_finding(self, tmp_path):
        pkg = tmp_path / "pkg"
        cache = pkg / "__pycache__"
        cache.mkdir(parents=True)
        src = pkg / "util.py"
        src.write_text("import json\n\n\ndef dump(x):\n    return json.dumps(x)\n")
        py_compile.compile(str(src), cfile=str(cache / "util.cpython-314.pyc"), doraise=True)
        findings = scan_bytecode.scan_repo(str(tmp_path))
        assert findings == [], _titles(findings)

    def test_source_stripped_vendored_wheel_no_finding(self, tmp_path):
        # A stripped wheel ships loose .pyc with no .py under site-packages.
        vendor = tmp_path / "site-packages" / "thirdparty"
        vendor.mkdir(parents=True)
        src = vendor / "mod.py"
        src.write_text("import json\n\n\ndef f(s):\n    return json.loads(s)\n")
        py_compile.compile(str(src), cfile=str(vendor / "mod.pyc"), doraise=True)
        src.unlink()
        findings = scan_bytecode.scan_repo(str(tmp_path))
        # Vendored orphan with no primitive -> suppressed entirely.
        assert findings == [], _titles(findings)


class TestBenignOversize:
    def test_large_benign_asset_low_note_only(self, tmp_path):
        # 11 MB benign asset: allowed signal is the oversized-file low note only.
        f = tmp_path / "asset.dat"
        f.write_bytes(b"benign content line\n" * (11 * 1024 * 1024 // 20 + 1))
        findings = scan_oversize.scan_repo(str(tmp_path))
        assert _crit_high(findings) == [], _titles(findings)
        # And it is reported (not silently dropped).
        assert any(fnd.category == "oversized-file" for fnd in findings)

    def test_normal_source_tree_no_findings(self, tmp_path):
        (tmp_path / "a.py").write_text("def f():\n    return 1\n\n\nx = f()\n")
        (tmp_path / "b.md").write_text("# Title\n\nSome documentation.\n")
        findings = scan_oversize.scan_repo(str(tmp_path))
        assert findings == [], _titles(findings)


class TestCombinedBenignTree:
    def test_all_three_scanners_clean_tree(self, tmp_path):
        # A realistic benign mini-repo touched by all three scanners.
        _build_real_wheel(tmp_path / "dep.whl")
        _build_normal_docx(tmp_path / "readme.docx")
        pkg = tmp_path / "pkg"
        cache = pkg / "__pycache__"
        cache.mkdir(parents=True)
        src = pkg / "m.py"
        src.write_text("VALUE = 42\n")
        py_compile.compile(str(src), cfile=str(cache / "m.cpython-314.pyc"), doraise=True)

        all_findings = []
        all_findings += scan_archive.scan_repo(str(tmp_path))
        all_findings += scan_bytecode.scan_repo(str(tmp_path))
        all_findings += scan_oversize.scan_repo(str(tmp_path))
        assert _crit_high(all_findings) == [], _titles(all_findings)
