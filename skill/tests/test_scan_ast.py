"""Tests for scan_ast.py - Python AST Obfuscation Detector (new patterns 6-12)."""

import os
import pytest
import scan_ast as scanner


class TestExistingPatterns:
    """Verify existing patterns still work after enhancement."""

    def test_exec_base64_decode(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("import base64\nexec(base64.b64decode('cHJpbnQ='))\n")
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("Encoded Payload" in f.title for f in findings)

    def test_eval_compile(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("eval(compile('print(1)', '<>', 'exec'))\n")
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("eval(compile" in f.title for f in findings)

    def test_dunder_import_system(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("__import__('os').system('whoami')\n")
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("__import__" in f.title for f in findings)

    def test_getattr_evasion(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("getattr(os, 'system')('whoami')\n")
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("getattr" in f.title for f in findings)

    def test_pickle_reduce(self, repo_with_obfuscation):
        """Test that existing obfuscation fixture still detects."""
        for fp, rp in [(str(repo_with_obfuscation / "evil.py"), "evil.py")]:
            findings = scanner.scan_file(fp, rp)
            assert len(findings) > 0


class TestNewPattern6ImportlibVariable:
    def test_importlib_import_module_variable(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text(
            "import importlib\n"
            "mod = importlib.import_module(module_name)\n"
        )
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("importlib.import_module" in f.title for f in findings)

    def test_importlib_import_module_literal_no_flag(self, tmp_path):
        f = tmp_path / "safe.py"
        f.write_text(
            "import importlib\n"
            "mod = importlib.import_module('json')\n"
        )
        findings = scanner.scan_file(str(f), "safe.py")
        importlib_findings = [f for f in findings if "importlib.import_module" in f.title]
        assert len(importlib_findings) == 0


class TestNewPattern7ImportlibReload:
    def test_importlib_reload(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text(
            "import importlib\n"
            "import my_module\n"
            "importlib.reload(my_module)\n"
        )
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("reload" in f.title.lower() for f in findings)


class TestNewPattern8MarshalLoads:
    def test_marshal_loads(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text(
            "import marshal\n"
            "code = marshal.loads(data)\n"
        )
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("marshal" in f.title.lower() for f in findings)

    def test_marshal_load(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text(
            "import marshal\n"
            "with open('code.pyc', 'rb') as fh:\n"
            "    code = marshal.load(fh)\n"
        )
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("marshal" in f.title.lower() for f in findings)


class TestNewPattern9TypesConstruction:
    def test_types_function_type(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text(
            "import types\n"
            "func = types.FunctionType(code_obj, globals())\n"
        )
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("types.FunctionType" in f.title for f in findings)

    def test_types_code_type(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text(
            "import types\n"
            "code = types.CodeType(0, 0, 0, 0, 0, b'', (), (), (), '', '', 0, b'')\n"
        )
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("types.CodeType" in f.title for f in findings)


class TestNewPattern10AuditHook:
    def test_sys_addaudithook(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text(
            "import sys\n"
            "sys.addaudithook(lambda event, args: None)\n"
        )
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("addaudithook" in f.title.lower() for f in findings)


class TestNewPattern11BytesDecodeObfuscation:
    def test_bytes_list_decode(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("cmd = bytes([112, 114, 105, 110, 116]).decode()\n")
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("bytes" in f.title.lower() or "obfuscation" in f.title.lower() for f in findings)

    def test_bytearray_list_decode(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("cmd = bytearray([112, 114, 105, 110, 116]).decode()\n")
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("bytes" in f.title.lower() or "obfuscation" in f.title.lower() or "bytearray" in f.title.lower() for f in findings)


class TestNewPattern12SelfModification:
    def test_open_self_write(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("with open(__file__, 'w') as fh:\n    fh.write('pwned')\n")
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("self-modification" in f.title.lower() or "__file__" in f.title for f in findings)

    def test_open_self_append(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("f = open(__file__, 'a')\nf.write('# injected')\n")
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("self-modification" in f.title.lower() or "__file__" in f.title for f in findings)


class TestCleanCode:
    def test_clean_python(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text(
            "import json\nimport os\n\n"
            "def process(data):\n"
            "    return json.dumps(data)\n"
        )
        findings = scanner.scan_file(str(f), "clean.py")
        assert len(findings) == 0

    def test_non_python_file(self, tmp_path):
        f = tmp_path / "clean.js"
        f.write_text("console.log('hello');\n")
        findings = scanner.scan_file(str(f), "clean.js")
        assert len(findings) == 0
