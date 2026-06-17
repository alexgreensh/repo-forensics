"""Tests for scan_ast.py - Python AST Obfuscation Detector (new patterns 6-12)."""

import base64

import scan_ast as scanner

# Plaintext that trips the SAST/trifecta heuristics once decoded.
# (chr(114) avoids embedding a literal shell pipe in the test source.)
_DECODE_MALICIOUS = b'import os\nos.system(chr(114))\nimport socket\nsubprocess.Popen([])\n'
_DECODE_ENCODED = base64.b64encode(_DECODE_MALICIOUS).decode()


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


class TestDecodeAndRescan:
    """U2: exec(base64.b64decode('...')) is decoded and rescanned, surfacing the
    hidden payload as an additive decoded-payload finding."""

    def test_exec_base64_payload_flags_both(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text('import base64\nexec(base64.b64decode("%s"))\n' % _DECODE_ENCODED)
        findings = scanner.scan_file(str(f), "evil.py")
        cats = [x.category for x in findings]
        assert "obfuscated-exec" in cats, "existing Encoded Payload finding must remain"
        assert "decoded-payload" in cats, "decoded os.system must be surfaced"
        assert any("Encoded Payload" in x.title for x in findings)

    def test_same_blob_twice_decodes_once(self, tmp_path):
        """Same encoded literal used twice in one file decodes once (dedup)."""
        src = (
            'import base64\n'
            'exec(base64.b64decode("%s"))\n'
            'exec(base64.b64decode("%s"))\n'
        ) % (_DECODE_ENCODED, _DECODE_ENCODED)
        f = tmp_path / "evil.py"
        f.write_text(src)
        double = [c for c in (x.category for x in scanner.scan_file(str(f), "evil.py"))
                  if c == "decoded-payload"]

        single = tmp_path / "single.py"
        single.write_text('import base64\nexec(base64.b64decode("%s"))\n' % _DECODE_ENCODED)
        once = [c for c in (x.category for x in scanner.scan_file(str(single), "single.py"))
                if c == "decoded-payload"]
        assert len(double) == len(once), "repeated literal must decode once, not twice"

    def test_benign_base64_no_payload(self, tmp_path):
        """Regression: exec of benign base64 keeps the Encoded Payload finding but
        adds NO decoded-payload finding (no severity inflation)."""
        benign = base64.b64encode(
            b'the quick brown fox jumps over the lazy dog repeatedly today and tomorrow'
        ).decode()
        f = tmp_path / "benign.py"
        f.write_text('import base64\nexec(base64.b64decode("%s"))\n' % benign)
        findings = scanner.scan_file(str(f), "benign.py")
        cats = [x.category for x in findings]
        assert "obfuscated-exec" in cats
        assert "decoded-payload" not in cats


class TestPlainDecodeLiteral:
    """torture H2: a plain `base64.b64decode("...")` NOT wrapped in exec/eval used
    to surface 0 decoded payloads (the decode branch was only reachable inside
    exec(decode(...))). A bare decode-family call with a string literal must now
    extract the literal and route it to scan_decode."""

    def test_bare_b64decode_literal_surfaces_payload(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text('import base64\nx = base64.b64decode("%s")\n' % _DECODE_ENCODED)
        findings = scanner.scan_file(str(f), "evil.py")
        assert "decoded-payload" in [x.category for x in findings], \
            "a plain base64.b64decode literal must surface the decoded payload"

    def test_bare_fromhex_literal_surfaces_payload(self, tmp_path):
        payload = b'import os\nos.system(chr(114))\nimport socket\n'
        hexed = payload.hex()
        f = tmp_path / "evil.py"
        f.write_text('x = bytes.fromhex("%s")\n' % hexed)
        findings = scanner.scan_file(str(f), "evil.py")
        assert "decoded-payload" in [x.category for x in findings], \
            "a plain bytes.fromhex literal must surface the decoded payload"

    def test_bare_benign_literal_no_payload(self, tmp_path):
        benign = base64.b64encode(
            b'the quick brown fox jumps over the lazy dog repeatedly today tomorrow'
        ).decode()
        f = tmp_path / "ok.py"
        f.write_text('x = base64.b64decode("%s")\n' % benign)
        findings = scanner.scan_file(str(f), "ok.py")
        assert "decoded-payload" not in [x.category for x in findings], \
            "a benign decode literal must not inflate into a decoded-payload finding"

    def test_main_threads_one_budget(self, tmp_path, monkeypatch):
        import scan_decode
        calls = {"n": 0}
        real = scan_decode.new_budget

        def counting(deadline=None):
            calls["n"] += 1
            return real(deadline=deadline)

        monkeypatch.setattr(scan_decode, "new_budget", counting)
        for name in ("a.py", "b.py"):
            (tmp_path / name).write_text(
                'import base64\nx = base64.b64decode("%s")\n' % _DECODE_ENCODED)
        monkeypatch.setattr("sys.argv", ["scan_ast.py", str(tmp_path), "--format", "json"])
        scanner.main()
        assert calls["n"] == 1, "main() must mint exactly one shared budget"


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
