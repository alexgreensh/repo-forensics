"""Detection tests for the Sept 2026 relay-driven agent-malware batch.

Covers the four gaps verified against 18 live malicious npm packages
(AgentGate tarball-verified list, dev.to/agentgate, 2026-09-06):
  1. ESM destructured child_process imports + bare spawn() evaded SA-JS-005.
  2. MCP tools registering remote shell/patch execution were invisible.
  3. Auth-gate inversion (DANGEROUSLY_OMIT_AUTH !== "false") had no rule.
  4. walk_repo skipped dist/, which is the entire payload of an npm tarball.
Plus the package.json self-IOC and provenance-squat checks.
"""

import json
import os

import forensics_core as core
import scan_sast as sast
import scan_mcp_security as mcp
import scan_dependencies as deps


def _walk_scan(scanner, repo_path):
    findings = []
    for fp, rp in core.walk_repo(str(repo_path)):
        findings.extend(scanner.scan_file(fp, rp))
    return findings


def _pkg(root):
    (root / "package.json").write_text(json.dumps({"name": "fixture-pkg", "main": "dist/index.js"}))


def _write(root, rel, content):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


class TestESMChildProcess:
    def test_destructured_spawn_import_flagged(self, tmp_path):
        _pkg(tmp_path)
        _write(tmp_path, "dist/local-effects.js",
               'import { spawn } from "node:child_process";\nconst child = spawn(command, { shell: true });\n')
        findings = _walk_scan(sast, tmp_path)
        ids = {f.rule_id for f in findings}
        assert "SA-JS-035" in ids
        assert "SA-JS-036" in ids

    def test_bare_require_fs_not_flagged(self, tmp_path):
        _write(tmp_path, "index.js", 'import { readFile } from "fs";\nreadFile("x");\n')
        findings = _walk_scan(sast, tmp_path)
        assert "SA-JS-035" not in {f.rule_id for f in findings}

    def test_agent_cli_spawn_flagged(self, tmp_path):
        _pkg(tmp_path)
        _write(tmp_path, "dist/agent/claude.js",
               'spawnAgent("claude", ["-p", fullPrompt]);\n')
        findings = _walk_scan(sast, tmp_path)
        assert "SA-JS-037" in {f.rule_id for f in findings}

    def test_node_spawn_not_flagged(self, tmp_path):
        _write(tmp_path, "index.js", "spawn('node', args);\n")
        findings = _walk_scan(sast, tmp_path)
        assert "SA-JS-037" not in {f.rule_id for f in findings}


class TestAuthInversion:
    def test_omit_auth_inverted_flagged(self, tmp_path):
        _pkg(tmp_path)
        _write(tmp_path, "build/index.js",
               'const authDisabled = process.env.DANGEROUSLY_OMIT_AUTH !== "false";\n')
        findings = _walk_scan(sast, tmp_path)
        assert "SA-JS-038" in {f.rule_id for f in findings}

    def test_safe_direction_not_flagged(self, tmp_path):
        _write(tmp_path, "index.js",
               'const authDisabled = process.env.DANGEROUSLY_OMIT_AUTH === "true";\n')
        findings = _walk_scan(sast, tmp_path)
        assert "SA-JS-038" not in {f.rule_id for f in findings}


class TestMcpRemoteExec:
    def test_run_command_tool_flagged(self, tmp_path):
        _pkg(tmp_path)
        _write(tmp_path, "dist/mcp-server.js",
               'server.tool("tunnel_run_command", "Run a local shell command in the bridge workdir", {});\n')
        findings = _walk_scan(mcp, tmp_path)
        ids = {f.rule_id for f in findings}
        assert "SM-CFG-007" in ids
        assert "SM-CFG-008" in ids

    def test_benign_tool_not_flagged(self, tmp_path):
        _write(tmp_path, "server.js", 'server.tool("get_weather", "Read the forecast");\n')
        findings = _walk_scan(mcp, tmp_path)
        ids = {f.rule_id for f in findings}
        assert "SM-CFG-007" not in ids
        assert "SM-CFG-008" not in ids


class TestTarballWalk:
    def test_dist_walked_for_package_tarball(self, tmp_path):
        _write(tmp_path, "package.json", json.dumps({"name": "x", "main": "dist/index.js"}))
        _write(tmp_path, "dist/index.js", 'spawnAgent("claude", ["-p", p]);\n')
        findings = _walk_scan(sast, tmp_path)
        assert any(f.file.replace(os.sep, "/").endswith("dist/index.js") for f in findings)

    def test_dist_still_skipped_beside_source_tree(self, tmp_path):
        _write(tmp_path, "package.json", json.dumps({"name": "x"}))
        _write(tmp_path, "src/index.js", "const a = 1;\n")
        _write(tmp_path, "dist/index.js", 'spawnAgent("claude", ["-p", p]);\n')
        findings = _walk_scan(sast, tmp_path)
        assert not any("dist" in f.file.split(os.sep) for f in findings)


class TestPackageJsonChecks:
    def test_self_ioc_flagged(self, tmp_path):
        p = _write(tmp_path, "package.json", json.dumps({"name": "agenttunnels", "version": "0.1.17"}))
        findings = deps.scan_package_json(str(p), "package.json")
        assert any("Known Malicious Package (self)" in f.title for f in findings)

    def test_provenance_squat_flagged(self, tmp_path):
        p = _write(tmp_path, "package.json", json.dumps({
            "name": "@atom8n/inspector", "author": "Anthropic, PBC (https://anthropic.com)",
            "homepage": "https://modelcontextprotocol.io"}))
        findings = deps.scan_package_json(str(p), "package.json")
        assert any("Provenance Squat" in f.title for f in findings)

    def test_canonical_scope_not_flagged(self, tmp_path):
        p = _write(tmp_path, "package.json", json.dumps({
            "name": "@modelcontextprotocol/inspector", "author": "Anthropic, PBC",
            "homepage": "https://modelcontextprotocol.io"}))
        findings = deps.scan_package_json(str(p), "package.json")
        assert not any("Provenance Squat" in f.title for f in findings)

    def test_unrelated_package_not_flagged(self, tmp_path):
        p = _write(tmp_path, "package.json", json.dumps({
            "name": "@someone/toolkit", "author": "Some Dev", "homepage": "https://example.dev"}))
        findings = deps.scan_package_json(str(p), "package.json")
        assert not any("Provenance Squat" in f.title for f in findings)


class TestAgentCLIPermissionBypass:
    """SA-JS-039 / SA-TS-019 / SA-SH-025: --dangerously-skip-permissions and
    bypassPermissions passed to agent CLIs (MCPA-2026-0063/0084 pattern)."""

    def _titles(self, root):
        return [f.title for f in _walk_scan(sast, root)]

    def test_js_spawn_flag_flagged(self, tmp_path):
        _pkg(tmp_path)
        _write(tmp_path, "dist/spawn.js",
               "permissionFlags.push('--dangerously-skip-permissions');\n")
        assert any("Permission Bypass" in t for t in self._titles(tmp_path))

    def test_js_bypass_permissions_const_flagged(self, tmp_path):
        _pkg(tmp_path)
        _write(tmp_path, "dist/spawn.js",
               "if (input.permissionMode === 'bypassPermissions') { go(); }\n")
        assert any("Permission Bypass" in t for t in self._titles(tmp_path))

    def test_ts_permission_mode_bypass_flagged(self, tmp_path):
        _pkg(tmp_path)
        _write(tmp_path, "src/run.ts",
               "spawn('claude', ['--permission-mode', 'bypass']);\n")
        assert any("Permission Bypass" in t for t in self._titles(tmp_path))

    def test_shell_wrapper_flagged(self, tmp_path):
        _pkg(tmp_path)
        _write(tmp_path, "dist/run-claude.sh",
               "#!/bin/bash\nclaude -p \"$PROMPT\" \\\n  --dangerously-skip-permissions \\\n")
        assert any("Permission Bypass" in t for t in self._titles(tmp_path))

    def test_benign_spawn_not_flagged(self, tmp_path):
        _pkg(tmp_path)
        _write(tmp_path, "dist/run.sh", "#!/bin/bash\nclaude -p \"$PROMPT\"\n")
        _write(tmp_path, "dist/s.js", "spawn('claude', ['-p', prompt]);\n")
        assert not any("Permission Bypass" in t for t in self._titles(tmp_path))

    def test_permission_mode_auto_not_flagged(self, tmp_path):
        _pkg(tmp_path)
        _write(tmp_path, "src/audit.js",
               "spawn(claudeCmd, ['-p', '--permission-mode', 'auto']);\n")
        assert not any("Permission Bypass" in t for t in self._titles(tmp_path))
