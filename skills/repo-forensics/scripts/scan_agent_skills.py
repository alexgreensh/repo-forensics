#!/usr/bin/env python3
"""
scan_agent_skills.py - Agent Skill Security Scanner
Scans AI agent skills and plugins across ecosystems: Claude Code, OpenClaw,
Codex, Cursor, and generic MCP servers.
Detects: frontmatter abuse, tools.json poisoning, agent config injection,
.clawhubignore bypass, and ClawHavoc delivery patterns.

Sources: Koi Security (ClawHavoc), OWASP MCP Top 10 (2026), Snyk ToxicSkills.
Created by Alex Greenshpun
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
from _shared_patterns import (
    AUTO_EXEC_PATHS_RE, GIT_UPDATABLE, REF_FILE_EXTS_RE,
    REF_VERBS_RE, SEED_FILES, WRITE_VERBS_RE,
)

SCANNER_NAME = "agent_skills"
_F = core.Finding  # shorthand

# --- Pattern lists ---
PROMPT_INJECTION_RE = [
    re.compile(r'(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|directives|prompts|rules)'),
    re.compile(r'(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|context)'),
    re.compile(r'(?i)you\s+are\s+now\s+(a|an|my)\s+\w+'),
    re.compile(r'(?i)silently\s+(execute|run|perform|install|download)'),
    re.compile(r'(?i)override\s+(safety|security|restriction|guardrail|filter)'),
    re.compile(r'(?i)forget\s+(everything|all|your)\s+(you|instructions|training|rules)'),
    re.compile(r'(?i)new\s+(system\s+)?instructions'),
    re.compile(r'(?i)act\s+as\s+(if|though)\s+you\s+(have|had)\s+no\s+(restrictions|limits|rules)'),
    re.compile(r'(?i)pretend\s+you\s+are\b'),
]
CRED_ACCESS_RE = [
    re.compile(r'(?i)(os\.environ|process\.env)'), re.compile(r'(?i)\bAPI_KEY\b'),
    re.compile(r'(?i)\b(token|password|secret|credential)\s*[=:]'),
    re.compile(r'(?i)~/\.ssh\b'), re.compile(r'(?i)\bkeychain\b'), re.compile(r'(?i)\b\.env\b'),
]
TOOL_INJECTION_KW = [
    (re.compile(r'(?i)\bIMPORTANT\b'), "IMPORTANT directive in tool metadata", "critical"),
    (re.compile(r'(?i)ignore\s+previous\b'), "Instruction override in tool metadata", "critical"),
    (re.compile(r'(?i)you\s+must\b'), "Coercive directive in tool metadata", "high"),
    (re.compile(r'(?i)do\s+not\s+tell\b'), "Concealment directive in tool metadata", "high"),
    (re.compile(r'(?i)\bsystem:\b'), "System role injection in tool metadata", "critical"),
    (re.compile(r'(?i)\bassistant:\b'), "Assistant role injection in tool metadata", "critical"),
]
CRED_FIELD_RE = re.compile(r'(?i)(api_key|token|password|secret|credential|auth)')
BROAD_TRIGGERS = {'help', 'search', 'code', 'write', 'run', 'build', 'fix', 'test', 'chat', 'ask'}
IGNORE_EXEC_RE = [re.compile(p) for p in [
    r'^\*\.py$', r'^\*\.js$', r'^\*\.sh$', r'^\*\.ts$', r'^hooks/?$', r'^scripts/?$', r'^\.env$']]
IGNORE_WILDCARDS = {'*', '**/*', '**'}
CLAWHAVOC = [
    (re.compile(r'(?i)(OpenClawDriver|ClawDriver)'), "critical", "Fake prerequisite driver reference (ClawHavoc campaign)"),
    (re.compile(r'(?i)install\.app-distribution\.net'), "critical", "Known AMOS delivery domain (ClawHavoc campaign)"),
    (re.compile(r'(?i)base64\s+(-D|--decode)\s*\|\s*(bash|sh)'), "critical", "Base64 decode piped to shell execution"),
    (re.compile(r'(?i)pass(word)?:\s*openclaw'), "high", "Password-protected archive with OpenClaw password"),
]


def _read(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def is_agent_skill(repo_path):
    """Return True if repo looks like an AI agent skill, plugin, or extension.
    Covers: Claude Code, OpenClaw/NanoClaw/ClawHub, Codex, Cursor, generic MCP.
    """
    # OpenClaw/ClawHub markers
    for name in ('.clawhubignore', '.clawdhubignore', 'SOUL.md',
                 'USER.md', 'IDENTITY.md', 'HEARTBEAT.md', 'BOOT.md', 'BOOTSTRAP.md',
                 'openclaw.plugin.json'):
        if os.path.isfile(os.path.join(repo_path, name)):
            return True
    # Claude Code skill/plugin markers
    if os.path.isdir(os.path.join(repo_path, '.claude')):
        return True
    if os.path.isdir(os.path.join(repo_path, '.claude-plugin')):
        return True
    # Codex markers
    if os.path.isfile(os.path.join(repo_path, 'codex.json')):
        return True
    if os.path.isdir(os.path.join(repo_path, '.codex')):
        return True
    # Cursor extension markers
    if os.path.isdir(os.path.join(repo_path, '.cursor')):
        return True
    # AGENTS.md (used by multiple agent frameworks)
    if os.path.isfile(os.path.join(repo_path, 'AGENTS.md')):
        return True
    # SKILL.md (any agent skill with frontmatter or without)
    if os.path.isfile(os.path.join(repo_path, 'SKILL.md')):
        return True
    # package.json with openclaw namespace
    pkg_json = os.path.join(repo_path, 'package.json')
    if os.path.isfile(pkg_json):
        content = _read(pkg_json)
        if content:
            try:
                data = json.loads(content)
                if 'openclaw' in data and 'extensions' in data.get('openclaw', {}):
                    return True
            except (json.JSONDecodeError, TypeError):
                pass
    # tools.json with MCP-style tool definitions (any MCP server)
    tools_json = os.path.join(repo_path, 'tools.json')
    if os.path.isfile(tools_json):
        content = _read(tools_json)
        if content:
            try:
                data = json.loads(content)
                tools = data if isinstance(data, list) else data.get('tools', [])
                if tools and isinstance(tools[0], dict) and ('inputSchema' in tools[0] or 'description' in tools[0]):
                    return True
            except (json.JSONDecodeError, IndexError, TypeError):
                pass
    # MCP config files (.mcp.json, mcp.json)
    for name in ('.mcp.json', 'mcp.json'):
        if os.path.isfile(os.path.join(repo_path, name)):
            return True
    return False


def scan_frontmatter(repo_path):
    """Cat 1: Parse SKILL.md frontmatter, validate name/author/triggers/description."""
    findings = []
    content = _read(os.path.join(repo_path, 'SKILL.md'))
    if not content:
        return findings
    fm_match = re.match(r'^---\s*\n(.*?)\n---', content, re.DOTALL)
    if not fm_match:
        return findings
    fm_text = fm_match.group(1)
    fields = {}
    for line in fm_text.split('\n'):
        m = re.match(r'^(\w[\w-]*):\s*(.*)', line)
        if m:
            fields[m.group(1).lower()] = m.group(2).strip()
    if not fields.get('name'):
        findings.append(_F(SCANNER_NAME, "high", "Missing skill name in frontmatter",
            "SKILL.md frontmatter has no 'name' field.", "SKILL.md", 1, fm_text[:120], "frontmatter"))
    if not fields.get('author'):
        # Note: 'author' is not an official OpenClaw frontmatter field (identity comes from
        # ClawHub account), but unattributed skills in the wild are a supply-chain signal.
        findings.append(_F(SCANNER_NAME, "medium", "Missing skill author in frontmatter (unattributed skill)",
            "No author field in frontmatter. In OpenClaw, author comes from ClawHub account, but standalone skills should declare authorship.",
            "SKILL.md", 1, fm_text[:120], "frontmatter"))
    if 'triggers' in fields:
        raw = fields['triggers']
        for w in re.findall(r'[\w]+', raw.lower()):
            if w in BROAD_TRIGGERS:
                findings.append(_F(SCANNER_NAME, "medium", f"Overly broad trigger keyword: '{w}'",
                    f"Trigger '{w}' matches too many intents, risking skill hijacking.",
                    "SKILL.md", 1, raw[:120], "frontmatter"))
    desc = fields.get('description', '')
    for pat in PROMPT_INJECTION_RE:
        if pat.search(desc):
            findings.append(_F(SCANNER_NAME, "high", "Prompt injection in skill description",
                "Frontmatter description contains prompt injection.", "SKILL.md", 1, desc[:120], "frontmatter"))
            break
    return findings


def scan_tools_json(repo_path):
    """Cat 2: Check tools.json for schema poisoning and credential fields."""
    findings = []
    path = os.path.join(repo_path, 'tools.json')
    raw = _read(path)
    if not raw:
        return findings
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        findings.append(_F(SCANNER_NAME, "medium", "Unparseable tools.json",
            "tools.json could not be parsed as JSON. Manual review required.",
            "tools.json", 0, raw[:80], "tool-poisoning"))
        return findings
    tools = data if isinstance(data, list) else data.get('tools', [data]) if isinstance(data, dict) else []
    raw_lines = raw.split('\n')
    for idx, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue
        tname = tool.get('name', f'#{idx}')
        for fld in ('description', 'name', 'title', 'summary'):
            val = tool.get(fld, '')
            if not isinstance(val, str):
                continue
            for pat, title, sev in TOOL_INJECTION_KW:
                if pat.search(val):
                    ln = next((i+1 for i, line in enumerate(raw_lines) if val[:40] in line), 0)
                    findings.append(_F(SCANNER_NAME, sev, title,
                        f"Tool '{tname}' field '{fld}' contains injection pattern.",
                        "tools.json", ln, val[:120], "tool-poisoning"))
        schema = tool.get('inputSchema', {})
        if isinstance(schema, dict):
            for prop in (schema.get('properties', {}) or {}):
                if CRED_FIELD_RE.search(prop):
                    findings.append(_F(SCANNER_NAME, "high", "Tool requests credential input",
                        f"Tool '{tname}' has credential-type input '{prop}'.",
                        "tools.json", 0, f"inputSchema.properties.{prop}", "tool-poisoning"))
    return findings


def scan_agent_configs(repo_path):
    """Cat 3: Scan SOUL.md, AGENTS.md, CLAUDE.md, memory/*.md for injection + credential access."""
    findings = []
    targets = ['SOUL.md', 'AGENTS.md', 'CLAUDE.md']
    mem_dir = os.path.join(repo_path, 'memory')
    try:
        if os.path.isdir(mem_dir):
            targets += [os.path.join('memory', f) for f in os.listdir(mem_dir) if f.endswith('.md')]
    except OSError:
        findings.append(_F(SCANNER_NAME, "medium", "Memory directory unreadable",
            "Could not list memory/ directory - memory files were not scanned for injection.",
            "memory/", 0, "", "agent-access-error"))
    for rel in targets:
        content = _read(os.path.join(repo_path, rel))
        if not content:
            continue
        for i, line in enumerate(content.split('\n')):
            if len(line) > core.MAX_LINE_LENGTH:
                continue
            for pat in PROMPT_INJECTION_RE:
                if pat.search(line):
                    findings.append(_F(SCANNER_NAME, "critical", "Safety override in agent config",
                        f"Prompt injection in {rel}.", rel, i+1, line.strip()[:120], "agent-injection"))
                    break
            for pat in CRED_ACCESS_RE:
                if pat.search(line):
                    findings.append(_F(SCANNER_NAME, "high", "Credential access in agent config",
                        f"Agent config {rel} references credentials.", rel, i+1, line.strip()[:120], "agent-injection"))
                    break
    return findings


def scan_clawhubignore(repo_path):
    """Cat 4: Check .clawhubignore (or legacy .clawdhubignore) for patterns that hide executable code."""
    findings = []
    # Support both current and legacy spelling
    content = _read(os.path.join(repo_path, '.clawhubignore'))
    if not content:
        content = _read(os.path.join(repo_path, '.clawdhubignore'))
    if not content:
        return findings
    for i, raw in enumerate(content.split('\n')):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line in IGNORE_WILDCARDS:
            findings.append(_F(SCANNER_NAME, "critical", "Wildcard ignore suppresses all ClawHub scanning",
                f"Pattern '{line}' hides ALL files from ClawHub review.",
                ".clawhubignore", i+1, line, "clawhubignore-bypass"))
        else:
            for pat in IGNORE_EXEC_RE:
                if pat.search(line):
                    findings.append(_F(SCANNER_NAME, "high",
                        "Ignore pattern hides executable code from ClawHub scanner",
                        f"Pattern '{line}' hides reviewable files.",
                        ".clawhubignore", i+1, line, "clawhubignore-bypass"))
                    break
    return findings


def scan_clawhavoc(repo_path):
    """Cat 5: Scan OpenClaw-specific files for ClawHavoc delivery patterns.
    Only scans SKILL.md, tools.json, SOUL.md, AGENTS.md to avoid duplicating
    scan_skill_threats.py which already covers the full repo for these IOCs.
    """
    findings = []
    openclaw_files = ['SKILL.md', 'tools.json', 'SOUL.md', 'AGENTS.md']
    for name in openclaw_files:
        file_path = os.path.join(repo_path, name)
        content = _read(file_path)
        if not content:
            continue
        for i, line in enumerate(content.split('\n')):
            if len(line) > core.MAX_LINE_LENGTH:
                continue
            for pat, sev, title in CLAWHAVOC:
                if pat.search(line):
                    findings.append(_F(SCANNER_NAME, sev, title,
                        f"ClawHavoc delivery indicator in {name}",
                        name, i+1, line.strip()[:120], "clawhavoc-delivery"))
    return findings


def scan_plugin_manifest(repo_path):
    """Cat 6: Check openclaw.plugin.json for suspicious patterns."""
    findings = []
    content = _read(os.path.join(repo_path, 'openclaw.plugin.json'))
    if not content:
        return findings
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        findings.append(_F(SCANNER_NAME, "medium", "Unparseable openclaw.plugin.json",
            "Plugin manifest could not be parsed.", "openclaw.plugin.json", 0, content[:80], "plugin-manifest"))
        return findings
    # Check for missing required fields
    if not data.get('id'):
        findings.append(_F(SCANNER_NAME, "high", "Missing plugin id in manifest",
            "openclaw.plugin.json missing required 'id' field.", "openclaw.plugin.json", 0, "", "plugin-manifest"))
    if not data.get('configSchema'):
        findings.append(_F(SCANNER_NAME, "medium", "Missing configSchema in manifest",
            "openclaw.plugin.json missing required 'configSchema' field.", "openclaw.plugin.json", 0, "", "plugin-manifest"))
    # Check description/name for injection
    for fld in ('name', 'description'):
        val = data.get(fld, '')
        if isinstance(val, str):
            for pat in PROMPT_INJECTION_RE:
                if pat.search(val):
                    findings.append(_F(SCANNER_NAME, "critical", f"Prompt injection in plugin manifest {fld}",
                        f"Plugin manifest '{fld}' contains injection pattern.", "openclaw.plugin.json", 0, val[:120], "plugin-manifest"))
                    break
    return findings


# ============================================================
# Cat 7: Workspace Config Write Requests (high)
# Skills that instruct agents to write to auto-executed config files.
# Source: Terra Security OpenClaw vulnerability research (May 2026)
# ============================================================
_AUTO_EXEC_FILES = AUTO_EXEC_PATHS_RE
_WRITE_VERBS = WRITE_VERBS_RE

CONFIG_WRITE_PATTERNS = [
    (re.compile(r'(?i)\b' + _WRITE_VERBS + r'\b[^\n]{0,60}\b(?:to|in|into)\s+' + _AUTO_EXEC_FILES), "Config write request: modify auto-executed file (Terra Security OpenClaw, May 2026)"),
    (re.compile(r'(?i)\b' + _WRITE_VERBS + r'\b[^\n]{0,40}' + _AUTO_EXEC_FILES), "Config write request: target auto-executed file (Terra Security OpenClaw, May 2026)"),
    (re.compile(r'(?i)\b(?:create|install|register|set\s+up)\s+(?:a\s+)?(?:PreToolUse|PostToolUse|SessionStart|hook)\b'), "Config write request: hook installation directive (Terra Security OpenClaw, May 2026)"),
]


def scan_config_write_requests(repo_path):
    """Cat 7: Detect skills that instruct agents to write to auto-executed config files."""
    findings = []
    for root, _dirs, files in os.walk(repo_path):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in ('.md', '.txt', '.yml', '.yaml', '.toml', '.cfg', '.ini', '.json'):
                continue
            fpath = os.path.join(root, fname)
            content = _read(fpath)
            if not content:
                continue
            rel = os.path.relpath(fpath, repo_path)
            for i, line in enumerate(content.split('\n')):
                if len(line) > core.MAX_LINE_LENGTH:
                    continue
                for pat, title in CONFIG_WRITE_PATTERNS:
                    if pat.search(line):
                        if re.search(r'(?i)\b(?:users?\s+can|you\s+(?:can|may)|documentation|how\s+to)\b', line):
                            continue
                        findings.append(_F(SCANNER_NAME, "high", title,
                            "Skill instructs agent to write to auto-executed config file",
                            rel, i + 1, line.strip()[:120], "config-write-request"))
                        break
    return findings


# ============================================================
# Cat 8: Trusted File Reference Chains (medium/high)
# Transitive reference chains that create trust-laundering pipelines.
# Source: Terra Security OpenClaw vulnerability research (May 2026)
# ============================================================
_SEED_FILES = SEED_FILES
_GIT_UPDATABLE = GIT_UPDATABLE
_REF_PATTERN = re.compile(r'(?i)\b' + REF_VERBS_RE + r'\s+(\S+\.' + REF_FILE_EXTS_RE + r')\b')
_MAX_CHAIN_DEPTH = 5


def scan_reference_chains(repo_path):
    """Cat 8: Detect transitive file reference chains from seed config files."""
    findings = []
    graph = {}
    for seed in _SEED_FILES:
        seed_path = os.path.join(repo_path, seed)
        content = _read(seed_path)
        if not content:
            continue
        refs = _REF_PATTERN.findall(content)
        if refs:
            graph[seed] = [r for r in refs if r.lower() != seed.lower()]

    for ref_file in list(graph.values()):
        for rf in ref_file:
            rf_path = os.path.join(repo_path, rf)
            content = _read(rf_path)
            if not content:
                continue
            refs = _REF_PATTERN.findall(content)
            if refs:
                graph[rf] = [r for r in refs if r.lower() != rf.lower()]

    for seed in _SEED_FILES:
        if seed not in graph:
            continue
        _find_chains(seed, graph, [], findings, repo_path)

    return findings


def _find_chains(current, graph, path, findings, repo_path):
    if len(path) >= _MAX_CHAIN_DEPTH:
        return
    for ref in graph.get(current, []):
        if ref in path:
            continue
        new_path = path + [current]
        chain_depth = len(new_path)
        if chain_depth >= 2:
            terminates_at_updatable = ref.lower() in _GIT_UPDATABLE
            severity = "high" if chain_depth >= 3 or terminates_at_updatable else "medium"
            chain_str = " -> ".join(new_path + [ref])
            findings.append(_F(SCANNER_NAME, severity,
                f"Trusted file reference chain (depth {chain_depth})",
                f"Chain: {chain_str}. Transitive references create a trust-laundering pipeline (Terra Security OpenClaw, May 2026).",
                new_path[0], 0, chain_str[:120], "reference-chain"))
        if ref in graph:
            _find_chains(ref, graph, new_path, findings, repo_path)


# ============================================================
# Cat 9: Memory/RAG Poisoning Indicators (high/critical)
# Content designed to persist in agent memory or RAG corpus as backdoors.
# Source: DeepMind AI Agent Traps "Cognitive State Poisoning" (March 2026)
# ============================================================
MEMORY_POISONING_PATTERNS = [
    (re.compile(r'(?i)(?:memory_store|memory_write|remember|store_memory|add_memory|save_to_memory)\s*\([^)]*(?:ignore|override|system|admin|always|never|must)'), "Memory write with injection keywords (DeepMind Agent Traps, March 2026)"),
    (re.compile(r'(?i)(?:add|write|store|save|persist|remember)\s+(?:to|in|into)\s+(?:memory|knowledge.?base|rag|vector.?store|embedding|index|corpus).*(?:ignore|override|system|always|never|must|from\s+now\s+on)'), "Memory/RAG poisoning: injection payload in memory write (DeepMind Agent Traps, March 2026)"),
    (re.compile(r'(?i)(?:when\s+(?:retrieved|queried|searched|asked|recalled))\s*[,:]\s*(?:always|never|must|ignore|override|instead)'), "RAG trigger: conditional instruction on retrieval (DeepMind Agent Traps, March 2026)"),
    (re.compile(r'(?i)(?:if\s+(?:this|an)\s+(?:document|chunk|passage|entry)\s+is\s+(?:found|retrieved|returned))\s*[,:]\s*(?:always|ignore|execute|run|override)'), "RAG trigger: conditional execution on document retrieval (DeepMind Agent Traps, March 2026)"),
]

PROVENANCE_STRIP_PATTERNS = [
    (re.compile(r'(?i)(?:do\s+not|never|don\'t)\s+(?:include|add|store|record|log)\s+(?:the\s+)?(?:source|origin|provenance|attribution|timestamp|author)'), "Provenance stripping: suppressing attribution (DeepMind Agent Traps, March 2026)"),
    (re.compile(r'(?i)(?:strip|remove|clear|delete)\s+(?:the\s+)?(?:source|origin|provenance|metadata|attribution)[\w\s]{0,30}(?:from|before|when)'), "Provenance stripping: removing metadata (DeepMind Agent Traps, March 2026)"),
]


_MEMORY_SCAN_EXTS = {'.md', '.txt', '.py', '.js', '.ts', '.json', '.yml', '.yaml'}


def scan_memory_poisoning(repo_path):
    """Cat 9: Detect memory/RAG poisoning indicators."""
    findings = []
    for fpath, rel in core.walk_repo(repo_path, skip_binary=True):
        ext = os.path.splitext(fpath)[1].lower()
        if ext not in _MEMORY_SCAN_EXTS:
            continue
        content = _read(fpath)
        if not content:
            continue
        in_code_fence = False
        for i, line in enumerate(content.split('\n')):
            stripped = line.strip()
            if stripped.startswith('```'):
                in_code_fence = not in_code_fence
                continue
            if in_code_fence and ext in ('.md', '.txt'):
                continue
            if len(line) > core.MAX_LINE_LENGTH:
                continue
            for pat, title in MEMORY_POISONING_PATTERNS:
                if pat.search(line):
                    findings.append(_F(SCANNER_NAME, "high", title,
                        "Content designed to persist as backdoor in agent memory or RAG corpus (DeepMind Agent Traps, March 2026)",
                        rel, i + 1, line.strip()[:120], "memory-poisoning"))
                    break
            for pat, title in PROVENANCE_STRIP_PATTERNS:
                if pat.search(line):
                    findings.append(_F(SCANNER_NAME, "high", title,
                        "Provenance stripping enables untraceable memory poisoning (DeepMind Agent Traps, March 2026)",
                        rel, i + 1, line.strip()[:120], "provenance-stripping"))
                    break
    return findings


def main(args):
    """Run all agent skill checks. Returns list[Finding].
    Args can be a namespace with .repo_path or a string path (for testing).
    """
    repo_path = args if isinstance(args, str) else args.repo_path
    output_format = "text" if isinstance(args, str) else getattr(args, "format", "text")
    if not is_agent_skill(repo_path):
        core.emit_status(output_format, "[+] Not an agent skill. Skipping.")
        return []
    core.emit_status(output_format, f"[*] Scanning agent skill in {repo_path}...")
    findings = []
    findings.extend(scan_frontmatter(repo_path))
    findings.extend(scan_tools_json(repo_path))
    findings.extend(scan_agent_configs(repo_path))
    findings.extend(scan_clawhubignore(repo_path))
    findings.extend(scan_clawhavoc(repo_path))
    findings.extend(scan_plugin_manifest(repo_path))
    findings.extend(scan_config_write_requests(repo_path))
    findings.extend(scan_reference_chains(repo_path))
    findings.extend(scan_memory_poisoning(repo_path))
    return findings


if __name__ == "__main__":
    args = core.parse_common_args(sys.argv, "Agent Skill Scanner")
    findings = main(args)
    core.output_findings(findings, args.format, SCANNER_NAME)
