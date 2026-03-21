#!/usr/bin/env python3
"""
scan_openclaw_skills.py - OpenClaw/NanoClaw/ClawHub Skill Scanner
Detects: frontmatter abuse, tools.json poisoning, agent config injection,
.clawhubignore bypass, and ClawHavoc delivery patterns.

Sources: Koi Security (ClawHavoc), OWASP MCP Top 10 (2026), Snyk ToxicSkills.
Created by Alex Greenshpun
"""
import os, re, sys, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "openclaw_skills"
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
    except Exception:
        return None


def is_openclaw_skill(repo_path):
    """Return True if repo looks like an OpenClaw/NanoClaw/ClawHub skill.
    Requires at least one OpenClaw-specific marker. SKILL.md alone needs
    frontmatter (---) to distinguish from generic Claude skills.
    """
    # OpenClaw-specific markers (not found in generic repos)
    for name in ('.clawhubignore', 'SOUL.md', 'AGENTS.md'):
        if os.path.isfile(os.path.join(repo_path, name)):
            return True
    # SKILL.md with frontmatter = OpenClaw/NanoClaw style
    skill_md = os.path.join(repo_path, 'SKILL.md')
    if os.path.isfile(skill_md):
        content = _read(skill_md)
        if content and content.startswith('---'):
            return True
    # tools.json with tool definitions (not generic config)
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
        findings.append(_F(SCANNER_NAME, "high", "Missing skill author in frontmatter (unattributed skill)",
            "Unattributed skills are a supply-chain risk.", "SKILL.md", 1, fm_text[:120], "frontmatter"))
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
                    ln = next((i+1 for i, l in enumerate(raw_lines) if val[:40] in l), 0)
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
    if os.path.isdir(mem_dir):
        targets += [os.path.join('memory', f) for f in os.listdir(mem_dir) if f.endswith('.md')]
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
    """Cat 4: Check .clawhubignore for patterns that hide executable code."""
    findings = []
    content = _read(os.path.join(repo_path, '.clawhubignore'))
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


def main(args):
    """Run all OpenClaw skill checks. Returns list[Finding].
    Args can be a namespace with .repo_path or a string path (for testing).
    """
    repo_path = args if isinstance(args, str) else args.repo_path
    if not is_openclaw_skill(repo_path):
        print("[+] Not an OpenClaw skill. Skipping.")
        return []
    print(f"[*] Scanning OpenClaw skill in {repo_path}...")
    findings = []
    findings.extend(scan_frontmatter(repo_path))
    findings.extend(scan_tools_json(repo_path))
    findings.extend(scan_agent_configs(repo_path))
    findings.extend(scan_clawhubignore(repo_path))
    findings.extend(scan_clawhavoc(repo_path))
    return findings


if __name__ == "__main__":
    args = core.parse_common_args(sys.argv, "OpenClaw Skill Scanner")
    findings = main(args)
    core.output_findings(findings, args.format, SCANNER_NAME)
