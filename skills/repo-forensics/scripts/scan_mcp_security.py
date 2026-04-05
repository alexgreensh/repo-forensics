#!/usr/bin/env python3
"""
scan_mcp_security.py - MCP Attack Surface Scanner (v3)
Detects attack vectors specific to Model Context Protocol servers and tools:
SQL injection -> stored prompt injection, tool metadata poisoning,
indirect prompt injection via sampling, cross-domain privilege escalation,
log-to-leak patterns, tool shadowing, and 2026 attack patterns.

Research basis:
- Invariant Labs (April 2025): Tool Poisoning Attack, tool shadowing, <IMPORTANT> tag
- Palo Alto Unit 42 (Dec 2025): MCP sampling exploitation (3 attack classes)
- Trend Micro TrendAI (May 2025): SQL injection -> stored prompt injection
- OpenReview: MCP log-to-leak analysis
- CVE-2025-59536 (CVSS 8.7): Claude Code hooks RCE via .claude/settings.json
- CVE-2026-21852 (CVSS 5.3): ANTHROPIC_BASE_URL override -> API key exfiltration
- CVE-2025-6514 (CVSS 9.6): mcp-remote OAuth command injection via authorization_endpoint
- CVE-2025-49596 (CVSS 9.4): MCP Inspector DNS rebinding + CSRF
- ClawHavoc campaign (Jan-Feb 2026): 1,184 malicious MCP tool packages

Created by Alex Greenshpun
"""

import os
import re
import sys
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core


def _normalize_for_keyword_match(text):
    """Normalize text before substring matching against TOOL_INJECTION_KEYWORDS.

    Two transformations, both required to prevent trivial bypasses:

    1. Unicode NFKC normalization. Folds compatibility characters to their
       canonical ASCII-ish equivalents so e.g. full-width Latin letters,
       ligatures, and compatibility forms collapse to their base characters.
       Without this, attackers can smuggle injection payloads past ASCII
       keyword matches using visually identical Unicode variants.

    2. Whitespace collapse. The keyword list contains anchored phrases like
       "send to http" and "send credentials to" that require specific space
       placement. Attackers can substitute ASCII spaces with non-breaking
       space (U+00A0), narrow no-break space (U+202F), ideographic space
       (U+3000), or any other Unicode whitespace to evade detection while
       retaining visual identity for human readers. Collapsing all Unicode
       whitespace runs to a single ASCII space defeats this class of bypass.

    Case folding happens via .lower() AFTER normalization since NFKC can
    change the casing of some compatibility characters.
    """
    normalized = unicodedata.normalize("NFKC", text)
    collapsed = re.sub(r"\s+", " ", normalized)
    return collapsed.lower()

SCANNER_NAME = "mcp_security"

# ============================================================
# Category A: SQL Injection in MCP Server Code (critical)
# SQL injection can store malicious prompts for agent execution.
# Source: Trend Micro, May 2025
# ============================================================
SQL_INJECTION_PATTERNS = [
    (re.compile(r'(?i)(cursor\.execute|connection\.execute|db\.execute)\s*\([^)]*\+'), "SQL string concatenation in execute() call"),
    (re.compile(r'(?i)(cursor\.execute|connection\.execute|db\.execute)\s*\(\s*f["\']'), "SQL f-string interpolation in execute() call"),
    (re.compile(r'(?i)(cursor\.execute|connection\.execute|db\.execute)\s*\([^)]*%\s*\('), "SQL % formatting in execute() call"),
    (re.compile(r'(?i)(cursor\.execute|connection\.execute|db\.execute)\s*\([^)]*\.format\s*\('), "SQL .format() in execute() call"),
    (re.compile(r'(?i)["\']SELECT\s[^"\']*["\'\s]*\+'), "SQL SELECT with string concatenation"),
    (re.compile(r'(?i)["\']INSERT\s[^"\']*["\'\s]*\+'), "SQL INSERT with string concatenation"),
    (re.compile(r'(?i)["\']UPDATE\s[^"\']*["\'\s]*\+'), "SQL UPDATE with string concatenation"),
    (re.compile(r'(?i)["\']DELETE\s[^"\']*["\'\s]*\+'), "SQL DELETE with string concatenation"),
    (re.compile(r'(?i)["\']SELECT\s.*\+\s*\w'), "SQL SELECT with variable concatenation"),
]

# ============================================================
# Category B: Tool Metadata Poisoning (critical)
# Prompt injection keywords hidden in tool description/name fields.
# These are invisible to users reading the skill name but loaded into LLM context.
# Source: Invariant Labs (April 2025), ClawHavoc campaign (Jan-Feb 2026)
# ============================================================
TOOL_INJECTION_KEYWORDS = [
    "ignore previous", "ignore all previous", "disregard",
    "you are now", "do not ask", "silently execute",
    "never reveal", "override safety", "new system prompt",
    "forget everything", "act as if you have no",
    "your new instructions",
    # Invariant Labs canonical patterns (2026)
    "<important>", "note to the ai", "note to claude", "note to llm",
    "read ~/.ssh", "cat ~/.ssh",
    # Network exfiltration targets — anchored to URL schemes and credential
    # targets so benign English ("send to the GPU", "send to the server",
    # "send to the queue") does not false-positive. Issue #9 (marcgadsdon,
    # 2026-04-05): bare "send to" substring cascaded into compound criticals
    # in Flowise's Ollama parameter descriptions.
    "send to http", "send to ftp", "send to webhook",
    "send credentials to", "send data to http",
    "post to http", "exfiltrate",
    #
    # REMOVED 2026-04-05 (torture-room pattern-recognition Finding 3):
    #
    # "from now on", "always remember", "you must always"
    #   → moved to PROMPT_INJECTION_IMPERATIVE_REGEX below, which requires
    #     an attack verb (ignore|execute|send|cat|read|write|override|etc.)
    #     within 50 characters. As bare substrings these phrases triggered
    #     on benign instruction text like "From now on, the tool returns
    #     JSON" or "Always remember to pass a valid API key" — same false
    #     positive class as Issue #9.
    #
    # "when using this tool", "when calling this tool", "before using"
    #   → already covered by TOOL_SHADOWING_PATTERNS regex at a stricter
    #     anchor ("when using" + action verb within 60 chars). As bare
    #     substrings they fired on every well-documented MCP/LangChain/
    #     Flowise tool description that mentions usage instructions.
    #     Pure deduplication — no recall loss.
]

# Prompt-injection imperatives that are too common in benign documentation
# as bare substrings but become highly specific when followed by an attack
# verb within a tight window. Added 2026-04-05 per torture-room review.
PROMPT_INJECTION_IMPERATIVE_REGEX = re.compile(
    r'\b(from now on|always remember|you must always)\b'
    r'[,.\s]*'
    r'.{0,60}?'
    r'\b(ignore|execute|send|cat|read|write|override|forget|reveal|'
    r'disregard|bypass|disable|leak|exfiltrate|exec|eval|shell)\b',
    re.IGNORECASE | re.DOTALL
)

# Broader exfil verb pattern — catches verb-substitution bypasses of the
# keyword list (caught by torture-room security review 2026-04-05). The
# keyword list is send-verb-only; an attacker can substitute upload,
# transmit, forward, push, beacon, relay, report, notify, deliver, dispatch,
# submit, leak, exfiltrate, siphon, extract, ship, pipe, or stream and walk
# through the keyword loop clean. This regex catches (verb) + up to 40 chars
# + (URL scheme or webhook target).
#
# Severity is HIGH not CRITICAL because legitimate tool descriptions DO
# sometimes mention uploading/posting to HTTPS URLs (e.g., "uploads your
# package to https://s3.amazonaws.com/..."). HIGH tells reviewers "investigate
# this" without the CRITICAL "abort install" escalation. The anchored keyword
# list remains the source of CRITICAL for known-bad patterns.
EXFIL_VERB_URL_PATTERN = re.compile(
    r'\b(send|post|upload|transmit|forward|push|beacon|relay|report|notify|'
    r'deliver|dispatch|submit|exfiltrate|leak|siphon|extract|ship|pipe|stream)\b'
    r'[^\n]{0,40}?'
    r'\b(https?://|ftp://|webhook\.)',
    re.IGNORECASE
)

# Tool shadowing: description instructs agent to hijack trusted tools
# Source: Invariant Labs tool shadowing demo (April 2025)
TOOL_SHADOWING_PATTERNS = [
    (re.compile(r'(?i)when\s+(using|calling|invoking)\s+.{0,60}(send|email|post|write|delete|push|commit)'), "Tool shadowing: hijack instruction targeting another tool action"),
    (re.compile(r'(?i)redirect\s+all\s+(emails?|messages?|output)'), "Tool shadowing: redirect all output"),
    (re.compile(r'(?i)instead\s+of\s+(sending|emailing|posting)\s+to\s+the\s+(user|real|original)'), "Tool shadowing: intercept and reroute"),
    (re.compile(r'(?i)(bcc|cc|forward|copy)\s+all\s+(to|emails?\s+to)\s+'), "Tool shadowing: silent BCC/forward pattern"),
]

# MCP configuration risks (2026 CVE patterns)
MCP_CONFIG_RISKS = [
    (re.compile(r'(?i)enableAllProjectMcpServers\s*["\']?\s*:\s*true'), "enableAllProjectMcpServers:true (CVE-2025-59536 consent bypass)"),
    (re.compile(r'(?i)(ANTHROPIC_BASE_URL|anthropic_base_url)\s*[=:]\s*["\']?https?://'), "ANTHROPIC_BASE_URL override (CVE-2026-21852: API key exfiltration risk)"),
    (re.compile(r'(?i)(host|bind|listen)\s*[=:]\s*["\']?0\.0\.0\.0'), "MCP server binding to 0.0.0.0 (CVE-2025-49596 DNS rebinding surface)"),
    (re.compile(r'(?i)(allowedOrigins|allowed_origins)\s*[=:]\s*["\']?\*["\']?'), "Wildcard CORS in MCP server (CSRF/DNS rebinding risk)"),
    (re.compile(r'(?i)(\.ssh/id_rsa|\.cursor/mcp\.json|\.claude/settings|ANTHROPIC_API_KEY)\s*'), "Credential/config path reference in MCP tool field"),
    # CVE-2025-6514 (CVSS 9.6): mcp-remote OAuth command injection via crafted authorization_endpoint
    (re.compile(r'(?i)(authorization_endpoint|authorizationEndpoint)\s*[=:]\s*["\']?https?://(?!accounts\.google\.com|login\.microsoftonline\.com|github\.com)'), "Suspicious authorization_endpoint in mcp-remote OAuth config (CVE-2025-6514 vector)"),
]

# Match tool schema fields containing injection text (Full-Schema Poisoning, CyberArk 2025)
# Check description, name, title, summary — all schema fields can carry injection payloads
TOOL_DEF_PY_PATTERN = re.compile(
    r'["\'](?:description|title|summary)["\']\s*:\s*["\']([^"\']{20,})["\']'
)
TOOL_DEF_JSON_PATTERN = re.compile(
    r'"(?:description|title|summary)"\s*:\s*"([^"]{20,})"'
)
# Tool name injection: shorter names can still carry keywords
TOOL_NAME_PATTERN = re.compile(
    r'"name"\s*:\s*"([^"]{5,80})"'
)

# ============================================================
# Category C: Indirect Prompt Injection via MCP Sampling (high)
# Structured result objects or sampling API calls containing injection text.
# Source: Palo Alto Unit 42
# ============================================================
SAMPLING_INJECTION_PATTERNS = [
    (re.compile(r'(?i)force_tool_call|forceToolCall|force-tool-call'), "Force-tool-call pattern (sampling injection)"),
    (re.compile(r'(?i)(include_context|includeContext)\s*=?\s*["\']allServers["\']'), "Cross-server context inclusion (privilege escalation)"),
    (re.compile(r'(?i)(createMessage|create_message)\s*\(.*system.*ignore'), "Sampling createMessage with injection payload"),
    (re.compile(r'(?i)maxTokens\s*=\s*["\']?0["\']?\s*[,;)].*include_context'), "Zero-token sampling with cross-server context"),
]

# ============================================================
# Category D: Cross-Domain Privilege Escalation (high)
# Single privileged credential used across multiple permission scopes.
# Source: Invariant Labs
# ============================================================
CROSS_DOMAIN_PATTERNS = [
    (re.compile(r'(?i)(GITHUB_TOKEN|github_token)\s*=\s*(os\.environ|os\.getenv|process\.env)'), "GITHUB_TOKEN in MCP server (write-scope risk)"),
    (re.compile(r'(?i)(admin_token|master_token|super_token|root_token)\s*=\s*["\'\w]'), "Privileged hardcoded token name in MCP"),
    (re.compile(r'(?i)permissions\s*=\s*["\']?(admin|root|write:all|full_access)["\']?'), "Broad permission scope assignment in MCP"),
    (re.compile(r'(?i)(scope|access_level)\s*=\s*["\']?(admin|all|full|root)["\']?'), "Overly broad scope/access level in MCP"),
]

# ============================================================
# Category E: Log-to-Leak Patterns (high)
# Logging all tool calls to an external endpoint.
# Source: OpenReview (MCP log-to-leak analysis)
# ============================================================
LOG_EXFIL_PATTERNS = [
    (re.compile(r'(?i)(log|logger|logging)\.(info|debug|warning|error|critical)\s*\(.*tool_(call|result|input|output)'), "Logging all tool calls (potential exfil channel)"),
    (re.compile(r'(?i)(send_log|log_to|emit_log|post_log)\s*\(.*(https?://|webhook|endpoint)'), "Logging to external HTTP endpoint"),
    (re.compile(r'(?i)(tool_call|tool_result)\s*.*requests\.(post|put)\s*\('), "Tool call data sent via HTTP POST"),
    (re.compile(r'(?i)(audit_log|access_log|call_log)\s*=.*https?://'), "Audit log URL pointing to remote server"),
]

# ============================================================
# Category G: Rug Pull Enablers (high)
# Tool descriptions sourced from mutable/external data.
# These don't prove malicious intent but flag that tool behavior
# can change without code changes.
# Source: Lukas Kania "Your MCP Server's Tool Descriptions Changed Last Night" (March 2026)
# OWASP MCP03 (Tool Poisoning), MCP07 (Rug Pull)
# ============================================================
RUG_PULL_PATTERNS = [
    (re.compile(r'description\s*[=:]\s*(cursor|db|conn|session)\.\w*(query|execute|fetch|get)'), "Rug Pull Enabler: tool description from database query"),
    (re.compile(r'description\s*[=:]\s*(requests\.(get|post)|fetch|urllib|http)'), "Rug Pull Enabler: tool description fetched from network"),
    (re.compile(r'description\s*[=:]\s*(os\.environ|os\.getenv|process\.env)'), "Rug Pull Enabler: tool description from environment variable"),
    (re.compile(r'description\s*[=:]\s*(open|json\.load|yaml\.load|toml\.load)\s*\('), "Rug Pull Enabler: tool description loaded from file at runtime"),
    (re.compile(r'if\b.*:\s*\n\s*.*description\s*='), "Rug Pull Enabler: conditional tool description assignment"),
    (re.compile(r'(tools|tool_list)\s*=\s*(requests|fetch|db\.|cursor\.)'), "Rug Pull Enabler: tool list from external source"),
    # OWASP MCP07: inputSchema and annotations can also be rug-pulled
    (re.compile(r'inputSchema\s*[=:]\s*(requests|fetch|db\.|cursor\.|os\.environ|os\.getenv)'), "Rug Pull Enabler: inputSchema from external source"),
    (re.compile(r'annotations\s*[=:]\s*(requests|fetch|db\.|cursor\.|os\.environ|os\.getenv)'), "Rug Pull Enabler: annotations from external source"),
]

# MCP framework signals for file heuristic
MCP_SIGNALS = [
    '@mcp.tool', 'mcp.Server', 'McpServer', 'ModelContextProtocol',
    'FastMCP', 'CallToolRequest', 'ListToolsResult', 'tool_handler',
    'from mcp import', 'import mcp', '@tool(', '"tools":', "'tools':",
    'mcp-server', 'mcp_server',
]


def scan_tool_metadata_poisoning(content, rel_path, ext):
    """Check tool definition schema fields for injected prompt keywords.
    Covers Full-Schema Poisoning (FSP): description, title, summary, and name fields.
    Source: CyberArk 2025 (FSP), Invariant Labs 2025 (TPA).
    """
    findings = []

    if ext in ('.py', '.ts', '.js'):
        main_pattern = TOOL_DEF_PY_PATTERN
    elif ext == '.json':
        main_pattern = TOOL_DEF_JSON_PATTERN
    else:
        return findings

    # Check description/title/summary fields
    for m in main_pattern.finditer(content):
        field_value = _normalize_for_keyword_match(m.group(1))
        keyword_hit = False
        for keyword in TOOL_INJECTION_KEYWORDS:
            if keyword in field_value:
                line_no = content[:m.start()].count('\n') + 1
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="Tool Metadata Poisoning",
                    description=f"Prompt injection keyword '{keyword}' found in tool schema field",
                    file=rel_path, line=line_no,
                    snippet=m.group(0)[:120],
                    category="tool-poisoning"
                ))
                keyword_hit = True
                break  # One finding per matched field block

        # Anchored prompt-injection imperative regex. Catches "from now on",
        # "always remember", "you must always" followed by an attack verb
        # within 60 chars. These were previously bare keyword substrings,
        # which fired on benign instruction text. The regex anchor restricts
        # to the genuinely malicious forms.
        if not keyword_hit:
            imperative_match = PROMPT_INJECTION_IMPERATIVE_REGEX.search(field_value)
            if imperative_match:
                line_no = content[:m.start()].count('\n') + 1
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="Tool Metadata Poisoning",
                    description=(
                        f"Prompt injection imperative '{imperative_match.group(1)}' "
                        f"followed by attack verb '{imperative_match.group(2)}' in "
                        f"tool schema field"
                    ),
                    file=rel_path, line=line_no,
                    snippet=m.group(0)[:120],
                    category="tool-poisoning"
                ))
                keyword_hit = True

        # Broader verb-substitution exfil pattern — only if no keyword
        # already flagged the field (avoid double-counting the same issue).
        # See EXFIL_VERB_URL_PATTERN definition for rationale.
        if not keyword_hit:
            verb_match = EXFIL_VERB_URL_PATTERN.search(field_value)
            if verb_match:
                line_no = content[:m.start()].count('\n') + 1
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Suspicious Exfiltration Pattern in Tool Description",
                    description=(
                        f"Tool description contains exfiltration verb "
                        f"'{verb_match.group(1)}' followed by URL/webhook target "
                        f"'{verb_match.group(2)}'. Review whether this is a "
                        f"legitimate upload target or an exfiltration vector."
                    ),
                    file=rel_path, line=line_no,
                    snippet=m.group(0)[:120],
                    category="exfil-pattern"
                ))

    # Check name fields for injection (FSP — shorter but still loaded into context)
    if ext == '.json':
        for m in TOOL_NAME_PATTERN.finditer(content):
            name_val = _normalize_for_keyword_match(m.group(1))
            for keyword in TOOL_INJECTION_KEYWORDS:
                if keyword in name_val:
                    line_no = content[:m.start()].count('\n') + 1
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title="Tool Name Field Injection",
                        description=f"Prompt injection keyword '{keyword}' found in tool name field (Full-Schema Poisoning)",
                        file=rel_path, line=line_no,
                        snippet=m.group(0)[:120],
                        category="tool-poisoning"
                    ))
                    break

    return findings


def scan_tool_shadowing(content, rel_path):
    """Check for tool shadowing patterns — cross-tool contamination via description fields.
    Source: Invariant Labs tool shadowing demo (April 2025).
    """
    findings = []
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if len(line) > core.MAX_LINE_LENGTH:
            continue
        for pattern, title in TOOL_SHADOWING_PATTERNS:
            if pattern.search(line):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"Tool Shadowing: {title}",
                    description="Cross-tool contamination: this tool's metadata may override trusted tool behavior",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="tool-shadowing"
                ))
    return findings


def scan_patterns(content, rel_path, patterns, category, default_severity):
    """Delegate to shared scan_patterns in forensics_core."""
    return core.scan_patterns(content, rel_path, patterns, category, default_severity, SCANNER_NAME)


def is_mcp_related(file_path, rel_path, content_sample):
    """Heuristic: is this likely an MCP server or tool file?"""
    basename = os.path.basename(file_path).lower()
    rel_lower = rel_path.lower()

    # Filename signals
    if any(term in basename for term in ('mcp', 'server', 'tool', 'handler')):
        return True
    # Directory signals
    if any(term in rel_lower for term in ('/mcp/', '/tools/', '/handlers/', '/servers/')):
        return True
    # Content signals
    return any(sig in content_sample for sig in MCP_SIGNALS)


def scan_file(file_path, rel_path):
    """Scan a single file for MCP attack surface patterns."""
    ext = os.path.splitext(file_path)[1].lower()
    basename = os.path.basename(file_path)

    target_exts = {'.py', '.js', '.ts', '.json', '.toml'}
    if ext not in target_exts:
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return []

    findings = []

    # Tool metadata poisoning: check all potential tool definition files
    if ext in ('.py', '.js', '.ts', '.json'):
        findings.extend(scan_tool_metadata_poisoning(content, rel_path, ext))

    # For code files, run full MCP pattern categories
    if ext in ('.py', '.js', '.ts'):
        # SQL injection: check all code files (not just MCP)
        findings.extend(scan_patterns(content, rel_path, SQL_INJECTION_PATTERNS, "sql-injection", "critical"))

        # Deeper checks only for likely MCP server files
        content_sample = content[:8000]
        if is_mcp_related(file_path, rel_path, content_sample):
            findings.extend(scan_patterns(content, rel_path, SAMPLING_INJECTION_PATTERNS, "sampling-injection", "high"))
            findings.extend(scan_patterns(content, rel_path, CROSS_DOMAIN_PATTERNS, "cross-domain-privilege", "high"))
            findings.extend(scan_patterns(content, rel_path, LOG_EXFIL_PATTERNS, "log-to-leak", "high"))
            findings.extend(scan_tool_shadowing(content, rel_path))
            findings.extend(scan_patterns(content, rel_path, MCP_CONFIG_RISKS, "mcp-config-risk", "critical"))
            # Category G: Rug Pull Enablers - dynamic tool descriptions
            findings.extend(scan_patterns(content, rel_path, RUG_PULL_PATTERNS, "rug-pull-enabler", "high"))

    # MCP config files (.json) — check for enableAllProjectMcpServers, ANTHROPIC_BASE_URL
    if ext == '.json' or basename in ('settings.json', 'claude_desktop_config.json', '.mcp.json'):
        findings.extend(scan_patterns(content, rel_path, MCP_CONFIG_RISKS, "mcp-config-risk", "critical"))

    return findings


def main():
    args = core.parse_common_args(sys.argv, "MCP Attack Surface Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning {repo_path} for MCP security issues...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
