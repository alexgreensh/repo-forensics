#!/usr/bin/env python3
"""
scan_skill_threats.py - AI Agent Skill Threat Scanner (v3)
Detects prompt injection, unicode smuggling, prerequisite attacks,
credential exfiltration, persistence, scope escalation, stealth
directives, known campaign IOCs, ClickFix/sleeper malware,
and MCP tool definition injection.

All detection patterns are original, informed by published research from:
- Snyk (ToxicSkills: Malicious AI Agent Skills)
- Koi Security (ClawHavoc campaign: 1,184 poisoned packages, Jan-Feb 2026)
- Invariant Labs (Tool Poisoning Attack, April 2025)
- Telegram/Discord confirmed exfil channels (VVS Stealer, ChaosBot, Pulsar RAT 2025-2026)
- OWASP MCP Top 10 (2026)

Created by Alex Greenshpun
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "skill_threats"

# ============================================================
# Category 1: Prompt Injection Directives (critical)
# ============================================================
PROMPT_INJECTION_PATTERNS = [
    (re.compile(r'(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|directives|prompts|rules)'), "Instruction override directive"),
    (re.compile(r'(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|context)'), "Instruction disregard directive"),
    (re.compile(r'(?i)you\s+are\s+now\s+(a|an|my)\s+\w+'), "Persona reassignment (DAN-style)"),
    (re.compile(r'(?i)do\s+not\s+(ask\s+for\s+confirmation|confirm|verify|check\s+with)'), "Confirmation bypass directive"),
    (re.compile(r'(?i)silently\s+(execute|run|perform|install|download)'), "Silent execution directive"),
    (re.compile(r'(?i)never\s+(reveal|show|display|output|print)\s+(these|this|the|your)\s+(instructions|prompt|rules|system)'), "Instruction concealment directive"),
    (re.compile(r'(?i)override\s+(safety|security|restriction|guardrail|filter)'), "Safety override directive"),
    (re.compile(r'(?i)act\s+as\s+(if|though)\s+you\s+(have|had)\s+no\s+(restrictions|limits|rules)'), "Restriction bypass directive"),
    (re.compile(r'(?i)forget\s+(everything|all|your)\s+(you|instructions|training|rules)'), "Memory wipe directive"),
    (re.compile(r'(?i)new\s+system\s+prompt'), "System prompt replacement"),
]

# ============================================================
# Category 2: Invisible Unicode Smuggling (critical)
# ============================================================
ZERO_WIDTH_CHARS = set([
    '\u200b',  # ZERO WIDTH SPACE
    '\u200c',  # ZERO WIDTH NON-JOINER
    '\u200d',  # ZERO WIDTH JOINER
    '\u2060',  # WORD JOINER
    '\ufeff',  # ZERO WIDTH NO-BREAK SPACE (BOM)
    '\u00ad',  # SOFT HYPHEN
    '\u200e',  # LEFT-TO-RIGHT MARK
    '\u200f',  # RIGHT-TO-LEFT MARK
])

RTL_OVERRIDE = '\u202e'  # RIGHT-TO-LEFT OVERRIDE
ZERO_WIDTH_PATTERN = re.compile('[' + ''.join(ZERO_WIDTH_CHARS) + ']')

# Cyrillic confusables for Latin letters
HOMOGLYPHS = {
    '\u0430': 'a',  # Cyrillic а
    '\u0435': 'e',  # Cyrillic е
    '\u043e': 'o',  # Cyrillic о
    '\u0440': 'p',  # Cyrillic р
    '\u0441': 'c',  # Cyrillic с
    '\u0443': 'y',  # Cyrillic у
    '\u0445': 'x',  # Cyrillic х
    '\u0456': 'i',  # Cyrillic і
    '\u0458': 'j',  # Cyrillic ј
    '\u04bb': 'h',  # Cyrillic һ
    '\u0501': 'd',  # Cyrillic ԁ
    # Greek confusables (added 2026 — Unicode confusables.txt)
    '\u03bf': 'o',  # Greek ο (omicron)
    '\u03c5': 'u',  # Greek υ (upsilon)
    '\u03ba': 'k',  # Greek κ (kappa)
    '\u03c1': 'p',  # Greek ρ (rho)
    '\u03b1': 'a',  # Greek α (alpha)
    '\u03b5': 'e',  # Greek ε (epsilon)
}
HOMOGLYPH_PATTERN = re.compile('[' + ''.join(HOMOGLYPHS.keys()) + ']')

# ============================================================
# Category 3: Prerequisite Red Flags (critical)
# ============================================================
PREREQUISITE_PATTERNS = [
    (re.compile(r'(?i)(curl|wget)\s+.*(https?://|ftp://).*\|\s*(sh|bash|python|ruby|perl)'), "Pipe-to-shell download pattern"),
    (re.compile(r'(?i)(curl|wget)\s+-[^\s]*o?\s+\S+.*&&\s*(chmod\s+\+x|sh|bash|\./)'), "Download-and-execute pattern"),
    (re.compile(r'(?i)unzip\s+-P\s'), "Password-protected archive extraction"),
    (re.compile(r'(?i)7z\s+x\s+-p'), "Password-protected 7z extraction"),
    (re.compile(r'(?i)xattr\s+-[crd]'), "macOS quarantine bypass (xattr)"),
    (re.compile(r'(?i)spctl\s+--master-disable'), "macOS Gatekeeper disable"),
    (re.compile(r'(?i)sudo\s+(installer|pkgutil|hdiutil)'), "macOS package installer elevation"),
    (re.compile(r'(?i)(pip|npm|gem)\s+install\s+.*--force'), "Forced package installation"),
    (re.compile(r'(?i)chmod\s+777'), "World-writable permissions"),
    # Hook injection patterns (informed by AgentShield research)
    (re.compile(r'\$\{\{.*\}\}'), "Variable interpolation in hook script (command injection risk)"),
    (re.compile(r'(?i)(pip|npm|gem)\s+install\b.*(?:PreToolUse|PostToolUse|hook)'), "Hidden package install in hook context"),
    (re.compile(r'(?i)curl\s+-s\b.*\|\s*(eval|bash|sh)\b'), "Silent curl piped to eval/shell in hook"),
]

# ============================================================
# Category 4: Credential Exfiltration Patterns (critical)
# ============================================================
EXFIL_PATTERNS_CRITICAL = [
    (re.compile(r'(?i)(process\.env|os\.environ)\s*(\.copy|\.keys|\.values|\.items)\s*\('), "Bulk environment access"),
    (re.compile(r'(?i)Object\.keys\s*\(\s*process\.env\s*\)'), "JS environment key enumeration"),
    (re.compile(r'(?i)dict\s*\(\s*os\.environ\s*\)'), "Full environment copy"),
]
EXFIL_PATTERNS_MEDIUM = [
    (re.compile(r'(?i)(process\.env|os\.environ)\s*(\[|\.get\s*\()'), "Environment variable access"),
]
EXFIL_PATTERNS = [
    (re.compile(r'(?i)(webhook\.site|requestbin|pipedream\.net|hookbin\.com|burpcollaborator)'), "Known exfiltration webhook service"),
    (re.compile(r'(?i)base64\.(b64encode|encode|urlsafe_b64encode)\s*\(.*open\s*\('), "Base64 encoding of file contents"),
    (re.compile(r'(?i)btoa\s*\(\s*(fs\.)?readFileSync'), "JS base64 encoding of file"),
    (re.compile(r'(?i)\.readFile(Sync)?\s*\(.*(\.env|\.ssh|\.aws|\.gnupg|\.config|credentials)'), "Reading credential files"),
]

# ============================================================
# Category 5: Persistence Mechanisms (high)
# ============================================================
PERSISTENCE_PATTERNS = [
    (re.compile(r'(?i)(LaunchAgents|LaunchDaemons)/'), "macOS LaunchAgent/Daemon creation"),
    (re.compile(r'(?i)(crontab\s+-[^l\s]|crontab\s+[^-\s]|/etc/cron)'), "Crontab modification"),
    (re.compile(r'(?i)(systemctl|systemd)\s+(enable|start)'), "Systemd service installation"),
    (re.compile(r'(?i)\.(bashrc|zshrc|profile|bash_profile|zprofile)'), "Shell RC file modification"),
    (re.compile(r'(?i)(HKEY_|RegOpenKey|RegSetValue)'), "Windows registry modification"),
    (re.compile(r'(?i)schtasks\s+/create'), "Windows scheduled task creation"),
]

# ============================================================
# Category 6: Scope Escalation (high)
# ============================================================
SCOPE_PATTERNS = [
    (re.compile(r'(?i)(/etc/passwd|/etc/shadow|/etc/hosts)'), "Accessing system files"),
    (re.compile(r'(?i)(~/|\\$HOME/|/Users/|/home/)\w'), "Accessing user home directories"),
    (re.compile(r'(?i)(Chrome|Firefox|Safari|Brave|Edge)/(Default|Profile|Cookies|Login Data|Local State)'), "Accessing browser data"),
    (re.compile(r'(?i)(Keychain|keychain-db|login\.keychain)'), "Accessing macOS Keychain"),
    (re.compile(r'(?i)(~|\\$HOME)/\.claude/(skills|commands|settings)'), "Accessing Claude configuration"),
    (re.compile(r'(?i)/Library/(Application Support|Preferences|Keychains)'), "Accessing macOS Library data"),
    (re.compile(r'(?i)(credential-store|git-credential|pass\s+show)'), "Accessing credential stores"),
]

# ============================================================
# Category 7: Stealth Directives (high)
# ============================================================
STEALTH_PATTERNS = [
    (re.compile(r'(?i)(do\s+not|don\'t|never)\s+(log|record|track|audit|save)'), "Anti-logging directive"),
    (re.compile(r'(?i)(disable|suppress|silence)\s+(log|output|warning|error)'), "Output suppression directive"),
    (re.compile(r'(?i)2>\s*/dev/null.*&'), "Stderr suppression with background exec"),
    (re.compile(r'(?i)(>\s*/dev/null\s+2>&1|&>\s*/dev/null)\s*&'), "Full output suppression with background"),
    (re.compile(r'(?i)(nohup|disown|setsid)\s+.*(curl|wget|python|node|bash)'), "Detached background process"),
]

# ============================================================
# Category 8: Known Campaign IOCs (high, IOC match = critical)
# Lazy loaded from ioc_manager (single source of truth)
# ============================================================
_KNOWN_C2_IPS = None
_KNOWN_MALICIOUS_DOMAINS = None

_FALLBACK_C2_IPS = [
    "91.92.242.30", "54.91.154.110", "157.245.55.238",
    "45.77.240.42", "104.248.30.47", "159.65.147.111",
    # Axios supply chain RAT C2 (March 2026)
    "142.11.206.73",
]
_FALLBACK_MALICIOUS_DOMAINS = [
    "install.app-distribution.net", "dl.dropboxusercontent.com",
    "socifiapp.com", "hackmoltrepeat.com", "giftshop.club",
    "glot.io", "api.telegram.org/bot", "discord.com/api/webhooks",
    "hooks.slack.com/services",
    # liteLLM supply chain attack C2 (March 2026)
    "eo1n0jq9qgggt.m.pipedream.net",
    # Axios supply chain RAT C2 domain (March 2026)
    "sfrclak.com",
]

# Known malicious binary paths (host IOCs)
KNOWN_RAT_BINARY_PATHS = [
    "/Library/Caches/com.apple.act.mond",  # Axios supply chain RAT (March 2026)
]

# Known malicious file hashes (SHA256)
KNOWN_MALICIOUS_HASHES = {
    # Axios supply chain RAT binary (March 2026)
    "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a",
}


def _get_ioc_lists():
    """Lazy-load IOC lists from ioc_manager."""
    global _KNOWN_C2_IPS, _KNOWN_MALICIOUS_DOMAINS
    if _KNOWN_C2_IPS is None:
        try:
            import ioc_manager as _ioc
            _ioc_data = _ioc.get_iocs()
            _KNOWN_C2_IPS = _ioc_data.get('c2_ips', _FALLBACK_C2_IPS)
            _KNOWN_MALICIOUS_DOMAINS = _ioc_data.get('malicious_domains', _FALLBACK_MALICIOUS_DOMAINS)
        except (ImportError, OSError, json.JSONDecodeError, ValueError) as e:
            print(f"[!] IOC loading failed, using fallback: {e}", file=sys.stderr)
            _KNOWN_C2_IPS = _FALLBACK_C2_IPS
            _KNOWN_MALICIOUS_DOMAINS = _FALLBACK_MALICIOUS_DOMAINS
    return _KNOWN_C2_IPS, _KNOWN_MALICIOUS_DOMAINS

# Known malicious ClawHub authors (ClawHavoc campaign, Koi Security 2026)
KNOWN_MALICIOUS_AUTHORS = [
    "zaycv",         # ClawHavoc uploader
    "linhui1010",    # Comment-based AMOS delivery
]

# ============================================================
# Category 9: ClickFix/Sleeper Malware (critical)
# SKILL.md prerequisites that execute payloads at install/first-run.
# Source: Active campaigns observed 2025-2026 using AI skills as delivery.
# ============================================================
CLICKFIX_PATTERNS = [
    (re.compile(r'(?i)(curl|wget)\s+.*(https?://).*\|\s*(base64\s+-d|base64\s+--decode)\s*\|\s*(bash|sh|python)'), "ClickFix pipe: download | base64-decode | shell exec"),
    (re.compile(r'(?i)(bash|sh)\s+<\s*\(\s*(curl|wget)'), "Shell process substitution with remote download"),
    (re.compile(r'(?i)glot\.io'), "Payload hosted on glot.io code paste site"),
    (re.compile(r'(?i)(python|python3)\s+-c\s+["\']import\s+(base64|socket|subprocess)'), "Python one-liner with suspicious import"),
    (re.compile(r'(?i)(curl|wget)\s+.*-s\s+.*\|\s*(python|python3)\s+-'), "Silent download piped to Python interpreter"),
    (re.compile(r'(?i)eval\s*\(\s*(atob|Buffer\.from|base64_decode|base64\.b64decode)'), "eval(decode(...)) pattern"),
    (re.compile(r'(?i)echo\s+[A-Za-z0-9+/]{30,}={0,2}\s*\|\s*base64\s+(-d|--decode)'), "Inline base64 payload in shell command"),
    # AMOS stealer delivery patterns (ClawHavoc campaign)
    (re.compile(r'(?i)(OpenClawDriver|ClawDriver)'), "Fake prerequisite name (AMOS stealer delivery)"),
    (re.compile(r'(?i)(pass|password)\s*:\s*openclaw'), "Password-protected ZIP with known AMOS password"),
]

# ============================================================
# Category 10: MCP Tool Definition Injection (critical)
# Injection patterns specific to MCP tool definition files.
# Source: Invariant Labs (April 2025), OWASP MCP Top 10 (2026)
# ============================================================
# Detect <IMPORTANT> tag pattern (Invariant Labs canonical TPA)
IMPORTANT_TAG_PATTERN = re.compile(r'<(?i:important)>[\s\S]{0,500}</(?i:important)>', re.MULTILINE)
IMPORTANT_TAG_OPEN = re.compile(r'<important>', re.IGNORECASE)

MCP_TOOL_INJECTION_PATTERNS = [
    (re.compile(r'(?i)<important>'), "Invariant Labs <IMPORTANT> tag in tool description (canonical TPA pattern)"),
    (re.compile(r'(?i)(note\s+to\s+(the\s+)?(ai|llm|claude|model|assistant))'), "Hidden AI-directed note in tool/skill metadata"),
    (re.compile(r'(?i)(full\s+schema\s+(injection|poisoning)|schema.+poison)'), "Full-schema poisoning reference"),
    (re.compile(r'(?i)"description"\s*:\s*"[^"]{0,200}(read|cat|exfil|send|post\s+to|forward)[^"]{0,100}\.ssh'), "Tool description with credential exfiltration instruction"),
    (re.compile(r'(?i)"name"\s*:\s*"[^"]{0,50}(admin|sudo|root|privileged|elevated)[^"]{0,50}"'), "Elevated privilege claim in tool name field"),
]


def scan_unicode_smuggling(content, rel_path):
    """Category 2: Detect zero-width chars, RTL overrides, homoglyphs."""
    findings = []

    # Count zero-width characters
    zw_count = len(ZERO_WIDTH_PATTERN.findall(content))
    if zw_count >= 3:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Zero-Width Character Cluster",
            description=f"Found {zw_count} zero-width/invisible Unicode characters (potential text smuggling)",
            file=rel_path, line=0,
            snippet=f"{zw_count} invisible chars detected",
            category="unicode-smuggling"
        ))

    # RTL override
    if RTL_OVERRIDE in content:
        line_no = content[:content.index(RTL_OVERRIDE)].count('\n') + 1
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Right-to-Left Override Character",
            description="RTL override (U+202E) can hide true text direction to disguise file extensions or code",
            file=rel_path, line=line_no,
            snippet="Contains U+202E RTL override",
            category="unicode-smuggling"
        ))

    # Homoglyph detection in code files
    code_exts = {'.py', '.js', '.ts', '.jsx', '.tsx', '.rb', '.go', '.rs', '.sh', '.bash'}
    ext = os.path.splitext(rel_path)[1].lower()
    if ext in code_exts:
        m = HOMOGLYPH_PATTERN.search(content)
        if m:
            ch = m.group(0)
            line_no = content[:m.start()].count('\n') + 1
            lines = content.split('\n')
            line_content = lines[line_no - 1] if line_no <= len(lines) else ""
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Homoglyph Character in Code",
                description=f"Cyrillic '{ch}' (looks like Latin '{HOMOGLYPHS[ch]}') found in code file",
                file=rel_path, line=line_no,
                snippet=line_content.strip()[:120],
                category="unicode-smuggling"
            ))

    return findings


def scan_patterns(content, rel_path, patterns, category, default_severity):
    """Delegate to shared scan_patterns in forensics_core."""
    return core.scan_patterns(content, rel_path, patterns, category, default_severity, SCANNER_NAME)


def scan_known_iocs(content, rel_path):
    """Category 8: Check for known campaign indicators (C2 IPs, domains, binary paths, hashes)."""
    findings = []
    lines = content.split('\n')
    c2_ips, malicious_domains = _get_ioc_lists()

    for i, line in enumerate(lines):
        for ip in c2_ips:
            if ip in line:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"Known C2 IP Address: {ip}",
                    description="IP address associated with known malicious campaigns (source: Koi Security research)",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="known-ioc"
                ))

        for domain in malicious_domains:
            if domain in line:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Suspicious Domain: {domain}",
                    description="Domain associated with malware distribution (source: published threat intelligence)",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="known-ioc"
                ))

        # Host IOC: known RAT binary paths
        for rat_path in KNOWN_RAT_BINARY_PATHS:
            if rat_path in line:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"Known RAT Binary Path: {rat_path}",
                    description="File path matches known RAT installation location (Axios supply chain, March 2026)",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="known-ioc"
                ))

        # Host IOC: known malicious file hashes
        for mal_hash in KNOWN_MALICIOUS_HASHES:
            if mal_hash in line.lower():
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"Known Malicious Hash: {mal_hash[:16]}...",
                    description="SHA256 hash matches known malware binary (Axios supply chain RAT, March 2026)",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="known-ioc"
                ))

    return findings


def scan_file(file_path, rel_path):
    """Run all 10 categories on a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return []

    findings = []

    # Only scan markdown/text files for prompt injection and stealth directives
    ext = os.path.splitext(rel_path)[1].lower()
    text_exts = {'.md', '.txt', '.yml', '.yaml', '.toml', '.cfg', '.ini', '.json', ''}
    code_exts = {'.py', '.js', '.ts', '.jsx', '.tsx', '.rb', '.sh', '.bash', '.zsh',
                 '.go', '.rs', '.php', '.java', '.swift', '.kt'}

    if ext in text_exts or ext in code_exts or os.path.basename(rel_path).upper() in ('SKILL.MD', 'README.MD', 'CLAUDE.MD'):
        # Cat 1: Prompt injection (most relevant in .md, .txt, .yml)
        findings.extend(scan_patterns(content, rel_path, PROMPT_INJECTION_PATTERNS, "prompt-injection", "critical"))

    # Cat 2: Unicode smuggling (all files)
    findings.extend(scan_unicode_smuggling(content, rel_path))

    if ext in text_exts or ext in code_exts:
        # Cat 3: Prerequisite red flags
        findings.extend(scan_patterns(content, rel_path, PREREQUISITE_PATTERNS, "prerequisite-attack", "critical"))

    if ext in code_exts:
        # Cat 4: Credential exfiltration (bulk = critical, single = medium)
        findings.extend(scan_patterns(content, rel_path, EXFIL_PATTERNS_CRITICAL, "credential-exfiltration", "critical"))
        findings.extend(scan_patterns(content, rel_path, EXFIL_PATTERNS_MEDIUM, "credential-exfiltration", "medium"))
        findings.extend(scan_patterns(content, rel_path, EXFIL_PATTERNS, "credential-exfiltration", "critical"))
        # Cat 5: Persistence
        findings.extend(scan_patterns(content, rel_path, PERSISTENCE_PATTERNS, "persistence", "high"))
        # Cat 6: Scope escalation
        findings.extend(scan_patterns(content, rel_path, SCOPE_PATTERNS, "scope-escalation", "high"))
        # Cat 7: Stealth
        findings.extend(scan_patterns(content, rel_path, STEALTH_PATTERNS, "stealth", "high"))

    # Cat 8: IOCs (all files)
    findings.extend(scan_known_iocs(content, rel_path))

    # Cat 9: ClickFix/sleeper malware (text + code: SKILL.md prereqs with payload delivery)
    if ext in text_exts or ext in code_exts:
        findings.extend(scan_patterns(content, rel_path, CLICKFIX_PATTERNS, "clickfix-sleeper", "critical"))

    # Cat 10: MCP tool definition injection (.json, .py, .ts, .js, .md)
    if ext in ('.json', '.py', '.ts', '.js', '.md', '.toml'):
        findings.extend(scan_patterns(content, rel_path, MCP_TOOL_INJECTION_PATTERNS, "mcp-tool-injection", "critical"))

    return findings


def main():
    args = core.parse_common_args(sys.argv, "AI Skill Threat Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning for AI skill threats in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
