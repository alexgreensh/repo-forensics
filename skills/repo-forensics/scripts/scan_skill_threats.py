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
from _shared_patterns import EXFIL_VERBS_RE, SKILL_CONFIG_FILES

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
    (re.compile(r'(?i)this\s+(is\s+)?(a\s+)?(safe|routine|standard|normal)\s+(operation|action|step|task|command)'), "LITL: False safety assertion (Checkmarx Lies-in-the-Loop, September 2025)"),
    (re.compile(r'(?i)press\s+(enter|return|y|yes)\s+to\s+(continue|proceed|approve|confirm)'), "LITL: Approval coercion directive"),
    (re.compile(r'(?i)(summarize|describe|present)\s+(this|the)\s+(action|command|operation)\s+as\s+(safe|benign|routine|harmless)'), "LITL: Action description tampering (HITL dialog forging)"),
]

# ============================================================
# Category 2: Invisible Unicode Smuggling (critical)
# Character sets from anti-trojan-source (Liran Tal) + Unicode 15.1 spec.
# ============================================================
ZERO_WIDTH_CHARS = set([
    '\u200b',  # ZERO WIDTH SPACE
    '\u200c',  # ZERO WIDTH NON-JOINER
    '\u200d',  # ZERO WIDTH JOINER
    '\u2060',  # WORD JOINER
    '\u2061',  # FUNCTION APPLICATION
    '\u2062',  # INVISIBLE TIMES
    '\u2063',  # INVISIBLE SEPARATOR
    '\u2064',  # INVISIBLE PLUS
    '\ufeff',  # ZERO WIDTH NO-BREAK SPACE (BOM)
    '\u00ad',  # SOFT HYPHEN
    '\u200e',  # LEFT-TO-RIGHT MARK
    '\u200f',  # RIGHT-TO-LEFT MARK
    '\u180e',  # MONGOLIAN VOWEL SEPARATOR
    '\u061c',  # ARABIC LETTER MARK
])

# Trojan Source bidi controls: override visual text direction in renderers.
# All 10 chars from Unicode Bidirectional Algorithm (UAX #9).
BIDI_CONTROL_CHARS = set([
    '\u202a',  # LEFT-TO-RIGHT EMBEDDING (LRE)
    '\u202b',  # RIGHT-TO-LEFT EMBEDDING (RLE)
    '\u202c',  # POP DIRECTIONAL FORMATTING (PDF)
    '\u202d',  # LEFT-TO-RIGHT OVERRIDE (LRO)
    '\u202e',  # RIGHT-TO-LEFT OVERRIDE (RLO)
    '\u2066',  # LEFT-TO-RIGHT ISOLATE (LRI)
    '\u2067',  # RIGHT-TO-LEFT ISOLATE (RLI)
    '\u2068',  # FIRST STRONG ISOLATE (FSI)
    '\u2069',  # POP DIRECTIONAL ISOLATE (PDI)
    '\u206a',  # INHIBIT SYMMETRIC SWAPPING
    '\u206b',  # ACTIVATE SYMMETRIC SWAPPING
    '\u206c',  # INHIBIT ARABIC FORM SHAPING
    '\u206d',  # ACTIVATE ARABIC FORM SHAPING
    '\u206e',  # NATIONAL DIGIT SHAPES
    '\u206f',  # NOMINAL DIGIT SHAPES
])

# Variation selectors alter glyph appearance without changing semantics.
VARIATION_SELECTORS = set(
    [chr(cp) for cp in range(0xFE00, 0xFE10)]  # VS1-VS16
)

# Supplemental variation selectors VS17-VS256 (U+E0100-U+E01EF).
# GlassWorm campaign (Oct 2025-Mar 2026) weaponized this range to hide executable
# JavaScript in 433 VS Code extensions. No legitimate use in source code.
SUPPLEMENTAL_VARIATION_SELECTORS = set(
    [chr(cp) for cp in range(0xE0100, 0xE01F0)]  # VS17-VS256
)

# Confusable space characters (Glassworm attack vector).
CONFUSABLE_SPACES = set([
    '\u00a0',  # NO-BREAK SPACE (most common Glassworm vector)
    '\u2000',  # EN QUAD
    '\u2001',  # EM QUAD
    '\u2002',  # EN SPACE
    '\u2003',  # EM SPACE
    '\u2004',  # THREE-PER-EM SPACE
    '\u2005',  # FOUR-PER-EM SPACE
    '\u2006',  # SIX-PER-EM SPACE
    '\u2007',  # FIGURE SPACE
    '\u2008',  # PUNCTUATION SPACE
    '\u2009',  # THIN SPACE
    '\u200a',  # HAIR SPACE
    '\u205f',  # MEDIUM MATHEMATICAL SPACE
    '\u3000',  # IDEOGRAPHIC SPACE
])

# Tag characters (invisible Unicode plane 14 tags).
TAG_CHARS = set(
    [chr(0xE0001)]  # LANGUAGE TAG
    + [chr(cp) for cp in range(0xE0020, 0xE0080)]  # TAG SPACE..CANCEL TAG
)

# Interlinear annotation chars.
ANNOTATION_CHARS = set([
    '\ufff9',  # INTERLINEAR ANNOTATION ANCHOR
    '\ufffa',  # INTERLINEAR ANNOTATION SEPARATOR
    '\ufffb',  # INTERLINEAR ANNOTATION TERMINATOR
])

# Combined pattern for all invisible/smuggling characters (fast boolean check).
_ALL_INVISIBLE = (ZERO_WIDTH_CHARS | BIDI_CONTROL_CHARS | CONFUSABLE_SPACES
                  | ANNOTATION_CHARS | VARIATION_SELECTORS
                  | TAG_CHARS)
ZERO_WIDTH_PATTERN = re.compile('[' + re.escape(''.join(_ALL_INVISIBLE)) + ']')
BIDI_PATTERN = re.compile('[' + re.escape(''.join(BIDI_CONTROL_CHARS)) + ']')
VARIATION_SELECTOR_PATTERN = re.compile('[' + re.escape(''.join(VARIATION_SELECTORS)) + ']')
SUPPLEMENTAL_VS_PATTERN = re.compile('[' + re.escape(''.join(SUPPLEMENTAL_VARIATION_SELECTORS)) + ']')
TAG_CHAR_PATTERN = re.compile('[' + re.escape(''.join(TAG_CHARS)) + ']')
CONFUSABLE_SPACE_PATTERN = re.compile('[' + re.escape(''.join(CONFUSABLE_SPACES)) + ']')
# C1 controls (0x80-0x9F) + C0 non-whitespace (0x00-0x08, 0x0B, 0x0E-0x1F, 0x7F)
C1_CONTROL_PATTERN = re.compile(r'[\x00-\x08\x0b\x0e-\x1f\x7f-\x9f]')

# Shared code file extensions for Unicode checks.
UNICODE_CODE_EXTS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.rb', '.go', '.rs', '.sh', '.bash',
                     '.mjs', '.cjs', '.php', '.java', '.c', '.cpp', '.h', '.swift', '.kt', '.zsh'}

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


def _is_emoji_codepoint(cp):
    """Return True if codepoint is an emoji base character (not ZWJ/VS16 themselves)."""
    return (0x1F300 <= cp <= 0x1FFFF      # Misc Symbols, Emoticons, Transport, Supplemental
            or 0x2600 <= cp <= 0x27BF     # Misc Symbols, Dingbats
            or 0x2300 <= cp <= 0x23FF     # Misc Technical (hourglass, watch, etc.)
            or 0x20E3 == cp               # Combining Enclosing Keycap
            or 0x1F1E0 <= cp <= 0x1F1FF   # Regional Indicator Symbols (flags)
            or cp in (0x2702, 0x2705, 0x2708, 0x2709, 0x270A, 0x270B,
                      0x270C, 0x270D, 0x270F, 0x2712, 0x2714, 0x2716,
                      0x2728, 0x2733, 0x2734, 0x2744, 0x2747, 0x274C,
                      0x274E, 0x2753, 0x2754, 0x2755, 0x2757, 0x2763,
                      0x2764, 0x27A1, 0x2934, 0x2935, 0x2B05, 0x2B06,
                      0x2B07, 0x2B1B, 0x2B1C, 0x2B50, 0x2B55, 0x3030,
                      0x303D, 0x3297, 0x3299, 0xA9, 0xAE))


def _is_emoji_context(content, pos, char):
    """Return True if the invisible char at `pos` is part of a legitimate emoji
    sequence (adjacent to an actual emoji codepoint).

    Only whitelists U+200D (ZWJ) and U+FE0F (VS16). Requires the adjacent
    character to be in a Unicode emoji range, not just any non-ASCII char.
    This prevents bypass via accented Latin (e.g. 'é') or CJK characters.
    """
    if char not in ('‍', '️'):
        return False
    for offset in (-1, -2, 1, 2):
        adj_pos = pos + offset
        if 0 <= adj_pos < len(content):
            if _is_emoji_codepoint(ord(content[adj_pos])):
                return True
    return False


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
    # Destructive command patterns (Shai-Hulud destructive fallback)
    (re.compile(r'(?i)\bshred\b.*(-[uvzn]|--remove)'), "Destructive: File shredding command (Shai-Hulud destructive fallback)"),
    (re.compile(r'(?i)\brm\s+(-[rf]+\s+)+(\$HOME|~/|~\b|/home/)'), "Destructive: Home directory deletion"),
    (re.compile(r'(?i)\bcipher\s+/[wW]:'), "Destructive: Windows cipher wipe (Shai-Hulud destructive fallback)"),
    (re.compile(r'(?i)\bdd\s+if=/dev/(zero|random)\s+of=/dev/'), "Destructive: Disk overwrite"),
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
# Category 4b: Credential-Path Directives (high)
# Instruction files directing agents to read sensitive credential paths.
# ============================================================
_CRED_PATHS = r'(~/.aws/credentials|~/.ssh/id_|~/.gnupg/|~/.config/gh/hosts\.yml|~/.claude/settings\.json|~/.gitconfig|/etc/shadow|\.env\b)'
_CRED_VERBS = r'(?:include|read|cat|output|print|show|display|add\s+to|copy|send|upload|forward|open|access)'
CREDENTIAL_PATH_PATTERNS = [
    (re.compile(r'(?i)\b' + _CRED_VERBS + r'\b[^.\n]{0,80}' + _CRED_PATHS), "Credential-path directive: instruction to access sensitive file"),
    (re.compile(r'(?i)' + _CRED_PATHS + r'[^.\n]{0,80}\b' + _CRED_VERBS + r'\b'), "Credential-path directive: sensitive file referenced with action verb"),
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
    (re.compile(r'(?i)config\.sh\s+--url.*--token'), "GHA Self-Hosted Runner Installation (Shai-Hulud backdoor pattern)"),
    (re.compile(r'(?i)svc\.sh\s+(install|start)'), "GHA Runner Service Installation (Shai-Hulud backdoor pattern)"),
    (re.compile(r'(?i)actions[/-]runner'), "GitHub Actions Runner Binary Reference"),
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
    # LiteLLM supply chain compromise (March 2026)
    "models.litellm.cloud",
    # Checkmarx TeamPCP infrastructure (2026)
    "checkmarx.zone",
    # TanStack worm: Session P2P exfiltration (May 2026)
    "filev2.getsession.org",
    "seed1.getsession.org",
    "seed2.getsession.org",
    "seed3.getsession.org",
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
    # TeamPCP C2 patterns (Bitwarden worm + Mini Shai-Hulud, April 2026)
    (re.compile(r'LongLiveTheResistanceAgainstMachines'), "TeamPCP C2: GitHub commit dead-drop pattern (Bitwarden worm, April 2026)"),
    (re.compile(r'beautifulcastle\s+[A-Za-z0-9+/=]'), "TeamPCP C2: RSA-signed command delivery (Bitwarden worm, April 2026)"),
    (re.compile(r'docs-tpcp'), "TeamPCP: Exfiltration repo indicator (April 2026)"),
    # Mini Shai-Hulud IOC strings (TeamPCP Wave 6, April 29 2026)
    (re.compile(r'OhNoWhatsGoingOnWithGitHub'), "Mini Shai-Hulud: GitHub commit dead-drop token sharing marker (TeamPCP Wave 6)"),
    (re.compile(r'A Mini Shai-Hulud has Appeared'), "Mini Shai-Hulud: Exfiltration repo description marker (TeamPCP Wave 6)"),
    (re.compile(r'ctf-scramble-v2'), "Mini Shai-Hulud: PBKDF2 obfuscation salt (TeamPCP shared indicator across Waves 5-6)"),
    (re.compile(r'tmp\.987654321\.lock'), "Mini Shai-Hulud: Anti-re-execution lock file (TeamPCP Wave 6)"),
    (re.compile(r'\bSHA1HULUD\b'), "Mini Shai-Hulud: Self-hosted GHA runner name (TeamPCP Wave 6)"),
    (re.compile(r'\.dev-env/(config|run)\.(sh|cmd)'), "Mini Shai-Hulud: GHA runner installation path (TeamPCP Wave 6)"),
    (re.compile(r'api\.cloud-aws\.adc-e\.uk'), "Mini Shai-Hulud: Attacker-controlled C2 domain (TeamPCP Wave 6)"),
    (re.compile(r'Exiting as russian language detected'), "TeamPCP: Anti-attribution locale check (Waves 5-6)"),
    (re.compile(r'__DAEMONIZED'), "Mini Shai-Hulud: Anti-re-execution environment variable guard (TeamPCP Wave 6)"),
    (re.compile(r'thebeautifulmarchoftime'), "TanStack Shai-Hulud: beautify() cipher key marker (TeamPCP Wave 7, May 2026)"),
    (re.compile(r'thebeautifulsandsoftime'), "TanStack Shai-Hulud: beautify() cipher key marker (TeamPCP Wave 7, May 2026)"),
    (re.compile(r'\brouter_init\.js\b'), "TanStack Shai-Hulud: Malicious payload filename (TeamPCP Wave 7, May 2026)"),
    (re.compile(r'getsession\.org'), "TanStack Shai-Hulud: Session P2P exfiltration network (TeamPCP Wave 7, May 2026)"),
    (re.compile(r'voicproducoes'), "TanStack Shai-Hulud: Attacker git identity (TeamPCP Wave 7, May 2026)"),
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


# ============================================================
# Category 14: Sub-Agent Spawn Detection (high)
# Instructions to spawn rogue child agents with attacker-controlled prompts.
# Source: DeepMind AI Agent Traps (March 2026), 58-90% success rate
# ============================================================
SUB_AGENT_SPAWN_PATTERNS = [
    (re.compile(r'(?i)(?:create|spawn|launch|start|initialize|instantiate|fork|dispatch)\s+(?:a\s+)?(?:new\s+)?(?:agent|sub-?agent|child\s+agent|assistant|worker|instance|clone|replica)'), "Sub-agent spawn directive (DeepMind Agent Traps, March 2026)"),
    (re.compile(r'(?i)(?:delegate|hand\s+off|pass)\s+(?:to|this\s+to)\s+(?:a\s+)?(?:new\s+)?(?:agent|sub-?agent|assistant)'), "Sub-agent delegation directive (DeepMind Agent Traps, March 2026)"),
    (re.compile(r'(?i)(?:run|execute)\s+(?:this|the\s+following)\s+(?:in|as|with)\s+(?:a\s+)?(?:new|separate|independent|background)\s+(?:agent|session|context|instance)'), "Sub-agent execution isolation directive (DeepMind Agent Traps, March 2026)"),
    (re.compile(r'(?:Agent|SubAgent|ChildAgent|Worker)\s*\(\s*["\{]'), "Code-level agent instantiation with inline config (DeepMind Agent Traps, March 2026)"),
]

# ============================================================
# Category 15: Authority Framing / Social Engineering (medium/high)
# Persuasion-based attacks that bypass injection detection by social engineering.
# Source: DeepMind AI Agent Traps "Semantic Manipulation" (March 2026)
# ============================================================
AUTHORITY_FRAMING_PATTERNS = [
    (re.compile(r'(?i)(?:as\s+the|acting\s+as|I\s+am\s+the)\s+(?:system\s+)?(?:administrator|admin|root|owner|operator|maintainer|developer)'), "Authority claim: impersonating admin/root (DeepMind Semantic Manipulation, March 2026)"),
    (re.compile(r'(?i)(?:you\s+(?:have\s+been|are)\s+(?:granted|authorized|permitted|given))\s+(?:access|permission|elevated|full|admin)'), "Authority claim: granting elevated permissions (DeepMind Semantic Manipulation, March 2026)"),
    (re.compile(r'(?i)(?:with\s+(?:elevated|admin|root|full|special|override))\s+(?:permissions?|privileges?|access|authority)'), "Authority claim: elevated privilege assertion (DeepMind Semantic Manipulation, March 2026)"),
    (re.compile(r'(?i)(?:this\s+(?:is|has\s+been)\s+(?:approved|authorized|sanctioned|cleared))\s+by\s+(?:the\s+)?(?:admin|owner|team|security)'), "Authority claim: fake approval assertion (DeepMind Semantic Manipulation, March 2026)"),
]

SAFETY_THEATER_PATTERNS = [
    (re.compile(r'(?i)(?:this\s+is\s+(?:a|an|just\s+a))\s+(?:red.?team|pentest|security\s+(?:test|audit|exercise|drill)|educational|training|simulation|demo|test\s+environment)'), "Safety theater: fake testing context (DeepMind Semantic Manipulation, March 2026)"),
    (re.compile(r'(?i)(?:for\s+(?:educational|research|testing|debugging|diagnostic|demonstration)\s+purposes?\s+only)'), "Safety theater: educational/research pretext (DeepMind Semantic Manipulation, March 2026)"),
    (re.compile(r'(?i)(?:in\s+(?:a\s+)?(?:sandbox|test|staging|development|safe|isolated)\s+environment)'), "Safety theater: fake sandbox claim (DeepMind Semantic Manipulation, March 2026)"),
]

TRUST_ESCALATION_PATTERNS = [
    (re.compile(r'(?i)(?:you\s+can\s+(?:safely|freely|trust|skip)\s+(?:ignore|bypass|disable|skip))\s+(?:safety|security|verification|validation|checks?)'), "Trust escalation: bypass safety checks (DeepMind Semantic Manipulation, March 2026)"),
    (re.compile(r'(?i)(?:no\s+(?:need|reason)\s+to\s+(?:verify|check|validate|confirm|worry))'), "Trust escalation: skip verification (DeepMind Semantic Manipulation, March 2026)"),
]

_ALL_AUTHORITY_PATTERNS = AUTHORITY_FRAMING_PATTERNS + SAFETY_THEATER_PATTERNS + TRUST_ESCALATION_PATTERNS
_AUTHORITY_FP_PATH_RE = re.compile(r'(?i)(?:test|spec|example|sample|documentation|tutorial|how.?to)')

# ============================================================
# Category 12: Deferred Update Channel (high)
# Skills that create persistent remote-control channels by instructing agents
# to check for updates, read changelogs, or apply patches from files.
# Source: Terra Security OpenClaw vulnerability research (May 2026)
# ============================================================
_SKILL_CONFIG_FILES = SKILL_CONFIG_FILES

UPDATE_CHANNEL_PATTERNS = [
    (re.compile(r'(?i)\b(?:check|read|review)\s+(?:\S+\.)?(changelog|updates?|release.?notes?)\b.*\b(?:for|about)\s+(?:updates?|changes?|new\s+instructions?|procedures?|patches?)'), "Deferred update channel: check file for updates (Terra Security OpenClaw, May 2026)"),
    (re.compile(r'(?i)\b(?:apply|follow|execute|run)\s+(?:updates?|patches?|procedures?|instructions?)\s+(?:from|in|described\s+in)\s+\S+'), "Deferred update channel: apply instructions from file (Terra Security OpenClaw, May 2026)"),
    (re.compile(r'(?i)\b(?:pull\s+latest|git\s+pull|fetch\s+updates?)\b'), "Deferred update channel: pull latest from repository (Terra Security OpenClaw, May 2026)"),
    (re.compile(r'(?i)\b(?:read|check|consult)\s+\S+\.md\s+(?:for|about)\s+(?:new\s+instructions?|updates?|changes?|procedures?)'), "Deferred update channel: read file for new instructions (Terra Security OpenClaw, May 2026)"),
    (re.compile(r'(?i)\b(?:run|execute|follow)\s+\S+\.md\s+(?:each|every|on\s+each|per)\s+(?:heartbeat|cycle|iteration|session|loop)'), "Deferred update channel: run file on each heartbeat/cycle (Terra Security OpenClaw, May 2026)"),
]

# ============================================================
# Category 13: Prose Imperative Exfiltration (medium/high)
# Natural language instructions an AI agent would follow as commands.
# Source: Terra Security OpenClaw vulnerability research (May 2026)
# ============================================================
_PROSE_VERBS = EXFIL_VERBS_RE
_PROSE_URL = r'https?://\S+'
_SENSITIVE_FILE_REF = r'(?:\.json|\.env|\.ssh|\.aws|config|credentials?|tokens?|secrets?|keys?|openclaw|\.gnupg|password)'
_SAFE_DOMAINS = {'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'docs.google.com', 'npmjs.com', 'pypi.org'}

PROSE_IMPERATIVE_VERB_FILE_URL = re.compile(
    r'(?i)\b' + _PROSE_VERBS + r'\b[^.\n]{0,80}' + _SENSITIVE_FILE_REF + r'[^.\n]{0,80}' + _PROSE_URL
)
PROSE_IMPERATIVE_VERB_URL = re.compile(
    r'(?i)\b' + _PROSE_VERBS + r'\b[^.\n]{0,120}' + _PROSE_URL
)
PROSE_IMPERATIVE_URL_VERB_FILE = re.compile(
    r'(?i)' + _SENSITIVE_FILE_REF + r'[^.\n]{0,80}\b' + _PROSE_VERBS + r'\b[^.\n]{0,80}' + _PROSE_URL
)


def scan_unicode_smuggling(content, rel_path):
    """Category 2: Detect invisible Unicode chars, Trojan Source bidi controls,
    variation selectors, confusable spaces, and homoglyphs.
    Character sets informed by anti-trojan-source (Liran Tal) + Unicode 15.1.
    All checks use compiled regex patterns (C-speed inner loop, no O(N^2)).
    """
    findings = []

    # Count zero-width/invisible characters (capped to prevent slow scans).
    # Skip ZWJ/VS16 that are part of legitimate emoji sequences.
    zw_count = 0
    for m in ZERO_WIDTH_PATTERN.finditer(content):
        if _is_emoji_context(content, m.start(), m.group(0)):
            continue
        zw_count += 1
        if zw_count >= 100:
            break
    if zw_count >= 3:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Zero-Width Character Cluster",
            description=f"Found {zw_count} zero-width/invisible Unicode characters (potential text smuggling)",
            file=rel_path, line=0,
            snippet=f"{zw_count} invisible chars detected",
            category="unicode-smuggling"
        ))

    # Trojan Source: bidirectional control characters (critical)
    m = BIDI_PATTERN.search(content)
    if m:
        cp = ord(m.group(0))
        line_no = content[:m.start()].count('\n') + 1
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Trojan Source: Bidirectional Control Character",
            description=f"Bidi control U+{cp:04X} can make code render differently than it executes (trojansource.codes)",
            file=rel_path, line=line_no,
            snippet=f"Contains U+{cp:04X} bidi control",
            category="unicode-smuggling"
        ))

    # Variation selectors (alter glyph rendering invisibly).
    # Skip VS16 (U+FE0F) when used in emoji sequences.
    for m in VARIATION_SELECTOR_PATTERN.finditer(content):
        if _is_emoji_context(content, m.start(), m.group(0)):
            continue
        cp = ord(m.group(0))
        line_no = content[:m.start()].count('\n') + 1
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="high",
            title="Unicode Variation Selector",
            description=f"Variation selector U+{cp:04X} alters character appearance without changing semantics",
            file=rel_path, line=line_no,
            snippet=f"Contains U+{cp:04X} variation selector",
            category="unicode-smuggling"
        ))
        break

    # Supplemental variation selectors (VS17-VS256, GlassWorm campaign range)
    m = SUPPLEMENTAL_VS_PATTERN.search(content)
    if m:
        cp = ord(m.group(0))
        line_no = content[:m.start()].count('\n') + 1
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="GlassWorm: Supplemental Variation Selector",
            description=f"Supplemental variation selector U+{cp:05X} (VS17-VS256 range). This range was weaponized in the GlassWorm campaign (Oct 2025-Mar 2026) to hide executable JavaScript in 433 VS Code extensions.",
            file=rel_path, line=line_no,
            snippet=f"Contains U+{cp:05X} supplemental variation selector",
            category="unicode-smuggling"
        ))

    # Tag characters (invisible Unicode plane 14)
    m = TAG_CHAR_PATTERN.search(content)
    if m:
        cp = ord(m.group(0))
        line_no = content[:m.start()].count('\n') + 1
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="high",
            title="Unicode Tag Character",
            description=f"Tag character U+{cp:04X} is invisible and can embed hidden metadata",
            file=rel_path, line=line_no,
            snippet=f"Contains U+{cp:04X} tag character",
            category="unicode-smuggling"
        ))

    ext = os.path.splitext(rel_path)[1].lower()
    if ext in UNICODE_CODE_EXTS:
        # C1 control characters in source code
        m = C1_CONTROL_PATTERN.search(content)
        if m:
            cp = ord(m.group(0))
            line_no = content[:m.start()].count('\n') + 1
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="medium",
                title="Control Character in Source Code",
                description=f"Control character U+{cp:04X} in source file (potential terminal injection or obfuscation)",
                file=rel_path, line=line_no,
                snippet=f"Contains U+{cp:04X} control char",
                category="unicode-smuggling"
            ))

        # Confusable space in code (Glassworm vector)
        m = CONFUSABLE_SPACE_PATTERN.search(content)
        if m:
            cp = ord(m.group(0))
            line_no = content[:m.start()].count('\n') + 1
            lines = content.split('\n')
            line_content = lines[line_no - 1] if line_no <= len(lines) else ""
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="medium",
                title="Glassworm: Confusable Space in Code",
                description=f"Non-standard space U+{cp:04X} looks identical to regular space but has different semantics",
                file=rel_path, line=line_no,
                snippet=line_content.strip()[:120],
                category="unicode-smuggling"
            ))

        # Homoglyph detection
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
        if len(line) > core.MAX_LINE_LENGTH:
            continue
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

    # AI agent instruction files: treat like SKILL.MD for prompt injection + exfiltration + persistence
    _AGENT_INSTRUCTION_FILES = {'SKILL.MD', 'README.MD', 'CLAUDE.MD', '.CURSORRULES', '.WINDSURFRULES'}
    basename_upper = os.path.basename(rel_path).upper()
    # Also match .github/copilot-instructions.md by path
    is_copilot_instructions = rel_path.replace('\\', '/').endswith('.github/copilot-instructions.md')
    is_agent_instruction_file = basename_upper in _AGENT_INSTRUCTION_FILES or is_copilot_instructions

    if ext in text_exts or ext in code_exts or is_agent_instruction_file:
        # Cat 1: Prompt injection (most relevant in .md, .txt, .yml)
        findings.extend(scan_patterns(content, rel_path, PROMPT_INJECTION_PATTERNS, "prompt-injection", "critical"))

    # Cat 2: Unicode smuggling (all files)
    findings.extend(scan_unicode_smuggling(content, rel_path))

    if ext in text_exts or ext in code_exts:
        # Cat 3: Prerequisite red flags
        findings.extend(scan_patterns(content, rel_path, PREREQUISITE_PATTERNS, "prerequisite-attack", "critical"))

    if ext in code_exts or is_agent_instruction_file:
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

    # Cat 4b: Credential-path directives (agent instruction files + text files)
    if is_agent_instruction_file or ext in text_exts:
        findings.extend(scan_patterns(content, rel_path, CREDENTIAL_PATH_PATTERNS, "credential-path-directive", "high"))

    # Cat 8: IOCs (all files)
    findings.extend(scan_known_iocs(content, rel_path))

    # Cat 9: ClickFix/sleeper malware (text + code: SKILL.md prereqs with payload delivery)
    if ext in text_exts or ext in code_exts:
        findings.extend(scan_patterns(content, rel_path, CLICKFIX_PATTERNS, "clickfix-sleeper", "critical"))

    # Cat 10: MCP tool definition injection (.json, .py, .ts, .js, .md)
    if ext in ('.json', '.py', '.ts', '.js', '.md', '.toml'):
        findings.extend(scan_patterns(content, rel_path, MCP_TOOL_INJECTION_PATTERNS, "mcp-tool-injection", "critical"))

    # Category 11: LITL text padding detection (Checkmarx, September 2025)
    # Detect excessively long tool descriptions or instructions designed to push
    # malicious content off-screen in HITL approval dialogs
    if ext in {'.md', '.txt', '.yml', '.yaml', '.toml'}:
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if len(line) > 2000 and any(kw in line.lower() for kw in ('approve', 'permission', 'confirm', 'execute', 'allow')):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="LITL: Oversized Line with Action Keywords",
                    description="Line exceeds 2000 chars and contains action/approval keywords. May be LITL text padding to push malicious commands off-screen (Checkmarx Lies-in-the-Loop attack).",
                    file=rel_path, line=i + 1,
                    snippet=line[:120],
                    category="litl-attack"
                ))
                break

    # Cat 12: Deferred update channel (Terra Security OpenClaw, May 2026)
    # Only fire in skill config files to avoid FPs in general documentation
    if ext in text_exts:
        basename_lower = os.path.basename(rel_path).lower()
        if basename_lower in _SKILL_CONFIG_FILES:
            findings.extend(scan_patterns(content, rel_path, UPDATE_CHANNEL_PATTERNS, "update-channel", "high"))

    # Cat 14: Sub-agent spawn detection (DeepMind Agent Traps, March 2026)
    if ext in text_exts or ext in code_exts:
        findings.extend(scan_patterns(content, rel_path, SUB_AGENT_SPAWN_PATTERNS, "sub-agent-spawn", "high"))

    # Cat 15: Authority framing / social engineering (DeepMind Agent Traps, March 2026)
    if ext in text_exts:
        if not _AUTHORITY_FP_PATH_RE.search(rel_path):
            findings.extend(_scan_authority_framing(content, rel_path))

    # Cat 13: Prose imperative exfiltration (Terra Security OpenClaw, May 2026)
    if ext in text_exts:
        findings.extend(_scan_prose_imperatives(content, rel_path))

    return findings


def _scan_authority_framing(content, rel_path):
    """Category 15: Detect authority framing and social engineering.
    Skips lines inside code fences."""
    findings = []
    in_code_fence = False
    for i, line in enumerate(content.split('\n')):
        stripped = line.strip()
        if stripped.startswith('```'):
            in_code_fence = not in_code_fence
            continue
        if in_code_fence:
            continue
        if len(line) > core.MAX_LINE_LENGTH:
            continue
        for pat, title in _ALL_AUTHORITY_PATTERNS:
            if pat.search(line):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title=title,
                    description="Social engineering technique that bypasses injection detection by persuading rather than commanding (DeepMind Agent Traps, March 2026).",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="authority-framing"
                ))
                break
    return findings


def _scan_prose_imperatives(content, rel_path):
    """Category 13: Detect natural language exfiltration instructions.
    Tracks markdown code fences to skip code examples."""
    findings = []
    in_code_fence = False
    lines = content.split('\n')
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('```'):
            in_code_fence = not in_code_fence
            continue
        if in_code_fence:
            continue
        if len(line) > core.MAX_LINE_LENGTH:
            continue

        url_match = re.search(r'https?://(\S+)', line)
        if not url_match:
            continue
        domain = url_match.group(1).split('/')[0].lower()
        is_safe_domain = domain in _SAFE_DOMAINS
        if '@' in line[:url_match.start()] and 'http' not in line[:url_match.start()]:
            continue

        if PROSE_IMPERATIVE_VERB_FILE_URL.search(line) or PROSE_IMPERATIVE_URL_VERB_FILE.search(line):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Prose Imperative: Exfiltration instruction with file reference",
                description="Natural language instruction to send/upload a sensitive file to a URL. AI agents may follow this as a command (Terra Security OpenClaw, May 2026).",
                file=rel_path, line=i + 1,
                snippet=line.strip()[:120],
                category="prose-imperative"
            ))
        elif not is_safe_domain and PROSE_IMPERATIVE_VERB_URL.search(line):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="medium",
                title="Prose Imperative: Action directive with URL",
                description="Natural language instruction with imperative verb and URL target. May be benign documentation or agent-directed exfiltration (Terra Security OpenClaw, May 2026).",
                file=rel_path, line=i + 1,
                snippet=line.strip()[:120],
                category="prose-imperative"
            ))
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
