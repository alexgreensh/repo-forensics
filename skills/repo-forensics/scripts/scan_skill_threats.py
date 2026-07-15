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
import rule_loader
from _shared_patterns import EXFIL_VERBS_RE, SKILL_CONFIG_FILES

SCANNER_NAME = "skill_threats"

# ============================================================
# Rules-as-data (U4): all behavioral pattern tables, the unicode-smuggling
# character sets, and the homoglyph map load from skill_threats.json at import
# (rule_loader memoizes). The pack is the single source of truth; no hardcoded
# fallback table. If the pack cannot load, the scanner emits ONE loud critical
# diagnostic per file and scans nothing. Context/algorithm machinery (emoji
# context, count capping, NFKC, imperative-proximity windows, safe-domain
# allowlist, morse/hex/IOC detectors, Cat-11 length check) STAYS in code.
# ============================================================
_PACK = rule_loader.load_pack(SCANNER_NAME)
PACK_LOAD_ERROR = _PACK is None


def _rules_for_category(category):
    """Regex rules tagged with `category`, in pack order, as a tuple of
    CompiledRule so call sites read like the old tuple-lists but each finding
    can stamp rule_id + confidence."""
    if _PACK is None:
        return ()
    return tuple(r for r in _PACK.all_rules
                 if r.type == "regex" and r.category == category)


def _charset_codepoints(rule_id):
    if _PACK is None:
        return frozenset()
    for r in _PACK.charset_rules:
        if r.id == rule_id:
            return r.codepoints
    return frozenset()


def _homoglyph_map():
    if _PACK is None:
        return {}
    for r in _PACK.map_rules:
        if r.id == "ST-HG-001":
            return r.mapping
    return {}


def _pack_load_finding(rel_path):
    """Single loud diagnostic when the rule pack failed to load (no hardcoded
    fallback copy of the rules; corrupted install also caught by integrity)."""
    return core.Finding(
        scanner=SCANNER_NAME, severity="critical",
        title="Skill-threat rule pack failed to load",
        description=("data/rulepacks/skill_threats.json is missing or "
                     "schema-incompatible; skill-threat scanning is disabled. "
                     "Reinstall repo-forensics to restore detection."),
        file=rel_path, line=0,
        snippet="rule pack failed to load",
        category="scanner-integrity",
    )


# Per-category regex rule lists (replace the old tuple-list constants). Category
# names match the pack + scan_file call sites, so correlation keyword matching
# and core.scan_rule_patterns call sites are unaffected.
PROMPT_INJECTION_RULES = _rules_for_category("prompt-injection")
PREREQUISITE_RULES = _rules_for_category("prerequisite-attack")
EXFIL_RULES = _rules_for_category("credential-exfiltration")
# The credential-exfil rules historically emitted at different severities by
# sub-table; we re-derive the split from rule id so the call sites keep the same
# per-table default severity (parity). 005-007 = bulk-env critical, 008 = single
# env-access medium, 001-004 = webhook/base64/readfile critical.
EXFIL_RULES_CRITICAL = tuple(r for r in EXFIL_RULES if r.id in ("ST-EX-005", "ST-EX-006", "ST-EX-007"))
EXFIL_RULES_MEDIUM = tuple(r for r in EXFIL_RULES if r.id == "ST-EX-008")
EXFIL_RULES_OTHER = tuple(r for r in EXFIL_RULES if r.id in ("ST-EX-001", "ST-EX-002", "ST-EX-003", "ST-EX-004"))
CREDENTIAL_PATH_RULES = _rules_for_category("credential-path-directive")
PERSISTENCE_RULES = _rules_for_category("persistence")
SCOPE_RULES = _rules_for_category("scope-escalation")
STEALTH_RULES = _rules_for_category("stealth")
CLICKFIX_RULES = _rules_for_category("clickfix-sleeper")
MCP_TOOL_INJECTION_RULES = _rules_for_category("mcp-tool-injection")
UPDATE_CHANNEL_RULES = _rules_for_category("update-channel")
SUB_AGENT_SPAWN_RULES = _rules_for_category("sub-agent-spawn")
AUTHORITY_FRAMING_RULES = _rules_for_category("authority-framing")
MEMORY_HEIST_RULES = _rules_for_category("memory-heist-exfil")

# ============================================================
# Category 2: Invisible Unicode Smuggling (critical)
# Character sets load from the pack as `charset` rules; the scanner rebuilds its
# compiled [..] detection patterns from those codepoints at load. The
# counting/capping/emoji-context ALGORITHM stays in scan_unicode_smuggling.
# ============================================================
ZERO_WIDTH_CHARS = {chr(cp) for cp in _charset_codepoints("ST-ZW-001")}
BIDI_CONTROL_CHARS = {chr(cp) for cp in _charset_codepoints("ST-BD-001")}
VARIATION_SELECTORS = {chr(cp) for cp in _charset_codepoints("ST-VS-001")}
SUPPLEMENTAL_VARIATION_SELECTORS = {chr(cp) for cp in _charset_codepoints("ST-SV-001")}
CONFUSABLE_SPACES = {chr(cp) for cp in _charset_codepoints("ST-CS-001")}
TAG_CHARS = {chr(cp) for cp in _charset_codepoints("ST-TG-001")}
ANNOTATION_CHARS = {chr(cp) for cp in _charset_codepoints("ST-AN-001")}

# Combined pattern for all invisible/smuggling characters (fast boolean check).
_ALL_INVISIBLE = (ZERO_WIDTH_CHARS | BIDI_CONTROL_CHARS | CONFUSABLE_SPACES
                  | ANNOTATION_CHARS | VARIATION_SELECTORS
                  | TAG_CHARS)


def _charset_pattern(chars):
    """Compiled [..] class from a char set; empty-safe (never-match when the
    pack is missing, so a failed load degrades to no unicode findings, not a
    crash)."""
    if not chars:
        return re.compile(r'(?!x)x')  # matches nothing
    return re.compile('[' + re.escape(''.join(chars)) + ']')


ZERO_WIDTH_PATTERN = _charset_pattern(_ALL_INVISIBLE)
BIDI_PATTERN = _charset_pattern(BIDI_CONTROL_CHARS)
VARIATION_SELECTOR_PATTERN = _charset_pattern(VARIATION_SELECTORS)
SUPPLEMENTAL_VS_PATTERN = _charset_pattern(SUPPLEMENTAL_VARIATION_SELECTORS)
TAG_CHAR_PATTERN = _charset_pattern(TAG_CHARS)
CONFUSABLE_SPACE_PATTERN = _charset_pattern(CONFUSABLE_SPACES)
# C1 controls (0x80-0x9F) + C0 non-whitespace. Algorithmic control-char class,
# not a pattern table, so it stays in code.
C1_CONTROL_PATTERN = re.compile(r'[\x00-\x08\x0b\x0e-\x1f\x7f-\x9f]')

# Shared code file extensions for Unicode checks (scanning context, stays).
UNICODE_CODE_EXTS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.rb', '.go', '.rs', '.sh', '.bash',
                     '.mjs', '.cjs', '.php', '.java', '.c', '.cpp', '.h', '.swift', '.kt', '.zsh'}

# Cyrillic/Greek confusables for Latin letters (homoglyph map rule from pack).
HOMOGLYPHS = _homoglyph_map()
HOMOGLYPH_PATTERN = (re.compile('[' + ''.join(HOMOGLYPHS.keys()) + ']')
                     if HOMOGLYPHS else re.compile(r'(?!x)x'))


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
# Categories 9-15 pattern tables now live in skill_threats.json (loaded above as
# CLICKFIX_RULES, MCP_TOOL_INJECTION_RULES, SUB_AGENT_SPAWN_RULES,
# AUTHORITY_FRAMING_RULES, UPDATE_CHANNEL_RULES). The authority/safety/trust
# rules share one category ("authority-framing") and are scanned together by
# _scan_authority_framing, which needs (regex, title) tuples; we rebuild that
# list from the pack rules here (construction stays in code, data is in the pack).
# ============================================================
_ALL_AUTHORITY_RULES = AUTHORITY_FRAMING_RULES
_AUTHORITY_FP_PATH_RE = re.compile(r'(?i)(?:test|spec|example|sample|documentation|tutorial|how.?to)')

# Skill config filenames that gate the deferred-update-channel check (from shared pack).
_SKILL_CONFIG_FILES = SKILL_CONFIG_FILES

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


def scan_rules(content, rel_path, rules, category, default_severity):
    """Delegate to pack-aware scan_rule_patterns (stamps rule_id + confidence)."""
    return core.scan_rule_patterns(content, rel_path, rules, category, default_severity, SCANNER_NAME)


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


MORSE_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
MORSE_MAP = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
}
MORSE_TOKEN_RE = re.compile(r'[.\-]{1,6}')
MORSE_SEQUENCE_RE = re.compile(r'(?:[.\-]{1,6}[\s/]{1,3}){7,}[.\-]{1,6}')
HEX_PAIR_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}\s*){8,}')
HEX_SPACED_RE = re.compile(r'(?:[0-9a-fA-F]{2}\s){7,}[0-9a-fA-F]{2}')


def scan_morse_encoding(content, rel_path):
    """Category 16: Detect Morse code sequences in documentation files."""
    ext = os.path.splitext(rel_path)[1].lower()
    if ext not in {'.md', '.txt', '.rst', '.adoc'}:
        return []
    findings = []
    for i, line in enumerate(content.split('\n')):
        if len(line) > core.MAX_LINE_LENGTH:
            continue
        m = MORSE_SEQUENCE_RE.search(line)
        if not m:
            continue
        tokens = MORSE_TOKEN_RE.findall(m.group()[:500])
        valid = sum(1 for t in tokens if t in MORSE_MAP)
        if len(tokens) >= 8 and valid / len(tokens) >= 0.5:
            decoded_chars = [MORSE_MAP.get(t, '?') for t in tokens[:20]]
            decoded_preview = ''.join(decoded_chars)
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Morse Code Encoding in Documentation",
                description=f"Line contains {len(tokens)} Morse tokens ({valid}/{len(tokens)} valid). "
                    f"Decoded preview: '{decoded_preview}'. May hide executable instructions "
                    f"(Grok/Bankrbot incident, May 2026).",
                file=rel_path, line=i + 1,
                snippet=line.strip()[:120],
                category="morse-encoding"
            ))
    return findings


def scan_hex_encoding(content, rel_path):
    """Category 17: Detect hex-encoded strings in documentation files."""
    ext = os.path.splitext(rel_path)[1].lower()
    if ext not in {'.md', '.txt', '.rst', '.adoc'}:
        return []
    findings = []
    for i, line in enumerate(content.split('\n')):
        if len(line) > core.MAX_LINE_LENGTH:
            continue
        for pattern in (HEX_PAIR_RE, HEX_SPACED_RE):
            m = pattern.search(line)
            if not m:
                continue
            hex_str = m.group()
            raw_bytes = re.findall(r'[0-9a-fA-F]{2}', hex_str)
            if len(raw_bytes) < 8:
                continue
            try:
                sample = raw_bytes[:30]
                decoded = bytes(int(b, 16) for b in sample)
                printable = sum(1 for c in decoded if 32 <= c <= 126)
                if printable / len(decoded) >= 0.6:
                    preview = decoded.decode('ascii', errors='replace')[:40]
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title="Hex-Encoded String in Documentation",
                        description=f"Line contains {len(raw_bytes)} hex-encoded bytes "
                            f"({printable}/{len(sample)} sampled are printable). Preview: '{preview}'. "
                            f"May hide executable instructions.",
                        file=rel_path, line=i + 1,
                        snippet=line.strip()[:120],
                        category="hex-encoding"
                    ))
                    break
            except (ValueError, OverflowError):
                continue
    return findings


def scan_file(file_path, rel_path, budget=None):
    """Run all categories on a single file (reads, then delegates to scan_content).

    `budget`: optional shared scan_decode budget (see main()). When None a fresh
    per-file budget is minted inside the decode feed (correct for single-file
    callers / tests); main() threads ONE budget across every file."""
    if PACK_LOAD_ERROR:
        return [_pack_load_finding(rel_path)]
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return []
    return scan_content(content, rel_path, budget=budget)


def scan_content(content, rel_path, budget=None):
    """Run all categories over already-loaded text — an extracted archive
    member, a decoded blob. The KTD7 in-memory entry point scan_archive recurses
    so prompt-injection / unicode-smuggling / exfil / IOC detection reaches
    inside archives (the embedded-instruction-in-word/document.xml case)."""
    if PACK_LOAD_ERROR:
        return [_pack_load_finding(rel_path)]

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
        findings.extend(scan_rules(content, rel_path, PROMPT_INJECTION_RULES, "prompt-injection", "critical"))

    # Cat 2: Unicode smuggling (all files)
    findings.extend(scan_unicode_smuggling(content, rel_path))

    if ext in text_exts or ext in code_exts:
        # Cat 3: Prerequisite red flags
        findings.extend(scan_rules(content, rel_path, PREREQUISITE_RULES, "prerequisite-attack", "critical"))

    if ext in code_exts or is_agent_instruction_file:
        # Cat 4: Credential exfiltration (bulk = critical, single = medium)
        findings.extend(scan_rules(content, rel_path, EXFIL_RULES_CRITICAL, "credential-exfiltration", "critical"))
        findings.extend(scan_rules(content, rel_path, EXFIL_RULES_MEDIUM, "credential-exfiltration", "medium"))
        findings.extend(scan_rules(content, rel_path, EXFIL_RULES_OTHER, "credential-exfiltration", "critical"))
        # Cat 5: Persistence
        findings.extend(scan_rules(content, rel_path, PERSISTENCE_RULES, "persistence", "high"))
        # Cat 6: Scope escalation
        findings.extend(scan_rules(content, rel_path, SCOPE_RULES, "scope-escalation", "high"))
        # Cat 7: Stealth
        findings.extend(scan_rules(content, rel_path, STEALTH_RULES, "stealth", "high"))

    # Cat 4b: Credential-path directives (agent instruction files + text files)
    if is_agent_instruction_file or ext in text_exts:
        findings.extend(scan_rules(content, rel_path, CREDENTIAL_PATH_RULES, "credential-path-directive", "high"))

    # Cat 8: IOCs (all files)
    findings.extend(scan_known_iocs(content, rel_path))

    # Cat 9: ClickFix/sleeper malware (text + code: SKILL.md prereqs with payload delivery)
    if ext in text_exts or ext in code_exts:
        findings.extend(scan_rules(content, rel_path, CLICKFIX_RULES, "clickfix-sleeper", "critical"))

    # Cat 10: MCP tool definition injection (.json, .py, .ts, .js, .md)
    if ext in ('.json', '.py', '.ts', '.js', '.md', '.toml'):
        findings.extend(scan_rules(content, rel_path, MCP_TOOL_INJECTION_RULES, "mcp-tool-injection", "critical"))

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
            findings.extend(scan_rules(content, rel_path, UPDATE_CHANNEL_RULES, "update-channel", "high"))

    # Cat 14: Sub-agent spawn detection (DeepMind Agent Traps, March 2026)
    if ext in text_exts or ext in code_exts:
        findings.extend(scan_rules(content, rel_path, SUB_AGENT_SPAWN_RULES, "sub-agent-spawn", "high"))

    # Cat 15: Authority framing / social engineering (DeepMind Agent Traps, March 2026)
    if ext in text_exts:
        if not _AUTHORITY_FP_PATH_RE.search(rel_path):
            findings.extend(_scan_authority_framing(content, rel_path))

    # Cat 13: Prose imperative exfiltration (Terra Security OpenClaw, May 2026)
    if ext in text_exts:
        findings.extend(_scan_prose_imperatives(content, rel_path))

    # Cat 19: Memory Heist exfiltration patterns (Ayush Paul, July 2026)
    # Detects keyboard exfiltration, fake authentication, user-agent routing,
    # PII-to-URL encoding, and tool-limitation exploitation.
    if ext in text_exts or ext in code_exts:
        findings.extend(scan_rules(content, rel_path, MEMORY_HEIST_RULES,
                                   "memory-heist-exfil", "critical"))

    # Cat 16: Morse code encoding (Grok/Bankrbot, May 2026)
    findings.extend(scan_morse_encoding(content, rel_path))

    # Cat 17: Hex-encoded strings in documentation
    findings.extend(scan_hex_encoding(content, rel_path))

    # Cat 18: collect FULL base64/base85/base32/hex encoded blobs to FEED the
    # decoder. scan_skill_threats had no base64 detector, so a base64 payload in
    # a SKILL.md was never handed to scan_decode at all (torture C1.2). We do NOT
    # emit a visible finding per encoded run — that floods the benign corpus
    # (hashes, data-URIs) with false positives. The ONLY finding that surfaces is
    # the additive, FP-safe decoded-payload one, emitted ONLY when the decoded
    # plaintext actually trips a rule.
    findings.extend(_decode_and_rescan_blobs(content, rel_path, budget))

    return findings


def _decode_and_rescan_blobs(content, rel_path, budget):
    """Detect every FULL encoded run (base64/base85/base32/hex) in `content` via
    the hoisted scan_decode.detect_encoded_blobs (single source of truth, with the
    CORRECTED base85 charset — a real RFC1924 b85 payload is now matched whole and
    routed), hand each to scan_decode, and return any decoded-payload hits. The
    FULL untruncated blob is fed (a payload token past char 120 is NOT lost). ONE
    shared budget spans the scan, never re-armed. Fully guarded: a scan_decode
    failure never breaks the scan. Emits NO finding of its own — the only surfaced
    finding is the additive, FP-safe decoded-payload one.

    NOTE: the old morse/hex "backstop" loop (`_full_blob_from_finding` +
    `_ENCODED_BLOB_CATEGORIES`) was DEAD and is removed — hex blobs are already
    collected in full by detect_encoded_blobs, and morse is none of the 4
    alphabets scan_decode knows, so a morse snippet could never decode."""
    extra = []
    try:
        import scan_decode
    except Exception:
        return extra
    if budget is None:
        budget = scan_decode.host_budget()
    blobs = scan_decode.detect_encoded_blobs(content)
    scan_decode.feed_blobs(blobs, rel_path, set(), extra, budget)
    return extra


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
        for rule in _ALL_AUTHORITY_RULES:
            if rule.regex.search(line):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title=rule.title,
                    description="Social engineering technique that bypasses injection detection by persuading rather than commanding (DeepMind Agent Traps, March 2026).",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="authority-framing",
                    rule_id=rule.id,
                    confidence=rule.confidence,
                    attacker=rule.attacker,
                    boundary=rule.boundary,
                    asset=rule.asset,
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

    # ONE shared decode budget across every file (see scan_decode.new_budget):
    # the wall-clock deadline + byte cap span the whole scan, never re-armed —
    # re-arming per blob is what let many blobs blow the 15s auto_scan SIGKILL
    # into a silent zero.
    try:
        import scan_decode
        budget = scan_decode.host_budget()
    except Exception:
        budget = None

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = scan_file(file_path, rel_path, budget=budget)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
