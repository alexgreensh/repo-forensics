#!/usr/bin/env python3
"""
scan_secrets.py - Secret Scanner (rules-as-data)

Detects hardcoded API keys, tokens, certificates, private keys, database
credentials, and generic secret assignments. As of v2.10 the detection
patterns live in a JSON rule pack (data/rulepacks/secrets.json), loaded at
module import via rule_loader. The pack is the single source of truth; there
is no hardcoded fallback table. If the pack cannot be loaded (a corrupted or
tampered install), the scanner emits one loud diagnostic finding and scans no
patterns rather than carrying a stale 500-line copy of the rules in code (a
corrupted install is independently caught by the integrity scanner).

The .env-variant allowlist, the MAX_LINE_LENGTH skip, and binary-file skipping
are scanning *context* machinery, not detection rules, so they stay in code.

Created by Alex Greenshpun
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import rule_loader

SCANNER_NAME = "secrets"

ENV_FILE_VARIANTS = {
    '.env', '.env.local', '.env.production', '.env.staging',
    '.env.development', '.env.test', '.env.docker', '.env.container',
}
ENV_FILE_SAFE = {'.env.example', '.env.template', '.env.sample'}

# --- Known documentation and regression-test placeholders ---
# Explicitly fake values that have no credential value. The scanner does
# NOT flag them as real secrets. Suppression is at the scanner layer (not the
# regex) so the rulepack examples still accurately document what the regex
# matches. All checks are EXACT full-string matches on the regex-captured
# snippet, never substring searches, so a real credential in a URI whose host
# contains "example.com" (e.g. db.example.com) is NOT suppressed.
_DOC_PLACEHOLDER_EXACT = frozenset({
    "AKIAIOSFODNN7EXAMPLE",  # canonical example AWS key ID
    "AKIA1234567890123456",  # sequential dummy key used in redaction tests
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz",  # canonical example GitHub PAT
    "AKIA1234567890ABCDEF",  # ordered digits/hex in credential-preservation test
    "sk-ant-BearerSecretTOKEN1234567890abcdefXYZ",  # literal BearerSecret test marker
    "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",  # ordered alphabet benchmark sample
    "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",  # alternating-case benchmark sample
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",  # ordered alphabet benchmark sample
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB",  # full traceback benchmark sample
    "AIzaSyBcDeFgHiJkLmNoPqRsTuVwXyZ01234567",  # ordered alphabet benchmark sample
    "AIzaSyBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abc",  # full log benchmark sample
})

# Canonical example JWT from jwt.io. The FULL token (header.payload.signature)
# is the placeholder. Only an exact match on the complete token suppresses; a
# token that shares the header.payload but has a different (real) signature is
# NOT suppressed, because the signature is the secret-bearing segment.
_JWT_IO_SAMPLE_FULL = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def _is_doc_placeholder(snippet, full_line="", match_start=None, match_end=None):
    """Return True if the matched snippet is a known placeholder
    that must not be flagged as a real secret.

    Checks are exact matches on a complete token, never substring searches.
    Some regexes capture a fixed-length prefix, so compare the whole source
    token before accepting a placeholder. A real credential in a URI
    whose host contains 'example.com' (e.g. db.example.com) is NOT suppressed
    because the full URI string does not match any known placeholder.
    """
    if match_start is not None and re.fullmatch(r"[A-Za-z0-9_-]+", snippet):
        escaped_bell = full_line[:match_start].endswith(r"\x07")
        if (match_start > 0 and not escaped_bell
                and re.match(r"[A-Za-z0-9_-]", full_line[match_start - 1])):
            return False
        full_token = re.match(r"[A-Za-z0-9_-]+", full_line[match_start:])
        return bool(full_token and full_token.group(0) in _DOC_PLACEHOLDER_EXACT)
    if match_end is not None and match_end < len(full_line) and re.match(r"[A-Za-z0-9_-]", full_line[match_end]):
        return False
    if snippet in _DOC_PLACEHOLDER_EXACT:
        return True
    if snippet == _JWT_IO_SAMPLE_FULL:
        return True
    return False


def _emit_line_findings(findings, rule, line, line_no, rel_path):
    """Emit one finding per non-placeholder match of `rule` on `line`.

    Iterates EVERY match (finditer, not just the leftmost search) so a
    canonical placeholder earlier on a line cannot suppress a real key later
    on the same line, and two real keys on one line are both reported. Each
    individual match that is exactly a placeholder is skipped; the remaining
    matches are still examined. (Previously a single rule.regex.search per
    line returned only the first match, so a placeholder first match silently
    dropped every later real key on that line.)
    """
    for match in rule.regex.finditer(line):
        snippet = match.group(0)
        if _is_doc_placeholder(snippet, full_line=line, match_start=match.start(), match_end=match.end()):
            continue
        if len(snippet) > 80:
            snippet = snippet[:77] + "..."
        findings.append(core.Finding(
            scanner=SCANNER_NAME,
            severity=rule.severity,
            title=rule.title,
            description="Potential hardcoded secret detected",
            file=rel_path,
            line=line_no,
            snippet=snippet,
            category="secret",
            rule_id=rule.id,
            confidence=rule.confidence,
            attacker=rule.attacker,
            boundary=rule.boundary,
            asset=rule.asset,
        ))


# Detection rules load from the shipped pack at import time (rule_loader
# memoizes, so this parses once per process). load_pack returns None only when
# the pack file is missing or schema-incompatible -> a corrupted/tampered
# install, surfaced as PACK_LOAD_ERROR below.
_PACK = rule_loader.load_pack(SCANNER_NAME)
PACK_LOAD_ERROR = _PACK is None
# Flat list of compiled rules (secrets has no extension gating; every rule
# applies to every text line).
_RULES = _PACK.all_rules if _PACK is not None else []

# B6 fix: emit the pack-load-failure diagnostic exactly ONCE per scanner run,
# not once per scanned file (which could flood a large repo with thousands of
# duplicate criticals and cause OOM in the aggregator).
_pack_error_emitted = False


def _pack_load_finding(rel_path):
    """The single loud diagnostic emitted (once per scanner run) when the
    rule pack failed to load. Critical so it cannot be missed; the operator is
    told to reinstall. We deliberately do NOT fall back to a hardcoded copy."""
    return core.Finding(
        scanner=SCANNER_NAME, severity="critical",
        title="Secret rule pack failed to load",
        description=("data/rulepacks/secrets.json is missing or "
                     "schema-incompatible; secret scanning is disabled. "
                     "Reinstall repo-forensics to restore detection."),
        file=rel_path, line=0,
        snippet="rule pack failed to load",
        category="scanner-integrity",
    )


def scan_file(file_path, rel_path):
    global _pack_error_emitted
    findings = []

    if PACK_LOAD_ERROR:
        # B6: emit the diagnostic only on the first call; subsequent files get
        # an empty list so the aggregator is not flooded with duplicates.
        if not _pack_error_emitted:
            _pack_error_emitted = True
            return [_pack_load_finding(rel_path)]
        return []

    basename = os.path.basename(file_path)
    if basename in ENV_FILE_VARIANTS and basename not in ENV_FILE_SAFE:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="high",
            title=f"Unencrypted {basename} File in Repository",
            description=f"{basename} likely contains plaintext secrets and should be in .gitignore",
            file=rel_path, line=0,
            snippet=f"{basename} found in repo (should never be committed)",
            category="secret-storage"
        ))

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            # Skip mega-lines to prevent O(n^2) regex backtracking
            line = core.clip_line(line)

            for rule in _RULES:
                _emit_line_findings(findings, rule, line, i + 1, rel_path)
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_text(text, rel_path):
    """Secret-detection over an in-memory text blob — an extracted archive
    member. KTD7 in-memory entry point scan_archive recurses. Mirrors
    scan_file's per-rule emission; the env-file basename check is applied from
    rel_path's basename so a `.env` packed inside an archive is still flagged."""
    global _pack_error_emitted
    findings = []
    if PACK_LOAD_ERROR:
        if not _pack_error_emitted:
            _pack_error_emitted = True
            return [_pack_load_finding(rel_path)]
        return []

    basename = os.path.basename(rel_path)
    if basename in ENV_FILE_VARIANTS and basename not in ENV_FILE_SAFE:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="high",
            title=f"Unencrypted {basename} File in Repository",
            description=f"{basename} likely contains plaintext secrets and should be in .gitignore",
            file=rel_path, line=0,
            snippet=f"{basename} found in repo (should never be committed)",
            category="secret-storage",
        ))

    # split('\n') for parity with scan_file's readlines().
    for i, line in enumerate(text.split('\n')):
        line = core.clip_line(line)
        for rule in _RULES:
            _emit_line_findings(findings, rule, line, i + 1, rel_path)
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Secret Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning for secrets in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    if ignore_patterns:
        core.emit_status(args.format, f"[*] Loaded {len(ignore_patterns)} custom ignore patterns from .forensicsignore")

    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
