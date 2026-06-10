#!/usr/bin/env python3
"""
scan_sast.py - Static Application Security Testing (rules-as-data)

Identifies dangerous functions, injection patterns, and code vulnerabilities.
As of v2.10 the per-language detection patterns live in a JSON rule pack
(data/rulepacks/sast.json), loaded at module import via rule_loader and indexed
by file extension so the hot loop stays O(rules-for-ext). The pack is the
single source of truth; there is no hardcoded fallback table. If the pack
cannot be loaded (a corrupted or tampered install), the scanner emits one loud
diagnostic finding and scans no patterns. tests/ is deliberately NOT excluded
from the walk (attackers hide malware there per Snyk research).

The CSS-steganography pass and the MAX_LINE_LENGTH / binary skips are scanning
context machinery, not pattern tables, so they stay in code.

Created by Alex Greenshpun
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import rule_loader

SCANNER_NAME = "sast"

# Per-language detection rules load from the shipped pack at import time
# (rule_loader memoizes -> parsed once per process). by_extension is the
# pre-built index; rules_for_extension(ext) returns the rules gated to `ext`
# plus any extension-agnostic rules, preserving the original O(rules-for-ext)
# per-line cost. load_pack returns None only for a missing/incompatible pack
# (corrupted/tampered install), surfaced as PACK_LOAD_ERROR below.
_PACK = rule_loader.load_pack(SCANNER_NAME)
PACK_LOAD_ERROR = _PACK is None
# Extensions the pack actually covers (used to short-circuit non-target files,
# matching the old `if ext not in SAST_PATTERNS` guard).
_PACK_EXTENSIONS = (
    {e for e in _PACK.by_extension if e} if _PACK is not None else set()
)

# B6 fix: emit the pack-load-failure diagnostic exactly ONCE per scanner run,
# not once per scanned file (which could flood a large repo with thousands of
# duplicate criticals and cause OOM in the aggregator).
_pack_error_emitted = False


def _pack_load_finding(rel_path):
    """The single loud diagnostic emitted when the SAST rule pack failed to
    load. Critical so it cannot be missed; the operator is told to reinstall.
    We deliberately do NOT fall back to a hardcoded copy of the patterns."""
    return core.Finding(
        scanner=SCANNER_NAME, severity="critical",
        title="SAST rule pack failed to load",
        description=("data/rulepacks/sast.json is missing or "
                     "schema-incompatible; SAST scanning is disabled. "
                     "Reinstall repo-forensics to restore detection."),
        file=rel_path, line=0,
        snippet="rule pack failed to load",
        category="scanner-integrity",
    )


CSS_STEG_PATTERNS = [
    (re.compile(r'display:\s*none', re.IGNORECASE), "CSS hiding: display:none"),
    (re.compile(r'visibility:\s*hidden', re.IGNORECASE), "CSS hiding: visibility:hidden"),
    (re.compile(r'opacity:\s*0(?:\s*[;},!]|\s*$)', re.IGNORECASE), "CSS hiding: opacity:0"),
    (re.compile(r'font-size:\s*0', re.IGNORECASE), "CSS hiding: zero-size text"),
    (re.compile(r'position:\s*absolute.*left:\s*-\d{4,}', re.IGNORECASE), "CSS hiding: positioned off-screen"),
    (re.compile(r'clip:\s*rect\(0', re.IGNORECASE), "CSS hiding: clipped to zero area"),
    (re.compile(r'text-indent:\s*-\d{4,}', re.IGNORECASE), "CSS hiding: text pushed off-screen"),
    (re.compile(r'overflow:\s*hidden[^;]*height:\s*0', re.IGNORECASE), "CSS hiding: zero-height container"),
    (re.compile(r'color:\s*(?:white|#fff(?:fff)?|rgba?\([^)]*,\s*0\s*\))', re.IGNORECASE), "CSS hiding: text matching background"),
]

CSS_STEG_EXTENSIONS = {'.html', '.htm', '.svg', '.jsx', '.tsx', '.vue', '.md'}

def scan_css_steganography(file_path, rel_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in CSS_STEG_EXTENSIONS:
        return []
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return []
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if len(line) > core.MAX_LINE_LENGTH:
            continue
        for pat, title in CSS_STEG_PATTERNS:
            if pat.search(line):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title=title,
                    description="Visual hiding technique that could conceal instructions from human reviewers (DeepMind AI Agent Traps, March 2026).",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="css-steganography"
                ))
                break
    return findings


def scan_file(file_path, rel_path):
    global _pack_error_emitted

    if PACK_LOAD_ERROR:
        # B6: emit the diagnostic only on the first call; subsequent files get
        # an empty list so the aggregator is not flooded with duplicates.
        if not _pack_error_emitted:
            _pack_error_emitted = True
            return [_pack_load_finding(rel_path)]
        return []

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in _PACK_EXTENSIONS:
        return []

    # rules_for_extension keeps the hot loop O(rules-for-ext) per line.
    rules = _PACK.rules_for_extension(ext)
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                if len(line) > core.MAX_LINE_LENGTH:
                    continue
                for rule in rules:
                    if rule.regex.search(line):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME,
                            severity=rule.severity,
                            title=rule.title,
                            description=f"Potential {rule.category} vulnerability",
                            file=rel_path,
                            line=i + 1,
                            snippet=line.strip()[:120],
                            category=rule.category,
                            rule_id=rule.id,
                            confidence=rule.confidence,
                        ))
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def main():
    args = core.parse_common_args(sys.argv, "SAST Vulnerability Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Starting SAST scan on {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    if ignore_patterns:
        core.emit_status(args.format, f"[*] Loaded {len(ignore_patterns)} custom ignore patterns from .forensicsignore")

    all_findings = []

    # Use custom skip_dirs to NOT exclude tests/
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)
        all_findings.extend(scan_css_steganography(file_path, rel_path))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
