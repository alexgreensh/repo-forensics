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
            if len(line) > core.MAX_LINE_LENGTH:
                continue

            for rule in _RULES:
                match = rule.regex.search(line)
                if match:
                    snippet = match.group(0)
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."

                    findings.append(core.Finding(
                        scanner=SCANNER_NAME,
                        severity=rule.severity,
                        title=rule.title,
                        description="Potential hardcoded secret detected",
                        file=rel_path,
                        line=i + 1,
                        snippet=snippet,
                        category="secret",
                        rule_id=rule.id,
                        confidence=rule.confidence,
                        attacker=rule.attacker,
                        boundary=rule.boundary,
                        asset=rule.asset,
                    ))
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
        if len(line) > core.MAX_LINE_LENGTH:
            continue
        for rule in _RULES:
            match = rule.regex.search(line)
            if match:
                snippet = match.group(0)
                if len(snippet) > 80:
                    snippet = snippet[:77] + "..."
                findings.append(core.Finding(
                    scanner=SCANNER_NAME,
                    severity=rule.severity,
                    title=rule.title,
                    description="Potential hardcoded secret detected",
                    file=rel_path,
                    line=i + 1,
                    snippet=snippet,
                    category="secret",
                    rule_id=rule.id,
                    confidence=rule.confidence,
                    attacker=rule.attacker,
                    boundary=rule.boundary,
                    asset=rule.asset,
                ))
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
