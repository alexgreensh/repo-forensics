#!/usr/bin/env python3
"""
scan_entropy.py - Entropy & Encoding Scanner (v2)
Detects high-entropy strings (obfuscated code, packed payloads),
base64 blocks, and long hex strings. Excludes minified JS and lockfiles.

Created by Alex Greenshpun
"""

import os
import math
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "entropy"

# Base64 block pattern (50+ chars of base64 alphabet)
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')
# Long hex string pattern
HEX_PATTERN = re.compile(r'(?:0x)?[a-fA-F0-9]{64,}')


def shannon_entropy(data):
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_minified(file_path):
    """Detect minified JS/CSS files to reduce false positives."""
    basename = os.path.basename(file_path).lower()
    if '.min.' in basename:
        return True
    if basename in ('bundle.js', 'vendor.js', 'chunk.js'):
        return True
    return False


# Known secret format patterns for combo detection (entropy + format = HIGH)
# If entropy is high AND line matches one of these, confidence is much higher.
SECRET_FORMAT_PATTERNS = [
    re.compile(r'(?i)(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}'),  # AWS key ID
    re.compile(r'(?i)sk-[a-zA-Z0-9]{20,}'),                 # OpenAI/Anthropic API key prefix
    re.compile(r'(?i)ghp_[a-zA-Z0-9]{36}'),                 # GitHub PAT
    re.compile(r'(?i)gho_[a-zA-Z0-9]{36}'),                 # GitHub OAuth token
    re.compile(r'(?i)npm_[a-zA-Z0-9]{36}'),                 # NPM token
    re.compile(r'(?i)(xox[baprs]-[0-9a-zA-Z-]{10,})'),      # Slack token
    re.compile(r'(?i)(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'),  # JWT
    re.compile(r'(?i)[a-zA-Z0-9]{32,}@[a-zA-Z0-9.]+\.[a-z]{2,}'),  # email-shaped credential
]


def scan_file(file_path, rel_path, threshold=5.8):
    """Scan for high-entropy strings with per-string distribution (TruffleHog v3 approach).
    Threshold raised to 5.8 to reduce false positives on cryptographic constants.
    Combo detection: HIGH if entropy > 5.8 AND matches known secret format.
    """
    findings = []

    # Skip minified files
    if is_minified(file_path):
        return findings

    # Skip lockfiles
    basename = os.path.basename(file_path)
    if basename in core.LOCKFILES:
        return findings

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            stripped = line.strip()
            if len(stripped) < 50:
                continue

            # Check for base64 blocks
            for m in BASE64_PATTERN.finditer(stripped):
                matched = m.group(0)
                if len(matched) >= 80:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title="Base64 Encoded Block",
                        description=f"Large base64-encoded string ({len(matched)} chars) may hide payloads",
                        file=rel_path, line=i+1,
                        snippet=matched[:120],
                        category="encoding"
                    ))
                    break  # One finding per line

            # Check for long hex strings
            for m in HEX_PATTERN.finditer(stripped):
                matched = m.group(0)
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Long Hex String",
                    description=f"Long hex string ({len(matched)} chars) may be shellcode or encoded data",
                    file=rel_path, line=i+1,
                    snippet=matched[:120],
                    category="encoding"
                ))
                break

            # Shannon entropy check (per-string distribution, threshold 5.8)
            ent = shannon_entropy(stripped)
            if ent > threshold:
                # Don't duplicate if already caught by base64/hex patterns
                already_found = any(f.line == i+1 for f in findings)
                if not already_found:
                    # Combo detection: HIGH if matches known secret format, MEDIUM otherwise
                    matches_secret_format = any(p.search(stripped) for p in SECRET_FORMAT_PATTERNS)
                    severity = "high" if matches_secret_format else "medium"
                    title = "High-Confidence Secret" if matches_secret_format else "High Entropy Line"
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity=severity,
                        title=title,
                        description=f"Shannon entropy {ent:.2f} bits/char" + (" + known secret format match" if matches_secret_format else ""),
                        file=rel_path, line=i+1,
                        snippet=stripped[:120],
                        category="obfuscation"
                    ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Entropy & Encoding Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning {repo_path} for entropy anomalies...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
