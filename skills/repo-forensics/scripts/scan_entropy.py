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

# Base64 block pattern (50+ chars of base64 alphabet). Kept LOCAL because the
# visible ">=80 Base64 Encoded Block" display finding iterates these matches with
# per-line positioning + data-URI suppression. The full encoded-blob DETECTION
# that feeds scan_decode (base64/base85/base32/hex, incl. the CORRECTED base85
# charset) is the hoisted scan_decode.detect_encoded_blobs — single source of
# truth, used for routing below.
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')
# Long hex string pattern (display finding only; floor 64 to mirror prior FP gate).
HEX_PATTERN = re.compile(r'(?:0x)?[a-fA-F0-9]{64,}')
_SHA256SUM_LINE = re.compile(r'[a-fA-F0-9]{64} [ *]\S.*')
_SHA256SUM_NAMES = {'checksums.sha256', 'sha256sums'}


# A long run of letters and slashes is often a file path, which the base64
# alphabet happens to contain. Display-only: every blob is still decoded and
# rescanned by detect_encoded_blobs above, so a real payload is not hidden.
_PATH_SEGMENT = re.compile(r'(?:[a-z]+|(?:[A-Z][a-z]+)+|[a-z]+(?:[A-Z][a-z]+)+|[A-Z]{2,8})[0-9]{0,3}')


def _looks_like_path(run):
    if '+' in run or '=' in run:
        return False
    segments = run.strip('/').split('/')
    if len(segments) < 3 or any(not seg for seg in segments):
        return False
    if sum(len(seg) for seg in segments) < 3 * len(segments):
        return False
    return all(_PATH_SEGMENT.fullmatch(seg) for seg in segments)


def _is_sha256_manifest_hash(rel_path, line, match):
    """A standard checksum record is a digest, not an encoded payload claim."""
    return (os.path.basename(rel_path).lower() in _SHA256SUM_NAMES
            and match.start() == 0 and len(match.group(0)) == 64
            and _SHA256SUM_LINE.fullmatch(line) is not None)


# Pinned digests are best practice, not payloads: a container image digest
# (`image@sha256:<64 hex>`) and a pip hash pin (`--hash=sha256:<64 hex>`).
_PINNED_DIGEST_PREFIX = re.compile(r'(?:@|--hash=)sha256:$')


def _is_pinned_digest(line, match):
    """True when the hex run is exactly a sha256 digest right after an image
    `@sha256:` or a pip `--hash=sha256:` prefix."""
    return (len(match.group(0)) == 64
            and _PINNED_DIGEST_PREFIX.search(line, 0, match.start()) is not None)


_DIGEST_SIZES = (64, 128)      # sha256 / Ed25519 key, sha512 / Ed25519 signature
_DIGEST_NAME = re.compile(
    r'(?i)(?<![a-z])(?:sha(?:1|224|256|384|512)?|digests?|hash(?:es)?|checksums?'
    r'|fingerprints?|pub(?:lic)?[_-]?keys?|verify(?:ing)?[_-]?keys?|signatures?'
    r'|integrity|pinned)(?![a-z])')
# A file that turns hex back into bytes can be storing a payload in "digest"
# rows, so nothing in it is exempted as a digest. `.digest('hex')` and
# `.toString('hex')` produce hex rather than decode it, so they do not count.
_HEX_DECODER = re.compile(
    r'(?i)fromhex|unhexlify|a2b_hex|hex2bin|DecodeString|xxd\s+-r'
    r'|(?<!digest\()(?<!toString\()["\']hex["\']|\bpack\s*\(\s*["\']H')
# More named digests than this in one file is a table, not a pin: report them.
_MAX_NAMED_DIGESTS = 8
# Lockfiles whose integrity fields are skipped one field at a time (the older
# formats in core.LOCKFILES are skipped as whole files).
_FIELD_LOCKFILES = frozenset({'uv.lock', 'pdm.lock', 'bun.lock', 'deno.lock'})
_INTEGRITY_PREFIX = re.compile(r'(?i)(?:\bsha(?:1|256|384|512)[:-]|"integrity"\s*:\s*")$')
_URL_KEY_HEX_VALUE = re.compile(r'^"https?://[^"\s]+"\s*:\s*"[0-9a-fA-F]{64}",?$')


def _looks_random_digest(text):
    """A real digest or key is uniformly random: its hex spreads over the whole
    alphabet and it does not decode to readable text. Padding runs and hex
    encoded source code fail one test or the other."""
    if shannon_entropy(text.lower()) < 3.0:
        return False
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return True
    printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    return printable < 0.6 * len(raw)


_REGISTRY_HOSTS = ('pythonhosted.org', 'pypi.org', 'registry.npmjs.org',
                   'registry.yarnpkg.com', 'deno.land', 'jsr.io', 'codeload.github.com')
_URL_HOST = re.compile(r'https?://([A-Za-z0-9.-]{1,253})(?=[/:?#]|$)')


def _in_registry_url(stripped, start):
    """True when position `start` sits inside a whitespace/quote-delimited URL
    token on a package registry host (a download link's path, not a blob)."""
    token_start = max(stripped.rfind(c, 0, start) for c in ' \t"\'<>(),')
    host = _URL_HOST.match(stripped, token_start + 1)
    if host is None:
        return False
    name = host.group(1).lower()
    return any(name == h or name.endswith('.' + h) for h in _REGISTRY_HOSTS)


def _is_lockfile_integrity(basename, stripped, match, is_hex):
    """An integrity field of a modern lockfile: a hash after sha256:/sha512-,
    an "integrity" value, a deno.lock "<url>": "<sha256>" row, or a path
    segment inside a download URL. Low-entropy filler is never integrity."""
    if basename not in _FIELD_LOCKFILES:
        return False
    text = match.group(0)
    if is_hex and not _looks_random_digest(text[:128]):
        return False
    if _in_registry_url(stripped, match.start()):
        return True
    if _INTEGRITY_PREFIX.search(stripped, 0, match.start()):
        return True
    return (is_hex and basename == 'deno.lock' and len(text) == 64
            and _URL_KEY_HEX_VALUE.match(stripped) is not None)


def _is_named_digest(lines, index, stripped, match):
    """True when the hex run is exactly one digest or public-key sized quoted
    string and the assignment it belongs to names it as a hash or public key (EXPECTED_PUBLIC_KEY = "<64 hex>", sha256: '<64 hex>').
    The name is read from the text before the string, or from the previous line
    when the string sits alone inside a parenthesised assignment. The caller
    exempts it only when it also looks random, the file does not decode hex,
    and the file holds no more than _MAX_NAMED_DIGESTS such strings."""
    text = match.group(0)
    start, end = match.start(), match.end()
    if len(text) not in _DIGEST_SIZES or start == 0 or end >= len(stripped):
        return False
    quote = stripped[start - 1]
    if quote not in '"\'' or stripped[end] != quote:
        return False
    before = stripped[:start - 1]
    if not before.strip(' \t([{,'):
        prev = index - 1
        while prev >= 0 and not lines[prev].strip():
            prev -= 1
        if prev < 0 or index - prev > 2:
            return False
        before = lines[prev].strip()[-200:]
    return _DIGEST_NAME.search(before[-200:]) is not None


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


def scan_file(file_path, rel_path, threshold=5.8, budget=None):
    """Scan for high-entropy strings with per-string distribution (TruffleHog v3 approach).
    Threshold raised to 5.8 to reduce false positives on cryptographic constants.
    Combo detection: HIGH if entropy > 5.8 AND matches known secret format.

    `budget`: optional shared scan_decode budget (see main()). When None a fresh
    per-file budget is minted (still correct for a single-file caller / tests),
    but main() threads ONE budget across every file so the decode deadline + byte
    cap are shared, never re-armed."""
    findings = []
    try:
        import scan_decode
    except Exception:
        scan_decode = None
    if budget is None and scan_decode is not None:
        budget = scan_decode.host_budget()

    # Skip minified files
    if is_minified(file_path):
        return findings

    # Skip lockfiles
    basename = os.path.basename(file_path)
    if basename in core.LOCKFILES:
        return findings

    # Track blobs already handed to scan_decode (per file) so a blob repeated
    # across lines is decoded only once (dedup).
    decoded_seen = set()

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        # Decode-and-rescan routing (additive; Gap 4(a) / torture H1). The full
        # encoded-blob DETECTION (base64/base85/base32/hex, with the CORRECTED
        # base85 charset and ONE reconciled floor) is the hoisted helper — so a
        # real base85 payload using v-z/{|}~ is now matched whole and routed,
        # instead of being split into sub-floor fragments and dropped.
        if scan_decode is not None:
            blobs = scan_decode.detect_encoded_blobs("\n".join(lines))
            scan_decode.feed_blobs(blobs, rel_path, decoded_seen, findings, budget)

        decodes_hex = _HEX_DECODER.search("".join(lines)) is not None
        named_digests = []
        named_shapes = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if len(stripped) < 50:
                continue

            # Visible "Base64 Encoded Block" DISPLAY finding (>=80 chars). The
            # actual decode routing for EVERY encoded blob (base64/85/32/hex,
            # incl. sub-80 payloads) happens once-per-file above via the hoisted
            # detect_encoded_blobs, so a short os.system(...) one base64 layer
            # deep is still routed even though it never trips this display gate.
            for m in BASE64_PATTERN.finditer(stripped):
                matched = m.group(0)
                # Skip data-URI payloads (e.g. CSS url("data:image/png;base64,...")
                # or HTML/SVG src="data:..."). Standard web practice for inline
                # assets; a base64 image in a data URI cannot self-execute, so
                # flagging it is a false positive (benign-corpus styles.css).
                prefix = stripped[:m.start()]
                if 'data:' in prefix and prefix.rstrip().endswith(';base64,'):
                    continue
                if _is_lockfile_integrity(basename, stripped, m, False):
                    continue
                if _looks_like_path(matched):
                    continue
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

            # Check for long hex strings (display finding; decode routing is the
            # once-per-file detect_encoded_blobs pass above).
            for m in HEX_PATTERN.finditer(stripped):
                if (_is_sha256_manifest_hash(rel_path, stripped, m)
                        or _is_pinned_digest(stripped, m)
                        or _is_lockfile_integrity(basename, stripped, m, True)):
                    continue
                matched = m.group(0)
                hex_finding = core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Long Hex String",
                    description=f"Long hex string ({len(matched)} chars) may be encoded data or a packed payload",
                    file=rel_path, line=i+1,
                    snippet=matched[:120],
                    category="encoding"
                )
                if _is_named_digest(lines, i, stripped, m):
                    named_shapes += 1
                    if not decodes_hex and _looks_random_digest(matched):
                        named_digests.append(hex_finding)
                        continue
                findings.append(hex_finding)
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

        # A handful of named digests is a set of pins; more is a table that
        # could be a payload cut into digest-sized rows, so report them all.
        if named_shapes > _MAX_NAMED_DIGESTS:
            findings.extend(named_digests)
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Entropy & Encoding Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning {repo_path} for entropy anomalies...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    # Mint ONE shared decode budget for the whole scan and thread it into every
    # file, so the scan_decode wall-clock deadline AND cumulative byte cap span
    # all blobs across all files instead of being re-armed per call (re-arming is
    # what let N blobs blow the 15s auto_scan SIGKILL into a silent zero).
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
