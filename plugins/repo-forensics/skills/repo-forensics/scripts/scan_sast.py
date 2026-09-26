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

import ast
import os
import re
import sys
import ast

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import rule_loader

SCANNER_NAME = "sast"


def _filter_python_shell_docstring_examples(findings, source, ext):
    """A quoted historical shell call in a docstring is not executable code."""
    if ext != ".py" or not any(f.rule_id == "SA-PY-006" for f in findings):
        return findings
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return findings
    interior_lines = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", ())
        if not body or not isinstance(body[0], ast.Expr):
            continue
        value = body[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            interior_lines.update(range(body[0].lineno + 1, body[0].end_lineno))
    return [f for f in findings
            if not (f.rule_id == "SA-PY-006" and f.line in interior_lines)]

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
    ext = core.normalized_ext(file_path)
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
        line = core.clip_line(line)
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


# Extensions where a trailing backslash is a real line-continuation the
# interpreter honors, so a split token must be rejoined before matching. For
# every other language (JS/TS/JSON/...) a `\` at EOL is not a statement
# continuation, and joining there only mis-attributes a finding to a preceding
# `//`-comment line -- so those files are scanned physical-line-for-physical-
# line, exactly as before this pack existed.
_CONTINUATION_EXTS = frozenset({
    ".sh", ".bash", ".zsh", ".ksh", ".py", ".pyw", ".mk", "makefile",
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
})


def _trailing_backslash_count(s):
    n = 0
    for ch in reversed(s):
        if ch == "\\":
            n += 1
        else:
            break
    return n


def _logical_lines(lines, ext=None):
    r"""Join backslash-continued physical lines into logical lines for matching.

    A trailing (odd count of) backslash is a shell/Python/make/C line
    continuation that lets an attacker split a matched token across physical
    lines (`unshare \\\n-Urn sh`), dodging every per-line pattern. Joining
    restores the logical line the interpreter actually sees. Yields
    (start_index, text); start_index is the 0-based physical line where the
    yielded text begins so findings keep accurate line numbers.

    Two safety properties that prior revisions lacked:

    * The join is CAPPED at MAX_LINE_LENGTH. clip_line() truncates any line
      past that bound, so an unbounded join let an attacker pad a continued
      statement past 10k and push the real payload into the clipped tail --
      a FALSE NEGATIVE that plain physical-line scanning (main's behavior)
      never had. Once the running join reaches the cap we stop joining and
      yield the remaining physical lines of the group individually, so every
      physical line is still scanned. (Regression fix, PR #44 review.)
    * Joining only happens for languages where `\` at EOL is a real
      continuation (_CONTINUATION_EXTS). Elsewhere each physical line is
      yielded unchanged -- byte-for-byte the pre-pack behavior.

    A comment line never starts a continuation join (a trailing `\` in a
    comment is inert), and an EVEN number of trailing backslashes is a literal
    backslash, not a continuation.
    """
    n = len(lines)
    join_lang = (ext or "").lower() in _CONTINUATION_EXTS
    i = 0
    while i < n:
        start = i
        raw = lines[i]
        stripped = raw.rstrip("\r\n")
        if (not join_lang
                or stripped.lstrip().startswith("#")
                or _trailing_backslash_count(stripped) % 2 == 0
                or i + 1 >= n):
            yield start, raw
            i += 1
            continue
        # Accumulate a continuation group, bounded by MAX_LINE_LENGTH.
        parts = []
        joined_len = 0
        capped = False
        while (_trailing_backslash_count(stripped) % 2 == 1 and i + 1 < n):
            seg = stripped[:-1]
            if joined_len + len(seg) > core.MAX_LINE_LENGTH:
                capped = True
                break
            parts.append(seg)
            joined_len += len(seg)
            i += 1
            stripped = lines[i].rstrip("\r\n")
        if capped:
            # Cap hit: emit what we joined so far, then let the loop scan the
            # remaining physical lines of the group one by one, so a payload
            # past the 10k bound is never clipped out of every match.
            if parts:
                yield start, "".join(parts)
            continue
        parts.append(lines[i])
        yield start, "".join(parts)
        i += 1


_STRUCTURED_TLS_IDS = {"SA-PY-032", "SA-JS-040", "SA-TS-020", "SA-TSX-003"}
_NODE_TLS_RE = re.compile(
    r"\brejectUnauthorized\s*:\s*false\b|"
    r"[\"']rejectUnauthorized[\"']\s*:\s*false\b|"
    r"\b(?:[A-Za-z_$][\w$]*\.)+rejectUnauthorized\s*=\s*false\b|"
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']0[\"']",
    re.MULTILINE,
)


def _rule_finding(rule, rel_path, text, offset, snippet=None):
    line = text.count("\n", 0, offset) + 1
    if snippet is None:
        snippet = text.splitlines()[line - 1] if text.splitlines() else ""
    return core.Finding(
        scanner=SCANNER_NAME, severity=rule.severity,
        title=rule.title, description=f"Potential {rule.category} vulnerability",
        file=rel_path, line=line, snippet=snippet.strip()[:120],
        category=rule.category, rule_id=rule.id, confidence=rule.confidence,
        attacker=rule.attacker, boundary=rule.boundary, asset=rule.asset,
    )


def _qualified_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _scan_structured_tls(text, rel_path, ext, rules):
    """Parse TLS-disable forms that line regexes cannot safely model.

    Python calls use AST keyword analysis, so nested calls and multiline calls
    cannot hide verify=False. Node-family property forms use a whole-file regex
    because whitespace/newlines do not change their syntax.
    """
    by_id = {r.id: r for r in rules}
    findings = []
    if ext == ".py" and "SA-PY-032" in by_id:
        rule = by_id["SA-PY-032"]
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, TypeError):
            tree = None
        if tree is None:
            # Extracted archive/bytecode text and parity corpora may be
            # intentionally non-parseable. Preserve the old per-line fallback
            # there; valid Python always takes the AST path below.
            for match in rule.regex.finditer(text):
                findings.append(_rule_finding(rule, rel_path, text, match.start(), match.group(0)))
        else:
            http_methods = {"request", "get", "post", "put", "patch", "delete", "head", "options"}
            parents = {}
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    parents[child] = parent
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = _qualified_name(node.func)
                if name in {"ssl._create_unverified_context"}:
                    # Avoid double reporting: the surrounding assignment to
                    # verify_mode=ssl.CERT_NONE is the stronger same-line form.
                    parent = parents.get(node)
                    grand = parents.get(parent)
                    if not (isinstance(grand, ast.Assign) and
                            isinstance(grand.value, ast.Attribute) and
                            _qualified_name(grand.value) == "ssl.CERT_NONE"):
                        offset = sum(len(x) + 1 for x in text.splitlines()[:node.lineno - 1]) + node.col_offset
                        findings.append(_rule_finding(rule, rel_path, text, offset))
                    continue
                root, _, method = name.partition(".")
                if root not in {"requests", "httpx"} or method not in http_methods:
                    continue
                if any(kw.arg == "verify" and isinstance(kw.value, ast.Constant)
                       and kw.value.value is False for kw in node.keywords):
                    offset = sum(len(x) + 1 for x in text.splitlines()[:node.lineno - 1]) + node.col_offset
                    findings.append(_rule_finding(rule, rel_path, text, offset))
        for match in re.finditer(r"\bssl\.CERT_NONE\b", text):
            findings.append(_rule_finding(rule, rel_path, text, match.start()))
    elif ext in {".js", ".jsx", ".ts", ".tsx"}:
        rid = {".js": "SA-JS-040", ".jsx": "SA-JS-040", ".ts": "SA-TS-020", ".tsx": "SA-TSX-003"}[ext]
        rule = by_id.get(rid)
        if rule:
            for match in _NODE_TLS_RE.finditer(text):
                findings.append(_rule_finding(rule, rel_path, text, match.start(), match.group(0)))
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

    # Resolve through the SHARED gate. It normalizes the trailing
    # dot/space that Windows strips when executing (`evil.py ` / `evil.py.`
    # both run as evil.py but keyed as ".py " / "." here, missing every
    # allowlist and skipping the ENTIRE ruleset), and routes language variants
    # (.mjs/.cjs/.pyw/.phtml) to their family's rules instead of dropping them.
    ext = core.resolve_scan_ext(file_path, _PACK_EXTENSIONS)
    ext = {".bash": ".sh", ".zsh": ".sh", ".ksh": ".sh"}.get(ext, ext)
    if not ext:
        return []

    # rules_for_extension keeps the hot loop O(rules-for-ext) per line.
    rules = _PACK.rules_for_extension(ext)
    findings = []
    source = ""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            source = ''.join(lines)
            text = source
            for i, line in _logical_lines(lines, ext):
                line = core.clip_line(line)
                for rule in rules:
                    if rule.id in _STRUCTURED_TLS_IDS:
                        continue
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
                            attacker=rule.attacker,
                            boundary=rule.boundary,
                            asset=rule.asset,
                        ))
            findings.extend(_scan_structured_tls(text, rel_path, ext, rules))
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return _filter_python_shell_docstring_examples(findings, source, ext)


def scan_text(text, rel_path, ext=None):
    """SAST scan over an in-memory text blob — an extracted archive member or a
    disassembled .pyc listing — instead of a file on disk.

    Mirrors scan_file's per-rule emission exactly (rule.severity, rule.category,
    rule_id, confidence) so a finding surfaced from inside an archive is
    indistinguishable in shape from one surfaced from a plain source file. The
    KTD7 text shim the bytecode (U2) and archive (U3) scanners share for SAST,
    placed here rather than in forensics_core so the single _PACK source of
    truth is not forked. `ext` overrides the rule-selection extension (defaults
    to rel_path's extension); pass e.g. ".py" when scanning a bytecode listing.
    """
    global _pack_error_emitted
    if PACK_LOAD_ERROR:
        if not _pack_error_emitted:
            _pack_error_emitted = True
            return [_pack_load_finding(rel_path)]
        return []

    if ext is None:
        ext = core.resolve_scan_ext(rel_path, _PACK_EXTENSIONS)
    if ext not in _PACK_EXTENSIONS:
        return []

    rules = _PACK.rules_for_extension(ext)
    findings = []
    # split('\n') for parity with scan_file's readlines() (line numbers + no
    # Unicode-line-boundary split-evasion). _logical_lines applies the same
    # continuation joining as scan_file so in-memory text cannot smuggle a
    # split token past the per-line patterns either.
    for i, line in _logical_lines(text.split('\n'), ext):
        line = core.clip_line(line)
        for rule in rules:
            if rule.id in _STRUCTURED_TLS_IDS:
                continue
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
                    attacker=rule.attacker,
                    boundary=rule.boundary,
                    asset=rule.asset,
                ))
    findings.extend(_scan_structured_tls(text, rel_path, ext, rules))
    return _filter_python_shell_docstring_examples(findings, text, ext)


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
