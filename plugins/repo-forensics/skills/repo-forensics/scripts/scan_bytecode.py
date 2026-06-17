#!/usr/bin/env python3
"""
scan_bytecode.py - Python .pyc Bytecode Scanner

Closes the precompiled-bytecode blind spot from the 2026-06 CSA / Trail of Bits
audit: .pyc is binary-skipped and __pycache__ is ignored, so compiled Python
bytecode is never inspected — malicious logic compiled to bytecode is invisible
to every source-only scanner.

This scanner reaches .pyc (including inside __pycache__) via
core.walk_aux(reach_pycache=True), and for each one:
  - identifies it by magic and derives the header length from the magic
    (16 bytes for 3.7+ per PEP 552, 12 for 3.3-3.6, 8 for older),
  - unmarshals + disassembles it in an ISOLATED SUBPROCESS (_pyc_unmarshal.py)
    so hostile bytecode that crashes the interpreter at the C level can only
    kill the child, never this scan (KTD6 user-safety),
  - runs the shared SAST + trifecta patterns over the disassembly text
    (opcodes + co_names + string co_consts) -> `bytecode-hidden-logic`,
  - flags orphan .pyc (no sibling .py) but only ELEVATES it when a primitive
    also matched; bare orphan bytecode under a vendor root is normal (stripped
    wheels / Cython) and suppressed to avoid a false-positive cannon,
  - degrades gracefully: a crash/timeout/mismatched-version .pyc yields one
    `unanalyzable bytecode` note, never a raised exception or a dead scan.

Created by Alex Greenshpun
"""

import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "bytecode"

_UNMARSHAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_pyc_unmarshal.py")

PYC_EXTENSIONS = {".pyc", ".pyo"}
MAX_PYC_BYTES = 5 * 1024 * 1024     # skip absurdly large .pyc (bounds child memory)
PER_FILE_TIMEOUT_SEC = 5            # per-.pyc subprocess wall-clock (<< pipeline budget)
TOTAL_BUDGET_SEC = 60              # whole-scanner wall-clock budget (fail-loud past it)
# Honest count cap: at ~32 ms per .pyc (subprocess startup + marshal + dis) the
# 60s wall-clock budget binds first at ~1,800 files, so the count cap matches it
# rather than implying 5,000 are ever reachable within the budget.
MAX_PYC = 1800                      # cap on number of .pyc processed

# Directory components that legitimately ship loose .pyc without source.
_VENDOR_MARKERS = {"site-packages", "dist-packages", "_vendor", "vendored", "vendor"}

# Bytecode-native primitive detection. The disassembly blob holds co_names,
# string co_consts, and IMPORT_NAME targets on separate lines — the dotted
# source form `os.system(` never appears literally, so the source regexes alone
# miss the call primitives. We detect them by CO-OCCURRENCE (a dangerous module
# imported AND a dangerous call name referenced), which keeps false positives
# low enough for R9: a module that merely `import os` and calls os.path.join
# will not have `system` among its names.
_EXEC_OS_NAMES = {"system", "popen", "execv", "execve", "execvp", "execvpe",
                  "spawnv", "spawnl", "spawnlp", "spawnvp", "posix_spawn"}
_EXEC_SUBPROC_NAMES = {"Popen", "run", "call", "check_output", "check_call",
                       "getoutput", "getstatusoutput"}
_EXEC_BUILTIN_NAMES = {"eval", "exec", "compile"}
_NET_MODULES = {"socket", "urllib", "http", "requests", "httplib", "ftplib",
                "urllib2", "httpx", "aiohttp"}
_NET_NAMES = {"urlopen", "Request", "HTTPSConnection", "HTTPConnection",
              "create_connection", "connect", "post", "put", "request",
              "urlretrieve", "sendto"}
_URL_MARKERS = ("http://", "https://", "/dev/tcp/")
_CRED_CONST_MARKERS = (".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_dsa",
                       ".ssh/id_ecdsa", ".aws/credentials", ".aws/config",
                       ".netrc", "/etc/shadow")
_CRED_NAME_MARKERS = {"GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN",
                      "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID"}


def _parse_blob(blob):
    names, consts, imported = set(), [], set()
    for line in blob.split("\n"):
        if line.startswith("NAME "):
            names.add(line[5:])
        elif line.startswith("CONST "):
            consts.append(line[6:])
        elif line.startswith("OP IMPORT_NAME "):
            imported.add(line[len("OP IMPORT_NAME "):])
    return names, consts, imported


def _native_primitives(blob, rel_path):
    """Detect exec / network / credential primitives directly from the
    disassembly (names + imports co-occurrence, plus literal markers in string
    constants). Returns Findings tagged with the primitive category."""
    names, consts, imported = _parse_blob(blob)
    consts_text = "\n".join(consts)
    findings = []

    def add(severity, title, desc, category):
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity=severity, title=title,
            description=desc, file=rel_path, line=0, snippet="", category=category,
        ))

    exec_hit = (
        ("os" in imported and (names & _EXEC_OS_NAMES))
        or ("subprocess" in imported and (names & _EXEC_SUBPROC_NAMES))
        or (len(names & _EXEC_BUILTIN_NAMES) >= 2)
    )
    if exec_hit:
        add("high", "Code execution primitive",
            "Bytecode references a process-execution primitive (os.system/"
            "subprocess/exec) reconstructed from co_names + imports.",
            "code-execution")

    net_hit = (
        ((imported & _NET_MODULES) and (names & _NET_NAMES))
        or any(m in consts_text for m in _URL_MARKERS)
    )
    if net_hit:
        add("high", "Outbound network primitive",
            "Bytecode references an outbound-network primitive or embeds a "
            "URL / reverse-shell target in its string constants.",
            "exfiltration")

    cred_hit = (
        any(m in consts_text for m in _CRED_CONST_MARKERS)
        or (names & _CRED_NAME_MARKERS)
    )
    if cred_hit:
        add("high", "Credential read primitive",
            "Bytecode embeds a credential path (.ssh/id_*, .aws/credentials, "
            ".netrc) or token env-var name in its string constants / names.",
            "credential-read")

    return findings


def pyc_header_len(magic4):
    """Header length (bytes before the marshalled code object) from the 4-byte
    .pyc magic, or None if it is not a recognizable pyc magic.

    A pyc magic is a 2-byte little-endian version number followed by b'\\r\\n'.
    PEP 552 (3.7+) made the header 16 bytes; 3.3-3.6 = 12; older = 8."""
    if len(magic4) < 4 or magic4[2:4] != b"\r\n":
        return None
    n = magic4[0] | (magic4[1] << 8)
    if n >= 3390:      # 3.7+ (PEP 552)
        return 16
    if n >= 3000:      # 3.3 - 3.6
        return 12
    if n >= 2000:      # <= 3.2
        return 8
    return None


def _sibling_py(pyc_path):
    """The .py source path a .pyc would have been compiled from.

    Strips the cache tag (`.cpython-NN[.opt-N]`) rather than splitting on the
    first dot, so a source module whose name legitimately contains dots
    (`my.helper.py` -> `__pycache__/my.helper.cpython-314.pyc`) resolves to
    `my.helper.py`, not `my.py` (which would be a false orphan)."""
    d, fn = os.path.split(pyc_path)
    # Drop the cpython/pypy cache tag and everything after it, else just the ext.
    base = re.sub(r"\.(?:cpython|pypy)-\d+.*$", "", fn)
    if base == fn:  # plain mod.pyc / mod.pyo (no cache tag)
        base = re.sub(r"\.py[co]$", "", fn)
    if os.path.basename(d) == "__pycache__":
        src_dir = os.path.dirname(d)
    else:
        src_dir = d
    return os.path.join(src_dir, base + ".py")


def _is_vendored(rel_path):
    parts = set(rel_path.replace("\\", "/").split("/"))
    return bool(parts & _VENDOR_MARKERS)


def _unanalyzable(rel_path, reason):
    return core.Finding(
        scanner=SCANNER_NAME, severity="low",
        title="Unanalyzable bytecode",
        description=f"Could not analyze .pyc ({reason}). Bytecode left uninspected.",
        file=rel_path, line=0, snippet=reason, category="unanalyzable-bytecode",
    )


def _disassemble(pyc_path, header_len):
    """Run the isolated unmarshal+dis child. Returns (blob, error_reason).
    Exactly one of the two is truthy."""
    try:
        proc = subprocess.run(
            [sys.executable, _UNMARSHAL, pyc_path, str(header_len)],
            capture_output=True, timeout=PER_FILE_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return None, "disassembly timed out"
    except OSError as exc:
        return None, f"subprocess failed: {exc}"
    if proc.returncode != 0:
        # Negative returncode == killed by signal (the C-level crash we isolate).
        if proc.returncode < 0:
            return None, f"interpreter crash unmarshalling bytecode (signal {-proc.returncode})"
        return None, "could not unmarshal bytecode (corrupt or cross-version)"
    # surrogatepass matches the child's encoding so a lone-surrogate constant
    # round-trips instead of being mangled.
    return proc.stdout.decode("utf-8", "surrogatepass"), None


def scan_pyc(pyc_path, rel_path):
    """Analyze one .pyc. Returns a list of Findings."""
    findings = []
    try:
        size = os.path.getsize(pyc_path)
        with open(pyc_path, "rb") as f:
            magic4 = f.read(4)
    except OSError:
        return findings

    header_len = pyc_header_len(magic4)
    if header_len is None:
        findings.append(_unanalyzable(rel_path, "unrecognized .pyc magic"))
        return findings
    if size > MAX_PYC_BYTES:
        findings.append(_unanalyzable(rel_path, f"file too large ({size} bytes)"))
        return findings

    blob, error = _disassemble(pyc_path, header_len)
    if error is not None:
        findings.append(_unanalyzable(rel_path, error))
        return findings

    # Detect primitives: bytecode-native co-occurrence (catches os.system /
    # subprocess call forms that never appear dotted in the blob) PLUS the
    # shared trifecta over the string constants only (catches literal-source
    # payloads, shell pipes, urls, and credential paths embedded as consts).
    # Dedup by category so the two paths do not double-count.
    _, consts, _ = _parse_blob(blob)
    raw_hits = _native_primitives(blob, rel_path)
    raw_hits.extend(core.scan_text_trifecta("\n".join(consts), rel_path))
    hits = []
    _seen_cat = set()
    for h in raw_hits:
        if h.category in _seen_cat:
            continue
        _seen_cat.add(h.category)
        hits.append(h)

    matched_primitive = len(hits) > 0
    for h in hits:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity=h.severity,
            title=f"Hidden logic in bytecode: {h.title}",
            description=(
                "Pattern matched inside compiled .pyc bytecode (invisible to "
                "source-only scanners). " + h.description
            ),
            file=rel_path, line=0, snippet=h.snippet,
            category="bytecode-hidden-logic",
            rule_id=getattr(h, "rule_id", "") or "",
        ))

    # Orphan handling: a .pyc with no sibling .py. Only meaningful as a signal
    # when a primitive also matched OR when it is NOT in a vendor root (stripped
    # wheels and Cython builds ship loose .pyc legitimately).
    if not os.path.exists(_sibling_py(pyc_path)):
        if matched_primitive:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Orphan bytecode with hidden logic",
                description=(
                    "A .pyc shipped without its .py source AND containing a "
                    "matched dangerous primitive — bytecode-only delivery of "
                    "code that evades source review."
                ),
                file=rel_path, line=0, snippet="no sibling .py", category="orphan-bytecode",
            ))
        elif not _is_vendored(rel_path):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="low",
                title="Orphan bytecode (no source)",
                description=(
                    "A .pyc shipped without its .py source. Often benign "
                    "(stripped distribution) but worth noting outside vendor dirs."
                ),
                file=rel_path, line=0, snippet="no sibling .py", category="orphan-bytecode",
            ))
    return findings


def scan_repo(repo_path, ignore_patterns=None):
    all_findings = []
    processed = 0
    t0 = time.monotonic()
    for file_path, rel_path in core.walk_aux(
        repo_path, ignore_patterns=ignore_patterns,
        apply_size_cap=False, reach_pycache=True,
    ):
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in PYC_EXTENSIONS:
            continue
        if processed >= MAX_PYC or (time.monotonic() - t0) > TOTAL_BUDGET_SEC:
            all_findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="low",
                title="Bytecode scan incomplete (budget reached)",
                description=(
                    "Stopped scanning .pyc files after the time/count budget; "
                    "remaining bytecode left uninspected."
                ),
                file=rel_path, line=0, snippet="", category="archive-scan-incomplete",
            ))
            break
        processed += 1
        all_findings.extend(scan_pyc(file_path, rel_path))
    return all_findings


def main():
    args = core.parse_common_args(sys.argv, "Python Bytecode Scanner")
    repo_path = args.repo_path
    core.emit_status(args.format, f"[*] Scanning .pyc bytecode in {repo_path}...")
    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = scan_repo(repo_path, ignore_patterns)
    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
