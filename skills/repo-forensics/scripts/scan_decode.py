#!/usr/bin/env python3
"""
scan_decode.py - Bounded decode-and-rescan LIBRARY (U1)

Closes scanner-bypass Gap 4(a) from the 2026-06 audit: a malicious payload
encoded as base64/base85/base32/hex sails past the string/AST/trifecta
heuristics because those heuristics scan the *encoded* text, which looks like an
opaque high-entropy blob. The existing entropy/AST scanners FLAG such a blob but
never decode it, so `os.system("...")` hidden one base64 layer deep is invisible.

This module is an IN-PROCESS library (KTD1), not a standalone subprocess
scanner. A host scanner that has already flagged a high-entropy / base64-ish blob
calls `rescan_blob(blob, origin_path)`; we decode it across the fixed KTD2
alphabet, recurse up to a depth cap if the decoded output is itself encoded, and
re-run the shared SAST + trifecta heuristics over the decoded plaintext.

WHAT THE REPORT GATE ACTUALLY IS (KTD8, accurate as of the 2026-06-17 hardening):
the gate that decides whether a decoded blob produces a Finding is the INNER
SAST + trifecta scan (`scan_sast.scan_text` + `forensics_core.scan_text_trifecta`)
run over the decoded plaintext, NOT `_looks_code_like`. `_looks_code_like` is
only a cheap PRE-FILTER that decides whether the (printable) decoded text is
worth handing to that inner scan and worth recursing into. A finding is emitted
ONLY when the inner SAST/trifecta scan trips a rule; benign base64 (an embedded
PNG, a cert, lockfile hashes, prose) stays silent because nothing trips.

Because the inner SAST/trifecta scan historically MISSED getattr-based attribute
access (`getattr(os,'system')(...)`), urllib/http exfiltration, and sensitive-file
reads (`open('/etc/passwd').read()`), those decoded payloads passed silently. This
module now adds a targeted `_decoded_payload_checks` pass that flags those three
families directly, so a decoded payload that evades SAST/trifecta is still caught.

Containment is the whole point (KTD3, MANDATORY — input is attacker-controlled):
  - INPUT cap (~1 MB, MAX_INPUT_BLOB): a blob larger than this is truncated
    BEFORE any decode / ast.parse, so a 5 MB blob can never drive the decode +
    str-decode + parse-tree working set to ~1.5 GB RSS;
  - per-blob decoded-output cap (~2 MB): truncate, never grow unbounded;
  - the per-origin byte budget counts the FULL (pre-truncation) decoded length —
    including ascii85 `z`-shortcut expansion — so an amplifying decoder is
    visible to the cap, not just the post-truncation bytes;
  - a pre-decode expansion guard refuses to a85/b85-decode an input whose
    worst-case expansion would blow the remaining origin budget, so the ~95x
    `z`-shortcut transient never materializes;
  - recursion FAN-OUT cap (MAX_DECODERS_PER_BLOB): at most the 1-2 most-likely
    decodings are pursued per blob, so the 5^depth fan-out cannot accumulate;
  - recursion depth cap of 3 (KTD2): then stop with a low "max decode depth"
    note (emitted at most once per origin);
  - per-call / per-scan wall-clock deadline (~12 s default): SHARED across all
    recursion AND across every blob in a scan when the caller threads one in;
    checked before each decode, inside the recursion, and before ast.parse, so a
    single slow op cannot overrun. On exhaustion emit a "decode budget exhausted"
    note (deduped, at most once per origin) and return, never hang;
  - DECODE ONLY — never zlib/gzip-decompress decoded bytes (no bomb amplification).

NEVER exec (KTD4): decoded content is scanned as TEXT and via `ast.parse` only —
no `compile(..., 'exec')`, no `exec()`, no `eval()`, ever. Decoded text is
neutralized (mirrors adjudication.sanitize_snippet) before it is placed in any
Finding description a host LLM session might read.

SHARED-BUDGET WIRING (for host scanners looping over many blobs):
A host scanner that calls `rescan_blob` per blob MUST mint ONE budget at the top
of its scan and thread it into every call, so the wall-clock deadline AND the
cumulative byte budget are shared across all blobs (not re-armed per call, which
is what let N blobs blow the 15 s auto_scan SIGKILL into a silent zero):

    budget = scan_decode.new_budget()          # once per scan/repo
    for blob in blobs:
        findings += scan_decode.rescan_blob(blob, path, budget=budget)

`new_budget(deadline=None)` mints a budget with a fresh ~12 s deadline (or wraps
a caller-supplied absolute monotonic deadline). For backward compatibility a
caller may instead pass `deadline=<abs monotonic time>` directly to `rescan_blob`;
that shares the deadline but NOT the byte budget, so prefer threading a budget.

Created by Alex Greenshpun
"""

import ast
import base64
import binascii
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import scan_sast

SCANNER_NAME = "decode"

# --- Containment caps (KTD3) ---
# INPUT cap: a blob larger than this is truncated BEFORE any decode / ast.parse.
# Bounds the transient decode + str-decode + ast.parse working set so a single
# large blob cannot spike RSS to ~1.5 GB. ~1 MB of encoded text still decodes to
# well under the 2 MB per-blob output cap for every alphabet here.
MAX_INPUT_BLOB = 1 * 1024 * 1024                # 1 MB
# Per-blob decoded-output cap: a single decode that yields more than this is
# truncated here, never held whole in memory.
PER_BLOB_DECODED_CAP = 2 * 1024 * 1024          # 2 MB
# Per-origin total decoded-bytes budget across the whole recursion tree, shared
# across every blob in a scan when the caller threads one budget in. Bounds a
# decode-bomb chain. Counts FULL pre-truncation decoded length (so expansion is
# visible).
PER_ORIGIN_DECODED_BUDGET = 8 * 1024 * 1024     # 8 MB
# Recursion depth cap (KTD2): decoded output that is itself encoded recurses up
# to this depth, then stops with a low note.
MAX_DECODE_DEPTH = 3
# Fan-out cap (KTD3): a single blob can validate under several alphabets at once
# (base64 + a85 + b85 + base32 + hex), giving up to 5^depth recursion subtrees.
# Pursue at most this many decodings per blob, most-likely first, so the fan-out
# cannot accumulate.
MAX_DECODERS_PER_BLOB = 2
# Worst-case byte expansion per decoder, used by the pre-decode guard so an
# amplifying decoder (ascii85 'z'-shortcut: 1 byte -> 4) cannot materialize a
# huge transient before the post-decode byte accounting sees it.
_MAX_EXPANSION = {
    "base85-a85": 4,
    "base85-b85": 4,
    "base64": 1,
    "base32": 1,
    "hex": 1,
}
# Per-call / per-scan wall-clock budget. Mirrors scan_oversize.TOTAL_BUDGET_SEC
# so a host scanner invoking us finishes before the 15 s auto_scan SIGKILL. When
# a caller threads in a shared deadline/budget this default is NOT re-armed.
TOTAL_BUDGET_SEC = 12

# Below this length a candidate is too short to carry an interesting payload and
# decoding noise wastes budget; skip it.
MIN_BLOB_LEN = 16

# --- HOISTED blob/fragment DETECTION (single source of truth) ---
# Host scanners (entropy / ast / skill_threats) previously each re-derived these
# regexes with DIVERGENT length floors AND a base85 charset bug. They are defined
# ONCE here and exposed via `detect_encoded_blobs(text)` / `build_blob_res(floor)`
# so the alphabets and the corrected base85 class cannot drift again.
#
# Default routing floor: a flagged encoded RUN must be at least this long before
# it is worth handing to decode (mirrors the old entropy/skill_threats floor of
# 50). splitstream intentionally uses a LOWER fragment floor (its fragments are
# small by design) and builds its own regexes via build_blob_res(MIN_FRAGMENT_LEN).
DETECT_BLOB_FLOOR = 50

# Source-string delimiters stripped from the EDGES of a captured blob so a
# wrapping quote does not break strict a85/base32/base64 validation. SINGLE
# definition (was duplicated verbatim in entropy + skill_threats).
EDGE_DELIMS = '"\'`'

# Base85 charset — the CORRECTED classes (adversarial P1-1). The old wiring regex
# was `[!-u]` (0x21-0x75), which EXCLUDES `v w x y z { | } ~` — 9 of the chars
# RFC1924 base85 (what base64.b85encode / b85decode consume) actually uses. ~99.8%
# of real b85 blobs contain at least one excluded char, so they were SPLIT into
# sub-floor fragments and never routed to decode. We now match BOTH alphabets:
#   - a85 (ascii85): '!'..'u' plus the 'z'/'y' shortcut chars (already in range).
#   - b85 (RFC1924): 0-9 A-Z a-z and  !#$%&()*+-;<=>?@^_`{|}~  (note: NO space,
#     NO " ' , . / : [ \ ] — so this stays tight and does not match prose).
# A captured run is the UNION of the two so a real b85 blob using v-z / {|}~ is
# caught whole. The two are kept as named building blocks for build_blob_res.
_A85_CHARSET = r"!-u"
# RFC1924 b85 alphabet as a regex char class (escaped where needed). Covers the
# 85 chars base64.b85encode emits, including the v-z / {|}~ the old class dropped.
_B85_CHARSET = r"0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~"
# Union charset used for ROUTING detection (catch a blob under either alphabet).
_BASE85_UNION_CHARSET = r"!-u" + r"v-z{|}~"  # a85 range + the 9 chars it dropped


def build_blob_res(floor):
    """Build the canonical (base64, base85, base32, hex) full-blob detection
    regexes for a given minimum-length `floor`. ONE definition; callers that want
    a different floor (splitstream uses a smaller fragment floor) pass it here
    instead of re-deriving the alphabets. The base85 pattern uses the CORRECTED
    union charset so real RFC1924 b85 blobs (v-z, {|}~) are matched whole."""
    return (
        re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % floor),       # base64
        re.compile(r"[%s]{%d,}" % (_BASE85_UNION_CHARSET, floor)),  # base85 (a85 ∪ b85)
        re.compile(r"[A-Z2-7]{%d,}={0,6}" % floor),            # base32
        re.compile(r"(?:0x)?[a-fA-F0-9]{%d,}" % floor),        # hex
    )


# Canonical routing regexes at the default floor (entropy / skill_threats use
# these directly via detect_encoded_blobs).
B64_BLOB_RE, B85_BLOB_RE, B32_BLOB_RE, HEX_BLOB_RE = build_blob_res(DETECT_BLOB_FLOOR)
ENCODED_BLOB_RES = (B64_BLOB_RE, B85_BLOB_RE, B32_BLOB_RE, HEX_BLOB_RE)


def detect_encoded_blobs(text, floor=DETECT_BLOB_FLOOR):
    """Single source of truth for encoded-blob ROUTING detection (hoisted from the
    3 host scanners). Scan `text` for base64/base85/base32/hex runs of at least
    `floor` chars, strip wrapping source-string delimiters from each blob's edges,
    dedup, and return the list of unique FULL (untruncated) blob strings ready to
    hand to `rescan_blob`. Emits NO finding — detection only.

    The base85 alphabet here is the CORRECTED union of a85 and RFC1924 b85, so a
    real `base64.b85encode` payload (which uses v-z / {|}~) is matched WHOLE and
    routed to decode instead of being split into sub-floor fragments (P1-1).
    """
    res = ENCODED_BLOB_RES if floor == DETECT_BLOB_FLOOR else build_blob_res(floor)
    blobs = []
    seen = set()
    for rx in res:
        for m in rx.finditer(text):
            matched = m.group(0).strip(EDGE_DELIMS)
            if len(matched) < floor or matched in seen:
                continue
            seen.add(matched)
            blobs.append(matched)
    return blobs


def feed_blobs(blobs, origin_path, seen, findings, budget):
    """Hoisted guarded rescan loop (was reimplemented 3x as `_decode_and_rescan` /
    `_feed`). For each blob not already in `seen`, hand it to `rescan_blob` under
    the shared `budget` and extend `findings` with any decoded-payload hits. Fully
    guarded: a scan_decode failure never breaks the host scan. `seen` dedups so a
    blob repeated across lines/files is decoded once."""
    for blob in blobs:
        if not blob or blob in seen:
            continue
        seen.add(blob)
        try:
            findings.extend(rescan_blob(blob, origin_path, budget=budget))
        except Exception:
            pass


def host_budget():
    """Import-guarded shared-budget mint for a host scanner's main(). Returns ONE
    `new_budget()` to thread across every file/blob in a scan (so the wall-clock
    deadline AND cumulative byte cap span the whole scan, never re-armed). Returns
    None only if budget construction itself fails — callers pass that straight
    through and rescan_blob mints a per-call budget as a safe fallback."""
    try:
        return new_budget()
    except Exception:
        return None

# A decoded blob counts as "code-like" (the cheap PRE-FILTER, NOT the report
# gate) if it is mostly printable AND trips one of these suspicious tokens. Kept
# deliberately narrow so a benign printable blob (license text, lockfile hashes)
# does not trip it on its own. The report gate is the inner SAST/trifecta scan
# plus _decoded_payload_checks.
_PRINTABLE_RATIO_MIN = 0.85
_SUSPICIOUS_TOKEN_RE = re.compile(
    r"\b(?:os\.system|subprocess|popen|exec|eval|compile|__import__|"
    r"importlib|getattr|setattr|marshal|pickle|base64|b64decode|urllib|"
    r"urlopen|Request|requests|httplib|http\.client|socket|curl|wget|bash|"
    r"/bin/sh|/etc/passwd|/etc/shadow|id_rsa|\.aws|\.ssh|GITHUB_TOKEN|"
    r"powershell|cmd\.exe|fromCharCode|child_process|require\()\b",
    re.IGNORECASE,
)

# Characters considered "printable" for the printable-ratio gate: ASCII
# graphic + space + the common whitespace bytes. Anything else (control bytes,
# raw binary) drags the ratio down so an embedded PNG / cert never passes.
_PRINTABLE_BYTES = frozenset(
    bytes(range(0x20, 0x7F)) + b"\t\n\r"
)

# --- Targeted decoded-payload checks (broaden the report gate, KTD8) ---
# These catch payload families the inner SAST/trifecta scan historically missed.
# getattr-based attribute dispatch on a dangerous module: getattr(os,'system'),
# getattr(__import__('os'), 'system'), getattr(subprocess, 'Popen'), etc.
_GETATTR_DISPATCH_RE = re.compile(
    r"getattr\s*\(\s*"
    r"(?:os\b|subprocess\b|sys\b|builtins\b|__import__\s*\(|importlib\b|socket\b)"
    r".*?\)\s*\(",
    re.IGNORECASE | re.DOTALL,
)
# urllib / http / requests exfiltration: a network egress primitive present in
# decoded code.
_NET_EXFIL_RE = re.compile(
    r"\b(?:urllib\.request\.urlopen|urllib2?\.urlopen|urlopen\s*\(|"
    r"requests\.(?:get|post|put)\s*\(|http\.client\.|httplib\.|"
    r"urllib\.request\.Request|socket\.socket\s*\(|"
    r"urllib\.request\.urlretrieve)\b",
    re.IGNORECASE,
)
# Sensitive-file read: open('/etc/passwd'), open('~/.ssh/id_rsa'), reading
# credential stores.
_SENSITIVE_FILE_RE = re.compile(
    r"open\s*\(\s*[^)]*?"
    r"(?:/etc/passwd|/etc/shadow|/root/|\.ssh/|id_rsa|id_dsa|id_ecdsa|"
    r"\.aws/credentials|\.aws/config|/proc/self/environ|"
    r"\.npmrc|\.netrc|\.git-credentials|\.docker/config)",
    re.IGNORECASE,
)
# Single dangerous statement (adversarial P1-2): a ONE-statement destructive /
# exec / process-spawn / dynamic-import call that the multi-statement
# `_looks_code_like` pre-filter and the SAST/trifecta gate historically missed,
# so e.g. `shutil.rmtree("/")` one base64 layer deep returned ZERO findings. This
# pass runs on ANY printable decoded text (not gated by statement count), so a
# single line IS flagged. Kept to recognisable dangerous CALLS (the `(` is
# required) so benign prose / single benign statements (open('config.yaml'),
# print(...)) stay silent.
_DANGEROUS_CALL_RE = re.compile(
    r"\b(?:"
    # destructive filesystem ops
    r"shutil\.rmtree|shutil\.move|os\.remove|os\.unlink|os\.rmdir|os\.removedirs|"
    r"os\.rename|os\.truncate"
    # process / shell execution
    r"|os\.system|os\.popen|os\.exec[lv][ep]?e?|os\.spawn\w+|"
    r"subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)|"
    r"pty\.spawn|commands\.getoutput"
    # dynamic code construction / execution
    r"|exec|eval|compile|__import__|importlib\.import_module|marshal\.loads|"
    r"pickle\.loads|ctypes\.(?:CDLL|cdll|windll|memmove)|mmap\.mmap"
    # raw socket egress
    r"|socket\.socket"
    r")\s*\("
    # Path(...).unlink() / .rmdir() / .write_bytes() — bounded, no nested-call
    # backtracking blowup (the inner arg cannot contain '(' or ')').
    r"|\b(?:pathlib\.Path|Path)\s*\([^()\n]*\)\s*\.\s*"
    r"(?:unlink|rmdir|write_bytes|write_text|chmod)\s*\(",
    re.IGNORECASE,
)
_DECODED_CHECKS = (
    ("getattr-attribute-dispatch", _GETATTR_DISPATCH_RE,
     "getattr-based attribute dispatch on a dangerous module"),
    ("network-exfiltration", _NET_EXFIL_RE,
     "urllib/http network egress primitive"),
    ("sensitive-file-read", _SENSITIVE_FILE_RE,
     "read of a sensitive credential / system file"),
    ("dangerous-call", _DANGEROUS_CALL_RE,
     "a single destructive / exec / process-spawn / dynamic-import call"),
)

# --- AST confirmation for the dangerous-call check (HIGH-1 FP fix) ---
# `_DANGEROUS_CALL_RE` is a TEXT regex: it fires on a bare token followed by `(`
# anywhere, including inside natural-language prose ("...the helper will call
# shutil.rmtree(target) only after a confirmation dialog..."). When that prose is
# itself encoded as a long blob it decodes to printable text and the regex tripped
# a HIGH finding even though nothing executable is present. The clean discriminator
# between real code and prose is Python-parseability: `shutil.rmtree("/")` is valid
# Python that `ast.parse`s to a real Call node; the prose sentence raises
# SyntaxError. So the dangerous-call finding is gated behind an `ast.parse` that
# must succeed AND yield a Call whose target is one of the dangerous primitives.
#
# Bare-name callables (exec/eval/compile/__import__) the regex matches. We confirm
# them as `ast.Call(func=ast.Name(id=...))`. NOTE: we only NAME these for AST
# matching; we never call them (the AST self-check forbids exec/eval/compile call
# sites — these are string literals in a set, not call targets).
_DANGEROUS_NAME_CALLS = frozenset({
    "exec", "eval", "compile", "__import__",
})
# Attribute callables: the LAST attribute name is the dangerous primitive. We match
# on the trailing attribute (e.g. `os.system(...)` -> "system", `shutil.rmtree(...)`
# -> "rmtree"), guarded by the leading module/root where the regex is module-anchored.
# Keyed by attribute name -> the set of acceptable root identifiers (None == any root,
# used for Path(...).unlink()-style chains whose root is a call, not a name).
_DANGEROUS_ATTR_CALLS = {
    # destructive filesystem ops (module-anchored)
    "rmtree": {"shutil"}, "move": {"shutil"},
    "remove": {"os"}, "unlink": {"os", None}, "rmdir": {"os", None},
    "removedirs": {"os"}, "rename": {"os"}, "truncate": {"os"},
    # process / shell execution
    "system": {"os"}, "popen": {"os"},
    "execl": {"os"}, "execle": {"os"}, "execlp": {"os"}, "execlpe": {"os"},
    "execv": {"os"}, "execve": {"os"}, "execvp": {"os"}, "execvpe": {"os"},
    "spawnl": {"os"}, "spawnle": {"os"}, "spawnlp": {"os"}, "spawnlpe": {"os"},
    "spawnv": {"os"}, "spawnve": {"os"}, "spawnvp": {"os"}, "spawnvpe": {"os"},
    "run": {"subprocess"}, "call": {"subprocess"},
    "check_call": {"subprocess"}, "check_output": {"subprocess"},
    "Popen": {"subprocess"}, "getoutput": {"subprocess", "commands"},
    "getstatusoutput": {"subprocess"}, "spawn": {"pty"},
    # dynamic code construction / execution
    "import_module": {"importlib"},
    "loads": {"marshal", "pickle"},
    "CDLL": {"ctypes"}, "cdll": {"ctypes"}, "windll": {"ctypes"},
    "memmove": {"ctypes"},
    "mmap": {"mmap"},
    # raw socket egress
    "socket": {"socket"},
    # Path(...).unlink()/.rmdir()/.write_bytes()/.write_text()/.chmod()
    "write_bytes": {None}, "write_text": {None}, "chmod": {None},
}


def _attr_root_name(node):
    """Return the leftmost identifier of an attribute chain (`os.path.join` -> 'os',
    `shutil.rmtree` -> 'shutil'), or None if the chain bottoms out in something
    that is not a bare Name (e.g. `Path("x").unlink` whose root is a Call). Pure
    AST traversal, no execution."""
    cur = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    if isinstance(cur, ast.Name):
        return cur.id
    return None


def _ast_has_dangerous_call(text):
    """True iff `text` parses as Python AND its AST contains a Call node whose
    target is one of the dangerous primitives. This is the real-code-vs-prose
    discriminator for the dangerous-call check: prose that merely MENTIONS a
    dangerous call raises SyntaxError here and returns False, while an actual
    single statement like `shutil.rmtree("/")` parses and matches.

    ONLY `ast.parse` (a pure parser) is used — never compile/exec/eval, so the
    no-exec invariant and the AST self-check test stay green."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Bare-name dangerous builtins: exec(...) / eval(...) / compile(...) /
        # __import__(...).
        if isinstance(func, ast.Name) and func.id in _DANGEROUS_NAME_CALLS:
            return True
        # Attribute-form dangerous calls: match on the trailing attribute name,
        # constrained to the acceptable root module(s).
        if isinstance(func, ast.Attribute):
            roots = _DANGEROUS_ATTR_CALLS.get(func.attr)
            if roots is None:
                continue
            root = _attr_root_name(func)
            # None in `roots` means the root may be a non-name (e.g. a Call like
            # Path("x").unlink()); otherwise require a matching module root.
            if root in roots or (None in roots and root is None):
                return True
    return False


def _confirm_dangerous_call(text, match):
    """Confirm a `_DANGEROUS_CALL_RE` text match is REAL executable code, not prose
    that merely names the call (HIGH-1 FP fix). Try the full decoded text first; if
    it does not parse (a real payload may be embedded in a larger non-Python blob),
    fall back to the minimal line/statement window around the match. Conservative:
    if no AST Call to a dangerous primitive can be confirmed in either, return False
    so no finding is emitted."""
    if _ast_has_dangerous_call(text):
        return True
    # Full text did not confirm (didn't parse, or no dangerous Call). Try the
    # narrow region around the match: the run of lines spanning the match, with
    # leading indentation stripped so an indented snippet parses standalone.
    start = text.rfind("\n", 0, match.start()) + 1
    nl = text.find("\n", match.end())
    end = len(text) if nl == -1 else nl
    window = text[start:end]
    # Dedent every line so a block lifted out of a function body still parses.
    dedented = "\n".join(line.lstrip() for line in window.splitlines())
    return _ast_has_dangerous_call(dedented)


def _printable_ratio(data):
    """Fraction of bytes in `data` that are printable ASCII / common whitespace."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in _PRINTABLE_BYTES)
    return printable / len(data)


def _looks_code_like(text):
    """Cheap PRE-FILTER (NOT a standalone report decision) for whether decoded
    plaintext is worth handing to the inner SAST/trifecta report gate. ast.parse is
    the ONLY parse here — never compile/exec.

    HIGH-1 FP fix: a suspicious TOKEN alone is no longer sufficient. Encoded PROSE
    that merely mentions `os.system()` / `subprocess.run()` / `eval(...)` matches the
    token regex but is NOT valid Python, so before this fix it sailed into the
    SAST/trifecta gate and tripped SA-PY-* / trifecta findings on a plain English
    sentence. The real code-vs-prose discriminator is Python-parseability, so the
    text must `ast.parse`:
      - with a suspicious token present, ANY successful parse qualifies (a real
        single-statement payload like `os.system(chr(99))` is 1 statement);
      - with no token, require >=2 statements (weak structural evidence of code) so
        a one-line benign string ("hello world") does not register as code.
    Prose raises SyntaxError under either branch and returns False."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return False
    body = getattr(tree, "body", [])
    if _SUSPICIOUS_TOKEN_RE.search(text):
        return len(body) >= 1
    return len(body) >= 2


def _decoded_finding(alphabet, depth, origin_path, indicator, rule_id,
                     confidence, severity, trips):
    """ONE builder for the decoded-payload `core.Finding` (was open-coded in
    `_decoded_payload_checks` AND `_scan_decoded_text`). `trips` is the short
    clause describing what the decoded plaintext matched."""
    return core.Finding(
        scanner=SCANNER_NAME,
        severity=severity,
        title="Decoded payload contains a malicious indicator",
        description=(
            f"A {alphabet}-encoded blob (decode depth {depth}) decodes to "
            f"plaintext {trips}: {indicator}"
        ),
        file=origin_path,
        line=0,
        snippet=indicator,
        category="decoded-payload",
        rule_id=rule_id,
        confidence=confidence,
    )


def _decoded_payload_checks(text, origin_path, alphabet, depth):
    """Targeted checks that broaden the report gate beyond SAST/trifecta (KTD8):
    flag getattr-based dispatch, urllib/http exfil, sensitive-file reads, AND a
    single destructive/exec/process-spawn call (P1-2) in decoded plaintext.
    Returns list[Finding] (possibly empty)."""
    findings = []
    for category, rx, label in _DECODED_CHECKS:
        m = rx.search(text)
        if not m:
            continue
        # HIGH-1 FP fix: the dangerous-call check fires on a bare token + `(`
        # anywhere, so encoded PROSE that merely MENTIONS a dangerous call (e.g.
        # "...the helper will call shutil.rmtree(target) only after...") tripped a
        # HIGH finding. Gate it behind an ast.parse confirmation that the match is
        # real executable code containing an actual Call to a dangerous primitive.
        # Prose raises SyntaxError -> no finding; real code -> finding.
        if category == "dangerous-call" and not _confirm_dangerous_call(text, m):
            continue
        snippet = _neutralize(m.group(0), max_len=120) or label
        findings.append(_decoded_finding(
            alphabet, depth, origin_path, snippet,
            rule_id="decode-" + category, confidence="high", severity="high",
            trips=f"containing {label}",
        ))
    return findings


def _b64(b):
    return base64.b64decode(b, validate=True)


def _b32(b):
    return base64.b32decode(b, casefold=True)


# Decoders in fixed most-likely-first order (KTD2 alphabet). base64/base32/hex are
# real-and-strict; base85 (a85 then b85) is near-unfalsifiable + amplifying, so it
# is guarded hardest and pursued LAST (the fan-out cap usually excludes it once a
# real base64/base32/hex decode validated). NO XOR / affine / transposition.
_DECODERS = (
    ("base64", _b64),
    ("base32", _b32),
    ("hex", binascii.unhexlify),
    ("base85-a85", base64.a85decode),
    ("base85-b85", base64.b85decode),
)


def _decode_candidates(blob_bytes, budget):
    """Yield (alphabet_name, decoded_bytes, raw_len) for the most-likely KTD2
    decoders that strictly succeed on `blob_bytes`, capped at
    MAX_DECODERS_PER_BLOB to bound fan-out. A pre-decode expansion guard refuses
    an amplifying decoder whose worst-case output would blow the remaining origin
    byte budget. ONE loop over `_DECODERS` (was hand-unrolled 3x + a base85 loop)."""
    yielded = 0
    remaining = max(0, PER_ORIGIN_DECODED_BUDGET - budget.decoded_bytes)

    for name, fn in _DECODERS:
        if yielded >= MAX_DECODERS_PER_BLOB:
            break
        # Refuse to even call the decoder if its worst-case expansion would
        # exceed the remaining origin budget — prevents the ascii85 'z'-shortcut
        # ~95x transient from ever materializing.
        if len(blob_bytes) * _MAX_EXPANSION.get(name, 1) > max(remaining, MAX_INPUT_BLOB):
            continue
        try:
            out = fn(blob_bytes)
        except (binascii.Error, ValueError):
            continue
        if out:
            yield (name, out[:PER_BLOB_DECODED_CAP], len(out))
            yielded += 1


def _neutralize(text, max_len=200):
    """Neutralize decoded plaintext before it lands in a host-readable Finding
    description. Mirrors adjudication.sanitize_snippet (strip escapes / fences /
    zero-width / control / BIDI, collapse whitespace). Best-effort: falls back to
    an inline control-strip if adjudication is unavailable OR raises, so decoded
    attacker text is never surfaced raw and a sanitizer bug never drops a
    finding."""
    try:
        import adjudication
        return adjudication.sanitize_snippet(text, max_len=max_len)
    except Exception:
        # Strip control bytes, BIDI/zero-width controls, and backtick fences.
        # Ranges built from \u escapes so this is source-encoding-independent.
        cleaned = re.sub(
            "[\x00-\x08\x0b-\x1f\x7f\x80-\x9f"
            "‪-‮⁦-⁩​-‏"
            "`｀]",
            "",
            text,
        )
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned[:max_len]


def _scan_decoded_text(text, origin_path, alphabet, depth):
    """Run the heavier half of the report gate over decoded plaintext: the shared
    SAST + trifecta heuristics, re-labelling findings as decoded-payload, naming
    the decoded indicator and citing origin_path. (The targeted getattr/urllib/
    sensitive-file checks run separately in _rescan on any printable text.)
    Returns [] when nothing trips (KTD8)."""
    # Scan as Python source (the worst case); attacker-controlled, so do not gate
    # on the origin's real extension.
    inner = []
    inner.extend(scan_sast.scan_text(text, origin_path, ext=".py"))
    inner.extend(core.scan_text_trifecta(text, origin_path))

    findings = []
    for f in inner:
        indicator = _neutralize(f.snippet or f.title, max_len=120) or f.title
        severity = f.severity if f.severity in ("critical", "high", "medium") else "high"
        findings.append(_decoded_finding(
            alphabet, depth, origin_path, indicator,
            rule_id=f.rule_id, confidence=f.confidence, severity=severity,
            trips=f"that trips '{f.category}'",
        ))
    return findings


class _Budget:
    """Per-scan containment state shared across one rescan_blob recursion tree —
    and, when the caller threads it in, across EVERY blob in a scan (KTD3): total
    decoded bytes + a single wall-clock deadline. Re-arming this per call is the
    bug that let N blobs blow the 15 s SIGKILL; share ONE instead."""

    __slots__ = ("decoded_bytes", "deadline", "exhausted", "max_depth_noted")

    def __init__(self, deadline):
        self.decoded_bytes = 0
        self.deadline = deadline
        self.exhausted = False
        self.max_depth_noted = False

    def over_time(self):
        return time.monotonic() > self.deadline

    def over_bytes(self):
        return self.decoded_bytes >= PER_ORIGIN_DECODED_BUDGET


def new_budget(deadline=None):
    """Mint ONE shared decode budget for a whole scan. A host scanner that loops
    over many blobs calls this ONCE and threads the result into every
    `rescan_blob(blob, path, budget=...)` call, so the wall-clock deadline AND
    the cumulative per-origin byte budget are shared across all blobs and never
    re-armed.

    Args:
        deadline: optional absolute `time.monotonic()` deadline to share. If
            None, a fresh deadline of now + TOTAL_BUDGET_SEC is minted.

    Returns:
        a budget object to pass as `rescan_blob(..., budget=budget)`.
    """
    if deadline is None:
        deadline = time.monotonic() + TOTAL_BUDGET_SEC
    return _Budget(deadline=deadline)


def _as_bytes(blob):
    if isinstance(blob, bytes):
        return blob
    if isinstance(blob, bytearray):
        return bytes(blob)
    if isinstance(blob, str):
        return blob.encode("utf-8", errors="replace")
    return b""


def _budget_note(origin_path):
    return core.Finding(
        scanner=SCANNER_NAME, severity="low",
        title="Decode budget exhausted",
        description=(
            "Stopped decoding before the per-origin byte / wall-clock budget was "
            "exceeded; remaining encoded layers not decoded."
        ),
        file=origin_path, line=0, snippet="",
        category="decode-scan-incomplete",
    )


def _rescan(blob_bytes, origin_path, depth, budget):
    """Internal recursive worker. Returns list[Finding]."""
    findings = []

    # Strip surrounding whitespace; encoders never embed it meaningfully and it
    # breaks strict validation.
    blob_bytes = blob_bytes.strip()
    if len(blob_bytes) < MIN_BLOB_LEN:
        return findings

    # INPUT cap BEFORE any decode / ast.parse (memory containment): a blob larger
    # than MAX_INPUT_BLOB is truncated here so the transient decode + parse
    # working set can never spike to ~1.5 GB on a 5 MB input.
    if len(blob_bytes) > MAX_INPUT_BLOB:
        blob_bytes = blob_bytes[:MAX_INPUT_BLOB]

    # Check the deadline / byte budget BEFORE decoding (frequently, so one slow
    # op cannot overrun).
    if budget.over_time() or budget.over_bytes():
        if not budget.exhausted:
            budget.exhausted = True
            findings.append(_budget_note(origin_path))
        return findings

    if depth >= MAX_DECODE_DEPTH:
        if not budget.max_depth_noted:
            budget.max_depth_noted = True
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="low",
                title="Max decode depth reached",
                description=(
                    f"Reached the decode recursion cap of {MAX_DECODE_DEPTH} "
                    f"layers at {origin_path}; deeper encoded layers not decoded."
                ),
                file=origin_path, line=0, snippet="", category="decode-max-depth",
            ))
        return findings

    for alphabet, truncated, raw_len in _decode_candidates(blob_bytes, budget):
        if budget.over_time() or budget.over_bytes():
            if not budget.exhausted:
                budget.exhausted = True
                findings.append(_budget_note(origin_path))
            break

        # Count the FULL pre-truncation decoded length against the budget so an
        # amplifying decoder (ascii85 'z'-shortcut) is visible to the cap, even
        # though only the truncated bytes are scanned/recursed.
        budget.decoded_bytes += raw_len

        ratio = _printable_ratio(truncated)
        text = truncated.decode("utf-8", errors="replace")

        if ratio >= _PRINTABLE_RATIO_MIN:
            if budget.over_time():
                if not budget.exhausted:
                    budget.exhausted = True
                    findings.append(_budget_note(origin_path))
                break
            # Targeted checks (getattr-dispatch / urllib-exfil / sensitive-file
            # read) run on ANY printable decoded text — these payloads can be a
            # single short statement that the _looks_code_like pre-filter misses.
            findings.extend(_decoded_payload_checks(text, origin_path, alphabet, depth))
            # The heavier SAST/trifecta report gate only runs when the cheap
            # pre-filter says the text is plausibly code (cost control).
            if _looks_code_like(text):
                findings.extend(_scan_decoded_text(text, origin_path, alphabet, depth))

        # KTD2 recursion: the decoded output may itself be another encoded blob
        # (e.g. base64(base64(payload))). Recurse regardless of the pre-filter,
        # because an inner layer can be high-entropy noise that only the NEXT
        # decode reveals as code. Depth + fan-out + budget bound this.
        findings.extend(_rescan(truncated, origin_path, depth + 1, budget))

    return findings


def rescan_blob(blob, origin_path, depth=0, deadline=None, budget=None):
    """Public entry (KTD1): decode an already-flagged blob across the fixed KTD2
    alphabet with bounded recursion, and re-run the report gate (shared SAST +
    trifecta heuristics PLUS targeted getattr/urllib/sensitive-file checks) over
    the decoded plaintext.

    Containment is shared, not re-armed: a host scanner that loops over many
    blobs should mint ONE budget via `new_budget()` and thread it in as `budget=`
    so the wall-clock deadline AND the cumulative per-origin byte budget span the
    whole scan (re-arming per call is what let N blobs blow the 15 s SIGKILL into
    a silent zero).

    Args:
        blob: the flagged blob, str or bytes (the encoded text a host scanner
            already flagged as high-entropy / base64-ish). Full blobs are
            accepted; anything over MAX_INPUT_BLOB is truncated before decode.
        origin_path: repo-relative path of the file the blob came from; cited in
            every emitted Finding.
        depth: current recursion depth (callers pass 0; recursion increments it).
        deadline: optional absolute `time.monotonic()` deadline to SHARE across
            calls. Used only when `budget` is None. Shares the deadline but NOT
            the byte budget — prefer threading a `budget`.
        budget: optional shared budget from `new_budget()`. When passed, it is
            used as the single shared wall-clock + byte budget across this and all
            other calls threaded with the same object; it is NOT re-armed.

    Returns:
        list[core.Finding]: decoded-payload findings (KTD8: emitted ONLY when the
        decoded plaintext trips the report gate), plus at most one low note per
        category for max-depth / budget exhaustion. A blob that decodes to benign
        printable data returns [].
    """
    blob_bytes = _as_bytes(blob)
    if not blob_bytes:
        return []
    if budget is None:
        budget = new_budget(deadline=deadline)
    return _rescan(blob_bytes, origin_path, depth, budget)
