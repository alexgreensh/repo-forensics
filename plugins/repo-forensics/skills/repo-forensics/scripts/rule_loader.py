#!/usr/bin/env python3
"""
rule_loader.py - Rules-as-data loader for repo-forensics v2.

Loads, validates, compiles, and self-tests JSON rule packs. A rule pack is a
declarative replacement for the regex/keyword/charset/map tables that used to
live hardcoded in scanner source. Scanners import this module and consume the
compiled structures; this module is a LEAF in the dependency graph (KTD-14):

    scanners  --->  rule_loader        (allowed)
    forensics_core / aggregate_json  --X-->  rule_loader   (FORBIDDEN)

Keeping `rule_loader` a leaf prevents circular imports — its compiled output
flows INTO Findings, it never reaches back into the aggregation layer.

Usage:
    from rule_loader import load_pack
    pack = load_pack("secrets")           # -> CompiledPack
    for rule in pack.all_rules:           # flat list (secrets/skill_threats/mcp)
        m = rule.regex.search(line)
    for rule in pack.by_extension.get(".py", ()):   # SAST hot loop, pre-indexed
        ...

Rule-pack JSON schema (mirrors data/compromised_versions.json conventions):
    {
      "schema_version": "1.0",          # "major.minor"; major-version gated
      "generated": "2026-06-10",
      "pack": "secrets",
      "pack_version": 1,                  # strictly-increasing INTEGER (feed overlay)
      "rules": [ {rule}, ... ]
    }

Each rule:
    {
      "id": "SC-KEY-001",                 # <SCANNER>-<CATEGORY>-<NNN>
      "type": "regex"|"keyword"|"charset"|"map",
      # --- type-specific payload ---
      "pattern": "...",                   # regex
      "flags": ["IGNORECASE", ...],       # regex (optional)
      "extensions": [".py", ".js"],       # regex (optional gate)
      "values": ["..."],                  # keyword (lowercase) / charset (codepoints)
      "mapping": {"а": "a"},              # map (e.g. homoglyph -> latin)
      # --- metadata (all types) ---
      "title": "...", "severity": "...", "confidence": 0.9,
      "category": "...", "explanation": "...",
      "examples": {"match": [...], "no_match": [...]},
      "retired": false                    # retired rules keep id, are skipped
    }

Security notes:
    * Packs resolve ONLY from the install-dir (realpath of this file) and the
      verified cache dir. Never from CWD, never relative, never from anything
      derived from a scan target. See _pack_search_paths().
    * ReDoS guards are MANDATORY (a compromised feed could ship a catastrophic
      pattern): pattern-length cap + nested-quantifier heuristic (both platform
      independent) + a hard per-rule self-test timeout (POSIX SIGALRM with
      save/restore, threading.Timer fallback elsewhere).

Created by Alex Greenshpun.
"""

import os
import re
import sys
import json
import time
import signal
import threading
import unicodedata

# Keep sibling modules importable regardless of load path (CLI / hook / daemon).
_SCRIPTS_DIR = os.path.dirname(os.path.realpath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

# --- Schema / config --------------------------------------------------------

# Major-version gate, mirroring COMPROMISED_VERSIONS_SCHEMA_VERSION in
# ioc_manager.py. A pack whose major version differs is rejected wholesale;
# the caller treats that as "use the shipped fallback".
RULEPACK_SCHEMA_VERSION = "1.0"

# Valid rule types.
_RULE_TYPES = ("regex", "keyword", "charset", "map")

# Severity vocabulary (mirrors forensics_core); unknown severities are kept as
# given but warned — we do not silently rewrite a pack author's intent.
_KNOWN_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Allowlisted re flag names. Anything outside this set is ignored with a warn,
# so a poisoned pack cannot smuggle in surprising behavior via flag strings.
_ALLOWED_REGEX_FLAGS = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
    "UNICODE": re.UNICODE,
    "ASCII": re.ASCII,
}

# --- ReDoS guards (mandatory, platform-independent) -------------------------

# Hard cap on regex source length. A legitimate detection pattern is well under
# this; a multi-kilobyte pattern is either machine-generated bloat or an attempt
# to defeat the nested-quantifier heuristic with sheer size.
MAX_PATTERN_LENGTH = 1000

# Per-rule self-test wall-clock budget (seconds). A rule whose examples cannot
# evaluate in this window is treated as catastrophic and rejected.
SELF_TEST_TIMEOUT_SEC = 2

# Nested-quantifier heuristic. Catches the classic catastrophic-backtracking
# shapes where a quantified group's BODY is itself a single quantified atom (or
# an alternation of such atoms) with no required literal boundary separating
# iterations — the exponential-backtracking signature:
#   (a+)+   (a*)*   (a+)*   ([ab]+)+   (\w+)+   (a|aa)+   (a+|b+)*
#
# It deliberately does NOT flag a quantified group whose body is a SEQUENCE
# containing a required, non-quantified separator, e.g. `(-[rf]+\s+)+` or
# `(-[uvzn\s]+)*` — there each iteration is anchored by structure, so it cannot
# blow up (verified empirically: those run sub-millisecond on adversarial input,
# while `(a+)+$` takes ~76s on 30 chars). Over-flagging real scanner patterns
# would block legitimate extraction in U3-U5, so the heuristic targets the
# precise dangerous shape rather than "any nested quantifier".
#
# Body grammar accepted as a "quantified atom": a char class `[...]`, an escape
# `\w`, or a literal char, optionally followed by a quantifier; branches joined
# by `|`. The whole body must be quantified atoms only (plus the outer quantifier).
_QUANT_ATOM = r"""(?: \\.|\[[^\]]*\]|[^()\[\]|*+?{}\\] ) [*+]? """
_NESTED_QUANT_RE = re.compile(
    r"""
    \(                          # group open
        (?: \?P?[<][^>]*> | \?: )?   # optional named/non-capturing prefix
        \s*
        """ + _QUANT_ATOM + r"""    # first atom (quantified)
        (?:                         # zero+ more atoms, all alternation branches
            \s* \| \s* """ + _QUANT_ATOM + r"""
        )*
    \)                          # group close
    \s*
    [*+]                        # ... and the GROUP itself is quantified
    """,
    re.VERBOSE,
)

# A quantified group whose body is a bare alternation (no inner quantifiers),
# e.g. `(a|aa)+`. Captures the alternation body so _looks_catastrophic can test
# whether any branch is a prefix of another (the overlap that makes it explode).
_ALT_GROUP_RE = re.compile(
    r"\((?:\?P?<[^>]*>|\?:)?\s*(?P<body>[^()]*\|[^()]*)\)\s*[*+]"
)


def _looks_catastrophic(pattern):
    """Best-effort static detection of catastrophic-backtracking shapes.

    Returns a non-empty reason string if the pattern looks dangerous, else "".
    Platform-independent; complements (does not replace) the hard timeout, which
    is the real backstop for shapes a static heuristic can't see.
    """
    if len(pattern) > MAX_PATTERN_LENGTH:
        return f"pattern length {len(pattern)} exceeds cap {MAX_PATTERN_LENGTH}"
    m = _NESTED_QUANT_RE.search(pattern)
    if m:
        # Only dangerous if an inner atom is itself quantified (overlap), i.e.
        # the matched body contains a `+`/`*` quantifier before the group
        # close. A bare `(abc)+` is fine; `(a+)+` is not.
        body = m.group(0)
        inner = body[:body.rfind(")")]
        if re.search(r"[*+]", inner):
            return "nested-quantifier shape (potential catastrophic backtracking)"
    # Overlapping-alternation inside a quantified group, e.g. `(a|aa)+` where one
    # branch is a prefix of another — an exponential shape with no inner
    # quantifier. Conservative: only flags simple-literal branches that share a
    # prefix, so `(?:foo|bar)+` (disjoint) is left alone. The hard timeout is the
    # backstop for anything subtler than this.
    for g in _ALT_GROUP_RE.finditer(pattern):
        branches = [b.strip() for b in g.group("body").split("|")]
        if len(branches) >= 2 and all(re.fullmatch(r"[^()\[\]|*+?{}\\]+", b or "x") for b in branches):
            for i in range(len(branches)):
                for j in range(len(branches)):
                    if i != j and branches[j] and branches[i].startswith(branches[j]):
                        return "overlapping-alternation in quantified group (potential catastrophic backtracking)"
    return ""


# --- Timeout wrapper (platform-branched) ------------------------------------

_HAS_SIGALRM = hasattr(signal, "SIGALRM")


class RuleTestTimeout(Exception):
    """Raised when a rule's self-test exceeds SELF_TEST_TIMEOUT_SEC."""


def run_with_timeout(func, timeout=SELF_TEST_TIMEOUT_SEC):
    """Run `func()` under a hard wall-clock timeout, returning its result.

    Raises RuleTestTimeout if the budget is exceeded.

    POSIX (signal.SIGALRM available) — SAVE-AND-RESTORE style:
        We read the caller's pending alarm via `prev = signal.alarm(t)`. This
        is critical: refresh_threat_dbs.py arms its own 60s SIGALRM hard cap
        and THEN calls the feed updater, which (in U6) calls this loader's
        self-test. If we naively set/clear our alarm we would clobber that 60s
        cap. So in a `finally` we restore the caller's alarm to
        `max(1, prev - elapsed)` (or 0 if the caller had none). We also save and
        restore the previous SIGALRM handler.

    Windows / no SIGALRM — threading.Timer watchdog fallback:
        A daemon timer raises in the worker is not possible cleanly across
        threads, so we run `func` in the calling thread, start a Timer that
        sets a flag + interrupts via a cooperative check, and additionally cap
        by measuring elapsed time after the call. This is a WEAKER guarantee: a
        truly wedged C-level regexp match in CPython holds the GIL and the timer
        callback cannot preempt it. The static heuristic + length cap above are
        the real protection on this platform; the timer catches the common case
        and the post-hoc elapsed check rejects anything that overran.
    """
    if _HAS_SIGALRM:
        return _run_with_sigalrm(func, timeout)
    return _run_with_timer(func, timeout)


def _run_with_sigalrm(func, timeout):
    t = max(1, int(round(timeout)))

    def _handler(signum, frame):
        del signum, frame  # required by signal.signal contract; unused
        raise RuleTestTimeout(f"self-test exceeded {t}s (SIGALRM)")

    start = time.monotonic()
    prev_handler = signal.getsignal(signal.SIGALRM)
    # Arm OUR alarm; `prev` is the caller's remaining seconds (0 if none).
    prev = signal.alarm(0)  # read + clear caller's alarm without losing it
    signal.signal(signal.SIGALRM, _handler)
    signal.alarm(t)
    try:
        return func()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, prev_handler)
        # Restore the caller's hard cap, debited for the time we consumed.
        if prev > 0:
            elapsed = int(time.monotonic() - start)
            signal.alarm(max(1, prev - elapsed))
        # prev == 0 -> caller had no alarm; leave it disarmed.


def _run_with_timer(func, timeout):
    # No SIGALRM (Windows). We cannot preempt a wedged match holding the GIL, so
    # this is a weaker, advisory guard documented above. We run, then enforce a
    # post-hoc elapsed-time rejection; the Timer flag covers the cooperative case.
    timed_out = {"flag": False}

    def _trip():
        timed_out["flag"] = True

    timer = threading.Timer(timeout, _trip)
    timer.daemon = True
    start = time.monotonic()
    timer.start()
    try:
        result = func()
    finally:
        timer.cancel()
    elapsed = time.monotonic() - start
    if timed_out["flag"] or elapsed > timeout:
        raise RuleTestTimeout(
            f"self-test exceeded {timeout}s (timer fallback, elapsed {elapsed:.2f}s)"
        )
    return result


# --- Compiled structures ----------------------------------------------------

class CompiledRule:
    """One compiled, validated rule.

    Attributes (always present):
        id, type, title, severity, confidence, category, explanation
    Type-specific (exactly one set is meaningful per `type`):
        regex      -> .regex (compiled), .extensions (tuple or None)
        keyword    -> .values (tuple of NFKC-normalized lowercase strings)
        charset    -> .codepoints (frozenset[int])
        map        -> .mapping (dict[str, str])
    Plus .examples (dict with "match"/"no_match" lists) for self-testing.
    """

    __slots__ = (
        "id", "type", "title", "severity", "confidence", "category",
        "explanation", "examples", "regex", "extensions", "values",
        "codepoints", "mapping",
    )

    def __init__(self, *, id, type, title, severity, confidence, category,
                 explanation, examples, regex=None, extensions=None,
                 values=None, codepoints=None, mapping=None):
        self.id = id
        self.type = type
        self.title = title
        self.severity = severity
        self.confidence = confidence
        self.category = category
        self.explanation = explanation
        self.examples = examples or {"match": [], "no_match": []}
        self.regex = regex
        self.extensions = extensions  # tuple[str] or None (regex only)
        self.values = values          # tuple[str] (keyword)
        self.codepoints = codepoints  # frozenset[int] (charset)
        self.mapping = mapping        # dict[str, str] (map)

    def __repr__(self):
        return f"<CompiledRule {self.id} type={self.type} sev={self.severity}>"


class CompiledPack:
    """A loaded, validated rule pack.

    Public surface consumed by scanners:
        .name           pack name (str)
        .pack_version   strictly-increasing integer
        .schema_version source schema string
        .source_path    install-dir or cache path it loaded from
        .all_rules      list[CompiledRule]  (flat — secrets/skill_threats/mcp)
        .by_extension   dict[str, list[CompiledRule]]  (regex rules, pre-indexed;
                        an empty-string key "" holds extension-agnostic regex
                        rules that apply to every file)
        .keyword_rules  list[CompiledRule]  (type == "keyword")
        .charset_rules  list[CompiledRule]  (type == "charset")
        .map_rules      list[CompiledRule]  (type == "map")
        .rules_for_extension(ext) -> list[CompiledRule]  (regex rules that apply
                        to `ext`: extension-agnostic rules + ext-gated ones)
    """

    def __init__(self, name, pack_version, schema_version, source_path, rules):
        self.name = name
        self.pack_version = pack_version
        self.schema_version = schema_version
        self.source_path = source_path
        self.all_rules = list(rules)

        self.by_extension = {}
        self.keyword_rules = []
        self.charset_rules = []
        self.map_rules = []

        for rule in self.all_rules:
            if rule.type == "regex":
                exts = rule.extensions if rule.extensions else ("",)
                for ext in exts:
                    self.by_extension.setdefault(ext, []).append(rule)
            elif rule.type == "keyword":
                self.keyword_rules.append(rule)
            elif rule.type == "charset":
                self.charset_rules.append(rule)
            elif rule.type == "map":
                self.map_rules.append(rule)

    def rules_for_extension(self, ext):
        """Regex rules applicable to files with extension `ext`.

        Returns extension-agnostic regex rules (key "") plus rules gated to
        `ext`. The SAST hot loop calls this once per file, so it stays
        O(rules-for-ext), never O(all-rules) per line.
        """
        out = list(self.by_extension.get("", ()))
        if ext and ext != "":
            out.extend(self.by_extension.get(ext, ()))
        return out

    def __repr__(self):
        return (f"<CompiledPack {self.name} v{self.pack_version} "
                f"rules={len(self.all_rules)}>")


# --- Validation / compilation -----------------------------------------------

def _warn(msg):
    print(f"[rule_loader] {msg}", file=sys.stderr)


def _normalize_keyword(s):
    """NFKC-normalize + lowercase a keyword value for substring matching."""
    return unicodedata.normalize("NFKC", s).lower()


def _parse_codepoint(v):
    """Accept an int codepoint or a 'U+XXXX'/'0xXXXX' string -> int, or None."""
    if isinstance(v, bool):
        return None  # bool is an int subclass; reject explicitly
    if isinstance(v, int):
        return v if 0 <= v <= 0x10FFFF else None
    if isinstance(v, str):
        s = v.strip()
        try:
            if s[:2].upper() == "U+":
                return int(s[2:], 16)
            if s[:2].lower() == "0x":
                return int(s, 16)
            # Single literal character is also acceptable.
            if len(s) == 1:
                return ord(s)
            return int(s)
        except (ValueError, IndexError):
            return None
    return None


def _compile_rule(raw):
    """Validate + compile one raw rule dict into a CompiledRule.

    Returns (CompiledRule, None) on success or (None, reason) on rejection.
    Structurally-invalid rules are skipped by the caller with a warning; they
    never crash the scanner (KTD-4 runtime-load granularity).
    """
    if not isinstance(raw, dict):
        return None, "rule is not an object"

    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        return None, "missing/empty 'id'"

    if raw.get("retired") is True:
        return None, f"{rule_id}: retired"

    rtype = raw.get("type")
    if rtype not in _RULE_TYPES:
        return None, f"{rule_id}: invalid type {rtype!r}"

    severity = raw.get("severity", "medium")
    if not isinstance(severity, str):
        return None, f"{rule_id}: severity must be a string"
    if severity not in _KNOWN_SEVERITIES:
        _warn(f"{rule_id}: unknown severity {severity!r} (kept as-is)")

    confidence = raw.get("confidence", 0.0)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        return None, f"{rule_id}: confidence not a number"
    if confidence < 0.0:
        confidence = 0.0
    elif confidence > 1.0:
        confidence = 1.0

    title = raw.get("title", rule_id)
    category = raw.get("category", "")
    explanation = raw.get("explanation", "")
    examples = raw.get("examples", {}) or {}
    if not isinstance(examples, dict):
        examples = {}
    examples = {
        "match": [e for e in examples.get("match", []) if isinstance(e, str)],
        "no_match": [e for e in examples.get("no_match", []) if isinstance(e, str)],
    }

    common = dict(
        id=rule_id, type=rtype, title=str(title), severity=severity,
        confidence=confidence, category=str(category),
        explanation=str(explanation), examples=examples,
    )

    if rtype == "regex":
        pattern = raw.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            return None, f"{rule_id}: regex rule missing 'pattern'"
        catastrophic = _looks_catastrophic(pattern)
        if catastrophic:
            return None, f"{rule_id}: rejected ({catastrophic})"
        flagval = 0
        for f in raw.get("flags", []) or []:
            if f in _ALLOWED_REGEX_FLAGS:
                flagval |= _ALLOWED_REGEX_FLAGS[f]
            else:
                _warn(f"{rule_id}: ignoring unknown regex flag {f!r}")
        try:
            compiled = re.compile(pattern, flagval)
        except re.error as e:
            return None, f"{rule_id}: re.error ({e})"
        exts = raw.get("extensions")
        if exts is not None:
            if not isinstance(exts, list):
                return None, f"{rule_id}: 'extensions' must be a list"
            exts = tuple(e for e in exts if isinstance(e, str) and e)
            if not exts:
                exts = None
        return CompiledRule(regex=compiled, extensions=exts, **common), None

    if rtype == "keyword":
        values = raw.get("values")
        if not isinstance(values, list) or not values:
            return None, f"{rule_id}: keyword rule missing non-empty 'values'"
        norm = tuple(_normalize_keyword(v) for v in values if isinstance(v, str) and v)
        if not norm:
            return None, f"{rule_id}: keyword rule has no usable values"
        return CompiledRule(values=norm, **common), None

    if rtype == "charset":
        values = raw.get("values")
        if not isinstance(values, list) or not values:
            return None, f"{rule_id}: charset rule missing non-empty 'values'"
        cps = set()
        for v in values:
            cp = _parse_codepoint(v)
            if cp is None:
                return None, f"{rule_id}: invalid codepoint {v!r}"
            cps.add(cp)
        return CompiledRule(codepoints=frozenset(cps), **common), None

    if rtype == "map":
        mapping = raw.get("mapping")
        if not isinstance(mapping, dict) or not mapping:
            return None, f"{rule_id}: map rule missing non-empty 'mapping'"
        clean = {k: v for k, v in mapping.items()
                 if isinstance(k, str) and isinstance(v, str)}
        if not clean:
            return None, f"{rule_id}: map rule has no usable mapping entries"
        return CompiledRule(mapping=clean, **common), None

    return None, f"{rule_id}: unhandled type {rtype!r}"  # pragma: no cover


# --- Self-test runner (reused by U6 feed verifier) --------------------------

class RuleTestResult:
    """Per-rule self-test outcome. Reusable by U6's feed verifier (don't assert
    inside the runner — return structured results so callers decide policy)."""

    __slots__ = ("rule_id", "passed", "failures")

    def __init__(self, rule_id, passed, failures):
        self.rule_id = rule_id
        self.passed = passed
        self.failures = failures  # list[str] of human-readable failure reasons

    def __repr__(self):
        status = "PASS" if self.passed else "FAIL"
        return f"<RuleTestResult {self.rule_id} {status} ({len(self.failures)} issues)>"


def _rule_matches(rule, text):
    """Does `rule` match `text`? Mirrors how scanners will consume each type."""
    if rule.type == "regex":
        return rule.regex.search(text) is not None
    if rule.type == "keyword":
        norm = _normalize_keyword(text)
        return any(v in norm for v in rule.values)
    if rule.type == "charset":
        return any(ord(ch) in rule.codepoints for ch in text)
    if rule.type == "map":
        return any(ch in rule.mapping for ch in text)
    return False  # pragma: no cover


def run_rule_self_test(rule, timeout=SELF_TEST_TIMEOUT_SEC):
    """Execute one rule's embedded match/no_match examples under a hard timeout.

    Returns a RuleTestResult. A rule whose `match` example does NOT match, or
    whose `no_match` example DOES match, fails (with the offending example named
    in .failures). A rule whose evaluation times out (catastrophic backtracking)
    fails with a timeout failure — the caller rejects it like a structurally
    invalid rule.

    This is the shared verifier: U6's whole-bundle feed acceptance reuses it.
    """
    failures = []
    try:
        def _do():
            local = []
            for ex in rule.examples.get("match", []):
                if not _rule_matches(rule, ex):
                    local.append(f"match example did not match: {ex!r}")
            for ex in rule.examples.get("no_match", []):
                if _rule_matches(rule, ex):
                    local.append(f"no_match example matched: {ex!r}")
            return local
        failures = run_with_timeout(_do, timeout=timeout)
    except RuleTestTimeout as e:
        failures = [f"self-test timeout: {e}"]
    return RuleTestResult(rule.id, not failures, failures)


def self_test_pack(pack, timeout=SELF_TEST_TIMEOUT_SEC):
    """Run every rule's self-test in a pack. Returns list[RuleTestResult].

    Pure data-out, no assertions — U6's feed verifier and the loader's
    own load-time validation both consume this.
    """
    return [run_rule_self_test(r, timeout=timeout) for r in pack.all_rules]


# --- Path discipline --------------------------------------------------------

# Install-dir rule packs live next to this script's parent: scripts/../data/rulepacks.
# Anchored via realpath(__file__) to resolve the ~/.claude/skills symlink — never
# from CWD, never relative, never from a scan target.
_INSTALL_RULEPACK_DIR = os.path.normpath(
    os.path.join(_SCRIPTS_DIR, "..", "data", "rulepacks")
)

# Cache overlay dir (U6 signed-feed overlay). The verified bundle written by
# rulepack_feed.accept_bundle lives here as bundle.json + bundle.json.sig.
# load_pack re-verifies the signature on EVERY load (KTD-12) and overlays a pack
# only when its cached pack_version is strictly newer than the shipped pack AND
# the schema major matches AND every example self-test passes.
CACHE_RULEPACK_DIR = os.path.join(
    os.path.expanduser("~"), ".cache", "repo-forensics", "rulepacks"
)
_CACHE_BUNDLE_FILE = "bundle.json"
_CACHE_BUNDLE_SIG_FILE = "bundle.json.sig"

# rule-pack-degraded flag (DISTINCT from ioc_manager's _ioc_degraded, KTD-11).
# Set True whenever a cache bundle exists but fails verification/overlay, so the
# scanner can surface a rule-pack-specific warning. Reset to False each time the
# overlay verifies cleanly or no cache is present at all.
_RULEPACK_DEGRADED = False
# Overlay log: human-readable notes about what the last overlay attempt did
# (which packs overlaid, any shipped-active rule arriving retired:true, any
# rejection reason). Surfaced by callers; never raises.
_OVERLAY_LOG = []


def get_rulepack_degraded():
    """True iff a rule-pack cache bundle is present but failed verification or
    overlay (tampered / invalid signature / rollback). Callers surface a
    rule-pack-degraded warning, distinct from the IOC-degraded message."""
    return _RULEPACK_DEGRADED


def get_overlay_log():
    """Return a copy of the most recent overlay log lines (diagnostics)."""
    return list(_OVERLAY_LOG)


def _set_degraded(value):
    global _RULEPACK_DEGRADED
    _RULEPACK_DEGRADED = bool(value)


def _overlay_note(msg):
    _OVERLAY_LOG.append(msg)


# Process-lifetime memo for the cache-bundle signature verification keyed on
# (path, mtime, size) so repeated loads in one process don't re-verify the same
# bytes needlessly (~5-20ms each, ~20 verifies per scan otherwise). KTD-12.
_BUNDLE_VERIFY_MEMO = {}


def _reset_overlay_state():
    """Test helper: clear overlay memo + degraded flag + log."""
    _BUNDLE_VERIFY_MEMO.clear()
    _OVERLAY_LOG.clear()
    _set_degraded(False)


def _verified_cache_bundle(cache_dir=None):
    """Read + verify the cached signed bundle. Returns the parsed bundle dict on
    success, or None (and sets the degraded flag) on any failure.

    Verify-on-load (KTD-12): the signature is checked over the EXACT cached raw
    bytes EVERY call — the cache is writable by any same-user process (the
    postinstall-malware class this tool detects). Memoized per (path, mtime,
    size); a tamper changes mtime/size and busts the memo, forcing a re-verify
    that then fails.
    """
    root = cache_dir if cache_dir is not None else CACHE_RULEPACK_DIR
    bundle_path = os.path.join(root, _CACHE_BUNDLE_FILE)
    sig_path = os.path.join(root, _CACHE_BUNDLE_SIG_FILE)
    if not (os.path.isfile(bundle_path) and os.path.isfile(sig_path)):
        return None  # no cache at all -> not degraded, shipped is the norm
    try:
        st = os.stat(bundle_path)
        memo_key = (bundle_path, st.st_mtime, st.st_size)
    except OSError:
        _set_degraded(True)
        return None
    if memo_key in _BUNDLE_VERIFY_MEMO:
        return _BUNDLE_VERIFY_MEMO[memo_key]
    try:
        with open(bundle_path, "rb") as f:
            raw = f.read()
        with open(sig_path, "rb") as f:
            sig = f.read()
    except OSError:
        _set_degraded(True)
        return None
    # Import the verify chokepoint lazily (rulepack_feed -> _ed25519). KTD-14:
    # rulepack_feed/_ed25519 do NOT import rule_loader's aggregation consumers,
    # so this stays leaf-safe (it is the feed/crypto layer, not aggregation).
    try:
        import rulepack_feed
        ok = rulepack_feed.verify_raw_bundle(raw, sig)
    except Exception as e:  # never let a feed-module issue crash a scan
        _warn(f"cache bundle verify error: {e}")
        ok = False
    if not ok:
        _warn("cached rule-pack bundle signature INVALID — ignoring cache, "
              "using shipped packs (rule-pack-degraded)")
        _set_degraded(True)
        _BUNDLE_VERIFY_MEMO[memo_key] = None
        return None
    try:
        bundle = json.loads(raw.decode("utf-8"))
        if not isinstance(bundle, dict):
            raise ValueError("bundle top-level not an object")
    except (ValueError, UnicodeDecodeError) as e:
        _warn(f"cached rule-pack bundle parse error after verify: {e}")
        _set_degraded(True)
        _BUNDLE_VERIFY_MEMO[memo_key] = None
        return None
    _BUNDLE_VERIFY_MEMO[memo_key] = bundle
    return bundle


def _compiled_pack_from_bundle_entry(name, entry, source_path):
    """Compile a pack from a verified-bundle entry into a CompiledPack, running
    every rule's self-test. Returns (CompiledPack, None) or (None, reason).
    Whole-pack acceptance: ANY self-test failure rejects the overlay for this
    pack (shipped stays authoritative)."""
    if not isinstance(entry, dict):
        return None, "bundle entry not an object"
    schema_version = entry.get("schema_version", RULEPACK_SCHEMA_VERSION)
    if not isinstance(schema_version, str):
        return None, "schema_version not a string"
    major = schema_version.split(".")[0] if schema_version else ""
    if major != RULEPACK_SCHEMA_VERSION.split(".")[0]:
        return None, f"schema major mismatch ({schema_version!r})"
    pack_version = entry.get("pack_version", 0)
    if isinstance(pack_version, bool) or not isinstance(pack_version, int):
        return None, "pack_version not an integer"
    raw_rules = entry.get("rules", [])
    if not isinstance(raw_rules, list):
        return None, "rules not a list"
    compiled = []
    seen = set()
    retired_ids = set()
    for raw in raw_rules:
        rule, reason = _compile_rule(raw)
        if rule is None:
            if reason and reason.endswith(": retired"):
                # Track retired ids so the overlay can flag silent removal of a
                # shipped-active rule (silent-detection-removal guard, KTD-6).
                rid = raw.get("id") if isinstance(raw, dict) else None
                if isinstance(rid, str) and rid:
                    retired_ids.add(rid)
                continue
            return None, f"rule rejected: {reason}"
        if rule.id in seen:
            continue
        seen.add(rule.id)
        result = run_rule_self_test(rule)
        if not result.passed:
            return None, (f"rule {rule.id} self-test failed: "
                          f"{'; '.join(result.failures)}")
        compiled.append(rule)
    cp = CompiledPack(name, pack_version, schema_version, source_path, compiled)
    cp._retired_ids = retired_ids  # attached for the silent-removal diff
    return cp, None


def _pack_search_paths(name, base_dir=None):
    """Resolve the candidate file path(s) for a pack `name`, in priority order.

    Security: every path is derived ONLY from realpath-anchored install dir (or
    an explicit `base_dir` passed by tests/U6), never from CWD or scan target.
    The pack name is sanitized to a bare filename so '../' traversal is
    impossible.

    U6 seam: when overlay support lands, the verified CACHE_RULEPACK_DIR is
    consulted here (newer pack_version + valid signature wins). For U2 we only
    return the install-dir path (or base_dir override).
    """
    safe = os.path.basename(str(name))
    if not safe or safe in (".", ".."):
        return []
    if not safe.endswith(".json"):
        safe = safe + ".json"
    root = base_dir if base_dir is not None else _INSTALL_RULEPACK_DIR
    return [os.path.join(root, safe)]


# --- Loading + memoization --------------------------------------------------

# Process-lifetime memo keyed on (resolved path, mtime). One process never
# parses the same pack file twice. Keyed on path (not just name) so a base_dir
# override or a future cache overlay is a distinct cache entry.
_PACK_CACHE = {}


def _reset_pack_cache():
    """Test helper: force a fresh parse on the next load_pack call."""
    _PACK_CACHE.clear()


class SchemaIncompatibleError(Exception):
    """Raised when a pack's schema major version is incompatible. Callers treat
    this as 'use the shipped fallback' (return None at the call site)."""


def _load_pack_file(path):
    """Parse + validate + compile a single pack file at `path`.

    Returns a CompiledPack. Raises:
        FileNotFoundError      - path missing
        SchemaIncompatibleError - major schema mismatch (whole-pack reject)
        ValueError              - structurally invalid top-level shape
    Individually-invalid rules are skipped with a stderr warning, never fatal.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level must be a JSON object")

    # Schema major-version gate (mirror ioc_manager.py).
    schema_version = data.get("schema_version", "")
    if not isinstance(schema_version, str):
        raise SchemaIncompatibleError(
            f"{path}: schema_version must be a string, "
            f"got {type(schema_version).__name__}"
        )
    major = schema_version.split(".")[0] if schema_version else ""
    expected_major = RULEPACK_SCHEMA_VERSION.split(".")[0]
    if major != expected_major:
        raise SchemaIncompatibleError(
            f"{path}: schema version {schema_version!r} incompatible with "
            f"expected {RULEPACK_SCHEMA_VERSION!r}"
        )

    # pack_version is a strictly-increasing INTEGER (feed overlay comparison in
    # U6 uses explicit int comparison — no semver/string ambiguity per KTD-13).
    pack_version = data.get("pack_version", 0)
    if isinstance(pack_version, bool) or not isinstance(pack_version, int):
        raise ValueError(f"{path}: pack_version must be an integer")

    name = data.get("pack")
    if not isinstance(name, str) or not name:
        name = os.path.splitext(os.path.basename(path))[0]

    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError(f"{path}: 'rules' must be a list")

    compiled = []
    seen_ids = set()
    for raw in raw_rules:
        rule, reason = _compile_rule(raw)
        if rule is None:
            # Retired rules are an expected, silent skip; everything else warns.
            if not (reason and reason.endswith(": retired")):
                _warn(f"skipping rule in {os.path.basename(path)}: {reason}")
            continue
        if rule.id in seen_ids:
            _warn(f"duplicate rule id {rule.id} in {os.path.basename(path)}; "
                  f"keeping first")
            continue
        seen_ids.add(rule.id)
        # Runtime-load self-test granularity (KTD-4): a rule whose embedded
        # example fails (including a catastrophic-backtracking timeout) is
        # skipped individually, never crashing the scanner.
        result = run_rule_self_test(rule)
        if not result.passed:
            _warn(f"skipping rule {rule.id} ({os.path.basename(path)}): "
                  f"self-test failed: {'; '.join(result.failures)}")
            continue
        compiled.append(rule)

    return CompiledPack(name, pack_version, schema_version, path, compiled)


def _maybe_overlay(name, shipped, cache_dir=None):
    """Given the shipped CompiledPack for `name`, return the overlay pack from
    the verified cache bundle IF it is strictly newer and fully valid; otherwise
    return the shipped pack unchanged (shipped authoritative, KTD-6).

    Verifies the cache bundle's signature on every call (KTD-12, memoized).
    """
    bundle = _verified_cache_bundle(cache_dir)
    if bundle is None:
        return shipped  # no cache (or invalid -> degraded flag already set)
    packs = bundle.get("packs", {})
    if not isinstance(packs, dict):
        return shipped
    entry = packs.get(name)
    if not isinstance(entry, dict):
        return shipped  # bundle doesn't carry this pack
    entry_version = entry.get("pack_version", 0)
    shipped_version = shipped.pack_version if shipped is not None else -1
    if not isinstance(entry_version, int) or isinstance(entry_version, bool):
        return shipped
    if entry_version <= shipped_version:
        return shipped  # equal/older ignored — shipped stays authoritative
    overlay, reason = _compiled_pack_from_bundle_entry(
        name, entry, os.path.join(
            cache_dir if cache_dir is not None else CACHE_RULEPACK_DIR,
            _CACHE_BUNDLE_FILE)
    )
    if overlay is None:
        _warn(f"rule-pack overlay for {name!r} rejected: {reason} "
              f"(shipped v{shipped_version} stays authoritative)")
        _overlay_note(f"{name}: overlay REJECTED ({reason})")
        _set_degraded(True)
        return shipped
    # Silent-detection-removal guard (KTD-6): a shipped-ACTIVE rule arriving
    # retired:true in the overlay is surfaced, never silent.
    retired = getattr(overlay, "_retired_ids", set())
    if shipped is not None and retired:
        shipped_active = {r.id for r in shipped.all_rules}
        silenced = sorted(shipped_active & retired)
        for rid in silenced:
            _overlay_note(
                f"{name}: shipped-active rule {rid} retired by overlay "
                f"v{entry_version} (silent-detection-removal guard)")
            _warn(f"overlay retires shipped-active rule {rid} in pack {name!r}")
    _overlay_note(f"{name}: overlaid shipped v{shipped_version} -> v{entry_version}")
    return overlay


def load_pack(name, base_dir=None, cache_dir=None):
    """Load a rule pack by name. Returns a CompiledPack, or None if no pack file
    exists or the pack is schema-incompatible (caller falls back to shipped
    behavior).

    `base_dir` is a documented test/U6 seam: when supplied, packs resolve from
    that directory instead of the install dir. It is still resolved as an
    explicit absolute path — it is NEVER derived from a scan target or CWD.

    `cache_dir` overrides the signed-feed cache location (test seam). The
    verified cache bundle overlays a shipped pack only when strictly newer +
    valid (KTD-6); its signature is re-verified on every load (KTD-12).

    Memoized per (resolved path, mtime): one process never parses a pack twice.
    """
    for path in _pack_search_paths(name, base_dir=base_dir):
        if not os.path.isfile(path):
            continue
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        cache_key = (path, mtime)
        if cache_key in _PACK_CACHE:
            shipped = _PACK_CACHE[cache_key]
        else:
            try:
                shipped = _load_pack_file(path)
            except SchemaIncompatibleError as e:
                _warn(f"{e} — falling back to shipped behavior")
                return None
            except (OSError, ValueError, json.JSONDecodeError) as e:
                _warn(f"could not load pack {name!r}: {e}")
                return None
            _PACK_CACHE[cache_key] = shipped
        # Overlay seam: a base_dir override (tests loading a single pack file)
        # bypasses the cache overlay entirely — the override IS the source of
        # truth. The signed-feed overlay only applies to install-dir loads.
        if base_dir is not None:
            return shipped
        return _maybe_overlay(name, shipped, cache_dir=cache_dir)
    return None


# --- CLI (dev convenience: self-test a pack) --------------------------------

def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: rule_loader.py <pack-name|path-to-pack.json>", file=sys.stderr)
        return 2
    target = argv[0]
    if os.path.isfile(target):
        base_dir = os.path.dirname(os.path.abspath(target))
        name = os.path.basename(target)
    else:
        base_dir = None
        name = target
    pack = load_pack(name, base_dir=base_dir)
    if pack is None:
        print(f"[rule_loader] pack {target!r} not found or incompatible",
              file=sys.stderr)
        return 1
    results = self_test_pack(pack)
    failed = [r for r in results if not r.passed]
    print(f"pack={pack.name} v{pack.pack_version} rules={len(pack.all_rules)} "
          f"self-test: {len(results) - len(failed)} pass, {len(failed)} fail")
    for r in failed:
        print(f"  FAIL {r.rule_id}: {'; '.join(r.failures)}", file=sys.stderr)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
