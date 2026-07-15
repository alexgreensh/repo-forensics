"""
Tests for rule_loader.py (Unit U2).

Covers: valid pack load + compile + metadata round-trip, by_extension index,
schema major-version wholesale rejection, malformed-regex single-rule skip,
self-test failure naming the rule id, charset/map/keyword compilation +
NFKC normalization, extension gating, mandatory ReDoS guards (heuristic AND
hard-timeout, BOTH the POSIX SIGALRM path and the simulated no-SIGALRM threading
fallback), hostile-path discipline, and coarse load-time perf.

The fixture packs are written to a tmp dir per-test and loaded via the
documented `base_dir` seam — they are NEVER shipped in data/rulepacks/ (U3
ships the first real packs).
"""

import math as _math
import os
import sys
import json
import time
import importlib

import pytest

SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
)
sys.path.insert(0, SCRIPTS_DIR)

import rule_loader  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_pack_cache():
    """Each test gets a fresh module-level pack cache."""
    rule_loader._reset_pack_cache()
    yield
    rule_loader._reset_pack_cache()


def _write_pack(dir_path, name, pack_dict):
    path = os.path.join(dir_path, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(pack_dict, f)
    return path


def _base_pack(**overrides):
    pack = {
        "schema_version": "1.0",
        "generated": "2026-06-10",
        "pack": "fixture",
        "pack_version": 1,
        "rules": [],
    }
    pack.update(overrides)
    return pack


def _regex_rule(id="SC-GEN-001", pattern=r"AKIA[A-Z0-9]{16}", **kw):
    rule = {
        "id": id,
        "type": "regex",
        "pattern": pattern,
        "title": "AWS Access Key",
        "severity": "critical",
        "confidence": 0.95,
        "category": "secret",
        "explanation": "Looks like an AWS access key id.",
        "examples": {
            "match": ["AKIAIOSFODNN7EXAMPLE"],
            "no_match": ["not a key", "AKIA"],
        },
    }
    rule.update(kw)
    return rule


# --- Valid load + compile + index -------------------------------------------

def test_valid_pack_loads_and_compiles(tmp_path):
    pack_dict = _base_pack(rules=[
        _regex_rule(id="SC-GEN-001"),
        _regex_rule(id="SC-GEN-002", pattern=r"sk-[a-zA-Z0-9]{20}",
                    title="OpenAI Key",
                    examples={"match": ["sk-abcdefghijklmnopqrst"],
                              "no_match": ["sk-short"]}),
    ])
    _write_pack(str(tmp_path), "fixture", pack_dict)
    pack = rule_loader.load_pack("fixture", base_dir=str(tmp_path))

    assert pack is not None
    assert pack.name == "fixture"
    assert pack.pack_version == 1
    assert len(pack.all_rules) == 2

    r = pack.all_rules[0]
    assert r.id == "SC-GEN-001"
    assert r.severity == "critical"
    assert r.confidence == 0.95
    assert r.category == "secret"
    assert "AWS" in r.title
    assert r.explanation.startswith("Looks like")
    # Compiled regex actually works.
    assert r.regex.search("AKIAIOSFODNN7EXAMPLE")
    assert not r.regex.search("nothing here")


def test_by_extension_index_and_rules_for_extension(tmp_path):
    pack_dict = _base_pack(rules=[
        _regex_rule(id="SA-GEN-001", pattern=r"\beval\(", extensions=[".py"],
                    title="eval", severity="high", confidence=0.8,
                    examples={"match": ["eval("], "no_match": ["evaluate"]}),
        _regex_rule(id="SA-GEN-002", pattern=r"\brequire\(", extensions=[".js"],
                    title="require", severity="low", confidence=0.4,
                    examples={"match": ["require("], "no_match": ["required"]}),
        # extension-agnostic rule (no extensions) -> applies everywhere
        _regex_rule(id="SA-GEN-003", pattern=r"TODO", title="todo",
                    severity="low", confidence=0.3,
                    examples={"match": ["TODO"], "no_match": ["done"]}),
    ])
    _write_pack(str(tmp_path), "sast", pack_dict)
    pack = rule_loader.load_pack("sast", base_dir=str(tmp_path))

    assert set(pack.by_extension.keys()) == {".py", ".js", ""}
    py_rules = pack.rules_for_extension(".py")
    py_ids = {r.id for r in py_rules}
    # python gets its own rule + the agnostic one, NOT the .js rule
    assert "SA-GEN-001" in py_ids
    assert "SA-GEN-003" in py_ids
    assert "SA-GEN-002" not in py_ids

    js_ids = {r.id for r in pack.rules_for_extension(".js")}
    assert js_ids == {"SA-GEN-002", "SA-GEN-003"}


def test_all_rules_complete(tmp_path):
    rules = [_regex_rule(id=f"SC-GEN-{i:03d}",
                         examples={"match": ["AKIAIOSFODNN7EXAMPLE"],
                                   "no_match": ["x"]})
             for i in range(1, 6)]
    _write_pack(str(tmp_path), "many", _base_pack(rules=rules))
    pack = rule_loader.load_pack("many", base_dir=str(tmp_path))
    assert len(pack.all_rules) == 5
    assert {r.id for r in pack.all_rules} == {f"SC-GEN-{i:03d}" for i in range(1, 6)}


# --- Schema gate ------------------------------------------------------------

def test_schema_major_mismatch_rejected_wholesale(tmp_path):
    pack_dict = _base_pack(schema_version="2.0", rules=[_regex_rule()])
    _write_pack(str(tmp_path), "future", pack_dict)
    # Caller-fallback semantics: load_pack returns None -> caller uses shipped.
    pack = rule_loader.load_pack("future", base_dir=str(tmp_path))
    assert pack is None


def test_non_string_schema_version_rejected(tmp_path):
    pack_dict = _base_pack(rules=[_regex_rule()])
    pack_dict["schema_version"] = 1.0  # number, not string
    _write_pack(str(tmp_path), "badschema", pack_dict)
    assert rule_loader.load_pack("badschema", base_dir=str(tmp_path)) is None


def test_minor_version_bump_still_loads(tmp_path):
    pack_dict = _base_pack(schema_version="1.7", rules=[_regex_rule()])
    _write_pack(str(tmp_path), "minor", pack_dict)
    pack = rule_loader.load_pack("minor", base_dir=str(tmp_path))
    assert pack is not None
    assert len(pack.all_rules) == 1


# --- Malformed regex: skip that rule, keep others ---------------------------

def test_malformed_regex_skips_only_that_rule(tmp_path, capsys):
    pack_dict = _base_pack(rules=[
        _regex_rule(id="SC-GEN-001"),
        _regex_rule(id="SC-GEN-002", pattern=r"(unterminated",
                    examples={"match": [], "no_match": []}),
        _regex_rule(id="SC-GEN-003", pattern=r"sk-live",
                    examples={"match": ["sk-live"], "no_match": ["nope"]}),
    ])
    _write_pack(str(tmp_path), "mixed", pack_dict)
    pack = rule_loader.load_pack("mixed", base_dir=str(tmp_path))
    ids = {r.id for r in pack.all_rules}
    assert ids == {"SC-GEN-001", "SC-GEN-003"}  # bad one skipped, others live
    err = capsys.readouterr().err
    assert "SC-GEN-002" in err


# --- Self-test failure names the rule ---------------------------------------

def test_self_test_failure_names_rule_id(tmp_path):
    # A no_match example that actually MATCHES -> self-test failure.
    bad = _regex_rule(id="SC-GEN-009", pattern=r"secret",
                      examples={"match": ["secret here"],
                                "no_match": ["this also has secret"]})
    rule, reason = rule_loader._compile_rule(bad)
    assert rule is not None
    result = rule_loader.run_rule_self_test(rule)
    assert result.passed is False
    assert result.rule_id == "SC-GEN-009"
    assert any("no_match example matched" in f for f in result.failures)


def test_self_test_failure_skips_rule_at_load(tmp_path, capsys):
    good = _regex_rule(id="SC-GEN-001")
    bad = _regex_rule(id="SC-GEN-099", pattern=r"secret",
                      examples={"match": ["has secret"],
                                "no_match": ["also has secret"]})
    _write_pack(str(tmp_path), "selftest", _base_pack(rules=[good, bad]))
    pack = rule_loader.load_pack("selftest", base_dir=str(tmp_path))
    ids = {r.id for r in pack.all_rules}
    assert ids == {"SC-GEN-001"}  # failing-selftest rule dropped
    assert "SC-GEN-099" in capsys.readouterr().err


# --- charset / map / keyword ------------------------------------------------

def test_charset_rule_yields_codepoints(tmp_path):
    rule = {
        "id": "ST-ZW-001", "type": "charset",
        "values": [0x200B, "U+200C", "0x200D", "‮"],
        "title": "zero-width", "severity": "high", "confidence": 0.7,
        "category": "smuggling", "explanation": "invisible chars",
        "examples": {"match": ["a​b"], "no_match": ["plain text"]},
    }
    _write_pack(str(tmp_path), "charset", _base_pack(rules=[rule]))
    pack = rule_loader.load_pack("charset", base_dir=str(tmp_path))
    assert len(pack.charset_rules) == 1
    cps = pack.charset_rules[0].codepoints
    assert 0x200B in cps and 0x200C in cps and 0x200D in cps and 0x202E in cps


def test_map_rule_yields_dict(tmp_path):
    rule = {
        "id": "ST-HG-001", "type": "map",
        "mapping": {"а": "a", "е": "e"},  # cyrillic а,е -> latin
        "title": "homoglyphs", "severity": "medium", "confidence": 0.6,
        "category": "homoglyph", "explanation": "cyrillic lookalikes",
        "examples": {"match": ["pаypal"], "no_match": ["paypal"]},
    }
    _write_pack(str(tmp_path), "map", _base_pack(rules=[rule]))
    pack = rule_loader.load_pack("map", base_dir=str(tmp_path))
    assert len(pack.map_rules) == 1
    m = pack.map_rules[0].mapping
    assert m["а"] == "a" and m["е"] == "e"


def test_keyword_rule_nfkc_normalizes(tmp_path):
    # Fullwidth "ＩＧＮＯＲＥ" NFKC-folds to "ignore"; value stored lowercased.
    rule = {
        "id": "ST-KW-001", "type": "keyword",
        "values": ["IGNORE PREVIOUS", "system prompt"],
        "title": "injection keyword", "severity": "high", "confidence": 0.7,
        "category": "injection", "explanation": "...",
        "examples": {
            "match": ["please ignore previous instructions",
                      "ＩＧＮＯＲＥ previous"],
            "no_match": ["normal text"],
        },
    }
    _write_pack(str(tmp_path), "kw", _base_pack(rules=[rule]))
    pack = rule_loader.load_pack("kw", base_dir=str(tmp_path))
    assert len(pack.keyword_rules) == 1
    kr = pack.keyword_rules[0]
    assert "ignore previous" in kr.values  # lowercased, NFKC-normalized
    # The fullwidth example NFKC-folds and matches.
    assert rule_loader._rule_matches(kr, "ＩＧＮＯＲＥ previous")


# --- ReDoS guards: heuristic + timeout, BOTH platform paths -----------------

def test_catastrophic_pattern_rejected_by_heuristic(tmp_path, capsys):
    # (a+)+ nested quantifier -> static heuristic rejects before any run.
    bad = _regex_rule(id="SC-GEN-666", pattern=r"(a+)+$",
                      examples={"match": ["aaaa"], "no_match": []})
    rule, reason = rule_loader._compile_rule(bad)
    assert rule is None
    assert "nested-quantifier" in reason

    # And at load time it is skipped, not fatal.
    good = _regex_rule(id="SC-GEN-001")
    _write_pack(str(tmp_path), "redos", _base_pack(rules=[good, bad]))
    pack = rule_loader.load_pack("redos", base_dir=str(tmp_path))
    assert {r.id for r in pack.all_rules} == {"SC-GEN-001"}


def test_pattern_length_cap(tmp_path):
    huge = "a" * (rule_loader.MAX_PATTERN_LENGTH + 1)
    rule, reason = rule_loader._compile_rule(
        _regex_rule(id="SC-GEN-777", pattern=huge,
                    examples={"match": [], "no_match": []}))
    assert rule is None
    assert "length" in reason


def _slow_func_factory(seconds):
    def _slow():
        time.sleep(seconds)
        return ["done"]
    return _slow


@pytest.mark.skipif(not rule_loader._HAS_SIGALRM, reason="POSIX-only path")
def test_timeout_posix_sigalrm():
    with pytest.raises(rule_loader.RuleTestTimeout):
        rule_loader.run_with_timeout(_slow_func_factory(3), timeout=1)


@pytest.mark.skipif(not rule_loader._HAS_SIGALRM, reason="POSIX-only path")
def test_posix_save_and_restore_preserves_caller_alarm():
    import signal
    fired = {"hit": False}

    def _outer(signum, frame):
        fired["hit"] = True

    prev = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _outer)
    try:
        # Caller arms a long alarm, THEN runs a self-test under our wrapper.
        signal.alarm(10)
        rule_loader.run_with_timeout(lambda: ["ok"], timeout=1)
        # The caller's alarm must STILL be pending (not clobbered to 0).
        remaining = signal.alarm(0)  # read + clear
        assert remaining > 0, "caller's SIGALRM was clobbered by the wrapper"
        assert remaining <= 10
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, prev)


def test_timeout_threading_fallback_when_no_sigalrm(monkeypatch):
    # Force the Windows / no-SIGALRM branch by simulating absence of SIGALRM.
    monkeypatch.setattr(rule_loader, "_HAS_SIGALRM", False)
    with pytest.raises(rule_loader.RuleTestTimeout):
        rule_loader.run_with_timeout(_slow_func_factory(2), timeout=1)


def test_timeout_threading_fallback_passes_fast_call(monkeypatch):
    monkeypatch.setattr(rule_loader, "_HAS_SIGALRM", False)
    out = rule_loader.run_with_timeout(lambda: ["fast"], timeout=2)
    assert out == ["fast"]


def test_catastrophic_runtime_timeout_rejects_rule(monkeypatch, tmp_path, capsys):
    # A pattern the static heuristic does NOT catch but that backtracks badly,
    # proving the hard timeout (not just the heuristic) is load-bearing.
    # `a?{n}a{n}` style isn't easily authored; instead force a slow self-test by
    # monkeypatching the matcher to sleep, and assert the timeout drops the rule.
    monkeypatch.setattr(rule_loader, "SELF_TEST_TIMEOUT_SEC", 1)

    real_matches = rule_loader._rule_matches

    def _slow_matches(rule, text):
        if rule.id == "SC-GEN-555":
            time.sleep(3)
        return real_matches(rule, text)

    monkeypatch.setattr(rule_loader, "_rule_matches", _slow_matches)

    good = _regex_rule(id="SC-GEN-001")
    slow = _regex_rule(id="SC-GEN-555", pattern=r"slow",
                       examples={"match": ["slow"], "no_match": []})
    _write_pack(str(tmp_path), "slowpack", _base_pack(rules=[good, slow]))
    pack = rule_loader.load_pack("slowpack", base_dir=str(tmp_path))
    assert {r.id for r in pack.all_rules} == {"SC-GEN-001"}
    assert "SC-GEN-555" in capsys.readouterr().err


# --- Path discipline (security) ---------------------------------------------

def test_hostile_cwd_rulepack_is_never_loaded(tmp_path, monkeypatch):
    """A scan target / CWD containing its own data/rulepacks/ must NOT be loaded.
    load_pack resolves only from the install dir (or explicit base_dir)."""
    # Build a hostile scan-target tree with a malicious pack.
    hostile = tmp_path / "scan_target"
    hostile_packs = hostile / "data" / "rulepacks"
    hostile_packs.mkdir(parents=True)
    evil = _base_pack(pack="secrets", rules=[
        _regex_rule(id="EVIL-001", pattern=r"never-loaded",
                    examples={"match": ["never-loaded"], "no_match": []})
    ])
    with open(hostile_packs / "secrets.json", "w", encoding="utf-8") as f:
        json.dump(evil, f)

    # cd into the hostile tree.
    monkeypatch.chdir(str(hostile))
    # With NO base_dir, load_pack must consult only the realpath-anchored install
    # dir (which has no 'secrets' pack yet in U2) -> returns None, never the evil one.
    pack = rule_loader.load_pack("secrets")
    if pack is not None:
        assert "EVIL-001" not in {r.id for r in pack.all_rules}
    # And the resolved search path must be the install dir, not CWD.
    paths = rule_loader._pack_search_paths("secrets")
    assert all(rule_loader._INSTALL_RULEPACK_DIR in p for p in paths)
    assert all(str(hostile) not in p for p in paths)


def test_pack_name_traversal_is_neutralized():
    # '../' and absolute escapes are stripped to a bare basename.
    paths = rule_loader._pack_search_paths("../../../etc/passwd")
    for p in paths:
        assert "etc" not in os.path.dirname(p) or rule_loader._INSTALL_RULEPACK_DIR in p
        assert p.startswith(rule_loader._INSTALL_RULEPACK_DIR)


def test_missing_pack_returns_none(tmp_path):
    assert rule_loader.load_pack("does-not-exist", base_dir=str(tmp_path)) is None


# --- Memoization ------------------------------------------------------------

def test_pack_memoized_within_process(tmp_path):
    _write_pack(str(tmp_path), "memo", _base_pack(rules=[_regex_rule()]))
    p1 = rule_loader.load_pack("memo", base_dir=str(tmp_path))
    p2 = rule_loader.load_pack("memo", base_dir=str(tmp_path))
    assert p1 is p2  # same object, parsed once


# --- Coarse load-time perf (generous ceiling) -------------------------------

def test_load_time_for_200_rule_pack(tmp_path):
    rules = []
    for i in range(1, 201):
        rules.append(_regex_rule(
            id=f"SC-GEN-{i:04d}",
            pattern=rf"token_{i}_[A-Za-z0-9]{{8}}",
            examples={"match": [f"token_{i}_abcd1234"],
                      "no_match": [f"token_{i}_short"]},
        ))
    _write_pack(str(tmp_path), "big", _base_pack(rules=rules))
    start = time.monotonic()
    pack = rule_loader.load_pack("big", base_dir=str(tmp_path))
    elapsed = time.monotonic() - start
    assert len(pack.all_rules) == 200
    # Generous ceiling so a one-CPU CI never flakes. Each rule runs its embedded
    # self-test, so this includes 200 self-tests. 10s is comfortably loose.
    assert elapsed < 10.0, f"200-rule load took {elapsed:.2f}s"


# --- self_test_pack returns structured results (U6 reuse) -------------------

def test_self_test_pack_returns_per_rule_results(tmp_path):
    good = _regex_rule(id="SC-GEN-001")
    _write_pack(str(tmp_path), "stp", _base_pack(rules=[good]))
    pack = rule_loader.load_pack("stp", base_dir=str(tmp_path))
    results = rule_loader.self_test_pack(pack)
    assert len(results) == 1
    assert results[0].rule_id == "SC-GEN-001"
    assert results[0].passed is True
    assert results[0].failures == []


def test_module_importable_without_sigalrm(monkeypatch):
    # Import must not crash on a platform lacking signal.SIGALRM. We simulate by
    # reloading with SIGALRM absent and asserting _HAS_SIGALRM flips, no raise.
    import signal as _sig
    had = hasattr(_sig, "SIGALRM")
    if had:
        monkeypatch.delattr(_sig, "SIGALRM", raising=False)
    reloaded = importlib.reload(rule_loader)
    try:
        assert reloaded._HAS_SIGALRM is False
        # The threading fallback must still work post-reload.
        with pytest.raises(reloaded.RuleTestTimeout):
            reloaded.run_with_timeout(_slow_func_factory(2), timeout=1)
    finally:
        # Restore a clean module for subsequent tests.
        importlib.reload(rule_loader)


# ---------------------------------------------------------------------------
# C1: sequential-overlap quantifier heuristic (fix for _SEQ_QUANT_RE bug)
# ---------------------------------------------------------------------------

# The 5 canonical evil patterns from the fix spec.  Each causes
# superpolynomial backtracking when the trailing literal fails.
_SEQ_EVIL_PATTERNS = [
    r"\w*\w*\w*\w*x",       # same backslash-class ×4 then failing suffix
    r"[a-z]*[a-z]*[a-z]*c", # same char-class ×3
    r".*.*.*end",            # dot ×3
    r"[^\n]*[^\n]*[^\n]*end", # negated class repeated ×3 (same body)
    r"\w*\w+\w*x",           # mixed * and + on same class ×3
]

# Patterns that must NOT be flagged (linear / bounded / single-occurrence).
_SEQ_SAFE_PATTERNS = [
    r"[^)]*shell=True",      # single negated class, no repetition
    r"[^.\n]{0,80}",         # bounded quantifier — always polynomial
    r"AKIA[A-Z0-9]{16}",     # literal + bounded class
    r"\beval\(",             # word boundary + literal paren
    r"sk-[a-zA-Z0-9]{20}",  # literal prefix + bounded class
    r"\w+",                  # single \w, not 3+ consecutive
    r"\w*foo\w*",            # \w separated by required literal 'foo'
    r"\w*\d*\s*end",         # different classes, not the same one ×3+
]


@pytest.mark.parametrize("pattern", _SEQ_EVIL_PATTERNS)
def test_c1_sequential_overlap_evil_flagged(pattern):
    """C1: all 5 known-evil sequential-overlap patterns are caught."""
    reason = rule_loader._looks_catastrophic(pattern)
    assert reason, (
        f"_looks_catastrophic({pattern!r}) returned empty — evil pattern not caught. "
        "Check _SEQ_QUANT_RE backslash count (r\"\\\\\" = one literal backslash needed)."
    )
    assert "sequential" in reason


@pytest.mark.parametrize("pattern", _SEQ_SAFE_PATTERNS)
def test_c1_sequential_overlap_safe_not_flagged(pattern):
    """C1: linear/bounded patterns that ship in real packs must NOT be flagged."""
    reason = rule_loader._looks_catastrophic(pattern)
    assert not reason, (
        f"_looks_catastrophic({pattern!r}) incorrectly flagged {reason!r} — "
        "false-positive in C1 heuristic."
    )


def test_c1_all_shipped_packs_load_fully():
    """C1 post-condition: every shipped rule pack loads without any rule rejected
    by the updated sequential-overlap heuristic.  The expected rule counts are
    the frozen baseline; a mismatch means the heuristic regressed on real patterns."""
    rule_loader._reset_pack_cache()
    expected = {
        "secrets": 46,
        "sast": 121,
        "skill_threats": 124,
        "mcp_security": 44,
        "shared": 5,
        "runtime_dynamism": 60,
    }
    for name, count in expected.items():
        pack = rule_loader.load_pack(name)
        assert pack is not None, f"pack {name!r} failed to load (returned None)"
        assert len(pack.all_rules) == count, (
            f"pack {name!r}: expected {count} rules, got {len(pack.all_rules)} — "
            "C1 heuristic may be false-positiving on a shipped pattern"
        )


# ---------------------------------------------------------------------------
# C4: NaN / ±inf / non-numeric confidence in _compile_rule (rule_loader side)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_confidence,label", [
    (float("nan"),  "NaN"),
    (float("inf"),  "+inf"),
    (float("-inf"), "-inf"),
    ("high",        "string 'high'"),
    (None,          "None"),
    ({},            "dict"),
])
def test_c4_compile_rule_bad_confidence_yields_finite(tmp_path, bad_confidence, label):
    """C4: non-numeric or non-finite confidence in a rule dict is coerced to a
    finite fallback by _compile_rule; the rule is accepted (not rejected)."""
    raw = _regex_rule(id="SC-C4-001", confidence=bad_confidence)
    rule, reason = rule_loader._compile_rule(raw)
    assert rule is not None, (
        f"_compile_rule rejected a rule with confidence={label!r}: {reason}"
    )
    assert _math.isfinite(rule.confidence), (
        f"rule.confidence is not finite after coercion for input {label!r}: "
        f"{rule.confidence}"
    )
    assert 0.0 <= rule.confidence <= 1.0, (
        f"rule.confidence {rule.confidence} out of [0, 1] for input {label!r}"
    )


def test_c4_compile_rule_nan_confidence_produces_valid_json(tmp_path):
    """C4: a rule compiled with a NaN confidence must produce valid JSON when
    its findings are serialised — no non-standard NaN literal in the output."""
    import json
    raw = _regex_rule(id="SC-C4-JSON", confidence=float("nan"))
    rule, reason = rule_loader._compile_rule(raw)
    assert rule is not None
    # Simulate the serialisation path used by format_findings / output_findings.
    data = {"confidence": rule.confidence, "id": rule.id}
    serialised = json.dumps(data)        # must not raise
    parsed = json.loads(serialised)      # must round-trip
    assert _math.isfinite(parsed["confidence"])
