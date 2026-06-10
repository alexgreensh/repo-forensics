"""Parity gate for the rules-as-data extraction (U3, extended by U4/U5).

Behavior contract: moving a scanner's hardcoded pattern table into a JSON rule
pack must not change what the scanner finds. We prove that with a *frozen
golden*: before the constants were deleted, the constant-driven scanners were
run over a fixed corpus and their findings recorded (on the parity key) into
tests/golden/parity_<scanner>.json. The pack-driven scanner must reproduce that
golden exactly.

Parity key (per the plan): (title, severity, file, line, category). The
`description` field is scanner-generated and `snippet`/`scanner` are stable
derivatives, so they are deliberately excluded from the key. Rule ids are NOT
in the parity comparison key either (they did not exist pre-extraction); their
presence is asserted separately (`test_*_findings_carry_rule_id`).

Harness API (reused by U4/U5):
    scan_corpus(scan_file_fn, root)  -> list[Finding]
        Walk `root` with the shared repo walker and collect the findings a
        scanner's `scan_file(file_path, rel_path)` produces.
    key_set(findings)               -> set[tuple]
        Project findings onto the parity key (title, severity, file, line,
        category) as a set (the pre-extraction golden was order-independent).
    load_golden(name)               -> set[tuple]
        Read tests/golden/parity_<name>.json into a key set.
    assert_parity(name, scan_file_fn, root)
        One-call gate: build the key set for `root`, diff it against the golden,
        and fail with the symmetric difference if they disagree.

To add a scanner in U4/U5: capture its golden the same way (run the old
constant-driven scanner over the shared corpus, dump key tuples to
tests/golden/parity_<scanner>.json), then add a test that calls
assert_parity("<scanner>", <scanner>.scan_file, corpus_root) plus a
rule_id-presence test.
"""

import os
import json
import pytest

import forensics_core as core
import parity_corpus

import scan_secrets
import scan_sast

GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden")


# --- harness ----------------------------------------------------------------

def scan_corpus(scan_file_fn, root):
    """Run a scanner's scan_file over every walked file under `root`."""
    findings = []
    for fp, rp in core.walk_repo(str(root), skip_binary=True):
        findings.extend(scan_file_fn(fp, rp))
    return findings


def key_set(findings):
    """Project findings onto the parity key as a set."""
    return {
        (f.title, f.severity, f.file, f.line, f.category) for f in findings
    }


def load_golden(name):
    path = os.path.join(GOLDEN_DIR, f"parity_{name}.json")
    with open(path, "r", encoding="utf-8") as f:
        rows = json.load(f)
    return {tuple(r) for r in rows}


def assert_parity(name, scan_file_fn, root):
    actual = key_set(scan_corpus(scan_file_fn, root))
    golden = load_golden(name)
    missing = golden - actual   # findings the golden had that we lost
    extra = actual - golden     # findings we now produce that the golden lacked
    assert not missing and not extra, (
        f"parity drift for {name}: "
        f"{len(missing)} missing, {len(extra)} extra.\n"
        f"missing (first 10): {sorted(missing)[:10]}\n"
        f"extra (first 10): {sorted(extra)[:10]}"
    )


# --- shared corpus fixture --------------------------------------------------

@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    root = tmp_path_factory.mktemp("parity_corpus")
    parity_corpus.build_corpus(str(root))
    return root


# --- secrets ----------------------------------------------------------------

class TestSecretsParity:
    def test_pack_driven_matches_golden(self, corpus):
        assert_parity("secrets", scan_secrets.scan_file, corpus)

    def test_findings_carry_rule_id(self, corpus):
        findings = scan_corpus(scan_secrets.scan_file, corpus)
        # Every finding produced by a pack rule (i.e. category == "secret",
        # the per-line detector output; env-file findings are context machinery)
        # must carry a non-empty rule_id and the rule's confidence.
        rule_findings = [f for f in findings if f.category == "secret"]
        assert rule_findings, "expected at least one secret rule finding"
        assert all(f.rule_id for f in rule_findings), \
            "a pack-driven secret finding is missing its rule_id"
        assert all(0.0 < f.confidence <= 1.0 for f in rule_findings)

    def test_specific_rule_id_and_confidence(self, corpus):
        # A known private-key finding must carry its specific pack rule_id and
        # the high confidence assigned at extraction (KTD-8).
        findings = scan_corpus(scan_secrets.scan_file, corpus)
        pk = [f for f in findings
              if f.title == "Private Key (RSA/PEM/EC/DSA/OPENSSH)"]
        assert pk, "private-key rule did not fire on the corpus"
        f = pk[0]
        assert f.rule_id == "SC-KEY-001"
        assert f.confidence >= 0.9


# --- sast -------------------------------------------------------------------

class TestSastParity:
    def test_pack_driven_matches_golden(self, corpus):
        assert_parity("sast", scan_sast.scan_file, corpus)

    def test_findings_carry_rule_id(self, corpus):
        findings = scan_corpus(scan_sast.scan_file, corpus)
        assert findings, "expected at least one sast finding"
        assert all(f.rule_id for f in findings), \
            "a pack-driven sast finding is missing its rule_id"
        assert all(0.0 < f.confidence <= 1.0 for f in findings)

    def test_specific_rule_id(self, corpus):
        findings = scan_corpus(scan_sast.scan_file, corpus)
        evals = [f for f in findings
                 if f.title == "Dangerous Eval" and f.file.endswith(".py")]
        assert evals, "py Dangerous Eval rule did not fire"
        assert evals[0].rule_id == "SA-PY-001"


# --- pack-load failure behavior (no hardcoded fallback) ---------------------

class TestPackLoadFailure:
    """When load_pack returns None (a missing/tampered install), the scanner
    emits ONE loud critical diagnostic and scans no patterns, rather than
    carrying a dead hardcoded copy of the rules."""

    def test_secrets_emits_single_diagnostic(self, monkeypatch):
        monkeypatch.setattr(scan_secrets, "PACK_LOAD_ERROR", True)
        out = scan_secrets.scan_file("/some/file.py", "file.py")
        assert len(out) == 1
        f = out[0]
        assert f.severity == "critical"
        assert f.category == "scanner-integrity"
        assert "rule pack failed to load" in f.title.lower()

    def test_sast_emits_single_diagnostic(self, monkeypatch):
        monkeypatch.setattr(scan_sast, "PACK_LOAD_ERROR", True)
        out = scan_sast.scan_file("/some/file.py", "file.py")
        assert len(out) == 1
        f = out[0]
        assert f.severity == "critical"
        assert f.category == "scanner-integrity"

    def test_scanners_have_no_hardcoded_pattern_constant(self):
        # The whole point of U3: the deleted constants must stay deleted.
        assert not hasattr(scan_secrets, "PATTERNS")
        assert not hasattr(scan_sast, "SAST_PATTERNS")


# --- self-test gate (R8 structural ≥3 match / ≥2 no_match) -------------------

class TestPackSelfTests:
    @pytest.mark.parametrize("pack_name", ["secrets", "sast"])
    def test_all_examples_pass(self, pack_name):
        import rule_loader
        pack = rule_loader.load_pack(pack_name)
        assert pack is not None, f"{pack_name} pack failed to load"
        results = rule_loader.self_test_pack(pack)
        failed = [r for r in results if not r.passed]
        assert not failed, (
            f"{pack_name}: {len(failed)} rule self-tests failed: "
            + "; ".join(f"{r.rule_id}={r.failures}" for r in failed[:5])
        )

    @pytest.mark.parametrize("pack_name,min_rules", [("secrets", 40), ("sast", 110)])
    def test_every_rule_has_min_examples(self, pack_name, min_rules):
        # R2/R8: each rule ships >=3 match and >=2 no_match examples.
        import rule_loader
        pack = rule_loader.load_pack(pack_name)
        assert pack is not None
        assert len(pack.all_rules) >= min_rules
        for rule in pack.all_rules:
            m = rule.examples.get("match", [])
            nm = rule.examples.get("no_match", [])
            assert len(m) >= 3, f"{rule.id}: only {len(m)} match examples"
            assert len(nm) >= 2, f"{rule.id}: only {len(nm)} no_match examples"
