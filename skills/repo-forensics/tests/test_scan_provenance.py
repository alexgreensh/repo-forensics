"""Tests for scan_provenance.py — U4 artifact provenance / attestation scanner.

All subprocess / shutil.which calls are MOCKED (monkeypatch) so the suite never
shells out to real cosign/gh/npm/pip and never touches the network.
"""

import ast
import os
import subprocess
import time

import pytest

import scan_provenance as scanner


# --- helpers -----------------------------------------------------------------

def _make_skill(tmp_path):
    """A generic skill/repo: no package.json, no PyPI markers."""
    (tmp_path / "SKILL.md").write_text("# A skill\nDoes a thing.\n")
    (tmp_path / "main.py").write_text("def go():\n    return 1\n")
    return tmp_path


def _no_tools(monkeypatch):
    """shutil.which always returns None: no verification tooling on PATH."""
    monkeypatch.setattr(scanner.shutil, "which", lambda _name: None)


def _have_tool(monkeypatch, present=("cosign",)):
    monkeypatch.setattr(
        scanner.shutil, "which",
        lambda name: ("/usr/bin/" + name) if name in present else None,
    )


def _fake_run(monkeypatch, code=0, out="", err="", raises=None):
    """Patch subprocess.run inside the scanner module."""
    def _run(*args, **kwargs):
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(args=args, returncode=code,
                                           stdout=out, stderr=err)
    monkeypatch.setattr(scanner.subprocess, "run", _run)


# --- scenarios ---------------------------------------------------------------

# The expert call: an unsigned/verified/unverifiable artifact is NOT a finding
# (alarming on the near-universal unsigned state is noise and breaks the
# clean-repo exit-0 contract). The ONLY actionable verdict is a present-but-
# FAILED signature = tampering = CRITICAL, and it always fires. No user toggle.

class TestSilentVerdicts:
    """Everything that is not tampering stays silent — repo-forensics owns the
    judgment, the user is never asked to opt in."""

    def test_unsigned_is_silent(self, tmp_path, monkeypatch):
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, code=1, err="error: no signatures found")
        assert scanner.scan_repo(str(tmp_path)) == []

    @pytest.mark.parametrize("msg", [
        "no signatures found",
        "no signature found",
        "no signatures present",
        "Error: not signed",
        "no attestations",
    ])
    def test_definitive_absent_is_unsigned_silent(
            self, tmp_path, monkeypatch, msg):
        # Tier-2 ABSENT wording = signature is absent (not failed) -> silent.
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, code=1, err=msg)
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_classify_definitive_absent_is_unsigned(self, monkeypatch):
        res = {"ran": True, "code": 1, "out": "",
               "err": "no signatures found"}
        assert scanner._classify_output(res) == "unsigned"

    # --- M2 regression: "no valid signatures" must NOT flip to false CRITICAL --
    # Before the original fix, "no valid" was treated as a verification failure
    # and ordered ahead of the absent signals, so a clean UNSIGNED repo whose
    # tool printed "no valid signatures found" was flipped to a false CRITICAL,
    # breaking the clean-repo exit-0 contract. Under the three-tier partition
    # "no valid" is AMBIGUOUS (dual-meaning) and, with NO definitive tampering
    # phrase present, resolves to unchecked -> SILENT. These assert no false
    # CRITICAL — the clean-repo contract holds.

    @pytest.mark.parametrize("msg", [
        "error: no valid signatures found",
        "found no valid attestation for the subject",
        "no valid signature found for artifact",
        "Error: no valid attestations were found",
    ])
    def test_no_valid_signatures_is_silent_not_critical(
            self, tmp_path, monkeypatch, msg):
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, code=1, err=msg)
        # AMBIGUOUS-only, no tampering phrase -> silent, NOT a false CRITICAL.
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_classify_ambiguous_no_valid_is_silent(self, monkeypatch):
        # "no valid" alone is ambiguous: could be absent or mismatch. With no
        # definitive tampering phrase we stay silent (unchecked), never CRITICAL.
        res = {"ran": True, "code": 1, "out": "",
               "err": "no valid signatures found"}
        assert scanner._classify_output(res) == "unchecked"

    def test_npm_no_valid_text_is_silent(self, tmp_path, monkeypatch):
        # npm path: non-JSON text fallthrough with ambiguous "no valid" -> silent.
        (tmp_path / "package.json").write_text('{"name": "p", "version": "1.0.0"}')
        _have_tool(monkeypatch, present=("npm",))
        _fake_run(monkeypatch, code=1, out="audit found no valid signatures")
        assert scanner.scan_repo(str(tmp_path)) == []

    # --- (d) ambiguous / inconclusive output -> conservative silence -----------
    @pytest.mark.parametrize("code,out,err", [
        (1, "", "something went sideways"),         # unknown non-zero
        (3, "weird output", ""),                     # unrecognized exit + text
        (1, "", "connection reset"),                 # transient/network-ish
    ])
    def test_ambiguous_output_is_silent(self, tmp_path, monkeypatch,
                                        code, out, err):
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, code=code, out=out, err=err)
        # When wording is ambiguous we fall through to unchecked -> silent.
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_valid_signature_is_silent(self, tmp_path, monkeypatch):
        # A verified-OK artifact is good news, not a finding; clean repo stays 0.
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, code=0, out="Verified OK")
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_no_tooling_is_silent(self, tmp_path, monkeypatch):
        _make_skill(tmp_path)
        _no_tools(monkeypatch)
        _fake_run(monkeypatch, raises=AssertionError("should not run"))
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_timeout_is_silent_no_raise(self, tmp_path, monkeypatch):
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign", "gh"))
        _fake_run(monkeypatch,
                  raises=subprocess.TimeoutExpired(cmd="cosign", timeout=8))
        # Must not hang, must not raise — an inconclusive check is non-actionable.
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_oserror_is_silent_no_raise(self, tmp_path, monkeypatch):
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, raises=OSError("boom"))
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_never_raises_on_arbitrary_inputs(self, tmp_path, monkeypatch):
        _no_tools(monkeypatch)
        findings = scanner.scan_repo(str(tmp_path))
        assert isinstance(findings, list)
        assert findings == []

    def test_accepts_ignore_patterns_kwarg(self, tmp_path, monkeypatch):
        # Uniform registration signature (U5): scan_repo(repo, ignore_patterns).
        _make_skill(tmp_path)
        _no_tools(monkeypatch)
        assert scanner.scan_repo(str(tmp_path), ignore_patterns=["*.md"]) == []


class TestTamperingIsCritical:
    """The one actionable verdict: a present signature that fails verification."""

    def test_present_but_invalid_is_critical(self, tmp_path, monkeypatch):
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, code=1,
                  err="error: signature verification failed")
        findings = scanner.scan_repo(str(tmp_path))
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "critical"
        assert f.category == "provenance"
        assert "verification failed" in f.title.lower()

    def test_npm_invalid_attestation_is_critical(self, tmp_path, monkeypatch):
        (tmp_path / "package.json").write_text('{"name": "p", "version": "1.0.0"}')
        _have_tool(monkeypatch, present=("npm",))
        _fake_run(monkeypatch, code=1,
                  out='{"invalid": [{"name": "p"}], "missing": []}')
        findings = scanner.scan_repo(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_npm_missing_only_is_silent(self, tmp_path, monkeypatch):
        # missing[] non-empty but invalid[] empty = unsigned (absent), not failed.
        (tmp_path / "package.json").write_text('{"name": "p", "version": "1.0.0"}')
        _have_tool(monkeypatch, present=("npm",))
        _fake_run(monkeypatch, code=1,
                  out='{"invalid": [], "missing": [{"name": "p"}]}')
        assert scanner.scan_repo(str(tmp_path)) == []


class TestTamperingWinsOverAmbiguous:
    """The false-NEGATIVE fix (P2-1 / P1-3): a definitive verification-FAILURE
    phrase ALWAYS produces a CRITICAL, even when an absent/ambiguous phrase
    ("no matching", "could not find") co-occurs in the same output. The earlier
    UNSIGNED-before-INVALID ordering over-corrected the M2 false-positive into a
    tampering-masking false-negative; the three-tier partition closes it."""

    def test_no_matching_signatures_present_but_mismatched_is_critical(
            self, tmp_path, monkeypatch):
        # cosign prints "no matching signatures" when signatures ARE present but
        # none match the trusted identity/key = real tampering. Must be CRITICAL.
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, code=1,
                  err="Error: no matching signatures")
        findings = scanner.scan_repo(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_classify_no_matching_signatures_is_invalid(self, monkeypatch):
        res = {"ran": True, "code": 1, "out": "",
               "err": "error: no matching signatures"}
        assert scanner._classify_output(res) == "invalid"

    def test_verification_failed_plus_no_matching_is_critical(
            self, tmp_path, monkeypatch):
        # Output contains BOTH a tampering phrase AND a broad ambiguous phrase.
        # Tampering MUST win -> CRITICAL (cannot be masked by co-occurrence).
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, code=1,
                  out="signature verification failed",
                  err="no matching attestation")
        findings = scanner.scan_repo(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_classify_tampering_plus_absent_phrase_is_invalid(self, monkeypatch):
        # Even a DEFINITIVE absent phrase cannot mask a tampering phrase.
        res = {"ran": True, "code": 1,
               "out": "signature verification failed",
               "err": "no signatures found"}
        assert scanner._classify_output(res) == "invalid"

    def test_ambiguous_could_not_find_alone_is_silent(
            self, tmp_path, monkeypatch):
        # Ambiguous-only ("could not find") with NO tampering phrase -> silent.
        # Must NOT reintroduce the M2 false CRITICAL on a clean unsigned repo.
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, code=1, err="could not find a signature")
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_classify_ambiguous_could_not_find_is_unchecked(self, monkeypatch):
        res = {"ran": True, "code": 1, "out": "",
               "err": "could not find a matching entry"}
        assert scanner._classify_output(res) == "unchecked"

    @pytest.mark.parametrize("phrase", [
        "does not match",
        "doesn't match",
        "bad signature",
        "invalid signature",
        "cryptographic verification failed",
        "untrusted key",
        "the artifact was tampered",
    ])
    def test_definitive_tampering_phrases_are_critical(
            self, tmp_path, monkeypatch, phrase):
        _make_skill(tmp_path)
        _have_tool(monkeypatch, present=("cosign",))
        _fake_run(monkeypatch, code=1, err="Error: " + phrase)
        findings = scanner.scan_repo(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].severity == "critical"


class TestTotalTimeBudget:
    """perf CRITICAL #2: sequential per-tool 8s timeouts must NOT sum past the
    auto_scan ~15s SIGKILL. All probes share one TOTAL_BUDGET_SEC deadline; each
    tool's timeout is clamped to the time remaining and probing STOPS once the
    budget is spent. We mock the hang so wall-clock equals the *clamped* timeout
    the scanner actually requested, then assert the SUM stays under budget."""

    def _hanging_tools(self, monkeypatch, present):
        """Every probe tool is on PATH and 'hangs': subprocess.run sleeps for the
        timeout it was given (the clamped value), then raises TimeoutExpired —
        exactly how a wedged/PATH-shimmed tool behaves. Records each requested
        timeout so we can assert the scanner clamped them against the budget."""
        _have_tool(monkeypatch, present=present)
        requested = []

        def _run(*args, **kwargs):
            timeout = kwargs.get("timeout")
            requested.append(timeout)
            # Simulate the tool burning its full (clamped) timeout, capped small
            # so the suite stays fast while preserving the summation behavior.
            time.sleep(min(timeout, 0.05))
            raise subprocess.TimeoutExpired(cmd=args[0], timeout=timeout)

        monkeypatch.setattr(scanner.subprocess, "run", _run)
        return requested

    def test_npm_three_hanging_tools_stops_within_budget(
            self, tmp_path, monkeypatch):
        # npm artifact => npm + cosign + gh probed, the worst case (3 tools).
        (tmp_path / "package.json").write_text('{"name": "p", "version": "1.0.0"}')
        # Shrink the budget so the test is deterministic and fast but still
        # exercises clamp + early-stop. Each "hang" requests its clamped timeout.
        monkeypatch.setattr(scanner, "TOTAL_BUDGET_SEC", 0.30)
        requested = self._hanging_tools(monkeypatch, present=("npm", "cosign", "gh"))

        start = time.monotonic()
        findings = scanner.scan_repo(str(tmp_path))
        elapsed = time.monotonic() - start

        # No raise, no finding (all unchecked/silent), and bounded by the budget.
        # The real-world invariant the perf-CRITICAL is about: WALL-CLOCK never
        # approaches the 15s SIGKILL. Here it is capped by TOTAL_BUDGET_SEC.
        assert findings == []
        assert elapsed < scanner.TOTAL_BUDGET_SEC + 0.5  # generous slack for CI
        # Every requested timeout is clamped to <= the per-tool cap AND to the
        # time remaining in the shared budget — so no single probe can ever ask
        # for the full 8s once earlier probes have eaten into the budget.
        assert requested  # probes did run
        assert all(t <= scanner.SUBPROCESS_TIMEOUT_SEC for t in requested)
        assert all(t <= scanner.TOTAL_BUDGET_SEC + 1e-6 for t in requested)
        # Requested timeouts shrink monotonically as the budget is consumed.
        assert requested == sorted(requested, reverse=True)

    def test_budget_exhaustion_skips_later_tools(self, tmp_path, monkeypatch):
        # Drive the budget to ~0 so later probes are skipped entirely, proving
        # the scanner does NOT attempt all tools once the budget is spent.
        (tmp_path / "package.json").write_text('{"name": "p", "version": "1.0.0"}')
        monkeypatch.setattr(scanner, "TOTAL_BUDGET_SEC", 0.05)
        requested = self._hanging_tools(monkeypatch, present=("npm", "cosign", "gh"))

        findings = scanner.scan_repo(str(tmp_path))
        assert findings == []
        # The first probe consumes the tiny budget; subsequent probes are either
        # skipped (not appended to `requested`) or requested with a ~0 timeout
        # and refused before spawning. Either way fewer than 3 real runs happen.
        real_runs = [t for t in requested if t and t > 0.0]
        assert len(real_runs) < 3

    def test_clamped_timeout_never_exceeds_per_tool_cap(
            self, tmp_path, monkeypatch):
        # Even with a large budget, a single tool's timeout is capped at the
        # per-tool SUBPROCESS_TIMEOUT_SEC (the budget only ever shrinks it).
        _make_skill(tmp_path)
        monkeypatch.setattr(scanner, "TOTAL_BUDGET_SEC", 1000.0)
        requested = self._hanging_tools(monkeypatch, present=("cosign",))
        scanner.scan_repo(str(tmp_path))
        assert requested and all(
            t <= scanner.SUBPROCESS_TIMEOUT_SEC for t in requested)


class TestZeroDepInvariant:
    def test_only_stdlib_and_forensics_core_imported(self):
        """AST self-check: the module's top-level imports are stdlib +
        forensics_core only — no third-party package (KTD7)."""
        path = os.path.join(scanner.os.path.dirname(scanner.__file__),
                            "scan_provenance.py")
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read())

        stdlib = {
            "os", "sys", "time", "json", "shutil", "subprocess",
        }
        allowed = stdlib | {"forensics_core"}
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_roots.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.level == 0:
                    imported_roots.add(node.module.split(".")[0])

        extra = imported_roots - allowed
        assert not extra, f"non-stdlib / unexpected imports: {extra}"
