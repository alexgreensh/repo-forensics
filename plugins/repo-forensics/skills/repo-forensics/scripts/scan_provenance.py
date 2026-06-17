#!/usr/bin/env python3
"""
scan_provenance.py - Artifact Provenance / Attestation Scanner (U4, Gap 5)

Closes the "no artifact provenance check" gap from the 2026-06 audit:
scan_git_forensics verifies commit GPG signatures, but nothing checks whether
the SHIPPED artifact (a published npm package, a PyPI dist, or a generic
skill/repo) is signed by a trusted publisher (sigstore/SLSA/cosign, npm/PyPI
attestation). An attacker who can publish an unsigned (or tampered) artifact to
a registry slips past every other scanner.

Expert posture (repo-forensics makes the call, the user does not):
  - signature PRESENT but verification FAILS  -> CRITICAL "signature
    verification failed" (tampering signal). This is the one actionable,
    alarm-worthy verdict, and it always fires.
  - signature valid / NO signature found / tooling absent or inconclusive
                                              -> NOT a finding. An unsigned
    third-party artifact is the normal state of the world today; alarming on it
    would fire on nearly every scan, flip every clean repo off the exit-0
    contract, and only train users to ignore alarms. The scanner decides this
    is not worth surfacing, like `integrity` only firing on drift. No user
    flag, no opt-in toggle — the expert tool owns the judgment.

User-safety north star: NEVER raise, NEVER hard-fail, NEVER require network.
Every subprocess call is time-bounded and wrapped so a missing tool / timeout /
OSError degrades to "couldn't verify" — which, being non-actionable, stays
silent.

Zero non-stdlib deps (KTD7): shell out to external CLIs (cosign / gh / npm /
pip) via subprocess ONLY when found on PATH (shutil.which). No third-party
Python package is imported — stdlib + forensics_core only.

Created by Alex Greenshpun
"""

import os
import sys
import time
import json
import shutil
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "provenance"

# Per-tool wall-clock cap. The scanner runs inside the auto_scan hook (SIGKILL
# at ~15s -> silent zero), so a hung cosign/gh/npm/pip must never stall us.
SUBPROCESS_TIMEOUT_SEC = 8

# TOTAL subprocess wall-clock budget across ALL probes in one scan. Probes run
# sequentially; each per-tool 8s timeout summed over 2-3 tools (npm+cosign+gh)
# could reach 16-24s and trip the auto_scan ~15s SIGKILL -> silent zero, which
# would suppress even a real tampering CRITICAL. We budget the SUM well under 15s
# and stop probing once it is exhausted (an unprobed tool = unchecked = silent,
# which is safe; getting SIGKILLed is not).
TOTAL_BUDGET_SEC = 12.0


class _Deadline:
    """Tracks remaining wall-clock against the single shared TOTAL_BUDGET_SEC so
    the sequential probes can never sum past it. `remaining()` returns seconds
    left (>=0); `expired()` is True once the budget is spent. TOTAL_BUDGET_SEC is
    read at construction (not import) so a test can monkeypatch it."""

    def __init__(self):
        self._end = time.monotonic() + TOTAL_BUDGET_SEC

    def remaining(self):
        return max(0.0, self._end - time.monotonic())

    def expired(self):
        return self.remaining() <= 0.0

# Hardened env for every shell-out: never prompt, never page, isolated config.
_SAFE_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": os.environ.get("HOME", "/tmp"),
    "LANG": "C.UTF-8",
    "GIT_TERMINAL_PROMPT": "0",
    "GH_PROMPT_DISABLED": "1",
    "NO_COLOR": "1",
    "CI": "1",
}


def _run(cmd, cwd=None, deadline=None):
    """Run an external CLI with a timeout and a hardened env. Returns a dict:
        {"ran": bool, "code": int|None, "out": str, "err": str}
    `ran` is False (and code None) when the tool is missing / timed out / OSError
    — the caller treats that as `unchecked`, which is non-actionable and stays
    SILENT (no finding), never a crash. NEVER raises; NEVER requires network
    (offline tools just return non-zero or time out, both of which degrade to the
    silent unchecked verdict).

    The effective timeout is min(per-tool cap, remaining shared budget): a single
    tool can never burn more than the time left in the scanner-wide budget, so the
    sum of all probes stays under TOTAL_BUDGET_SEC (no SIGKILL / silent zero)."""
    timeout = SUBPROCESS_TIMEOUT_SEC
    if deadline is not None:
        timeout = min(SUBPROCESS_TIMEOUT_SEC, deadline.remaining())
        if timeout <= 0.0:
            # Budget already exhausted; do not even start the process.
            return {"ran": False, "code": None, "out": "", "err": ""}
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_SAFE_ENV,
            check=False,
        )
        return {
            "ran": True,
            "code": result.returncode,
            "out": (result.stdout or ""),
            "err": (result.stderr or ""),
        }
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        # TimeoutExpired -> tool hung; FileNotFoundError/OSError -> tool vanished
        # between which() and run(); all degrade to "couldn't check".
        return {"ran": False, "code": None, "out": "", "err": ""}


# --- Artifact-type detection (mirrors scan_dependencies.py manifest recognition) ---

def detect_artifact(repo_path):
    """Classify the scanned tree. Returns (artifact_type, marker_rel_path).

    artifact_type is one of: "npm", "pypi", "generic". marker_rel_path is the
    file/dir that anchored the classification (used as the finding's `file`)."""
    # npm: a package.json at the root.
    pkg = os.path.join(repo_path, "package.json")
    if os.path.isfile(pkg):
        return "npm", "package.json"

    # PyPI dist: a built/sdist marker or a project manifest.
    for name in ("PKG-INFO", "pyproject.toml", "setup.py", "setup.cfg"):
        if os.path.isfile(os.path.join(repo_path, name)):
            return "pypi", name
    try:
        for entry in os.listdir(repo_path):
            if entry.endswith(".dist-info") or entry.endswith(".egg-info"):
                return "pypi", entry
    except OSError:
        pass

    return "generic", "."


# --- Verification probes (each returns a verdict string) ---
#   "valid"     -> signature/attestation present and verified
#   "invalid"   -> signature present but verification FAILED (tampering)
#   "unsigned"  -> no signature/attestation found
#   "unchecked" -> tooling absent / timeout / couldn't determine
#
# THREE-TIER SIGNAL PARTITION (precedence, see _classify_output):
#
#   1. TAMPERING (definitive verification FAILURE) -> INVALID -> CRITICAL.
#      Scanned FIRST over the WHOLE output. If ANY tampering phrase is present
#      it WINS, regardless of any absent/ambiguous wording co-occurring. This is
#      the one alarm-worthy verdict and it must never be maskable.
#   2. ABSENT (definitively "nothing is signed") -> UNSIGNED -> silent.
#      Unambiguous "no signature is present" wording. Means absent, not failed.
#   3. AMBIGUOUS ("no matching" / "could not find" / "no valid"): dual-meaning —
#      could be absent OR a mismatch. With NO tampering phrase present, treated
#      as unchecked -> SILENT (conservative). NOT a CRITICAL (avoids the M2 false
#      positive on a clean unsigned repo) and NOT claimed unsigned-clean either.
#
# This replaces the earlier "UNSIGNED-before-INVALID, broad phrases first"
# ordering, which over-corrected the M2 false-CRITICAL into a false-NEGATIVE:
# cosign printing "no matching signatures" on a PRESENT-but-mismatched signature
# (real tampering) was masked as unsigned and went silent. Tampering now wins.

# TIER 1 — DEFINITIVE TAMPERING: a signature IS PRESENT but cryptographic
# verification FAILED (mismatch / untrusted key / modified after signing). Any
# of these phrases anywhere in the output forces a CRITICAL.
_TAMPERING_SIGNALS = (
    "verification failed",
    "signature verification failed",
    "cryptographic verification failed",
    "failed to verify",
    "signature failed",
    "invalid signature",
    "signature is invalid",
    "bad signature",
    "does not match",
    "doesn't match",
    "no matching signatures",  # cosign: signatures PRESENT, none match identity
    "tampered",
    "untrusted signer",
    "untrusted key",
    "untrusted certificate",
)

# TIER 2 — DEFINITIVE ABSENT: nothing is signed at all. Unambiguous "no
# signature is present" wording. These mean ABSENT (silent), not failed.
_ABSENT_SIGNALS = (
    "no signature found",
    "no signatures found",
    "no signatures present",
    "no signatures",
    "no attestation found",
    "no attestation",
    "no attestations",
    "no provenance",
    "missing signature",
    "not signed",
)

# TIER 3 — AMBIGUOUS: dual-meaning wording that could indicate either an absent
# signature OR a present-but-mismatched one. Without a Tier-1 tampering phrase we
# refuse to guess and stay SILENT (unchecked), so we neither raise a false
# CRITICAL nor falsely clear the artifact.
_AMBIGUOUS_SIGNALS = (
    "no matching",
    "could not find",
    "no valid",
)


def _classify_output(res):
    """Map a tool result dict to a verdict using exit code + stdout/stderr text.
    Shared by all probes so the severity ladder stays consistent.

    Precedence is the security-critical invariant:

      1. TAMPERING wins ALWAYS. The whole output is scanned for a definitive
         verification-failure phrase FIRST; if one is present we return
         "invalid" (CRITICAL) even if absent/ambiguous wording co-occurs. A
         present-but-failed signature is strictly more alarming than "no match",
         so tampering can never be masked by a co-occurring broad phrase.
      2. Else, a definitive ABSENT phrase -> "unsigned" (silent).
      3. Else exit 0 -> "valid".
      4. Else AMBIGUOUS-only wording (or anything unrecognized) -> "unchecked"
         (silent). We are deliberately conservative: ambiguous output never
         produces a false CRITICAL on a clean unsigned repo, and never falsely
         clears the artifact."""
    if not res["ran"]:
        return "unchecked"
    blob = (res["out"] + " " + res["err"]).lower()
    code = res["code"]

    # 1. Tampering wins regardless of any other co-occurring wording.
    if any(sig in blob for sig in _TAMPERING_SIGNALS):
        return "invalid"

    # 2. Definitively-absent signature -> unsigned (silent), on any exit code.
    if any(sig in blob for sig in _ABSENT_SIGNALS):
        return "unsigned"

    # 3. Clean exit with no absent/tampering notice -> a signature verified.
    if code == 0:
        return "valid"

    # 4. Non-zero with only ambiguous or unrecognized wording -> unchecked
    #    (silent). No tampering phrase was present, so we do NOT CRITICAL.
    return "unchecked"


def probe_npm(repo_path, deadline=None):
    """npm audit signatures: verifies registry signatures/attestations."""
    if not shutil.which("npm"):
        return "unchecked"
    res = _run(["npm", "audit", "signatures", "--json"], cwd=repo_path,
               deadline=deadline)
    if not res["ran"]:
        return "unchecked"
    # npm audit signatures emits structured JSON when it can; fall back to text.
    try:
        data = json.loads(res["out"]) if res["out"].strip() else {}
        invalid = data.get("invalid")
        missing = data.get("missing")
        if isinstance(invalid, list) and invalid:
            return "invalid"
        if isinstance(missing, list) and missing:
            return "unsigned"
        if data:
            return "valid"
    except (ValueError, AttributeError):
        pass
    return _classify_output(res)


def probe_pypi(repo_path, marker, deadline=None):
    """PyPI attestation presence. No network: we look for a local attestation
    sidecar (PEP 740 .publish.attestation) and, if cosign exists, let the
    generic cosign probe run. Absent any sidecar -> unsigned."""
    try:
        for entry in os.listdir(repo_path):
            if entry.endswith(".attestation") or entry.endswith(".publish.attestation"):
                # A present attestation sidecar; if cosign can verify it, great.
                if shutil.which("cosign"):
                    return probe_cosign(repo_path, deadline=deadline)
                return "valid"
    except OSError:
        return "unchecked"
    return "unsigned"


def probe_cosign(repo_path, deadline=None):
    """cosign verify over the artifact dir. Offline / keyless without a bundle
    will non-zero -> we read the message to classify."""
    if not shutil.which("cosign"):
        return "unchecked"
    res = _run(["cosign", "verify", "--offline", repo_path], cwd=repo_path,
               deadline=deadline)
    return _classify_output(res)


def probe_gh(repo_path, deadline=None):
    """gh attestation verify: GitHub artifact attestation (SLSA provenance)."""
    if not shutil.which("gh"):
        return "unchecked"
    res = _run(["gh", "attestation", "verify", repo_path], cwd=repo_path,
               deadline=deadline)
    return _classify_output(res)


def _verify(artifact_type, repo_path, marker):
    """Run the appropriate probe(s) and collapse to a single verdict.

    Order of precedence across probes: invalid > valid > unsigned > unchecked.
    A CRITICAL-worthy 'invalid' from any probe wins; a single 'valid' clears
    the artifact; 'unsigned' only stands if no probe could verify.

    All probes share ONE wall-clock deadline (TOTAL_BUDGET_SEC). Each tool's
    timeout is clamped to the time remaining, and once the budget is spent we
    STOP probing further tools (they degrade to 'unchecked' = silent). This caps
    the SUM of sequential per-tool timeouts well under the auto_scan ~15s SIGKILL,
    so a hung/PATH-shimmed cosign/gh/npm can never drive us to a silent zero."""
    deadline = _Deadline()
    verdicts = []
    if artifact_type == "npm":
        verdicts.append(probe_npm(repo_path, deadline=deadline))
    elif artifact_type == "pypi":
        verdicts.append(probe_pypi(repo_path, marker, deadline=deadline))

    # cosign / gh apply to any artifact type (sigstore/SLSA are ecosystem-wide).
    # Skip a probe outright once the shared budget is exhausted: an unprobed tool
    # is 'unchecked' (silent), which is safe — being SIGKILLed is not.
    if not deadline.expired():
        verdicts.append(probe_cosign(repo_path, deadline=deadline))
    if not deadline.expired():
        verdicts.append(probe_gh(repo_path, deadline=deadline))

    if "invalid" in verdicts:
        return "invalid"
    if "valid" in verdicts:
        return "valid"
    if "unsigned" in verdicts:
        return "unsigned"
    return "unchecked"


def scan_repo(repo_path, ignore_patterns=None):
    """Verify artifact provenance; emit at most ONE finding.

    ignore_patterns is accepted for uniform registration (U5) but provenance is
    an artifact-level check, not a per-file walk, so it is unused.

    repo-forensics makes the expert call here rather than offloading a decision
    to the user: an unsigned third-party artifact is the *normal* state of the
    world today, so alarming on it would fire on nearly every scan and only
    train users to ignore alarms (and it would flip every clean repo off the
    exit-0 contract). The single actionable, expert-worthy signal is a signature
    that is PRESENT but FAILS verification — tampering — which always emits as a
    CRITICAL. Unsigned / verified / unverifiable states are deliberately NOT
    findings: the scanner decided they are not alarm-worthy, like `integrity`
    only firing on drift. No user flag, no opt-in toggle."""
    findings = []

    artifact_type, marker = detect_artifact(repo_path)
    verdict = _verify(artifact_type, repo_path, marker)

    if verdict == "invalid":
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Artifact signature verification failed",
            description=(
                "A provenance signature/attestation is PRESENT on this "
                f"{artifact_type} artifact but verification FAILED. This is a "
                "tampering signal: the artifact may have been modified after "
                "signing, or signed by an untrusted key."
            ),
            file=marker, line=0,
            snippet="provenance verification failed",
            category="provenance",
        ))

    # verdict in {valid, unsigned, unchecked}: not alarm-worthy. The expert call
    # is to stay silent so clean repos keep a 0 verdict and users are not nagged
    # about the universal unsigned state. Capability is retained for the day
    # signing becomes common; only tampering surfaces today.
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Artifact Provenance / Attestation Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Checking artifact provenance for {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = scan_repo(repo_path, ignore_patterns)
    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
