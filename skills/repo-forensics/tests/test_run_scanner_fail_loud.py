"""Fail-loud contract for auto_scan.run_scanner (scanner orchestrator).

ROOT-CAUSE bug (preexisting, all scanners): run_scanner ran each scanner as a
subprocess and SILENTLY returned [] on every failure mode — timeout, signal-kill
(SIGKILL/OOM, returncode < 0), error exit (returncode > 2), unparseable JSON, or
a NON-zero exit with empty stdout (the uncaught-exception crash door: rc 1/2 +
traceback on stderr + empty stdout). A clean verdict on an incomplete scan =
detection bypass: an attacker who makes any scanner overrun the 15s budget (OOM)
or simply CRASH thereby suppresses all of that scanner's findings with no trace.
(Torture 2026-06-17 "SIGKILL -> silent zero"; CE review P1 "crash -> silent zero".)

These tests pin that each failure mode now produces a LOUD high-severity
'scan-incomplete' finding that flows into the verdict, while a legitimate
empty/clean result stays [] (no false loud finding) and normal findings pass
through unchanged.
"""

import json
import subprocess

import auto_scan


class _Result:
    """Stand-in for subprocess.CompletedProcess."""

    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


# subprocess is lazy-imported inside run_scanner, so patch the stdlib name.
def _run_with(monkeypatch, fake):
    monkeypatch.setattr(subprocess, "run", fake)
    return auto_scan.run_scanner("scan_secrets.py", "/some/repo")


def _is_loud(findings):
    return (
        isinstance(findings, list)
        and len(findings) == 1
        and findings[0]["category"] == "scan-incomplete"
        and findings[0]["severity"] == "high"
        and "did not complete" in findings[0]["title"].lower()
    )


# (a) timeout -> loud
def test_timeout_is_loud(monkeypatch):
    def fake(*a, **k):
        raise subprocess.TimeoutExpired(cmd="scan", timeout=15)

    findings = _run_with(monkeypatch, fake)
    assert _is_loud(findings)
    assert "timed out" in findings[0]["description"].lower()
    assert findings[0]["scanner"] == "scan_secrets"


# (b) killed by signal (rc < 0) -> loud
def test_signal_kill_is_loud(monkeypatch):
    def fake(*a, **k):
        return _Result(returncode=-9, stdout="")

    findings = _run_with(monkeypatch, fake)
    assert _is_loud(findings)
    assert "signal 9" in findings[0]["description"].lower()


# (c) error exit (rc > 2) -> loud
def test_error_exit_is_loud(monkeypatch):
    def fake(*a, **k):
        return _Result(returncode=3, stdout="garbage")

    findings = _run_with(monkeypatch, fake)
    assert _is_loud(findings)
    assert "error code 3" in findings[0]["description"].lower()


# (d) unparseable JSON on non-empty stdout -> loud
def test_unparseable_json_is_loud(monkeypatch):
    def fake(*a, **k):
        return _Result(returncode=0, stdout="this is not json {")

    findings = _run_with(monkeypatch, fake)
    assert _is_loud(findings)
    assert "unparseable" in findings[0]["description"].lower()


# (e) legitimate empty + rc 0 -> still [] (no false loud finding)
def test_clean_empty_is_silent(monkeypatch):
    def fake(*a, **k):
        return _Result(returncode=0, stdout="   \n")

    findings = _run_with(monkeypatch, fake)
    assert findings == []


# (g) rc==1 + empty stdout = uncaught-exception CRASH -> loud (P1, CE review).
# A scanner that throws exits 1 with its traceback on stderr and EMPTY stdout.
# That must NOT be read as "ran clean, no findings" — it suppressed the scanner.
def test_crash_rc1_empty_stdout_is_loud(monkeypatch):
    def fake(*a, **k):
        return _Result(returncode=1, stdout="")

    findings = _run_with(monkeypatch, fake)
    assert _is_loud(findings)
    assert "rc 1" in findings[0]["description"].lower()
    assert "crashed" in findings[0]["description"].lower()


# (h) rc==2 + empty stdout -> also loud (non-zero + no output = no results).
def test_crash_rc2_empty_stdout_is_loud(monkeypatch):
    def fake(*a, **k):
        return _Result(returncode=2, stdout="   \n")

    findings = _run_with(monkeypatch, fake)
    assert _is_loud(findings)
    assert "rc 2" in findings[0]["description"].lower()


# (i) rc==1 WITH valid findings JSON -> findings returned, NOT clobbered.
# Some scanners use the exit code as a severity/found signal; if they printed
# findings, those findings are real and must survive.
def test_rc1_with_findings_passes_through(monkeypatch):
    payload = [
        {
            "scanner": "secrets",
            "severity": "high",
            "title": "token",
            "description": "found a token",
            "file": "b.py",
            "line": 9,
            "snippet": "ghp_...",
            "category": "secret",
        }
    ]

    def fake(*a, **k):
        return _Result(returncode=1, stdout=json.dumps(payload))

    findings = _run_with(monkeypatch, fake)
    assert findings == payload


# (f) normal findings pass through unchanged
def test_normal_findings_pass_through(monkeypatch):
    payload = [
        {
            "scanner": "secrets",
            "severity": "critical",
            "title": "AWS key",
            "description": "found a key",
            "file": "a.py",
            "line": 4,
            "snippet": "AKIA...",
            "category": "secret",
        }
    ]

    def fake(*a, **k):
        return _Result(returncode=2, stdout=json.dumps(payload))

    findings = _run_with(monkeypatch, fake)
    assert findings == payload


def test_oserror_launch_failure_is_loud(monkeypatch):
    def fake(*a, **k):
        raise OSError("exec format error")

    findings = _run_with(monkeypatch, fake)
    assert _is_loud(findings)
    assert "oserror" in findings[0]["description"].lower()


# The loud finding actually surfaces in the verdict (not swallowed downstream).
def test_loud_finding_flips_verdict():
    loud = auto_scan._scan_incomplete_finding("scan_secrets.py", "TIMED OUT")
    out = auto_scan.format_output(loud, scanned_target="some/repo")
    assert "VERDICT" in out
    assert "HIGH" in out
    # high-severity loud finding => HIGH verdict line, not a clean "no issues" line.
    assert "no issues found" not in out


def test_loud_finding_shape_survives_finding_dataclass():
    # The synthetic dict must round-trip through forensics_core.Finding the same
    # way real scanner findings do (so correlation + aggregation never crash).
    import forensics_core as core

    loud = auto_scan._scan_incomplete_finding("scan_sast.py", "was KILLED by signal 9")
    objs = core.findings_from_dicts(loud)
    assert len(objs) == 1
    assert objs[0].severity == "high"
    assert objs[0].category == "scan-incomplete"
