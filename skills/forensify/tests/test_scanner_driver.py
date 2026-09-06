"""
Exit-code contract of scanner_driver.run_scanners().

run_forensics.sh ends in `case "$_rc" in 0|1|2) exit "$_rc" ;; *) exit 99 ;; esac`:
exit 0, 1 and 2 each write a complete aggregate report to stdout and are
results; 99 is an infrastructure failure. The driver must keep the report for
every result code and return an error only for 99 and the unforeseen, so
"the scanner broke" and "the scanner found nothing" stay distinguishable.

The subprocess is faked with a stub script — the pattern TestDeepScanItem
established in skills/repo-forensics/tests/test_session_scan.py — so these
tests pin the driver's exit-code contract, not the scanners.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ORCH_DIR = Path(__file__).resolve().parent.parent / "orchestrator"
sys.path.insert(0, str(ORCH_DIR.parent))

from orchestrator import scanner_driver  # noqa: E402

_POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt", reason="POSIX shell/process behavior not available on Windows"
)


def aggregate_payload(severities=()):
    """A minimal aggregate report carrying one finding per requested severity.

    The driver treats stdout as opaque JSON, so the contract assertion is
    equality: whatever the scan wrote is what the caller receives.
    """
    return {
        "findings": [
            {
                "finding_id": "f-%s-%d" % (sev, i),
                "severity": sev,
                "title": "finding %s" % sev,
                "file": "payload/%d.py" % i,
            }
            for i, sev in enumerate(severities)
        ],
        "scanners": [],
    }


def stub_scanner(tmp_path, monkeypatch, payload, exit_code):
    """Fake run_forensics.sh: print a chosen payload, exit with a chosen code."""
    script = tmp_path / "fake_run_forensics.sh"
    body = payload if isinstance(payload, str) else json.dumps(payload)
    script.write_text("#!/bin/bash\ncat <<'PAYLOAD'\n%s\nPAYLOAD\nexit %d\n" % (body, exit_code))
    script.chmod(0o755)
    monkeypatch.setattr(scanner_driver, "find_scanner_script", lambda: str(script))


@pytest.fixture
def target_dir(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    return str(target)


@_POSIX_ONLY
class TestRunScannersKeepsTheReport:
    def test_critical_findings_return_the_report_not_an_error(
        self, tmp_path, monkeypatch, target_dir
    ):
        """The defect, stated as a test: exit 2 used to discard the report on stdout."""
        payload = aggregate_payload(["critical"])
        stub_scanner(tmp_path, monkeypatch, payload, 2)

        result = scanner_driver.run_scanners(target_dir)

        assert "_error" not in result
        assert result == payload
        assert result["findings"][0]["severity"] == "critical"

    @pytest.mark.parametrize(
        "exit_code,severities",
        [(0, []), (1, ["high", "medium"]), (2, ["critical"])],
        ids=["clean", "high-medium", "critical"],
    )
    def test_each_report_exit_code_returns_the_complete_report(
        self, tmp_path, monkeypatch, target_dir, exit_code, severities
    ):
        payload = aggregate_payload(severities)
        stub_scanner(tmp_path, monkeypatch, payload, exit_code)

        result = scanner_driver.run_scanners(target_dir)

        assert result == payload


@_POSIX_ONLY
class TestRunScannersKeepsFailuresAsErrors:
    def test_infrastructure_failure_stays_an_error(self, tmp_path, monkeypatch, target_dir):
        """Exit 99 must not become a report: "the scanner broke" and "the scanner
        found nothing" stay distinguishable."""
        stub_scanner(tmp_path, monkeypatch, aggregate_payload(), 99)

        result = scanner_driver.run_scanners(target_dir)

        assert result["_error"] == "scanner_exit_99"

    @pytest.mark.parametrize("exit_code", [3, 124, 127])
    def test_an_unforeseen_exit_code_is_an_error(
        self, tmp_path, monkeypatch, target_dir, exit_code
    ):
        stub_scanner(tmp_path, monkeypatch, aggregate_payload(), exit_code)

        result = scanner_driver.run_scanners(target_dir)

        assert result["_error"] == "scanner_exit_%d" % exit_code

    def test_unparseable_stdout_at_a_report_exit_code_is_an_error(
        self, tmp_path, monkeypatch, target_dir
    ):
        stub_scanner(tmp_path, monkeypatch, "NOT JSON", 0)

        result = scanner_driver.run_scanners(target_dir)

        assert result["_error"] == "invalid_json"

    def test_timeout_is_an_error(self, tmp_path, monkeypatch, target_dir):
        # The stub closes its streams first so the pipe reaches EOF and the
        # orphaned sleep cannot hold subprocess.run past its kill.
        script = tmp_path / "slow_run_forensics.sh"
        script.write_text("#!/bin/bash\nexec 1>&- 2>&-\nsleep 60\n")
        script.chmod(0o755)
        monkeypatch.setattr(scanner_driver, "find_scanner_script", lambda: str(script))

        result = scanner_driver.run_scanners(target_dir, timeout=1)

        assert result["_error"] == "scanner_timeout"


class TestRunScannersWithoutASubprocess:
    def test_missing_script_is_an_error(self, monkeypatch, target_dir):
        monkeypatch.setattr(scanner_driver, "find_scanner_script", lambda: None)

        result = scanner_driver.run_scanners(target_dir)

        assert result["_error"] == "run_forensics.sh not found"

    def test_non_directory_target_is_an_error(self, tmp_path, monkeypatch):
        stub_scanner(tmp_path, monkeypatch, aggregate_payload(), 0)
        target = tmp_path / "a_file.txt"
        target.write_text("not a directory")

        result = scanner_driver.run_scanners(str(target))

        assert result["_error"] == "target_not_a_directory"

    def test_the_contract_is_a_named_constant(self):
        """One named place carries the contract; callers must not re-derive it
        from run_forensics.sh."""
        assert scanner_driver.SCANNER_REPORT_EXIT_CODES == (0, 1, 2)
