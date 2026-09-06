"""Report-shaped test data, built by the product's own emitters.

Nothing here hand-writes a report. ``finding()`` goes through
``forensics_core.Finding``, the dataclass scanner findings are emitted
through, and ``aggregate_report()`` drives
``aggregate_json.load_scanner_results()`` -- the same loader
``build_report()`` uses -- over scanner output files written the way
``run_forensics.sh`` writes them.

That is the whole point of the module. A hand-written fixture records what
its author believed the report looks like, and stays green while the product
drifts away from it: the SessionStart deep scan read a scanner-level
``severity`` key that the aggregator has never emitted, and the suite passed
throughout while CRITICAL findings were dropped. Test data built by the
emitter cannot describe a shape the product does not produce.

``aggregate_report()`` stops at the loader plus the two pure functions that
score its output (``build_summary``, ``calculate_report_exit_code``) rather
than calling ``build_report()`` end to end. ``build_report()`` also runs
correlation, raw trifecta detection, suppression and evidence capping, each
of which adds to or rewrites the finding set by reading the target from
disk -- a fixture whose findings change under it is not a fixture.
``TestAggregateReportContract`` in ``test_session_scan.py`` pins the two
against each other so that shortcut cannot become a drift of its own.
"""

import json
import os

import aggregate_json
import forensics_core


def finding(severity="high", **overrides):
    """One finding dict, shaped as scanners emit them.

    Built through ``forensics_core.Finding`` so the key set, the defaults and
    the ``__post_init__`` coercions (severity lowercasing, confidence fill,
    evidence class, ``finding_id``) are the product's rather than a test
    author's. Any field of the dataclass may be overridden by keyword.
    """
    fields = {
        "scanner": "skill_threats",
        "severity": severity,
        "title": "Test Finding",
        "description": "A finding built for a test.",
        "file": "evil.py",
        "line": 1,
        "snippet": "exec(payload)",
        "category": "injection",
    }
    fields.update(overrides)
    return forensics_core.Finding(**fields).to_dict()


def _exit_code_for(findings):
    """run_forensics.sh's per-scanner exit contract, applied as a default.

    0 clean, 1 high/medium, 2 critical, 99 infrastructure failure. Callers
    that are testing the exit code pass one explicitly; this only spares the
    rest from restating the contract at every call site.
    """
    severities = {item.get("severity") for item in findings}
    if "critical" in severities:
        return 2
    if severities & {"high", "medium"}:
        return 1
    return 0


def scanner_result(name, findings=(), exit_code=None, stderr=""):
    """Describe one scanner's raw output for ``aggregate_report()``."""
    findings = list(findings)
    return {
        "name": name,
        "findings": findings,
        "exit_code": _exit_code_for(findings) if exit_code is None else exit_code,
        "stderr": stderr,
    }


def write_scanner_results(dirpath, results):
    """Write the ``.out`` / ``.err`` / ``.exit`` trio run_forensics.sh writes.

    This is the input side of the loader's contract: the aggregator reads
    these three files per scanner and nothing else.
    """
    os.makedirs(dirpath, exist_ok=True)
    for result in results:
        base = os.path.join(str(dirpath), result["name"])
        with open(base + ".out", "w", encoding="utf-8") as handle:
            json.dump(result["findings"], handle)
        with open(base + ".err", "w", encoding="utf-8") as handle:
            handle.write(result["stderr"])
        with open(base + ".exit", "w", encoding="utf-8") as handle:
            handle.write(str(result["exit_code"]))
    return str(dirpath)


def aggregate_report(dirpath, results, target="/repo", mode="full"):
    """An aggregate report, assembled by the aggregator's own functions.

    ``dirpath`` is a scratch directory the scanner output files are written
    into; ``results`` is a sequence of ``scanner_result()`` dicts. The
    returned report's ``scanners`` and ``findings`` come straight out of
    ``load_scanner_results()``, its ``summary`` out of ``build_summary()``
    and its ``exit_code`` out of ``calculate_report_exit_code()``.
    """
    write_scanner_results(dirpath, results)
    scanners, findings = aggregate_json.load_scanner_results(str(dirpath))
    # Mirrors build_report(): worst first, so a reader that shows only the
    # top N sees the same order it would in a real report.
    findings.sort(
        key=lambda item: -aggregate_json.SEVERITY_ORDER.get(item.get("severity", "low"), 0)
    )
    summary = aggregate_json.build_summary(findings)
    return {
        "target": target,
        "mode": mode,
        "scanner_count": len(scanners),
        "scanners": scanners,
        "summary": summary,
        "exit_code": aggregate_json.calculate_report_exit_code(summary, scanners),
        "findings": findings,
    }
