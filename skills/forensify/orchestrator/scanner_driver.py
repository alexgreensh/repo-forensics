"""
ScannerDriver — scan -> parse -> dedupe -> cap

First stage of the orchestrator split per architecture-strategist finding.
Takes a repo path, runs the repo-forensics scanner suite, parses JSON
output, deduplicates findings by finding_id, and caps the result set to
stay within token budgets.

This module bridges forensify's self-inspection use case with the existing
repo-forensics scanners. It does NOT re-implement any detection logic —
it calls the scanners as subprocesses and consumes their JSON output.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

from .contracts import DomainJob


def find_scanner_script() -> Optional[str]:
    """Locate run_forensics.sh relative to this file."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, "..", "..", "repo-forensics", "scripts", "run_forensics.sh")
    candidate = os.path.realpath(candidate)
    if os.path.isfile(candidate):
        return candidate
    return None


def run_scanners(
    target_path: str,
    skill_scan: bool = False,
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Run repo-forensics scanners against a target path and return parsed
    JSON output. Uses --format json so output is machine-parseable.

    Returns the parsed aggregate JSON dict on success, or a dict with
    _error key on failure.
    """
    script = find_scanner_script()
    if not script:
        return {"_error": "run_forensics.sh not found"}

    cmd = ["bash", script, target_path, "--format", "json"]
    if skill_scan:
        cmd.insert(3, "--skill-scan")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=os.path.dirname(script),
        )
    except subprocess.TimeoutExpired:
        return {"_error": "scanner_timeout", "timeout": timeout}
    except OSError as e:
        return {"_error": "subprocess_failed", "detail": str(e)}

    if result.returncode not in (0, 1):
        # Exit 1 = warnings found (normal). Anything else is unexpected.
        return {
            "_error": "scanner_exit_%d" % result.returncode,
            "stderr": result.stderr[:500] if result.stderr else "",
        }

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"_error": "invalid_json", "stdout_head": result.stdout[:200]}


def parse_findings(scanner_output: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract the flat list of findings from aggregate scanner output.
    Handles both the top-level 'findings' key and per-scanner nested results.
    """
    findings: List[Dict[str, Any]] = []

    # Top-level findings array (aggregate_json.py format)
    if "findings" in scanner_output:
        findings.extend(scanner_output["findings"])
        return findings

    # Per-scanner results (fallback for non-aggregate output)
    for key, val in scanner_output.items():
        if isinstance(val, dict) and "findings" in val:
            findings.extend(val["findings"])
        elif isinstance(val, list):
            findings.extend(val)

    return findings


def dedupe_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Deduplicate findings by finding_id (if present) or by (scanner, file, line)
    composite key. Returns the deduplicated list preserving first-seen order.
    """
    seen = set()
    unique: List[Dict[str, Any]] = []

    for f in findings:
        fid = f.get("finding_id")
        if not fid:
            # Composite fallback key
            fid = "%s:%s:%s" % (
                f.get("scanner", "?"),
                f.get("file", "?"),
                f.get("line", "?"),
            )
        if fid in seen:
            continue
        seen.add(fid)
        unique.append(f)

    return unique


def cap_findings(
    findings: List[Dict[str, Any]],
    max_per_severity: int = 50,
    max_total: int = 200,
) -> List[Dict[str, Any]]:
    """
    Cap findings to stay within token budgets. Preserves severity ordering:
    CRITICAL > HIGH > MEDIUM > LOW > INFO. Within each severity, preserves
    first-seen order up to max_per_severity.
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "INFO"), 4))

    by_sev: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        by_sev.setdefault(sev, []).append(f)

    capped: List[Dict[str, Any]] = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        entries = by_sev.get(sev, [])
        capped.extend(entries[:max_per_severity])

    return capped[:max_total]


def filter_findings_for_domain(
    findings: List[Dict[str, Any]],
    domain_config: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Filter findings to those relevant to a specific domain based on the
    scanner names declared in the domain's JSON config.
    """
    allowed_scanners = set(domain_config.get("scanners", []))
    if not allowed_scanners:
        return findings

    return [
        f for f in findings
        if f.get("scanner", "") in allowed_scanners
    ]
