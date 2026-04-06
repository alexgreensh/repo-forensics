"""
AnalysisDispatcher — inventory -> spawn -> poll domain sub-agents

Second stage of the orchestrator split. Takes the inventory output and
filtered scanner findings, constructs DomainJob objects, dispatches them
to domain sub-agents (via Claude Code Agent tool), and collects results.

The coord folder at ~/.cache/forensify/runs/<hash>-<ts>/ is the
shared filesystem between dispatcher and sub-agents. Each DomainJob is
written as a JSON file the sub-agent reads; each DomainResult is written
by the sub-agent into the same folder.

This module does NOT execute sub-agents directly — it prepares the jobs
and manages the coord folder lifecycle. The actual Agent tool invocation
happens at the SKILL.md entrypoint level where Claude Code APIs are
available.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .contracts import DomainJob, DomainResult

COORD_BASE = os.path.expanduser("~/.cache/forensify/runs")
LOCK_DIR = os.path.expanduser("~/.cache/repo-forensics/locks")
MAX_RETAINED_RUNS = 10
MAX_RETAINED_DAYS = 30


def _run_id() -> str:
    """Generate a unique run ID: <short_hash>-<timestamp>."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    h = hashlib.sha256(("%s-%s" % (ts, os.getpid())).encode()).hexdigest()[:8]
    return "%s-%s" % (h, ts)


def create_coord_folder(run_id: Optional[str] = None) -> str:
    """
    Create a persistent coord folder for a forensify run.
    Sets 0o700 permissions. Returns the absolute path.
    """
    if run_id is None:
        run_id = _run_id()

    coord_path = os.path.join(COORD_BASE, run_id)
    os.makedirs(coord_path, mode=0o700, exist_ok=True)

    # Fix ancestor permissions: os.makedirs only applies mode to the leaf.
    # Existing parents may have permissive modes from prior runs.
    for ancestor in [COORD_BASE, os.path.dirname(COORD_BASE)]:
        if os.path.isdir(ancestor):
            current = os.stat(ancestor).st_mode & 0o777
            if current != 0o700:
                try:
                    os.chmod(ancestor, 0o700)
                except OSError:
                    pass

    # Write manifest
    manifest = {
        "coord_schema_version": 1,
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "in_progress",
    }
    with open(os.path.join(coord_path, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    return coord_path


def write_domain_job(coord_path: str, job: DomainJob) -> str:
    """Write a DomainJob to the coord folder as a JSON file. Returns the path."""
    filename = "job_%s_%s.json" % (job.domain, job.ecosystem)
    filepath = os.path.join(coord_path, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(job.to_json())
    return filepath


def read_domain_result(coord_path: str, domain: str, ecosystem: str) -> Optional[DomainResult]:
    """Read a DomainResult from the coord folder if it exists."""
    filename = "result_%s_%s.json" % (domain, ecosystem)
    filepath = os.path.join(coord_path, filename)
    if not os.path.isfile(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return DomainResult.from_json(f.read())
    except (json.JSONDecodeError, TypeError, KeyError):
        return None


def build_domain_jobs(
    run_id: str,
    inventory: Dict[str, Any],
    findings: List[Dict[str, Any]],
    domain_configs: Dict[str, Dict[str, Any]],
) -> List[DomainJob]:
    """
    Construct DomainJob objects for each (domain, ecosystem) pair.
    Only builds jobs for detected ecosystems with non-empty inventory slices.
    """
    jobs: List[DomainJob] = []

    cross_agents_md = inventory.get("cross_ecosystem", {}).get("agents_md", [])
    cross_iocs = inventory.get("cross_ecosystem", {}).get("iocs", [])

    for eco in inventory.get("ecosystems", []):
        if not eco.get("detected"):
            continue

        eco_key = eco["key"]
        surfaces = eco.get("surfaces", {})

        for domain_name, domain_cfg in domain_configs.items():
            # Collect the inventory slice for this domain
            inv_surfaces = domain_cfg.get("inventory_surfaces", [])
            slice_items: List[Dict[str, Any]] = []
            for surface_name in inv_surfaces:
                items = surfaces.get(surface_name, [])
                if isinstance(items, list):
                    slice_items.extend(items)

            if not slice_items:
                continue

            # Filter findings for this domain's scanner set
            from .scanner_driver import filter_findings_for_domain
            domain_findings = filter_findings_for_domain(findings, domain_cfg)

            job = DomainJob(
                job_id="%s-%s-%s" % (domain_name, eco_key, run_id[:8]),
                domain=domain_name,
                ecosystem=eco_key,
                run_id=run_id,
                inventory_slice=slice_items,
                scanner_findings=domain_findings,
                scanner_names=domain_cfg.get("scanners", []),
                ecosystem_display_name=eco.get("display_name", eco_key),
                total_items_in_slice=len(slice_items),
                cross_ecosystem_agents_md=cross_agents_md,
                cross_tool_iocs=cross_iocs,
            )
            jobs.append(job)

    return jobs


def gc_old_runs(max_runs: int = MAX_RETAINED_RUNS, max_days: int = MAX_RETAINED_DAYS) -> int:
    """
    Clean up old coord folders. Keeps the most recent max_runs or those
    younger than max_days, whichever is shorter. Returns count of removed
    folders.
    """
    if not os.path.isdir(COORD_BASE):
        return 0

    entries = []
    for name in os.listdir(COORD_BASE):
        full = os.path.join(COORD_BASE, name)
        if os.path.isdir(full):
            try:
                mtime = os.path.getmtime(full)
            except OSError:
                mtime = 0
            entries.append((mtime, full))

    entries.sort(reverse=True)  # newest first

    now = time.time()
    removed = 0

    for idx, (mtime, path) in enumerate(entries):
        age_days = (now - mtime) / 86400
        if idx >= max_runs or age_days > max_days:
            try:
                # Symlink guard: don't rmtree a symlink (attacker could
                # point it at ~/.claude/skills/ and we'd delete the target)
                if os.path.islink(path):
                    os.unlink(path)
                else:
                    shutil.rmtree(path)
                removed += 1
            except OSError:
                pass

    return removed


def list_runs() -> List[Dict[str, Any]]:
    """List all coord folder runs with metadata."""
    if not os.path.isdir(COORD_BASE):
        return []

    runs: List[Dict[str, Any]] = []
    for name in sorted(os.listdir(COORD_BASE), reverse=True):
        full = os.path.join(COORD_BASE, name)
        if not os.path.isdir(full):
            continue
        manifest_path = os.path.join(full, "manifest.json")
        manifest = {}
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        runs.append({
            "run_id": name,
            "path": full,
            "created_at": manifest.get("created_at", "unknown"),
            "status": manifest.get("status", "unknown"),
        })

    return runs
