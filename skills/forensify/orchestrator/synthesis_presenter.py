"""
SynthesisPresenter — synthesize -> ground -> render briefing

Third stage of the orchestrator split. Takes DomainResult objects from
all domain sub-agents, synthesizes findings into a coherent narrative
briefing, performs grounding post-check (every citation must appear in
domain output), and renders dual-format output (briefing.md + briefing.json).

The synthesis step treats domain sub-agent output as UNTRUSTED input —
a malicious SKILL.md could have injected content into a domain result.
The grounding post-check is the defense: any finding in the narrative
that does not trace to a scanner output or inventory fact is flagged.

This module provides the deterministic rendering logic. The actual
LLM synthesis call happens at the SKILL.md entrypoint level.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .contracts import DomainResult


def collect_all_findings(results: List[DomainResult]) -> List[Dict[str, Any]]:
    """Flatten findings from all domain results into a single list."""
    all_findings: List[Dict[str, Any]] = []
    for r in results:
        for f in r.findings:
            # Copy before decorating — never mutate DomainResult dicts
            enriched = dict(f)
            enriched["_source_domain"] = r.domain
            enriched["_source_ecosystem"] = r.ecosystem
            all_findings.append(enriched)
    return all_findings


def build_risk_themes(results: List[DomainResult]) -> List[str]:
    """Collect unique risk themes across all domain results."""
    themes = []
    seen = set()
    for r in results:
        for theme in r.risk_themes:
            if theme not in seen:
                seen.add(theme)
                themes.append(theme)
    return themes


def detect_suppressed_findings(
    results: List[DomainResult],
    scanner_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Suppression detection: if a scanner produced a CRITICAL or HIGH finding
    and the corresponding domain sub-agent omitted it from results, surface
    it as suspicious. This catches prompt-injection attacks where a malicious
    SKILL.md instructs the sub-agent to report clean.
    """
    reported_ids = set()
    for r in results:
        for f in r.findings:
            fid = f.get("finding_id") or f.get("id")
            if fid:
                reported_ids.add(fid)
        for sid in r.suppressed_scanner_ids:
            reported_ids.add(sid)

    suppressed: List[Dict[str, Any]] = []
    for sf in scanner_findings:
        sev = sf.get("severity", "")
        if sev not in ("CRITICAL", "HIGH"):
            continue
        fid = sf.get("finding_id") or sf.get("id")
        if fid and fid not in reported_ids:
            suppressed.append({
                "finding_id": fid,
                "severity": sev,
                "scanner": sf.get("scanner", "unknown"),
                "reason": "critical/high finding from scanner not present in any domain result",
            })

    return suppressed


def ground_check(
    narrative_findings: List[Dict[str, Any]],
    scanner_findings: List[Dict[str, Any]],
    inventory_facts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Grounding post-check: every finding cited in the narrative must trace
    to either a scanner finding or an inventory fact. Ungrounded findings
    are flagged — they may indicate hallucination or injection.
    """
    scanner_ids = set()
    for sf in scanner_findings:
        fid = sf.get("finding_id") or sf.get("id")
        if fid:
            scanner_ids.add(fid)

    inventory_paths = set()
    for fact in inventory_facts:
        p = fact.get("path")
        if p:
            inventory_paths.add(p)

    ungrounded: List[Dict[str, Any]] = []
    for nf in narrative_findings:
        fid = nf.get("finding_id") or nf.get("id")
        path = nf.get("path") or nf.get("file")
        grounded = False
        if fid and fid in scanner_ids:
            grounded = True
        if path and path in inventory_paths:
            grounded = True
        if not grounded:
            ungrounded.append({
                "finding": nf,
                "reason": "not traceable to scanner output or inventory fact",
            })

    return ungrounded


def render_briefing_json(
    inventory: Dict[str, Any],
    results: List[DomainResult],
    scanner_findings: List[Dict[str, Any]],
    suppressed: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Render the structured briefing.json with full machine-parseable findings,
    risk themes, suppression alerts, and inventory summary.
    """
    all_findings = collect_all_findings(results)
    themes = build_risk_themes(results)

    # Build top-5 action list
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        all_findings,
        key=lambda f: severity_order.get(f.get("severity", "INFO"), 4),
    )
    top_actions = sorted_findings[:5]

    eco_summary = {}
    for eco in inventory.get("ecosystems", []):
        if eco.get("detected"):
            surfaces = eco.get("surfaces", {})
            eco_summary[eco["key"]] = {
                k: len(v) if isinstance(v, list) else 0
                for k, v in surfaces.items()
            }

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ecosystem_summary": eco_summary,
        "risk_themes": themes,
        "finding_count": len(all_findings),
        "findings_by_severity": _count_by_severity(all_findings),
        "top_actions": top_actions,
        "suppression_alerts": suppressed,
        "cross_ecosystem": inventory.get("cross_ecosystem", {}),
        # Key by domain+ecosystem so multi-ecosystem scans keep all results
        "domain_sections": {
            "%s_%s" % (r.domain, r.ecosystem): {
                "domain": r.domain,
                "ecosystem": r.ecosystem,
                "finding_count": len(r.findings),
                "risk_themes": r.risk_themes,
            }
            for r in results
        },
    }


def render_briefing_md(
    inventory: Dict[str, Any],
    results: List[DomainResult],
    suppressed: List[Dict[str, Any]],
) -> str:
    """
    Render briefing.md — the narrative briefing for human consumption.
    This is the deterministic template; LLM-generated narrative sections
    are injected from DomainResult.narrative_section fields.
    """
    lines: List[str] = []
    lines.append("# Forensify Briefing")
    lines.append("")
    lines.append("Generated: %s" % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    lines.append("")

    # Ecosystem landscape
    detected = [e for e in inventory.get("ecosystems", []) if e.get("detected")]
    eco_names = [e.get("display_name", e["key"]) for e in detected]
    lines.append("## Stack landscape")
    lines.append("")
    lines.append("Detected ecosystems: **%s**" % ", ".join(eco_names))
    lines.append("")

    for eco in detected:
        surfaces = eco.get("surfaces", {})
        counts = {k: len(v) if isinstance(v, list) else 0 for k, v in surfaces.items()}
        non_zero = {k: v for k, v in counts.items() if v > 0}
        if non_zero:
            parts = ["%d %s" % (v, k) for k, v in non_zero.items()]
            lines.append("- **%s**: %s" % (eco.get("display_name", eco["key"]), ", ".join(parts)))

    lines.append("")

    # Domain sections
    lines.append("## Risk domains")
    lines.append("")
    for r in results:
        lines.append("### %s (%s)" % (r.domain.title(), r.ecosystem))
        if r.narrative_section:
            lines.append("")
            lines.append(r.narrative_section)
        if r.findings:
            lines.append("")
            lines.append("%d findings" % len(r.findings))
        lines.append("")

    # Suppression alerts
    if suppressed:
        lines.append("## Suppression alerts")
        lines.append("")
        for s in suppressed:
            lines.append("- **%s** [%s]: %s" % (s["finding_id"], s["severity"], s["reason"]))
        lines.append("")

    # Cross-ecosystem
    iocs = inventory.get("cross_ecosystem", {}).get("iocs", [])
    if iocs:
        lines.append("## Cross-ecosystem findings")
        lines.append("")
        for ioc in iocs:
            lines.append("- **[%s] %s**: %s" % (ioc["severity"], ioc["id"], ioc.get("title", "")))
        lines.append("")

    return "\n".join(lines)


def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def write_briefing(
    coord_path: str,
    briefing_json: Dict[str, Any],
    briefing_md: str,
) -> None:
    """Write both briefing formats to the coord folder."""
    with open(os.path.join(coord_path, "briefing.json"), "w", encoding="utf-8") as f:
        json.dump(briefing_json, f, indent=2)
    with open(os.path.join(coord_path, "briefing.md"), "w", encoding="utf-8") as f:
        f.write(briefing_md)
