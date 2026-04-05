"""
DomainJob dataclass — typed contract between inventory layer and domain
sub-agents, per PLAN.md section 9.7.

This is the unit of work the AnalysisDispatcher sends to each domain
sub-agent. It bundles the filtered scanner output, inventory slice,
and metadata the sub-agent needs to reason about one risk domain for
one ecosystem.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class DomainJob:
    """Input contract for a domain sub-agent."""

    # Identity
    job_id: str                      # unique per run, e.g. "skills-claude_code-<run_hash>"
    domain: str                      # one of: skills, mcp, hooks, plugins, commands, credentials
    ecosystem: str                   # ecosystem key from ecosystem_roots.json
    run_id: str                      # coord folder name: <hash>-<ts>

    # Inventory slice — the subset of inventory output relevant to this domain
    inventory_slice: List[Dict[str, Any]] = field(default_factory=list)

    # Scanner findings — filtered to this domain's scanner set
    scanner_findings: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    scanner_names: List[str] = field(default_factory=list)
    ecosystem_display_name: str = ""
    total_items_in_slice: int = 0
    walk_depth_cap: int = 8

    # Cross-ecosystem context (injected by dispatcher for cross-domain awareness)
    cross_ecosystem_agents_md: List[Dict[str, Any]] = field(default_factory=list)
    cross_tool_iocs: List[Dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> str:
        """Serialize for sub-agent input via coord folder file."""
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> "DomainJob":
        """Deserialize from coord folder file."""
        d = json.loads(data)
        return cls(**d)


@dataclass
class DomainResult:
    """Output contract from a domain sub-agent."""

    job_id: str
    domain: str
    ecosystem: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_themes: List[str] = field(default_factory=list)
    suppressed_scanner_ids: List[str] = field(default_factory=list)
    narrative_section: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> "DomainResult":
        d = json.loads(data)
        return cls(**d)
