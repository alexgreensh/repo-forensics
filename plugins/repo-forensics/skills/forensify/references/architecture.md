# Forensify Architecture Reference

Detailed invariants, design rationale, and implementation notes.
SKILL.md is the primary entry point; this file provides depth.

## Directory map

```
skills/forensify/
├── SKILL.md                        # Skill manifest, invocation contract
├── README.md                       # (this file)
├── config/
│   ├── ecosystem_roots.json        # Canonical agent-stack root paths per ecosystem (stdlib-parseable)
│   ├── ecosystem_roots.md          # Rationale, provenance, and schema invariants
│   └── scanner_safety.json         # Per-scanner safety audit (lands in Session 3)
├── domains/
│   ├── skills.json                 # Domain 1 — Skills surface filters
│   ├── mcp.json                    # Domain 2 — MCP surface filters
│   ├── hooks.json                  # Domain 3 — Hooks & auto-execution
│   ├── plugins.json                # Domain 4 — Plugins & marketplace trust chain
│   ├── commands.json               # Domain 5 — Commands, agents, memory, config
│   └── credentials.json            # Domain 6 — Credentials & permissions
├── orchestrator/
│   ├── scanner_driver.py           # scan → parse → dedupe → cap
│   ├── analysis_dispatcher.py      # inventory → spawn → poll domain sub-agents
│   └── synthesis_presenter.py      # synthesize → ground → render briefing
├── prompts/
│   ├── domain_skills.txt           # Sub-agent prompt template per domain
│   ├── domain_mcp.txt
│   ├── domain_hooks.txt
│   ├── domain_plugins.txt
│   ├── domain_commands.txt
│   ├── domain_credentials.txt
│   └── synthesis.txt               # Synthesis agent prompt template
├── scripts/
│   └── build_inventory.py          # Cross-agent inventory layer (zero-LLM)
└── tests/
    ├── test_forensify_inventory.py
    ├── test_ecosystem_detection.py
    ├── test_credentials_metadata.py
    └── fixtures/
        ├── claude_code_stack/      # shaped fixture
        ├── codex_stack/
        ├── openclaw_stack/
        ├── nanoclaw_stack/
        └── multi_ecosystem/        # all four side by side
```

## Plan reference

Full architecture in `plans/forensify.md` (955 lines, reviewed twice). Cross-agent scope correction applied per `OUTPUTS/forensify-handoff-2026-04-06/SCOPE_CORRECTION.md` before any code shipped.

## Key invariants

- **Zero external dependencies.** Config files are JSON, parsed by `json` (stdlib). No PyYAML, no tomllib version constraint, no pip install. Preserves repo-forensics' trust promise.
- **Read-only at runtime.** macOS Seatbelt sandbox profile for sub-agents. No writes outside the coord folder.
- **Credentials are structured metadata.** Never read values. `auth_mode`, `file_mode_octal`, `staleness_days`, `known_cross_tool_contention` — all derived from `stat()` and JSON shape inspection.
- **NFKC + bidi-override rejection** on every string that enters the inventory output.
- **Cross-ecosystem IOCs are deterministic.** No LLM guessing — curated rule set matches against known upstream bug reports (e.g., openai/codex#54506).
- **Persistent coord folder** at `~/.cache/forensify/runs/<hash>-<ts>/` with 0o700 perms, retention policy, lock file at `~/.cache/repo-forensics/locks/` (outside coord folder per architecture-strategist finding).

## How this lives next to repo-forensics

`forensify` reuses repo-forensics scanners as parse primitives. It does not duplicate detection logic. The domain sub-agents call scanner outputs as input facts, then reason over them with hostile-data posture.
