# ecosystem_roots — rationale and provenance

`ecosystem_roots.json` is the authoritative map of where each supported
ecosystem lives on disk, what surfaces each ecosystem exposes, and which
paths are shadow surfaces that should be reported separately rather than
scanned by the domain sub-agents.

This file carries the rationale, provenance, and design notes that a JSON
schema file cannot. `ecosystem_roots.json` is parsed by
`scripts/build_inventory.py` using only the Python standard library.
JSON was chosen over YAML to preserve repo-forensics' zero-dependency
promise.

## Schema invariants (enforced by `build_inventory.py` at runtime)

| Invariant | Value | Why |
|---|---|---|
| `path_normalization` | NFKC | Blocks Unicode confusable attacks on filenames |
| `bidi_override_policy` | reject | Blocks right-to-left override filename spoofs |
| `symlink_resolution` | realpath before hash | Hooks often symlink to external dirs (confirmed on live filesystem) |
| `walk_depth_cap` | 8 | Prevents runaway globbing on deep/recursive trees |
| `follow_symlinks_outside_root` | true, redirect recorded | Alex's own `~/.claude/hooks/` symlinks into Personal OS — the symlink target is the actual code to hash |
| `credential_value_reads` | forbidden | stat + JSON-shape inspection only; never read token values |
| `shadow_surfaces_in_default_scan` | false | Preserves signal-to-noise; opt-in via `--include-shadows` |

## Research provenance per ecosystem

| Ecosystem | Source | Key findings |
|---|---|---|
| **Claude Code** | context7 `/anthropics/claude-code` + live filesystem recon 2026-04-06 | `~/.claude.json` at `$HOME` is a separate surface from `~/.claude/`. Hooks in `~/.claude/hooks/` can symlink to files outside the stack root — realpath resolution is mandatory. |
| **Codex CLI** | context7 `/openai/codex` + developers.openai.com/codex/auth + live `auth.json` shape inspection | `CODEX_HOME` env var overrides default path. `config.toml` carries inline `[mcp_servers.*]` tables. `auth.json` carries `auth_mode`, `tokens.*`, `last_refresh` — structured metadata only, values never read. |
| **OpenClaw** | docs.openclaw.ai/llms.txt + docs.openclaw.ai/tools/skills + openclawplaybook.ai workspace architecture | Skills precedence is a 5-location chain (workspace > project agent > personal agent > managed > bundled). `OPENCLAW_PROFILE` env var affects workspace suffix. Workspace brain files: AGENTS.md, SOUL.md, USER.md, IDENTITY.md, TOOLS.md, HEARTBEAT.md. |
| **NanoClaw** | docs.nanoclaw.dev/llms.txt + docs.nanoclaw.dev/api/skills/skill-structure + /features/cli | Not a dotfolder — a git-cloned repo wherever the user put it. Four skill types: operational (`.claude/skills/` on main), utility (standalone tools), feature (`skill/*` branches), container (`container/skills/`). Detection is signature-based. |

## Cross-ecosystem conventions

### `AGENTS.md`

OpenClaw workspaces, Codex global instructions, and Claude Code projects all
use `AGENTS.md` as an agent instructions file. When forensify finds it under
any ecosystem root, it reports under that ecosystem's memory surface AND
cross-links it under a top-level `cross_ecosystem.agents_md` findings bucket
so multi-stack users can see the coordination risk at a glance.

## Cross-tool IOC registry (deterministic, append-only)

The `cross_tool_iocs` array in the JSON file is forensify's curated catalog
of known upstream bugs where one ecosystem silently corrupts another's
state. Each entry is referenced by a public upstream URL and carries
`trigger_conditions` that forensify evaluates deterministically at inventory
build time. No LLM inference.

Current entries:

1. **`openai/codex#54506`** — OpenClaw `models status` command silently
   overwrites fresh Codex OAuth credentials by syncing stale tokens from
   `~/.codex/auth.json`. Any user running both Codex and OpenClaw is
   exposed to credential corruption. This is forensify's unique value: a
   finding class that TruffleHog/CredSweeper cannot produce because they
   scan file contents for secrets, not cross-ecosystem stack interaction
   patterns.
   - Reference: https://github.com/openclaw/openclaw/issues/54506
   - Severity: high
   - Trigger: `codex_installed AND openclaw_installed`

Append-only rule: entries are never removed, only added. If an upstream bug
is fixed, the entry gains a `fixed_in: <version>` field but stays in the
registry so historical stacks running the affected version are still
matched.

## Credentials surface design

Credentials are captured as **structured metadata**, not binary "file
exists" findings. Every Codex user has `~/.codex/auth.json`, so existence
alone is noise. What matters and what forensify reports:

- `file_mode_octal` — 0o600 is safe, 0o644+ is a critical finding
- `is_world_readable`, `is_group_readable`, `owner_uid_matches_current`
- `size_bytes`, `last_modified_iso`
- `auth_mode` — ecosystem-specific enrichment. For Codex: `"chatgpt"` (OAuth,
  medium risk, short-lived refresh-rotated) vs `"apikey"` (non-rotating,
  broad-scope, exfil-once-use-forever — high risk)
- `token_last_refresh_iso` — if OAuth mode
- `staleness_days` — derived. Refresh tokens unused >30 days = gratuitous
  attack surface
- `known_cross_tool_contention` — list of matching entries from the IOC
  registry

The `schema_inspection: shape_only` policy means forensify opens the JSON
file, enumerates top-level keys and their value types/lengths, then closes
the file. Values are never captured into inventory output.

For NanoClaw's `.env` files, the policy is `line_count_only` — count
non-comment lines, never capture keys or values.

## Shadow surface policy

Shadow surfaces are paths that:

1. Exist under an ecosystem root
2. Are NOT part of the live stack (backups, caches, session DBs, file history)
3. May contain stale credentials, old skill versions, or orphaned state
4. Would 10x the scan token cost if included in domain sub-agent input

The inventory reports shadow surfaces under a separate top-level
`shadow_surfaces` key so agents can reason about stale-credential risk
separately from the live stack. Default scans skip them. Users opt in via
`--include-shadows` for a comprehensive audit.

Examples per ecosystem (non-exhaustive):

- **Claude Code**: `~/.claude-backup-*`, `~/.claude.full_backup_*`,
  `~/.claude.json.backup`, `~/.claude/backups/`, `~/.claude/_backups/`,
  `~/.claude/debug/`, `~/.claude/file-history/`, `~/.claude/cache/`
- **Codex**: `config.toml.bak.*`, `logs_*.sqlite` (176MB on live system),
  `state_*.sqlite` (114MB), `sessions/`, `shell_snapshots/`, `cache/`,
  `.tmp/`, `vendor_imports/`, `sqlite/`
- **OpenClaw**: `agents/*/sessions/`, `cache/`, `tmp/`
- **NanoClaw**: `node_modules/`, `dist/`, `build/`, `.next/`

## NanoClaw detection strategy (special case)

NanoClaw is the only ecosystem that does not use a dotfolder under `$HOME`.
It ships as a git repo the user clones to a path of their choice. Detection
walks three paths in order:

1. **`NANOCLAW_DIR` environment variable** — primary override
2. **Common clone paths** — `~/NanoClaw`, `~/nanoclaw`, `~/code/nanoclaw`,
   `~/CascadeProjects/*nanoclaw*`, `~/projects/nanoclaw`, and case variants
3. **Signature scan** — any directory under the common paths containing
   ALL of `scripts/claw`, `container/skills`, and `package.json`, AND whose
   `package.json` content matches `"name":"nanoclaw*"` or contains
   `"nanoclaw-agent"`

The `walk_depth_cap: 3` on `common_paths` prevents runaway globbing in
deeply nested project trees.

## Adding a new ecosystem

1. Add a new entry under `ecosystems` in `ecosystem_roots.json`
2. Declare `detection.kind` (`dotfolder` or `git_repo_signature`)
3. Fill `surfaces` with globs for each of the six risk domains
4. Fill `shadow_surfaces` with backups/caches/session data
5. If the ecosystem shares conventions with others (like `AGENTS.md`), add
   an entry to `cross_ecosystem_conventions`
6. Add fixture tests under `skills/forensify/tests/fixtures/<ecosystem>/`
7. Update this markdown file with research provenance

The JSON schema is additive — new ecosystems and new surfaces never break
existing consumers bound to `schema_version: 1`.
