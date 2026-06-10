# Repo Forensics Distribution Kit

Use this file when submitting Repo Forensics to directories, awesome lists, launch posts, and community threads. Keep the canonical install path pointed at the GitHub repo so installs, updates, issues, and stars all flow back to the source.

## Canonical Links

- GitHub: https://github.com/alexgreensh/repo-forensics
- Install: `/plugin marketplace add alexgreensh/repo-forensics`
- Run: `/repo-forensics /path/to/repo`
- CLI: `./skills/repo-forensics/scripts/run_forensics.sh /path/to/repo`
- Social/launch artwork: use the existing Repo Forensics artwork in `diagrams/hero.svg` and related `diagrams/*.svg` files
- License: PolyForm Noncommercial 1.0.0

## Positioning

### One-Liner

Offline security scanner for AI-agent repos, skills, plugins, and MCP servers.

### Short Blurb

Repo Forensics is a local-first security scanner for the AI agent ecosystem. Audit untrusted Claude Code plugins, Codex skills, MCP servers, OpenClaw extensions, dependencies, and GitHub repos before they touch your machine. 20 scanners, 41 correlation rules, CVE + CISA KEV checks, package IOCs, prompt-injection detection, supply-chain analysis, and post-incident forensics. Zero dependencies. Zero telemetry.

### Punchier Blurb

npm audit for AI-agent plugins, skills, and MCP servers. Run Repo Forensics before installing that plugin someone linked in Discord.

### Categories

- Security
- Supply Chain
- AI Agent Security
- MCP Security
- Claude Code Plugins
- Codex Skills
- Developer Tools
- Static Analysis
- Forensics

### Suggested GitHub Topics

`security`, `supply-chain-security`, `agent-security`, `ai-agent-security`, `mcp-security`, `claude-code`, `codex`, `agent-skills`, `plugins`, `static-analysis`, `forensics`, `developer-tools`

## Awesome-List PR Snippets

### Claude Code / Agent Plugin Lists

```md
- [Repo Forensics](https://github.com/alexgreensh/repo-forensics) - Offline security scanner for AI-agent repos, Claude Code plugins, Codex skills, MCP servers, and dependencies. 20 scanners, zero dependencies, zero telemetry.
```

### MCP Security Lists

```md
- [Repo Forensics](https://github.com/alexgreensh/repo-forensics) - Local-first scanner for MCP servers and agent plugins that detects tool poisoning, prompt injection, credential exfiltration paths, lifecycle hooks, and supply-chain risks before install.
```

### Security Tool Lists

```md
- [Repo Forensics](https://github.com/alexgreensh/repo-forensics) - Zero-dependency repo scanner for AI-agent supply-chain security, covering prompt injection, MCP tool poisoning, malicious lifecycle hooks, secrets, CVEs, CISA KEV, and post-incident traces.
```

### PR Description

```md
Adds Repo Forensics, a local security scanner for the AI agent supply chain.

Why it fits:
- Scans Claude Code plugins, Codex skills, MCP servers, OpenClaw extensions, dependencies, and generic GitHub repos.
- Runs fully offline with zero runtime dependencies and no telemetry.
- Covers agent-specific risks like prompt injection, tool poisoning, hidden Unicode, lifecycle hooks, credential exfiltration, and malicious package IOCs.
- Provides both Claude Code plugin install and CLI scan paths.
```

## Directory Submission Fields

### Name

Repo Forensics

### URL

https://github.com/alexgreensh/repo-forensics

### Description

Offline security scanner for AI-agent repos, skills, plugins, and MCP servers.

### Long Description

Repo Forensics audits untrusted AI-agent code before install: Claude Code plugins, Codex skills, MCP servers, OpenClaw extensions, dependencies, and generic GitHub repos. It runs locally with zero dependencies and zero telemetry, using 20 scanners and 41 correlation rules to detect prompt injection, MCP tool poisoning, hidden Unicode, credential exfiltration, malicious lifecycle hooks, package IOCs, CVEs, CISA KEV exposure, and post-incident traces.

### Install

```bash
/plugin marketplace add alexgreensh/repo-forensics
/plugin install repo-forensics@alexgreensh-repo-forensics
```

### CLI

```bash
git clone https://github.com/alexgreensh/repo-forensics.git
cd repo-forensics
./skills/repo-forensics/scripts/run_forensics.sh /path/to/repo
```

## Priority Submission Targets

### Highest Leverage

- https://github.com/hesreallyhim/awesome-claude-code
- https://github.com/ComposioHQ/awesome-codex-skills
- https://github.com/punkpeye/awesome-mcp-servers
- https://github.com/appcypher/awesome-mcp-servers
- https://github.com/ccplugins/awesome-claude-code-plugins
- https://github.com/rohitg00/awesome-claude-code-toolkit
- https://github.com/trailofbits/skills-curated

### Security / Agent-Security Niche

- https://github.com/Eyadkelleh/awesome-claude-skills-security
- https://github.com/LLMSecurity/awesome-agent-skills-security
- https://github.com/EthanYolo01/Awesome-OpenClaw
- https://github.com/Jiashuo-Zhang/Awesome-Security-Skills
- https://github.com/teehooai/awesome-mcp-security

### Directory / Index Surfaces

- https://aescut.sh/
- https://www.findskills.org/
- https://www.skillsdirectory.com/
- https://awesomeskill.ai/
- https://www.awesomeskills.dev/
- https://awesomeskills.net/
- https://skillsmd.dev/
- https://openagentskills.dev/
- https://agentskills.my/
- https://agentskillshub.top/
- https://www.remoteopenclaw.com/
- https://agenticskills.io/

## Launch Copy

### X / LinkedIn Short Post

```md
The AI-agent supply chain is getting weird.

Claude Code plugins, Codex skills, MCP servers, OpenClaw extensions, GitHub repos from Discord - all of them can run with your agent's permissions.

So I built Repo Forensics:

- 20 scanners
- 41 correlation rules
- zero dependencies
- zero telemetry
- runs locally

It checks for prompt injection, MCP tool poisoning, hidden Unicode, credential exfiltration paths, malicious lifecycle hooks, package IOCs, CVEs, CISA KEV exposure, and post-incident traces.

Install:
/plugin marketplace add alexgreensh/repo-forensics

GitHub:
https://github.com/alexgreensh/repo-forensics
```

### Hacker News / Reddit Title Options

- Show HN: Repo Forensics - npm audit for AI-agent plugins and MCP servers
- I built a local scanner for Claude Code plugins, Codex skills, and MCP servers
- Before your agent installs that plugin, scan it locally
- AI-agent plugins are a supply-chain risk, so I built a scanner for them

### First Comment / Context

```md
I built this after seeing how quickly agent plugins, skills, MCP servers, and marketplace installs were becoming normal developer workflow.

The scary part is that these are not just prompts. Many can execute hooks, read files, modify configs, call networks, and run with the same permissions as the agent.

Repo Forensics is intentionally boring in the security-tool sense: local only, no cloud upload, no API key, no pip install, no Docker. Clone it, run it against a repo, and get a severity-ranked verdict with exit codes for CI.
```

## Rule-Pack Publishing and Signing Workflow

Rule packs are the versioned JSON files in `skills/repo-forensics/data/rulepacks/`. The
signed bundle in `iocs/rulepacks.json` lets those packs reach installed users between
code releases. This section documents how to author, sign, and publish rule-pack updates.

### Authoring and editing rule packs

Rule packs live at `skills/repo-forensics/data/rulepacks/<scanner>.json`. The JSON
schema requires these top-level fields:

```json
{
  "schema_version": 1,
  "generated": "YYYY-MM-DD",
  "pack": "<scanner-name>",
  "pack_version": <strictly-increasing integer>,
  "rules": [ ... ]
}
```

Each rule object requires:

```json
{
  "id": "<SCANNER>-<CATEGORY>-<NNN>",
  "type": "regex|keyword|charset|map",
  "pattern": "<regex string>",
  "title": "Human-readable title",
  "severity": "critical|high|medium|low",
  "confidence": 0.0,
  "category": "<category-tag>",
  "explanation": "Why this pattern is suspicious.",
  "examples": {
    "match": ["...string that must match..."],
    "no_match": ["...string that must NOT match..."]
  }
}
```

Rules with `type: keyword` use a `values` array instead of `pattern`. Rules with
`type: charset` use a `codepoints` array. Rules with `type: map` use a `mapping`
object. SAST rules may include an `extensions` list to gate on file type.

Rule ids are stable forever. Retired rules keep their id with `"retired": true` rather
than being deleted, so user suppression files never dangle.

**Bump `pack_version`** (an integer) by at least 1 whenever any rule content changes.
The feed acceptance pipeline enforces strictly-increasing integers; string or semver
comparisons are intentionally not used.

### Signing and publishing

Key generation (once, offline):

```bash
python3 scripts/gen_rulepack_keys.py
# Outputs: rulepack_pubkey.hex (commit this)
#          rulepack_privkey.hex (NEVER commit; store offline)
```

The private key belongs in `~/.claude/_backups/` and your password manager. It is
never committed to the repository.

Sign and publish (per release, after editing packs):

```bash
python3 scripts/sign_rulepacks.py
# Reads:   skills/repo-forensics/data/rulepacks/*.json
# Reads:   iocs/latest.json
# Writes:  iocs/rulepacks.json        (bundled packs)
#          iocs/rulepacks.json.sig    (Ed25519 signature over raw bundle bytes)
#          iocs/latest.json.sig       (Ed25519 signature over raw IOC feed bytes)
```

Commit the four files (`iocs/rulepacks.json`, `iocs/rulepacks.json.sig`,
`iocs/latest.json.sig`, and any updated pack files under `data/rulepacks/`) to main.
The daily refresh pipeline on user machines fetches from the committed feed URL.

### Key ceremony and rotation

- **Public key constants**: `rulepack_feed.RULEPACK_FEED_PUBKEY_HEX` (rule-pack feed)
  and `ioc_manager.IOC_FEED_PUBKEY_HEX` (IOC feed). These are pinned in source.
- **Private key**: generate offline, store in `~/.claude/_backups/` and a password
  manager. Never commit, never leave on a networked machine longer than necessary.
- **Rotation**: generate a new keypair with `gen_rulepack_keys.py`, update both
  pubkey constants in `rulepack_feed.py` and `ioc_manager.py`, and ship a code
  release. Old clients continue using the old key until they update. The feed
  degrades gracefully if verification fails (shipped packs remain authoritative),
  so a key rotation does not break existing installs.
- **Backup**: store the p12/hex backup alongside the existing key material in
  `~/.claude/_backups/` with a dated filename (e.g.,
  `rulepack-signing-key-2026-06-10.hex`).

### Acceptance chain (for reference)

When a user's machine fetches the bundle, `rulepack_feed.py` enforces in order:

1. HTTPS only, host allowlist, 5 MB size cap.
2. Ed25519 signature over the exact raw fetched bytes (before any decode).
3. JSON parse + schema major-version gate.
4. `generated` timestamp no older than 30 days (replay protection).
5. `pack_version` strictly greater than the persisted floor.
6. Per-rule example self-tests including ReDoS timeout.
7. Atomic cache write to `~/.cache/repo-forensics/rulepacks/` (dir mode 0700) +
   floor update.

Any failure leaves the prior cache (or shipped packs) authoritative and sets a
degraded flag surfaced in scan output. The rule-pack-degraded and IOC-degraded
flags are reported separately.

---

## GitHub Social Preview

Use the existing Repo Forensics artwork, starting from `diagrams/hero.svg` or the source file behind that artwork. Do not introduce a separate generated visual style for social preview images.

GitHub social previews are set in the repository UI:

1. Go to `Settings` -> `General` -> `Social preview`.
2. Upload a PNG exported from the existing Repo Forensics artwork.
3. Use the repository description: `Offline security scanner for AI-agent repos, skills, plugins, and MCP servers.`

Recommended PNG size: 1280 x 640.
