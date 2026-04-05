---
name: forensify
description: Self-inspection of your AI-agent stack. Audits what you have installed across Claude Code, Codex, OpenClaw, and NanoClaw. Covers skills, MCP servers, hooks, plugins, commands, configuration, and credentials. Auto-detects installed ecosystems or takes an explicit --target path. For auditing your OWN accumulated setup; use repo-forensics for vetting external code before install.
metadata:
  author: Alex Greenshpun
allowed-tools: Bash Read Glob Grep
user-invocable: true
argument-hint: [--target PATH] [--inventory] [--domains NAMES] [--list-runs] [--dry-run] [--format md|json|both] [--include-shadows]
---

<!-- forensify v0.1 (pre-release) | built by Alex Greenshpun | https://linkedin.com/in/alexgreensh -->

# Forensify

First-class self-inspection for the AI-agent stack you have already installed.

`repo-forensics` vets external code before you install it. `forensify` tells you what you have already accumulated on this machine across every agent framework you use, and where the credential, prompt-injection, and auto-execution surfaces live today.

## What it audits

Across four ecosystems (v0.1 scope): **Claude Code**, **Codex**, **OpenClaw**, **NanoClaw**.

Six risk domains:

1. **Skills surface** — Claude Code `~/.claude/skills/`, Codex `~/.codex/skills/`, OpenClaw 5-location precedence chain, NanoClaw operational + container skills
2. **MCP surface** — `~/.claude.json`, `~/.claude/settings.json`, Codex `config.toml` `[mcp_servers.*]`, any plugin `.mcp.json`
3. **Hooks & auto-execution** — Claude Code settings + plugin `hooks.json`, Codex execution policies, shell hooks referencing agent tools
4. **Plugins & marketplace trust chain** — `installed_plugins.json`, `known_marketplaces.json`, `blocklist.json`, Codex `.codex-plugin/plugin.json`, OpenClaw `openclaw.plugin.json`
5. **Commands, agents, configuration & memory** — slash commands, subagent definitions, `CLAUDE.md`, `AGENTS.md` (cross-ecosystem), `SOUL.md`, `TOOLS.md`, rules, prompts
6. **Credentials & permission grants** — structured metadata only (file mode, perms, auth mode, staleness, cross-tool contention IOCs). Never reads values.

## Invocation

```bash
# Auto-detect every installed ecosystem and audit all of them
forensify

# Audit a single ecosystem by root path
forensify --target ~/.claude
forensify --target ~/.codex
forensify --target ~/.openclaw
forensify --target /path/to/nanoclaw-clone

# Enumerate without running any sub-agents (zero-LLM, deterministic)
forensify --inventory

# Pick specific domains
forensify --domains skills,mcp,credentials

# Estimate cost before running
forensify --dry-run

# List prior runs (persistent coord folder)
forensify --list-runs

# Include shadow surfaces (backups, caches, session DBs) in the inventory
forensify --include-shadows

# Output formats
forensify --format md     # narrative briefing only
forensify --format json   # structured findings only
forensify --format both   # default: both briefing.md and briefing.json
```

## Not what it does

- Does not fix, patch, or quarantine anything. Read-only.
- Does not scan external code you have not yet installed (that is `repo-forensics`).
- Does not read credential file values. Only file metadata and structured shape.
- Does not run during active attacks. Re-entrancy limitation: forensify runs inside a Claude Code process whose own stack it is auditing, so hooks on `self` cannot be cleanly disabled. Treat findings as current-state observations, not incident response.

## Status

v0.1 (pre-release). Architecture specified and reviewed twice in `plans/forensify.md`. Cross-agent scope correction applied before implementation. Four ecosystems, six domains, structured inventory + narrative briefing output.
