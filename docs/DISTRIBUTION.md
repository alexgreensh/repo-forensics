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

## GitHub Social Preview

Use the existing Repo Forensics artwork, starting from `diagrams/hero.svg` or the source file behind that artwork. Do not introduce a separate generated visual style for social preview images.

GitHub social previews are set in the repository UI:

1. Go to `Settings` -> `General` -> `Social preview`.
2. Upload a PNG exported from the existing Repo Forensics artwork.
3. Use the repository description: `Offline security scanner for AI-agent repos, skills, plugins, and MCP servers.`

Recommended PNG size: 1280 x 640.
