---
name: repo-forensics
description: Security forensics for git repos and AI agent skills. Use when auditing repos, reviewing dependencies, investigating compromises, vetting MCP servers, or checking AI skills for prompt injection, credential theft, and 2026 attack patterns. Not for fixing vulnerabilities or pentesting.
metadata:
  author: Alex Greenshpun
allowed-tools: Bash Read Glob Grep
user-invocable: true
argument-hint: <repo_path> [--skill-scan] [--format text|json|summary]
---

<!-- repo-forensics v3 | built by Alex Greenshpun | https://linkedin.com/in/alexgreensh | Co-Intelligent.ai -->

# Repo Forensics v3

Deep security auditing for repositories, AI agent skills, and MCP servers.

## When to Use

- **Auditing a new repo or dependency** before adding it to your project
- **Vetting AI skills/plugins** before installation (prompt injection, credential theft, backdoors)
- **Auditing MCP servers** for tool poisoning, SQL injection → prompt escalation, config risks
- **Security review** when someone asks "is this code secure?"
- **Forensic investigation** of a suspected compromise
- **CI/CD gating** with machine-readable output and exit codes

## Quick Start

Full audit (all 12 scanners):
```bash
./scripts/run_forensics.sh /path/to/repo
```

Focused AI skill scan (6 scanners, faster):
```bash
./scripts/run_forensics.sh /path/to/repo --skill-scan
```

JSON output for automation:
```bash
./scripts/run_forensics.sh /path/to/repo --format json
```

## Severity System

| Level | Score | Meaning | Exit Code |
|-------|-------|---------|-----------|
| CRITICAL | 4 | Active threat, immediate action required | 2 |
| HIGH | 3 | Significant risk, investigate promptly | 1 |
| MEDIUM | 2 | Potential issue, review recommended | 1 |
| LOW | 1 | Informational, may be false positive | 0 |

## Scanners

| Scanner | What It Detects | Mode |
|---------|----------------|------|
| **skill_threats** | Prompt injection, unicode smuggling, prerequisite attacks, ClickFix, MCP tool injection | skill + full |
| **mcp_security** | SQL injection → prompt escalation, tool poisoning, config CVEs (2025-59536, 2026-21852) | skill + full |
| **dataflow** | Source-to-sink taint tracking (env vars to network calls), cross-file import taint | skill + full |
| **secrets** | 40+ patterns: API keys, tokens, private keys, database URIs, JWTs | skill + full |
| **sast** | Dangerous functions, injection, shell execution across 8 languages | skill + full |
| **lifecycle** | NPM hooks + Python setup.py/pyproject.toml cmdclass overrides | skill + full |
| **entropy** | Per-string Shannon entropy, base64 blocks, hex strings (combo detection for high confidence) | full |
| **infra** | Docker, K8s, GitHub Actions, Claude Code config (CVE-2025-59536, CVE-2026-21852) | full |
| **dependencies** | NPM + Python typosquatting, l33t normalization, IOC packages (SANDWORM_MODE 2026) | full |
| **ast_analysis** | Python AST obfuscated exec chains, `__reduce__` backdoors, dynamic attribute access | full |
| **binary** | Executables hidden as images/text files | full |
| **git_forensics** | Time anomalies, GPG signature issues, identity inconsistencies | full |

## AI Skill Threat Detection

The `scan_skill_threats.py` scanner detects 10 categories of AI agent skill attacks:

1. **Prompt injection directives** ("ignore previous instructions", persona reassignment)
2. **Invisible unicode smuggling** (zero-width chars, RTL override, Cyrillic + Greek homoglyphs)
3. **Prerequisite red flags** (curl-pipe-bash, password-protected archives, xattr -c)
4. **Credential exfiltration** (bulk env access + network calls, webhook services)
5. **Persistence mechanisms** (LaunchAgents, crontab, shell RC modifications)
6. **Scope escalation** (accessing ~/.ssh, browser data, Keychain, other skills)
7. **Stealth directives** ("do not log", output suppression with background exec)
8. **Known campaign IOCs** (C2 IPs from ClawHavoc, SANDWORM_MODE, Telegram/Discord exfil)
9. **ClickFix / sleeper malware** (curl|base64-d|bash delivery, glot.io pastebins, SKILL.md prereqs)
10. **MCP tool description injection** (Invariant Labs `<IMPORTANT>` tag, "note to the AI", hidden instructions in JSON description fields)

## MCP Attack Surface

The `scan_mcp_security.py` scanner covers MCP-specific attack vectors discovered in 2025-2026:

### Tool Poisoning Attack (TPA)
Hidden instructions injected into tool `description` fields load into LLM context without user visibility. Canonical pattern: `<IMPORTANT>` tag (Invariant Labs, 2025). Scanner checks tool definitions in `.json`, `.py`, `.ts`, `.js`, `.toml` files.

### SQL Injection → Stored Prompt Injection
SQL injection in MCP server code can write malicious prompts into databases that are later retrieved and executed by agents. String concatenation in `cursor.execute()` or f-strings in SQL queries are flagged as critical (Trend Micro TrendAI, May 2025).

### Configuration Risks
- **CVE-2025-59536** (CVSS 8.7): Claude Code hooks execute before trust dialog — attacker-planted hooks in `.claude/settings.json` achieve RCE
- **CVE-2026-21852** (CVSS 7.5): `ANTHROPIC_BASE_URL` override routes all API calls through attacker proxy, exfiltrating API keys
- **CVE-2025-49596** (CVSS 9.4): MCP Inspector binding to `0.0.0.0` creates DNS rebinding + CSRF surface
- **`enableAllProjectMcpServers: true`**: Auto-approves all MCP servers, bypassing per-server consent dialogs

### Tool Shadowing
Cross-tool contamination where one tool's description instructs the LLM to modify behavior of other tools (demonstrated by Invariant Labs 2025).

## Correlation Engine

The correlation engine (`forensics_core.py`) identifies compound threats across 8 rules:

1. Environment/credential access + network call = **Potential Data Exfiltration** (critical)
2. Base64 encoding + exec/eval = **Obfuscated Code Execution** (critical)
3. Sensitive file read + network call = **Credential Theft Pattern** (high)
4. Prompt injection + code execution = **Prompt-Assisted Code Execution** (critical)
5. Lifecycle hook + network call = **Install-Time Exfiltration** (critical)
6. SQL injection + MCP/skill_threats finding = **SQL Injection Prompt Escalation** (critical)
7. Tool metadata poisoning + code execution = **Tool Metadata Poisoning Chain** (critical)
8. Unicode smuggling + prompt injection in docs = **Hidden Instruction Attack in Documentation** (high)

## Configuration

Create `.forensicsignore` in the repo root to suppress false positives:
```text
tests/fixtures/secrets.json
legacy/unsafe_code/*
src/config/dev_keys.py
```

Note: `.forensicsignore` itself is scanned for attacker-planted wildcard suppression patterns.

## Output Formats

- `--format text` (default): Colored human-readable output with severity tags
- `--format json`: Machine-readable JSON array of Finding objects
- `--format summary`: Counts only (for CI/CD scripting)

## Research Sources

See `references/research_sources.md` for full credits and links to the published research that informed this skill's threat detection capabilities.
