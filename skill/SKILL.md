---
name: repo-forensics
description: Security forensics for git repos and AI agent skills. Use when auditing repos, reviewing dependencies, investigating compromises, vetting MCP servers, or checking AI skills for prompt injection, credential theft, runtime behavior prediction, and 2026 attack patterns. Includes runtime dynamism detection (time bombs, rug pulls, deferred payloads), manifest drift analysis, DAST for hook testing, file integrity monitoring, and IOC auto-update. Not for fixing vulnerabilities or pentesting.
metadata:
  author: Alex Greenshpun
allowed-tools: Bash Read Glob Grep
user-invocable: true
argument-hint: <repo_path> [--skill-scan] [--format text|json|summary] [--update-iocs] [--watch] [--verify-install]
---

<!-- repo-forensics v2 | built by Alex Greenshpun | https://linkedin.com/in/alexgreensh -->

# Repo Forensics v2

Deep security auditing for repositories, AI agent skills, and MCP servers.

## Highlights

- **Auto-scan hook** (v2): PostToolUse hook auto-triggers on `git clone`, `pip install`, `npm install`, etc. Zero-overhead for non-matching commands.
- **.pth file injection detection** (v2): Detects liteLLM-style Python startup injection attacks (exec/eval/base64/known IOC filenames)
- **Transitive dependency scanning** (v2): Deep-parses `package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock` for supply chain IOCs
- **DAST scanner** (`scan_dast.py`): Dynamic analysis of Claude Code hooks with 8 malicious payload types, sandboxed execution
- **File integrity monitor** (`scan_integrity.py`): SHA256 baselines for critical config files, drift detection with `--watch`
- **IOC auto-update** (`--update-iocs`): Pull latest indicators of compromise from remote feed
- **Installation verification** (`--verify-install`): Verify repo-forensics itself hasn't been tampered with
- **GitHub Actions** (`action.yml`): CI/CD integration for automated security gating
- **Runtime behavior prediction** (`scan_runtime_dynamism.py`): Detects code that changes behavior after install: dynamic imports, fetch-then-execute, self-modification, time bombs, dynamic tool descriptions
- **Manifest drift detection** (`scan_manifest_drift.py`): Compares declared vs actual dependencies, catches phantom deps, runtime installs, conditional import+install fallbacks
- **MCP rug pull detection**: Tool descriptions sourced from database, network, env vars, or conditional logic
- **Enhanced AST analysis**: 12 patterns including marshal.loads, types.CodeType, sys.addaudithook, bytes decode obfuscation, self-modification
- **Test suite**: 223 pytest tests covering all scanners
- **OpenClaw/ClawHub scanning**: Auto-detects OpenClaw skills, validates frontmatter, tools.json, SOUL.md, .clawhubignore
- **17 scanners** with 16 correlation rules

## When to Use

- **Auditing a new repo or dependency** before adding it to your project
- **Vetting AI skills/plugins** before installation (prompt injection, credential theft, backdoors)
- **Auditing MCP servers** for tool poisoning, SQL injection, config risks
- **Security review** when someone asks "is this code secure?"
- **Forensic investigation** of a suspected compromise
- **CI/CD gating** with machine-readable output and exit codes
- **Hook security testing** to verify Claude Code hooks handle malicious input safely

## Quick Start

Full audit (all 17 scanners):
```bash
./scripts/run_forensics.sh /path/to/repo
```

Focused AI skill scan (8 scanners, faster):
```bash
./scripts/run_forensics.sh /path/to/repo --skill-scan
```

With IOC update and integrity monitoring:
```bash
./scripts/run_forensics.sh /path/to/repo --update-iocs --watch
```

Verify your installation:
```bash
./scripts/run_forensics.sh /path/to/repo --verify-install
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
| **runtime_dynamism** | Dynamic imports, fetch-then-execute, self-modification, time bombs, dynamic tool descriptions | skill + full |
| **manifest_drift** | Phantom dependencies, runtime package installs, conditional import+install, declared-but-unused deps | skill + full |
| **skill_threats** | Prompt injection, unicode smuggling, prerequisite attacks, ClickFix, MCP tool injection | skill + full |
| **openclaw_skills** | SKILL.md frontmatter abuse, tools.json FSP, SOUL.md/AGENTS.md injection, .clawhubignore bypass, ClawHavoc IOCs | skill + full |
| **mcp_security** | SQL injection to prompt escalation, tool poisoning, rug pull enablers, config CVEs | skill + full |
| **dataflow** | Source-to-sink taint tracking (env vars to network calls), cross-file import taint | skill + full |
| **secrets** | 40+ patterns: API keys, tokens, private keys, database URIs, JWTs | skill + full |
| **sast** | Dangerous functions, injection, shell execution across 8 languages | skill + full |
| **lifecycle** | NPM hooks + Python setup.py/pyproject.toml cmdclass overrides | skill + full |
| **integrity** | SHA256 baselines for .claude/settings.json, CLAUDE.md, hook scripts. Drift detection with `--watch` | full |
| **dast** | Dynamic hook testing: 8 payload types (injection, traversal, amplification, env leak) in sandbox | full |
| **entropy** | Per-string Shannon entropy, base64 blocks, hex strings (combo detection) | full |
| **infra** | Docker, K8s, GitHub Actions, Claude Code config (CVE-2025-59536, CVE-2026-21852) | full |
| **dependencies** | NPM + Python typosquatting, l33t normalization, IOC packages (SANDWORM_MODE 2026) | full |
| **ast_analysis** | Python AST: obfuscated exec chains, `__reduce__` backdoors, marshal/types bytecode, audit hook abuse, self-modification | full |
| **binary** | Executables hidden as images/text files | full |
| **git_forensics** | Time anomalies, GPG signature issues, identity inconsistencies | full |

## Dynamic Analysis (DAST)

The `scan_dast.py` scanner executes hook scripts with malicious payloads in a sandboxed subprocess:

**8 payload types:**
1. Prompt injection in tool input
2. Path traversal in file arguments
3. Command injection via backticks/subshell
4. Oversized input (amplification test)
5. Unicode smuggling in arguments
6. Environment variable exfiltration attempt
7. Shell metacharacter injection
8. Null byte injection

**Safety:** All execution uses subprocess with 5s timeout, stdout/stderr capture, scrubbed environment, temp directory isolation, no shell=True.

## File Integrity Monitor

The `scan_integrity.py` scanner protects critical configuration files:

- SHA256 baselines for `.claude/settings.json`, `CLAUDE.md`, `.mcp.json`, hook scripts
- **`--watch` mode**: Creates baseline on first run, alerts on drift on subsequent runs
- Detects dangerous hook commands (curl, wget, eval, base64, /dev/tcp)
- Flags executable config files (unusual permission bits)

## IOC Auto-Update

The `--update-iocs` flag pulls latest indicators of compromise from a hosted JSON feed:

- C2 IP addresses, malicious domains, known-bad packages
- Cached locally in `.forensics-iocs.json` (24h TTL)
- Falls back to hardcoded IOCs when offline
- Managed by `ioc_manager.py` (`--show` to inspect, `--update` to pull)

## Installation Verification

The `--verify-install` flag checks that repo-forensics itself hasn't been tampered with:

- Compares all skill files against `checksums.json` (SHA256)
- Detects modified, missing, or unexpected files
- Run `verify_install.py --generate` at release time to create checksums

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
Hidden instructions injected into tool `description` fields load into LLM context without user visibility. Canonical pattern: `<IMPORTANT>` tag (Invariant Labs, 2025).

### SQL Injection to Stored Prompt Injection
SQL injection in MCP server code can write malicious prompts into databases that are later retrieved and executed by agents (Trend Micro TrendAI, May 2025).

### Configuration Risks
- **CVE-2025-59536** (CVSS 8.7): Claude Code hooks execute before trust dialog, RCE via `.claude/settings.json`
- **CVE-2026-21852** (CVSS 7.5): `ANTHROPIC_BASE_URL` override exfiltrates API keys
- **CVE-2025-49596** (CVSS 9.4): MCP Inspector DNS rebinding via `0.0.0.0` binding
- **CVE-2025-6514** (CVSS 9.6): mcp-remote OAuth command injection
- **`enableAllProjectMcpServers: true`**: Bypasses per-server consent dialogs

### Tool Shadowing
Cross-tool contamination where one tool's description instructs the LLM to modify behavior of other tools (Invariant Labs 2025).

### Rug Pull Enablers
Tool descriptions sourced from mutable data (database queries, network requests, environment variables, runtime file loads). These don't prove malicious intent but flag that tool behavior can change without code changes (Lukas Kania, March 2026; OWASP MCP07).

## Runtime Behavior Prediction

The `scan_runtime_dynamism.py` scanner detects static indicators that code will change behavior after install:

1. **Dynamic imports**: `importlib.import_module(variable)`, `__import__(env_var)`, `require(variable)`, ES `import(variable)`
2. **Fetch-then-execute**: `requests.get(url).text` piped to `eval()`, runtime `pip install`/`npm install`, download-and-run scripts
3. **Self-modification**: `types.FunctionType()`, `types.CodeType()`, `marshal.loads()`, `open(__file__, 'w')`, `SourcelessFileLoader` (CVE-2026-2297)
4. **Time bombs**: `datetime.now() > datetime(2026,6,1)`, unix timestamp comparisons, counter-based activation, probabilistic triggers
5. **Dynamic tool descriptions**: MCP description from `db.query()`, `requests.get()`, `os.environ`, conditional descriptions

Uses both regex patterns and Python AST analysis for reliable detection.

## Manifest Drift Detection

The `scan_manifest_drift.py` scanner compares what a package DECLARES vs what it actually USES:

- **Phantom dependencies**: Module imported in code but not in `requirements.txt`/`package.json`
- **Runtime package installs**: `subprocess.run(["pip", "install", pkg])` in code
- **Conditional import+install**: `try: import X except: os.system("pip install X")`
- **Declared but unused**: Package in manifest but never imported (potential dependency confusion decoy)

Supports Python (requirements.txt, pyproject.toml, setup.py) and Node.js (package.json).

## Correlation Engine

The correlation engine (`forensics_core.py`) identifies compound threats across 14 rules:

1. Environment/credential access + network call = **Potential Data Exfiltration** (critical)
2. Base64 encoding + exec/eval = **Obfuscated Code Execution** (critical)
3. Sensitive file read + network call = **Credential Theft Pattern** (high)
4. Prompt injection + code execution = **Prompt-Assisted Code Execution** (critical)
5. Lifecycle hook + network call = **Install-Time Exfiltration** (critical)
6. SQL injection + MCP/skill_threats finding = **SQL Injection Prompt Escalation** (critical)
7. Tool metadata poisoning + code execution = **Tool Metadata Poisoning Chain** (critical)
8. Unicode smuggling + prompt injection in docs = **Hidden Instruction Attack in Documentation** (high)
9. Dynamic import + network fetch = **Deferred Payload Loading** (critical)
10. Time/counter trigger + exec/eval = **Time-Triggered Malware** (critical)
11. Dynamic tool description + MCP server = **MCP Rug Pull Enabler** (high)
12. Phantom dependency + network call = **Shadow Dependency with Network Access** (critical)
13. Pipe exfiltration + network sink = **Shell Script Data Exfiltration Chain** (critical)
14. Tools.json poisoning + prompt injection = **Agent Skill Compound Attack** (critical)

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

## GitHub Actions

Add to your workflow:
```yaml
- uses: alexgreensh/repo-forensics@v1
  with:
    mode: full
    format: text
    update-iocs: true
```

## Research Sources

See `references/research_sources.md` for full credits and links to the published research that informed this skill's threat detection capabilities.
