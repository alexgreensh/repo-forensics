# Research Sources & Credits

This skill's AI agent threat detection capabilities are informed by published security research. All detection patterns are original work, written from scratch based on the threat intelligence described in these sources.

## Primary Research

### Snyk: ToxicSkills - Malicious AI Agent Skills
- **Finding**: 13.4% of public AI agent skills have critical security issues
- **Key insight**: 91% of malicious skills combine code patterns (100%) with prompt injection (91%)
- **Attack vectors**: Credential exfiltration, backdoors in working code, obfuscated payloads
- **Impact on this skill**: Informed categories 1-4 of scan_skill_threats.py
- **Source**: [Snyk Finds Prompt Injection in 36%, 1467 Malicious Payloads in a ToxicSkills Study of Agent Skills Supply Chain Compromise](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)

### Koi Security: ClawHavoc Campaign
- **Finding**: 824 malicious skills on ClawHub (7.7% of marketplace)
- **Key insight**: AMOS stealer delivered via fake prerequisites with password-protected archives
- **Techniques**: xattr -c for macOS quarantine bypass, download-and-execute patterns
- **IOCs**: C2 IP addresses and domains used in the campaign
- **Impact on this skill**: Informed categories 3, 5, 8 of scan_skill_threats.py

## Complementary Tools

### skillsio by Alon Wolenitz
- **What it does**: Pre-installation gate for AI agent skills (npm CLI, scans before `skills add`)
- **License**: MIT
- **GitHub**: https://github.com/alonw0/secure-skills
- **Relationship**: We recommend skillsio as a complementary tool. It gates installation; we do deep forensic audits. Different use cases, both valuable. Our detection patterns are independently developed.

## 2025-2026 MCP & Agent Security Research

### Invariant Labs: Tool Poisoning Attack (TPA)
- **Finding**: Tool descriptions are loaded into LLM context without user visibility — arbitrary instructions can be embedded
- **Key insight**: The `<IMPORTANT>` tag pattern as canonical TPA indicator; Tool Shadowing as cross-tool contamination
- **Technique**: One tool's description modifies LLM behavior when calling other legitimate tools
- **Impact on this skill**: Informed `scan_mcp_security.py` TPA patterns and Category 10 of `scan_skill_threats.py`

### Trend Micro TrendAI: MCP SQL Injection → Prompt Escalation
- **Date**: May 2025
- **Finding**: SQL injection in MCP server code enables stored prompt injection — malicious prompts written to DB, later executed by agents
- **Key insight**: SQL injection isn't just a data risk in MCP context — it's a prompt execution risk
- **Impact on this skill**: Informed `scan_mcp_security.py` SQL patterns and Correlation Rule 6

### Koi Security: ClawHavoc Campaign (Updated 2026)
- **Updated finding**: 1,184 malicious skills on ClawHub (upgraded from 824); AMOS stealer delivery still via password-protected archives
- **New IOCs**: Extended C2 domain list, SANDWORM_MODE collaboration
- **Impact on this skill**: Updated IOC lists in `scan_skill_threats.py`

### Socket Research: SANDWORM_MODE npm Worm (Jan-Feb 2026)
- **Finding**: `McpInject` npm module poisons MCP configs in Claude Code and Cursor
- **Key insight**: Supply chain attack via typosquatted packages that modify local MCP configuration
- **IOC packages**: 17 known-malicious npm and PyPI packages documented
- **Impact on this skill**: `SANDWORM_KNOWN_IOC_PACKAGES` list in `scan_dependencies.py`

### Check Point Research: MCP Rug Pull
- **Finding**: MCP servers can change tool descriptions after user approval (rug pull) — approved server presents different behavior than what was audited
- **Key insight**: One-time approval is insufficient for MCP trust; behavioral drift is an attack vector
- **Impact on this skill**: `MCP_RUGPULL_PATTERNS` in `scan_mcp_security.py`

### Wiz Research: Indirect Prompt Injection via GitHub MCP
- **Finding**: Malicious content in GitHub issues can inject prompts into agents using the GitHub MCP tool
- **Key insight**: Any untrusted data source consumed by an MCP tool is a prompt injection vector
- **Impact on this skill**: Sampling exploitation patterns in `scan_mcp_security.py`

### CVE-2025-59536 (CVSS 8.7) — Claude Code Hooks RCE
- **Description**: Claude Code hooks configured in `.claude/settings.json` execute before the user trust dialog, enabling RCE via attacker-planted hook configurations
- **Impact on this skill**: `scan_claude_config()` in `scan_infra.py`

### CVE-2026-21852 (CVSS 7.5) — ANTHROPIC_BASE_URL API Key Exfiltration
- **Description**: Setting `ANTHROPIC_BASE_URL` in Claude Code configuration routes all API calls through an attacker-controlled proxy, exfiltrating every API key
- **Impact on this skill**: `scan_claude_config()` in `scan_infra.py`

### CVE-2025-49596 (CVSS 9.4) — MCP Inspector DNS Rebinding
- **Description**: MCP Inspector's development server binding to `0.0.0.0` exposes a DNS rebinding + CSRF attack surface to malicious websites
- **Impact on this skill**: `MCP_CONFIG_RISKS` detection in `scan_mcp_security.py`

### OWASP MCP Top 10 (2026)
- **Resource**: OWASP formal taxonomy of MCP vulnerability classes
- **Coverage in this skill**: MCP01 (Prompt Injection), MCP05 (Tool Poisoning), MCP06 (Insecure Tool Design), MCP09 (Supply Chain)

## Dead-Anchor / Repojacking Research (Skilljacking)

### AIR Security: Skilljacking
- **Finding**: A skill's prose/manifest/docs can reference an external anchor (a GitHub owner/repo, an npm/PyPI package named in an install command, a domain, or a free-tier cloud subdomain) that was live when the skill was authored but has since been deleted, renamed, or expired — leaving it **claimable by an attacker** with zero change to the file content.
- **Key insight**: Because the content never changes (no injected instruction, no secret, no malicious code), every existing content-scanner "tripped nothing at all" — the gap is *anchor claimability*, not content.
- **Attack vectors**: (1) deleted/renamed GitHub user/org → re-registerable username; (2) phantom/removed npm/PyPI package → squattable name; (3) unregistered/expired domain; (4) dangling free-tier cloud subdomain (Vercel/Railway/etc.) whose app was deleted.
- **Impact on this skill**: Motivated `scan_dead_anchors.py` (DA-01..DA-05, DA-09 free-tier flag, DA-10 owner-trust signals). Claimability is confirmed via read-only GitHub API / npm & PyPI registry / RDAP / DNS+fingerprint probes; a finding fires only on a confirmed-claimable anchor, never on a live one or a network hiccup.

### Circus of Skills: free-tier hosting suffixes
- **Finding**: 98 skills / ~1.6M installs referenced apps on trivially-reclaimable free-tier suffixes (`vercel.app`, `github.io`, …).
- **Impact on this skill**: The free-tier-suffix flag (DA-09) and the cloud-subdomain suffix list in `data/rulepacks/dead_anchors.json`.

### Snyk ToxicSkills — 8 live-malicious IOC URLs (negative control)
- **Use**: The ToxicSkills malicious IOC URLs (e.g. `clawhub.ai/...`) belong in `ioc_manager.py`'s signed IOC feed, and serve as negative-control fixtures confirming `scan_dead_anchors.py` does not double-fire or conflict with the existing IOC flag on the same anchor (IOC-badness ≠ claimability).

### SkillSieve dataset (test corpus, security-gated)
- **Resource**: `github.com/xiaohou521/skillsieve` — 49,592 skills + 400 labeled, permissively licensed; the most usable public dataset for benign/malicious fixtures.
- **Handling**: Extraction of any labeled folder into `tests/corpus/` is gated behind a mandatory repo-forensics-first scan of an isolated clone (Alex's standing external-code rule applied to the test data itself). Not automated; see `tests/corpus/DEAD_ANCHORS_CORPUS.md`.

## Note on Originality

Detection patterns in this skill are original work, informed by the threat intelligence published in the above research. No code was copied from any of the referenced tools or research. Regular expressions, detection logic, severity scoring, and correlation rules were all written from scratch based on documented attack techniques and indicators of compromise.
