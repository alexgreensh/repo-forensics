# Research References

repo-forensics is original work. Its detection code, correlation rules, scoring, and
architecture were written by **Alex Greenshpun**. The *vulnerability classes and attack
techniques* those detectors look for were, in many cases, first disclosed by other security
researchers. This file credits that prior work, links the primary sources, and records the
live data feeds and standards repo-forensics builds on.

If we implement detection for a technique, the researcher who **disclosed the technique** is
credited here, and the **detector implementation** is repo-forensics. Cataloguing prior work
is not the same as originating it; this file keeps that line clear.

Provenance is git-dated: every scanner's first commit is in this repo's history, so the
"shipped on" dates below are verifiable, not asserted. Sources are listed most recent first.

---

## Vulnerability research and disclosures

| Technique / disclosure | Researcher | Date | repo-forensics scanner | Detector shipped |
|---|---|---|---|---|
| **Bytecode / source divergence** (malicious `.pyc` shipped over benign `.py`; CPython loads the cache over source) | [**CSA / Trail of Bits**, "AI Agent Skill Scanners: Bypassed Across the Board"](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/) | 2026-06-10 | `bytecode` | 2026-06-17 |
| **Context-loader bypass** (zip saved as `.instructions.docx.txt` to evade skill loaders) | [**Trail of Bits**, "The sorry state of skill distribution"](https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/) | 2026-06-03 | `archive`, `oversize` | 2026 |
| **Dead-anchor / SkillJacking** (repojacking of deleted GitHub owners, phantom npm/PyPI packages, expired domains, dangling cloud subdomains) | [**AIR Security**, "The Story of Skills"](https://www.air.security/blog-posts/the-story-of-skills) | 2026-06 | `dead_anchors` | 2026-07-04 |
| SANDWORM_MODE / McpInject npm worm (Shai-Hulud-style; injects a rogue MCP server) | [Socket](https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning) | 2026-02 | `dependencies` | |
| ClawHavoc campaign (1,184 malicious skills, AMOS stealer delivery) | [Koi Security](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) | 2026 | `skill_threats`, `agent_skills` | |
| ToxicSkills (36.8% of skills have flaws; 91% combine code + prompt injection) | [Snyk](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub) | 2026 | `skill_threats` | |
| Tool Poisoning success rate (72.8%, MCPTox benchmark) | [Repello AI](https://repello.ai/blog/mcp-security) | 2026 | `runtime_dynamism` | |
| MCP contract diffs (tool descriptions changed without code changes) | [Lukas Kania](https://medium.com/@binarEx/your-mcp-servers-tool-descriptions-changed-last-night-nobody-noticed-e3ad93cf6bc7) | 2026 | `mcp_security`, `runtime_dynamism` | |
| Model Confusion (dependency confusion for AI model registries) | [Checkmarx](https://checkmarx.com/zero-post/hugs-from-strangers-ai-model-confusion-supply-chain-attack/) | 2026 | `sast` | |
| liteLLM `.pth` injection (malicious `.pth` auto-exfiltrates creds on `pip install`) | Socket / community disclosure | 2026 | `lifecycle`, `dependencies` | |
| Axios / `plain-crypto-js` supply-chain compromise (hijacked maintainer, RAT dropper) | community disclosure | 2026 | `dependencies`, `lifecycle`, `post_incident` | |
| PylangGhost RAT (benign v1.0.0 weaponized in v1.0.1) | community disclosure | 2026 | `manifest_drift`, `runtime_dynamism` | |
| TeamPCP campaign (cascading supply chain, WAV steganography) | community disclosure | 2026 | `infra`, `dependencies`, `binary`, `skill_threats` | |
| Tool Poisoning (`<IMPORTANT>` tag as canonical TPA) | [Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | 2025 | `mcp_security` | |
| SQL to Prompt escalation (SQL injection stores malicious prompts) | [Trend Micro](https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html) | 2025 | `mcp_security` | |
| Lies-in-the-Loop (HITL dialog manipulation via text padding) | [Checkmarx](https://checkmarx.com/zero-post/bypassing-ai-agent-defenses-with-lies-in-the-loop/) | 2025 | `skill_threats` | |
| 11 emerging MCP risks (attack taxonomy) | [Checkmarx](https://checkmarx.com/zero-post/11-emerging-ai-security-risks-with-mcp-model-context-protocol/) | 2025 | `mcp_security` | |
| Shai-Hulud (first NPM worm, destructive fallback, self-hosted runner backdoor) | [Checkmarx](https://checkmarx.com/zero-post/inside-shai-huluds-maw-how-the-npm-worm-exploits-and-propagates/) | 2025 | `sast`, `skill_threats`, `dependencies` | |
| NuGet time bombs (hardcoded future activation dates) | [Socket](https://socket.dev/blog) | 2025 | `runtime_dynamism` | |
| Command-Jacking (entry-point hijack via console_scripts shadows system CLIs) | [Checkmarx](https://checkmarx.com/blog/this-new-supply-chain-attack-technique-can-trojanize-all-your-cli-commands) | 2024 | `lifecycle` | |
| StarJacking (packages claim popular repos to steal star counts) | [Checkmarx](https://checkmarx.com/blog/starjacking-making-your-new-open-source-package-popular-in-a-snap/) | 2022 | `dependencies` | |

---

## CVEs referenced by detections

Linked to the NIST National Vulnerability Database. Most recent first.

| CVE | Severity | Finding | Scanner |
|---|---|---|---|
| [CVE-2026-45321](https://nvd.nist.gov/vuln/detail/CVE-2026-45321) | CVSS 9.6 | TanStack npm OIDC trusted-publisher abuse: 42 `@tanstack/*` packages publish a credential stealer | `dependencies`, `lifecycle`, `post_incident` |
| [CVE-2026-33068](https://nvd.nist.gov/vuln/detail/CVE-2026-33068) | | Claude Code workspace-trust bypass via committed `.claude/settings.json` `defaultMode` (<v2.1.53) | `integrity`, `infra` |
| [CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852) | CVSS 7.5 | `ANTHROPIC_BASE_URL` API-key exfiltration | `mcp_security` |
| [CVE-2026-2297](https://nvd.nist.gov/vuln/detail/CVE-2026-2297) | | Python SourcelessFileLoader audit bypass | `ast`, `runtime_dynamism` |
| [CVE-2025-59536](https://nvd.nist.gov/vuln/detail/CVE-2025-59536) | CVSS 8.7 | Claude Code hooks RCE before trust dialog | `integrity`, `infra` |
| [CVE-2025-49596](https://nvd.nist.gov/vuln/detail/CVE-2025-49596) | CVSS 9.4 | MCP Inspector DNS rebinding | `mcp_security` |
| [CVE-2025-30066](https://nvd.nist.gov/vuln/detail/CVE-2025-30066) | | tj-actions/changed-files supply-chain compromise | `infra`, `dependencies` |
| [CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514) | CVSS 9.6 | mcp-remote OAuth command injection | `mcp_security` |

---

## Live data sources and threat feeds

repo-forensics queries these at scan time (all read-only, most opt-out with `--offline`).

| Source | Use | Endpoint |
|---|---|---|
| **OSV** (Open Source Vulnerabilities, Google) | Per-package known-vulnerability lookup | `https://api.osv.dev/v1/query` |
| **CISA KEV** (Known Exploited Vulnerabilities) | In-the-wild exploitation flag (escalates to CRITICAL) | `https://www.cisa.gov/.../known_exploited_vulnerabilities.json` |
| **GitHub REST API** | Owner/repo existence + claimability probes (dead anchors) | `https://api.github.com` |
| **PyPI** | Package existence / phantom-package probes | `https://pypi.org/pypi/<name>/json` |
| **npm registry** | Package existence / phantom-package probes | `https://registry.npmjs.org` |
| **RDAP** | Domain registration / expiry probes (dead anchors) | `https://rdap.org/domain/<domain>` |

---

## Standards and frameworks

repo-forensics maps findings to established frameworks so results land where defenders already work.

| Standard | Body | Link |
|---|---|---|
| OWASP Top 10 for LLM Applications | OWASP | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| OWASP MCP Top 10 | OWASP | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| MITRE ATLAS | MITRE | https://atlas.mitre.org |
| NIST AI Risk Management Framework | NIST | https://www.nist.gov/itl/ai-risk-management-framework |
| CWE (Common Weakness Enumeration) | MITRE | https://cwe.mitre.org |

---

## A note on provenance

The detection *techniques* here are, wherever noted, the work of the researchers credited above.
repo-forensics' contribution is the working detection: the scanners, the correlation engine, the
scoring, and the signed rule distribution. We credit the source of an idea when we implement it,
and we keep our own findings in this repo's history so the provenance of our own work is equally
clear.

*Maintained by Alex Greenshpun. Corrections welcome via issue or PR.*
