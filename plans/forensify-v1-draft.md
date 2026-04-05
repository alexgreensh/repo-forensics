# Forensify: Agentic Narrative Mode for repo-forensics

**Status:** Draft v1 (pre-review)
**Target version:** 2.4.0
**Author:** Alex Greenshpun (via Claude planning session 2026-04-05)

---

## 1. Problem

A beta tester ran `run_forensics.sh` against their own large agent repo (plugin-heavy, many files) and got:

```
VERDICT: 16788 findings (253 critical, 15475 high, 130 medium, 930 low)
EXIT CODE: 2 (critical findings)
```

Dumped to terminal. Two concerns raised:

1. **"Is it alive?"** — During the scan, no per-scanner feedback. Users worry the tool is stuck or doing something untrustworthy. For a security tool, this is a trust problem, not just a polish problem.
2. **"That's overwhelming."** — 16k findings in terminal scrollback is unusable. User couldn't even scroll through them. There is no path from "wall of findings" to "what do I do on Monday."

Root causes split:

- **Noise floor inflation.** Issue #9 documents one canonical example: the `"send to"` keyword in `TOOL_INJECTION_KEYWORDS` is a substring matcher that fires on any English phrase containing those words (e.g., "send to the GPU"). It then cascades through Rule 19 correlation into multiple compound critical findings. One loose base pattern becomes four criticals multiplicatively. In a big codebase with lots of natural English in config/tool descriptions, this class of problem alone can account for thousands of phantom findings.
- **Presentation mismatch.** Scanners think in *events* (pattern matches). Users think in *risks* (decisions). The tool currently dumps events; the user needs a decision. The gap is where overwhelm lives, and no amount of better rendering fixes it — the output needs to move up the abstraction pyramid (verdict → themes → examples → details) rather than dump the bottom layer.

## 2. Goals

- Transform large scan results into **actionable narrative briefings** when a human is the consumer.
- **Preserve** hook/automation mode behavior exactly. Zero breaking changes to exit codes, JSON output, CI integration, or current shell invocation.
- Enforce **read-only, no-auto-action security posture** throughout. The tool analyzes. The user decides. The tool never modifies the scanned repo.
- Enable **state-based comparison** for users who audit their own evolving projects — "what changed since last scan" — strictly opt-in, local-only.
- Reduce **noise floor** from known false-positive classes (issue #9 and similar).

## 3. Non-goals

- Dashboards, HTML reports, TUIs, browser UIs. **The agent IS the UI.** All narrative lives in conversation.
- Auto-remediation, auto-fix, auto-patch, "want me to fix this?" followed by action. The tool will never modify scanned repos under any circumstances.
- State tracking for external/one-off scans. Privacy-preserving default: we remember nothing unless explicitly opted in.
- Severity score changes to the hook/CI contract. Scanner output schema stays stable.
- External network calls from the narrative layer (no live intel fetches during analysis).

## 4. Design Decisions (locked)

| # | Decision | Rationale |
|---|---|---|
| 1 | Two invocation modes: hook vs skill | Different consumers (machine vs human) need different presentation. Scanner layer unchanged. |
| 2 | Skill mode = new sibling skill, proposed name `forensify` | Clean separation from existing `repo-forensics` skill. User explicitly invokes when they want a briefing. |
| 3 | 6 parallel Sonnet domain sub-agents | Context isolation per domain, specialized prompts, parallelism, trustworthy security reasoning. |
| 4 | Opus for synthesis on heavy scans | Narrative quality + prioritization judgment are where the top model earns its cost. Single call = bounded. |
| 5 | Haiku only for routing/filter pre-processing | Cheap deterministic dedupe and categorization, never for analysis of findings. |
| 6 | Narrative shape: landscape → verdict → themes → noise → top 5 priority actions → drill-down invitation | Priority-framed, not timeline-framed. User refinement locked. |
| 7 | Opt-in state via sentinel file (`.forensify-state`) | Conservative default. Never tracks external repos. Local-only JSON. |
| 8 | Read-only, no auto-action | Non-negotiable security posture. Enforced at tool allowlist level. |

## 5. Architecture

### 5.1 Layer overview

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 1: Scanner layer (existing, unchanged)                │
│  - 18 scanners run in parallel                               │
│  - Produces: raw findings JSON                               │
│  - Consumers: hook mode (exit codes), skill mode (below)     │
└──────────────────────────────────────────────────────────────┘
                             │
            ┌────────────────┴────────────────┐
            │                                 │
            ▼                                 ▼
   ┌─────────────────┐          ┌──────────────────────────────┐
   │  Hook/CI mode   │          │  Skill mode (forensify, NEW) │
   │  - Exit codes   │          │  - Parses raw findings       │
   │  - Terse verdict│          │  - Spins up coordination fldr│
   │  - No narrative │          │  - Dispatches sub-agents     │
   │  - UNCHANGED    │          │  - Runs synthesis            │
   └─────────────────┘          │  - Narrates to user          │
                                │  - Optional state diff       │
                                └──────────────────────────────┘
                                             │
                                             ▼
                    ┌────────────────────────────────────────────┐
                    │  Coordination folder (NEW)                 │
                    │  /tmp/forensify-<hash>-<ts>/               │
                    │    raw/findings.json                       │
                    │    findings/theme_<domain>.md  (x6)        │
                    │    status/  (sub-agent liveness)           │
                    │    state/   (optional, opt-in only)        │
                    └────────────────────────────────────────────┘
                                             │
                     ┌───────────────────────┴───────────────────────┐
                     │                                               │
                     ▼                                               ▼
   ┌─────────────────────────────────┐        ┌──────────────────────────────┐
   │  Layer 3: Domain sub-agents     │        │  Layer 4: Synthesis agent    │
   │  6 parallel Sonnet calls        │        │  1 call (Opus if heavy)      │
   │  Tools: Read, Grep, Glob ONLY   │─ ──>   │  Reads theme summaries only  │
   │  Scope: target path (read-only) │        │  Produces narrative          │
   │  Output: theme_<domain>.md      │        │  Returns to user             │
   └─────────────────────────────────┘        └──────────────────────────────┘
```

### 5.2 Domain mapping (18 scanners → 6 risk domains)

| Domain | Scanners |
|---|---|
| **1. Secrets & credentials** | `scan_secrets`, `scan_entropy` |
| **2. Supply chain integrity** | `scan_dependencies`, `scan_infra`, `scan_integrity`, `scan_manifest_drift`, `scan_lifecycle` |
| **3. Code execution risk** | `scan_sast`, `scan_ast`, `scan_runtime_dynamism`, `scan_binary`, `scan_dast` |
| **4. AI / tool poisoning** | `scan_mcp_security`, `scan_skill_threats`, `scan_openclaw_skills` |
| **5. Data flow & exfiltration** | `scan_dataflow` |
| **6. Git history & post-incident** | `scan_git_forensics`, `scan_post_incident` |

Domains with zero findings are skipped entirely (no sub-agent spawned, noted in synthesis as "no findings in X, good news").

### 5.3 Sub-agent contract

**Input to each domain sub-agent:**
- Scanner slice: findings from its assigned scanners only
- Target repo path (absolute, read-only)
- Domain-specific system prompt (specialist persona)
- Optional: previous-scan summary if state tracking enabled
- Finding cap: max 500 findings per domain (deterministic dedupe first, then sample with note)

**Tool allowlist (hard limit):**
- `Read`, `Grep`, `Glob` only
- No `Edit`, `Write`, `Bash` against the target path
- Can write only to its own `findings/theme_<domain>.md` file in the coordination folder

**Output schema (structured markdown):**
```markdown
# Theme: <domain name>

## Summary
<1-2 paragraph human-language overview>

## Real risks
- [severity] <finding> at <file:line>
  - Why it matters for this repo: <context-aware explanation>
  - Evidence: <actual code quote>
  - Suggested fix (narrative only, never applied): <remediation>

## False positives / noise
- <pattern> — <N occurrences> — reason for dismissal
- ...

## Severity reassessment
<scanner said X, I think Y, because Z>

## Representative examples
<2-3 items chosen to teach the shape of the problem, not the worst items>
```

Sub-agents are forbidden from inventing findings. Every item must trace to a real scanner finding + a real file:line they verified by reading the source.

### 5.4 Synthesis agent contract

**Input:**
- ONLY the 6 theme summary files (not raw findings)
- Scan metadata (repo size, scan duration, scanner versions)
- Optional: state diff summary if opted in

**Output (to user):**
```
Landscape: "You scanned a ~X-file repo with N plugins. We ran 18 scanners
and found patterns across K risk themes."

Verdict: <one honest sentence>

Theme walkthroughs (3-5, prioritized):
  - Theme name
  - Why it's risky for THIS repo
  - 2-3 representative examples with file:line
  - What to do about it (narrative only)

Noise: <one paragraph if there was significant noise>

Top 5 priority actions (priority-framed, not timeline):
  1. <Theme> → <specific fix>
  2. ...
  "Tackle these themes first; within them, these specific fixes are the
   most important."

Drill-down invitation: "Want me to dig deeper into any theme?"
```

Model: Opus if `total_findings > 5000` OR `--deep` flag, else Sonnet.

## 6. Three Tracks

### Track A — Noise floor + liveness (small, ships first if needed)

**Scope:**
- Fix issue #9: tighten `TOOL_INJECTION_KEYWORDS` in `scan_mcp_security.py:63`
  - Replace bare `"send to"` with anchored variants: `"send to http"`, `"send to ftp"`, `"send data to"`, `"send credentials to"`, `"send ... to <URL>"` (regex)
  - Audit other bare substrings in the same list for similar issues
- Add correlation-engine guard: low-confidence base findings must have at least N corroborating signals before cascading into compound Rule 19 criticals. One loose keyword match should not produce a compound critical on its own.
- Add per-scanner progress lines in `run_forensics.sh` as each scanner completes:
  ```
  [OK] scan_secrets: 23 findings (2.1s)
  [OK] scan_dependencies: 0 findings (0.8s)
  [WARN] scan_mcp_security: 47 findings (3.4s)
  ```
- Add `--quiet` flag to suppress progress lines (CI consumers stay silent)
- Expand default `.forensicsignore` with conservative vendor/build exclusions: `node_modules/`, `dist/`, `build/`, `vendor/`, `.venv/`, `__pycache__/`, `.pytest_cache/` — users can override

**Non-breaking guarantees:**
- Exit codes unchanged
- JSON output schema unchanged
- `--quiet` defaults off (progress lines visible for interactive use) but CI runners can opt in
- `.forensicsignore` additions are documented; existing users can override by editing their local file

**Could ship as 2.3.1 patch release before Track B/C land.** Decision deferred to plan_review.

### Track B — Forensify skill (the main feature)

**Scope:**
- New skill file: `skill/forensify/SKILL.md` (sibling to existing `skill/SKILL.md`, same plugin)
- Orchestrator entry: `skill/scripts/forensify.py`
  - Invokes `run_forensics.sh` internally with JSON output
  - Parses raw findings
  - Creates coordination folder
  - Dispatches 6 domain sub-agents in parallel (via Agent tool)
  - Waits for completion, reads theme summaries
  - Dispatches synthesis agent
  - Returns narrative to user
- Sub-agent prompts: 6 domain prompts + 1 synthesis prompt as template files in `skill/forensify/prompts/`
- Coordination folder management + cleanup (keep last N runs for debugging, prune older)
- Finding cap + dedupe logic (deterministic pre-processing before sub-agents see data)

**Orchestrator state machine:**
```
1. Validate target path, absolutize, read-only check
2. Run scanners via run_forensics.sh --format json
3. Parse findings, group by domain
4. Dedupe + cap per domain (keep signal, drop repetition)
5. Create coordination folder
6. Check state sentinel → load previous state if opted in
7. Dispatch 6 domain sub-agents in parallel (Sonnet, read-only tools)
8. Poll findings/ folder for all 6 theme files
9. Dispatch synthesis agent (Opus or Sonnet based on volume/flag)
10. Return synthesis output to user
11. Update state JSON if opted in
12. Optionally clean up coordination folder (keep on error for debugging)
```

**Failure modes:**
- Sub-agent times out → synthesis agent gets a placeholder for that theme with a warning
- Sub-agent crashes → retry once, then placeholder
- Scanner fails → existing run_forensics.sh error handling, skill mode surfaces error clearly, does NOT attempt partial analysis
- All 6 sub-agents fail → fall back to deterministic summary (counts by domain) + error message
- Synthesis fails → return raw theme summaries to user with apology

### Track C — Internal-project state (opt-in, depends on Track B)

**Scope:**
- Sentinel file: `.forensify-state` at repo root (presence = opt-in, contents = optional config)
- State storage: `~/.config/repo-forensics/state/<sha256-of-abs-path>.json`
- State schema:
  ```json
  {
    "repo_path": "/absolute/path",
    "created_at": "2026-04-05T...",
    "scans": [
      {
        "timestamp": "...",
        "scanner_version": "2.4.0",
        "verdict": "caution",
        "finding_counts": {"critical": 3, "high": 12, ...},
        "themes": [
          {"domain": "secrets", "risk_level": "high", "key_findings": [...]}
        ]
      }
    ],
    "accepted_risks": [
      {"finding_id": "...", "accepted_at": "...", "note": "..."}
    ]
  }
  ```
- State diff logic: compare current scan to most recent prior scan
  - New findings (appeared since last scan)
  - Resolved findings (present last time, absent now)
  - Unchanged findings
  - Regressions (previously accepted → now worse)
- Synthesis agent receives state-diff summary and narrates: "Since your last scan on <date>, these N findings are new, these M are resolved, and these K you previously accepted as known risks are still present."

**Privacy guarantees:**
- Sentinel file is the ONLY way state is ever recorded
- One-off scans on unfamiliar repos never touch state storage
- State storage never leaves local filesystem
- User can `rm -rf ~/.config/repo-forensics/state/` at any time to wipe

## 7. Non-breaking Guarantees (hard requirements)

- `./skill/scripts/run_forensics.sh <path>` behavior: **identical** in default mode
- Exit codes: **identical** (0 = clean, 1 = warnings, 2 = critical)
- JSON output schema: **additive only** (new fields OK, existing fields untouched)
- `action.yml` CI integration: **unchanged**
- Existing hook auto-scan behavior: **unchanged**
- Progress lines added behind `--quiet` so CI with fixed-output parsing can opt for silence
- New functionality lives entirely in the new `forensify` skill path; it is unreachable from existing entry points
- Regression tests must cover all current behavior before and after

## 8. Security Posture (non-negotiable)

1. **Read-only against the target.** Sub-agents spawned with tool allowlist: `Read, Grep, Glob`. No `Edit`, `Write`, `Bash`, or `WebFetch` against target paths.
2. **No auto-action ever.** The narrative may SUGGEST fixes in prose. It may NOT apply them. There is no "fix it for me" button, no auto-remediation path, no hidden writes. The user decides what to fix, the user runs their own remediation (which might be Claude Code in a separate invocation with explicit consent).
3. **Scope enforcement.** Sub-agents receive absolute paths. Reads outside the target path are rejected. Consider macOS Seatbelt sandbox (already used for DAST) as defense in depth.
4. **No network calls from sub-agents.** No live intel fetches. All analysis is local and self-contained.
5. **No credential access.** Sub-agents are explicitly forbidden from reading `~/.ssh`, `~/.aws`, `~/.config`, env files outside the target, keychain, etc.
6. **State JSON is local.** Never uploaded, never sent. User-owned.
7. **Coordination folder is ephemeral.** `/tmp` by default, cleaned after run on success. On failure, preserved for debugging with a clear log line.

## 9. Models & Cost

| Layer | Model | Call count | Typical cost |
|---|---|---|---|
| Pre-processing (dedupe, categorize) | Haiku | 1 | <$0.01 |
| Domain sub-agents | Sonnet | 6 (parallel) | $0.30-$1.00 |
| Synthesis | Sonnet (default) or Opus (heavy) | 1 | $0.10-$0.80 |
| **Typical skill-mode total** | — | — | **$0.50-$2.00** |

Hook mode cost: **$0.00** (unchanged, no models involved).

## 10. Success Criteria

- [ ] Beta tester can run forensify on investor repo and get a 5-theme narrative briefing with top 5 priority actions, within ~90s after scan completes
- [ ] Hook mode regression tests all pass (exit codes, JSON contract, CI action)
- [ ] Issue #9 closed and verified by re-running the Flowise reproduction case
- [ ] No auto-action paths exist in the codebase (verified by code review + grep for Write/Edit/Bash in sub-agent code paths)
- [ ] State JSON works for opted-in internal projects and is provably inert for external scans
- [ ] `forensify` skill has its own SKILL.md, tests, and entry point
- [ ] Release notes use forward-positive framing, no public bug-shaming
- [ ] All changes gated by security-sentinel + kieran-python-reviewer + torture-room before ship

## 11. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Sub-agent hallucinates severity reassessment | Require file:line + verbatim code quote in output; synthesis double-checks claims against raw findings |
| Cost blowup on pathologically large scans | Per-domain finding cap (500), deterministic dedupe before sub-agents, clear user warning if capping triggered |
| Sub-agent reads outside target scope | Absolute path enforcement + optional Seatbelt sandbox |
| User confuses hook vs skill mode | Clear README split, distinct skill names (`repo-forensics` vs `forensify`), first-run hint in skill output |
| State JSON privacy leak | Sentinel-based opt-in (never auto), local-only, documented wipe instructions |
| Non-breaking regression | Pre-existing test suite runs before and after, green required |
| Sub-agent crash cascades to user-facing error | Graceful degradation: timeout → placeholder theme, total failure → deterministic fallback summary |
| Synthesis agent invents recommendations not grounded in findings | Synthesis prompt requires every recommendation to cite a theme + finding; post-check rejects ungrounded claims |

## 12. Rollout (production workflow per established practice)

1. **Plan written** ✓ (this document)
2. **compound-engineering plan_review** — multi-agent parallel critique of this plan
3. **Iterate plan** based on review findings
4. **Create worktree + branch** `feat/forensify-skill-mode`
5. **Track A implementation + tests** (can ship as 2.3.1 if desired)
6. **Track B implementation + tests**
7. **Track C implementation + tests**
8. **Ralph loops** for edge cases (large repos, pathological finding distributions, non-English source, Hebrew/RTL paths like the tester's environment)
9. **compound-engineering torture-room** QA gauntlet
10. **security-sentinel** review (this is a security tool — no exceptions)
11. **kieran-python-reviewer** pass
12. **Version bump** 2.3.0 → 2.4.0 in `plugin.json`, `.claude-plugin/marketplace.json`, README badge
13. **Tag, gh release create, verify Latest badge**

## 13. Open Questions (for plan_review to attack)

1. **Domain count: 6 right?** Should AI/tool poisoning split from skill threats? Should dataflow merge with secrets? Should git forensics be its own domain when it mostly surfaces secrets in history?
2. **Opus synthesis worth the cost?** On heavy scans, does Opus meaningfully improve narrative quality over Sonnet, enough to justify ~2x cost? Could A/B on a sample corpus.
3. **One skill or two?** `forensify` as a sibling skill in the same plugin, vs. a flag on the existing skill (`repo-forensics --narrative`), vs. a separate plugin entirely. Sibling skill is current lean but plan_review should challenge this.
4. **Scope enforcement**: tool allowlist alone, or also Seatbelt sandbox for defense in depth? The DAST scanner already uses Seatbelt — reusable?
5. **Sentinel vs registry** for state opt-in: is `.forensify-state` in the repo root the right signal, or should we use a config-level registry of tracked paths? Sentinel is more explicit per-repo, registry is more user-controlled.
6. **Track A ship separately?** Patch release 2.3.1 for noise fixes + liveness, THEN minor release 2.4.0 for forensify? Or bundle everything in 2.4.0?
7. **Sub-agent failure fallback**: timeout → placeholder vs retry vs escalate vs deterministic fallback. What's the right default?
8. **Machine-readable narrative?** Should forensify offer `--format json` for the narrative so other agents can consume it structurally? Or is the agentic conversation the only interface?
9. **How are sub-agents actually spawned?** Via the Agent tool within the orchestrator Python script (invoke Claude subprocess), or via a separate CLI shim? Implementation detail but affects complexity.
10. **Re-runs during active editing**: if the user runs forensify, edits files, reruns — does the coordination folder need to invalidate? How do we prevent stale theme summaries from leaking across runs? (Fresh folder per run, keyed by timestamp, is the obvious answer but worth locking.)

## 14. Out of Scope (explicit)

- Windows / Linux sandbox equivalent to Seatbelt (macOS only for now, matches existing tool posture)
- Multi-user / team-mode state (single local user per machine)
- Integrations with external issue trackers (no auto-create GitHub issues from findings)
- IDE plugin (`forensify` runs in terminal via Claude Code only)
- Real-time watch mode for skill mode (hook mode already has `--watch`; skill mode is on-demand)
- Historical CVE correlation beyond what scanners already do

---

**Next step:** dispatch `compound-engineering:plan_review` against this document for parallel multi-agent critique. Iterate, then begin implementation in a feature worktree.
