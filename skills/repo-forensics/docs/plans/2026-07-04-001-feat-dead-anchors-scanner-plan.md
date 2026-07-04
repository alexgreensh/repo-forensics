---
title: "feat: Dead-Anchor / Repojacking Scanner (scan_dead_anchors.py)"
date: 2026-07-04
type: feat
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
origin: "DATA/SESSIONS/active/repo-forensics-skilljacking-2026-07-04/spec/DETECTION_SPEC.md (PERSONAL_OS repo; synthesized from findings/A_air_primary.md, B_secondary_vectors.md, C_academic_taxonomy.md, D_coverage_audit.md)"
---

# feat: Dead-Anchor / Repojacking Scanner

## Summary

Every skill/repo scanned today can reference a GitHub owner/repo, an npm/PyPI package, a bare domain, or a free-tier cloud subdomain that has since gone dead and become **claimable by an attacker** — the exact "Skilljacking" mechanic AIR's research post describes as tripping zero existing scanners, ours included. This plan adds `scan_dead_anchors.py`: an algorithmic (non-per-file) scanner that extracts every external anchor a skill points at, probes each for claimability via hardened HTTPS/DNS/RDAP calls through the already-audited `vuln_feed._https_fetch` plumbing, and emits a finding only when the anchor is definitively re-registerable — never on a live anchor, never on a network hiccup. It ships OSS, offline-degradable, and correlatable with repo-forensics' other 25 scanners, beating AIR's closed, methodology-silent SaaS on every axis the research surfaced.

## Problem Frame

AIR's Skilljacking research (and the corroborating academic/secondary-vector research in this session's `findings/`) identifies a structural gap: a skill's prose, manifest, or docs can point at an anchor (GitHub user, package name, domain, cloud subdomain) that was live when the skill was written but has since been deleted, renamed, or expired. The content itself never changes — no secret, no injected instruction, no malicious code — so every existing repo-forensics scanner (secrets, SAST, skill_threats, dependencies' typosquat/IOC matching) is silent, because none of them ask "is this reference *still owned by whoever the author meant*?" That is the gap this scanner closes.

**Deferred note (verdict-decay):** an anchor confirmed live-and-owned at scan time can still decay to claimable weeks later with zero local file change (DA-07/DA-P2-5). Closing that gap needs new per-anchor persistent state that repo-forensics has no equivalent of today (the existing 24h caches in `vuln_feed`/`refresh_threat_dbs` are feed caches, not scan-result state). This plan builds the stateless P0/P1 core and defers the recheck/decay architecture to Phase 2 (see below) rather than building persistent state twice for DA-07 and its sibling DA-P2-5 (content-drift hashing).

**Non-negotiable framing (Alex's explicit worry):** a network-touching scanner is the one shape in this codebase that can go wrong in three specific, user-visible ways — loops (retry storms, rate-limit hammering), races (concurrent scans corrupting shared cache state), and latency (a slow/hostile host hanging the whole scan). This plan treats freedom from all three as a hard acceptance gate, not an implementation detail: every probe is single-attempt with no retry, every host gets a per-scan circuit breaker, every cache write is atomic-and-lock-free, and the entire claimability pass runs under one wall-clock deadline. The scanner must feel weightless — `--offline` sub-second, a live scan bounded and provably terminating regardless of what the network does. See "Concurrency & Loop-Safety Contract" below, which the torture-room phase attacks directly (spec §10).

## Requirements Traceability

| Spec ID | Description | Status |
|---|---|---|
| DA-01 | GitHub user/org deleted/renamed → re-registerable | **In scope** (U2, U3) |
| DA-02 | GitHub repo gone under a still-live user | **In scope** (U2, U3) |
| DA-03 | Phantom/removed npm or PyPI package from a prose install command | **In scope** (U2, U3) |
| DA-04 | Unregistered/lapsed domain via RDAP | **In scope** (U2, U3) |
| DA-05 | Dangling cloud-hosting subdomain (DNS + fingerprint) | **In scope** (U2, U3) |
| DA-09 | Free-tier-hosting-suffix structural flag (zero extra network cost) | **In scope** (U3) |
| DA-10 | GitHub-owner trust signals (account age, repo count) — free off DA-01's response | **In scope** (U3), bundled per open question 7's resolution (see Decisions Log) |
| DA-06 | Joint prose+code credential-leak correlation | **Deferred** (Follow-Up Work) |
| DA-07 | Verdict-decay / time-based recheck | **Deferred** (Phase 2 — needs persistent state) |
| DA-08 | Untrusted-external-instruction-fetch structural flag | **Deferred** (Follow-Up Work — scope boundary vs `scan_runtime_dynamism.py` needs a design pass) |
| DA-11 | Reputation-inheritance abuse (star-count + recent-PR heuristic) | **Deferred** (Follow-Up Work — lower confidence, needs commit-date-vs-file-date heuristic) |
| DA-P2-1..7 | Reasoning-layer attacks, LLM jury, sandboxed dynamic testing, WHOIS scoring, content-drift hashing, platform governance, runtime egress monitoring | **Deferred** (Phase 2 / out of scanner scope entirely for P2-6) |

Already-covered categories (prompt injection, secrets, SAST, typosquatting, dependency confusion, provenance tampering, git tampering, etc.) are explicitly NOT rebuilt here — see spec §2 "Already covered" table; this scanner's job is exclusively anchor claimability.

## Scope Boundaries

**In scope**
- `scripts/scan_dead_anchors.py`: standalone algorithmic scanner, `SCANNER_NAME = "dead_anchors"`.
- Anchor extraction (GitHub URL/shorthand, prose package-install commands, bare domains, cloud subdomains) from `SKILL.md`/`AGENTS.md`/etc. (reusing `_shared_patterns.SEED_FILES`) and MCP manifest files (`.mcp.json`).
- Claimability probes for the 5 P0 anchor types (DA-01 through DA-05) via a thin wrapper over `vuln_feed._https_fetch`.
- DA-09 (free-tier-suffix flag) and DA-10 (GitHub-owner trust signals), both zero-marginal-cost extensions of the P0 probes.
- `data/rulepacks/dead_anchors.json`: pack-driven extraction regexes, cloud-suffix list, safe-domain allowlist, GitHub reserved-word exclusions.
- A small bundled multi-part-TLD data file for eTLD+1 domain reduction (documented as an imprecise heuristic, not a full PSL).
- Registration into `SKILL.md`, `run_forensics.sh`, `auto_scan.py`, `gen_rule_ids.py`, `tests/test_non_breaking_contract.py`.
- Full test suite: positive/negative/never-hard-fail, all network monkeypatched, plus benign-corpus additions.

**Deferred to Follow-Up Work**
- **DA-06** — joint prose+code credential-leak correlation. Needs a new cross-scanner correlation shape (SKILL.md prose near a credential pattern vs. the actual code sink); distinct project, not part of anchor claimability.
- **DA-07** — verdict-decay / time-based recheck. Needs new per-anchor persistent scan-result state (does not exist in repo-forensics today); biggest single architecture decision, explicitly punted (see Decisions Log).
- **DA-08** — untrusted-external-instruction-fetch structural flag. Needs an explicit scope line against `scan_runtime_dynamism.py` (code-level fetch-then-execute) before it can be built without double-firing on the same "fetch external content" pattern from the prose angle.
- **DA-11** — reputation-inheritance abuse. Lower-confidence heuristic (commit-date-vs-file-date), needs its own validation pass against real repos before it's worth shipping.
- **All P2 items** (DA-P2-1 through DA-P2-7) — reasoning-layer/LLM-jury/sandboxed-dynamic-testing/WHOIS-scoring/content-drift-hashing/platform-governance/runtime-egress-monitoring. Different scanner shapes, heavier infra, or not a scanner concern at all (P2-6). See Phase 2 / Future.

**Out of scope entirely**
- Any change to existing scanners' detection logic (secrets, SAST, skill_threats, dependencies, provenance, etc.) — this is purely additive.
- WHOIS/registrar-reputation scoring beyond the RDAP registered/unregistered signal (DA-P2-4).
- Any code that requires a paid API key for baseline operation (`GITHUB_TOKEN` stays optional-never-required, per Alex's standing "no API keys for graceful UX" rule).

## High-Level Technical Design

Pipeline (single pass per scan):

```
repo/skill files (SEED_FILES + .mcp.json)
        │
        ▼
┌─────────────────────────┐
│ U1: anchor extraction    │  pack-driven regexes (dead_anchors.json)
│  - GitHub URL/shorthand  │  + safe-domain allowlist + reserved-word skip
│  - prose package-install │  + cloud-suffix list + mini multi-part-TLD file
│  - bare domain           │
│  - cloud subdomain       │
└────────────┬─────────────┘
             │ list[Anchor(type, value, ...)]
             ▼
┌──────────────────────────────────────────────────────────┐
│ U2: claimability probe layer (thin wrapper over            │
│     vuln_feed._https_fetch — HTTPS-only, size-capped,      │
│     timeout-bounded, atomic 0o600 cache, --offline bypass) │
│                                                              │
│   for each anchor (GH call budget ~15-20/scan enforced):    │
│     try fetch → urllib.error.HTTPError caught FIRST         │
│       .code == 404            → CC (signal, not failure)    │
│       .code in {403,429,5xx}  → NC (silent)                 │
│     generic URLError/timeout  → NC (silent)                 │
│     200                       → LO (silent)                 │
└────────────┬─────────────────────────────────────────────┘
             │ verdict per anchor: CC | LO | NC
             ▼
┌─────────────────────────┐
│ U3: scan_dead_anchors.py │  3-tier classify → Finding only on CC
│  scan_repo(repo_path)    │  DA-09 (free-tier suffix) + DA-10 (owner trust)
│  -> list[Finding]        │  bundled in, zero extra network cost
└────────────┬─────────────┘
             │
             ▼
   core.output_findings() / correlation engine (cross-scanner, unchanged)
```

The never-hard-fail contract is the load-bearing design constraint: `LO` and `NC` are BOTH silent (no Finding), and only `CC` (confirmed-claimable) emits. This mirrors `scan_provenance.py`'s three-tier signal partition exactly, renamed for this domain (see Key Technical Decisions, KTD-3).

## Key Technical Decisions

**KTD-1 — Standalone algorithmic scanner, not a per-file walk.**
`scan_repo(repo_path, ignore_patterns=None) -> list[Finding]` iterates *extracted anchors*, not `core.walk_repo`. Mirrors `scan_provenance.py`'s shape exactly (`ignore_patterns` accepted for uniform registration but unused, since this is an artifact/anchor-level check). Registered as a standalone scanner in `tests/test_non_breaking_contract.py`'s `EXPECTED_BASE_SCANNER_NAMES` set, same bucket as `"provenance"` and `"splitstream"`.

**KTD-2 — All network calls go through one wrapper over `vuln_feed._https_fetch`.**
No fourth hand-rolled `urlopen` call site. The wrapper enforces HTTPS-only, a fixed User-Agent, `NETWORK_TIMEOUT_SEC`, and a response byte cap, matching every existing network-touching scanner. DNS resolution for cloud subdomains (`socket.gethostbyname`) is the one exception — it has no HTTP equivalent and is called directly, wrapped in the same try/except discipline (`socket.gaierror` → NC, never a crash).

**KTD-3 — HTTPError-first branching inverts the exact anti-pattern in `vuln_feed.fetch_npm_freshness`/`fetch_pypi_freshness`.**
Those two functions (`vuln_feed.py` lines ~594 and ~690-694) catch the generic `urllib.error.URLError` first, which silently collapses a real, informative 404 into the same `return None` as a genuine network failure. `urllib.error.HTTPError` subclasses `URLError`, so this scanner's fetch wrapper catches `HTTPError` FIRST and branches on `.code`: `404` is signal (CC), `403`/`429`/`5xx` is `NC`, anything else unexpected is `NC`. The generic `URLError`/timeout/`socket.error` catch comes second and always yields `NC`. This ordering is the single most important correctness property in the whole scanner — get it backwards and every CC downgrades to a silent NC, and the scanner detects nothing.

**KTD-4 — Three-tier signal partition (CC/LO/NC), with LO and NC BOTH silent.**
Directly ports `scan_provenance.py`'s `_TAMPERING_SIGNALS`/`_ABSENT_SIGNALS`/`_AMBIGUOUS_SIGNALS` precedence pattern into this domain's vocabulary: CONFIRMED-CLAIMABLE emits, LIVE-AND-OWNED is the normal state of the world (silent, same posture as provenance's "unsigned"), COULDN'T-CHECK is silent (never an INFO-level "unchecked" per-anchor line — that trains users to ignore output, the exact trap `scan_provenance.py`'s own docstring names). One optional scanner-level summary line at the end of `--format text` output ("N anchors probed, M skipped") is allowed for operator visibility but is never a `Finding` and never affects exit code.

**KTD-5 — GitHub API call budget capped at 15-20/scan; `GITHUB_TOKEN` optional-never-required.**
Unauthenticated GitHub API is 60 req/hr/IP. A repo with many GitHub anchors, or repeated scans in a session, exhausts this fast. Rather than requiring an env var (which reintroduces the API-key friction Alex has explicitly banned for Total Recall enrichment and elsewhere), the scanner hard-caps GH calls per scan run and silently NC's the rest (unprobed = unchecked = safe, per KTD-4). If `GITHUB_TOKEN` is present in the environment it is used opportunistically to raise the budget to the authenticated ceiling, but its absence never degrades UX beyond "some anchors go unchecked this run" — no prompt, no warning nag.

**KTD-6 — Extraction rules and static lists are pack-driven; probe/classification logic is code-baked.**
Per `rule_loader.py`'s intended split: pure pattern matching (GitHub URL regex, package-install regex, cloud-suffix list, safe-domain allowlist, GitHub reserved-word list) lives in `data/rulepacks/dead_anchors.json` as `type: "regex"`/`"keyword"` rules with `examples.match`/`examples.no_match` self-tests. The claimability/liveness verdict logic (network probes, HTTPError branching, 3-tier classification) is algorithmic and stays in `scan_dead_anchors.py` with `rule_id=""` on emitted Findings — same convention as `scan_provenance.py`'s one Finding type.

**KTD-7 — Domain eTLD+1 reduction uses a small bundled multi-part-TLD data file, not a full Public Suffix List.**
Zero-non-stdlib-dep constraint rules out a PSL library. A static data file (`data/dead_anchors_multi_tld.txt` or embedded in the rulepack) covering common compound TLDs (`co.uk`, `com.au`, `github.io`, etc.) is vendored and the imprecision is documented in-code and in SKILL.md — some eTLD+1 extractions will be wrong for obscure ccTLDs, which degrades to either an over-broad or under-broad domain check, never a crash.

**KTD-8 — Zero non-stdlib dependencies.**
Everything (regex extraction, `urllib`/`socket` network calls, RDAP JSON parsing) uses stdlib + `forensics_core`/`vuln_feed`/`rule_loader` only, consistent with every other scanner in the tool.

**KTD-9 — RDAP via `rdap.org` bootstrap for domain claimability, not raw WHOIS.**
`https://rdap.org/domain/{domain}` resolves to the correct registry RDAP server and returns JSON over HTTPS — no port-43 socket code, no WHOIS text parsing. A 404 is CC (unregistered/expired), 200 is LO (registered, with a secondary imminent-expiry check against the `events[].expiration` array for a lower-severity flag), anything else is NC. ccTLD coverage gaps are a known limitation (see Decisions Log).

**KTD-10 — Cloud-subdomain fingerprints, GitHub reserved words, cloud-suffix list, and safe-domain allowlist are pack-driven data, not hardcoded Python.**
This lets `refresh_threat_dbs.py`'s existing signed-feed cadence refresh the fingerprint strings when providers redesign their error pages, without a code change — the exact rot risk the spec's open question 3 flags. The pack is read-only at scan time; the scanner never writes `data/rulepacks/dead_anchors.json` itself (only `refresh_threat_dbs.py`'s existing signed overlay pipeline does, per its established cadence — no new cron, no new refresh loop is introduced by this scanner).

**KTD-11 — Per-provider circuit breaker: one strike and the whole host is done for the scan.**
The first 429/403 response from a given host (GitHub is the realistic case, given its 60/hr unauthenticated ceiling) trips a per-scan, per-host breaker; every subsequent anchor that would hit that host is short-circuited straight to NC with zero further calls. This is a stronger, simpler guarantee than the GH numeric call budget alone (KTD-5) — the budget caps volume, the breaker stops entirely on the first sign of throttling, and the two compose (whichever trips first wins). No backoff, no sleep-and-retry: a tripped breaker never un-trips within the same scan.

**KTD-12 — Single-attempt probes, no retries, ever.** A failed probe (of any NC-classified kind) is final for that anchor within that scan. There is no code path anywhere in `dead_anchors_probe.py` that re-issues the same request. This is what makes the loop-safety guarantee structural rather than "we tested it and it seemed fine" — there is simply no retry loop to misbehave.

**KTD-13 — Global network deadline + total probe ceiling, composing with the per-provider GH budget.**
Beyond GitHub's own 15-20 call cap (KTD-5), the whole claimability pass is bounded two ways simultaneously: (a) a total-probe ceiling across ALL anchor types (~50/scan) so a skill with hundreds of npm/PyPI/domain references can't turn into hundreds of sequential HTTP calls, and (b) one shared wall-clock deadline for the entire pass (mirroring `scan_provenance.py`'s `_Deadline`/`TOTAL_BUDGET_SEC` pattern exactly), so a slow or deliberately-hanging host can never stall the scan — once the deadline expires, every remaining anchor is skipped straight to NC. Both caps are enforced BEFORE a request is issued (an anchor over budget never even calls `_https_fetch`), not after a slow response comes back.

**KTD-14 — Atomic, lock-free 24h result cache; no self-trigger.**
Anchor verdicts are cached for 24h using the identical write-to-temp-in-the-same-dir + `os.replace()` + `0o600` pattern `vuln_feed._atomic_write` already implements — reused directly, not reimplemented. No file locks (no `flock`, no lockfile) are used anywhere: two concurrent scans of the same repo (a manual full scan racing the `auto_scan.py` PostToolUse hook) can each read a possibly-stale-but-never-torn cache and each may write their own atomic replace; the last writer wins and no reader ever observes partial JSON, because `os.replace()` is a single atomic syscall on POSIX. A missing, truncated, or malformed cache entry degrades to a cache-miss (re-probe subject to the usual budget/deadline/breaker, or NC if those are exhausted) — never a crash, per the same tolerant-read discipline `vuln_feed._load_cache` already uses. Separately: this scanner performs read-only GET/DNS/RDAP calls exclusively — it never installs, clones, or mutates git state, so it structurally cannot trip `auto_scan.py`'s PostToolUse hook (which keys on install/clone commands). Scanner → hook → scanner is not just avoided, it is impossible given the hook's trigger surface.

## Concurrency & Loop-Safety Contract

This is a first-class acceptance gate (spec §10), not an implementation footnote — the torture-room phase (U5) attacks it directly, and the six scenarios below are non-negotiable Verification Contract items.

| Property | Guarantee | Where it's enforced |
|---|---|---|
| **No retries** | Single attempt per anchor; a failed probe is final for that scan | KTD-12; no retry loop exists in `dead_anchors_probe.py` |
| **Per-provider circuit breaker** | First 429/403 from a host trips a per-scan breaker; every later anchor to that host → instant NC, zero further calls | KTD-11 |
| **No self-trigger** | Read-only GET/DNS/RDAP only; never installs/clones/mutates git → cannot trip `auto_scan.py`'s PostToolUse hook | KTD-14 |
| **Bounded iteration** | Anchor set is finite, extracted once, deduped before any probe fires; no recursion over network responses | U1 (dedup at extraction) + KTD-13 (probe ceiling) |
| **Atomic cache, no locks** | `vuln_feed._atomic_write`'s temp+`os.replace()`+`0o600` pattern, reused not reimplemented; zero `flock`/lockfile → zero deadlock surface | KTD-14 |
| **Tolerant reads** | Missing/partial/malformed cache entry → cache-miss or NC, never a crash | KTD-14 |
| **No shared mutable state across scanners** | GH budget counter, circuit-breaker state, and deadline are all local to one `scan_repo()` invocation; the only cross-invocation artifact is the atomic on-disk cache | U2/U3 |
| **Feed pack is read-only at scan time** | `data/rulepacks/dead_anchors.json` is refreshed only by the existing signed `refresh_threat_dbs.py` pipeline; the scanner never writes it; no new cron/loop | KTD-10 |
| **Dedup before probing** | Unique `(anchor_type, target)` set computed in U1; N references to the same anchor cost exactly 1 probe | U1 |
| **Hard caps** | GitHub ≤ ~15-20 calls/scan (KTD-5), total probe ceiling ≤ ~50/scan across all types (KTD-13); overflow → silent NC | KTD-5, KTD-13 |
| **Global network deadline** | One wall-clock budget for the entire claimability pass; expiry stops further probes, remaining anchors → NC, scan completes promptly | KTD-13 |
| **24h result cache** | Re-scanning the same repo within 24h reuses cached per-anchor verdicts; no re-probe within the TTL | KTD-14 |
| **Parallel-friendly** | Runs as one more `throttled_run` job in `run_forensics.sh`, alongside the other 25 scanners; does not serialize the pipeline | U4 |
| **`--offline` = instant + silent** | Zero network attempted, every anchor → NC immediately, zero findings, sub-second | U2/U3 (`offline` param short-circuits before any socket call) |

**Distinction from Phase-2 verdict-decay (important, do not conflate):** the 24h result cache above is a pure latency/rate-limit optimization — it caches "what did we last observe for this exact anchor" the same way `vuln_feed`'s existing freshness caches do, and a cache-miss just re-probes normally. DA-07/DA-P2-5 (deferred to Phase 2) is a different problem: proactively detecting that a PREVIOUSLY-live anchor has since gone claimable with zero local file change, which requires comparing verdicts ACROSS scans over time (a decay-detection ledger), not just avoiding redundant probes WITHIN a short TTL. Building the 24h cache now does not build DA-07's state architecture; they are related but distinct, and conflating them would either under-scope this plan's caching need or over-scope it into Phase 2's territory.

## Implementation Units

### U1. Anchor extraction module + rulepack

**Goal:** Given a repo path, extract every candidate anchor (GitHub owner/repo, prose package-install target, bare domain, cloud subdomain) with zero network calls, applying the safe-domain allowlist and GitHub-reserved-word exclusions so noise is filtered before any probe is even considered.

**Requirements:** DA-01, DA-02, DA-03, DA-04, DA-05 (extraction half only — no probing here), DA-09 (cloud-suffix membership is computed here, consumed in U3).

**Dependencies:** None (first unit).

**Files:**
- `scripts/dead_anchors_extract.py` (new) — extraction functions, pure stdlib, imports `rule_loader`.
- `data/rulepacks/dead_anchors.json` (new) — extraction regexes/keyword lists per KTD-6.
- `data/dead_anchors_multi_tld.txt` (new) — bundled compound-TLD list per KTD-7 (or embed as a rulepack keyword-type rule if that fits the schema more cleanly than a bespoke file format; decide at implementation time based on which the `rule_loader` self-test harness covers more naturally).
- `tests/test_dead_anchors_extract.py` (new).

**Approach:**
1. Build `data/rulepacks/dead_anchors.json` mirroring `skill_threats.json`'s schema exactly: `schema_version: "1.0"`, `pack: "dead_anchors"`, `pack_version: 1`, one rule per extraction pattern from spec §3 (`DA-GH-001` GitHub URL, `DA-GH-002` `github:` shorthand, `DA-PK-001` package-install prose, `DA-DM-001` bare domain, `DA-CL-001` cloud-subdomain suffix match), plus keyword-type rules for the GitHub reserved-word exclusion list and the safe-domain allowlist (spec §3 tables, verbatim).
2. `dead_anchors_extract.py` loads the pack via `rule_loader.load_pack("dead_anchors")`, exposes `extract_anchors(file_paths) -> list[Anchor]` where `Anchor` is a small dataclass/namedtuple: `(type, raw_value, owner=None, repo=None, ecosystem=None, file=None, line=None)`.
3. Read anchors from `_shared_patterns.SEED_FILES` (`SKILL.md`, `AGENTS.md`, `CLAUDE.md`, etc.) plus `.mcp.json`/`mcp.json` if present, matching `scan_agent_skills.py`'s file-discovery convention.
4. Apply the safe-domain allowlist and GitHub reserved-word list as extraction-time filters (never probed at all), and de-duplicate anchors (same owner/repo/package/domain referenced twice in one skill = one probe).
5. For package-install extraction: strip version specifiers/flags per spec §3's regex, infer ecosystem from the verb (`pip*`→PyPI, `npm`/`yarn`/`pnpm`→npm; `gem`/`cargo`/`bundle`/`go get` extracted but NOT probed in P0 — tag them `ecosystem=None` so U2 skips them cleanly).
6. For domain extraction: reduce to eTLD+1 using the bundled multi-part-TLD list; skip if the reduced domain is in the safe allowlist.

**Patterns to follow:** `rule_loader.load_pack()` / `CompiledPack.all_rules` iteration (see `_shared_patterns.py`'s `_values_for()` helper for the pack-with-fallback pattern — though this module has no legacy hardcoded fallback to preserve, so it can load directly and treat a missing/invalid pack as "extraction pack unavailable, scanner has nothing to probe this run" rather than crashing). Rule IDs `DA-GH-001`, `DA-GH-002`, `DA-PK-001`, `DA-DM-001`, `DA-CL-001` per spec §6.

**Test scenarios:**
- `github.com/torvalds/linux` in SKILL.md → one GitHub anchor `(torvalds, linux)`.
- `github:hexiaochun/seedance2-api` → same anchor shape via shorthand pattern.
- `github.com/about` → NO anchor (reserved word `about` excluded).
- `npx skills hexiaochun/seedance2-api` → package-install extraction does NOT double-fire as a GitHub anchor (this string is the shorthand-pattern's own worked example from spec §6, not a `pip/npm install` verb match).
- `pip install requests==2.31.0` → PyPI anchor `requests`, version specifier stripped.
- `npm install --save lodash@^4.17.0` → npm anchor `lodash`, flag and specifier stripped.
- `see our github page for details` → NO anchor (no owner/repo captured, per spec §6 self-test example).
- `https://github.com/x/y` and a second, identical reference elsewhere in the same file → exactly ONE anchor after de-dup.
- `https://vercel.app` bare (no subdomain) → excluded structurally (suffix match requires a subdomain segment).
- `myapp.vercel.app` → cloud anchor, suffix `vercel.app`, flagged `is_free_tier=True` for DA-09.
- `https://docs.python.org/3/library/os.html` → NO anchor (safe-domain allowlist).
- `example.co.uk` → eTLD+1 reduces to `example.co.uk` (compound TLD), not `co.uk`.
- Rulepack self-test: every rule's `examples.match`/`examples.no_match` passes under `rule_loader.self_test_pack()`.

**Verification:** `pytest tests/test_dead_anchors_extract.py -v` green; `python3 scripts/rule_loader.py dead_anchors` reports 0 failed self-tests.

---

### U2. Network claimability layer

**Goal:** For each extracted anchor, produce a CC/LO/NC verdict via hardened, budget-capped network probes, with zero possibility of a hard crash or hang regardless of what the network returns.

**Requirements:** DA-01, DA-02, DA-03, DA-04, DA-05 (the probe half), the GH call-budget decision from KTD-5, DA-10's data collection (the raw GitHub user response is captured here for U3 to interpret).

**Dependencies:** U1 (consumes `Anchor` objects; can be developed against a hand-built anchor list in its own tests without waiting on U1's extraction regex correctness).

**Files:**
- `scripts/dead_anchors_probe.py` (new) — `probe_github_user`, `probe_github_repo`, `probe_npm`, `probe_pypi`, `probe_domain_rdap`, `probe_cloud_subdomain`, each returning a small result object `(verdict, raw_response_or_None)`; plus the shared `_ProbeBudget`/`_Deadline`/`_CircuitBreaker` state objects and the atomic result-cache read/write helpers.
- `tests/test_dead_anchors_probe.py` (new).

**Approach:**
1. One shared fetch wrapper `_probe_https(url, max_bytes) -> (verdict, parsed_json_or_None)` that calls `vuln_feed._https_fetch` and implements the HTTPError-first branch from KTD-3: `except urllib.error.HTTPError as e:` checked BEFORE `except urllib.error.URLError`. `e.code == 404` → `("CC", None)`; `e.code in (403, 429)` or `500 <= e.code < 600` → `("NC", None)`; any other code → `("NC", None)`. Then `except (urllib.error.URLError, OSError, TimeoutError):` → `("NC", None)`. On success, `("LO", parsed_json)`. This is a SINGLE attempt (KTD-12) — no loop, no `for attempt in range(...)`, nothing that could retry.
2. **Circuit breaker (KTD-11):** a small per-scan `_CircuitBreaker` object keyed by host (`api.github.com`, `registry.npmjs.org`, `pypi.org`, `rdap.org`, or the specific cloud subdomain's registrable suffix) tracks "tripped" booleans. Immediately after `_probe_https` classifies a response as NC via a 429 or 403 status specifically (not a generic timeout/5xx — those don't imply throttling), the breaker trips for that host. Every subsequent probe function checks `breaker.is_tripped(host)` BEFORE calling `_probe_https` and returns `("NC", None)` instantly if tripped, without issuing a request. A tripped breaker never resets within the scan (no timer, no retry-after honoring — simplicity over cleverness, since honoring `Retry-After` would reintroduce a wait/backoff shape the loop-safety contract explicitly forbids).
3. **Budget + total probe ceiling + global deadline (KTD-5, KTD-13):** `probe_github_user`/`probe_github_repo` consume one unit of a shared `_ProbeBudget` GH-specific counter (~15-20/scan); ALL probe functions additionally consume one unit of a shared TOTAL ceiling (~50/scan) regardless of type. A single `_Deadline` object (same shape as `scan_provenance.py`'s `_Deadline`/`TOTAL_BUDGET_SEC`: `remaining()`/`expired()`, constructed once per `scan_repo()` call) is threaded through every probe call; each probe function checks `deadline.expired()` FIRST, before the GH/total budget check, before the circuit breaker check, before issuing any request — cheapest checks first, network last. Any of the three exhausted → instant `("NC", None)`, zero request issued. The per-request `NETWORK_TIMEOUT_SEC` from `vuln_feed` bounds any individual call that IS issued, so the deadline is a backstop, not the only timeout.
4. **24h atomic result cache (KTD-14):** before issuing any probe, check a cache keyed on `(anchor_type, normalized_target)` at `~/.cache/repo-forensics/dead-anchors/{sha256-of-key}.json` (or a single consolidated cache file, decide at implementation time based on which reads more naturally through `vuln_feed._load_cache`'s existing helper — reuse that function directly rather than writing a second cache-age-check implementation). A cache hit within 24h returns the cached verdict without any network call, budget consumption, or deadline check (a cache hit costs nothing). A cache miss, or a cache read that raises `OSError`/`json.JSONDecodeError`/schema-mismatch, falls through to a normal probe (tolerant read — never a crash). Writes use `vuln_feed._atomic_write` (temp file in the same directory + `os.replace()` + `0o600`) exactly as-is, imported and called directly — not reimplemented. No file lock of any kind.
5. `probe_github_user(owner, ctx)`: GET `https://api.github.com/users/{owner}`, `ctx` bundling the budget/breaker/deadline/cache objects. On `LO`, the raw JSON (`created_at`, `public_repos`, `bio`) is returned for DA-10.
6. `probe_github_repo(owner, repo, ctx)`: only called by U3 if the owner probe returned `LO` (spec §4 — repo-gone-under-live-user is a weaker, conditional signal). Same shape.
7. `probe_npm(name, ctx)` / `probe_pypi(name, ctx)`: GET `registry.npmjs.org/{name}` / `pypi.org/pypi/{name}/json`. No GH-specific budget, but still subject to the total ceiling, deadline, and cache.
8. `probe_domain_rdap(domain, ctx)`: GET `https://rdap.org/domain/{domain}`. On `LO`, additionally inspect the `events` array for a past-dated `expiration` and surface it as a secondary flag (imminent-expiry, lower severity) rather than a distinct verdict tier.
9. `probe_cloud_subdomain(subdomain, suffix, ctx)`: first `socket.gethostbyname(subdomain)` wrapped in `try/except socket.gaierror: return ("CC", None)` (NXDOMAIN = confirmed claimable) `except OSError: return ("NC", None)`; on successful resolution, GET `https://{subdomain}` and match the response body against the pack-driven provider-fingerprint list (HIGH-confidence fingerprints only fire `CC`; MEDIUM-confidence/no-match → `LO` per spec §4's explicit "do not guess" instruction for Netlify/Render/Surge).
10. All probe functions accept an `offline: bool` param; when `True`, return `("NC", None)` immediately before any budget/breaker/deadline/cache check even runs — `--offline` must be the cheapest, fastest path in the whole module (sub-second, per spec §10's "lightweight/seamless" requirement), not just "skip the socket call after doing everything else."
11. Dedup happens once, upstream, in U1 — U2's functions are never called twice for the same `(anchor_type, target)` within one scan; this unit does not re-implement dedup, it relies on receiving an already-unique anchor list.

**Patterns to follow:** `vuln_feed._https_fetch(url, max_bytes)` for every HTTPS call (no direct `urlopen`). `vuln_feed._atomic_write` / `vuln_feed._load_cache` reused directly for the 24h result cache (do not reimplement atomic-write-with-temp-and-replace a second time in this module). `scan_provenance.py`'s `_Deadline`/`TOTAL_BUDGET_SEC` pattern for both the wall-clock deadline and, in spirit, the numeric budget counters (a small class with `remaining()`/`expired()`).

**Test scenarios (all network monkeypatched via `scanner.urllib.request.urlopen` / `scanner.socket.gethostbyname`, per `tests/test_scan_provenance.py:26-45` convention):**
- Canned 404 on GH user → `("CC", None)`.
- Canned 404 on npm → `("CC", None)`; canned 404 on PyPI → `("CC", None)`.
- Canned 404 on RDAP domain → `("CC", None)`.
- `socket.gaierror` on cloud subdomain DNS → `("CC", None)`.
- 200 body containing "DEPLOYMENT_NOT_FOUND" for a `vercel.app` subdomain (DNS resolves but app deleted) → `("CC", None)` via fingerprint match.
- 200 body containing "project not found" for `pages.dev` → `("CC", None)` (Cloudflare Pages, MEDIUM-confidence fingerprint, still fires per spec table).
- 200 body of generic unrelated content on `netlify.app` → `("LO", ...)` (generic 404 copy explicitly NOT trusted as a fingerprint per spec §4).
- Canned 200 (registered/found) on every endpoint type → `("LO", parsed)`, never a Finding downstream.
- Canned 403 → `("NC", None)`; canned 429 → `("NC", None)`; canned 500 → `("NC", None)`; `socket.timeout`/`TimeoutError` → `("NC", None)`. Assert NO exception propagates in any of these cases (never-hard-fail).
- GH budget exhausted (counter at 0) → `probe_github_user` returns `("NC", None)` WITHOUT calling `urlopen` at all (assert the monkeypatched `urlopen` was not invoked).
- `offline=True` → every probe returns `("NC", None)` with zero network attempts, for all 6 functions.
- RDAP 200 with a past `expiration` event → verdict `LO` but the imminent-expiry secondary flag is set.
- **Circuit breaker trips on first 429**: monkeypatch GH user probe #1 to raise `HTTPError(429)`; assert probe #2 for a DIFFERENT owner on the same host (`api.github.com`) returns `("NC", None)` WITHOUT any call to the monkeypatched `urlopen` (breaker short-circuits before the request). Assert a probe to a DIFFERENT host (e.g. `registry.npmjs.org`) in the same scan is NOT affected by the GitHub breaker (per-host, not global).
- **No retry, ever**: monkeypatch `urlopen` with a call-count assertion; feed it a 429 once; confirm the SAME anchor is never probed a second time within the scan (single attempt, KTD-12) — the breaker prevents OTHER anchors from probing that host, but this test specifically confirms the ORIGINAL anchor itself isn't retried.
- **Total probe ceiling**: construct 60 unique anchors across mixed types (not all GitHub, to isolate the total-ceiling behavior from the GH-specific budget); assert no more than ~50 probes are actually attempted (assert via call-count on the monkeypatched network functions) and the remainder resolve to `("NC", None)`.
- **Global deadline**: monkeypatch every probe's underlying call to sleep past a artificially-shortened test deadline (monkeypatch the deadline constant/budget like `scan_provenance.py`'s tests monkeypatch `TOTAL_BUDGET_SEC`); assert the scan returns promptly (bounded wall-clock in the test, not an actual multi-second sleep) with all not-yet-attempted anchors as `("NC", None)`, and zero exceptions.
- **24h cache hit avoids network entirely**: pre-populate the cache file with a valid, fresh (< 24h) verdict for a given anchor; call the probe; assert `urlopen`/`gethostbyname` was NEVER invoked and the cached verdict is returned as-is.
- **24h cache miss (expired) re-probes normally**: pre-populate the cache with a verdict timestamped > 24h old; assert the probe DOES call the network and the cache is refreshed via `vuln_feed._atomic_write` afterward.
- **Malformed/partial cache tolerated**: pre-populate the cache file with truncated JSON / wrong schema / a directory instead of a file at that path; assert the probe falls through to a normal network probe with NO exception raised (tolerant read, KTD-14).
- **Concurrent-write safety (simulated)**: two sequential calls to the cache-write helper for the SAME anchor key (simulating two racing scans) both complete without raising, and the final on-disk file is valid, complete JSON (never a torn/partial write) — verified by asserting `os.replace` (not a raw `open().write()`) is the mechanism used, per `vuln_feed._atomic_write`'s existing implementation.

**Verification:** `pytest tests/test_dead_anchors_probe.py -v` green, including an explicit assertion (via a monkeypatched `urlopen` call-counter) that no test ever performs a real network call.

---

### U3. Scanner orchestration (`scan_dead_anchors.py`)

**Goal:** Wire extraction (U1) and probing (U2) into the actual `scripts/scan_dead_anchors.py` entry point: 3-tier classification, `Finding` emission per spec §2's severity/confidence table, DA-09/DA-10 bundled in, argparse shape, and the optional end-of-scan summary line.

**Requirements:** DA-01 through DA-05 (end-to-end), DA-09, DA-10.

**Dependencies:** U1, U2.

**Files:**
- `scripts/scan_dead_anchors.py` (new).
- `tests/test_scan_dead_anchors.py` (new).

**Approach:**
1. `SCANNER_NAME = "dead_anchors"`.
2. `scan_repo(repo_path, ignore_patterns=None, offline=False) -> list[Finding]`: constructs ONE shared probe context per call (`_Deadline` for the global wall-clock budget, `_ProbeBudget` for the GH cap + total ceiling, `_CircuitBreaker` for per-host trip state, and the cache-dir path for the 24h result cache — all local to this invocation, never module-level mutable globals, per the Concurrency & Loop-Safety Contract's "no shared mutable state across scanners" line), calls `dead_anchors_extract.extract_anchors(...)` to get the deduped anchor list, then for each anchor dispatches to the matching U2 probe (GH owner → conditional GH repo per spec §4's "only if owner LO" gate; npm/PyPI; RDAP domain; cloud subdomain) passing the shared context, classifies CC/LO/NC, and emits a `Finding` ONLY on CC.
3. Per-anchor-type severity/confidence from spec §2's P0 table: DA-01 critical/0.90, DA-02 medium/0.55, DA-03 critical/0.90, DA-04 high/0.85 (critical if the domain is itself an install/fetch target rather than a passing mention — a secondary structural check on surrounding prose verb, best-effort), DA-05 critical/0.80 (fingerprint) or 0.90 (NXDOMAIN).
4. DA-09: for every cloud-subdomain anchor (regardless of CC/LO/NC verdict on liveness), if its suffix is in the free-tier list, this is an independent structural signal — decide at implementation time whether it fires as its own low-severity Finding on EVERY free-tier reference (matching spec's "regardless of current liveness" framing) or is folded into the DA-05 Finding's description as an aggravating factor when DA-05 already fired. Given the never-train-users-to-ignore-alarms principle (KTD-4), default to the latter (fold into DA-05, do not double-count) unless spec review during implementation decides the standalone low-severity signal has independent value; document the choice in `decisions.md`.
5. DA-10: when a GH owner probe returns `LO`, inspect the captured `created_at`/`public_repos`/`bio` fields; if account age < 1 year AND `public_repos` is very low AND `bio` is empty, attach this as supplementary context on the eventual DA-02 Finding for that owner's repo (if one fires) rather than emitting its own standalone Finding — DA-10 has no CC/LO/NC verdict of its own, it's an enrichment of DA-01/DA-02's verdict. (Resolves spec open question 7: bundled here for zero marginal cost, not split into its own scanner, because it produces no independent finding — only enriches an existing one.)
6. Build `argparse.ArgumentParser` locally in `main()` (repo_path, `--format`, `--offline`) exactly mirroring `scan_dependencies.py`'s pattern — do NOT invent `--no-network`, do NOT rely on `core.parse_common_args` (which has no offline flag).
7. Emit the optional end-of-scan summary line ("N anchors probed, M skipped: rate-limited/offline") to stderr/status output only in `--format text`, never as a `Finding`, never counted toward `output_findings`' severity tally.
8. `main()` follows `scan_provenance.py`'s shape: `core.emit_status(...)`, `core.load_ignore_patterns(repo_path)` (accepted, unused), `scan_repo(...)`, `core.output_findings(all_findings, args.format, SCANNER_NAME)`.

**Patterns to follow:** `scan_provenance.py`'s `scan_repo()`/`main()` structure end-to-end (this is the closest existing analog: standalone, algorithmic, silent-by-default). `Finding(scanner=SCANNER_NAME, severity=..., title=..., description=..., file=<seed file path where the anchor was found>, line=<line if extractable, else 0>, snippet=<the raw anchor reference, truncated>, category="dead-anchor", rule_id="")`.

**Test scenarios:**
- Full pipeline, GH user 404 (monkeypatched) → exactly one CRITICAL Finding, `category="dead-anchor"`, title mentions the owner name.
- Full pipeline, GH owner LO + GH repo 404 → exactly one MEDIUM Finding (DA-02), confidence 0.55.
- Full pipeline, GH owner LO + GH repo LO (both live) → zero Findings.
- Full pipeline, npm package 404 → one CRITICAL Finding; PyPI 404 → one CRITICAL Finding.
- Full pipeline, RDAP domain 404 → one HIGH Finding; RDAP 200 with imminent expiration → zero Findings today (LO stays silent; expiry-aware severity is documented as a future refinement, not built as a distinct verdict in P0 — confirm this against spec §4's wording during implementation and adjust if spec intends an actual lower-severity Finding for imminent expiry, in which case implement it as HIGH-but-lower-confidence, not a new verdict tier).
- Full pipeline, cloud subdomain NXDOMAIN → one CRITICAL Finding (confidence 0.90); fingerprint-match 200 → one CRITICAL Finding (confidence 0.80).
- Full pipeline, every probe returns NC (simulated 403 across the board) → zero Findings, zero exceptions, process exits cleanly.
- `--offline` flag → zero network calls attempted (assert via monkeypatched `urlopen` call count == 0), zero Findings, clean exit.
- GH budget cap: a repo with 25 distinct GitHub-owner anchors → at most ~15-20 probed (assert via call counter), the rest silently skipped, zero crash.
- `--format json` output round-trips through `Finding.to_dict()` with all expected keys present.
- `--format summary` produces the `"dead_anchors: N findings (...)"` line.

**Verification:** `pytest tests/test_scan_dead_anchors.py -v` green. Manual smoke: `python3 scripts/scan_dead_anchors.py <fixture-repo> --format text` and `--offline` both exit 0/1/2 appropriately with no traceback.

---

### U4. Registration (wire into the aggregation pipeline)

**Goal:** Make `dead_anchors` a first-class scanner in every place repo-forensics enumerates scanners, so it runs in both skill-scan and full-scan modes, participates in the PostToolUse auto-scan hook, and doesn't silently fall out of the non-breaking-contract test.

**Requirements:** Registration mechanics per spec §1 (4 points) and §6 (rule-id abbreviation).

**Dependencies:** U3 (the script must exist and run before wiring it into orchestration).

**Files:**
- `SKILL.md` — new row in the Scanners table, mode `skill + full`.
- `scripts/run_forensics.sh` — add `throttled_run run_scanner "dead_anchors" "scan_dead_anchors.py" &` to BOTH the `--skill-scan` block and the full-scan block (confirmed both blocks already list `provenance` last; add `dead_anchors` alongside it in each).
- `scripts/auto_scan.py` — add `'scan_dead_anchors.py'` to the `targeted_scanners` list in `run_targeted_scan` (confirmed list currently has 16 entries ending in `scan_bytecode.py`).
- `scripts/gen_rule_ids.py` — add `"scan_dead_anchors.py": "DA"` to `_SCANNER_ABBREV`.
- `tests/test_non_breaking_contract.py` — add `"dead_anchors"` to `EXPECTED_BASE_SCANNER_NAMES`.

**Approach:**
1. SKILL.md row, matching the existing table's column format: `| **dead_anchors** | GitHub/npm/PyPI/domain/cloud-subdomain claimability (repojacking, phantom packages, expired domains, dangling cloud slugs) | skill + full |`.
2. `run_forensics.sh`: two one-line additions, verified against the actual current line numbers at implementation time (spec's cited ~354-368/~377-405 are approximate; grep for the existing `"provenance"` line in each block and insert `dead_anchors` immediately after it, consistent with how `provenance` itself was appended last in both blocks).
3. `auto_scan.py`: one-line addition to the `targeted_scanners` list.
4. `gen_rule_ids.py`: add the abbreviation entry. **Important caveat to verify during implementation:** `gen_rule_ids.py` mints ids by AST-parsing each scanner's module-level `*_PATTERNS`/`*_KEYWORDS` table literals (see `collect_tables()`/`_is_pattern_table()`) — it does NOT read JSON rulepacks. Since `dead_anchors`'s extraction rules live entirely in `data/rulepacks/dead_anchors.json` (KTD-6) with ids already assigned directly in that JSON (matching `skill_threats.json`'s convention, where rule ids are authored in the JSON, not generated by this tool), adding `"scan_dead_anchors.py": "DA"` to `_SCANNER_ABBREV` is registration-for-completeness and will emit ZERO rows for `dead_anchors` in `data/rule_ids.csv` (no hardcoded pattern tables exist in `scan_dead_anchors.py` to scrape) — this is expected, not a bug. Document this in the rulepack's own header comment so a future maintainer doesn't go looking for missing CSV rows.
5. `test_non_breaking_contract.py`: add to the set (not a numbered list — verify against current line, spec's "~77" is approximate).

**Patterns to follow:** Exact existing surrounding syntax in each file (bash `&` job pattern, Python list literal, set literal, markdown table row).

**Test scenarios:**
- `pytest tests/test_non_breaking_contract.py -v` — `EXPECTED_BASE_SCANNER_COUNT` increments by 1 and all existing assertions still pass against a live `run_forensics.sh --format json` run.
- `run_forensics.sh <fixture> --skill-scan --format json` — `scanners` array includes a `dead_anchors` entry.
- `run_forensics.sh <fixture> --format json` (full mode) — same.
- `auto_scan.run_targeted_scan(<fixture>)` — includes `dead_anchors` findings (or empty list) without raising.
- `python3 scripts/gen_rule_ids.py --print` — runs without error; confirm zero `DA` rows are expected and documented (not silently wrong).

**Verification:** Full `pytest` run green (existing + new tests). `run_forensics.sh` manual run against a clean fixture repo shows `dead_anchors` in scanner output with `finding_count: 0`.

---

### U5. Tests + benign corpus additions

**Goal:** Complete the test matrix from spec §7 — positive (teeth) tests, negative tests, never-hard-fail tests, and new benign-corpus entries — so the scanner is provably both loud on real dead anchors and silent on clean ones.

**Requirements:** Spec §7 items 1-6 (test corpus plan), the SkillSieve security-gate step (manual pre-step, not a code unit), the ToxicSkills negative-control cross-check.

**Dependencies:** U1, U2, U3 (needs the full pipeline to exist).

**Files:**
- `tests/corpus/benign/dead_anchors_live_repo.md` or an addition to an existing benign SKILL.md fixture (new) — references repo-forensics' own stable GitHub org/repo (owner-controlled lifecycle, avoids third-party CI flakiness per spec §7 item 3a).
- `tests/corpus/benign/*` additions for a live npm package (`lodash`), live PyPI package (`requests`), `github:` shorthand to the same stable repo, and either a live cloud-subdomain reference or a mocked LO-branch fixture (spec §7 item 3d — mock if no stable public one is safe to depend on in CI).
- `tests/corpus/budgets.json` — updated with the `dead_anchors` scanner's expected zero-finding budget on the benign corpus.
- `tests/test_dead_anchors_extract.py`, `tests/test_dead_anchors_probe.py`, `tests/test_scan_dead_anchors.py` (already created in U1-U3; this unit is the pass where the FULL spec §7 matrix is confirmed present across them, plus the benign-corpus regression gate).

**Approach:**
1. **Manual pre-step (not code, do NOT skip, do NOT automate away):** before extracting any SkillSieve labeled-skill fixtures into `tests/corpus/`, clone `github.com/xiaohou521/skillsieve` into an isolated temp dir and run a full repo-forensics scan on the clone. Review findings. Only after that review is clean (or reviewed-and-accepted) do specific labeled skill folders get copied into `tests/corpus/`. This is Alex's non-negotiable repo-forensics-first rule applied to the test fixture itself, and it gates U5, not something U5's code does for you.
2. Add the ToxicSkills 8 live-malicious IOC URLs (e.g. `clawhub.ai/zaycv/clawhud`) as domain/URL entries submitted to the `ioc_manager.py` signed feed process (this is a feed-content change, not a `scripts/` code change — see Test Corpus & Security Gate section below for the exact mechanics) and additionally use them as negative-control fixtures: a test that confirms `scan_dead_anchors.py` does not double-fire or conflict with `ioc_manager`'s existing IOC flag on the same anchor.
3. New benign-corpus entries per spec §7 item 3: (a) repo-forensics' own live GitHub org/repo reference, (b) `lodash`/`requests` live-package references, (c) `github:` shorthand to the same stable repo, (d) one live cloud-subdomain reference OR a mocked-LO fixture.
4. Positive (teeth) tests, mirroring the existing `test_teeth_planted_*` naming pattern used elsewhere in the suite: for each of the 4 P0 anchor types, monkeypatch to return a canned 404/NXDOMAIN/fingerprint body, assert the correct severity+category fires.
5. Negative tests: canned 200/registered responses for all 4 types → zero findings. Canned 403/429/5xx/timeout for all 4 types → zero findings AND no crash (same shape as `tests/test_run_scanner_fail_loud.py`, though that file tests `auto_scan.run_scanner`'s subprocess-failure wrapper, not this scanner's internal try/except — both layers get exercised: this scanner must never raise internally, AND if it somehow did, `run_scanner`'s existing fail-loud wrapper is the backstop, not a reason to skip internal hardening).
6. All network calls in the test suite monkeypatched (`scanner.urllib.request.urlopen`, `scanner.socket.gethostbyname`) — confirmed zero real HTTP/DNS calls via an assertion helper, per `tests/test_scan_provenance.py:26-45`'s convention.

**Patterns to follow:** `tests/test_benign_corpus.py`'s budget-file convention (`tests/corpus/budgets.json`) for the zero-finding regression gate; `tests/corpus/benign/` directory's existing flat-file structure (SKILL.md, package.json, etc. sit directly in that directory today — follow the same layout, don't invent subdirectories unless the existing convention already has one for scanner-specific fixtures).

**Test scenarios:** (superset of U1-U3's per-unit scenarios, consolidated here for the corpus-level check)
- Running the FULL benign corpus (including the new dead-anchor-relevant fixtures) through `scan_dead_anchors.py` in offline mode → zero findings, budget respected.
- Running the full benign corpus WITH live network mocked to "everything resolves/200s" → zero findings.
- ToxicSkills IOC URL present in a test fixture → `ioc_manager` fires its existing IOC-match finding; `dead_anchors` either stays silent (if the IOC domain still resolves, since IOC-badness ≠ claimability) or fires independently (if the IOC domain happens to ALSO be unregistered) — assert no crash, no duplicate-finding conflict, and that the two scanners' findings are clearly distinguishable by `scanner` field and `category`.

**Verification:** `pytest tests/ -v` full suite green, including `tests/test_benign_corpus.py`'s budget gate with `dead_anchors` now in scope. `python3 -m pytest tests/test_dead_anchors_extract.py tests/test_dead_anchors_probe.py tests/test_scan_dead_anchors.py -v` all pass in isolation.

---

### U6. SKILL.md docs + threat-source logging

**Goal:** Document the new scanner's coverage and known limitations in SKILL.md, and log AIR/Skilljacking as a research source per repo-forensics' existing convention of citing the security research that motivated each scanner.

**Requirements:** Documentation completeness; no detection-logic requirement.

**Dependencies:** U1-U5 (docs describe the shipped behavior, written last).

**Files:**
- `SKILL.md` — scanners table row (already added in U4) plus, if SKILL.md has a "bypass coverage and known scope" or equivalent prose section (it does, for archive/oversize/bytecode per the file's existing structure), a short paragraph on dead-anchor coverage limits: RDAP ccTLD gaps, fingerprint-string rot risk, multi-part-TLD imprecision, the GH call-budget cap.
- `SYSTEM/references/research_sources.md`-equivalent within repo-forensics (check whether such a file exists; if repo-forensics has no dedicated research-sources log, add a brief "Research sources" note near the scanner's SKILL.md row instead, or check for a `CHANGELOG.md`/`docs/` convention already in use for this purpose and follow it — do not invent a new file/location without checking existing convention first).

**Approach:**
1. Add the known-scope paragraph to SKILL.md immediately following the scanners table, in the same voice as the existing archive/oversize/bytecode "Bypass coverage and known scope" section.
2. Cite AIR's Skilljacking research post and the Circus of Skills / ToxicSkills / SkillSieve sources from `findings/A_air_primary.md` and `findings/B_secondary_vectors.md` as the motivating research, matching however repo-forensics currently attributes its other CSA/Trail-of-Bits-motivated scanners in SKILL.md prose (grep existing scanner sections for "per X's audit" / "(CSA / Trail of Bits, ...)" style citations and mirror that exact convention rather than inventing new phrasing).

**Patterns to follow:** Existing SKILL.md prose style for citing external security research (the archive/oversize/bytecode section explicitly names "CSA / Trail of Bits, June 2026" as the motivating audit).

**Test scenarios:** N/A (documentation unit; verification is a read-through, not a test).

**Verification:** SKILL.md renders correctly (no broken markdown table), scanners table row count matches `EXPECTED_BASE_SCANNER_COUNT` from U4's test.

## Test Corpus & Security Gate

- **SkillSieve fixture safety gate (mandatory, blocking, manual):** before any labeled skill folder from `github.com/xiaohou521/skillsieve` is copied into `tests/corpus/`, clone it into an isolated temp directory and run a full `repo-forensics` scan against the clone. Review the findings. This is Alex's standing repo-forensics-first rule for any external code being evaluated for use, applied here to the test fixture data itself — do not skip this step because "it's just test data."
- **ToxicSkills 8 live-malicious IOC URLs** (Snyk-sourced, e.g. `clawhub.ai/zaycv/clawhud`, `clawhub.ai/Aslaep123/polymarket-traiding-bot`): add to the `ioc_manager.py` signed-feed content (this is a feed-authoring change through whatever process Alex uses to publish `iocs/latest.json` to the `repo-forensics` GitHub repo `ioc_manager.py` pulls from — NOT a direct edit to a file inside `scripts/` or `data/` in this repo, since the IOC feed is remote and signature-verified). Additionally use these 8 URLs as negative-control test fixtures per U5.
- **All test-suite network calls are monkeypatched.** No test in `tests/test_dead_anchors_*.py` ever performs a real HTTP request or DNS lookup — every scenario replaces `urllib.request.urlopen` and `socket.gethostbyname` at the module level the scanner imports them under, per the existing `tests/test_scan_provenance.py` convention.

## Verification Contract

- `pytest tests/` — full suite green, including the 3 new test files (`test_dead_anchors_extract.py`, `test_dead_anchors_probe.py`, `test_scan_dead_anchors.py`) and the updated `test_non_breaking_contract.py` (scanner count +1, `dead_anchors` present in every scan mode's JSON output).
- `tests/test_benign_corpus.py`'s budget gate stays green with `dead_anchors` in scope — zero findings on the full benign corpus (including the new dead-anchor-specific benign fixtures from U5).
- `python3 scripts/scan_dead_anchors.py <any-repo> --offline` emits ZERO findings and exits 0, with zero network calls attempted (manually confirm via a network-blocking sandbox or an strace/lsof spot-check, not just the mocked unit tests).
- `python3 scripts/rule_loader.py dead_anchors` reports 0 failed self-tests (every rule's `examples.match`/`examples.no_match` passes).
- `python3 scripts/gen_rule_ids.py --print` runs cleanly and regenerates `data/rule_ids.csv` without error (0 new `DA` rows expected and documented, per U4's caveat — this is NOT a failure).
- `run_forensics.sh <fixture> --format json` (both skill-scan and full modes) includes a `dead_anchors` scanner entry with a valid `exit_code`/`finding_count`/`findings` shape matching `REQUIRED_SCANNER_ENTRY_KEYS`.

**Torture-room gate (spec §10 — non-negotiable, blocks merge if any fails):**
1. **Two concurrent scans over the same repo** (e.g. two `subprocess.Popen` invocations of `scan_dead_anchors.py` against the same target, or two in-process threads calling `scan_repo()` against the same cache dir) → no torn cache file (the on-disk JSON is always fully valid, never half-written), no crash in either process, and identical verdicts returned by both (same anchors, same network responses in the test double → same classification regardless of write-order race).
2. **Simulated 429 on the first GitHub call** → the circuit breaker trips (KTD-11); assert zero further calls to `api.github.com` for the remainder of that scan, and assert no retry was attempted on the original call.
3. **Network timeout on every single probe** (monkeypatch every network function to raise `TimeoutError`/`socket.timeout`) → the scan finishes within the configured deadline (bounded, not hanging), emits zero findings, and exits cleanly (exit code 0, no traceback).
4. **Duplicate anchors ×50** (the same `(owner, repo)` or same domain referenced 50 times across the seed files) → exactly ONE probe is issued for that anchor (dedup at extraction, U1), not 50.
5. **`--offline` opens zero sockets** — assert via a monkeypatch that raises `AssertionError` (or records a call) if `urllib.request.urlopen` or `socket.gethostbyname` is invoked at all during an `--offline` run; assert zero findings and a sub-second wall-clock (no artificial sleep anywhere on the offline path).
6. **Malformed/partial cache file on disk** (truncated JSON, wrong top-level type, a directory where a file is expected) → tolerated; the scan falls through to a normal probe (or NC if budget/deadline is also exhausted) with no exception surfacing to the caller.

## Decisions Log

### Design Decisions
- Standalone algorithmic scanner (KTD-1), not a per-file walk — anchors are extracted once per scan, not per file.
- HTTPError-first branching (KTD-3) is the scanner's single most load-bearing correctness property; every probe function's tests must explicitly exercise the 404-vs-generic-failure distinction.
- DA-10 bundled into DA-01/DA-02's Finding as enrichment, not a standalone Finding (resolves spec open question 7) — it has no independent CC/LO/NC verdict.
- GH call budget capped, `GITHUB_TOKEN` optional-never-required (resolves spec open question 1) — chosen over mandatory-token because Alex has explicitly banned API-key friction elsewhere (Total Recall enrichment) and an unprobed anchor degrading to silent NC is safe by KTD-4's design.

### Tradeoffs
- Capping GH calls at ~15-20/scan means a large repo with many GitHub anchors will have some anchors silently unchecked (NC) rather than exhaustively probed. This trades completeness for staying within the unauthenticated rate limit without requiring a token — acceptable because NC is safe-by-design (never a false-clear, never a crash), just incomplete.
- The bundled multi-part-TLD list (KTD-7) is deliberately not a full PSL — some ccTLD domain reductions will be imprecise. Documented, not silently wrong.
- DA-09 (free-tier-suffix flag) folding into DA-05's Finding rather than firing standalone (see U3 step 4) trades a small amount of independent signal value for avoiding double-counting/alert fatigue; flagged as a decision to revisit if implementation review finds real value in the standalone signal.

### Open Questions (carried from spec §9, still unresolved — flag for a follow-up decision, not blocking this build)
- **RDAP ccTLD gaps** — `rdap.org`'s bootstrap covers gTLDs well but ccTLD support varies; some domain checks will degrade to NC purely due to RDAP coverage, not actual liveness. Spot-check a handful of common ccTLDs during U2 implementation before treating RDAP as fully reliable; if a ccTLD gap turns out to be large, consider surfacing it in the end-of-scan summary line.
- **Fingerprint rot cadence** — cloud-provider error-page copy will change over time (KTD-10 makes the list pack-driven specifically so `refresh_threat_dbs.py` can update it, but no automatic freshness-check exists yet for "is this fingerprint still accurate" — that would require periodically re-fetching a known-dead reference URL per provider, which is a possible Phase 2 addition, not built here).
- **PSL imprecision** — accepted per KTD-7, documented, not resolved (a full PSL would require either a bundled large static file or a network fetch of the real Mozilla PSL, both rejected for now to keep the dependency/size footprint small).
- **DA-08 scope boundary vs `scan_runtime_dynamism.py`** — still needs an explicit design pass (not attempted in this build) to ensure the two scanners don't eventually double-fire on the same "fetch external content" pattern from the prose vs. code angle when DA-08 is picked up as Follow-Up Work.

## Phase 2 / Future

- **DA-07 verdict-decay / time-based recheck + DA-P2-5 content-drift hash-pin-and-diff** — both need new per-repo, per-anchor persistent state across scans, which repo-forensics has no equivalent of today. Bundle these into ONE architecture decision when picked up (don't build persistent state twice): likely a new `~/.cache/repo-forensics/dead-anchors-state/{repo-hash}.json` ledger keyed on anchor identity, with a scheduled re-scan trigger (cron-style, outside this scanner's own invocation) that diffs today's verdict/content-hash against the ledger and surfaces NEWLY-claimable or NEWLY-drifted anchors as a distinct "regression" Finding type.
- **DA-06 joint prose+code credential-leak correlation** — a genuinely different scanner shape (cross-references SKILL.md prose against actual code sinks), not an anchor-claimability extension; picked up as its own plan when prioritized.
- **DA-08 untrusted-external-instruction-fetch structural flag** — needs the `scan_runtime_dynamism.py` scope-boundary design pass noted above before implementation.
- **DA-11 reputation-inheritance abuse** — needs a validation pass against real repos to calibrate the commit-date-vs-file-date heuristic before it's worth the false-positive risk of shipping.
- **DA-P2-1/2/3 (reasoning-layer attacks, LLM jury, sandboxed dynamic execution)** — explicitly out of repo-forensics' zero-non-stdlib-dep, offline-first posture; would be a different product/architecture entirely, not an extension of this scanner.
- **DA-P2-4 (WHOIS-based domain-age/registrar-reputation/TLD-risk scoring)** — a refinement layer on top of P0's RDAP check, not needed for the core CC/LO/NC verdict; revisit if RDAP-only proves insufficiently precise in practice.
- **DA-P2-6 (registry/platform governance recommendations)** — not a scanner concern at all; no code to write, ever, in this codebase.
- **DA-P2-7 (runtime egress monitoring against a declared-domain allowlist)** — needs a runtime hook, a fundamentally different scanner shape (`auto_scan.py`-style continuous monitoring, not a point-in-time `scan_dead_anchors.py` invocation).
