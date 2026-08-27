# Changelog

All notable changes to repo-forensics. Versions follow semver.

## [2.14.7] - 2026-08-28

### Fix: bound scan-hook concurrency (unbounded fan-out could stall a machine)

- `PreToolUse` and `PostToolUse` both fire on **every** Bash command, and each
  scan fans out into eight scanner processes. Nothing bounded that. Under an
  agent running commands back to back, scans outlived the gap between commands
  and stacked instead of queueing: **16 concurrent scan trees, ~64% CPU each,
  load average 175** on a live machine. Interactive use never hit it, because a
  human pauses between commands.
- New `hooks/scan_guard.sh` provides `rf_scan_guard <name> <debounce>`, sourced
  by all six wrappers (Claude Code + Cursor, pre/auto/session). A scan is
  skipped when another is genuinely **in flight**, or when one ran inside the
  debounce window.
- The `PreToolUse` gate uses **concurrency-only** guarding (debounce `0`): it is
  a blocking gate, so skipping it on recency would let a command run unscanned.
  `PostToolUse` (90s) and `SessionStart` (60s) are advisory and debounce on time.
- Portability: the lock is a `mkdir` (atomic on macOS, Linux and Git Bash;
  `flock` is reliably present on none of them), release is by **PID liveness**
  plus a stale TTL rather than an `EXIT` trap, because these wrappers `exec()`
  and never run cleanup code. No `stat` calls, per the 2.14.5 Git Bash path fix.
- Escape hatches: `REPO_FORENSICS_DISABLE_SCAN_GUARD=1` restores the previous
  unbounded behaviour, `REPO_FORENSICS_SCAN_DEBOUNCE` and
  `REPO_FORENSICS_SCAN_STALE` override the windows.
- A **missing** `scan_guard.sh` degrades to the old unbounded behaviour on
  purpose. For a security tool, silently not scanning is the worse failure.

- `refresh_controller.py`: a timed-out refresh worker no longer **orphans its
  scanners**. `subprocess.run(timeout=...)` kills only the direct child, so the
  worker's scanner fan-out survived every timeout, reparented to init/launchd
  and still burning CPU with nothing tracking it. The worker now starts in its
  own process group (POSIX) / `CREATE_NEW_PROCESS_GROUP` (Windows) and a
  timeout signals the whole tree: SIGTERM, then SIGKILL, with `taskkill /F /T`
  on Windows. Verified against a worker-plus-grandchild tree, with a negative
  control confirming the previous path really did leave the grandchild alive.

**Known limitation:** a scan that is skipped is skipped, not queued. Under a
sustained command stream the `PostToolUse` audit samples at roughly one scan per
debounce window rather than one per command. That is the intended trade: the
previous behaviour did not scan more reliably, it collapsed the host.

## [2.14.6] - 2026-08-26

### Windows support complete: full Tests matrix green

- The `windows-latest` / `macos-latest` / `ubuntu-latest` matrix is green end to end,
  validated on-branch before release.
- Fixes 5 pre-existing **forensify** Windows failures that only surfaced once the
  repo-forensics suite started passing on Windows (it previously short-circuited them):
  `os.getuid()` guarded (was an `AttributeError`), and the Unix-permission assertions
  (0o700 coord folder, 0o600 world-readable check) plus a tilde-expansion path comparison
  made platform-aware.
- **Tracked follow-up:** Windows ACL-based permission detection.

## [2.14.5] - 2026-08-26

### Fix: launcher-path comparison under Git Bash

- Clears the 2 residual `windows-latest` CI failures from 2.14.4. `test_windows_compat`
  compared launcher paths with `os.path.samefile`, which `stat()`s both operands. Under Git
  Bash the launcher prints MSYS paths (`/c/Users/...`) that native Windows Python cannot
  `stat`, so it raised `FileNotFoundError` even when the launcher had found the file.
- Now compares normalized path strings (`/<drive>/` -> `<drive>:/`, `normcase` + `normpath`),
  touching no filesystem. Verified against both `ntpath` and `posixpath` semantics.

## [2.14.4] - 2026-08-26

### Windows support + security hardening

- **Cross-platform Cursor gate.** Ported the bash `beforeShellExecution` gate to
  `cursor_pre_scan.py`. On Windows `bash` resolves to the WSL launcher, so the failClosed
  gate denied *every* shell command. The port uses in-process `hashlib` + `sys.executable`
  and preserves R8 tamper-deny, fail-closed, degrade-vs-deny and PII redaction.
- **Install-time interpreter baking.** The installed hook launches via the installer's own
  interpreter, so python.org Windows installs (no `python3.exe`) still start the gate.
- **Security: closed a corrupt-manifest fail-open.** `cursor_pre_scan.py` now **denies**
  when `checksums.json` is present but corrupt or unreadable (previously fail-open).
  Corrupting the manifest must not be cheaper than forging a hash. Regression test added.
- **7 Windows-only failures fixed:** clock granularity (splitstream/provenance), path
  separators (post_incident), path comparison (windows_compat), home-var isolation
  (integrity).
- **docx false positive resolved** by making the test's font input deterministic; a random
  blob can chance onto a bidi/zero-width decode, whereas real fonts are structured.

## [2.14.3] - 2026-08-26

### Security: modification-aware tamper check on the Cursor blocking gate

- The Cursor wrapper's runtime integrity was existence-only, so a scanner that
  was present but **modified** (`pre_scan.py` rewritten to always-allow, the
  launcher swapped, or the IOC feed edited) passed the check and silently
  approved malware. `run_pre_scan.sh` now hash-verifies the fast gate's trust
  base against `checksums.json` before trusting a verdict — one sha256 pass, hash
  tool resolved by absolute path (no PATH-planting), strict when checksums are
  present. This is tamper-**evident**, not tamper-proof: the authoritative
  defense against a same-user attacker remains the offline signed audit
  (`verify_install.py --verify-signature`) plus OS file permissions.
- `run_pre_scan.sh` / `run_session_scan.sh`: guard the refresh-latch `HOME`
  reference so the wrapper emits a verdict instead of crashing under `set -u`
  when `HOME` and `XDG_CACHE_HOME` are both unset.
- `run_pre_scan.sh`: redact `session_id` in the opt-in evidence log.
- `verify_install.py`: report `NEW HOOK FILE` for untracked files planted under
  `hooks/`, dropping the audit verdict from VERIFIED to PARTIAL.

### Added: Cursor adapter — scan-on-agent-activity as the 4th platform

- **`--adapter cursor`** on `pre_scan.py`, `auto_scan.py`, and `session_scan.py`.
  Envelope normalisation and verdict rendering move into a new stdlib-only leaf
  module, `hook_adapter.py`, so both wires reach the same `pre_scan.decide()`.
  Cursor's `{"permission","user_message","agent_message"}` triple and the shipped
  Claude `{}` / `{"decision":"block"}` shape are two renderings of one verdict;
  `tests/test_cursor_parity.py` asserts they never diverge.
- **Three Cursor hooks** (`hooks/cursor/*.sh`) mapped onto `beforeShellExecution`
  (blocking IOC gate), `afterShellExecution` (deep audit, observe-only), and
  `sessionStart`. The blocking wrapper bootstraps the refresh daemon behind a
  once-per-session latch, because Cursor does not reliably dispatch `sessionStart`
  in cloud contexts.
- **`scripts/cursor_install.py`** — user-scope install to `~/.cursor/hooks.json`
  with the absolute plugin root baked into each command (the `openclaw_install.py`
  pattern). Merges rather than overwrites: foreign hooks survive, the required
  `version` field is never dropped, writes are atomic with a `.bak` and roll back
  on validation failure, and `--uninstall` removes only `REPO_FORENSICS_MANAGED=1`
  entries.
- **`.cursor-plugin/plugin.json`** plugin manifest, plus `.cursor/rules/repo-forensics.mdc`.
- **`ask` verdict tier** (Cursor only): an install redirected to a plaintext-HTTP
  or non-canonical package index is a real dependency-confusion signal that
  internal mirrors also produce, so it goes to the human rather than being blocked
  or waved through. On the Claude shape, which has no `ask`, it degrades to an
  approve plus a stderr note — stdout stays byte-identical to v2.14.2.
- **Forensify audits `~/.cursor/`** as a fifth ecosystem, with a cross-tool IOC for
  an unrecognised `beforeShellExecution` entry: that hook runs ahead of every shell
  command with the user's environment, so an unowned one is an arbitrary-code-execution
  surface, not a preference.

### Verified: the Cursor adapter against the shipping client (closes K6)

- Every Cursor-side assumption in this work started as a reading of the docs,
  which the handoff called out as its own biggest risk and an M0 blocker. All of
  it is now confirmed against **Cursor 3.17.19**: the three hook scopes, the
  `deny`-throws / `ask`-prompts verdict handling, `additional_context` for
  `sessionStart`, and the live stdin envelope. Written up in
  `skills/repo-forensics/references/cursor-hook-contract.md`.
- The real envelope carries **three fields that appear in no documentation** —
  `session_id`, `user_email`, `transcript_path` — and sends `cwd` as an empty
  string with `workspace_roots` empty when no folder is open. Validating either
  as required would have failed closed on every command in a folderless session.
  `TestRealCapturedEnvelope` pins the captured shape.
- **`user_email` is PII in the envelope.** The opt-in evidence logger redacts it
  and `transcript_path` before anything reaches disk, and a test asserts the hook
  never echoes the address to stdout or stderr.
- End-to-end: Cursor invoked the hook (`process chain: cursor <- cursor <- systemd`),
  the gate denied a Shai-Hulud IOC-pinned install, and Cursor refused to run it
  while relaying our campaign name — which came from `data/compromised_versions.json`,
  not from the model. Screenshot in `diagrams/cursor-blocked.png`.
- Demo guidance learned the hard way: `curl <url> | bash` is refused by the model
  itself, so it never reaches the gate. A blocker can only be demonstrated on a
  command the model would otherwise happily run.

### Security: fail-closed on the Cursor blocking path

- **Unreadable stdin now DENIES on the Cursor wire.** `pre_scan.py` approves on
  unparseable input by design, which is right for Claude Code (one layer, with a
  PostToolUse deep scan behind it) and wrong for Cursor, where the hook is declared
  `failClosed: true` and is the only thing in front of the command. A renamed or
  spoofed field was a silent approve of a live payload. Malformed JSON, trailing
  garbage, a renamed `command`, a non-string `command`, an unknown
  `hook_event_name`, and a foreign envelope all deny. The Claude wire keeps its
  fail-open behaviour, and both directions are pinned by tests.
- **Tamper-aware degrade (R8).** "Scanner absent" and "scanner deleted at runtime"
  are the same observation, so a blocking hook that approves on absence is one an
  attacker disables by deleting a file. `cursor_install.py` writes an
  `install-manifest.json`; if a file it claims is missing at runtime the gate denies
  and says why, while an unclaimed absence allows loudly. The check runs before the
  allow branch in BOTH `pre_scan.py` and `hooks/cursor/run_pre_scan.sh` — the
  wrapper needs its own copy, because if `pre_scan.py` is the deleted file then
  Python never gets a vote.
- **A gate that cannot run denies.** The Cursor wrapper no longer `exec`s into
  `python-launcher.sh`; a missing interpreter (exit 127, empty stdout) or a crashed
  scanner used to produce a bare non-zero exit with no verdict, which is exactly the
  ambiguity `failClosed` exists to resolve.
- **Kill-switch precedence (R11).** `REPO_FORENSICS_PRE_SCAN=0` disables detection
  and nothing else. The variable is read from the session environment, so an earlier
  command can plant it; allowing it to also mask tamper and drift denials would let
  one planted variable buy the entire gate. `unsafe-off` is the documented full
  escape hatch. Only those exact literals disable anything — a switch with fuzzy
  truthiness is one an attacker trips by accident.

### Fixed: DAST reported unrunnable hooks as CRITICAL path traversal (Linux)

- The Linux bubblewrap sandbox mounted `--tmpfs /tmp`, which shadowed any hook
  script living under `/tmp` -- a repo cloned to a temp dir, a CI checkout, every
  pytest `tmp_path`. bash could not open the script, so DAST silently observed
  nothing on those hosts. The hook's own directory is now re-bound read-only
  after the tmpfs, mirroring what the macOS Seatbelt branch already did via
  `-D HOOK_PATH` / `-D HOOK_DIR`.
- Worse than the blind spot: bash's own failure diagnostic
  (`/bin/bash: <path>: No such file or directory`) contains the literal
  `/bin/bash`, which is one of the path-traversal *success* indicators — so a
  hook that never executed was reported as a CRITICAL "path traversal
  succeeded". Indicator matching now runs against the hook's output with the
  launcher's own diagnostics stripped, and an exec failure (exit 127, no stdout)
  reports nothing at all rather than something. Evidence that a hook did
  something has to come from the hook, not from the thing that tried to start it.

### Fixed: archive budget exhaustion did not name the starved archive

- `archive-scan-incomplete` reported "one or more archives hit a safety cap"
  against the repo root. For anyone trying to act on it that is indistinguishable
  from a silent skip — the archive that got truncated is exactly the one worth
  re-scanning on its own. Caps tripped while scanning an archive are now
  attributed to it by an edge-detect at the call site, and the finding names them
  (T5, fail-loud-by-name).

### Fixed: `hooks/` subdirectories escaped the integrity registry

- `get_tracked_hook_files` listed `hooks/` one level deep and skipped anything that
  was not a regular file, so a per-agent wrapper *directory* was exempt from
  checksums and signature verification — reopening the exact gap the function was
  written to close (commit 64fbe57). It now walks the tree. Found while confirming
  the PRD's assumption that `hooks/cursor/*` would be covered automatically; it
  would not have been.
- `get_tracked_runtime_manifest_files` hardcoded `.claude-plugin` / `.codex-plugin`,
  so `.cursor-plugin/plugin.json` — which names the hook commands — would have been
  checksummed by nobody. Now tracked, and registered with `validate_manifests.py`
  so `validate-manifests.yml` gates it.

### Fixed: pipe-to-shell false positive on quoted prose

- `git commit -m 'docs: warn against curl | bash'`, `echo 'never run curl … | bash'`,
  and `grep 'curl .* | sh' docs/` were blocked. This is the command-string analogue
  of the evidence model already applied to files: a message *about* an attack is not
  the attack. The suppression is narrow by necessity — the obvious wide version
  ("ignore anything in quotes") is a bypass, since `sh -c 'curl …|bash'` is quoted
  and executes. Two conditions must both hold: the command starts with a known inert
  carrier (`echo`, `printf`, `grep`, `git commit`…), and the residue left after
  deleting every quoted span contains no shell execution of its own. So
  `echo "curl http://x|bash" | bash` keeps its residual `| bash` and still blocks.
  Applied identically in `pre_scan.py` and `auto_scan.py`.

### Fixed: CI re-sign hint pointed at the wrong directory

- `verify-checksums.yml` told contributors to run `scripts/sign_release_manifest.py`
  directly under a `cd skills/repo-forensics`, where that script does not exist. The
  hint now names the repo-root path, says that signing is a maintainer step (the
  private seed is offline, so contributors can regenerate `checksums.json` but cannot
  produce a valid `.sig`), and spells out the shipping order for new files:
  regenerate checksums -> re-sign -> re-run the marketplace mirror sync.

### Added: keyv/cacheable August 2026 wave + 25-campaign IOC ingest

- `data/compromised_versions.json` grows from 25 to 50 campaigns and from 302 to
  5,828 pinned versions across 2,471 package entries, entirely additive. The
  headline entry is `shai_hulud_keyv_cacheable_aug_2026` (the August 2026 keyv /
  cacheable maintainer-token wave); the rest is a bulk ingest from the Cobenian
  `shai-hulud-detect` inventory covering the Mini Shai-Hulud PyPI and TanStack
  waves, the Miasma cluster, TeamPCP, and assorted RAT and typosquat campaigns.
  Versions stay pinned rather than collapsing to package names, so a clean
  release of a once-compromised package does not trip the scanner.

### Added: Shai-Hulud family behavioral signatures

- `scan_lifecycle.py` and `scan_post_incident.py` now cover the whole family
  behaviorally rather than the v1 worm alone: v1 (`chalk` / `debug`, September
  2025), the April-May 2026 Mini Shai-Hulud TanStack / AntV / atool dropper
  waves, the May 2026 copycats, and "The Second Coming" fake-Bun wave with its
  December 2025 "Golden Path" rename.
- Lifecycle detection covers the fake-Bun preinstall dropper hook
  (`"preinstall": "node setup_bun.js"`), the `setup_bun.js` / `bun_installer.js`
  installers, the `bun_environment.js` / `environment_source.js` obfuscated
  credential-harvest payloads, injected `formatter_<digits>.yml` workflows,
  `SHA1HULUD` self-hosted-runner persistence, TruffleHog credential harvesting,
  and the dead-man's-switch home-directory wipe that an `rm`-based rule alone
  does not see.
- Post-incident detection adds the family's host artifacts: the
  `gh-token-monitor` LaunchAgent / systemd / token-cache persistence set from the
  May 2026 TanStack wave, `kitty/cat.py`, staged TruffleHog binaries, confirmed
  malicious payload hashes, Shai-Hulud repository and branch names, exfil-repo
  description markers (including the character-reversed Mini beacon), and a
  base64-encoded `data.json` at repository root.

### Fixed: version-pinned `name@version` installs bypassed the IOC gate

- `pre_scan.py` and `auto_scan.py` matched install tokens against IOC package-name
  sets only, so a pinned npm-family token like `keyv@6.0.0` matched no name and
  sailed through, which is exactly the form a real install command takes. Both
  now split on the last `@` (never the leading scope marker, so
  `@scope/pkg@1.2.3` resolves correctly) and re-check the base name against
  known-malicious packages and the exact pinned version against the campaign
  database.

### Hardened: adversarial QA pass on the Shai-Hulud additions (torture gauntlet + review)

- **Behavioral false-positives tightened** without losing worm detection:
  `rm -rf $HOME/.cache` (and quoted `"$HOME"`), `node setup.mjs`, the standard CI
  `trufflehog` install, `find /var/log | xargs shred`, `os.homedir()` + a
  subpath `rmSync`, bare `formatter_<n>.yml`, and `if cred fail; rm ~/.cache` no
  longer fire CRITICAL. TruffleHog *download* is now context-aware (critical in an
  install/runtime script, suppressed in CI workflow files). Bare Bun dropper
  filenames drop to a MEDIUM weak-signal hint.
- **Gate bypasses closed**: version ranges that resolve to a compromised pin
  (`keyv@^6.0.0`, `~`, `>=`, `6.x`), `v`-prefixed pins (`keyv@v6.0.0`), npm-alias
  (`local@npm:keyv@6.0.0`), tarball/git URLs (incl. scoped `@scope/name`), and
  boolean-flag value smuggling (`--save-exact keyv@6.0.0`) all block; real
  dist-tags (`@latest`) still approve. Version-less alias/URL forms of a
  name-listed package now block too.
- **Latency**: the gate loads the IOC set once per invocation (was twice on the
  npm path); benign non-install commands never load IOCs.
- **IOC-cache crypto loader**: closed a verify-then-load TOCTOU (the signature is
  now verified over the exact bytes that are parsed, from a single read); fixed a
  restore-on-read race that could clobber a mid-refresh feed (grace-window guard);
  hardened strip-detection against sentinel co-deletion (`.previous.sig`); fixed
  file-descriptor and refresh-lock leak paths.
- **Self-scan gap**: `.forensicsignore` no longer wildcard-ignores `iocs/*.json`
  (which is not integrity-covered) — only the two known inventories by exact name,
  so a dropped payload under `iocs/` is still scanned.
- **Both-tree parity** is now enforced by `test_tree_parity.py`.

### Tests

- 113 new tests from the additions, plus the hardening pass: `test_pre_scan.py`
  regression matrix for every closed bypass, `test_tree_parity.py`, and updated
  crypto-loader coverage. Full suite green except the pre-existing checksum-drift
  gate (clears on re-sign).

## [2.14.2] - 2026-08-20

### Security: detection hardened to fail closed

Severity and the pass/fail exit code now key on what code does, not on surface cues an attacker
controls, closing a class of bypasses where a payload could dodge detection by its location, name,
extension, wrapping, or by hiding behind a scan limit.

- Location no longer changes severity: a finding under `docs/`, `tests/`, `fixtures/`, `filters/`,
  or in a file named `readme`/`license` is graded on its content, not its folder or filename.
  Identical bytes get an identical verdict everywhere.
- Obfuscation-resistant classification: executable code disguised as a log/print call, a string
  literal, or a shell command-substitution is no longer read as inert text; character-class and
  single-star `.forensicsignore` patterns are treated like their plain equivalents.
- No silent passes behind scan limits: unsupported archives (`.7z`/`.rar`), deeply nested archives,
  oversized files, over-cap bytecode, and deeply-encoded blobs can no longer report clean; an
  executable artifact the scanner could not fully inspect now floors the exit code.
- Suppression is visible and bounded: a `.forensicsignore` that hides source is always surfaced,
  wholesale suppression escalates, and suppressing a critical finding is flagged as tampering;
  legitimate scoped ignores keep working.
- The two evidence classifiers now share one fail-closed core, guarded by a test that fails the
  build if they ever disagree.

Recommended: update from 2.14.x. Earlier versions can under-report on obfuscated, archived, or
oversized payloads. Thanks to Naor Peretz ([@Naor-Peretz](https://github.com/Naor-Peretz)) for the
private report that started this work.

## [2.13.2] - 2026-08-05

### Changed: Memory-Heist context-gating (fewer false positives, no lost attacks)

- The `memory-heist-exfil` rules (ST-MH-001..005) now route through the unified
  file-type / line-context classifier from v2.13.1. Patterns are byte-identical, so
  the real UA-routing and PII-in-URL attacks still fire at CRITICAL, but the same
  patterns sitting in documentation prose, fenced code samples, `SECURITY.md` /
  `PRIVACY.md` self-descriptions, or test fixtures demote to informational. Every
  demoted finding stays listed with its original severity, so nothing is silently
  suppressed. This replaces the previous all-or-nothing behavior that accepted a wall
  of benign false positives to avoid losing a real catch.
- `module_from_spec` (RD-SMOD-003) demotes only in test-fixture context; a real
  write-then-load in production code stays CRITICAL.

### Security decision: an exfil directive in code stays CRITICAL

- Two deliberate calls, both because an AI agent reads code: a Memory-Heist directive
  hidden in a code comment or string, and one hidden in a code or config file named
  `security.*` / `privacy.*`, both stay CRITICAL rather than demoting. The handful of
  benign comment and security-named false positives are the accepted cost of catching
  attacks that hide there. Documentation, prose, and test contexts still demote.

### Fixed: codex marketplace mirror checksums

- The codex distribution mirror's signed `checksums.json` now includes the YARA and
  context-gate files shipped in v2.13.1 (they were present but unlisted, so a
  codex-install integrity check returned PARTIAL). The release gate now verifies both
  the canonical and mirror manifests before tagging so this cannot recur.

## [2.13.1] - 2026-08-05

### Added: unified context-gating primitive + YARA evidence gating

- New `scripts/_context_gate.py` is the single deterministic, offline, stdlib-only
  classifier that derives an evidence class from file type, path segment, and line
  context. It never raises and accepts no absolute-path input, so every scanner can
  route a match through one gating function instead of hand-tagging evidence.
- `scan_yara.py` now consumes the classifier instead of a hard-coded
  `evidence_class="direct"`. A YARA match on a real payload (`shell.php`, `x.bin`,
  `config.json`) stays `direct` and CRITICAL, while the same bytes in a doc
  (`x.md`, `docs/x.md`), a test fixture (`tests/test_x.py`), or a blocklist
  (`blocklist.js`) demote to `inferred` so the verdict loses false-positive noise
  without losing the real hit. Integrity, timeout, and read-error findings keep
  `direct` so capability-gap signals are never gated away.
- The YARA signature scanner (the 27th scanner, shipped in 2.13.0) is now
  context-gated end to end. `yara-python` stays an optional dependency: when absent
  the scanner degrades to a missing-tool capability gap (one stderr line,
  exit-neutral, stdout `[]`), so the core product remains zero-non-stdlib-deps and
  offline.

### Added: 6 YARA signature false-negative widenings

- Six existing rules had their strings or conditions widened so real family
  variants fire, with no new rule IDs and re-pinned per-file sha256 in
  `data/yara/manifest.json`: `YR-MAL-002`, `YR-WEB-002`, `YR-WEB-001` (the
  `not $assert` condition fix), `YR-CRY-001`, `YR-HCK-002`, `YR-HCK-003`. Each
  widening ships with a teeth trigger and a near-miss negative in
  `tests/test_scan_yara.py` so a one-token guess still does not match.

### Fixed: D1 correlation contamination from YARA leaves

- `forensics_core.correlate()` now excludes `yara` from the `by_file` correlation
  leaf set via `_CORRELATION_LEAF_EXCLUDED_SCANNERS = {"yara"}`. A YARA critical on
  a webshell plus an unrelated AWS key in the same file no longer synthesizes a
  bogus "Potential Data Exfiltration" finding. The YARA critical and the secrets
  high still surface on their own; only the contaminated cross-scanner rule is
  suppressed. A regression test (`tests/test_d1_yara_correlation.py`) pins a
  webshell + AWS-key, no-network fixture to assert no exfiltration finding while
  the real findings remain.

### Fixed: torture-hardening (extension-blind demotion + scan_text traversal)

- Extension-blind doc/blocklist demotion closed. A live payload on a code
  extension (`readme.php`, `changelog.php`, `license.bat`, `docs/shell.php`,
  `v1/docs/index.php`, `blacklist.bat`, `denylist.php`) now classifies
  `primary="code"`, `gate_evidence="direct"`, and stays CRITICAL with exit 2. The
  doc-basename, doc-path-segment, and blocklist-basename-token signals only
  demote on doc, empty, or unknown extensions, never on a code extension. The
  intended demotions still hold: a webshell in `.md` or `SKILL.md`, under
  `tests/shell.php`, or in a `blocklist.json` config still demotes and lists.
- `scan_yara.scan_text` now normalizes the caller `rel_path`
  (`os.path.normpath(rel_path.replace("\\","/"))`) before constructing the
  `Finding.file` and the SARIF uri, and `..` segments are collapsed before the
  classifier evaluates segment membership. `scan_text(payload, "../../evil.php")`
  and `"tests/../shell.php"` no longer carry `..` in `Finding.file`, and the
  `tests/../shell.php` payload can no longer demote via a segment it escaped.

### Docs

- SARIF 2.1.0 output (shipped in 2.13.0) and the YARA signature scanner are now
  documented in the README feature narrative and scanner table. The scanner count
  is stated as 27 everywhere it appears (README, both SKILL.md copies, every
  diagram), and `diagrams/scanner-map.svg` and `diagrams/pipeline.svg` now draw a
  `yara` node.

### Known residuals

- Flag-value whitespace can miss a literal rule match (flag-value-whitespace
  literal-rule miss), and the content-shape blocklist signal can false-positive
  on a real filter-list file (content-shape blocklist FP). Both are accepted,
  non-blocking, and tracked for a later release.

## [2.13.0] - 2026-08-04

### Added — SARIF 2.1.0 output (`--format sarif`)

- New `--format sarif` emits a GitHub code-scanning-compatible SARIF 2.1.0
  document from the same aggregated report the text/json/summary paths use.
  The converter (`scripts/sarif_export.py`) is lazy-imported only inside the
  `--sarif` branch, so the text/json/summary paths stay zero-new-dependency
  and byte-identical to v2.12.5 (verified by golden-output diff).
- Mapping: severity -> SARIF level (critical/high -> error, medium ->
  warning, low/info/unknown -> note); line=0 -> no region, line>0 ->
  startLine == line (never startLine: 0); Windows-style paths -> forward-
  slashed relative URIs under a `SRCROOT` uriBaseId; empty `rule_id` ->
  synthesized `rf/<scanner>/<category-slug>` descriptors (correlation/meta
  get their own namespace); `rules[]` deduped + sorted; every result.ruleId
  resolves in `driver.rules`; `partialFingerprints` carry `findingId` and a
  `stableLocationV1` sha1 (survives snippet rotation; distinct occurrences of
  the same rule+file get distinct fingerprints); suppressed findings get
  `suppressions[0].kind = "external"`.
- The OASIS SARIF 2.1.0 JSON Schema is vendored at
  `tests/schemas/sarif-schema-2.1.0.json` (draft-07, sha256
  `7c9688f0a1c4a4e1649ecc78521087e664729c1dff56ee8212ff195c7b16132a`).
  `test_sarif_export.py` validates output against it with `Draft7Validator`
  (importorskip `jsonschema`, so the test skips cleanly where jsonschema is
  absent) and pins `TOOL_VERSION` to `.claude-plugin/plugin.json`.
- `run_forensics.sh` plumbs `--format sarif` through the aggregator dispatch
  and the `MACHINE_FORMAT` banner/progress suppression (sarif suppresses the
  human banner exactly as json does; text/summary output is unchanged).

### Added — YARA signature scanner (`yara`)

- New `yara` scanner: curated YARA signatures for malware, webshells,
  cryptominers, and hacktools. 11 hand-authored rules across 4 families
  (`data/yara/{webshells,malware,cryptominers,hacktools}.yar`), each with a
  `meta:` block (id/severity/category/confidence/title) mirrored in
  `data/yara/manifest.json` with per-file sha256 integrity checks. Multi-
  string conjunctive conditions + filesize bounds so a match is a confirmed
  family indicator, not a single-token guess. Teeth tests confirm every rule
  fires on its trigger and near-miss negatives (one missing conjunctive
  string) stay clean.
- `yara-python` is an **optional** dependency. When absent the scanner
  degrades to a missing-tool capability gap: one stderr line containing the
  `not found` enrichment marker (-> `enrichment_status.overall = DEGRADED`),
  stdout `[]`, exit 0. The core product stays zero-non-stdlib-deps, offline,
  and deterministic. CI installs `yara-python` on the Ubuntu test leg so the
  live matcher runs there.
- Severity assignments (R4 conservative initial): webshells CRITICAL,
  reverse-shell/PowerShell/HTA stagers HIGH, XMRig stratum HIGH, browser
  miner MEDIUM, hacktools (Mimikatz/Metasploit/LSASS-dump) MEDIUM.
- Wired into `run_forensics.sh` (skill-scan + full-audit lists; count
  strings 26 -> 27 / 16 -> 17), `auto_scan.py` targeted_scanners (14 -> 18),
  `test_non_breaking_contract.py` EXPECTED_BASE_SCANNER_NAMES,
  `test_benign_corpus.py` _SCAN_FILE_MODULES, `gen_rule_ids.py`
  `_SCANNER_ABBREV` (YR), and `data/rule_ids.csv` (11 YR-* rows appended).
- `.forensicsignore` excludes `data/yara/*.yar` and `manifest.json` so the
  scanner does not self-fire on its own rule pack during a repo-forensics
  self-scan.
- New `tests/corpus/benign/minified_bundle.js` FP canary: a minified
  jQuery-shaped blob (high-entropy single-letter identifiers, eval()/
  document.write call shapes, base64 data-URIs) that MUST stay at zero
  findings across all scan_file scanners. Budget locked in
  `tests/corpus/budgets.json`.

### Changed — version bump 2.12.5 -> 2.13.0

- `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`,
  `.claude-plugin/marketplace.json`, `openclaw/openclaw.plugin.json`,
  `.github/badges/metrics.json`: version 2.13.0; scanner count 26 -> 27
  where stated. `scripts/sarif_export.py` `TOOL_VERSION` pinned to 2.13.0
  and drift-checked by `test_sarif_export.test_tool_version_matches_plugin_json`.

## [2.12.5] - 2026-07-25

### Fixed — skills load in GitHub Copilot CLI (thanks @thejesh23)

- `argument-hint` in the forensify SKILL.md frontmatter was written with bare
  brackets, which YAML reads as flow sequences rather than a string. Two of them
  on one line is a parse error, so stricter loaders (GitHub Copilot CLI 1.0.65
  and newer) dropped the skill. The value is now quoted. Reported and fixed by
  @thejesh23 (#35, #36).

### Added — frontmatter validation in the manifest gate

- `validate_manifests.py` now validates `SKILL.md` YAML frontmatter alongside
  the plugin manifests it already checked, so this class of frontmatter error is
  caught before release. It runs a dependency-free structural check and, with
  PyYAML available, a full parse and type check; `--require-yaml` keeps CI at
  full scope.

### Added — release manifest signature check

- `verify_install.py --verify-signature` confirms `checksums.json` is signed by
  the pinned release key, and the Verify Checksums workflow now runs it. This
  complements `--verify`, which checks files against the manifest.

### Fixed — refreshed threat data and plugin parity

- Re-signed the checksum manifest so threat-database refresh resumes.
- Re-synced the bundled marketplace plugin, bringing it to rulepack version 3
  (124 rules) to match the skill tree, including the Memory Heist detections.

## [2.12.1] - 2026-07-07

### Added — uv / bun / pnpm install triggers (thanks @noamloewenstern)

- The auto-scan (PostToolUse) and pre-scan (PreToolUse) hooks now trigger on
  `uv`, `bun`, and `pnpm` install commands, so these package managers get the
  same IOC pre-block and post-install scanning as pip/npm/yarn. `uv sync`
  scans the working directory like `git pull`. New patterns are ordered before
  pip/npm because the matchers are unanchored (`pnpm install x` substring-
  matches `npm install x`); regression tests pin the ordering. Contributed by
  @noamloewenstern (#33, #34).

### Hardened — monorepo forms and bare lockfile installs

- The `uv`/`pnpm`/`bun` matchers now accept package-manager flags between the
  tool and its subcommand, so monorepo/workspace forms are covered:
  `pnpm -r add x`, `pnpm --filter web add x`, `uv --project /p add x`. The
  flag prefix is written to fail fast on dash runs (no catastrophic
  backtracking; a ReDoS-timing test guards it).
- Bare lockfile installs now scan the working directory: `npm install`,
  `npm ci`, `pnpm install`, `bun install`, `yarn`, and the all-flags forms
  (`pnpm install --frozen-lockfile`, `npm install --production`) — previously
  the most common post-clone command triggered no scan at all.

## [2.12.0] - 2026-07-05

### Added — dead_anchors scanner (SkillJacking defense)

- New 26th scanner, `dead_anchors`, detects dead/claimable external anchors a
  skill references — GitHub owner/repo names, npm/PyPI package names, domains,
  and cloud-hosting subdomains — that have gone dead and are therefore claimable
  by an attacker (the SkillJacking / repojacking / dangling-reference attack
  class). Probes GitHub, package registries, RDAP, and DNS with a per-host
  circuit breaker and a three-tier verdict: only CONFIRMED-CLAIMABLE emits a
  finding; LIVE-AND-OWNED and COULDNT-CHECK stay silent to avoid noise. Ships
  an `--offline` opt-out and adds zero non-stdlib dependencies. Reuses the
  Windows-hardened atomic-write and threaded-timeout DNS helpers, so no new
  platform-sensitive primitives are introduced.
- Wired into `--skill-scan` (now 16 scanners) and the full audit (now 26
  scanners), the PostToolUse auto-scan targeted list, and the Codex marketplace
  mirror. Detection rules live as data in `data/rulepacks/dead_anchors.json`
  (8 self-tested rules).

## [2.11.7] - 2026-07-03

### Fixed — Codex Desktop bundled-Python discovery

- The auto-scan and pre-scan hooks now find the Python that Codex Desktop
  bundles inside its runtime cache (e.g.
  `~/.cache/codex-runtimes/<runtime>/dependencies/python/python.exe`). That
  interpreter is never on `PATH`, so on Windows/Codex the hooks previously
  failed with `no usable Python 3 interpreter found` and the automatic scan on
  clone/install did not run. `python-launcher.sh` now derives search roots from
  `XDG_CACHE_HOME`, `HOME`, and `LOCALAPPDATA` (no hardcoded user path), probes
  each candidate with an executable + `--version` check before use, and honors
  an explicit `CODEX_RUNTIME_PYTHON` override. Real system interpreters are
  still preferred; the bundled runtime is a last resort. This closes the gap
  that forced a local launcher patch, which in turn broke `--verify-install`
  integrity (the shipped launcher now works unpatched, so checksums verify
  clean on a fresh install).

## [2.11.6] - 2026-07-02

### Fixed — native Windows marketplace installs

- Preserve LF bytes in Git checkouts on Windows so signed installation
  integrity checks no longer report nearly every plugin file as tampered when
  `core.autocrlf=true`.
- Resolve and probe `python3`, `python`, then `py -3` once for CLI scans,
  skipping Microsoft Store execution aliases that exist on `PATH` but are not
  usable interpreters. Adapted from the Windows work contributed by Diane
  Whiddon in #28.

## [2.11.5] - 2026-06-20

### Fixed — verified, cross-platform refresh automation

- Refresh now self-heals after a reinstall/update: a leftover "disabled by
  uninstall" marker no longer keeps threat-DB refresh dark on a machine where the
  plugin is installed again. The next session re-enables and refreshes
  automatically, clearing any stale-DB warning with no manual step. An explicit
  user `disable` (or the env kill switch) still stays sticky.
- Fixed the reproduced stale-marker incident: an unchanged, valid signed
  rule-pack is now accepted as current after cache expiry; equal-version changed
  content remains rejected as equivocation and lower versions as rollback.
- IOC refresh now verifies the detached Ed25519 signature before replacing the
  cache or reporting success. KEV refresh rejects truncated catalogs below the
  reader's 100-CVE safety floor. Only immediately usable feed data advances
  freshness.
- Added one cross-platform refresh controller with machine-readable status,
  per-feed results, retry throttling, persistent disable/enable, exact scheduler
  repair, and stable integrity-checked payload promotion.
- Added native per-user scheduling for macOS launchd, Linux systemd timers, and
  Windows Task Scheduler, with an observable detached fallback when native
  scheduling is unavailable.
- Scheduler ownership is now agent-neutral and monotonic across Claude Code,
  Codex, and OpenClaw. A stale agent cannot downgrade the stable active payload;
  v2 scheduler names isolate migration from the v2.11.4 legacy job.
- Removed cross-marketplace executable-code fallback, the predictable `/tmp`
  diagnostics file, destructive `kickstart -k`, inherited-PATH command lookup,
  and versioned-cache scheduler targets.
- OpenClaw upgrades now recognize managed hooks after a checkout move, and both
  OpenClaw/Codex installers fail closed instead of overwriting malformed JSON.
- Added required macOS/Linux/Windows refresh-contract CI and deterministic
  Codex mirror verification; write-capable badge automation now uses SHA-pinned
  actions and does not persist checkout credentials.

## [2.11.4] - 2026-06-20

### Fixed — threat intelligence refresh self-healing

- SessionStart now bootstraps or repairs background threat-feed refresh
  automatically after the user trusts the plugin hook. macOS uses a daily
  LaunchAgent; Linux and Windows use a detached, once-daily session kick.
- Updater resolution now prefers the plugin copy that invoked it, preventing a
  Codex install from silently running older refresh code from a stale Claude
  plugin cache. Versioned scheduler paths repair themselves on the next session.
- The successful-refresh marker advances only when IOC, CISA KEV, and signed
  rule-pack updates all succeed. Partial/network failures remain visibly stale
  instead of creating a false-fresh state.
- The refresher now runs cross-platform with POSIX `flock` or Windows
  `msvcrt.locking`, while preserving the non-blocking SessionStart path.
- Added regression coverage for bootstrap ordering, source resolution,
  partial-failure truthfulness, Linux loading, cross-platform fallback, and
  Codex marketplace packaging.

## [2.11.3] - 2026-06-20

### Fixed

- **Codex automation hooks now load.** Removed the unsupported top-level
  `description` field from `hooks/hooks.json`. Codex uses a strict hook-file
  schema and previously rejected the entire plugin hook manifest, leaving
  Codex marketplace installs with the skills available but without the
  PreToolUse IOC gate, PostToolUse auto-scan, or SessionStart security scan.
- Added regression coverage for both the root plugin and the nested Codex
  marketplace mirror so future metadata changes cannot silently disable hooks.

## [2.11.2] - 2026-06-20

### Added — three scanner-bypass detection classes hardened

Closes three classes of scanner-evasion where a malicious payload is carried in
a form the text-only scanners never inspect, plus a supply-chain redirect class.

- **Content-based archive detection** (`scan_archive`): archives are now
  identified by magic bytes (`PK` / `ustar` / gzip / bzip2) and `is_zipfile`,
  not filename, so an archive renamed to dodge extension gating (e.g. a zip saved
  as `.docx.txt`) or a polyglot / self-extracting zip with a stub prefix is still
  opened and scanned. A script or native executable smuggled inside an OOXML
  (Office) document is flagged HIGH on structure alone. Binary members are
  identified by non-text-byte ratio (not a single null byte, which an attacker
  can trivially prepend) so embedded fonts/images neither false-positive nor
  blind the detectors.
- **Bytecode poisoning detection** (`scan_bytecode`): a benign `.py` source
  shipping a malicious compiled `.pyc` (Python loads the cached bytecode over
  source when the header validates) is caught by diffing raw `.pyc` danger
  markers against the sibling source — **no unmarshalling, no execution,
  cross-version-safe**, so the verdict never runs attacker bytecode. Markers are
  anchored to the marshal length prefix (compiled side) and word boundaries
  (source side) to prevent substring-cancellation evasion. Best-effort
  multi-interpreter decode enriches the report but never gates the verdict.
  Obfuscated dynamic attribute access (`getattr` + char-built names + sensitive
  import) is also flagged.
- **Registry hijack / dependency confusion** (`detect_registry_hijack_raw`):
  npm / yarn (incl. Berry `npmRegistryServer`) / pip `index-url` / bun registry
  redirected to a non-canonical host is flagged MEDIUM (corporate mirrors are
  legitimate — review, not block), escalating to HIGH only when the redirect
  co-occurs with reviewer-disarming assurance prose ("already public",
  "audited", "introduces no disclosure surface"). Resolves `${VAR}` indirection,
  strips comments, and is ReDoS-safe.
- **Install-time hook parity**: the archive and bytecode scanners plus the
  trifecta and registry-hijack raw detectors now run in the PostToolUse hook
  path, so a `git clone` / `npm install` is no longer given a false-clean
  verdict on exactly these threats.

### Notes

- Calibrated for accuracy over aggression: the offline benign-corpus
  false-positive gate stays green. HIGH is reserved for unambiguous manipulation,
  not legitimate corporate mirrors or normally-committed bytecode caches.
- Detection never executes or unmarshals attacker code to reach a verdict.

## [2.11.1] - 2026-06-18

### Added — final two scanner-bypass detection gaps closed

Closes the last two of the five CSA / Trail of Bits "AI agent skill scanner
bypass" techniques (the first three landed in 2.11.0), taking the suite to 25
standalone scanners.

- **decode-and-rescan** (`scan_decode`): an in-process, standard-library
  decode-and-rescan library. It decodes base64 / base85 / base32 / hex blobs
  (recursion-, input-size-, byte- and wall-clock-bounded) and re-runs the
  SAST/trifecta plus targeted heuristics over the decoded plaintext, so an
  encoded payload is inspected, not just flagged. It NEVER exec/eval/compiles
  decoded content (`ast.parse` only). Wired into the entropy, AST, and
  skill-threats scanners through one shared per-scan budget.
- **split-stream reassembly** (`scan_splitstream`): reassembles payloads split
  into inert encoded fragments across unrelated files (no import edge), unions
  same-alphabet length bands, tries a bounded set of orderings, and
  decode-rescans the joined blob. Hard-bounded against OOM/SIGKILL; a payload
  split into more than ~6 equal-length fragments in fully-scrambled order is a
  documented best-effort residual.
- **artifact provenance** (`scan_provenance`): verifies artifact signatures via
  cosign / gh / npm / pip when present (zero added dependencies, total-time
  budgeted). Quiet by design — only a signature that is PRESENT but FAILS
  verification (tampering) emits, as CRITICAL; the universal unsigned state is
  silent.

### Fixed

- **Silent-zero detection bypass (root cause).** `auto_scan` now fails LOUD when
  a scanner times out, is killed by a signal, crashes, or emits unparseable
  output, instead of returning an empty result that read as a clean verdict. A
  repo could previously force any scanner past the wall-clock budget (or OOM it)
  to suppress its findings silently. Memory and wall-clock are now bounded across
  the new scanners so attacker input cannot trigger a SIGKILL/OOM silent-zero.

## [2.11.0] - 2026-06-17

### Added — three scanner-bypass detection gaps closed

Closes the "hide the payload where the text reader never looks" bypass class
documented by CSA / Trail of Bits (June 2026). Three new standalone,
standard-library scanners reach the file classes the ~20 text scanners skip:

- **archive** (`scan_archive`): inspects payloads hidden inside
  `.zip/.docx/.xlsx/.pptx/.jar/.whl/.tar.*` and other archives. Members are read
  **in memory and scanned in process** — attacker-controlled bytes are never
  written to disk. Streaming byte-counter bomb guard (decompressed size is
  measured, never trusted from the header), cumulative fan-out cap, lazy tar
  iteration, tar symlink/hardlink/device/FIFO refusal, depth cap, and fail-loud
  findings (`unsupported-archive-type`, `opaque-archive`, `archive-scan-incomplete`).
- **bytecode** (`scan_bytecode`): disassembles Python `.pyc` bytecode that
  source-only scanners miss. `marshal.loads` runs in a disposable subprocess so
  hostile bytecode cannot crash or hang the scan; magic-derived header length,
  recursive `co_consts` walk, vendor-aware orphan handling.
- **oversize** (`scan_oversize`): head+tail window scan of files padded past the
  10 MB cap, plus whitespace-inflation detection — both wall-clock bounded.

Shared additions: `walk_aux()` (size-cap-free / `__pycache__`-reaching traversal
that leaves the shared `walk_repo` defaults untouched) and in-memory text
detection entry points (`scan_text` / `scan_content` / `scan_text_trifecta`).

### Security

- Hardened against a five-agent adversarial review: corrupt-archive crash,
  tar decompression bomb, scanner-timeout DoS, extension-gate bypass,
  surrogate-constant crash, disassembly-blob forgery, and fan-out starvation are
  all fixed and pinned by regression tests. Stdlib-only, cross-platform (POSIX
  rlimits guarded, subprocess-timeout isolation backstop).

## [2.10.0] - 2026-06-10

### Architecture

- **Rules-as-data**: Detection patterns for secrets, SAST, skill threats, MCP
  security, shared patterns, and runtime dynamism now live in versioned JSON
  rule packs (`data/rulepacks/*.json`, ~545 rules across 6 packs). Each rule
  carries a stable `id`, `type`, `title`, `severity`, `confidence`,
  `explanation`, and embedded `examples` that run as tests on pack load.
  Algorithmic scanners (entropy, AST, DAST, git forensics, integrity, manifest
  drift, binary, lifecycle, dependencies, infra, devcontainer, post-incident,
  dataflow, entrypoint) remain code-driven and are explicitly noted as such.
- **Signed daily rule-pack feed**: New behavioral rules reach installed users
  without a code release. An Ed25519-signed bundle (`iocs/rulepacks.json` +
  `.sig`) is fetched by the existing daily `refresh_threat_dbs.py` pipeline.
  The same signing pipeline now covers `iocs/latest.json` as well, so both
  update channels carry matching trust guarantees. Shipped packs remain
  authoritative when the feed is unavailable, invalid, or tampered; scanning
  always works offline.
- **Vendored Ed25519 verify-only** (`_ed25519.py`): stdlib-only, ~150 lines,
  no external dependencies. Signatures are re-verified on every cache load
  (not only at fetch) to cover the postinstall-malware threat class. Cache
  directory created with mode 0700.
- **Rollback and replay protection**: Feed acceptance requires a strictly
  increasing `pack_version` integer, a `generated` timestamp no older than
  30 days, and a persisted pack-version floor that survives cache clears.
  Signature is verified over exact raw bytes before any decode.

### Confidence Tiers and Verdict Levels

- Findings now carry a `confidence` score alongside `severity`. Four verdict
  tiers shape output and agent routing: **BLOCK** (confidence >= 0.92),
  **WARN** (>= 0.60), **INFO** (>= 0.30), **SUPPRESSED** (< 0.30 or
  user-suppressed). Severity continues to drive exit codes (0/1/2/99)
  unchanged.
- SUPPRESSED findings are excluded from summary counts and exit-code
  computation but remain visible under a top-level `suppressed` key for
  auditability.
- Per-finding suppression via `.forensicsignore` extended with
  `rule:<id>[:<glob>]` syntax. Suppressing a critical-severity rule escalates
  to a CRITICAL suppression-tampering finding; suppressing more than 5 rules
  total escalates to HIGH (mass-suppression guard).

### Benign-Corpus Regression Gate

- New offline FP gate (`tests/test_benign_corpus.py`) runs all scanners
  against a committed corpus of tricky-but-clean content (emoji/ZWJ-rich
  markdown, legitimate `postinstall` scripts, `.env.example`, clean SKILL.md
  files, OAuth docs prose). Any rule change that introduces new false positives
  on the corpus fails pytest before the change can ship. Extended corpus from
  pinned-SHA snapshots is supported for deeper local validation.

### LLM Adjudication

- WARN-tier findings are marked `needs_adjudication`. The auto-scan and
  session-scan outputs emit a self-contained adjudication block (capped at 5
  findings, sorted by confidence descending) with injection-safe formatting:
  every snippet line carries a `> SNIPPET: ` prefix so attacker-controlled
  content cannot escape the data boundary. Metadata (rule id, title,
  explanation, confidence) appears before the snippet so the agent anchors on
  rule context before encountering adversarial text. Verdict vocabulary:
  `confirm` / `downgrade` (reason required) / `escalate`. The agent can only
  annotate or escalate; BLOCK-tier behavior and pre-scan blocking are outside
  the agent's authority.

### Internals

- New `rule_loader.py` module loads, validates, compiles, and self-tests JSON
  rule packs. ReDoS guards (pattern-length cap, nested-quantifier heuristic,
  per-rule self-test timeout) are mandatory. Path resolution is anchored to the
  install directory so a hostile `data/rulepacks/` in the scan target is never
  loaded.
- `Finding` dataclass gains `rule_id` and `confidence`; `aggregate_json.py`
  computes verdict tiers and the `verdicts` summary block. All existing JSON
  schema keys are preserved.

## [2.7.8] - 2026-05-07

### Detection

- Added **Deferred Update Channel** detection (high): catches skills that create
  persistent remote-control channels via "check for updates", "apply procedures
  from [file]", or "run [file] each heartbeat" directives. Filename-gated to
  skill config files only (SKILL.md, ROUTINE.md, HEARTBEAT.md, etc.).
  (Source: Terra Security OpenClaw, May 2026)
- Added **Prose Imperative Exfiltration** detection (medium/high): catches
  natural language instructions like "Send openclaw.json to https://..." that
  an AI agent would follow as commands. Tracks markdown code fences, allowlists
  safe domains, excludes emails. (Source: Terra Security OpenClaw, May 2026)
- Added **Workspace Config Write Request** detection (high): catches skills
  that instruct agents to write to auto-executed config files (HEARTBEAT.md,
  CLAUDE.md, .claude/settings.json, hooks). Documentation-phrasing excluded.
  (Source: Terra Security OpenClaw, May 2026)
- Added **Trusted File Reference Chain** detection (medium/high): BFS from
  seed config files detects A->B->C trust-laundering pipelines. Escalates
  for chains terminating at git-updatable files (CHANGELOG.md, README.md).
  (Source: Terra Security OpenClaw, May 2026)
- Added **Correlation Rule 30: Staged Injection Kill Chain** (critical):
  update-channel + prose-imperative across repo triggers critical alert.
- Added **Correlation Rule 31: Workspace Persistence Setup** (critical):
  config-write-request + update-channel across repo triggers critical alert.
- Rules 30-31 use a new repo-wide correlation pass (not per-file), extending
  the correlation engine for cross-file compound threat detection.

### Fixes

- Fixed unused `field` import in `forensics_core.py`.
- Fixed f-string without placeholders in `forensics_core.py` and
  `scan_agent_skills.py`.
- Fixed multi-import line and ambiguous variable name in `scan_agent_skills.py`.

## [2.7.7] - 2026-05-07

### Detection

- Added **Pipe to Shell Interpreter** detection (critical): catches arbitrary
  input piped to `bash`, `sh`, `zsh`, `ksh`, or `dash`. Previously only
  `curl | bash` was detected. (Fixes #15)
- Added **Nested Command Substitution** detection (high): flags `$(... $(...) ...)`
  patterns commonly used to obfuscate command injection in shell scripts.
  (Fixes #15)

### Fixes

- Fixed `vuln_feed.py` passing unsupported `do_fsync` kwarg to
  `forensics_core.atomic_write_json`.
- Fixed `run_forensics.sh` cleanup trap overwriting the intended exit code,
  causing clean repos to exit 1 instead of 0.
- Aligned `test_session_scan.py` tests with refactored `_scan_directory`,
  `detect_changes`, and `ThreatDBWarning` APIs.

## [2.7.6] - 2026-05-05

### Internals

- Consolidated atomic-write logic into a single `forensics_core.atomic_write_json`
  / `atomic_write_text` helper, called by every cache writer (IOC, KEV, baseline,
  refresh marker). All cache writes now share identical guarantees:
  `O_EXCL` temp file + explicit `fchmod(0o600)` + `fsync` + `os.replace`.
- Explicit `fchmod` after open ensures the `0o600` permission is honored
  regardless of the user's umask.
- Threat-DB freshness warnings are now structured `ThreatDBWarning` records
  (`kind`, `detail`, `remediation`) instead of free-form strings — easier to
  route, suppress, or test.
- Added `forensics_core.import_module_by_path` for loading sibling modules by
  absolute path, with `BaseException` cleanup so signal-handler interrupts can't
  wedge half-imported modules in `sys.modules`.
- `refresh_threat_dbs._resolve_scripts_dir` requires `forensics_core.py` and
  `vuln_feed.py` siblings before accepting a candidate directory — survives
  partial installs cleanly.
- `_write_marker` feature-checks `atomic_write_text` so the daemon stays
  compatible across plugin-cache versions during upgrade transitions.

### Maintenance

- `vuln_feed.py` no longer imports `tempfile` (delegated atomic write).
- `_render_warning` dropped its dead `str` fallback path.
- Removed redundant per-file `do_fsync` knob (always on).

## [2.7.5] - 2026-05-05

### Performance

- **SessionStart hook latency cut from up to 25s → ~540ms** (warm cache).
  - Threat database refresh (IOC + KEV) moved out of the SessionStart hot path
    into a daily background `launchd` job (`com.alexgreenshpun.repo-forensics-refresh`).
    Eliminates up to 20s of network I/O from session start.
  - Baseline scanning now uses an mtime/size/ctime/inode gate to skip re-hashing
    unchanged files. ctime defeats `os.utime()` spoofing.
  - `detect_changes` now returns `(changed, all_entries)` so save path reuses
    fresh entries instead of re-walking the tree (~300 ms shave).

### Security

- `auto_scan.py` now detects `claude plugins install / update / add / enable`
  variants alongside existing pip/npm/git patterns.
- `_save_cache` writes (IOC, KEV, baseline, marker) are now fully atomic:
  `O_EXCL` temp file + `fsync` + `os.replace`, with `0o600` permissions to keep
  threat DB contents private on multi-user systems.
- Install script (`hooks/install_refresh_daemon.sh`) XML-escapes every value
  interpolated into the launchd plist heredoc and rejects paths containing
  newlines, `<`, `>`, `&`, or quote characters. Closes a persistence-RCE class
  via marketplace-controlled cache directory names.
- Install script prefers system Python locations
  (`/usr/bin/python3`, `/opt/homebrew/bin/python3`, `/usr/local/bin/python3`)
  over `command -v python3` to prevent baking a user-PATH-controlled
  interpreter into a persistent launchd job.
- Log sanitizer in `refresh_threat_dbs.py` switched from CR/LF/NUL stripping
  to a printable-ASCII allowlist + tab. Defeats log forging via ANSI escape
  sequences embedded in attacker-controlled feed data.
- v1 → v2 baseline migration uses a sentinel mtime to force re-hashing on the
  first scan. The previous draft paired the old hash with current stat
  metadata, which would have permanently masked any change made between the
  v1 baseline write and the upgrade.
- Baseline migration validates `item_key` paths against currently discovered
  monitored directories, defanging path-traversal in attacker-crafted v1
  baselines.
- SIGALRM handler in `refresh_threat_dbs.py` no longer calls Python I/O
  (was non-async-signal-safe). Writes a fixed bytestring via `os.write` and
  exits via `os._exit`.

### Reliability

- `_kill_stale_scanners` now runs *after* the kill switch check, honoring
  the disable contract.
- New `refresh_threat_dbs.py` daemon: fcntl flock with `O_NOFOLLOW` lock file
  in `~/.cache/repo-forensics/refresh.lock` (not `/tmp`), `socket.setdefaulttimeout(15)`,
  60 s SIGALRM hard cap, 90 s `ExitTimeOut` in plist, `Nice=10` +
  `LowPriorityIO` + `LowPriorityBackgroundIO` + `ProcessType=Background` so
  the kernel deprioritizes the daemon under thermal pressure.
- Marker freshness check uses `os.path.getmtime` instead of reading a
  timestamp from the marker contents, robust against userspace clock jumps
  and DST shifts.
- Module loader uses `importlib.util.spec_from_file_location` with
  canonical module names so internal self-imports stay consistent.
  Catches `BaseException` to clean up `sys.modules` even on
  KeyboardInterrupt / SIGALRM.
- `refresh_threat_dbs.py` exits cleanly on non-Darwin platforms.

### Fixes

- pip `pkg @ url` form no longer leaves trailing whitespace in the parsed
  package name; IOC matches now compare cleanly.
- Magic constants extracted: `CLOCK_SKEW_TOLERANCE_NS`, `STALE_SCANNER_KILL_SEC`.
- Hoisted `import re` out of a per-line loop in `_extract_dependencies`.
- Removed redundant `(ImportError, Exception)` tuple — `Exception` already
  covers `ImportError`.

### Files added

- `skills/repo-forensics/scripts/refresh_threat_dbs.py`
- `hooks/install_refresh_daemon.sh`
- `hooks/uninstall_refresh_daemon.sh`

### Migration

The first session after upgrading rebuilds the local baseline (v1 → v2 schema
with sentinel mtime forcing one full re-hash). Subsequent sessions stay under
1 second.

To install the background refresh daemon (recommended):

```
bash hooks/install_refresh_daemon.sh
```

To remove it:

```
bash hooks/uninstall_refresh_daemon.sh
```

Disable temporarily without uninstalling:

```
export REPO_FORENSICS_DISABLE_REFRESH=1
```

## [2.7.4]
- See git tag `v2.7.4`. CVE-2026-31431 kernel exploit detection: AF_ALG socket,
  AEAD bind, authencesn.

## [2.7.3]
- See git tag `v2.7.3`. Comprehensive Unicode attack detection (anti-trojan-source
  parity).

## [2.7.2]
- See git tag `v2.7.2`. Aligned all manifests.

## [2.7.1]
- See git tag `v2.7.1`. Prevent silent exit on fresh runs, harden shell reliability.

## [2.7.0]
- Checkmarx supply chain intelligence: Command-Jacking, Model Confusion,
  audio steganography, 12 compromised actions.
