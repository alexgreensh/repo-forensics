# Changelog

All notable changes to repo-forensics. Versions follow semver.

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
