# Changelog

All notable changes to repo-forensics. Versions follow semver.

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
