#!/usr/bin/env python3
"""
session_scan.py - SessionStart hook handler for repo-forensics v2.
Runs once when Claude Code starts a session. Three steps:

  1. Check threat database freshness (the hook wrapper schedules refreshes)
  2. Detect changes in plugins/skills/MCP servers since last session
  3. Scan changed items against fresh databases

Design constraints:
  - Step 1 is read-only. Network refresh runs in the background once/day.
  - Steps 2+3 are local-only (zero network calls).
  - Total timeout budget: 15s (set in hooks.json).
  - Silent when nothing changed. User sees output only when relevant.
  - Graceful degradation everywhere: missing dirs, permission errors,
    corrupt baselines, missing modules — all handled, never crash.

Exit convention:
  - Outputs JSON to stdout for SessionStart hook integration.
  - Exit 0 always (SessionStart hooks should never block session).

Created by Alex Greenshpun
"""

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import namedtuple

# Typed warning record for threat-DB freshness checks. Caller pattern-matches
# on `kind` to route by category instead of substring-matching messages.
ThreatDBWarning = namedtuple("ThreatDBWarning", "kind detail remediation")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

import hook_adapter  # noqa: E402  (leaf module, stdlib-only)

# Baseline location — persisted between sessions
BASELINE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "repo-forensics")
BASELINE_FILE = os.path.join(BASELINE_DIR, "session-baseline.json")
BASELINE_VERSION = 2

# Threat DB freshness check (refresh moved to background scheduler/session kick).
# refresh-state.json and refresh.disabled are resolved live inside
# check_threat_db_freshness() from BASELINE_DIR — see the note there.
LAST_RUN_MARKER = os.path.join(BASELINE_DIR, ".last-refresh-v2")
STALE_WARN_DAYS = 7

# Mtime gate: re-hash files whose mtime is more than this far in the future.
# Catches NTP step, restored-from-backup, manual clock changes — anything that
# could let a stale hash silently pair with disk content the gate would
# otherwise treat as unchanged.
CLOCK_SKEW_TOLERANCE_NS = 60 * 1_000_000_000

# Stale scanner reaper: kill orphan scan_*.py processes older than this.
STALE_SCANNER_KILL_SEC = 150

# File extensions we checksum (executable/config files only)
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.mjs', '.cjs', '.sh', '.bash',
    '.json', '.yaml', '.yml', '.toml',
}

# Max items to scan on first run (prevents long hang with many plugins)
FIRST_RUN_SCAN_CAP = 20

# Deep scan: full run_forensics.sh on changed items (catches zero-days)
RUN_FORENSICS_SCRIPT = os.path.join(SCRIPTS_DIR, "run_forensics.sh")
DEEP_SCAN_TIMEOUT_PER_ITEM = 10  # seconds per changed item
DEEP_SCAN_TIMEOUT_TOTAL = 30     # hard cap for all deep scans combined

# Suppress via environment variable
ENV_KILL_SWITCH = "REPO_FORENSICS_SESSION_SCAN"


# ========================================================================
# Step 1: Read-only threat DB freshness check
# (Network-based refresh moved to refresh_threat_dbs.py background job to keep
#  SessionStart latency under 2s.)
# ========================================================================

def check_threat_db_freshness():
    """Read-only check; no network calls. Returns a list of ThreatDBWarning
    records. Uses the marker file's mtime (kernel-managed) instead of reading
    a timestamp from its contents — robust against userspace clock jumps,
    NTP step adjustments, and DST shifts.

    Warning kinds:
      - "stale_marker": daemon ran recently in the past but hasn't refreshed
        in over STALE_WARN_DAYS days.
      - "daemon_missing": IOC or KEV cache exists but no refresh marker —
        the background refresher has not completed successfully.
    """
    warnings = []
    # Derive every path from the live BASELINE_DIR so the freshness check has a
    # single source of truth. Frozen module-level constants would otherwise pin
    # to the real ~/.cache marker even after BASELINE_DIR is repointed (tests,
    # relocated caches), leaking host state into the check.
    ioc_path = os.path.join(BASELINE_DIR, ".forensics-iocs.json")
    kev_path = os.path.join(BASELINE_DIR, "kev.json")
    refresh_disabled_file = os.path.join(BASELINE_DIR, "refresh.disabled")
    refresh_state_file = os.path.join(BASELINE_DIR, "refresh-state.json")

    if os.path.isfile(refresh_disabled_file):
        return [ThreatDBWarning(
            kind="refresh_disabled",
            detail="automatic threat intelligence refresh is disabled",
            remediation="run refresh_controller.py enable",
        )]

    state = {}
    try:
        with open(refresh_state_file, encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            state = loaded
    except (OSError, ValueError):
        pass

    try:
        last_ts = os.path.getmtime(LAST_RUN_MARKER)
        age_days = (time.time() - last_ts) / 86400.0
        failed = [name for name, result in (state.get("feeds") or {}).items()
                  if isinstance(result, dict) and not result.get("ok")]
        if age_days < -(CLOCK_SKEW_TOLERANCE_NS / 1_000_000_000 / 86400):
            warnings.append(ThreatDBWarning(
                kind="future_marker",
                detail="success marker is future-dated",
                remediation="run refresh_controller.py ensure --json",
            ))
        elif age_days > STALE_WARN_DAYS:
            failed_detail = f"; last failed: {', '.join(failed)}" if failed else ""
            warnings.append(ThreatDBWarning(
                kind="stale_marker",
                detail=f"{age_days:.0f} days since last complete verified refresh{failed_detail}",
                remediation="run refresh_controller.py status --json",
            ))
    except OSError:
        # Marker missing — first run, OR daemon never installed.
        if os.path.isfile(ioc_path) or os.path.isfile(kev_path):
            warnings.append(ThreatDBWarning(
                kind="refresh_never_succeeded",
                detail="caches exist but no successful refresh marker found",
                remediation="start a new session or run refresh_controller.py ensure --json",
            ))
    return warnings


# Compatibility alias — callers expect this name
def refresh_threat_databases():
    """Backwards-compat wrapper. Network refresh now runs in the background.
    This is now a fast read-only freshness check (<10ms)."""
    return check_threat_db_freshness()


# ========================================================================
# Step 2: Detect changes since last session
# (Hardened gate: tuple includes mtime_ns + size + ctime_ns + inode.
#  ctime cannot be set by userspace touch; defeats os.utime() spoofing.)
# ========================================================================

def _compute_file_hash(filepath):
    """SHA256 of a single file. Returns None on error."""
    try:
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _scan_directory(dirpath, old_entries=None):
    """Walk dir; reuse cached hash when (mtime_ns, size, ctime_ns, inode) all match.
    Returns {rel_path: [hash, mtime_ns, size, ctime_ns, inode]} or None if
    dirpath doesn't exist."""
    if not os.path.isdir(dirpath):
        return None
    old_entries = old_entries or {}
    entries = {}
    now_ns = time.time_ns()
    try:
        for root, _dirs, files in os.walk(dirpath):
            for fname in files:
                _, ext = os.path.splitext(fname)
                if ext.lower() not in SCANNABLE_EXTENSIONS:
                    continue
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, dirpath)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                mtime_ns = st.st_mtime_ns
                size = st.st_size
                ctime_ns = st.st_ctime_ns
                inode = st.st_ino

                # Future-dated mtime → re-hash (catches NTP step, restore from backup)
                if mtime_ns > now_ns + CLOCK_SKEW_TOLERANCE_NS:
                    h = _compute_file_hash(full)
                    if h:
                        entries[rel] = [h, mtime_ns, size, ctime_ns, inode]
                    continue

                # Reuse cached hash only if ALL four metadata fields match
                old = old_entries.get(rel)
                if (isinstance(old, list) and len(old) == 5
                        and old[1] == mtime_ns and old[2] == size
                        and old[3] == ctime_ns and old[4] == inode):
                    entries[rel] = old
                    continue

                h = _compute_file_hash(full)
                if h:
                    entries[rel] = [h, mtime_ns, size, ctime_ns, inode]
    except OSError:
        return None
    return entries


def discover_items():
    """Find all plugins, skills, and MCP server directories to monitor.
    Returns list of (directory_path, label, item_type) tuples."""
    items = []

    # Plugins: ~/.claude/plugins/cache/
    plugin_cache = os.path.join(os.path.expanduser("~"), ".claude", "plugins", "cache")
    if os.path.isdir(plugin_cache):
        try:
            for entry in os.listdir(plugin_cache):
                full = os.path.join(plugin_cache, entry)
                if os.path.isdir(full) and not entry.startswith('.'):
                    items.append((full, entry, "plugin"))
        except (OSError, PermissionError):
            pass

    # Skills: ~/.claude/commands/
    skills_dir = os.path.join(os.path.expanduser("~"), ".claude", "commands")
    if os.path.isdir(skills_dir):
        try:
            for entry in os.listdir(skills_dir):
                full = os.path.join(skills_dir, entry)
                if os.path.isdir(full) and not entry.startswith('.'):
                    items.append((full, entry, "skill"))
        except (OSError, PermissionError):
            pass

    # Project-level skills: .claude/commands/ (relative to cwd)
    cwd = os.getcwd()
    project_skills = os.path.join(cwd, ".claude", "commands")
    if os.path.isdir(project_skills) and project_skills != skills_dir:
        try:
            for entry in os.listdir(project_skills):
                full = os.path.join(project_skills, entry)
                if os.path.isdir(full) and not entry.startswith('.'):
                    items.append((full, f"{entry} (project)", "skill"))
        except (OSError, PermissionError):
            pass

    # MCP servers: check settings files for configured servers
    # MCP servers are binaries/scripts referenced in settings — we check
    # their configured paths if they're local directories
    for settings_path in [
        os.path.join(os.path.expanduser("~"), ".claude", "settings.json"),
        os.path.join(cwd, ".claude", "settings.local.json"),
    ]:
        mcp_dirs = _extract_mcp_dirs(settings_path)
        for mcp_dir, name in mcp_dirs:
            items.append((mcp_dir, name, "MCP"))

    return items


def _extract_mcp_dirs(settings_path):
    """Extract local MCP server directories from a settings file."""
    results = []
    if not os.path.isfile(settings_path):
        return results
    try:
        with open(settings_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return results

    mcp_servers = data.get('mcpServers', {})
    if not isinstance(mcp_servers, dict):
        return results

    for name, config in mcp_servers.items():
        if not isinstance(config, dict):
            continue
        args = config.get('args', [])
        if not isinstance(args, list):
            continue

        # Look for local paths in args (e.g., "node /path/to/server/index.js")
        for arg in args:
            if not isinstance(arg, str):
                continue
            if os.path.isabs(arg) and os.path.exists(arg):
                parent = os.path.dirname(arg) if os.path.isfile(arg) else arg
                if os.path.isdir(parent):
                    results.append((parent, name))
                    break  # One dir per MCP server
    return results


def load_baseline():
    """Load the session baseline file. Returns dict or None.
    Auto-migrates v1 baselines (hash-only) to v2 (hash+stat tuple) by stat'ing
    files on disk — preserves coverage without forcing full re-hash."""
    if not os.path.isfile(BASELINE_FILE):
        return None
    try:
        with open(BASELINE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None

        ver = data.get('version')
        if ver == BASELINE_VERSION:
            return data
        if ver == 1:
            # Migrate {path: hash_str} → {path: [hash, MIGRATE_SENTINEL, ...]}
            #
            # CRITICAL: do NOT pair the old hash with current stat metadata.
            # If the file was modified between the v1 baseline write and now
            # (the upgrade window may be days/weeks), pairing old_hash with
            # fresh mtime/size/ctime/inode would suppress re-hashing forever
            # (the gate would reuse old_hash because metadata "matches").
            # Instead, write a sentinel that can never match on disk so the
            # gate falls through to recompute on the very next _scan_directory.
            # The migration's only value is preserving the OLD hash for change
            # comparison — fresh stats get written naturally on first re-hash.
            SENTINEL_MTIME = -1
            migrated_items = {}
            # Build allowlist of valid base_dirs from current discovery to
            # defang path-traversal in attacker-crafted item_key entries.
            current_items = discover_items()
            valid_dirs = {dirpath for dirpath, _, _ in current_items}
            for item_key, file_map in data.get('items', {}).items():
                if not isinstance(file_map, dict):
                    continue
                parts = item_key.split(":", 1)
                if len(parts) != 2:
                    continue
                base_dir = parts[1]
                # Containment check: base_dir must be a known monitored dir.
                if base_dir not in valid_dirs:
                    continue
                new_map = {}
                for rel_path, old_hash in file_map.items():
                    if not isinstance(old_hash, str):
                        continue
                    if not isinstance(rel_path, str) or '..' in rel_path.split(os.sep):
                        continue
                    new_map[rel_path] = [old_hash, SENTINEL_MTIME, -1, -1, -1]
                migrated_items[item_key] = new_map
            data['version'] = BASELINE_VERSION
            data['items'] = migrated_items
            return data
        return None
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def save_baseline(items_checksums):
    """Save baseline atomically. Delegates to forensics_core for the shared
    atomic-write implementation. Non-fatal on failure: a stale baseline is
    safer than no baseline (a missing baseline silently triggers first-run
    cap, capping coverage)."""
    payload = {
        'version': BASELINE_VERSION,
        '_saved_at': time.time(),
        'items': items_checksums,
    }
    try:
        import forensics_core
        forensics_core.atomic_write_json(BASELINE_FILE, payload, mode=0o600)
    except OSError:
        return  # Non-fatal: keep prior baseline if disk is full / read-only.


def detect_changes(items, baseline):
    """Compare current items against baseline. Returns (changed_list, all_entries_dict).
    - changed_list entries: (directory_path, label, item_type, entries_dict)
    - all_entries_dict: {item_key: entries_dict} for every successfully scanned item.
    Entries are [hash, mtime_ns, size, ctime_ns, inode].

    Returning all_entries lets the save path snapshot the dict directly without
    re-walking — eliminates the second O(stat) traversal across the full tree."""
    changed = []
    all_entries = {}
    baseline_items = baseline.get('items', {}) if baseline else {}

    for dirpath, label, item_type in items:
        item_key = f"{item_type}:{dirpath}"
        old_entries = baseline_items.get(item_key, {})
        entries = _scan_directory(dirpath, old_entries=old_entries)
        if entries is None:
            continue
        all_entries[item_key] = entries

        # Compare hashes only (position 0); ignore metadata for change detection.
        old_hashes = {k: v[0] for k, v in old_entries.items() if isinstance(v, list)}
        new_hashes = {k: v[0] for k, v in entries.items()}

        if new_hashes != old_hashes:
            changed.append((dirpath, label, item_type, entries))

    return changed, all_entries


# ========================================================================
# Step 3: Scan changed items against threat databases
# ========================================================================

def scan_item(dirpath, label, item_type, checksums):
    """Scan a single changed item against IOC + compromised versions databases.
    Returns list of finding strings (empty = clean)."""
    findings = []

    # Load IOC database
    try:
        import ioc_manager
        iocs = ioc_manager.get_iocs()
    except (ImportError, OSError, AttributeError):
        iocs = None

    # Check for known-malicious package names
    if iocs:
        all_malicious = (iocs.get('malicious_npm', set()) |
                         iocs.get('malicious_pypi', set()))
        name_lower = label.lower().split('@')[0].split('/')[-1]
        if name_lower in all_malicious:
            findings.append("matches known malicious package name in IOC database")

    # Check plugin.json / package.json for version info
    version_info = _extract_version_info(dirpath)
    if version_info and iocs:
        pkg_name = version_info.get('name', '').lower()
        pkg_version = version_info.get('version', '')
        compromised = iocs.get('compromised_versions', {})
        if pkg_name in compromised and pkg_version in compromised[pkg_name]:
            campaign = compromised[pkg_name][pkg_version]
            findings.append(
                f"v{pkg_version} matches known compromised version "
                f"(campaign: {campaign})"
            )

    # Check dependencies for known compromised versions
    deps = _extract_dependencies(dirpath)
    if deps and iocs:
        compromised = iocs.get('compromised_versions', {})
        all_malicious_names = (iocs.get('malicious_npm', set()) |
                               iocs.get('malicious_pypi', set()))
        for dep_name, dep_version in deps:
            dep_lower = dep_name.lower()
            if dep_lower in all_malicious_names:
                findings.append(
                    f"dependency '{dep_name}' matches known malicious package"
                )
            if dep_lower in compromised and dep_version in compromised[dep_lower]:
                campaign = compromised[dep_lower][dep_version]
                findings.append(
                    f"dependency '{dep_name}' v{dep_version} is a known "
                    f"compromised version (campaign: {campaign})"
                )

    return findings


# Per-field caps for a rendered finding line. The session report is echoed
# into the agent's context, so length is bounded per field as well as per
# line. All three are the caps this codebase already applies to the same
# fields: title and description in aggregate_json.format_report_as_text() and
# adjudication.build_adjudication_block(), the path in the latter -- the text
# formatter is the odd one out and does not sanitize its path at all.
DEEP_FINDING_TITLE_MAX = 160
DEEP_FINDING_DESC_MAX = 300
DEEP_FINDING_PATH_MAX = 160

# The aggregator's severity vocabulary, mirrored rather than imported:
# session_scan is a SessionStart hook on a 15s budget and deliberately imports
# no heavy scanner module. TestDeepScanFindingsReachTheSession pins this tuple
# against aggregate_json.SEVERITY_ORDER so the mirror cannot drift -- its
# members and, since the reader sorts by position in it, its order.
DEEP_FINDING_SEVERITIES = ("critical", "high", "medium", "low")

# Severities worth a line at session start. `low` is deliberately excluded: it
# is an informational note, and a note that turns every plugin update into a
# warning line trains the reader to skip the report. A skipped report is not
# read as "nothing was said" but as "nothing was found" -- the same false-clean
# a nonzero scan reporting nothing would be.
#
# A severity the vocabulary does not contain is NOT below this floor -- see
# _is_above_report_floor(), which explains why.
DEEP_FINDING_REPORT_FLOOR = ("critical", "high", "medium")

# Finding lines one changed item may occupy, before the overflow line. This
# return value is echoed into the agent's session context, so an uncapped
# report from one finding-heavy item pushes the rest of the session out of the
# window. The cap is lossy by construction, which is why _format_overflow_line()
# exists: a capped report that did not say so would read as a complete one.
DEEP_FINDING_MAX_LINES = 5


def _snippet_sanitizer():
    """Return the sanitizer used for finding-derived text.

    Same lazy import and same stdlib fallback aggregate_json.format_report_as_text()
    uses for the same fields, so there is one neutralization behaviour in this
    codebase rather than two that can drift. The fallback's character ranges are
    that formatter's, written as escapes: C0/C1 controls plus the BIDI
    overrides (U+202A-U+202E) and isolates (U+2066-U+2069).
    """
    try:
        import adjudication as _adj
        return _adj.sanitize_snippet
    except ImportError:
        import re as _re

        def _sanitize(text, max_len=300):
            if not isinstance(text, str):
                return ""
            cleaned = _re.sub(
                "[\x00-\x1f\x7f\x80-\x9f\u202a-\u202e\u2066-\u2069]", "", text
            )
            cleaned = _re.sub(r"\s+", " ", cleaned).strip()
            return cleaned[:max_len]

        return _sanitize


def _format_finding_location(item, sanitize):
    """`file:line` for a finding, or `file` when the scanner gave no line."""
    path = sanitize(item.get("file") or "", max_len=DEEP_FINDING_PATH_MAX)
    if not path:
        return "location unknown"
    try:
        line_no = int(item.get("line") or 0)
    except (TypeError, ValueError):
        line_no = 0
    return f"{path}:{line_no}" if line_no > 0 else path


def _format_finding_severity(item):
    """The finding's severity tag, or `UNKNOWN` for anything off-vocabulary.

    Checked against the vocabulary rather than sanitized. Nothing downstream
    validates this field -- load_scanner_results() copies each scanner's JSON
    through verbatim -- so a scanned repository controls it exactly as it
    controls the title, and a severity of "high\n[CRITICAL] ..." would forge a
    top-level line. Sanitizing would neutralize that; refusing the value
    outright also refuses to show the reader a severity the aggregator cannot
    rank, which is the more honest failure.
    """
    severity = item.get("severity")
    if isinstance(severity, str) and severity.lower() in DEEP_FINDING_SEVERITIES:
        return severity.upper()
    return "UNKNOWN"


def _severity_rank(item):
    """Sort key for a finding: 0 is worst.

    Position in DEEP_FINDING_SEVERITIES, which is the aggregator's ranking
    mirrored worst-first. Anything off the vocabulary ranks after every known
    severity, so an unrankable value cannot be used to claim the top of a
    capped report.
    """
    severity = item.get("severity")
    if isinstance(severity, str):
        try:
            return DEEP_FINDING_SEVERITIES.index(severity.lower())
        except ValueError:
            pass
    return len(DEEP_FINDING_SEVERITIES)


def _is_above_report_floor(item):
    """Is this finding worth one of the session report's lines?

    A recognized severity is tested against DEEP_FINDING_REPORT_FLOOR. An
    unrecognized one is reported instead of dropped, and that asymmetry is
    deliberate: this field is attacker-controlled -- load_scanner_results()
    copies each scanner's JSON through verbatim -- so a floor that swallowed
    off-vocabulary severities would hand a scanned repository a one-word way
    to suppress its own worst finding, trading the false-clean this reader
    exists to remove for a narrower one. It renders `UNKNOWN` and sorts below
    every ranked finding, so it can neither hide nor crowd one out.
    """
    severity = item.get("severity")
    if isinstance(severity, str) and severity.lower() in DEEP_FINDING_SEVERITIES:
        return severity.lower() in DEEP_FINDING_REPORT_FLOOR
    return True


def _format_finding_line(item, sanitize):
    """One display line: severity, what was found, where, and why it matters."""
    title = sanitize(item.get("title") or "", max_len=DEEP_FINDING_TITLE_MAX)
    description = sanitize(item.get("description") or "", max_len=DEEP_FINDING_DESC_MAX)
    line = (
        f"[{_format_finding_severity(item)}] {title or 'untitled finding'} "
        f"({_format_finding_location(item, sanitize)})"
    )
    if description:
        line += f" - {description}"
    return line


def _format_overflow_line(hidden):
    """The one line a capped report owes the reader.

    Truncation is silent unless it says so, and a silent truncation is the
    same defect class as the false-clean above it: a report that showed five
    of nine findings and looked exactly like a report that found five. The
    count and the per-severity breakdown are what make the difference visible
    without adding another line per hidden finding.

    Carries no attacker-controlled text -- only integers and severity tags
    already checked against the vocabulary -- and deliberately does not start
    with `[`, so it cannot be mistaken for one more finding line.
    """
    counts = {}
    for item in sorted(hidden, key=_severity_rank):
        tag = _format_finding_severity(item)
        counts[tag] = counts.get(tag, 0) + 1
    breakdown = ", ".join(f"{count} {tag}" for tag, count in counts.items())
    noun = "finding" if len(hidden) == 1 else "findings"
    return f"... and {len(hidden)} more {noun} not shown ({breakdown})"


def _format_uncleared_scan_line(returncode):
    """The one line a scan owes the reader when it rendered nothing.

    Reached only past the early returns for exit 0 and for a signal death, so
    the scan ended nonzero and the reader still produced nothing: the report
    was unparseable at a code deep_scan_item()'s own fallbacks do not cover,
    or every finding in it sat below DEEP_FINDING_REPORT_FLOOR, or its shape
    was not one this reader knows. All three are problems inside the tool,
    and the owner cannot tell them apart from here -- but reporting the item
    `clean` would tell them the one thing that is certainly false.

    The exit code is in the line because it is the only handle the owner has
    on which of those happened: 99 is an infrastructure failure, 1 and 2 are
    findings the reader could not render. Carries no attacker-controlled text
    -- an integer from waitpid and nothing else -- and deliberately does not
    start with `[`, so it cannot be mistaken for a finding line.
    """
    return (
        f"deep scan exited {returncode} with no reportable finding "
        f"(not cleared; will be re-reported next session)"
    )


def report_findings(report):
    """The report's finding list, or empty for anything that is not one.

    Both readers of `report["findings"]` go through here, and the type checks
    are load-bearing rather than defensive habit: the report is parsed from a
    scanner's stdout, so any field can be any JSON type, and `for item in 5`
    raises a TypeError that deep_scan_item()'s
    `except (json.JSONDecodeError, ValueError)` does not catch -- breaking its
    documented promise never to raise, and taking the SessionStart hook with
    it.
    """
    if not isinstance(report, dict):
        return []
    items = report.get("findings")
    if not isinstance(items, (list, tuple)):
        return []
    return [item for item in items if isinstance(item, dict)]


def summarize_deep_findings(report):
    """Render a parsed aggregate report's findings as session display lines.

    Severity is read from each finding, because that is the only place the
    aggregator puts one. An entry of `report["scanners"]` carries exactly
    `name`, `exit_code`, `parse_error`, `finding_count`, `findings`, plus
    `stderr` when present -- never a severity. A reader that looked for one
    there collected nothing and printed `clean` over a scan that exited 2 on a
    CRITICAL finding, which is the defect this function exists to fix.

    Every rendered field originates in the scanned tree and this return value
    is echoed into the agent's session context, so none of it is rendered as
    it arrived: free text is sanitized, and the severity -- which is not free
    text but a four-word vocabulary -- is checked against it. That is a
    condition of the repair, not a refinement of it: reporting the findings
    without neutralizing them would trade a false-clean for an injection path
    into SessionStart.

    What reaches the reader is then bounded twice: DEEP_FINDING_REPORT_FLOOR
    drops the notes, and DEEP_FINDING_MAX_LINES bounds how many lines one item
    can occupy -- see each constant, which explains why it is there. Sorting
    happens here rather than being taken from the report: the aggregator does
    sort worst-first, but the report is a scanner's stdout and this is the last
    thing between it and the user, so truncating on a trusted order would let a
    producer decide which finding the owner never sees. The sort is stable, so
    findings of one severity keep the order they arrived in.

    Nothing here spawns a subprocess or reads the scanned tree, so the
    rendering can be exercised without one; deep_scan_item() owns the
    subprocess and hands the parsed report in.
    """
    sanitize = _snippet_sanitizer()
    items = [item for item in report_findings(report) if _is_above_report_floor(item)]
    items.sort(key=_severity_rank)
    shown, hidden = items[:DEEP_FINDING_MAX_LINES], items[DEEP_FINDING_MAX_LINES:]
    lines = [_format_finding_line(item, sanitize) for item in shown]
    if hidden:
        lines.append(_format_overflow_line(hidden))
    return lines


def deep_scan_item(dirpath, label, item_type, timeout=None, adjudication_sink=None,
                   uncleared_sink=None):
    """Run the full run_forensics.sh scanner suite on a changed item.

    On POSIX, uses start_new_session=True so the entire process tree
    (bash + all backgrounded scanner children) shares a process group.
    On timeout, os.killpg kills the whole group, preventing orphaned
    scanner zombies. Windows lacks os.getpgid/os.killpg, so it falls
    back to killing the direct subprocess.

    Returns list of finding strings. Never raises. A scan that actually ran
    and ended nonzero never returns an empty list: if it renders no finding it
    returns one line naming its exit code rather than going quiet, and appends
    the item's baseline key to *uncleared_sink* so main() can keep it out of
    the baseline. The early returns above -- no scanner script, no such
    directory, no time budget left, an OSError launching it -- still return []
    and leave the sink untouched.
    """
    if not os.path.isfile(RUN_FORENSICS_SCRIPT):
        return []
    if not os.path.isdir(dirpath):
        return []

    effective_timeout = timeout if timeout is not None else DEEP_SCAN_TIMEOUT_PER_ITEM
    if effective_timeout <= 0:
        return []

    proc = None
    pgid = None
    stdout = ""
    try:
        proc = subprocess.Popen(
            ["bash", RUN_FORENSICS_SCRIPT, dirpath, "--format", "json"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=dirpath,
            start_new_session=True,
        )
        pgid = _get_process_group_id(proc)
        stdout, _ = proc.communicate(timeout=effective_timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(pgid, proc)
        return [f"deep scan timed out after {effective_timeout}s (partial results unavailable)"]
    except OSError:
        if proc is not None:
            _kill_process_group(pgid, proc)
        return []
    finally:
        if proc is not None and proc.stdout and not proc.stdout.closed:
            proc.stdout.close()

    if proc.returncode == 0:
        return []
    if proc.returncode < 0:
        return [f"deep scan killed by signal {-proc.returncode}"]

    findings = []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            findings.extend(summarize_deep_findings(data))
            # Collect WARN-tier findings flagged for adjudication (U8). These
            # carry needs_adjudication=true from aggregate_json; they feed the
            # injection-safe adjudication block built once in main().
            if adjudication_sink is not None:
                for finding in report_findings(data):
                    if finding.get('needs_adjudication') is True:
                        adjudication_sink.append(finding)
    except (json.JSONDecodeError, ValueError):
        if proc.returncode == 2:
            findings.append("deep scan found CRITICAL issues (parse failed, check manually)")
        elif proc.returncode == 1:
            findings.append("deep scan found warnings (parse failed, check manually)")

    if not findings:
        # Silence is not an available answer past this point -- see
        # _format_uncleared_scan_line(). The item is reported uncleared as
        # well as spoken about, because a false-clean that gets baselined is
        # not one missed report, it is every future one.
        if uncleared_sink is not None:
            uncleared_sink.append(f"{item_type}:{dirpath}")
        findings.append(_format_uncleared_scan_line(proc.returncode))

    return findings


def _get_process_group_id(proc):
    """Return POSIX process group id for a subprocess, or None on Windows."""
    getpgid = getattr(os, 'getpgid', None)
    if proc is None or getpgid is None:
        return None
    try:
        return getpgid(proc.pid)
    except OSError:
        return None


def _kill_process_group(pgid, proc):
    """Terminate a POSIX process group, or fall back to the direct process."""
    killpg = getattr(os, 'killpg', None)
    sigterm = getattr(signal, 'SIGTERM', None)
    sigkill = getattr(signal, 'SIGKILL', None)
    if pgid and killpg is not None:
        try:
            if sigterm is not None:
                killpg(pgid, sigterm)
        except OSError:
            pass
        if proc is not None:
            try:
                proc.wait(timeout=1)
                return
            except (subprocess.TimeoutExpired, OSError):
                pass
        try:
            if sigkill is not None:
                killpg(pgid, sigkill)
        except OSError:
            pass
    if proc is not None:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except (subprocess.TimeoutExpired, OSError):
            pass


def _extract_version_info(dirpath):
    """Extract name + version from plugin.json or package.json."""
    for fname in ('plugin.json', 'package.json', 'manifest.json'):
        fpath = os.path.join(dirpath, fname)
        if os.path.isfile(fpath):
            try:
                with open(fpath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict) and 'name' in data:
                    return {
                        'name': str(data.get('name', '')),
                        'version': str(data.get('version', '')),
                    }
            except (OSError, json.JSONDecodeError):
                continue
    return None


def _extract_dependencies(dirpath):
    """Extract dependency name+version pairs from package.json / requirements.txt.
    Returns list of (name, version) tuples."""
    deps = []

    # package.json dependencies
    pkg_json = os.path.join(dirpath, 'package.json')
    if os.path.isfile(pkg_json):
        try:
            with open(pkg_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                for dep_key in ('dependencies', 'devDependencies'):
                    dep_dict = data.get(dep_key, {})
                    if isinstance(dep_dict, dict):
                        for name, ver in dep_dict.items():
                            if isinstance(name, str) and isinstance(ver, str):
                                # Strip semver range chars: ^1.2.3 -> 1.2.3
                                clean_ver = ver.lstrip('^~>=<! ')
                                deps.append((name, clean_ver))
        except (OSError, json.JSONDecodeError):
            pass

    # requirements.txt
    req_txt = os.path.join(dirpath, 'requirements.txt')
    if os.path.isfile(req_txt):
        try:
            with open(req_txt, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # Parse: package==1.2.3 or package>=1.2.3
                    m = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=><!]+\s*([^\s,;]+)', line)
                    if m:
                        deps.append((m.group(1), m.group(2)))
        except OSError:
            pass

    return deps


# ========================================================================
# Main orchestrator
# ========================================================================

def _render_warning(w):
    """Render a ThreatDBWarning into a single user-facing line."""
    if w.kind == "stale_marker":
        return f"Threat intelligence is stale: {w.detail}. Check: {w.remediation}"
    if w.kind in ("daemon_missing", "refresh_never_succeeded"):
        return f"Threat refresh has never completed ({w.detail}). Repair: {w.remediation}"
    if w.kind == "future_marker":
        return f"Threat refresh clock skew detected ({w.detail}). Repair: {w.remediation}"
    if w.kind == "refresh_disabled":
        return f"Threat refresh disabled ({w.detail}). Re-enable: {w.remediation}"
    return f"{w.kind}: {w.detail}"


def format_output(refresh_messages, changed_items, scan_results, is_first_run, total_items):
    """Format the SessionStart hook output as additional context."""
    lines = []

    # Refresh warnings (typed records or legacy strings)
    if refresh_messages:
        for msg in refresh_messages:
            lines.append(_render_warning(msg))

    # First run message
    if is_first_run:
        if total_items > 0:
            lines.append(
                f"First security baseline created. "
                f"{min(total_items, FIRST_RUN_SCAN_CAP)}/{total_items} "
                f"plugins/skills/MCP items scanned."
            )
        else:
            lines.append("First security baseline created. No plugins/skills/MCP found.")

    # Changed items + scan results
    if changed_items and not is_first_run:
        item_labels = [f"{label} ({itype})" for _, label, itype, _ in changed_items]
        lines.append(f"Updates detected: {', '.join(item_labels)}")

    has_threats = False
    for dirpath, label, itype, checksums in changed_items:
        findings = scan_results.get(f"{itype}:{dirpath}", [])
        if findings:
            has_threats = True
            for finding in findings:
                lines.append(f"  ⚠️  {label} ({itype}): {finding}")
        elif not is_first_run:
            lines.append(f"  ✓ {label} — clean")

    if changed_items and not has_threats and not is_first_run:
        lines.append("Security check passed ✓")

    if is_first_run and total_items > FIRST_RUN_SCAN_CAP:
        lines.append(
            f"  Note: {total_items - FIRST_RUN_SCAN_CAP} items not scanned. "
            f"Run full scan with: repo-forensics --scan-plugins"
        )

    return lines


def _kill_stale_scanners():
    """Kill orphaned repo-forensics scanner processes from previous runs."""
    try:
        result = subprocess.run(
            ["ps", "ax", "-o", "pid=,etime=,command="],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "repo-forensics/" not in line or "scan_" not in line or ".py" not in line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            pid_str, etime = parts[0], parts[1]
            # Parse etime: [[dd-]hh:]mm:ss
            segments = etime.replace("-", ":").split(":")
            secs = 0
            for i, seg in enumerate(reversed(segments)):
                secs += int(seg) * (60 ** min(i, 2)) * (24 if i == 3 else 1)
            if secs > STALE_SCANNER_KILL_SEC:
                try:
                    os.kill(int(pid_str), 15)
                except (ProcessLookupError, PermissionError):
                    pass
    except Exception:
        pass


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    adapter, adapter_error = hook_adapter.normalize_adapter(
        hook_adapter.adapter_from_argv(argv))
    if adapter_error:
        print(f"[repo-forensics] WARNING: {adapter_error}; falling back to "
              f"'{hook_adapter.ADAPTER_CLAUDE}'", file=sys.stderr)

    # Kill switch FIRST — disabled means truly disabled, no side effects.
    if os.environ.get(ENV_KILL_SWITCH, '').lower() in ('0', 'false', 'no', 'off'):
        output_session_context([], adapter=adapter)
        return

    # Reap orphaned scanner processes from prior crashed sessions.
    _kill_stale_scanners()

    # Step 1: Refresh threat databases if stale
    refresh_messages = refresh_threat_databases()

    # Step 2: Discover items and detect changes
    items = discover_items()

    if not items:
        # No plugins/skills/MCP — save empty baseline and exit
        save_baseline({})
        output_session_context(refresh_messages if refresh_messages else [], adapter=adapter)
        return

    baseline = load_baseline()
    is_first_run = baseline is None

    changed, all_entries = detect_changes(items, baseline)

    # Cap first run scans
    scan_items = changed
    if is_first_run and len(changed) > FIRST_RUN_SCAN_CAP:
        scan_items = changed[:FIRST_RUN_SCAN_CAP]

    # Step 3a: Fast scan — IOC + compromised versions (milliseconds)
    scan_results = {}
    for dirpath, label, itype, checksums in scan_items:
        findings = scan_item(dirpath, label, itype, checksums)
        scan_results[f"{itype}:{dirpath}"] = findings

    # Step 3b: Deep scan — full 18-scanner suite on changed items (seconds)
    # Catches zero-day supply chain attacks, obfuscated code, C2 beaconing,
    # manifest drift — threats that IOC-only checks miss.
    # Only runs when items actually changed (rare). Skipped on first run
    # (too many items) and when run_forensics.sh is missing.
    adjudication_findings = []
    uncleared_items = []
    if scan_items and not is_first_run and os.path.isfile(RUN_FORENSICS_SCRIPT):
        deep_start = time.monotonic()
        for dirpath, label, itype, checksums in scan_items:
            elapsed = time.monotonic() - deep_start
            remaining = DEEP_SCAN_TIMEOUT_TOTAL - elapsed
            if remaining < 2:
                scan_results.setdefault(f"{itype}:{dirpath}", []).append(
                    "deep scan skipped (total timeout budget exhausted)"
                )
                break
            deep_findings = deep_scan_item(dirpath, label, itype, timeout=min(
                DEEP_SCAN_TIMEOUT_PER_ITEM, remaining
            ), adjudication_sink=adjudication_findings,
                uncleared_sink=uncleared_items)
            scan_results.setdefault(f"{itype}:{dirpath}", []).extend(deep_findings)

    # Format output
    lines = format_output(
        refresh_messages, scan_items, scan_results,
        is_first_run, len(items)
    )

    # Adjudication block (U8): append the injection-safe WARN-tier block after
    # the status lines, mirroring the auto_scan / run_forensics text paths. The
    # WARN findings were collected from each deep scan's aggregate JSON. Empty
    # on a clean scan, so a clean session emits no block.
    if adjudication_findings:
        try:
            import adjudication
            block = adjudication.build_adjudication_block(adjudication_findings)
            if block:
                lines.append(block)
        except ImportError:
            pass

    # Save baseline before exit (output_session_context calls sys.exit).
    # detect_changes already produced fresh entries for every item; reuse them
    # directly instead of re-walking the tree. Avoids ~150-300ms of redundant
    # stat syscalls on warm sessions.
    #
    # An item whose deep scan ended nonzero and rendered nothing was never
    # cleared, so it is dropped from the snapshot rather than written into it.
    # Baselining it would silence the same result at every future session
    # start -- detect_changes() reports only items whose hashes moved -- which
    # turns one failure the owner could act on into a permanent one they never
    # see again. Dropping the key costs that item its incremental-hash cache
    # on the next run and nothing else.
    for item_key in uncleared_items:
        all_entries.pop(item_key, None)
    save_baseline(all_entries)

    output_session_context(lines, adapter=adapter)


def output_session_context(lines, adapter=hook_adapter.ADAPTER_CLAUDE):
    """Emit the session report in *adapter*'s output shape.

    Claude Code / Codex / OpenClaw surface plain text from a SessionStart hook,
    which is what has always been printed here. Cursor takes the same text as
    `additional_context` (PRD v3 R4) -- a session report is context for the
    agent, not a verdict on anything, so it deliberately does NOT ride in the
    permission triple the shell hooks use.
    """
    text = ("[repo-forensics] " + "\n".join(lines)) if lines else ""
    sys.exit(hook_adapter.emit_session_context(adapter, text))


if __name__ == '__main__':
    main()
