#!/usr/bin/env python3
"""
session_scan.py - SessionStart hook handler for repo-forensics v2.
Runs once when Claude Code starts a session. Three steps:

  1. Refresh threat databases if stale (IOC + KEV, once per day)
  2. Detect changes in plugins/skills/MCP servers since last session
  3. Scan changed items against fresh databases

Design constraints:
  - Step 1 makes network calls ONLY if caches are >24h old (once/day).
    Network timeout is 10s per source. Failure = use stale cache.
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
import subprocess
import sys
import time

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

# Baseline location — persisted between sessions
BASELINE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "repo-forensics")
BASELINE_FILE = os.path.join(BASELINE_DIR, "session-baseline.json")
BASELINE_VERSION = 1

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
# Step 1: Refresh threat databases if stale
# ========================================================================

def _is_ioc_cache_stale():
    """Check if IOC cache is older than 24h or missing."""
    try:
        import ioc_manager
        path = ioc_manager._cache_path()
        if not os.path.exists(path):
            return True
        cache = ioc_manager._load_cache()
        return cache is None  # None = stale or missing
    except (ImportError, Exception):
        return True


def _is_kev_cache_stale():
    """Check if KEV cache is older than 24h or missing."""
    try:
        import vuln_feed
        path = vuln_feed._cache_path(vuln_feed.KEV_CACHE_FILENAME)
        if not os.path.exists(path):
            return True
        cached = vuln_feed._load_cache(path, vuln_feed.KEV_CACHE_MAX_AGE_HOURS)
        return cached is None
    except (ImportError, Exception):
        return True


def refresh_threat_databases():
    """Refresh IOC + KEV caches if stale. Returns status messages (may be empty)."""
    messages = []
    ioc_stale = _is_ioc_cache_stale()
    kev_stale = _is_kev_cache_stale()

    if not ioc_stale and not kev_stale:
        return messages

    messages.append("Updating threat databases (daily)...")

    if ioc_stale:
        try:
            import ioc_manager
            ok, msg = ioc_manager.update_iocs()
            if ok:
                messages.append(f"  IOC: {msg}")
        except (ImportError, Exception):
            pass  # Graceful — hardcoded IOCs still work

    if kev_stale:
        try:
            import vuln_feed
            ok, msg = vuln_feed.update_kev_cache()
            if ok:
                messages.append(f"  KEV: {msg}")
        except (ImportError, Exception):
            pass  # Graceful — scanner continues without KEV

    return messages


# ========================================================================
# Step 2: Detect changes since last session
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


def _scan_directory(dirpath, label):
    """Walk a directory and return {relative_path: sha256} for scannable files.
    Returns (checksums_dict, item_name) or (None, None) if dir doesn't exist."""
    if not os.path.isdir(dirpath):
        return None, None
    checksums = {}
    try:
        for root, _dirs, files in os.walk(dirpath):
            for fname in files:
                _, ext = os.path.splitext(fname)
                if ext.lower() not in SCANNABLE_EXTENSIONS:
                    continue
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, dirpath)
                h = _compute_file_hash(full)
                if h:
                    checksums[rel] = h
    except (OSError, PermissionError):
        return None, None
    return checksums, label


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
    """Load the session baseline file. Returns dict or None."""
    if not os.path.isfile(BASELINE_FILE):
        return None
    try:
        with open(BASELINE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        if data.get('version') != BASELINE_VERSION:
            return None
        return data
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def save_baseline(items_checksums):
    """Save baseline to disk. items_checksums: {item_key: {rel_path: hash}}"""
    os.makedirs(BASELINE_DIR, exist_ok=True)
    payload = {
        'version': BASELINE_VERSION,
        '_saved_at': time.time(),
        'items': items_checksums,
    }
    try:
        with open(BASELINE_FILE, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
    except OSError:
        pass  # Non-fatal


def detect_changes(items, baseline):
    """Compare current items against baseline. Returns list of changed items.
    Each changed item: (directory_path, label, item_type, checksums_dict)."""
    changed = []
    baseline_items = baseline.get('items', {}) if baseline else {}

    for dirpath, label, item_type in items:
        checksums, _ = _scan_directory(dirpath, label)
        if checksums is None:
            continue

        item_key = f"{item_type}:{dirpath}"
        old_checksums = baseline_items.get(item_key, {})

        if checksums != old_checksums:
            changed.append((dirpath, label, item_type, checksums))

    return changed


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
    except (ImportError, Exception):
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


def deep_scan_item(dirpath, label, item_type, timeout=None):
    """Run the full run_forensics.sh scanner suite on a changed item.

    This catches zero-day supply chain attacks, obfuscated code, C2 beaconing,
    manifest drift, and other threats that IOC-only checks miss.

    Safe to call from SessionStart hooks (no recursion risk — SessionStart
    fires once, before any tools run).

    Returns list of finding strings (empty = clean). Never raises.
    """
    if not os.path.isfile(RUN_FORENSICS_SCRIPT):
        return []
    if not os.path.isdir(dirpath):
        return []

    effective_timeout = timeout or DEEP_SCAN_TIMEOUT_PER_ITEM
    try:
        result = subprocess.run(
            ["bash", RUN_FORENSICS_SCRIPT, dirpath, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            cwd=dirpath,
        )
    except subprocess.TimeoutExpired:
        return [f"deep scan timed out after {effective_timeout}s (partial results unavailable)"]
    except (OSError, PermissionError):
        return []

    # Exit codes: 0=clean, 1=warnings, 2=critical
    if result.returncode == 0:
        return []

    # Parse JSON output for findings
    findings = []
    try:
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            scanners = data.get('scanners', [])
            if isinstance(scanners, list):
                for scanner in scanners:
                    if not isinstance(scanner, dict):
                        continue
                    sev = scanner.get('severity', '')
                    if sev in ('critical', 'high', 'warning'):
                        scanner_name = scanner.get('name', 'unknown')
                        detail = scanner.get('detail', scanner.get('message', ''))
                        if detail:
                            findings.append(f"[{sev.upper()}] {scanner_name}: {detail}")
    except (json.JSONDecodeError, ValueError):
        # Fallback: use exit code as signal
        if result.returncode == 2:
            findings.append("deep scan found CRITICAL issues (parse failed, check manually)")
        elif result.returncode == 1:
            findings.append("deep scan found warnings (parse failed, check manually)")

    return findings


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
                    import re
                    m = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=><!]+\s*([^\s,;]+)', line)
                    if m:
                        deps.append((m.group(1), m.group(2)))
        except OSError:
            pass

    return deps


# ========================================================================
# Main orchestrator
# ========================================================================

def format_output(refresh_messages, changed_items, scan_results, is_first_run, total_items):
    """Format the SessionStart hook output as additional context."""
    lines = []

    # Refresh messages (only if databases were updated)
    if refresh_messages:
        for msg in refresh_messages:
            lines.append(msg)

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
            if secs > 150:
                try:
                    os.kill(int(pid_str), 15)
                except (ProcessLookupError, PermissionError):
                    pass
    except Exception:
        pass


def main():
    _kill_stale_scanners()

    # Kill switch
    if os.environ.get(ENV_KILL_SWITCH, '').lower() in ('0', 'false', 'no', 'off'):
        output_session_context([])
        return

    # Step 1: Refresh threat databases if stale
    refresh_messages = refresh_threat_databases()

    # Step 2: Discover items and detect changes
    items = discover_items()

    if not items:
        # No plugins/skills/MCP — save empty baseline and exit
        save_baseline({})
        output_session_context(refresh_messages if refresh_messages else [])
        return

    baseline = load_baseline()
    is_first_run = baseline is None

    changed = detect_changes(items, baseline)

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
            ))
            scan_results.setdefault(f"{itype}:{dirpath}", []).extend(deep_findings)

    # Format output
    lines = format_output(
        refresh_messages, scan_items, scan_results,
        is_first_run, len(items)
    )

    # Save baseline BEFORE exit (output_session_context calls sys.exit)
    new_baseline = {}
    for dirpath, label, itype, *rest in items:
        checksums, _ = _scan_directory(dirpath, label)
        if checksums is not None:
            new_baseline[f"{itype}:{dirpath}"] = checksums
    for dirpath, label, itype, checksums in changed:
        new_baseline[f"{itype}:{dirpath}"] = checksums
    save_baseline(new_baseline)

    output_session_context(lines)


def output_session_context(lines):
    """Output SessionStart hook JSON with additional context."""
    if not lines:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart"}}))
        sys.exit(0)

    context = "[repo-forensics] " + "\n".join(lines)
    result = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context
        }
    }
    print(json.dumps(result))
    sys.exit(0)


if __name__ == '__main__':
    main()
