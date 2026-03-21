#!/usr/bin/env python3
"""
scan_integrity.py - File Integrity Monitor (v1)
SHA256 baseline checking for critical files (.claude/settings.json,
CLAUDE.md, hook scripts). Detects unauthorized modifications that
could indicate CVE-2025-59536-style attacks.

Inspired by ClawSec's Soul Guardian, adapted to Python-only approach.

Modes:
  --watch    Store baselines on first run, alert on drift on subsequent runs.
             Baselines stored in .forensics-baseline.json in the repo root.
  (default)  Scan-only mode: check for suspicious file properties without
             baseline comparison.

Created by Alex Greenshpun
"""

import os
import sys
import json
import hashlib
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "integrity"

# Critical files that attackers target for persistence/RCE
CRITICAL_FILES = [
    '.claude/settings.json',
    '.claude/settings.local.json',
    'CLAUDE.md',
    '.claude/CLAUDE.md',
    '.mcp.json',
    '.claude/commands',  # directory - check contents
]

# Hook script patterns (files that execute code on Claude Code events)
HOOK_PATTERNS = [
    '.claude/settings.json',  # contains hooks section
]

# Suspicious permission bits
EXECUTABLE_CONFIG_EXTENSIONS = {'.json', '.md', '.toml', '.yml', '.yaml', '.txt'}

BASELINE_FILENAME = '.forensics-baseline.json'


def sha256_file(filepath):
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def find_critical_files(repo_path):
    """Find critical config files and hook scripts in the repo.
    Intentionally scoped to security-critical paths only, not all of .claude/."""
    found = {}

    for rel in CRITICAL_FILES:
        full_path = os.path.join(repo_path, rel)
        if os.path.isfile(full_path):
            found[rel] = full_path
        elif os.path.isdir(full_path):
            # Scan directory contents (e.g., .claude/commands/) - one level only
            try:
                for f in os.listdir(full_path):
                    fp = os.path.join(full_path, f)
                    if os.path.isfile(fp):
                        rp = os.path.relpath(fp, repo_path)
                        found[rp] = fp
            except OSError:
                pass

    # Find hook scripts referenced in settings.json
    settings_path = os.path.join(repo_path, '.claude/settings.json')
    if os.path.exists(settings_path):
        try:
            with open(settings_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for event_name, hook_list in data.get('hooks', {}).items():
                if not isinstance(hook_list, list):
                    continue
                for hook in hook_list:
                    cmd = hook.get('command', '') if isinstance(hook, dict) else ''
                    # Extract script paths from hook commands
                    for token in cmd.split():
                        if token.endswith(('.sh', '.bash', '.py', '.js')):
                            script_path = os.path.join(repo_path, token) if not os.path.isabs(token) else token
                            if os.path.isfile(script_path):
                                rp = os.path.relpath(script_path, repo_path)
                                found[rp] = script_path
        except (json.JSONDecodeError, OSError):
            pass

    return found


def check_hooks_in_settings(filepath, rel_path):
    """Check .claude/settings.json for hooks configuration (CVE-2025-59536 vector)."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            data = json.loads(content)

        if 'hooks' in data:
            hooks = data['hooks']
            for event_name, hook_list in hooks.items():
                if not isinstance(hook_list, list):
                    continue
                for hook in hook_list:
                    cmd = hook.get('command', '') if isinstance(hook, dict) else str(hook)
                    if cmd:
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="high",
                            title=f"Hook registered: {event_name}",
                            description=f"Shell command executes on {event_name} event (verify this is intentional)",
                            file=rel_path, line=0,
                            snippet=cmd[:120],
                            category="hook-configuration"
                        ))
                        # Check for especially dangerous patterns
                        dangerous = ['curl', 'wget', 'bash -c', 'eval', 'base64', '/dev/tcp']
                        for d in dangerous:
                            if d in cmd.lower():
                                findings.append(core.Finding(
                                    scanner=SCANNER_NAME, severity="critical",
                                    title=f"Dangerous command in hook: {event_name}",
                                    description=f"Hook contains '{d}' pattern (potential RCE/exfiltration)",
                                    file=rel_path, line=0,
                                    snippet=cmd[:120],
                                    category="hook-dangerous"
                                ))
                                break

    except (json.JSONDecodeError, OSError, KeyError):
        pass
    return findings


def check_executable_configs(repo_path, critical_files):
    """Flag config/doc files with executable permissions."""
    findings = []
    for rel_path, full_path in critical_files.items():
        ext = os.path.splitext(rel_path)[1].lower()
        if ext in EXECUTABLE_CONFIG_EXTENSIONS:
            try:
                mode = os.stat(full_path).st_mode
                if mode & 0o111:  # any execute bit
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title=f"Executable config file: {rel_path}",
                        description="Configuration/documentation file has execute permission (unusual, may indicate tampering)",
                        file=rel_path, line=0,
                        snippet=f"mode: {oct(mode)}",
                        category="permission-anomaly"
                    ))
            except OSError:
                pass
    return findings


def load_baseline(repo_path):
    """Load existing baseline from .forensics-baseline.json."""
    baseline_path = os.path.join(repo_path, BASELINE_FILENAME)
    if os.path.exists(baseline_path):
        try:
            with open(baseline_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
    return None


def save_baseline(repo_path, baseline_data):
    """Save baseline to .forensics-baseline.json."""
    baseline_path = os.path.join(repo_path, BASELINE_FILENAME)
    baseline_data['_meta'] = {
        'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'tool': 'repo-forensics/scan_integrity',
        'version': 'v1',
    }
    with open(baseline_path, 'w', encoding='utf-8') as f:
        json.dump(baseline_data, f, indent=2)


def watch_mode(repo_path, critical_files):
    """--watch mode: store baselines on first run, detect drift on subsequent runs."""
    findings = []
    existing = load_baseline(repo_path)

    current_hashes = {}
    for rel_path, full_path in critical_files.items():
        h = sha256_file(full_path)
        if h:
            current_hashes[rel_path] = h

    if existing is None:
        # First run: create baseline
        save_baseline(repo_path, {'files': current_hashes})
        print(f"[+] Baseline created: {len(current_hashes)} files tracked in {BASELINE_FILENAME}")
        return findings

    # Subsequent run: compare against baseline
    baseline_files = existing.get('files', {})
    meta = existing.get('_meta', {})
    created = meta.get('created', 'unknown')

    for rel_path, current_hash in current_hashes.items():
        if rel_path in baseline_files:
            if current_hash != baseline_files[rel_path]:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"File modified since baseline: {rel_path}",
                    description=f"SHA256 changed since baseline ({created}). Verify this change was intentional.",
                    file=rel_path, line=0,
                    snippet=f"was: {baseline_files[rel_path][:16]}... now: {current_hash[:16]}...",
                    category="integrity-drift"
                ))
        else:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"New critical file since baseline: {rel_path}",
                description=f"File did not exist when baseline was created ({created})",
                file=rel_path, line=0,
                snippet=f"hash: {current_hash[:32]}...",
                category="integrity-new-file"
            ))

    for rel_path in baseline_files:
        if rel_path not in current_hashes:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"File removed since baseline: {rel_path}",
                description=f"File existed in baseline ({created}) but is now missing",
                file=rel_path, line=0,
                snippet=f"was: {baseline_files[rel_path][:32]}...",
                category="integrity-removed"
            ))

    # Update baseline with current state
    save_baseline(repo_path, {'files': current_hashes})
    print(f"[+] Baseline updated: {len(current_hashes)} files tracked")

    return findings


def main():
    import argparse
    parser = argparse.ArgumentParser(description="repo-forensics: File Integrity Monitor")
    parser.add_argument('repo_path', help="Path to repository to scan")
    parser.add_argument('--format', choices=['text', 'json', 'summary'], default='text',
                        help="Output format (default: text)")
    parser.add_argument('--watch', action='store_true',
                        help="Store baselines and detect drift on subsequent runs")
    args = parser.parse_args()
    repo_path = os.path.abspath(args.repo_path)

    print(f"[*] Scanning file integrity in {repo_path}...")

    critical_files = find_critical_files(repo_path)

    if not critical_files:
        print("[+] No critical configuration files found.")
        return

    print(f"[*] Found {len(critical_files)} critical file(s)")

    all_findings = []

    # Check for hooks in settings.json
    settings_path = os.path.join(repo_path, '.claude/settings.json')
    if os.path.exists(settings_path):
        all_findings.extend(check_hooks_in_settings(
            settings_path,
            '.claude/settings.json'
        ))

    # Check for executable config files
    all_findings.extend(check_executable_configs(repo_path, critical_files))

    # Watch mode: baseline comparison
    if args.watch:
        all_findings.extend(watch_mode(repo_path, critical_files))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
