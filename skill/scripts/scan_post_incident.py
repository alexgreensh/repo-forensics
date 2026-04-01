#!/usr/bin/env python3
"""
scan_post_incident.py - Post-Incident Artifact Scanner
Detects traces of supply chain attacks that survive dropper self-cleanup.
Checks npm cache, install logs, node_modules artifacts, host IOCs, and persistence.

Created by Alex Greenshpun
"""

import os
import re
import sys
import glob

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "post_incident"

# Known malicious packages whose directory presence indicates compromise
MALICIOUS_PACKAGES = {
    "plain-crypto-js": "Axios supply chain RAT dropper (March 2026)",
    "claud-code": "SANDWORM_MODE campaign",
    "cloude-code": "SANDWORM_MODE campaign",
    "mcp-cliient": "SANDWORM_MODE campaign",
    "mcp-serever": "SANDWORM_MODE campaign",
}

# Known RAT binary paths (per platform)
RAT_BINARY_PATHS = [
    "/Library/Caches/com.apple.act.mond",              # macOS axios RAT
    os.path.expandvars("%PROGRAMDATA%/wt.exe"),         # Windows axios RAT
]

# C2 domains/IPs to check in npm logs
C2_INDICATORS = [
    "sfrclak.com",
    "142.11.206.73",
]

# Compromised versions (version in lockfile vs tampered package.json)
VERSION_MISMATCHES = {
    "plain-crypto-js": {"real": "4.2.1", "tampered": "4.2.0"},
}


def scan_node_modules(repo_path):
    """Check for known malicious package directories in node_modules."""
    findings = []
    for root, dirs, _files in os.walk(repo_path, followlinks=False):
        if 'node_modules' not in root:
            dirs[:] = [d for d in dirs if d != '.git']
            continue
        for pkg_name, description in MALICIOUS_PACKAGES.items():
            pkg_dir = os.path.join(root, pkg_name)
            if os.path.isdir(pkg_dir):
                rel = os.path.relpath(pkg_dir, repo_path)
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"Compromised Package Installed: {pkg_name}",
                    description=f"Directory exists in node_modules ({description}). The dropper likely already executed.",
                    file=rel, line=0,
                    snippet=f"node_modules/{pkg_name}/ directory present",
                    category="post-incident"
                ))
        dirs[:] = []  # Don't recurse deeper into node_modules
    return findings


def scan_npm_cache():
    """Check npm cache for compromised package tarballs."""
    findings = []
    npm_cache = os.path.expanduser("~/.npm/_cacache")
    if not os.path.isdir(npm_cache):
        return findings

    # Search content-v2 index for malicious package names
    index_dir = os.path.join(npm_cache, "content-v2")
    if not os.path.isdir(index_dir):
        return findings

    # Check the index entries for known bad packages
    tmp_dir = os.path.join(npm_cache, "tmp")
    index_entries = os.path.join(npm_cache, "index-v5")
    if os.path.isdir(index_entries):
        for root, _dirs, files in os.walk(index_entries):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read(4096)
                    for pkg_name, desc in MALICIOUS_PACKAGES.items():
                        if pkg_name in content:
                            findings.append(core.Finding(
                                scanner=SCANNER_NAME, severity="critical",
                                title=f"Compromised Package in npm Cache: {pkg_name}",
                                description=f"npm cache contains entry for '{pkg_name}' ({desc}). Package was downloaded to this machine.",
                                file=os.path.relpath(fpath, os.path.expanduser("~")),
                                line=0,
                                snippet=f"Cache entry references {pkg_name}",
                                category="post-incident"
                            ))
                            break
                except (OSError, UnicodeDecodeError):
                    continue
    return findings


def scan_npm_logs():
    """Check npm install logs for references to compromised packages."""
    findings = []
    log_dir = os.path.expanduser("~/.npm/_logs")
    if not os.path.isdir(log_dir):
        return findings

    for log_file in sorted(glob.glob(os.path.join(log_dir, "*.log")))[-50:]:
        try:
            with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(1024 * 1024)  # Cap at 1MB per log file
            for pkg_name, desc in MALICIOUS_PACKAGES.items():
                if pkg_name in content:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title=f"Compromised Package in npm Logs: {pkg_name}",
                        description=f"npm install log references '{pkg_name}' ({desc})",
                        file=os.path.basename(log_file),
                        line=0,
                        snippet=f"Log references {pkg_name}",
                        category="post-incident"
                    ))
            for c2 in C2_INDICATORS:
                if c2 in content:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"C2 Indicator in npm Logs: {c2}",
                        description=f"npm install log references known C2 indicator '{c2}'",
                        file=os.path.basename(log_file),
                        line=0,
                        snippet=f"Log references C2: {c2}",
                        category="post-incident"
                    ))
        except (OSError, UnicodeDecodeError):
            continue
    return findings


def scan_host_artifacts():
    """Check for known RAT binaries and persistence mechanisms."""
    findings = []

    # RAT binaries
    for rat_path in RAT_BINARY_PATHS:
        if os.path.exists(rat_path):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=f"RAT Binary Found: {os.path.basename(rat_path)}",
                description=f"Known RAT binary exists at {rat_path} (axios supply chain attack artifact)",
                file=rat_path, line=0,
                snippet=f"File exists: {rat_path}",
                category="post-incident"
            ))

    # LaunchAgent/LaunchDaemon persistence (macOS)
    launch_dirs = [
        os.path.expanduser("~/Library/LaunchAgents"),
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
    ]
    for launch_dir in launch_dirs:
        if not os.path.isdir(launch_dir):
            continue
        for plist in glob.glob(os.path.join(launch_dir, "*.plist")):
            try:
                with open(plist, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                for c2 in C2_INDICATORS:
                    if c2 in content:
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"C2 Persistence in LaunchAgent",
                            description=f"LaunchAgent/Daemon references C2 indicator '{c2}'",
                            file=os.path.relpath(plist, "/"), line=0,
                            snippet=f"plist references {c2}",
                            category="post-incident"
                        ))
                if "act.mond" in content or "plain-crypto" in content:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"RAT Persistence in LaunchAgent",
                        description="LaunchAgent references known RAT artifacts",
                        file=os.path.relpath(plist, "/"), line=0,
                        snippet="plist references RAT binary or dropper",
                        category="post-incident"
                    ))
            except (OSError, PermissionError):
                continue
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Post-Incident Artifact Scanner")
    repo_path = args.repo_path

    print(f"[*] Scanning for post-incident artifacts in {repo_path}...")

    all_findings = []

    # Repo-level checks
    all_findings.extend(scan_node_modules(repo_path))

    # Host-level checks (run regardless of repo path)
    all_findings.extend(scan_npm_cache())
    all_findings.extend(scan_npm_logs())
    all_findings.extend(scan_host_artifacts())

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
