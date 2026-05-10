#!/usr/bin/env python3
"""
scan_git_forensics.py - Git History Forensics (v2: severity + GPG check)
Analyzes commit history for time anomalies, email inconsistencies,
and unsigned commits.

Created by Alex Greenshpun
"""

import subprocess
import sys
import os
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "git_forensics"


def get_git_log(repo_path):
    # Use null byte delimiter to prevent author name spoofing with '|'
    # Minimal env prevents malicious .git/config from executing code via
    # core.fsmonitor, core.hooksPath, pager.*, credential.helper, etc.
    # -c flags override local .git/config to prevent RCE via core.fsmonitor,
    # credential.helper, core.hooksPath, or core.sshCommand in malicious repos.
    # This pattern is used by GitHub Actions runners for the same reason.
    cmd = [
        "git",
        "-c", "core.fsmonitor=",
        "-c", "core.hooksPath=",
        "-c", "credential.helper=",
        "-c", "core.sshCommand=",
        "-c", "safe.directory=*",
        "log", "--pretty=format:%H%x00%an%x00%ae%x00%aI%x00%cI%x00%G?", "-n", "1000",
    ]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
        "GIT_PAGER": "cat",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, check=True, env=env)
        return result.stdout.strip().split('\n')
    except subprocess.CalledProcessError:
        return []


def analyze_commits(commits, repo_path):
    findings = []
    authors = {}
    now = datetime.datetime.now(datetime.timezone.utc)

    for line in commits:
        try:
            parts = line.split('\x00')
            if len(parts) < 6:
                continue

            commit_hash = parts[0][:12]
            author_name = parts[1]
            author_email = parts[2]
            author_date_str = parts[3]
            committer_date_str = parts[4]
            gpg_status = parts[5] if len(parts) > 5 else 'N'

            if author_email not in authors:
                authors[author_email] = set()
            authors[author_email].add(author_name)

            a_date = datetime.datetime.fromisoformat(author_date_str)
            c_date = datetime.datetime.fromisoformat(committer_date_str)

            # Future dates
            if a_date > now + datetime.timedelta(days=1):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Future Author Date",
                    description=f"Commit {commit_hash} has author date in the future",
                    file=f"commit:{commit_hash}", line=0,
                    snippet=f"Author date: {author_date_str}",
                    category="time-anomaly"
                ))

            # Time stomping (>30 day lag)
            delta = c_date - a_date
            if delta > datetime.timedelta(days=30):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="Time Lag (>30 days)",
                    description=f"Large gap between author and committer dates",
                    file=f"commit:{commit_hash}", line=0,
                    snippet=f"Author: {author_date_str}, Commit: {committer_date_str}",
                    category="time-anomaly"
                ))

            # Impossible time
            if delta < datetime.timedelta(0):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Impossible Time (Committer before Author)",
                    description=f"Committer date is before author date (time manipulation)",
                    file=f"commit:{commit_hash}", line=0,
                    snippet=f"Author: {author_date_str}, Commit: {committer_date_str}",
                    category="time-anomaly"
                ))

            # GPG signature check
            if gpg_status == 'N':
                # Not signed, low severity (very common)
                pass  # Don't flag, too noisy
            elif gpg_status == 'B':
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Bad GPG Signature",
                    description=f"Commit {commit_hash} has an invalid/expired GPG signature",
                    file=f"commit:{commit_hash}", line=0,
                    snippet=f"GPG status: Bad signature",
                    category="signature"
                ))

        except (ValueError, IndexError):
            continue

    # Check for multiple names per email
    for email, names in authors.items():
        if len(names) > 2:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="medium",
                title="Multiple Identities per Email",
                description=f"Email '{email}' used by {len(names)} different author names",
                file="git-log", line=0,
                snippet=f"{email}: {', '.join(list(names)[:3])}",
                category="identity-anomaly"
            ))

    return findings


def scan_replace_refs(repo_path):
    """Detect git replace objects (refs/replace/*).

    Git replace objects silently rewrite what a commit hash resolves to,
    allowing an attacker to make a repo appear to have a clean history while
    serving a different object graph. This is a history-rewriting attack that
    bypasses normal git integrity checks unless --no-replace-objects is used.

    Detection: list any refs/replace/* refs via git for-each-ref. If any
    exist, report a critical finding.
    """
    findings = []
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
        "GIT_PAGER": "cat",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }
    cmd = [
        "git",
        "-c", "core.fsmonitor=",
        "-c", "core.hooksPath=",
        "-c", "credential.helper=",
        "-c", "core.sshCommand=",
        "-c", "safe.directory=*",
        "for-each-ref", "refs/replace/",
    ]
    try:
        result = subprocess.run(
            cmd, cwd=repo_path, capture_output=True, text=True, check=True, env=env
        )
        output = result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return findings

    if output:
        ref_lines = [l for l in output.splitlines() if l.strip()]
        ref_names = []
        for line in ref_lines:
            parts = line.split()
            if len(parts) >= 3:
                ref_names.append(parts[2])

        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Git Replace Objects Detected",
            description=(
                f"Repository contains {len(ref_lines)} git replace object(s) under "
                f"refs/replace/. Replace objects silently rewrite commit/tree/blob "
                f"resolution, enabling history forgery that bypasses normal git log "
                f"output. Use 'git log --no-replace-objects' to see unmodified history."
            ),
            file=".git/refs/replace/",
            line=0,
            snippet=(', '.join(ref_names[:5]) + (' ...' if len(ref_names) > 5 else ''))[:120],
            category="git-history-tampering"
        ))

    return findings


def scan_grafts(repo_path):
    """Detect presence of .git/info/grafts file.

    Grafts are a deprecated git mechanism that rewrites the apparent parentage
    of commits, allowing an attacker to detach part of the history or introduce
    fake merge ancestry. While superseded by replace objects, grafts still work
    in all git versions and are rarely present in legitimate repositories.

    Detection: check if .git/info/grafts exists and is non-empty.
    """
    findings = []
    dot_git = os.path.join(repo_path, '.git')
    if os.path.isfile(dot_git):
        try:
            with open(dot_git, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
            if content.startswith('gitdir:'):
                dot_git = content[7:].strip()
                if not os.path.isabs(dot_git):
                    dot_git = os.path.join(repo_path, dot_git)
        except OSError:
            pass
    grafts_path = os.path.join(dot_git, 'info', 'grafts')

    if not os.path.isfile(grafts_path):
        return findings

    try:
        with open(grafts_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
    except OSError:
        return findings

    if not content:
        return findings

    lines = [l for l in content.splitlines() if l.strip() and not l.startswith('#')]
    if not lines:
        return findings

    findings.append(core.Finding(
        scanner=SCANNER_NAME, severity="high",
        title="Git Grafts File Detected",
        description=(
            f".git/info/grafts exists with {len(lines)} graft(s). Grafts rewrite "
            f"commit parentage, enabling history falsification and detached ancestry "
            f"attacks. Grafts are deprecated (superseded by replace objects) and "
            f"are rarely present in legitimate repositories."
        ),
        file=".git/info/grafts",
        line=0,
        snippet=lines[0][:120],
        category="git-history-tampering"
    ))

    return findings


def main():
    args = core.parse_common_args(sys.argv, "Git History Forensics")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Analyzing Git History in {repo_path}...")

    commits = get_git_log(repo_path)
    if not commits or commits == ['']:
        core.emit_status(args.format, "[-] No git history found or not a git repo.")
        core.output_findings([], args.format, SCANNER_NAME)
        return

    findings = analyze_commits(commits, repo_path)
    findings.extend(scan_replace_refs(repo_path))
    findings.extend(scan_grafts(repo_path))

    core.emit_status(args.format, f"[+] Analyzed {len(commits)} recent commits.")
    core.output_findings(findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
