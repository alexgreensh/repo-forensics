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
    # Set GIT_PAGER=cat to prevent malicious .git/config pager execution
    cmd = ["git", "log", "--pretty=format:%H%x00%an%x00%ae%x00%aI%x00%cI%x00%G?", "-n", "1000"]
    env = dict(os.environ, GIT_PAGER="cat")
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


def main():
    args = core.parse_common_args(sys.argv, "Git History Forensics")
    repo_path = args.repo_path

    print(f"[*] Analyzing Git History in {repo_path}...")

    commits = get_git_log(repo_path)
    if not commits or commits == ['']:
        print("[-] No git history found or not a git repo.")
        return

    findings = analyze_commits(commits, repo_path)

    print(f"[+] Analyzed {len(commits)} recent commits.")
    core.output_findings(findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
