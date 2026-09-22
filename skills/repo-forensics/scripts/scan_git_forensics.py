#!/usr/bin/env python3
"""
scan_git_forensics.py - Git History Forensics (v2: severity + GPG check)
Analyzes commit history for time anomalies, email inconsistencies,
and unsigned commits.

Created by Alex Greenshpun
"""

import sys
import os
import datetime
import json
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "git_forensics"


def get_git_log(repo_path):
    # Null byte delimiter prevents author-name spoofing with '|'.
    #
    # The pretty format deliberately does NOT include %G? (signature status):
    # %G? makes git verify each commit's signature, which executes the repo's
    # own gpg.program config value -- arbitrary code execution just from reading
    # a hostile repo's history (the scanner runs inside the untrusted tree, and
    # this call runs first on every scan, including --skill-scan). The signature
    # status of an untrusted checkout, verified against whatever keys happen to
    # be in the scanning machine's keyring, is not a meaningful signal anyway.
    #
    # All git in this module goes through core.run_git_hardened, which overrides
    # every exec-capable config key (gpg.program, core.fsmonitor, core.hooksPath,
    # diff.external, the LFS filters, ...) so nothing the repo declares can run.
    result = core.run_git_hardened(
        repo_path,
        "log", "--pretty=format:%H%x00%an%x00%ae%x00%aI%x00%cI", "-n", "1000",
    )
    if result is None or result.returncode != 0:
        return []
    return result.stdout.strip().split('\n')


def analyze_commits(commits, repo_path):
    findings = []
    authors = {}
    now = datetime.datetime.now(datetime.timezone.utc)

    for line in commits:
        try:
            parts = line.split('\x00')
            if len(parts) < 5:
                continue

            commit_hash = parts[0][:12]
            author_name = parts[1]
            author_email = parts[2]
            author_date_str = parts[3]
            committer_date_str = parts[4]

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
                    description="Large gap between author and committer dates",
                    file=f"commit:{commit_hash}", line=0,
                    snippet=f"Author: {author_date_str}, Commit: {committer_date_str}",
                    category="time-anomaly"
                ))

            # Impossible time
            if delta < datetime.timedelta(0):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Impossible Time (Committer before Author)",
                    description="Committer date is before author date (time manipulation)",
                    file=f"commit:{commit_hash}", line=0,
                    snippet=f"Author: {author_date_str}, Commit: {committer_date_str}",
                    category="time-anomaly"
                ))

            # GPG signature status is intentionally not collected: reading it
            # (%G?) makes git execute the repo's own gpg.program (RCE from an
            # untrusted checkout), and the status is not trustworthy for a
            # third-party repo anyway. See get_git_log.

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
    result = core.run_git_hardened(repo_path, "for-each-ref", "refs/replace/")
    if result is None or result.returncode != 0:
        return findings
    output = result.stdout.strip()

    if output:
        ref_lines = [ln for ln in output.splitlines() if ln.strip()]
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

    lines = [ln for ln in content.splitlines() if ln.strip() and not ln.startswith('#')]
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



_SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_AMBIGUOUS_REF_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|FETCH_HEAD)$")
_PLUGIN_MARKERS = (
    ".claude-plugin", ".codex-plugin", ".agents", ".gemini",
    "openclaw.plugin.json", "SKILL.md",
)
_PIN_KEYS = frozenset({
    "sha", "commit", "commitsha", "commit_sha", "revision", "rev", "gitsha",
})
# Files read for an explicit commit pin. Split into two roles:
#  - CATALOG manifests list plugins by name/URL and have no pin concept; a
#    pin key there is a bonus but its ABSENCE is normal, so it must NOT raise a
#    "provenance pin unavailable" coverage gap (that FP fired on this tool's own
#    marketplace.json and trains readers to ignore the scanner).
#  - LOCKFILE manifests are expected to pin an exact commit; a lockfile present
#    without a recoverable pin IS a real coverage gap worth a low-severity note.
_PIN_CATALOG_NAMES = frozenset({
    "plugin.json", "marketplace.json", "plugins.json", "extensions.json",
})
_PIN_LOCKFILE_NAMES = frozenset({
    "lock.json", "plugin-lock.json", "marketplace.lock.json",
})
_PIN_METADATA_NAMES = _PIN_CATALOG_NAMES | _PIN_LOCKFILE_NAMES
# Directories never walked when recovering pins (vendored trees can carry a
# foreign project's manifest and manufacture a spurious pin mismatch).
_PIN_WALK_SKIP_DIRS = frozenset({".git", "node_modules", "vendor",
                                 "bower_components", ".pnpm"})


def _safe_git(repo_path, *args):
    """Run a read-only git command without honoring attacker-controlled config.

    Delegates to core.run_git_hardened so this shares ONE hardened git choke
    point with get_git_log/scan_replace_refs. The earlier local `-c` set here
    missed gpg*.program / diff.external / the LFS filters -- the hardened runner
    covers them all. Returns stripped stdout (this helper's historical contract)
    or None on any failure.
    """
    result = core.run_git_hardened(repo_path, *args)
    if result is None or result.returncode != 0:
        return None
    return result.stdout.strip()


def _is_agent_plugin_repo(repo_path):
    return any(os.path.exists(os.path.join(repo_path, marker))
               for marker in _PLUGIN_MARKERS)


def _walk_pin_values(value, key=""):
    """Yield explicit commit pins only; never treat arbitrary 40-hex text as a pin."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk_pin_values(v, str(k).lower())
    elif isinstance(value, list):
        for item in value:
            yield from _walk_pin_values(item, key)
    elif isinstance(value, str) and key in _PIN_KEYS and _SHA40_RE.fullmatch(value):
        yield value.lower()


def _recover_recorded_pins(repo_path):
    """Return (pins, lockfile_without_pin).

    `pins` are the explicit 40-hex commit pins recovered from any catalog OR
    lockfile manifest. `lockfile_without_pin` is True only when a LOCKFILE
    manifest (which is expected to pin) was found yet contributed no pin -- a
    genuine coverage gap. A bare catalog manifest with no pin concept never
    sets it (that was the medium false positive on ordinary marketplace repos).
    """
    pins = set()
    lockfile_seen = False
    lockfile_pins = set()
    for root, dirs, files in os.walk(repo_path):
        rel_root = os.path.relpath(root, repo_path)
        if rel_root.count(os.sep) > 3:
            dirs[:] = []
            continue
        # Prune vendored trees: a dependency's own manifest must not manufacture
        # a foreign pin (or pin mismatch) for the repo under audit.
        dirs[:] = [d for d in dirs if d not in _PIN_WALK_SKIP_DIRS]
        for name in files:
            lname = name.lower()
            if lname not in _PIN_METADATA_NAMES:
                continue
            path = os.path.join(root, name)
            try:
                if os.path.getsize(path) > 1024 * 1024:
                    continue
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            found = set(_walk_pin_values(data))
            pins.update(found)
            if lname in _PIN_LOCKFILE_NAMES:
                lockfile_seen = True
                lockfile_pins.update(found)
    lockfile_without_pin = lockfile_seen and not lockfile_pins
    return pins, lockfile_without_pin


def scan_plugin_checkout_provenance(repo_path):
    """Detect ambiguous Git refs and pin mismatches in agent plugin checkouts."""
    if not _is_agent_plugin_repo(repo_path):
        return []
    findings = []
    refs = _safe_git(repo_path, "for-each-ref", "--format=%(refname:short)", "refs/heads/")
    if refs is None:
        return findings
    ambiguous = sorted({r.strip() for r in refs.splitlines()
                        if _AMBIGUOUS_REF_RE.fullmatch(r.strip())})
    for ref in ambiguous:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Agent Plugin Ambiguous Git Ref",
            description=("Agent plugin repository contains a local branch whose name "
                         "can override commit-pin resolution during checkout."),
            file=f".git/refs/heads/{ref}", line=0, snippet=ref,
            category="plugin-provenance", evidence_class="direct"))

    head = _safe_git(repo_path, "rev-parse", "HEAD")
    symbolic = _safe_git(repo_path, "symbolic-ref", "--quiet", "--short", "HEAD")
    if symbolic and _AMBIGUOUS_REF_RE.fullmatch(symbolic):
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Agent Plugin Checked Out on Ambiguous Ref",
            description=("Installed agent plugin HEAD is attached to an ambiguous branch "
                         "instead of a verified detached commit."),
            file=".git/HEAD", line=0, snippet=f"HEAD -> {symbolic}",
            category="plugin-provenance", evidence_class="direct"))

    pins, lockfile_without_pin = _recover_recorded_pins(repo_path)
    if pins and head and head.lower() not in pins:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Agent Plugin Checkout Does Not Match Recorded Pin",
            description=(f"Resolved HEAD {head[:12]} does not match any recorded plugin "
                         "commit pin. The installed tree may have been substituted."),
            file=".git/HEAD", line=0,
            snippet=f"HEAD={head}; pins={','.join(sorted(pins))[:80]}",
            category="plugin-provenance", evidence_class="direct"))
    elif pins and symbolic:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="SHA-Pinned Agent Plugin Is Not Detached",
            description=("A plugin with a recorded commit pin is checked out on a symbolic "
                         "branch. Hash-pinned installs must use detached HEAD and verify it."),
            file=".git/HEAD", line=0, snippet=f"HEAD -> {symbolic}",
            category="plugin-provenance", evidence_class="direct"))
    elif lockfile_without_pin:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="Agent Plugin Lockfile Missing Commit Pin",
            description=("A plugin lockfile was found but records no explicit 40-hex "
                         "commit pin, so checkout provenance could not be verified. "
                         "A bare catalog manifest with no pin concept does not trigger "
                         "this note."),
            file="plugin-metadata", line=0, snippet="lockfile without commit pin",
            category="coverage-gap", evidence_class="inferred"))
    return findings


def scan_plugin_installers(repo_path):
    """Detect installer checkout flows that trust ref resolution without verifying HEAD."""
    if not _is_agent_plugin_repo(repo_path):
        return []
    findings = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor")]
        for name in files:
            if not name.endswith((".sh", ".bash", ".zsh", ".js", ".jsx", ".ts", ".tsx", ".py")):
                continue
            path = os.path.join(root, name)
            try:
                text = open(path, "r", encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            rel = os.path.relpath(path, repo_path)
            for f in _scan_installer_text(text, rel):
                findings.append(f)
    return findings


# HEURISTIC (documented limit): the verification of a pinned checkout
# (`git rev-parse HEAD` compared to the pin, aborting on mismatch) must appear
# in the SAME flow as the checkout, not merely somewhere in the file. We
# approximate "same flow" as a bounded window of source immediately AFTER the
# checkout. This removes the false negative where an unsafe checkout was
# excused by an unrelated rev-parse / comparison / raise elsewhere in the file,
# at the cost of missing a verification that lives in a separate function or
# module (a documented false negative -- installer findings are `high`, never a
# sole `critical`, so they inform rather than hard-block).
_INSTALLER_VERIFY_WINDOW = 800
_PIN_NAME_RE = r"(?:pinned_?sha|commit_?sha|sha|revision)"
_RE_FETCH_PIN = re.compile(rf"git[^\n]{{0,100}}fetch[^\n]{{0,100}}{_PIN_NAME_RE}", re.I)
_RE_CHECKOUT_FETCH = re.compile(r"git[^\n]{0,100}checkout[^\n]{0,60}FETCH_HEAD", re.I)
_RE_CHECKOUT_PIN = re.compile(rf"git[^\n]{{0,100}}checkout[^\n]{{0,80}}{_PIN_NAME_RE}", re.I)
_RE_REV_PARSE = re.compile(r"git[^\n]{0,100}rev-parse[^\n]{0,40}HEAD", re.I)
_RE_COMPARE = re.compile(
    rf"(?:!=|===?|equals?\s*\(|compare_digest\s*\()[^\n]{{0,100}}{_PIN_NAME_RE}"
    rf"|{_PIN_NAME_RE}[^\n]{{0,100}}(?:!=|===?|equals?\s*\(|compare_digest\s*\()",
    re.I)
_RE_ABORT = re.compile(
    r"(?:exit\s*\(?[1-9]|process\.exit\s*\(\s*[1-9]|abort|raise|throw)", re.I)


def _verified_after(text, pos):
    """True if a rev-parse/compare/abort verification appears in the window of
    source immediately after `pos` (the checkout site)."""
    window = text[pos:pos + _INSTALLER_VERIFY_WINDOW]
    return bool(_RE_REV_PARSE.search(window)
                and _RE_COMPARE.search(window)
                and _RE_ABORT.search(window))


def _scan_installer_text(text, rel):
    findings = []
    fetch_pin_anywhere = bool(_RE_FETCH_PIN.search(text))
    # FETCH_HEAD checkout not verified in its own flow (most dangerous).
    for m in _RE_CHECKOUT_FETCH.finditer(text):
        if fetch_pin_anywhere and not _verified_after(text, m.start()):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Agent Plugin Installer Trusts Ambiguous FETCH_HEAD",
                description=("Installer fetches a pinned revision then checks out FETCH_HEAD "
                             "without verifying, in the same flow, that resolved HEAD matches "
                             "the pin."),
                file=rel, line=0, snippet="git fetch ...; git checkout FETCH_HEAD",
                category="plugin-provenance", evidence_class="direct"))
            break
    # Pin-variable checkout not verified in its own flow.
    for m in _RE_CHECKOUT_PIN.finditer(text):
        if not _verified_after(text, m.start()):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Agent Plugin Installer Does Not Verify Resolved Commit",
                description=("Installer checks out a commit-pin variable but does not abort, in "
                             "the same flow, unless git rev-parse HEAD exactly matches the "
                             "requested pin."),
                file=rel, line=0, snippet="git checkout <pin> without HEAD verification",
                category="plugin-provenance", evidence_class="direct"))
            break
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Git History Forensics")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Analyzing Git History in {repo_path}...")

    commits = get_git_log(repo_path)
    findings = []
    if commits and commits != ['']:
        findings.extend(analyze_commits(commits, repo_path))
    else:
        core.emit_status(args.format, "[-] No git history found; scanning installer source only.")
    findings.extend(scan_replace_refs(repo_path))
    findings.extend(scan_grafts(repo_path))
    findings.extend(scan_plugin_checkout_provenance(repo_path))
    findings.extend(scan_plugin_installers(repo_path))

    core.emit_status(args.format, f"[+] Analyzed {len(commits)} recent commits.")
    core.output_findings(findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
