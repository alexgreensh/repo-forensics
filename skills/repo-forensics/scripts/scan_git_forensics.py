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
import stat

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "git_forensics"


def get_git_log(repo_path):
    # Null byte delimiter prevents author-name spoofing with '|'.
    #
    # The pretty format deliberately does NOT include %G? (signature status):
    # %G? makes git verify each commit's signature, which executes the repo's
    # own gpg.program config value -- arbitrary code execution just from reading
    # a hostile repo's history (the scanner runs inside the untrusted tree). The
    # signature status of an untrusted checkout, verified against whatever keys
    # happen to be in the scanning machine's keyring, is not a meaningful signal
    # anyway (a real third-party signer's key is almost never present, so it
    # reports "cannot check", and an attacker simply leaves commits unsigned).
    # We drop it rather than trust config neutralization alone.
    #
    # The call still goes through the hardened runner, which overrides every
    # exec-capable config key (gpg.program, core.fsmonitor, core.hooksPath, ...)
    # so nothing the repo declares can run during `git log`.
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

            # GPG signature status is intentionally not collected here: reading
            # it (%G?) makes git execute the repo's own gpg.program, an RCE
            # vector from an untrusted checkout, and the status is not a
            # trustworthy signal for a third-party repo anyway. See get_git_log.

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
    ".claude-plugin", ".codex-plugin", ".agents/plugin.json",
    ".gemini/plugin.json", "openclaw.plugin.json",
)
_PIN_KEYS = frozenset({
    "sha", "commit", "commitsha", "commit_sha", "revision", "rev", "gitsha",
})
_PIN_METADATA_NAMES = frozenset({
    "plugin.json", "marketplace.json", "plugins.json", "extensions.json",
    "lock.json", "plugin-lock.json", "marketplace.lock.json",
})
_MAX_PROVENANCE_FILE_BYTES = 1024 * 1024
_MAX_METADATA_RECORDS = 50000
_MAX_PLUGIN_WALK_ENTRIES = 20000


def _read_regular_text(path, repo_path):
    """Read a bounded regular file whose resolved path stays in the repo."""
    if os.path.islink(path):
        return None
    try:
        if os.path.commonpath((os.path.realpath(path), os.path.realpath(repo_path))) != os.path.realpath(repo_path):
            return None
    except ValueError:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_PROVENANCE_FILE_BYTES:
                return None
            data = source.read(_MAX_PROVENANCE_FILE_BYTES + 1)
    except OSError:
        return None
    if len(data) > _MAX_PROVENANCE_FILE_BYTES:
        return None
    return data.decode("utf-8", errors="ignore")


def _safe_git(repo_path, *args):
    """Run a read-only git command through the release hardened choke point."""
    result = core.run_git_hardened(repo_path, *args, check=True)
    return result.stdout.strip() if result is not None else None


def _is_agent_plugin_repo(repo_path):
    return any(os.path.exists(os.path.join(repo_path, marker))
               for marker in _PLUGIN_MARKERS)


def _plugin_identity(repo_path):
    """Return the installed plugin identity from its own manifest, if unique."""
    candidates = []
    for rel in (".claude-plugin/plugin.json", ".codex-plugin/plugin.json",
                ".agents/plugin.json", ".gemini/plugin.json", "openclaw.plugin.json"):
        path = os.path.join(repo_path, rel)
        try:
            text = _read_regular_text(path, repo_path)
            if text is None:
                continue
            data = json.loads(text)
        except (RecursionError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            for key in ("name", "id", "pluginId", "plugin_id"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    candidates.append(value.strip().lower())
                    break
    unique = set(candidates)
    return next(iter(unique)) if len(unique) == 1 else None


def _record_identities(value):
    if not isinstance(value, dict):
        return set()
    out = set()
    for key in ("name", "id", "pluginId", "plugin_id", "package"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            out.add(item.strip().lower())
    return out


def _record_pins(value):
    if not isinstance(value, dict):
        return set()
    pins = set()
    for key, item in value.items():
        if str(key).lower() in _PIN_KEYS and isinstance(item, str) and _SHA40_RE.fullmatch(item):
            pins.add(item.lower())
    return pins


def _iter_records(value):
    pending = [value]
    examined = 0
    while pending:
        examined += 1
        if examined > _MAX_METADATA_RECORDS:
            raise ValueError("plugin metadata record limit exceeded")
        item = pending.pop()
        if isinstance(item, dict):
            yield item
            pending.extend(reversed(list(item.values())))
        elif isinstance(item, list):
            pending.extend(reversed(item))


def _recover_recorded_pins(repo_path):
    """Resolve pins only from metadata records belonging to this plugin.

    A lockfile may contain many plugins. Pins from unrelated records must never
    make this checkout look valid. Missing or ambiguous identity is a coverage
    gap, not acceptance.
    """
    identity = _plugin_identity(repo_path)
    metadata_seen = False
    matching_records = []
    ambiguous_identity = False
    # The installed plugin's own manifest is authoritative for its own pin.
    own_manifest_seen = False
    for rel in (".claude-plugin/plugin.json", ".codex-plugin/plugin.json",
                ".agents/plugin.json", ".gemini/plugin.json", "openclaw.plugin.json"):
        path = os.path.join(repo_path, rel)
        if not os.path.lexists(path):
            continue
        own_manifest_seen = True
        try:
            text = _read_regular_text(path, repo_path)
            if text is None:
                ambiguous_identity = True
                continue
            own = json.loads(text)
        except (RecursionError, json.JSONDecodeError):
            ambiguous_identity = True
            continue
        if identity is not None and _record_pins(own):
            matching_records.append(own)
    if identity is None and own_manifest_seen:
        ambiguous_identity = True
    walked = 0
    for root, dirs, files in os.walk(repo_path):
        rel_root = os.path.relpath(root, repo_path)
        if rel_root.count(os.sep) > 3:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor", ".venv")]
        walked += 1 + len(files)
        if walked > _MAX_PLUGIN_WALK_ENTRIES:
            ambiguous_identity = True
            break
        for name in files:
            if name.lower() not in _PIN_METADATA_NAMES or name.lower() == "plugin.json":
                continue
            path = os.path.join(root, name)
            metadata_seen = True
            try:
                text = _read_regular_text(path, repo_path)
                if text is None:
                    ambiguous_identity = True
                    continue
                data = json.loads(text)
                records = list(_iter_records(data))
            except (RecursionError, ValueError, json.JSONDecodeError):
                ambiguous_identity = True
                continue
            if identity is None:
                if any(_record_pins(record) for record in records):
                    ambiguous_identity = True
                continue
            for record in records:
                ids = _record_identities(record)
                if identity in ids:
                    matching_records.append(record)
    pins = set()
    for record in matching_records:
        pins.update(_record_pins(record))
    # Multiple matching records that disagree are ambiguous. Never accept any.
    if len(pins) > 1:
        return set(), metadata_seen, True
    if identity is None and metadata_seen:
        ambiguous_identity = True
    if identity is not None and metadata_seen and not matching_records:
        ambiguous_identity = True
    return pins, metadata_seen, ambiguous_identity

def scan_plugin_checkout_provenance(repo_path):
    """Detect ambiguous Git refs and pin mismatches in agent plugin checkouts."""
    if not _is_agent_plugin_repo(repo_path):
        return []
    findings = []
    refs = _safe_git(repo_path, "for-each-ref", "--format=%(refname:short)", "refs/heads/")
    if refs is None:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="medium",
            title="Agent Plugin Git Provenance Unavailable",
            description="Plugin checkout has no readable Git refs; commit provenance cannot be verified.",
            file=".git", line=0, snippet="Git refs unavailable",
            category="coverage-gap", evidence_class="direct"))
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
    if head is None:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="medium",
            title="Agent Plugin Git Provenance Unavailable",
            description="Plugin checkout has no readable HEAD; commit provenance cannot be verified.",
            file=".git/HEAD", line=0, snippet="Git HEAD unavailable",
            category="coverage-gap", evidence_class="direct"))
    symbolic = _safe_git(repo_path, "symbolic-ref", "--quiet", "--short", "HEAD")
    if symbolic and _AMBIGUOUS_REF_RE.fullmatch(symbolic):
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Agent Plugin Checked Out on Ambiguous Ref",
            description=("Installed agent plugin HEAD is attached to an ambiguous branch "
                         "instead of a verified detached commit."),
            file=".git/HEAD", line=0, snippet=f"HEAD -> {symbolic}",
            category="plugin-provenance", evidence_class="direct"))

    pins, metadata_seen, ambiguous_identity = _recover_recorded_pins(repo_path)
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
    elif (metadata_seen and not pins) or ambiguous_identity:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="medium",
            title="Agent Plugin Provenance Pin Unavailable",
            description=("Plugin metadata was found, but no explicit 40-hex commit pin could "
                         "be recovered; checkout provenance could not be verified."),
            file="plugin-metadata", line=0, snippet=("ambiguous plugin identity/pin" if ambiguous_identity else "no explicit commit pin"),
            category="coverage-gap", evidence_class="direct"))
    return findings


def scan_plugin_installers(repo_path):
    """Detect installer checkout flows that trust ref resolution without verifying HEAD."""
    if not _is_agent_plugin_repo(repo_path):
        return []
    findings = []
    skipped = []
    walked = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor", ".venv")]
        walked += 1 + len(files)
        if walked > _MAX_PLUGIN_WALK_ENTRIES:
            skipped.append("plugin tree exceeds scan entry limit")
            break
        for name in files:
            if not name.endswith((".sh", ".bash", ".zsh", ".js", ".jsx", ".ts", ".tsx", ".py")):
                continue
            path = os.path.join(root, name)
            text = _read_regular_text(path, repo_path)
            rel = os.path.relpath(path, repo_path)
            if text is None:
                skipped.append(rel)
                continue
            pin_name = r"(?:pinned_?sha|commit_?sha|sha|revision)"
            # Shell and common subprocess/exec representations. We require git,
            # the relevant subcommand, and the pin/FETCH_HEAD in one bounded call.
            has_fetch_pin = bool(re.search(
                rf"git[^\n]{{0,100}}fetch[^\n]{{0,100}}{pin_name}", text, re.I))
            checkout_fetch = bool(re.search(
                r"git[^\n]{0,100}checkout[^\n]{0,60}FETCH_HEAD", text, re.I))
            checkout_pin = bool(re.search(
                rf"git[^\n]{{0,100}}checkout[^\n]{{0,80}}{pin_name}", text, re.I))
            has_rev_parse = bool(re.search(
                r"git[^\n]{0,100}rev-parse[^\n]{0,40}HEAD", text, re.I))
            has_compare = bool(re.search(
                rf"(?:!=|===?|equals?\s*\(|compare_digest\s*\()[^\n]{{0,100}}{pin_name}|{pin_name}[^\n]{{0,100}}(?:!=|===?|equals?\s*\(|compare_digest\s*\()",
                text, re.I))
            has_abort = bool(re.search(
                r"(?:exit\s*\(?[1-9]|process\.exit\s*\(\s*[1-9]|abort|raise|throw)",
                text, re.I))
            verifies = has_rev_parse and has_compare and has_abort
            if has_fetch_pin and checkout_fetch and not verifies:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="Agent Plugin Installer Trusts Ambiguous FETCH_HEAD",
                    description=("Installer fetches a pinned revision then checks out FETCH_HEAD "
                                 "without verifying resolved HEAD matches the pin."),
                    file=rel, line=0, snippet="git fetch ...; git checkout FETCH_HEAD",
                    category="plugin-provenance", evidence_class="direct"))
            elif checkout_pin and not verifies:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Agent Plugin Installer Does Not Verify Resolved Commit",
                    description=("Installer checks out a commit-pin variable but does not abort "
                                 "unless git rev-parse HEAD exactly matches the requested pin."),
                    file=rel, line=0, snippet="git checkout <pin> without HEAD verification",
                    category="plugin-provenance", evidence_class="direct"))
    if skipped:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="medium",
            title="Agent Plugin Installer Source Not Scanned",
            description=f"{len(skipped)} source paths could not be scanned because of input limits or unreadable files.",
            file=skipped[0], line=0, snippet="installer source skipped",
            category="coverage-gap", evidence_class="direct"))
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
