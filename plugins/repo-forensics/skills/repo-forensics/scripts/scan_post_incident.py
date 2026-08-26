#!/usr/bin/env python3
"""
scan_post_incident.py - Post-Incident Artifact Scanner
Detects traces of supply chain attacks that survive dropper self-cleanup.
Checks npm cache, install logs, node_modules artifacts, host IOCs, and persistence.

Created by Alex Greenshpun
"""

import json
import os
import re
import sys
import glob
import hashlib
import tempfile

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

# Packages where only specific versions are compromised (legitimate at other versions).
# scan_node_modules checks installed version before flagging.
VERSION_PINNED_MALICIOUS = {
    "@cap-js/db-service": {"versions": ["2.10.1"], "desc": "Mini Shai-Hulud worm (TeamPCP Wave 6, April 2026)"},
    "@cap-js/postgres": {"versions": ["2.2.2"], "desc": "Mini Shai-Hulud worm (TeamPCP Wave 6, April 2026)"},
    "@cap-js/sqlite": {"versions": ["2.2.2"], "desc": "Mini Shai-Hulud worm (TeamPCP Wave 6, April 2026)"},
    "mbt": {"versions": ["1.2.48"], "desc": "Mini Shai-Hulud worm (TeamPCP Wave 6, April 2026)"},
}

# "Shai-Hulud: The Second Coming" dropper and exfil/staging artifacts.
# November 24, 2025 fake-Bun npm wave (1,100+ packages) plus the December 28, 2025
# "Golden Path" rename of the same files. Filenames are taken verbatim from the
# Cobenian/shai-hulud-detect reference detector (check_bun_attack_files and
# check_new_workflow_patterns) -- none are inferred.
#
# These are checked by filename because the payload survives package removal and
# because bun_environment.js is a 10MB+ obfuscated blob that content scanners skip.
SECOND_COMING_ARTIFACTS = {
    "setup_bun.js": "Fake Bun runtime installer, dropper entrypoint (November 2025)",
    "bun_installer.js": "Fake Bun runtime installer variant, dropper entrypoint (November 2025)",
    "bun_environment.js": "Obfuscated credential-harvesting payload (10MB+) that downloads and runs TruffleHog (November 2025)",
    "environment_source.js": "Renamed bun_environment.js payload, 'Golden Path' variant (December 2025)",
    "actionsSecrets.json": "Double-Base64-encoded secrets exfiltration staging file (November 2025)",
    # CHANGELOG 3.1.0: "Detection for obfuscated exfiltration JSON files:
    # `3nvir0nm3nt.json`, `cl0vd.json`, `c9nt3nts.json`, `pigS3cr3ts.json`"
    # (check_new_workflow_patterns -> obfuscated_exfil_found.txt)
    "3nvir0nm3nt.json": "Obfuscated secrets-exfiltration staging file, 'Golden Path' variant (December 2025)",
    "cl0vd.json": "Obfuscated cloud-credential exfiltration staging file, 'Golden Path' variant (December 2025)",
    "c9nt3nts.json": "Obfuscated exfiltration staging file, 'Golden Path' variant (December 2025)",
    "pigS3cr3ts.json": "Obfuscated secrets exfiltration staging file, 'Golden Path' variant (December 2025)",
}

# Shai-Hulud FAMILY artifacts outside the Second Coming wave. Every filename is
# quoted from the Cobenian/shai-hulud-detect reference detector's
# collect_all_files() find list and the check that consumes it:
#   shai-hulud-workflow.yml            -> check_workflow_files()
#   router_init.js / tanstack_runner.js -> check_mini_shai_hulud_indicators() IOC 1
#   gh-token-monitor.* / kitty-monitor.* -> check_mini_shai_hulud_indicators() IOC 8
# Values are (severity, description).
SHAI_HULUD_FAMILY_ARTIFACTS = {
    "shai-hulud-workflow.yml": (
        "critical",
        "Shai-Hulud v1 worm GitHub Actions workflow, injected to exfiltrate repository secrets (September 2025)",
    ),
    "router_init.js": (
        "critical",
        "Mini Shai-Hulud obfuscated credential-stealing payload (TanStack wave, May 2026)",
    ),
    "tanstack_runner.js": (
        "critical",
        "Mini Shai-Hulud payload runner invoked from a prepare hook (TanStack wave, May 2026)",
    ),
    "gh-token-monitor.sh": (
        "critical",
        "Mini Shai-Hulud dead-man's-switch daemon that wipes the host when its monitored GitHub token is revoked (May 2026 wave)",
    ),
    "gh-token-monitor.service": (
        "critical",
        "systemd unit for the Mini Shai-Hulud dead-man's-switch daemon (May 2026 wave)",
    ),
    "com.user.gh-token-monitor.plist": (
        "critical",
        "macOS LaunchAgent for the Mini Shai-Hulud dead-man's-switch daemon (May 2026 wave)",
    ),
    "kitty-monitor.sh": (
        "critical",
        "Mini Shai-Hulud dead-man's-switch daemon, renamed variant (AntV/atool wave, May 2026)",
    ),
    "kitty-monitor.service": (
        "critical",
        "systemd unit for the Mini Shai-Hulud dead-man's-switch daemon, renamed variant (AntV/atool wave, May 2026)",
    ),
    "com.user.kitty-monitor.plist": (
        "critical",
        "macOS LaunchAgent for the Mini Shai-Hulud dead-man's-switch daemon, renamed variant (AntV/atool wave, May 2026)",
    ),
}

# check_new_workflow_patterns(): "Look for formatter_123456789.yml workflow files"
# -- only counted when the file actually sits in .github/workflows/.
FORMATTER_WORKFLOW_RE = re.compile(r'^formatter_\d{4,20}\.ya?ml$', re.I)

# Dead-man's-switch host paths, quoted verbatim from
# check_mini_shai_hulud_indicators() IOC 8 (host_paths array, --check-host).
# Upstream's warning is load-bearing: "Revoking the monitored token is designed
# to TRIGGER A WIPE -- do not rotate credentials until the service is stopped
# and removed."
DEADMAN_HOST_PATHS = [
    (os.path.expanduser("~/Library/LaunchAgents/com.user.gh-token-monitor.plist"), "gh-token-monitor (TanStack wave, May 2026)"),
    (os.path.expanduser("~/.config/systemd/user/gh-token-monitor.service"), "gh-token-monitor (TanStack wave, May 2026)"),
    (os.path.expanduser("~/.local/bin/gh-token-monitor.sh"), "gh-token-monitor (TanStack wave, May 2026)"),
    (os.path.expanduser("~/.config/gh-token-monitor/token"), "gh-token-monitor (TanStack wave, May 2026)"),
    (os.path.expanduser("~/.config/gh-token-monitor"), "gh-token-monitor (TanStack wave, May 2026)"),
    (os.path.expanduser("~/Library/LaunchAgents/com.user.kitty-monitor.plist"), "kitty-monitor (AntV/atool wave, May 2026)"),
    (os.path.expanduser("~/.config/systemd/user/kitty-monitor.service"), "kitty-monitor (AntV/atool wave, May 2026)"),
    (os.path.expanduser("~/.local/bin/kitty-monitor.sh"), "kitty-monitor (AntV/atool wave, May 2026)"),
    (os.path.expanduser("~/.config/kitty-monitor/token"), "kitty-monitor (AntV/atool wave, May 2026)"),
    (os.path.expanduser("~/.config/kitty-monitor"), "kitty-monitor (AntV/atool wave, May 2026)"),
    (os.path.expanduser("~/.local/share/kitty/cat.py"), "kitty-monitor payload (AntV/atool wave, May 2026)"),
    ("/var/tmp/.gh_update_state", "kitty-monitor dead-drop state file (AntV/atool wave, May 2026)"),
]

# Known-malicious SHA-256 payload hashes for the family's priority payload
# filenames, quoted from the reference detector's MALICIOUS_HASHLIST and
# check_bun_attack_files(). Only files whose basename is in
# HASHED_PAYLOAD_BASENAMES are hashed, mirroring README step 4: "Hash priority
# files (bundle.js, setup_bun.js, router_init.js, tanstack_runner.js, cat.py,
# node-ipc.cjs, etc.) and compare against 20 known-malicious SHA-256s."
# The detector's two self-test fixture hashes are deliberately excluded.
WORM_PAYLOAD_HASHES = {
    # Shai-Hulud v1 bundle.js payload stages (source comment on MALICIOUS_HASHLIST:
    # socket.dev "ongoing-supply-chain-attack-targets-crowdstrike-npm-packages")
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6": "Shai-Hulud v1 worm payload (September 2025)",
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3": "Shai-Hulud v1 worm payload (September 2025)",
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e": "Shai-Hulud v1 worm payload (September 2025)",
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db": "Shai-Hulud v1 worm payload (September 2025)",
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c": "Shai-Hulud v1 worm payload (September 2025)",
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09": "Shai-Hulud v1 worm payload (September 2025)",
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777": "Shai-Hulud v1 worm payload (September 2025)",
    # "Shai-Hulud: The Second Coming" fake-Bun wave (check_bun_attack_files,
    # Koi.ai incident report)
    "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a": "Second Coming setup_bun.js dropper (Koi.ai IOC, November 2025)",
    "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0": "Second Coming bun_environment.js payload (Koi.ai IOC, November 2025)",
    "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068": "Second Coming bun_environment.js payload (Koi.ai IOC, November 2025)",
    "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd": "Second Coming bun_environment.js payload (Koi.ai IOC, November 2025)",
    # Mini Shai-Hulud waves (MALICIOUS_HASHLIST inline comments)
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c": "Mini Shai-Hulud router_init.js (StepSecurity IOC, May 2026)",
    "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96": "Mini Shai-Hulud tanstack_runner.js (StepSecurity IOC, May 2026)",
    "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c": "Mini Shai-Hulud 498KB obfuscated Bun bundle (SafeDep IOC, AntV/atool wave, May 2026)",
}

HASHED_PAYLOAD_BASENAMES = frozenset({
    "bundle.js", "setup_bun.js", "bun_installer.js", "bun_environment.js",
    "environment_source.js", "router_init.js", "tanstack_runner.js", "cat.py",
})

# Cap per-file hashing so an attacker cannot stall the scan with a huge file.
# bun_environment.js is ~10MB, so the cap has generous headroom.
MAX_HASHED_FILE_BYTES = 64 * 1024 * 1024

# Known RAT binary paths (per platform)
RAT_BINARY_PATHS = [
    "/Library/Caches/com.apple.act.mond",              # macOS axios RAT
    os.path.expandvars("%PROGRAMDATA%/wt.exe"),         # Windows axios RAT
    os.path.expanduser("~/.config/sysmon/sysmon.py"),   # liteLLM persistence
]

# C2 domains/IPs to check in npm logs
C2_INDICATORS = [
    "sfrclak.com",
    "142.11.206.73",
    "api.cloud-aws.adc-e.uk",
]

# Compromised versions (version in lockfile vs tampered package.json)
VERSION_MISMATCHES = {
    "plain-crypto-js": {"real": "4.2.1", "tampered": "4.2.0"},
}


def _read_installed_version(pkg_dir):
    """Read the version from an installed package's package.json."""
    pj = os.path.join(pkg_dir, "package.json")
    try:
        with open(pj, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data.get("version", "")
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return ""


def scan_node_modules(repo_path):
    """Check for known malicious package directories in node_modules."""
    findings = []
    for root, dirs, _files in os.walk(repo_path, followlinks=False):
        if 'node_modules' not in root:
            dirs[:] = [d for d in dirs if d != '.git']
            continue

        # Entirely malicious packages (any version is bad)
        for pkg_name, description in MALICIOUS_PACKAGES.items():
            pkg_dir = os.path.join(root, pkg_name)
            if os.path.isdir(pkg_dir):
                rel = os.path.relpath(pkg_dir, repo_path).replace(os.sep, "/")
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"Compromised Package Installed: {pkg_name}",
                    description=f"Directory exists in node_modules ({description}). The dropper likely already executed.",
                    file=rel, line=0,
                    snippet=f"node_modules/{pkg_name}/ directory present",
                    category="post-incident"
                ))

        # Version-pinned packages (only specific versions are compromised)
        for pkg_name, info in VERSION_PINNED_MALICIOUS.items():
            pkg_dir = os.path.join(root, pkg_name)
            if os.path.isdir(pkg_dir):
                installed_ver = _read_installed_version(pkg_dir)
                if installed_ver in info["versions"]:
                    rel = os.path.relpath(pkg_dir, repo_path).replace(os.sep, "/")
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Compromised Package Installed: {pkg_name}@{installed_ver}",
                        description=f"Compromised version {installed_ver} installed ({info['desc']}). The dropper likely already executed.",
                        file=rel, line=0,
                        snippet=f"node_modules/{pkg_name}@{installed_ver}",
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
    index_entries = os.path.join(npm_cache, "index-v5")
    if os.path.isdir(index_entries):
        for root, _dirs, files in os.walk(index_entries):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read(4096)

                    # Entirely malicious packages (any version)
                    for pkg_name, desc in MALICIOUS_PACKAGES.items():
                        # Match on tarball URL pattern to avoid substring false positives
                        if f"/{pkg_name}/-/" in content or f"/{pkg_name}" in content.split('"key"')[0]:
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

                    # Version-pinned packages (check version in tarball URL)
                    for pkg_name, info in VERSION_PINNED_MALICIOUS.items():
                        for ver in info["versions"]:
                            tarball_fragment = f"{pkg_name}/-/{pkg_name.split('/')[-1]}-{ver}.tgz"
                            if tarball_fragment in content:
                                findings.append(core.Finding(
                                    scanner=SCANNER_NAME, severity="critical",
                                    title=f"Compromised Package in npm Cache: {pkg_name}@{ver}",
                                    description=f"npm cache contains tarball for '{pkg_name}@{ver}' ({info['desc']}). Compromised version was downloaded.",
                                    file=os.path.relpath(fpath, os.path.expanduser("~")),
                                    line=0,
                                    snippet=f"Cache entry: {tarball_fragment}",
                                    category="post-incident"
                                ))
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


def scan_shai_hulud_artifacts():
    """Check for Mini Shai-Hulud (TeamPCP Wave 6) post-incident artifacts."""
    findings = []

    # Anti-re-execution lock file
    lock_path = os.path.join(tempfile.gettempdir(), "tmp.987654321.lock")
    if os.path.exists(lock_path):
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Mini Shai-Hulud: Lock File Found",
            description=f"Anti-re-execution lock file exists at {lock_path}. "
                "This machine was infected by the Mini Shai-Hulud worm (TeamPCP Wave 6)",
            file=lock_path, line=0,
            snippet=f"Lock file present: {lock_path}",
            category="post-incident"
        ))

    # Self-hosted runner installation directory
    runner_dir = os.path.expanduser("~/.dev-env")
    if os.path.isdir(runner_dir):
        runner_file = os.path.join(runner_dir, ".runner")
        confirmed = False
        if os.path.exists(runner_file) and not os.path.islink(runner_file):
            try:
                with open(runner_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read(4096)
                if 'SHA1HULUD' in content:
                    confirmed = True
            except OSError:
                pass
        severity = "critical" if confirmed else "high"
        desc = ("Runner config contains 'SHA1HULUD' name (confirmed TeamPCP Wave 6)"
                if confirmed else "GHA self-hosted runner directory exists (investigate)")
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity=severity,
            title="Mini Shai-Hulud: GHA Runner Installation",
            description=f"{desc} at {runner_dir}",
            file=runner_dir, line=0,
            snippet=f"Directory exists: {runner_dir}",
            category="post-incident"
        ))

    return findings


def scan_second_coming_artifacts(repo_path):
    """Check for "Shai-Hulud: The Second Coming" dropper and exfil artifacts on disk.

    Walks the full tree including node_modules, since the fake-Bun dropper stages
    itself inside installed packages and its artifacts outlive the package that
    delivered them. Filename presence alone is a post-incident indicator: these
    names have no legitimate use.
    """
    findings = []
    for root, dirs, files in os.walk(repo_path, followlinks=False):
        dirs[:] = [d for d in dirs if d != '.git']
        for fname in files:
            desc = SECOND_COMING_ARTIFACTS.get(fname)
            if desc is None:
                continue
            fpath = os.path.join(root, fname)
            if os.path.islink(fpath):
                continue
            rel = os.path.relpath(fpath, repo_path).replace(os.sep, "/")
            try:
                size = os.path.getsize(fpath)
            except OSError:
                size = 0
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=f"Shai-Hulud Second Coming Artifact: {fname}",
                description=f"{desc}. Presence of this file means the fake-Bun dropper "
                    "was staged or executed here. Assume every credential reachable "
                    "from this machine (GitHub PATs, npm tokens, cloud keys) is stolen.",
                file=rel, line=0,
                snippet=f"File present: {rel} ({size} bytes)",
                category="post-incident"
            ))
    return findings


def _sha256_file(fpath):
    """Stream a SHA-256 for fpath, or None if unreadable / over the size cap."""
    try:
        if os.path.getsize(fpath) > MAX_HASHED_FILE_BYTES:
            return None
        digest = hashlib.sha256()
        with open(fpath, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def scan_shai_hulud_family_artifacts(repo_path):
    """Check for Shai-Hulud family artifacts left on disk outside the Second Coming wave.

    Sibling of scan_second_coming_artifacts(). Walks the whole tree including
    node_modules, because these files outlive the package that delivered them:

      * v1 (September 2025): shai-hulud-workflow.yml.
      * Mini waves (April-May 2026): router_init.js, tanstack_runner.js, and the
        gh-token-monitor / kitty-monitor dead-man's-switch units.
      * Second Coming: formatter_<digits>.yml workflows injected under
        .github/workflows/.
      * Any wave: a staged TruffleHog binary (upstream check_trufflehog_activity
        flags "*trufflehog*" filenames as HIGH RISK).
    """
    findings = []
    for root, dirs, files in os.walk(repo_path, followlinks=False):
        dirs[:] = [d for d in dirs if d != '.git']
        in_workflows = root.replace(os.sep, '/').endswith('/.github/workflows')
        for fname in files:
            fpath = os.path.join(root, fname)
            if os.path.islink(fpath):
                continue
            rel = os.path.relpath(fpath, repo_path).replace(os.sep, "/")

            entry = SHAI_HULUD_FAMILY_ARTIFACTS.get(fname)
            if entry is not None:
                severity, desc = entry
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity=severity,
                    title=f"Shai-Hulud Family Artifact: {fname}",
                    description=f"{desc}. This file has no legitimate use. If it names a "
                        "dead-man's-switch daemon (gh-token-monitor / kitty-monitor), stop "
                        "and remove the service BEFORE rotating any credential: revoking "
                        "the monitored token is what triggers the wipe.",
                    file=rel, line=0,
                    snippet=f"File present: {rel}",
                    category="post-incident"
                ))
                continue

            # ~/.local/share/kitty/cat.py staged inside the tree. Bare cat.py is
            # too common to flag, so the kitty/ parent directory is required.
            if fname == "cat.py" and root.replace(os.sep, '/').endswith('/kitty'):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="Shai-Hulud Family Artifact: kitty/cat.py",
                    description="Mini Shai-Hulud dead-man's-switch payload "
                        "(~/.local/share/kitty/cat.py, AntV/atool wave, May 2026). Stop and "
                        "remove the kitty-monitor service BEFORE rotating any credential.",
                    file=rel, line=0,
                    snippet=f"File present: {rel}",
                    category="post-incident"
                ))
                continue

            if in_workflows and FORMATTER_WORKFLOW_RE.match(fname):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"Shai-Hulud Family Artifact: {fname}",
                    description="Injected GitHub Actions workflow matching the "
                        "'Shai-Hulud: The Second Coming' formatter_<digits>.yml pattern "
                        "(November 2025). The workflow runs on the attacker's schedule and "
                        "exfiltrates repository secrets.",
                    file=rel, line=0,
                    snippet=f"File present: {rel}",
                    category="post-incident"
                ))
                continue

            if 'trufflehog' in fname.lower():
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Staged TruffleHog Binary: {fname}",
                    description="A TruffleHog artifact is staged inside this tree. The "
                        "Shai-Hulud family downloads TruffleHog at install time and runs it "
                        "over the filesystem to harvest GitHub PATs, npm tokens and cloud "
                        "keys before exfiltration. Confirm this is a deliberate developer "
                        "install and not dropper residue.",
                    file=rel, line=0,
                    snippet=f"File present: {rel}",
                    category="post-incident"
                ))

    return findings


def scan_worm_payload_hashes(repo_path):
    """Confirm family payloads by SHA-256, not just by filename.

    Only files whose basename is in HASHED_PAYLOAD_BASENAMES are hashed, so the
    cost is bounded no matter how large the tree. A hit here is confirmation-grade
    evidence: the bytes match a published IOC, so it cannot be a name collision.
    Emits nothing when no hash matches.
    """
    findings = []
    for root, dirs, files in os.walk(repo_path, followlinks=False):
        dirs[:] = [d for d in dirs if d != '.git']
        for fname in files:
            if fname not in HASHED_PAYLOAD_BASENAMES:
                continue
            fpath = os.path.join(root, fname)
            if os.path.islink(fpath):
                continue
            digest = _sha256_file(fpath)
            if digest is None:
                continue
            desc = WORM_PAYLOAD_HASHES.get(digest)
            if desc is None:
                continue
            rel = os.path.relpath(fpath, repo_path).replace(os.sep, "/")
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=f"Confirmed Malicious Payload Hash: {fname}",
                description=f"SHA-256 matches a published Shai-Hulud IOC: {desc}. This is "
                    "byte-level confirmation, not a filename heuristic. Assume every "
                    "credential reachable from this machine is stolen.",
                file=rel, line=0,
                snippet=f"SHA256={digest}",
                category="post-incident"
            ))
    return findings


def scan_worm_repo_markers(repo_path):
    """Check git repositories for Shai-Hulud repo/branch/staging markers.

    Ported from the reference detector's check_shai_hulud_repos() (repo name,
    remote URL, double-Base64 data.json) and check_git_branches() (branch names
    matching *shai-hulud*). The worm pushes a "shai-hulud" branch and creates
    exfil repos under the victim's own GitHub account, so these markers survive
    even after the delivering package is removed.
    """
    findings = []
    for root, dirs, _files in os.walk(repo_path, followlinks=False):
        if '.git' not in dirs:
            continue
        git_dir = os.path.join(root, '.git')
        if not os.path.isdir(git_dir):
            continue
        rel_root = os.path.relpath(root, repo_path).replace(os.sep, "/")

        # Repository directory name (check_shai_hulud_repos: repo_name == *shai-hulud*)
        if 'shai-hulud' in os.path.basename(root).lower():
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Shai-Hulud Repository Name",
                description="Git repository directory name contains 'shai-hulud'. The worm "
                    "creates repositories under this name to stage exfiltrated credentials. "
                    "Confirm this is not a clone of a detection tool before acting.",
                file=rel_root, line=0,
                snippet=f"Repository: {os.path.basename(root)}",
                category="post-incident"
            ))

        # Branch names (check_git_branches: refs/heads/*shai-hulud*)
        heads_dir = os.path.join(git_dir, 'refs', 'heads')
        if os.path.isdir(heads_dir):
            try:
                branch_names = os.listdir(heads_dir)
            except OSError:
                branch_names = []
            for branch in branch_names:
                if 'shai-hulud' in branch.lower() or 'shai_hulud' in branch.lower():
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Shai-Hulud Branch: {branch}",
                        description="A local git branch named after the worm exists. Shai-Hulud "
                            "v1 pushes a 'shai-hulud' branch carrying the exfiltration workflow "
                            "into every repository it can reach with a stolen token.",
                        file=os.path.join(rel_root, '.git', 'refs', 'heads', branch),
                        line=0,
                        snippet=f"Branch: {branch}",
                        category="post-incident"
                    ))

        # Remote URLs (check_shai_hulud_repos: grep shai-hulud in .git/config)
        git_config = os.path.join(git_dir, 'config')
        if os.path.isfile(git_config):
            try:
                with open(git_config, 'r', encoding='utf-8', errors='replace') as f:
                    cfg = f.read(65536)
                if 'shai-hulud' in cfg.lower():
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="medium",
                        title="Shai-Hulud Reference in Git Remote",
                        description="A git remote URL references 'shai-hulud'. This is the worm's "
                            "exfil-repo naming, but it also matches a legitimate clone of a "
                            "Shai-Hulud detection tool. Check the remote's owner before acting.",
                        file=os.path.join(rel_root, '.git', 'config'), line=0,
                        snippet="Remote URL references shai-hulud",
                        category="post-incident"
                    ))
            except OSError:
                pass

        # Double-Base64 data.json at the repo root (check_shai_hulud_repos:
        # head -5 contains "eyJ" and "==")
        data_json = os.path.join(root, 'data.json')
        if os.path.isfile(data_json) and not os.path.islink(data_json):
            try:
                with open(data_json, 'r', encoding='utf-8', errors='replace') as f:
                    sample = ''.join(f.readline() for _ in range(5))
                if 'eyJ' in sample and '==' in sample:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title="Base64-Encoded data.json at Repository Root",
                        description="data.json at a git repository root contains a Base64 JSON "
                            "prefix ('eyJ') and padding. Shai-Hulud commits harvested credentials "
                            "as double-Base64 data.json into an exfil repository under the "
                            "victim's own GitHub account.",
                        file=os.path.join(rel_root, 'data.json'), line=0,
                        snippet=sample.strip()[:120],
                        category="post-incident"
                    ))
            except OSError:
                pass

    return findings


def scan_deadman_switch_host_artifacts():
    """Check host paths for Mini Shai-Hulud dead-man's-switch persistence.

    Ported from check_mini_shai_hulud_indicators() IOC 8. Upstream's warning is
    the reason this check exists at all: "Revoking the monitored token is designed
    to TRIGGER A WIPE -- do not rotate credentials until the service is stopped
    and removed." A scanner that reports credential theft without this finding
    leads the responder straight into the trap.
    """
    findings = []
    for host_path, variant in DEADMAN_HOST_PATHS:
        if not os.path.exists(host_path):
            continue
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title=f"Dead-Man's Switch Installed: {os.path.basename(host_path)}",
            description=f"Mini Shai-Hulud dead-man's-switch artifact for the {variant} variant "
                f"exists at {host_path}. The daemon polls GitHub roughly every 60 seconds and "
                "wipes this host when its monitored token is revoked. DO NOT rotate or revoke "
                "the stolen credential first: stop and remove the LaunchAgent / systemd unit, "
                "delete the payload, then rotate from a host verified clean.",
            file=host_path, line=0,
            snippet=f"Path exists: {host_path}",
            category="post-incident"
        ))
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
                            title="C2 Persistence in LaunchAgent",
                            description=f"LaunchAgent/Daemon references C2 indicator '{c2}'",
                            file=os.path.relpath(plist, "/"), line=0,
                            snippet=f"plist references {c2}",
                            category="post-incident"
                        ))
                if "act.mond" in content or "plain-crypto" in content:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title="RAT Persistence in LaunchAgent",
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

    core.emit_status(args.format, f"[*] Scanning for post-incident artifacts in {repo_path}...")

    all_findings = []

    # Repo-level checks
    all_findings.extend(scan_node_modules(repo_path))
    all_findings.extend(scan_second_coming_artifacts(repo_path))
    all_findings.extend(scan_shai_hulud_family_artifacts(repo_path))
    all_findings.extend(scan_worm_payload_hashes(repo_path))
    all_findings.extend(scan_worm_repo_markers(repo_path))

    # Host-level checks (run regardless of repo path)
    all_findings.extend(scan_npm_cache())
    all_findings.extend(scan_npm_logs())
    all_findings.extend(scan_host_artifacts())
    all_findings.extend(scan_shai_hulud_artifacts())
    all_findings.extend(scan_deadman_switch_host_artifacts())

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
