#!/usr/bin/env python3
"""
auto_scan.py - PostToolUse hook handler for repo-forensics v2.
Detects install/clone commands in Bash tool calls and auto-triggers security scans.

Runs as a Claude Code PostToolUse hook. Reads JSON from stdin, outputs JSON to stdout.
Fast path (<10ms for non-matching commands).

Created by Alex Greenshpun
"""

import json
import os
import re
import sys
# subprocess and concurrent.futures are lazy-imported in run_scanner/run_targeted_scan
# to keep the no-match fast path under 10ms

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

# --- Install/Clone Pattern Detection ---

INSTALL_PATTERNS = [
    # git clone
    (re.compile(r'git\s+clone\s+(?:--[^\s]+\s+)*(?:https?://|git@)([^\s]+)(?:\s+([^\s]+))?'), 'git_clone'),
    # git pull (update — scans CWD after pull)
    (re.compile(r'git\s+pull(?:\s|$)'), 'git_pull'),
    # pip install (with package names) — also catches --upgrade
    (re.compile(r'pip3?\s+install\s+(.+)'), 'pip_install'),
    # npm install (with package names)
    (re.compile(r'npm\s+(?:install|i)\s+(.+)'), 'npm_install'),
    # npm update (missed update commands)
    (re.compile(r'npm\s+update\s+(.+)'), 'npm_install'),
    # yarn add
    (re.compile(r'yarn\s+add\s+(.+)'), 'yarn_add'),
    # gem install
    (re.compile(r'gem\s+install\s+(.+)'), 'gem_install'),
    # gem update
    (re.compile(r'gem\s+update\s+(.+)'), 'gem_install'),
    # cargo install
    (re.compile(r'cargo\s+install\s+(.+)'), 'cargo_install'),
    # go get/install
    (re.compile(r'go\s+(?:get|install)\s+(.+)'), 'go_install'),
    # brew install
    (re.compile(r'brew\s+install\s+(.+)'), 'brew_install'),
    # brew upgrade
    (re.compile(r'brew\s+upgrade\s+(.+)'), 'brew_install'),
    # openclaw skills/plugins install or update
    (re.compile(r'openclaw\s+(?:skills|plugins)\s+(?:install|update)\s+(.+)'), 'openclaw_install'),
    # clawhub install
    (re.compile(r'clawhub\s+(?:install|publish)\s+(.+)'), 'openclaw_install'),
]

# Pipe-to-shell patterns (instant CRITICAL)
PIPE_TO_SHELL = re.compile(
    r'(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh'
    r'|(?:curl|wget)\s+[^>]*>\s*/tmp/[^\s;]+\s*[;&]\s*(?:sudo\s+)?(?:ba)?sh\s+/tmp/'
)

# Flags to strip from package names
INSTALL_FLAGS = re.compile(r'\s+--?[a-zA-Z][\w-]*(?:\s+[^\s-][^\s]*)?')


def parse_hook_input():
    """Read and parse PostToolUse JSON from stdin."""
    try:
        raw = sys.stdin.read(1_048_576)  # 1MB max to prevent memory exhaustion
        if not raw.strip():
            return None
        data = json.loads(raw)
        return data
    except (json.JSONDecodeError, IOError):
        return None


def extract_command(data):
    """Extract the bash command from hook payload."""
    if not data:
        return None
    tool_name = data.get('tool_name', '')
    if tool_name != 'Bash':
        return None
    tool_input = data.get('tool_input', {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except json.JSONDecodeError:
            return None
    return tool_input.get('command', '')


def detect_install_command(command):
    """Match command against install/clone patterns.
    Returns (pattern_type, match_obj) or (None, None)."""
    if not command:
        return None, None

    # Check pipe-to-shell first (instant CRITICAL)
    if PIPE_TO_SHELL.search(command):
        return 'pipe_to_shell', None

    for pattern, ptype in INSTALL_PATTERNS:
        m = pattern.search(command)
        if m:
            return ptype, m

    return None, None


def extract_package_names(pattern_type, match):
    """Extract package names from install command match."""
    if pattern_type in ('pip_install', 'npm_install', 'yarn_add', 'gem_install',
                        'cargo_install', 'go_install', 'brew_install', 'openclaw_install'):
        raw = match.group(1)
        # Strip flags
        cleaned = INSTALL_FLAGS.sub('', raw).strip()
        # Split on whitespace, filter empties and flags
        names = [n.strip() for n in cleaned.split() if n.strip() and not n.startswith('-')]
        # Strip version specifiers for pip
        if pattern_type == 'pip_install':
            names = [re.split(r'[>=<!\[\];@]', n)[0] for n in names]
        return names
    return []


def _is_safe_scan_path(resolved_path):
    """Ensure resolved path is within CWD to prevent scanning sensitive directories."""
    from pathlib import PurePath
    cwd = os.getcwd()
    try:
        # PurePath.is_relative_to handles all edge cases (cwd='/', symlinks, etc.)
        p = PurePath(resolved_path)
        return (p.is_relative_to(cwd)
                or p.is_relative_to('/tmp')
                or p.is_relative_to('/private/tmp'))
    except (TypeError, ValueError):
        return False


def extract_clone_target(match):
    """Extract directory path from git clone command."""
    if not match:
        return None
    url = match.group(1)
    explicit_dir = match.group(2) if match.lastindex >= 2 else None

    if explicit_dir:
        resolved = os.path.realpath(explicit_dir)
    else:
        # Derive directory from URL
        repo_name = url.rstrip('/').split('/')[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        resolved = os.path.realpath(repo_name)

    # Path containment: refuse to scan outside CWD or /tmp
    if not _is_safe_scan_path(resolved):
        return None
    return resolved


def check_ioc_packages(package_names):
    """Check package names against IOC database. Returns findings list."""
    try:
        import ioc_manager
        iocs = ioc_manager.get_iocs()
    except ImportError:
        return []

    findings = []
    malicious_npm = iocs.get('malicious_npm', set())
    malicious_pypi = iocs.get('malicious_pypi', set())
    all_malicious = malicious_npm | malicious_pypi

    for pkg in package_names:
        pkg_lower = pkg.lower()
        if pkg_lower in all_malicious:
            findings.append({
                'scanner': 'auto_scan',
                'severity': 'critical',
                'title': f"Known Malicious Package: '{pkg}'",
                'description': f"Package '{pkg}' matches IOC database. DO NOT INSTALL.",
                'file': 'N/A',
                'line': 0,
                'snippet': f"'{pkg}' is a known malicious package (IOC match)",
                'category': 'known-ioc'
            })

        # Also check for liteLLM specifically
        if pkg_lower == 'litellm':
            findings.append({
                'scanner': 'auto_scan',
                'severity': 'critical',
                'title': f"Supply Chain Risk: '{pkg}' (liteLLM)",
                'description': "liteLLM had a malicious .pth file injection in v1.82.8 (March 2026). "
                               "Verify version is not compromised before installing.",
                'file': 'N/A',
                'line': 0,
                'snippet': "liteLLM PyPI supply chain attack: .pth file auto-exfiltrates credentials",
                'category': 'supply-chain'
            })

    return findings


def run_scanner(scanner_script, repo_path):
    """Run a single scanner and return parsed findings."""
    import subprocess
    script_path = os.path.join(SCRIPTS_DIR, scanner_script)
    if not os.path.exists(script_path):
        return []

    try:
        result = subprocess.run(
            [sys.executable, script_path, repo_path, '--format', 'json'],
            capture_output=True, text=True, timeout=15,
            cwd=SCRIPTS_DIR
        )
        if result.returncode <= 2 and result.stdout.strip():
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass
    return []


def run_targeted_scan(repo_path):
    """Run 6 targeted scanners in parallel on a cloned/installed repo."""
    if not os.path.isdir(repo_path):
        return []

    targeted_scanners = [
        'scan_dependencies.py',
        'scan_secrets.py',
        'scan_lifecycle.py',
        'scan_skill_threats.py',
        'scan_manifest_drift.py',
        'scan_runtime_dynamism.py',
    ]

    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_findings = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(run_scanner, s, repo_path): s
            for s in targeted_scanners
        }
        for future in as_completed(futures):
            try:
                findings = future.result()
                if isinstance(findings, list):
                    all_findings.extend(findings)
            except Exception as e:
                print(f"[!] Scanner {futures[future]} failed: {e}", file=sys.stderr)

    # Run correlation engine on collected findings to detect compound threats.
    # Uses the shared findings_from_dicts helper to stay in sync with
    # aggregate_json.run_correlation_pass (PR-F1, 2026-04-05).
    try:
        import forensics_core as core
        finding_objs = core.findings_from_dicts(all_findings)
        if finding_objs:
            correlated = core.correlate(finding_objs)
            all_findings.extend(cf.to_dict() for cf in correlated)
    except (ImportError, AttributeError, KeyError, TypeError, ValueError) as e:
        print(f"[!] Correlation failed: {e}", file=sys.stderr)

    return all_findings


def build_pipe_to_shell_warning(command):
    """Build CRITICAL warning for pipe-to-shell commands."""
    return [{
        'scanner': 'auto_scan',
        'severity': 'critical',
        'title': 'Pipe-to-Shell Execution Detected',
        'description': (
            'Command pipes remote content directly to shell execution. '
            'This bypasses all package manager security checks and can execute '
            'arbitrary code. NEVER pipe untrusted URLs to shell.'
        ),
        'file': 'N/A',
        'line': 0,
        'snippet': command[:200] if command else '',
        'category': 'pipe-to-shell'
    }]


def format_output(findings, command='', pattern_type=''):
    """Format findings as hook JSON output with additionalContext."""
    if not findings:
        return '{}'

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings.sort(key=lambda f: severity_order.get(f.get('severity', 'low'), 3))

    critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
    high_count = sum(1 for f in findings if f.get('severity') == 'high')

    # Build summary
    lines = []
    lines.append(f"## repo-forensics auto-scan: {len(findings)} finding(s)")
    if pattern_type:
        lines.append(f"Triggered by: `{pattern_type}` command")
    lines.append("")

    for f in findings[:15]:  # Cap at 15 findings for readability
        sev = f.get('severity', 'low').upper()
        lines.append(f"**[{sev}]** {f.get('title', 'Unknown')}")
        lines.append(f"  {f.get('description', '')}")
        if f.get('snippet'):
            lines.append(f"  `{f['snippet'][:120]}`")
        lines.append("")

    if len(findings) > 15:
        lines.append(f"... and {len(findings) - 15} more findings. Run full scan for details.")

    if critical_count > 0:
        lines.append(f"**VERDICT: {critical_count} CRITICAL finding(s). Do not proceed without review.**")
    elif high_count > 0:
        lines.append(f"**VERDICT: {high_count} HIGH finding(s). Review before proceeding.**")

    output = {
        'additionalContext': '\n'.join(lines)
    }
    return json.dumps(output)


def main():
    # Parse hook input
    data = parse_hook_input()
    command = extract_command(data)

    if not command:
        print('{}')
        sys.exit(0)

    # Detect install/clone pattern
    pattern_type, match = detect_install_command(command)

    if not pattern_type:
        print('{}')
        sys.exit(0)

    # Pipe-to-shell: instant CRITICAL, no scan needed
    if pattern_type == 'pipe_to_shell':
        findings = build_pipe_to_shell_warning(command)
        print(format_output(findings, command, pattern_type))
        sys.exit(0)

    all_findings = []

    # For package install commands: check IOC list
    package_names = []
    if pattern_type != 'git_clone':
        package_names = extract_package_names(pattern_type, match)
        if package_names:
            ioc_findings = check_ioc_packages(package_names)
            all_findings.extend(ioc_findings)

    # For git clone: scan the cloned directory
    if pattern_type == 'git_clone':
        clone_dir = extract_clone_target(match)
        if clone_dir and os.path.isdir(clone_dir):
            scan_findings = run_targeted_scan(clone_dir)
            all_findings.extend(scan_findings)

    # For git pull: scan CWD (repo was updated with potentially changed code)
    if pattern_type == 'git_pull':
        cwd = os.getcwd()
        if os.path.isdir(cwd) and _is_safe_scan_path(cwd):
            scan_findings = run_targeted_scan(cwd)
            all_findings.extend(scan_findings)

    # For pip/npm install with a local path: scan it (with path containment)
    if pattern_type in ('pip_install', 'npm_install'):
        for pkg in package_names:
            pkg_path = os.path.realpath(pkg)
            if os.path.isdir(pkg_path) and _is_safe_scan_path(pkg_path):
                scan_findings = run_targeted_scan(pkg_path)
                all_findings.extend(scan_findings)

    print(format_output(all_findings, command, pattern_type))
    sys.exit(0)


if __name__ == '__main__':
    main()
