#!/usr/bin/env python3
"""
pre_scan.py - PreToolUse hook handler for repo-forensics v2.
Lightweight pre-execution gate that blocks known-malicious packages and
pipe-to-shell patterns BEFORE the command runs.

Runs as a Claude Code PreToolUse hook. Reads JSON from stdin, outputs JSON
to stdout. Fast path (<10ms for non-matching commands). IOC-only — no
subprocess calls, no full scans (those run post-execution in auto_scan.py).

Design constraints (all critical for safety):
  - MUST NOT call subprocess or spawn any child process (avoids recursive
    hook triggers and keeps latency under 200ms even on IOC matches)
  - MUST NOT block commands when IOC database is unavailable (graceful
    degradation — approve on error, never silently block legitimate work)
  - MUST output valid JSON to stdout in all code paths (empty {} = approve)
  - MUST exit 0 for approve, exit 2 for block (Claude Code convention)

Created by Alex Greenshpun
"""

import json
import os
import re
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

# --- Pattern Detection ---
# NOTE: These patterns are intentionally duplicated from auto_scan.py.
# pre_scan.py MUST remain standalone (no imports from auto_scan, no subprocess)
# to guarantee <10ms latency and zero recursion risk. If you update patterns
# here, update auto_scan.py too (and vice versa).

INSTALL_PATTERNS = [
    (re.compile(r'pip3?\s+install\s+(.+)'), 'pip_install'),
    (re.compile(r'npm\s+(?:install|i)\s+(.+)'), 'npm_install'),
    (re.compile(r'npm\s+update\s+(.+)'), 'npm_install'),
    (re.compile(r'yarn\s+add\s+(.+)'), 'yarn_add'),
    (re.compile(r'gem\s+(?:install|update)\s+(.+)'), 'gem_install'),
    (re.compile(r'cargo\s+install\s+(.+)'), 'cargo_install'),
    (re.compile(r'go\s+(?:get|install)\s+(.+)'), 'go_install'),
    (re.compile(r'brew\s+(?:install|upgrade)\s+(.+)'), 'brew_install'),
    (re.compile(r'openclaw\s+(?:skills|plugins)\s+(?:install|update)\s+(.+)'), 'openclaw_install'),
    (re.compile(r'clawhub\s+(?:install|publish)\s+(.+)'), 'openclaw_install'),
]

PIPE_TO_SHELL = re.compile(
    r'(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh'
    r'|(?:curl|wget)\s+[^>]*>\s*/tmp/[^\s;]+\s*[;&]\s*(?:sudo\s+)?(?:ba)?sh\s+/tmp/'
)

INSTALL_FLAGS = re.compile(r'\s+--?[a-zA-Z][\w-]*(?:\s+[^\s-][^\s]*)?')


def parse_hook_input():
    """Read and parse PreToolUse JSON from stdin."""
    try:
        raw = sys.stdin.read(1_048_576)  # 1MB max
        if not raw.strip():
            return None
        return json.loads(raw)
    except (json.JSONDecodeError, IOError):
        return None


def extract_command(data):
    """Extract the bash command from hook payload."""
    if not data:
        return None
    if data.get('tool_name', '') != 'Bash':
        return None
    tool_input = data.get('tool_input', {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except json.JSONDecodeError:
            return None
    return tool_input.get('command', '')


def detect_install_command(command):
    """Match command against install patterns.
    Returns (pattern_type, match_obj) or (None, None)."""
    if not command:
        return None, None
    if PIPE_TO_SHELL.search(command):
        return 'pipe_to_shell', None
    for pattern, ptype in INSTALL_PATTERNS:
        m = pattern.search(command)
        if m:
            return ptype, m
    return None, None


def extract_package_names(pattern_type, match):
    """Extract package names from install command match."""
    if not match:
        return []
    if pattern_type not in ('pip_install', 'npm_install', 'yarn_add', 'gem_install',
                            'cargo_install', 'go_install', 'brew_install', 'openclaw_install'):
        return []
    raw = match.group(1)
    cleaned = INSTALL_FLAGS.sub('', raw).strip()
    names = [n.strip() for n in cleaned.split() if n.strip() and not n.startswith('-')]
    if pattern_type == 'pip_install':
        names = [re.split(r'[>=<!\[\];@]', n)[0] for n in names]
    return names


def check_ioc_packages(package_names):
    """Check package names against IOC database. Returns list of malicious names."""
    try:
        import ioc_manager
        iocs = ioc_manager.get_iocs()
    except (ImportError, AttributeError, KeyError, TypeError):
        return []

    malicious_npm = iocs.get('malicious_npm', set())
    malicious_pypi = iocs.get('malicious_pypi', set())
    all_malicious = malicious_npm | malicious_pypi

    blocked = []
    for pkg in package_names:
        if pkg.lower() in all_malicious:
            blocked.append(pkg)
    return blocked


def output_block(reason):
    """Output JSON that tells Claude Code to block the command."""
    result = {
        "decision": "block",
        "reason": reason
    }
    print(json.dumps(result))
    sys.exit(2)


def output_approve():
    """Output empty JSON — command proceeds normally."""
    print('{}')
    sys.exit(0)


def main():
    data = parse_hook_input()
    command = extract_command(data)

    if not command:
        output_approve()
        return

    # Detect install/update pattern (also catches pipe-to-shell)
    pattern_type, match = detect_install_command(command)

    # Pipe-to-shell: instant block
    if pattern_type == 'pipe_to_shell':
        output_block(
            "[repo-forensics] BLOCKED: Command pipes remote content directly "
            "to shell execution. This bypasses all package manager security "
            "checks and can execute arbitrary code."
        )
        return

    if not pattern_type:
        output_approve()
        return

    # Extract package names and check IOC
    package_names = extract_package_names(pattern_type, match)
    if not package_names:
        output_approve()
        return

    blocked_packages = check_ioc_packages(package_names)
    if blocked_packages:
        pkg_list = ', '.join(blocked_packages)
        output_block(
            f"[repo-forensics] BLOCKED: Known malicious package(s) detected: "
            f"{pkg_list}. These packages match the IOC database and should NOT "
            f"be installed. Remove them from the command and try again."
        )
        return

    # No IOC matches — approve
    output_approve()


if __name__ == '__main__':
    main()
