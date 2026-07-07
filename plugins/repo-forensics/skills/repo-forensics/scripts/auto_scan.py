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

# Optional package-manager flags that can sit between the tool name and its
# subcommand, e.g. `pnpm -r add x`, `pnpm --filter web add x`,
# `uv --project /p add x`. Each unit is one -flag (whose first char after the
# leading dash(es) is a non-dash — this makes dash runs fail fast and avoids
# ReDoS) plus an OPTIONAL value token that must NOT itself be a subcommand
# keyword (the lookahead stops a flag value from swallowing `add`/`install`).
# Kept identical in pre_scan.py — update both.
_PM_FLAGS = (
    r'(?:-{1,2}[^-\s]\S*'
    r'(?:\s+(?!(?:install|i|add|update|sync|pip|tool|remove|run)\b)[^-\s]\S*)?'
    r'\s+)*'
)

INSTALL_PATTERNS = [
    # git clone
    (re.compile(r'git\s+clone\s+(?:--[^\s]+\s+)*(?:https?://|git@)([^\s]+)(?:\s+([^\s]+))?'), 'git_clone'),
    # git pull (update — scans CWD after pull)
    (re.compile(r'git\s+pull(?:\s|$)'), 'git_pull'),
    # uv add / uv pip install / uv tool install — must precede pip: patterns are
    # unanchored, so 'uv pip install x' substring-matches the pip entry.
    # _PM_FLAGS allows global options before the subcommand (`uv --project p add x`).
    (re.compile(r'uv\s+' + _PM_FLAGS + r'(?:add|pip\s+install|tool\s+install)\s+(.+)'), 'uv_install'),
    # uv sync (lockfile install — scans CWD after sync, like git_pull)
    (re.compile(r'uv\s+sync(?:\s|$)'), 'uv_sync'),
    # pip install (with package names) — also catches --upgrade
    (re.compile(r'pip3?\s+install\s+(.+)'), 'pip_install'),
    # pnpm install/add/update — must precede npm: 'pnpm install x'
    # substring-matches the npm entry. _PM_FLAGS covers monorepo/workspace
    # forms: `pnpm -r add x`, `pnpm --filter web add x`.
    (re.compile(r'pnpm\s+' + _PM_FLAGS + r'(?:install|i|add|update)\s+(.+)'), 'pnpm_install'),
    # bun install/add/update
    (re.compile(r'bun\s+' + _PM_FLAGS + r'(?:install|i|add|update)\s+(.+)'), 'bun_install'),
    # npm install (with package names)
    (re.compile(r'npm\s+(?:install|i)\s+(.+)'), 'npm_install'),
    # npm update (missed update commands)
    (re.compile(r'npm\s+update\s+(.+)'), 'npm_install'),
    # Bare lockfile installs (no package args) — scan CWD like uv_sync/git_pull.
    # MUST come after the with-args npm/pnpm/bun entries above so
    # 'pnpm install express' still classifies as pnpm_install. Anchored to
    # end-of-command (optionally trailing flags) so it only fires for the
    # arg-less form: `npm install`, `npm ci`, `pnpm install --frozen-lockfile`,
    # `bun install`, and `cd app && pnpm install`.
    (re.compile(r'(?:npm|pnpm|bun)\s+(?:ci|install|i)(?:\s+--?\S+)*\s*$'), 'lockfile_install'),
    (re.compile(r'yarn(?:\s+install)?(?:\s+--?\S+)*\s*$'), 'lockfile_install'),
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
    # claude plugins install/update/add (CLI variants: `claude plugins install`,
    # `claude plugins:install`, `claude /plugins install`, `claude plugins enable`)
    (re.compile(r'claude\s+/?plugins[:\s]+(?:install|update|add|enable)\s+(.+)'), 'claude_plugin_install'),
]

# Pipe-to-shell patterns (instant CRITICAL)
_DOWNLOADERS = r'(?:curl|wget|aria2c|http|Invoke-WebRequest)'
_SHELLS = r'(?:sudo\s+)?(?:/[\w/.-]*/)?(?:bash|zsh|dash|ksh|csh|tcsh|fish|pwsh|sh)(?!\w)'
_BASE64_PIPE = r'base64\s+(?:-d|--decode)\s*\|'

PIPE_TO_SHELL = re.compile(
    r'(?:'
    r'(?:' + _DOWNLOADERS + r')\s+[^|]*\|\s*(?:' + _BASE64_PIPE + r'\s*)?(?:' + _SHELLS + r'|iex)'
    r'|' + _BASE64_PIPE + r'\s*(?:' + _SHELLS + r'|iex)'
    r'|(?:' + _DOWNLOADERS + r')\s+[^>]*>\s*/tmp/[^\s;]+\s*(?:;|&&?)\s*(?:' + _SHELLS + r')\s+/tmp/'
    r')',
    re.IGNORECASE,
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
                        'cargo_install', 'go_install', 'brew_install', 'openclaw_install',
                        'claude_plugin_install', 'uv_install', 'bun_install', 'pnpm_install'):
        raw = match.group(1)
        # Strip flags
        cleaned = INSTALL_FLAGS.sub('', raw).strip()
        # Split on whitespace, filter empties and flags
        names = [n.strip() for n in cleaned.split() if n.strip() and not n.startswith('-')]
        # Strip version specifiers for pip; .strip() handles `pkg @ url` form
        # which leaves trailing whitespace after the @ split.
        if pattern_type in ('pip_install', 'uv_install'):
            names = [re.split(r'[>=<!\[\];@]', n)[0].strip() for n in names]
            names = [n for n in names if n]
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


def _scan_incomplete_finding(scanner_script, reason):
    """Build a LOUD synthetic finding for a scanner that failed to complete.

    A scanner that times out, is killed by a signal (SIGKILL/OOM), exits with
    an error code, or emits unparseable JSON used to return [] silently here —
    meaning the user got a CLEAN verdict with NO indication the scan was
    incomplete. That is a detection bypass: an attacker who pushes any scanner
    past the 15s wall-clock (or OOMs it) thereby SUPPRESSES all of that
    scanner's findings without a trace. Fail LOUD instead: emit a high-severity
    finding so the verdict flips and the gap is visible. (Closes the
    "SIGKILL -> silent zero" class; torture 2026-06-17.)
    """
    name = scanner_script[:-3] if scanner_script.endswith('.py') else scanner_script
    return [{
        'scanner': name,
        'severity': 'high',
        'title': 'Scanner did not complete — results may be incomplete',
        'description': (
            f"{name} {reason}; its findings are MISSING from this report. "
            f"A repo can trigger this (e.g. by making the scanner overrun its "
            f"time budget or exhaust memory) to suppress detection, so treat a "
            f"clean verdict from this scan as UNTRUSTWORTHY for {name}'s surface. "
            f"Re-run the scanner in isolation to obtain complete results."
        ),
        'file': '',
        'line': 0,
        'snippet': '',
        'category': 'scan-incomplete',
    }]


def run_scanner(scanner_script, repo_path):
    """Run a single scanner and return parsed findings.

    On any failure mode that would otherwise yield a SILENT empty result
    (timeout, signal-kill, scanner error, unparseable JSON on non-empty stdout,
    or a NON-zero exit with empty stdout — the uncaught-exception crash door),
    returns a LOUD synthetic 'scan-incomplete' finding instead of [] so the
    incompleteness surfaces in the verdict. A clean [] is returned when rc==0
    with empty stdout, or whenever stdout parses to valid JSON (including an
    empty list) at rc<=2 — a scanner may exit non-zero while still emitting its
    findings JSON, and that output is trusted. The crash door is specifically a
    NON-zero exit with EMPTY or unparseable stdout, which now fails loud.
    """
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
    except subprocess.TimeoutExpired:
        return _scan_incomplete_finding(
            scanner_script, "TIMED OUT (exceeded the 15s wall-clock budget)")
    except OSError as e:
        return _scan_incomplete_finding(
            scanner_script, f"could not be launched (OSError: {e})")

    rc = result.returncode
    # Killed by a signal: subprocess returncode is negative (e.g. -9 = SIGKILL,
    # the classic OOM / wall-clock kill). This is the core silent-zero vector.
    if rc < 0:
        return _scan_incomplete_finding(
            scanner_script,
            f"was KILLED by signal {-rc} (e.g. SIGKILL/OOM or wall-clock kill)")
    # Scanner errored out (rc > 2 is outside the success/findings-present band).
    if rc > 2:
        return _scan_incomplete_finding(
            scanner_script, f"exited with error code {rc}")

    out = result.stdout.strip()
    if not out:
        # ONLY rc==0 with empty stdout is a legitimate "ran clean, found
        # nothing" result. A NON-zero rc with EMPTY stdout means the scanner
        # did NOT produce results — the classic uncaught-exception crash exits
        # rc==1 (or 2) and writes its traceback to STDERR, leaving stdout empty.
        # Treating that as "[] = benign" silently suppresses the whole scanner:
        # the same silent-zero detection-bypass class as the timeout/SIGKILL
        # doors, just via the crash door. Fail LOUD instead. (P1, CE review
        # 2026-06-17.)
        if rc == 0:
            return []
        return _scan_incomplete_finding(
            scanner_script,
            f"exited non-zero (rc {rc}) with no output — likely crashed")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return _scan_incomplete_finding(
            scanner_script, "produced UNPARSEABLE JSON output")


def run_targeted_scan(repo_path):
    """Run 14 targeted scanners in parallel on a cloned/installed repo."""
    if not os.path.isdir(repo_path):
        return []

    targeted_scanners = [
        'scan_dependencies.py',
        'scan_secrets.py',
        'scan_lifecycle.py',
        'scan_skill_threats.py',
        'scan_manifest_drift.py',
        'scan_runtime_dynamism.py',
        'scan_agent_skills.py',
        'scan_sast.py',
        'scan_mcp_security.py',
        'scan_infra.py',
        'scan_entrypoint.py',
        'scan_oversize.py',
        'scan_splitstream.py',
        'scan_provenance.py',
        'scan_archive.py',
        'scan_bytecode.py',
        'scan_dead_anchors.py',
    ]

    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_findings = []
    with ThreadPoolExecutor(max_workers=10) as executor:
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

    # Raw-content correlation fallbacks (Lethal Trifecta + registry hijack), run
    # before correlate() so the hook path has the same raw-content feed as the
    # full-scan build_report path. Without these the PostToolUse hook gives a
    # false-clean on registry-hijack and trifecta payloads at install time — the
    # exact moment interception matters most.
    try:
        import forensics_core as core
        all_findings.extend(f.to_dict() for f in core.detect_trifecta_raw(repo_path))
        all_findings.extend(f.to_dict() for f in core.detect_registry_hijack_raw(repo_path))
    except (ImportError, OSError, AttributeError) as e:
        print(f"[!] Raw-content scan failed: {e}", file=sys.stderr)

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


def format_output(findings, command='', pattern_type='', scanned_target=''):
    """Format scan results as plain text so Claude Code surfaces it to the model.

    Always produces output when a scan ran (even if clean) so the model knows
    the security check happened. Returns empty string only when no scan was
    triggered (non-matching command).
    """
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

    if not findings:
        if scanned_target:
            return f"[repo-forensics] auto-scan complete: {scanned_target} — no issues found."
        return ''

    findings.sort(key=lambda f: severity_order.get(f.get('severity', 'low'), 3))

    critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
    high_count = sum(1 for f in findings if f.get('severity') == 'high')

    lines = []
    lines.append(f"[repo-forensics] auto-scan: {len(findings)} finding(s)")
    if pattern_type:
        lines.append(f"Triggered by: {pattern_type} command")

    # Sanitize the scanner-authored title/description (defense in depth) and do
    # NOT echo the raw `snippet` here. The snippet is the attacker-controlled
    # payload; the only place it appears is inside the injection-safe
    # adjudication block below, behind the `> SNIPPET: ` prefix. Echoing it
    # unprefixed in this summary list would reintroduce the exact prompt-injection
    # surface U8 closes ("no unprefixed attacker text anywhere in the output").
    try:
        import adjudication as _adj
        _clean = _adj.sanitize_snippet
    except ImportError:
        # B4 fix: inline fallback must cover \r, U+2028/2029, BIDI, C1 range,
        # and collapse all whitespace/line-separator chars to a single space.
        # Kept self-contained since the import failed.
        import re as _re
        _FALLBACK_CTRL_RE = _re.compile(
            r"[\x00-\x1f\x7f\x80-\x9f  ‪-‮⁦-⁩⁠-⁤﻿]"
        )

        def _clean(text, max_len=160):
            if not isinstance(text, str):
                return ""
            cleaned = _FALLBACK_CTRL_RE.sub("", text or "")
            cleaned = _re.sub(r"\s+", " ", cleaned).strip()
            return cleaned[:max_len]

    for f in findings[:15]:
        sev = f.get('severity', 'low').upper()
        title = _clean(f.get('title', 'Unknown'), max_len=160)
        desc = _clean(f.get('description', ''), max_len=300)
        lines.append(f"[{sev}] {title}: {desc}")

    if len(findings) > 15:
        lines.append(f"... and {len(findings) - 15} more findings. Run full scan for details.")

    if critical_count > 0:
        lines.append(f"VERDICT: {critical_count} CRITICAL finding(s). Do not proceed without review.")
    elif high_count > 0:
        lines.append(f"VERDICT: {high_count} HIGH finding(s). Review before proceeding.")

    # Adjudication block (U8): WARN-tier findings get an injection-safe block
    # the host agent reads as tool output. auto_scan does not run aggregate_json,
    # so needs_adjudication is not pre-set; the helper falls back to the WARN
    # confidence band and excludes correlation-synthesized findings itself.
    try:
        import adjudication
        block = adjudication.build_adjudication_block(findings)
        if block:
            lines.append(block)
    except ImportError:
        pass

    return '\n'.join(lines)


def main():
    # Parse hook input
    data = parse_hook_input()
    command = extract_command(data)

    if not command:
        sys.exit(0)

    # Detect install/clone pattern
    pattern_type, match = detect_install_command(command)

    if not pattern_type:
        sys.exit(0)

    # Pipe-to-shell: instant CRITICAL, no scan needed
    if pattern_type == 'pipe_to_shell':
        findings = build_pipe_to_shell_warning(command)
        output = format_output(findings, command, pattern_type, scanned_target='pipe-to-shell')
        if output:
            print(output)
        sys.exit(0)

    all_findings = []
    scanned_target = ''

    # For package install commands: check IOC list
    package_names = []
    if pattern_type != 'git_clone':
        package_names = extract_package_names(pattern_type, match)
        if package_names:
            scanned_target = ', '.join(package_names)
            ioc_findings = check_ioc_packages(package_names)
            all_findings.extend(ioc_findings)

    # For git clone: scan the cloned directory
    if pattern_type == 'git_clone':
        clone_dir = extract_clone_target(match)
        if clone_dir and os.path.isdir(clone_dir):
            scanned_target = clone_dir
            scan_findings = run_targeted_scan(clone_dir)
            all_findings.extend(scan_findings)

    # For git pull / uv sync / bare lockfile install: scan CWD (repo or its
    # deps were updated in place from the lockfile — no package args to target).
    # A with-args install that extracted zero packages is also a lockfile
    # install: its args were all flags (`pnpm install --frozen-lockfile`,
    # `npm install --production`) — deps still changed, so scan CWD.
    _lockfile_like = pattern_type in ('git_pull', 'uv_sync', 'lockfile_install') or (
        pattern_type in ('pip_install', 'npm_install', 'uv_install',
                         'bun_install', 'pnpm_install') and not package_names)
    if _lockfile_like:
        cwd = os.getcwd()
        if os.path.isdir(cwd) and _is_safe_scan_path(cwd):
            scanned_target = cwd
            scan_findings = run_targeted_scan(cwd)
            all_findings.extend(scan_findings)

    # For pip/npm-style install with a local path: scan it (with path containment)
    if pattern_type in ('pip_install', 'npm_install', 'uv_install', 'bun_install',
                        'pnpm_install'):
        for pkg in package_names:
            pkg_path = os.path.realpath(pkg)
            if os.path.isdir(pkg_path) and _is_safe_scan_path(pkg_path):
                scanned_target = pkg_path
                scan_findings = run_targeted_scan(pkg_path)
                all_findings.extend(scan_findings)

    output = format_output(all_findings, command, pattern_type, scanned_target)
    if output:
        print(output)
    sys.exit(0)


if __name__ == '__main__':
    main()
