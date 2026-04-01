#!/usr/bin/env python3
"""
scan_lifecycle.py - Lifecycle Script Scanner (v2: rewritten from JS to Python)
Detects malicious NPM hooks and Python setup.py/pyproject.toml cmdclass overrides.
No Bun dependency, all pure Python.

Created by Alex Greenshpun
"""

import os
import re
import sys
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "lifecycle"

DANGEROUS_NPM_HOOKS = ['preinstall', 'postinstall', 'install', 'prepare', 'prepublish', 'postpublish']
SUSPICIOUS_COMMANDS = [
    (re.compile(r'\bcurl\b'), "curl command"),
    (re.compile(r'\bwget\b'), "wget command"),
    (re.compile(r'\bbash\s+-i\b'), "interactive bash"),
    (re.compile(r'/dev/tcp'), "/dev/tcp network"),
    (re.compile(r'\bbase64\s+-d\b.*\|\s*(sh|bash)'), "base64 decode piped to shell"),
    (re.compile(r'\bbase64\b.*\bsh\b'), "base64 with shell execution"),
    (re.compile(r'\bnc\s'), "netcat"),
    (re.compile(r'\bpython\b.*-c'), "python inline execution"),
    (re.compile(r'\bnode\b.*-e'), "node inline execution"),
    (re.compile(r'\beval\b'), "eval command"),
    (re.compile(r'>\s*/dev/null.*2>&1'), "output suppression"),
]

# Anti-forensics patterns: self-destructing installers (Axios supply chain, March 2026)
ANTI_FORENSICS_PATTERNS = [
    (re.compile(r'(?i)\brm\s+([-rf\s]*)(setup\.js|install\.js|postinstall\.js|preinstall\.js)'), "Self-deleting installer script"),
    (re.compile(r'(?i)fs\.unlinkSync\s*\(\s*__filename\s*\)'), "Script deletes itself after execution (fs.unlinkSync(__filename))"),
    (re.compile(r'(?i)fs\.unlink(Sync)?\s*\(\s*(path\.)?(resolve|join)\s*\(.*?(setup|install|postinstall)'), "Script deletes installer file after execution"),
    (re.compile(r'(?i)fs\.writeFileSync\s*\(\s*.*?package\.json'), "Script overwrites package.json (post-execution cleanup)"),
    (re.compile(r'(?i)(fs\.rename|fs\.copyFile)(Sync)?\s*\(.*?package\.json'), "Script replaces package.json (anti-forensics)"),
    (re.compile(r'(?i)child_process.*\brm\s'), "child_process used to remove files (anti-forensics)"),
]


def scan_package_json(file_path, rel_path):
    """Check NPM lifecycle scripts for suspicious commands."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        scripts = data.get('scripts', {})
        for hook in DANGEROUS_NPM_HOOKS:
            if hook in scripts:
                cmd = scripts[hook]

                # Check for suspicious commands
                found_suspicious = False
                for pattern, desc in SUSPICIOUS_COMMANDS:
                    if pattern.search(cmd):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"NPM Hook: Suspicious '{hook}'",
                            description=f"Hook contains {desc}",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="lifecycle-hook"
                        ))
                        found_suspicious = True
                        break

                if not found_suspicious:
                    # Check for filename relay pattern: node/python/sh/bash <file>
                    # This is THE standard supply chain attack entry point
                    relay_pattern = re.compile(
                        r'^(node|python|python3|sh|bash|bun|deno)\s+[\w./-]+\.(js|mjs|cjs|py|sh)$'
                    )
                    if relay_pattern.match(cmd.strip()):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="high",
                            title=f"NPM Hook: '{hook}' Runs External Script",
                            description=f"Lifecycle hook executes external file (standard supply chain attack pattern)",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="lifecycle-hook"
                        ))
                    else:
                        # Hook exists but no obviously malicious command
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="medium",
                            title=f"NPM Hook: '{hook}' Present",
                            description=f"Lifecycle hook exists (common malware vector)",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="lifecycle-hook"
                        ))

                # Check for anti-forensics patterns
                for pattern, desc in ANTI_FORENSICS_PATTERNS:
                    if pattern.search(cmd):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"Anti-Forensics in '{hook}' Hook",
                            description=f"Lifecycle hook contains self-destructing pattern: {desc} (Axios supply chain attack pattern, March 2026)",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="anti-forensics"
                        ))
                        break

    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_js_anti_forensics(file_path, rel_path):
    """Detect anti-forensics patterns in JS files referenced by lifecycle hooks.

    Patterns include: self-deleting scripts (fs.unlinkSync(__filename)),
    package.json overwrite after execution, and version mismatch indicators.
    Source: Axios supply chain compromise, March 31, 2026.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        lines = content.split('\n')
        for i, line in enumerate(lines):
            if len(line) > 10000:
                continue  # MAX_LINE_LENGTH guard
            for pattern, desc in ANTI_FORENSICS_PATTERNS:
                if pattern.search(line):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Anti-Forensics Pattern: {desc}",
                        description="Script contains self-destructing or evidence-cleanup pattern (supply chain attack indicator)",
                        file=rel_path, line=i + 1,
                        snippet=line.strip()[:120],
                        category="anti-forensics"
                    ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_setup_py(file_path, rel_path):
    """Check Python setup.py for cmdclass overrides (arbitrary code on pip install)."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check for cmdclass override
        if re.search(r'cmdclass\s*=\s*\{', content):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="setup.py: cmdclass Override",
                description="Custom cmdclass can execute arbitrary code during pip install",
                file=rel_path, line=0,
                snippet="cmdclass override detected",
                category="lifecycle-hook"
            ))

        # Check for subprocess/os.system in setup.py
        for suspicious in ['subprocess', 'os.system', 'os.popen', 'urllib', 'requests.', 'socket.']:
            if suspicious in content:
                line_no = 0
                for i, line in enumerate(content.split('\n')):
                    if suspicious in line:
                        line_no = i + 1
                        break
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"setup.py: Suspicious Import ({suspicious})",
                    description="setup.py contains network/execution code that runs during installation",
                    file=rel_path, line=line_no,
                    snippet=content.split('\n')[line_no - 1].strip()[:120] if line_no > 0 else suspicious,
                    category="lifecycle-hook"
                ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_pyproject_toml(file_path, rel_path):
    """Check pyproject.toml for cmdclass overrides."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if '[tool.setuptools.cmdclass]' in content or 'cmdclass' in content.lower():
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="pyproject.toml: cmdclass Override",
                description="Custom cmdclass can execute arbitrary code during pip install",
                file=rel_path, line=0,
                snippet="cmdclass override in pyproject.toml",
                category="lifecycle-hook"
            ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


# --- .pth File Injection Detection (liteLLM-style attack, March 2026) ---

# Known malicious .pth filenames - lazy loaded from ioc_manager
_KNOWN_MALICIOUS_PTH = None

_FALLBACK_MALICIOUS_PTH = {
    'litellm_init.pth', 'litellm-init.pth', 'litellm.pth',
    'llm_init.pth', 'init_hook.pth', 'startup.pth',
}


def _get_known_malicious_pth():
    """Lazy-load known malicious .pth filenames from ioc_manager."""
    global _KNOWN_MALICIOUS_PTH
    if _KNOWN_MALICIOUS_PTH is None:
        try:
            import ioc_manager as _ioc
            _KNOWN_MALICIOUS_PTH = _ioc.get_iocs().get('malicious_pth_files', _FALLBACK_MALICIOUS_PTH)
        except (ImportError, OSError, json.JSONDecodeError, ValueError) as e:
            print(f"[!] IOC loading failed, using fallback: {e}", file=sys.stderr)
            _KNOWN_MALICIOUS_PTH = _FALLBACK_MALICIOUS_PTH
    return _KNOWN_MALICIOUS_PTH

PTH_EXEC_PATTERNS = [
    (re.compile(r'\bexec\s*\('), "exec() call"),
    (re.compile(r'\beval\s*\('), "eval() call"),
    (re.compile(r'\bcompile\s*\('), "compile() call"),
    (re.compile(r'\b__import__\s*\('), "__import__() call"),
    (re.compile(r'\bos\.system\s*\('), "os.system() call"),
    (re.compile(r'\bsubprocess'), "subprocess usage"),
]


def scan_pth_files(file_path, rel_path):
    """Detect malicious .pth files (Python startup injection vector).

    .pth files in site-packages execute import statements on Python startup.
    The liteLLM attack (March 2026) used this to auto-exfiltrate all credentials
    on `pip install` without any user action.
    """
    findings = []
    basename = os.path.basename(file_path)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return findings

    lines = content.strip().split('\n')

    # Check for known malicious filenames (CRITICAL)
    if basename.lower() in _get_known_malicious_pth():
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title=f"Known Malicious .pth Filename: {basename}",
            description="Filename matches known supply chain attack IOC (liteLLM-style .pth injection)",
            file=rel_path, line=0,
            snippet=f"Known IOC: {basename}",
            category="pth-injection"
        ))

    # Check for base64 content (CRITICAL)
    # Pre-filter with simple 'in' check to avoid ReDoS on long alphanumeric lines
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    for i, line in enumerate(lines):
        stripped = line.strip()
        if len(stripped) > 10000:
            continue  # MAX_LINE_LENGTH guard against ReDoS
        # Skip filesystem paths (legitimate .pth content)
        if stripped.startswith('/') or stripped.startswith('.') or 'site-packages' in stripped:
            continue
        # Require at least one +, /, or = to distinguish from plain alphanumeric
        if not any(c in stripped for c in ('+', '/', '=')):
            continue
        if base64_pattern.search(stripped):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=".pth File: Base64 Content",
                description=".pth file contains base64-encoded data (obfuscated payload, liteLLM attack pattern)",
                file=rel_path, line=i + 1,
                snippet=line.strip()[:120],
                category="pth-injection"
            ))
            break  # One finding per file for base64

    # Check for exec/eval/compile (CRITICAL)
    for i, line in enumerate(lines):
        for pattern, desc in PTH_EXEC_PATTERNS:
            if pattern.search(line):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f".pth File: {desc}",
                    description=f".pth file contains {desc}. Executes on Python startup without user action.",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="pth-injection"
                ))
                break  # One finding per line

    # Check for import statements (MEDIUM - legitimate but worth flagging)
    import_pattern = re.compile(r'^import\s+\S+')
    for i, line in enumerate(lines):
        if import_pattern.match(line.strip()):
            # Only flag if no exec/eval already found (to avoid noise)
            if not any(f.category == "pth-injection" and f.severity == "critical" for f in findings):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title=".pth File: Import Statement",
                    description=".pth file with import statement runs code on Python startup",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="pth-injection"
                ))
                break  # One import finding is enough

    # If .pth file exists but has no suspicious content, still note it (LOW)
    if not findings:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title=f".pth File Present: {basename}",
            description=".pth files execute on Python startup. Verify this is intentional.",
            file=rel_path, line=0,
            snippet=content[:120].replace('\n', ' '),
            category="pth-injection"
        ))

    return findings


def main():
    args = core.parse_common_args(sys.argv, "Lifecycle Script Scanner")
    repo_path = args.repo_path

    print(f"[*] Scanning lifecycle scripts in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True, skip_lockfiles=True):
        basename = os.path.basename(file_path)

        if basename == 'package.json':
            all_findings.extend(scan_package_json(file_path, rel_path))
        elif basename == 'setup.py':
            all_findings.extend(scan_setup_py(file_path, rel_path))
        elif basename == 'pyproject.toml':
            all_findings.extend(scan_pyproject_toml(file_path, rel_path))
        elif basename.endswith('.pth'):
            all_findings.extend(scan_pth_files(file_path, rel_path))
        elif basename in ('setup.js', 'install.js', 'postinstall.js', 'preinstall.js'):
            all_findings.extend(scan_js_anti_forensics(file_path, rel_path))
        elif basename == 'binding.gyp':
            all_findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="binding.gyp: Implicit Native Build",
                description="binding.gyp triggers node-gyp rebuild on install without explicit install script (native code execution)",
                file=rel_path, line=0,
                snippet="binding.gyp present (implicit install-time execution)",
                category="lifecycle-hook"
            ))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
