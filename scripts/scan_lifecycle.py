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
                severity = "medium"  # Default for having a hook at all

                for pattern, desc in SUSPICIOUS_COMMANDS:
                    if pattern.search(cmd):
                        severity = "critical"
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"NPM Hook: Suspicious '{hook}'",
                            description=f"Hook contains {desc}",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="lifecycle-hook"
                        ))
                        break
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

    except Exception:
        pass
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

    except Exception:
        pass
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

    except Exception:
        pass
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

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
