#!/usr/bin/env python3
"""
scan_sast.py - Static Application Security Testing (v2)
Identifies dangerous functions, injection patterns, and code vulnerabilities.
Fixed: duplicate import, added os.system/__import__/compile/Function,
does NOT skip tests/ (attackers hide malware there per Snyk research).

Created by Alex Greenshpun
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "sast"

# NOTE: tests/ is NOT in core.IGNORE_DIRS either (attackers hide malware there)

SAST_PATTERNS = {
    ".py": [
        {"name": "Dangerous Eval", "severity": "high", "regex": re.compile(r'\beval\s*\('), "category": "code-execution"},
        {"name": "Dangerous Exec", "severity": "high", "regex": re.compile(r'\bexec\s*\('), "category": "code-execution"},
        {"name": "Dynamic Import", "severity": "high", "regex": re.compile(r'\b__import__\s*\('), "category": "code-execution"},
        {"name": "Dynamic Compile", "severity": "medium", "regex": re.compile(r'\bcompile\s*\([^)]*[\'"]exec[\'"]'), "category": "code-execution"},
        {"name": "Unsafe Deserialization", "severity": "critical", "regex": re.compile(r'\b(pickle|cPickle|shelve|yaml)\.(loads?|load_all|unsafe_load)\s*\('), "category": "deserialization"},
        {"name": "Shell Injection (subprocess)", "severity": "critical", "regex": re.compile(r'\bsubprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True'), "category": "shell-injection"},
        {"name": "Shell Injection (os)", "severity": "critical", "regex": re.compile(r'\bos\.(popen|system)\s*\('), "category": "shell-injection"},
        {"name": "SQL Injection Pattern", "severity": "high", "regex": re.compile(r'(?i)(execute|cursor\.execute)\s*\([^)]*(%s|%d|\+|\.format|f[\'"])'), "category": "injection"},
        {"name": "Hardcoded IP", "severity": "low", "regex": re.compile(r'[\'\"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\'"]'), "category": "hardcoded"},
    ],
    ".js": [
        {"name": "Dangerous Eval", "severity": "high", "regex": re.compile(r'\beval\s*\('), "category": "code-execution"},
        {"name": "Function Constructor", "severity": "high", "regex": re.compile(r'\bnew\s+Function\s*\('), "category": "code-execution"},
        {"name": "Unsafe HTML", "severity": "high", "regex": re.compile(r'dangerouslySetInnerHTML'), "category": "xss"},
        {"name": "innerHTML Assignment", "severity": "medium", "regex": re.compile(r'\.innerHTML\s*='), "category": "xss"},
        {"name": "Child Process Exec", "severity": "critical", "regex": re.compile(r'(require\s*\(\s*[\'"]child_process[\'"]\s*\)|child_process)\.(exec|execSync|spawn)\s*\('), "category": "shell-injection"},
        {"name": "Implied Eval (setTimeout)", "severity": "medium", "regex": re.compile(r'setTimeout\s*\(\s*[\'"][^\'"]+[\'"]'), "category": "code-execution"},
        {"name": "document.write", "severity": "medium", "regex": re.compile(r'document\.write\s*\('), "category": "xss"},
        {"name": "SQL String Concat", "severity": "high", "regex": re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*(?:req\.|params\.|query\.)'), "category": "injection"},
    ],
    ".ts": [
        {"name": "Dangerous Eval", "severity": "high", "regex": re.compile(r'\beval\s*\('), "category": "code-execution"},
        {"name": "Function Constructor", "severity": "high", "regex": re.compile(r'\bnew\s+Function\s*\('), "category": "code-execution"},
        {"name": "Unsafe HTML", "severity": "high", "regex": re.compile(r'dangerouslySetInnerHTML'), "category": "xss"},
        {"name": "Child Process Exec", "severity": "critical", "regex": re.compile(r'child_process\.(exec|execSync|spawn)\s*\('), "category": "shell-injection"},
    ],
    ".tsx": [
        {"name": "Dangerous Eval", "severity": "high", "regex": re.compile(r'\beval\s*\('), "category": "code-execution"},
        {"name": "Unsafe HTML", "severity": "high", "regex": re.compile(r'dangerouslySetInnerHTML'), "category": "xss"},
    ],
    ".jsx": [
        {"name": "Dangerous Eval", "severity": "high", "regex": re.compile(r'\beval\s*\('), "category": "code-execution"},
        {"name": "Unsafe HTML", "severity": "high", "regex": re.compile(r'dangerouslySetInnerHTML'), "category": "xss"},
    ],
    ".php": [
        {"name": "Shell Execution", "severity": "critical", "regex": re.compile(r'\b(shell_exec|exec|passthru|system|popen)\s*\('), "category": "shell-injection"},
        {"name": "Eval", "severity": "high", "regex": re.compile(r'\beval\s*\('), "category": "code-execution"},
        {"name": "SQL Injection", "severity": "high", "regex": re.compile(r'(?i)mysql_query\s*\(\s*["\'].*\$'), "category": "injection"},
        {"name": "File Inclusion", "severity": "critical", "regex": re.compile(r'\b(include|require)(_once)?\s*\(\s*\$'), "category": "injection"},
    ],
    ".java": [
        {"name": "Command Execution", "severity": "critical", "regex": re.compile(r'Runtime\.getRuntime\(\)\.exec'), "category": "shell-injection"},
        {"name": "ProcessBuilder", "severity": "high", "regex": re.compile(r'new\s+ProcessBuilder\s*\('), "category": "shell-injection"},
        {"name": "Unsafe Deserialization", "severity": "critical", "regex": re.compile(r'ObjectInputStream.*readObject'), "category": "deserialization"},
    ],
    ".go": [
        {"name": "Command Execution", "severity": "high", "regex": re.compile(r'exec\.Command\s*\('), "category": "shell-injection"},
        {"name": "Unsafe Pointer", "severity": "medium", "regex": re.compile(r'unsafe\.Pointer'), "category": "memory-safety"},
    ],
    ".rb": [
        {"name": "Eval", "severity": "high", "regex": re.compile(r'\beval\s*\('), "category": "code-execution"},
        {"name": "System Call", "severity": "critical", "regex": re.compile(r'\b(system|exec|`|%x)\s*[\(\[]'), "category": "shell-injection"},
        {"name": "Send Method", "severity": "medium", "regex": re.compile(r'\bsend\s*\(\s*params'), "category": "code-execution"},
    ],
    ".sh": [
        {"name": "Eval in Shell", "severity": "high", "regex": re.compile(r'\beval\s+'), "category": "code-execution"},
        {"name": "Curl Pipe Bash", "severity": "critical", "regex": re.compile(r'curl\s+.*\|\s*(ba)?sh'), "category": "shell-injection"},
        {"name": "Pipe Exfiltration: env to network", "severity": "critical", "regex": re.compile(r'(env|printenv|cat\s+\.env|cat\s+~/\.ssh|cat\s+~/\.aws)\s*\|.*\b(curl|wget|nc|ncat|socat)\b', re.IGNORECASE), "category": "exfiltration"},
        {"name": "Pipe Exfiltration: sensitive file to network", "severity": "critical", "regex": re.compile(r'cat\s+[^\|]*(?:\.env|credential|password|secret|\.ssh|\.aws|\.gnupg|id_rsa|shadow)[^\|]*\|.*\b(curl|wget|nc|ncat)\b', re.IGNORECASE), "category": "exfiltration"},
        {"name": "Redirect to /dev/tcp", "severity": "critical", "regex": re.compile(r'>\s*/dev/tcp/', re.IGNORECASE), "category": "exfiltration"},
        {"name": "Reverse shell pattern", "severity": "critical", "regex": re.compile(r'bash\s+-i\s+>&\s*/dev/tcp/|nc\s+(-e|--exec)\s+/bin/(ba)?sh', re.IGNORECASE), "category": "exfiltration"},
    ],
}


def scan_file(file_path, rel_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in SAST_PATTERNS:
        return []

    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                if len(line) > core.MAX_LINE_LENGTH:
                    continue
                for pattern in SAST_PATTERNS[ext]:
                    if pattern['regex'].search(line):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME,
                            severity=pattern['severity'],
                            title=pattern['name'],
                            description=f"Potential {pattern['category']} vulnerability",
                            file=rel_path,
                            line=i + 1,
                            snippet=line.strip()[:120],
                            category=pattern['category']
                        ))
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def main():
    args = core.parse_common_args(sys.argv, "SAST Vulnerability Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Starting SAST scan on {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    if ignore_patterns:
        core.emit_status(args.format, f"[*] Loaded {len(ignore_patterns)} custom ignore patterns from .forensicsignore")

    all_findings = []

    # Use custom skip_dirs to NOT exclude tests/
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
