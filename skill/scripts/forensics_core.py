#!/usr/bin/env python3
"""
forensics_core.py - Core framework for repo-forensics v2
Provides Finding dataclass, severity system, output formatting,
correlation engine, and .forensicsignore support.

Created by Alex Greenshpun
"""

import os
import sys
import json
import hashlib
import fnmatch
from dataclasses import dataclass, field, asdict

# --- Severity System ---
SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_COLORS = {
    "critical": "\033[91m",  # bright red
    "high": "\033[93m",      # yellow
    "medium": "\033[96m",    # cyan
    "low": "\033[37m",       # light gray
}
RESET = "\033[0m"
BOLD = "\033[1m"


@dataclass
class Finding:
    scanner: str       # "secrets", "sast", "skill_threats", etc.
    severity: str      # "critical", "high", "medium", "low"
    title: str         # "AWS Access Key ID"
    description: str   # Human-readable explanation
    file: str          # Relative path
    line: int          # Line number (0 if N/A)
    snippet: str       # Code context (max 120 chars)
    category: str      # "secret", "injection", "exfiltration", etc.

    def to_dict(self):
        return asdict(self)

    def severity_score(self):
        return SEVERITY.get(self.severity, 0)

    def format_text(self):
        color = SEVERITY_COLORS.get(self.severity, "")
        sev = self.severity.upper()
        loc = f"{self.file}:{self.line}" if self.line > 0 else self.file
        snip = self.snippet[:120] if self.snippet else ""
        return (
            f"  {color}[{sev}]{RESET} {self.title}\n"
            f"         {loc}\n"
            f"         {self.description}\n"
            f"         {snip}"
        )


# --- .forensicsignore Support (backward compatible) ---

def load_ignore_patterns(repo_path):
    """Loads ignore patterns from a .forensicsignore file in the repo root."""
    ignore_file = os.path.join(repo_path, '.forensicsignore')
    patterns = []

    if os.path.exists(ignore_file):
        try:
            with open(ignore_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns.append(line)
        except Exception as e:
            print(f"[!] Warning: Could not read .forensicsignore: {e}")

    return patterns


DANGEROUS_IGNORE_PATTERNS = {'*', '**', '**/*', '*.*', '.'}


def warn_forensicsignore(repo_path):
    """Return warning findings if .forensicsignore exists. Escalate for broad patterns."""
    ignore_file = os.path.join(repo_path, '.forensicsignore')
    if not os.path.exists(ignore_file):
        return []

    findings = []
    patterns = load_ignore_patterns(repo_path)
    has_broad = any(p in DANGEROUS_IGNORE_PATTERNS for p in patterns)

    if has_broad:
        findings.append(Finding(
            scanner="meta", severity="critical",
            title=".forensicsignore: Wildcard Suppression",
            description="Contains broad patterns (e.g. '*') that suppress ALL findings. Likely attacker-planted.",
            file=".forensicsignore", line=0,
            snippet=f"Broad patterns: {[p for p in patterns if p in DANGEROUS_IGNORE_PATTERNS]}",
            category="configuration"
        ))
    else:
        findings.append(Finding(
            scanner="meta", severity="medium",
            title=".forensicsignore Present",
            description=f"Suppresses {len(patterns)} pattern(s). Verify it wasn't planted by an attacker.",
            file=".forensicsignore", line=0,
            snippet=f"Patterns: {patterns[:3]}",
            category="configuration"
        ))
    return findings


def should_ignore(file_path, repo_root, patterns):
    """Checks if a file path matches any ignore pattern."""
    if not patterns:
        return False

    try:
        rel_path = os.path.relpath(file_path, repo_root)
    except ValueError:
        return False

    for pattern in patterns:
        if pattern.endswith('/'):
            if rel_path.startswith(pattern) or rel_path == pattern[:-1]:
                return True

        if fnmatch.fnmatch(rel_path, pattern):
            return True

        if '*' not in pattern and '?' not in pattern:
            if rel_path.startswith(pattern + os.sep) or rel_path == pattern:
                return True

    return False


# --- Common Constants ---

IGNORE_DIRS = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build', 'coverage', '.tox', '.mypy_cache'}
BINARY_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz', '.7z',
                     '.exe', '.dll', '.so', '.dylib', '.bin', '.pyc', '.class', '.woff', '.woff2',
                     '.ttf', '.eot', '.mp3', '.mp4', '.mov', '.avi', '.bmp', '.tiff'}
LOCKFILES = {'pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'go.sum', 'Cargo.lock',
             'Gemfile.lock', 'poetry.lock', 'Pipfile.lock', 'composer.lock'}
MAX_FILE_SIZE_MB = 10
MAX_LINE_LENGTH = 10000  # Skip/truncate lines longer than this to prevent ReDoS


def sha256_file(filepath):
    """Compute SHA256 hash of a file. Returns hex digest or None on error."""
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def is_binary_file(file_path):
    """Check if file is binary by extension, null bytes, or content sniffing."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in BINARY_EXTENSIONS:
        return True
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
        if b'\x00' in chunk:
            return True
        chunk.decode('utf-8')
        return False
    except (UnicodeDecodeError, PermissionError, OSError):
        return True


def walk_repo(repo_path, ignore_patterns=None, skip_dirs=None, skip_lockfiles=True, skip_binary=True):
    """Generator that walks a repo respecting ignore rules.
    Yields (file_path, rel_path) tuples."""
    if skip_dirs is None:
        skip_dirs = IGNORE_DIRS
    if ignore_patterns is None:
        ignore_patterns = load_ignore_patterns(repo_path)

    for root, dirs, files in os.walk(repo_path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for filename in files:
            if skip_lockfiles and filename in LOCKFILES:
                continue

            file_path = os.path.join(root, filename)

            # Skip symlinks to prevent traversal outside repo
            if os.path.islink(file_path):
                continue

            if should_ignore(file_path, repo_path, ignore_patterns):
                continue

            try:
                if os.path.getsize(file_path) > MAX_FILE_SIZE_MB * 1024 * 1024:
                    continue
            except OSError:
                continue

            if skip_binary and is_binary_file(file_path):
                continue

            rel_path = os.path.relpath(file_path, repo_path)
            yield file_path, rel_path


# --- Correlation Engine ---

def correlate(findings):
    """Flag compound threats where multiple findings in the same file form attack chains.

    Rules:
    - env/credential read + network POST in same file = "Potential data exfiltration" (critical)
    - base64 encoding + exec/eval in same file = "Obfuscated code execution" (critical)
    - file read of sensitive paths + any network call = "Credential theft pattern" (high)
    """
    correlated = []

    # Group findings by file
    by_file = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    env_keywords = {"env access", "environ", "credential", "secret", ".env", ".ssh", ".aws", "keychain"}
    network_keywords = {"network", "http", "fetch", "request", "post", "webhook", "curl", "wget", "exfiltration"}
    exec_keywords = {"eval", "exec", "system", "subprocess", "code execution", "shell"}
    encoding_keywords = {"base64", "obfuscat", "encoding", "hex string"}
    sensitive_read_keywords = {".env", ".ssh", ".aws", "credential", "keychain", "browser data", "config"}
    prompt_injection_keywords = {"prompt injection", "instruction override", "persona reassignment", "confirmation bypass"}
    lifecycle_keywords = {"lifecycle", "hook", "postinstall", "preinstall", "cmdclass", "setup.py"}
    dynamic_import_keywords = {"dynamic import", "importlib", "import_module", "dynamic-import"}
    time_bomb_keywords = {"time bomb", "time-bomb", "datetime comparison", "activation trigger", "unix timestamp"}
    dynamic_desc_keywords = {"dynamic-description", "rug-pull", "rug pull enabler", "dynamic tool description"}
    mcp_server_keywords = {"mcp", "tool-poisoning", "mcp_security", "mcp-config", "rug-pull-enabler"}
    phantom_dep_keywords = {"phantom-dependency", "phantom dep", "shadow dependency"}
    pipe_exfil_keywords = {"pipe exfiltration", "reverse shell", "/dev/tcp", "pipe-exfiltration"}
    openclaw_keywords = {"tool-poisoning", "agent-injection", "frontmatter", "clawhavoc-delivery", "clawhubignore-bypass"}

    def has_category(file_findings, keywords, exclude_scanner=None):
        for f in file_findings:
            if exclude_scanner and f.scanner == exclude_scanner:
                continue
            desc_lower = (f.description + " " + f.title + " " + f.category).lower()
            for kw in keywords:
                if kw in desc_lower:
                    return True
        return False

    for filepath, file_findings in by_file.items():
        # Rule 1: env access + network call
        if has_category(file_findings, env_keywords) and has_category(file_findings, network_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Potential Data Exfiltration",
                description="Environment/credential access combined with network call in the same file",
                file=filepath,
                line=0,
                snippet="[compound: env read + network call]",
                category="exfiltration"
            ))

        # Rule 2: base64/encoding + exec/eval
        if has_category(file_findings, encoding_keywords) and has_category(file_findings, exec_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Obfuscated Code Execution",
                description="Base64/encoding combined with code execution in the same file",
                file=filepath,
                line=0,
                snippet="[compound: encoding + exec]",
                category="obfuscation"
            ))

        # Rule 3: sensitive file read + network call
        if has_category(file_findings, sensitive_read_keywords) and has_category(file_findings, network_keywords):
            # Don't duplicate if already caught by Rule 1
            already_flagged = any(c.file == filepath and c.title == "Potential Data Exfiltration" for c in correlated)
            if not already_flagged:
                correlated.append(Finding(
                    scanner="correlation",
                    severity="high",
                    title="Credential Theft Pattern",
                    description="Sensitive file read combined with network call in the same file",
                    file=filepath,
                    line=0,
                    snippet="[compound: sensitive read + network call]",
                    category="exfiltration"
                ))

        # Rule 4: prompt injection + code execution (91% of malicious skills per Snyk)
        if has_category(file_findings, prompt_injection_keywords) and has_category(file_findings, exec_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Prompt-Assisted Code Execution",
                description="Prompt injection combined with code execution in the same file (top malicious skill pattern)",
                file=filepath,
                line=0,
                snippet="[compound: prompt injection + code exec]",
                category="compound-attack"
            ))

        # Rule 5: lifecycle hook + network call
        if has_category(file_findings, lifecycle_keywords) and has_category(file_findings, network_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Install-Time Exfiltration",
                description="Lifecycle hook combined with network call in the same file (install-time data theft)",
                file=filepath,
                line=0,
                snippet="[compound: lifecycle hook + network call]",
                category="exfiltration"
            ))

        # Rule 6: SQL injection → stored prompt injection (Trend Micro TrendAI, May 2025)
        sql_keywords = {"sql-injection", "string concatenation in execute", "sql select", "sql insert"}
        mcp_keywords = {"tool-poisoning", "mcp_security", "skill_threats", "prompt injection"}
        if has_category(file_findings, sql_keywords) and has_category(file_findings, mcp_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="SQL Injection Prompt Escalation",
                description="SQL injection in MCP code can store malicious prompts for agent execution (Trend Micro TrendAI, 2025)",
                file=filepath,
                line=0,
                snippet="[compound: sql injection + prompt injection in MCP file]",
                category="mcp-escalation"
            ))

        # Rule 7: Tool metadata poisoning + code execution chain
        poisoning_keywords = {"tool-poisoning", "tool shadowing", "mcp-tool-injection", "tool metadata"}
        if has_category(file_findings, poisoning_keywords) and has_category(file_findings, exec_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Tool Metadata Poisoning Chain",
                description="Hidden instructions in tool descriptions combined with code execution (Invariant Labs TPA pattern)",
                file=filepath,
                line=0,
                snippet="[compound: tool poisoning + code execution]",
                category="mcp-escalation"
            ))

        # Rule 8: Unicode smuggling + prompt injection in documentation
        ext_lower = os.path.splitext(filepath)[1].lower()
        if ext_lower in ('.md', '.txt', '.rst', '.adoc'):
            smuggling_keywords = {"unicode-smuggling", "zero-width", "rtl override", "homoglyph"}
            pi_keywords = {"prompt-injection", "prompt injection"}
            if has_category(file_findings, smuggling_keywords) and has_category(file_findings, pi_keywords):
                correlated.append(Finding(
                    scanner="correlation",
                    severity="high",
                    title="Hidden Instruction Attack in Documentation",
                    description="Invisible unicode combined with prompt injection in documentation (text steganography attack)",
                    file=filepath,
                    line=0,
                    snippet="[compound: unicode smuggling + prompt injection in doc]",
                    category="compound-attack"
                ))

        # Rule 9: Dynamic import/eval + network fetch = "Deferred Payload Loading"
        if has_category(file_findings, dynamic_import_keywords) and has_category(file_findings, network_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Deferred Payload Loading",
                description="Dynamic import combined with network fetch in the same file. Code can download and load arbitrary modules at runtime.",
                file=filepath,
                line=0,
                snippet="[compound: dynamic import + network fetch]",
                category="deferred-payload"
            ))

        # Rule 10: Date/counter comparison + exec/eval = "Time-Triggered Malware"
        if has_category(file_findings, time_bomb_keywords) and has_category(file_findings, exec_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Time-Triggered Malware",
                description="Time/counter-based activation combined with code execution. Classic time bomb pattern (Socket.dev NuGet, Nov 2025).",
                file=filepath,
                line=0,
                snippet="[compound: time bomb + code execution]",
                category="time-triggered-malware"
            ))

        # Rule 11: Dynamic tool description + MCP server signals = "MCP Rug Pull Enabler"
        if has_category(file_findings, dynamic_desc_keywords) and has_category(file_findings, mcp_server_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="high",
                title="MCP Rug Pull Enabler",
                description="MCP server with dynamic tool descriptions. Tool behavior can change without code changes (Lukas Kania, March 2026).",
                file=filepath,
                line=0,
                snippet="[compound: dynamic description + MCP server]",
                category="rug-pull"
            ))

        # Rule 12: Phantom dependency + network call = "Shadow Dependency with Network"
        if has_category(file_findings, phantom_dep_keywords) and has_category(file_findings, network_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Shadow Dependency with Network Access",
                description="Undeclared dependency combined with network access. Potential supply chain attack via shadow dependency.",
                file=filepath,
                line=0,
                snippet="[compound: phantom dependency + network call]",
                category="shadow-dependency"
            ))

        # Rule 13: Pipe exfiltration in shell scripts
        if has_category(file_findings, pipe_exfil_keywords) and has_category(file_findings, network_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Shell Script Data Exfiltration Chain",
                description="Shell script contains pipe exfiltration pattern combined with network tool. Data flows from sensitive source through pipe to external endpoint.",
                file=filepath,
                line=0,
                snippet="[compound: pipe exfiltration + network sink]",
                category="pipe-exfiltration"
            ))

        # Rule 14: OpenClaw skill compound attack (cross-scanner signal only)
        if has_category(file_findings, openclaw_keywords) and has_category(file_findings, prompt_injection_keywords, exclude_scanner="openclaw_skills"):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Agent Skill Compound Attack",
                description="Multiple attack vectors in agent skill: tool poisoning combined with prompt injection. Matches ClawHavoc campaign pattern.",
                file=filepath,
                line=0,
                snippet="[compound: tool/config poisoning + prompt injection]",
                category="openclaw-compound"
            ))

        # Rule 15: git dependency + lifecycle hook = npmrc injection risk
        git_dep_keywords = {"git-dependency", "git dependency", "git+"}
        if has_category(file_findings, git_dep_keywords) and has_category(file_findings, lifecycle_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="high",
                title="Git Dependency with Lifecycle Hook",
                description="Git dependency combined with lifecycle hook in the same package.json. Git deps can inject .npmrc to override git binary (PackageGate bypass, npm unfixed).",
                file=filepath,
                line=0,
                snippet="[compound: git dependency + lifecycle hook]",
                category="npmrc-injection-risk"
            ))

        # Rule 16: missing integrity + untrusted URL = lockfile tampering
        missing_integrity_keywords = {"missing-integrity", "missing integrity", "no integrity"}
        untrusted_url_keywords = {"untrusted-registry", "untrusted registry", "insecure-protocol"}
        if has_category(file_findings, missing_integrity_keywords) and has_category(file_findings, untrusted_url_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Lockfile Tampering Indicator",
                description="Missing integrity hashes combined with untrusted registry URLs. Strong indicator of lockfile manipulation.",
                file=filepath,
                line=0,
                snippet="[compound: missing integrity + untrusted URL]",
                category="lockfile-tampering"
            ))

        # Rule 17: .pth file + base64/exec = "Python Startup Injection (liteLLM-style)"
        pth_keywords = {"pth-injection", ".pth file", "pth file"}
        pth_exec_keywords = {"exec", "eval", "compile", "base64", "obfuscat"}
        if has_category(file_findings, pth_keywords) and has_category(file_findings, pth_exec_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Python Startup Injection (liteLLM-style)",
                description=".pth file with code execution or obfuscated payload. Matches March 2026 liteLLM supply chain attack pattern: .pth files execute on Python startup, exfiltrating credentials without user action.",
                file=filepath,
                line=0,
                snippet="[compound: .pth file + exec/base64]",
                category="pth-injection"
            ))

        # Rule 16: .pth file + known IOC = "Known Supply Chain .pth Attack"
        known_ioc_keywords = {"known-ioc", "known malicious", "ioc match", "ioc database"}
        if has_category(file_findings, pth_keywords) and has_category(file_findings, known_ioc_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Known Supply Chain .pth Attack",
                description="Known malicious .pth file from IOC database. Confirmed supply chain attack vector.",
                file=filepath,
                line=0,
                snippet="[compound: .pth file + known IOC match]",
                category="pth-injection"
            ))

    return correlated


# --- Output Formatting ---

def format_findings(findings, output_format="text"):
    """Format findings list according to output mode."""
    if output_format == "json":
        return json.dumps([f.to_dict() for f in findings], indent=2)

    elif output_format == "summary":
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        lines = []
        for sev in ["critical", "high", "medium", "low"]:
            if counts[sev] > 0:
                color = SEVERITY_COLORS.get(sev, "")
                lines.append(f"  {color}{sev.upper()}: {counts[sev]}{RESET}")
        return "\n".join(lines) if lines else "  No findings."

    else:  # text
        if not findings:
            return "  No findings."
        # Sort by severity (critical first)
        sorted_findings = sorted(findings, key=lambda f: -f.severity_score())
        return "\n\n".join(f.format_text() for f in sorted_findings)


def scan_patterns(content, rel_path, patterns, category, default_severity, scanner_name):
    """Generic line-based pattern scanner. Shared by scan_skill_threats and scan_mcp_security."""
    findings = []
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if len(line) > MAX_LINE_LENGTH:
            continue
        for pattern, title in patterns:
            if pattern.search(line):
                findings.append(Finding(
                    scanner=scanner_name, severity=default_severity,
                    title=title,
                    description=f"Matched in {category} scan",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category=category
                ))
    return findings


def parse_common_args(argv, scanner_name):
    """Parse common CLI args for scanners: <repo_path> [--format text|json|summary]"""
    import argparse
    parser = argparse.ArgumentParser(description=f"repo-forensics: {scanner_name}")
    parser.add_argument('repo_path', help="Path to repository to scan")
    parser.add_argument('--format', choices=['text', 'json', 'summary'], default='text',
                        help="Output format (default: text)")
    args = parser.parse_args(argv[1:])
    args.repo_path = os.path.abspath(args.repo_path)
    return args


def output_findings(findings, output_format="text", scanner_name=""):
    """Standard output routine for scanners."""
    if output_format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif output_format == "summary":
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        total = sum(counts.values())
        print(f"{scanner_name}: {total} findings ({counts['critical']}C {counts['high']}H {counts['medium']}M {counts['low']}L)")
    else:
        if findings:
            print(f"\n[!] Found {len(findings)} issue(s):")
            print(format_findings(findings, "text"))
        else:
            print(f"\n[+] No issues found.")
