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

    def __post_init__(self):
        # Defensive type coercion at the trust boundary between the in-process
        # correlation engine and external scanner JSON. Any scanner that emits
        # a stringified line number or a None severity must NOT crash the text
        # aggregator or the `self.line > 0` comparison in format_text().
        # (Python language review PL-F1 + PL-F12, 2026-04-05.)
        try:
            self.line = int(self.line) if self.line is not None else 0
        except (TypeError, ValueError):
            self.line = 0
        if self.line < 0:
            self.line = 0
        if not isinstance(self.severity, str):
            self.severity = "low"
        else:
            self.severity = self.severity.lower()
        # Guard the remaining string fields so downstream .lower() / slicing
        # can never NoneError.
        for _field in ("scanner", "title", "description", "file", "snippet", "category"):
            if getattr(self, _field) is None:
                setattr(self, _field, "")

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
            print(f"[!] Warning: Could not read .forensicsignore: {e}", file=sys.stderr)

    return patterns


# Patterns that suppress too much of the walk to be plausibly legitimate.
# An attacker-planted .forensicsignore with `*.py` or `*.js` would otherwise
# silently suppress entire languages and escape detection. (Security review
# SS-F4, 2026-04-05.)
DANGEROUS_IGNORE_PATTERNS = {
    # Total wildcards
    '*', '**', '**/*', '*.*', '.',
    # Language-scope wildcards — suppressing all files of a major language
    # is never a legitimate use case and is the shape of an attacker-planted
    # suppression.
    '*.py', '*.pyc', '*.pyw',
    '*.js', '*.jsx', '*.mjs', '*.cjs',
    '*.ts', '*.tsx',
    '*.rb',
    '*.go',
    '*.rs',
    '*.sh', '*.bash', '*.zsh',
    '*.php', '*.phtml',
    '*.pl', '*.pm',
    '*.ps1',
    '*.java', '*.kt', '*.scala',
    '*.cs',
    '*.c', '*.cpp', '*.cc', '*.h', '*.hpp',
    '*.swift',
    '*.lua',
    # Directory-scope wildcards that would suppress source trees
    'src/**', 'src/**/*',
    'scripts/**', 'scripts/**/*',
    '**/src/*', '**/src/**',
    '**/scripts/*', '**/scripts/**',
    '**/*.py', '**/*.js', '**/*.ts', '**/*.rb', '**/*.go',
}


def emit_status(output_format, message):
    """Emit human status lines only for non-JSON formats."""
    if output_format != "json":
        print(message)


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


# --- Raw-content Trifecta Scanner ---
# Rule 19 Lethal Trifecta relies on sub-scanner findings to detect the three
# primitives (exec, network, credential read). In practice, sub-scanners miss
# low-level primitives like direct `open('~/.ssh/id_rsa')` or raw
# `http.client.HTTPSConnection`. To keep Rule 19 from becoming dead code when
# sub-scanners are silent, this module also does an independent raw-content
# scan that synthesizes primitive findings directly. Called from
# aggregate_json.py before correlate().
# (Fix for 2026-04-05 security review A6.)

import re as _re_trifecta

# Each regex matches ONLY actionable code patterns — method calls with parens,
# specific file paths, or named constant references. Bare descriptive keywords
# (`webhook`, `api_key`, `browser data`, `reverse shell`, `keychain`) were
# removed in the 2026-04-05 torture review (CRC-F2) because they matched
# legitimate code comments, variable names, and doc strings and caused
# false-positive Rule 19 hits on every CI/integration test repo.
_TRIFECTA_EXEC_RE = _re_trifecta.compile(
    r'(?:os\.system\s*\(|subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(|'
    r'child_process\.(?:exec|spawn|execSync)\s*\(|(?<![a-zA-Z_])eval\s*\(|'
    r'(?<![a-zA-Z_])exec\s*\(|shell\s*=\s*True)'
)
_TRIFECTA_NETWORK_RE = _re_trifecta.compile(
    # Only actionable outbound network primitives with concrete call syntax.
    # Removed bare `webhook`, `reverse[\s_-]?shell`, and `node-fetch` which
    # were prose-level keywords that matched comments and docstrings.
    r'(?:http\.client\.HTTPS?Connection|urllib\.request\.urlopen|'
    r'requests\.(?:post|get|put|delete)\s*\(|socket\.(?:connect|send|sendto)\s*\(|'
    r'axios\.(?:post|get|put|delete)\s*\(|'
    r'\bfetch\s*\(\s*[\'"]https?://|'
    r'/dev/tcp/)'
)
_TRIFECTA_CREDENTIAL_RE = _re_trifecta.compile(
    # Specific file paths and named environment variables. Removed bare
    # `api_key`, `private_key`, `browser data`, `keychain` which matched
    # legitimate variable names and comments in any file with auth code.
    # Added \b boundaries on the remaining tokens so `GITHUB_TOKENIZE` and
    # `.aws/credentials_fake_helper` do not match.
    r'(?:\.ssh/id_(?:rsa|ed25519|dsa|ecdsa)\b|'
    r'\.aws/credentials\b|\.aws/config\b|'
    r'\.netrc\b|/etc/shadow\b|'
    r'\b(?:GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\b|'
    r'\.env(?!\.example|\.template)(?:\s|\)|\'|"|$))'
)

_TRIFECTA_SCAN_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.sh', '.bash', '.rb', '.go',
    '.rs', '.php', '.pl', '.ps1',
}
_TRIFECTA_MAX_SCAN_FILES = 5000
_TRIFECTA_MAX_SCAN_BYTES = 2 * 1024 * 1024  # 2MB per file


def detect_trifecta_raw(repo_path, ignore_patterns=None):
    """Scan files in repo_path for the Lethal Trifecta three primitives.

    Returns a list of Finding objects (one per primitive per file) that can
    be fed into correlate() so Rule 19 fires regardless of whether the
    specialized sub-scanners caught the primitives.

    This is deliberately narrow: it only fires on unambiguous keyword hits
    (e.g. `subprocess.run(` with the paren, `http.client.HTTPSConnection`,
    `.aws/credentials`). The regexes use lookbehinds and word boundaries to
    avoid false positives on `executable`, `.env.example`, etc.

    As of 2026-04-05 (CRC-F2, CRC-F3), iterates line-by-line rather than
    whole-file so each emitted Finding carries the actual line number and
    a snippet of the matching code. This makes triage possible — previously
    every CRITICAL Rule 19 finding pointed at file:0 with a canned snippet.
    """
    findings = []
    if not repo_path or not os.path.isdir(repo_path):
        return findings

    scanned = 0
    try:
        walker = walk_repo(
            repo_path,
            ignore_patterns=ignore_patterns,
            skip_binary=True,
            skip_lockfiles=True,
        )
    except OSError:
        return findings

    for file_path, rel_path in walker:
        if scanned >= _TRIFECTA_MAX_SCAN_FILES:
            break
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in _TRIFECTA_SCAN_EXTENSIONS:
            continue

        try:
            size = os.path.getsize(file_path)
            if size > _TRIFECTA_MAX_SCAN_BYTES:
                continue
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            continue
        scanned += 1

        # Line-by-line scan with attribution. Record first match per primitive.
        exec_hit = None       # (line_num, snippet_text)
        network_hit = None
        credential_hit = None
        for line_num, line in enumerate(content.splitlines(), start=1):
            # Skip obvious comment-only lines to reduce false positives from
            # prose. Conservative — language-agnostic comment prefixes only.
            stripped = line.lstrip()
            if stripped.startswith(('#', '//', ';;', '/*', '*')):
                continue
            if exec_hit is None and _TRIFECTA_EXEC_RE.search(line):
                exec_hit = (line_num, line.strip()[:120])
            if network_hit is None and _TRIFECTA_NETWORK_RE.search(line):
                network_hit = (line_num, line.strip()[:120])
            if credential_hit is None and _TRIFECTA_CREDENTIAL_RE.search(line):
                credential_hit = (line_num, line.strip()[:120])
            if exec_hit and network_hit and credential_hit:
                break  # early exit: we have enough for Rule 19 to fire

        # Only emit synthetic primitive findings when ALL THREE are present in
        # the file. This tightens the feed into Rule 19's correlation loop —
        # we never claim a file has only 1-2 primitives via this path.
        if exec_hit and network_hit and credential_hit:
            findings.append(Finding(
                scanner="trifecta_raw", severity="high",
                title="Code execution primitive",
                description="Raw-content match for exec primitive (os.system, subprocess, eval, exec, shell=true)",
                file=rel_path, line=exec_hit[0],
                snippet=exec_hit[1],
                category="code-execution",
            ))
            findings.append(Finding(
                scanner="trifecta_raw", severity="high",
                title="Outbound network primitive",
                description="Raw-content match for outbound network primitive (http.client, requests.post, urllib, socket, axios)",
                file=rel_path, line=network_hit[0],
                snippet=network_hit[1],
                category="exfiltration",
            ))
            findings.append(Finding(
                scanner="trifecta_raw", severity="high",
                title="Credential read primitive",
                description="Raw-content match for credential read primitive (.ssh/id_*, .aws/credentials, .netrc, GITHUB_TOKEN)",
                file=rel_path, line=credential_hit[0],
                snippet=credential_hit[1],
                category="credential-read",
            ))

    return findings


# --- Correlation Engine ---


def findings_from_dicts(dicts):
    """Convert a sequence of finding dicts back into Finding dataclass instances.

    Shared helper used by both `aggregate_json.run_correlation_pass` and
    `auto_scan.run_targeted_scan` to avoid diverged copy-paste of the
    conversion logic. (Pattern-recognition PR-F1, 2026-04-05.)

    Skips items that aren't dicts or fail construction (e.g. malformed
    scanner output). Type coercion for `line` (to int) is delegated to
    Finding.__post_init__ which handles None, str, and out-of-range values.
    """
    out = []
    for d in dicts:
        if not isinstance(d, dict):
            continue
        try:
            out.append(Finding(
                scanner=d.get("scanner", "unknown"),
                severity=d.get("severity", "low"),
                title=d.get("title", ""),
                description=d.get("description", ""),
                file=d.get("file", ""),
                line=d.get("line", 0),
                snippet=d.get("snippet", ""),
                category=d.get("category", ""),
            ))
        except (TypeError, ValueError):
            continue
    return out


def correlate(findings):
    """Flag compound threats where multiple findings in the same file form attack chains.

    Rules:
    - env/credential read + network POST in same file = "Potential data exfiltration" (critical)
    - base64 encoding + exec/eval in same file = "Obfuscated code execution" (critical)
    - file read of sensitive paths + any network call = "Credential theft pattern" (high)
    - Rule 19: exec + network + credential read in same file = "Lethal Trifecta" (critical)
    """
    correlated = []

    # Group findings by file path. Scanners emit paths relative to the
    # scanned repo, so we use the path string as-is. (An earlier revision
    # tried os.path.realpath here but that resolves relative paths against
    # the current working directory, not the scan target, which fragmented
    # findings and broke Rule 19. Symlink-based split attacks across two
    # different relative paths are a P1 follow-up.)
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

        # Rule 17: .pth file + base64/exec (liteLLM-style startup injection)
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

        # Rule 18: .pth file + known IOC = "Known Supply Chain .pth Attack"
        # (previously mis-labeled as Rule 16 — corrected 2026-04-05)
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

        # Rule 19: Lethal Trifecta — exec + outbound network + credential read
        # all in the same file. Named after Snyk's terminology. Per the
        # SkillSafe ClawHavoc post-mortem, this pattern catches ~91% of
        # malicious skills that evade the simpler Rule 1/Rule 3 checks.
        #
        # False-positive hardening (2026-04-05 code review):
        #   - Narrow keywords: removed bare "exec", "post", "http", "fork",
        #     "socket", "network", "request", ".env", "password", "secret",
        #     "credential". Those substrings appear in legitimate CI build
        #     scripts (e.g. "executable", "postgres", "urllib HTTP request",
        #     ".env.example", "password field") and fired false positives
        #     at the critical level.
        #   - Require each primitive-hit to come from a distinct scanner.
        #     A single kitchen-sink finding that mentions all three primitives
        #     in its description should not trip the rule on its own — real
        #     Lethal Trifecta malware has each primitive flagged by the
        #     appropriate specialized scanner (sast/dataflow/secrets).
        trifecta_exec_keywords = {
            "code execution", "code-execution", "arbitrary code",
            "remote code", "shell execution", "shell-exec",
            "eval(", "exec(", "os.system(", "os.system ",
            "subprocess.run", "subprocess.call", "subprocess.popen",
            "subprocess.check_output", "subprocess.exec",
            "child_process.exec", "child_process.spawn",
            "child_process.execsync", "command injection",
            "shell=true", "dangerous exec",
        }
        trifecta_network_keywords = {
            "exfiltration", "exfiltrate", "data theft",
            "outbound network", "outbound-network", "outbound http",
            "outbound-http", "webhook post", "webhook-post", "webhook exfil",
            "reverse shell", "reverse-shell", "/dev/tcp/",
            "requests.post(", "urllib.request.urlopen(",
            "socket.connect(", "socket.send(", "socket.sendto(",
            "http.client.httpsconnection", "http.client.httpconnection",
            "node-fetch(", "axios.post(", "axios.get(",
            "command and control", "c2 callback", "data posted to external",
            "posts to webhook",
        }
        trifecta_credential_keywords = {
            "credential read", "credential-read", "credential file",
            "credential access", "credential theft", "credential exfil",
            "secret read", "secret-read", "secret exfil",
            "env access", "env-access", ".env read", ".env access",
            "env_key read",
            ".ssh/id_", ".aws/credentials", ".aws/config",
            ".netrc", "id_rsa", "id_ed25519",
            "keychain access", "keychain read",
            "github_token", "api_key read", "api-key read",
            "browser data", "private key read", "token theft",
        }

        def _primitive_finding_ids(keywords):
            """Return set of distinct finding-indices that matched the keywords.

            Using indices (not scanner names) means multiple findings from
            the same synthetic scanner (e.g. trifecta_raw emits one finding
            per primitive) still count as distinct contributors — which is
            correct. The check blocks single "kitchen sink" findings that
            mention all three primitives in one description, not legitimate
            multi-finding matches from any source.
            """
            ids = set()
            for i, f in enumerate(file_findings):
                desc_lower = (f.description + " " + f.title + " " + f.category).lower()
                for kw in keywords:
                    if kw in desc_lower:
                        ids.add(i)
                        break
            return ids

        exec_ids = _primitive_finding_ids(trifecta_exec_keywords)
        network_ids = _primitive_finding_ids(trifecta_network_keywords)
        credential_ids = _primitive_finding_ids(trifecta_credential_keywords)

        # All three primitives must be present AND at least 2 must come from
        # different findings (so a single noisy finding cannot trip the rule
        # just by mentioning all three keywords in its description).
        has_exec = bool(exec_ids)
        has_network = bool(network_ids)
        has_credential = bool(credential_ids)
        distinct_contributors = exec_ids | network_ids | credential_ids
        if has_exec and has_network and has_credential and len(distinct_contributors) >= 2:
            # Rule 19 co-exists with Rules 1 and 3 when they fire on the same
            # file: the Trifecta finding carries extra attribution value
            # (names the pattern, ties to the SkillSafe ClawHavoc research).
            # No dedupe is needed because the titles and categories differ.
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Lethal Trifecta (exec + network + credential read)",
                description=(
                    "File contains all three primitives of the 'Lethal "
                    "Trifecta' (Snyk terminology): code execution, outbound "
                    "network capability, and credential/secret file access. "
                    "This co-occurrence pattern matches 91% of malicious "
                    "skills per the SkillSafe ClawHavoc post-mortem and is a "
                    "strong signal of credential-stealing malware even when "
                    "each primitive alone would be legitimate."
                ),
                file=filepath,
                line=0,
                snippet="[compound: exec + outbound network + credential read]",
                category="lethal-trifecta"
            ))

        # Rule 20: process.env exposure in error handler (same file)
        secret_exposure_keywords = {"secret-exposure", "process.env logged", "process.env serialized", "json.stringify"}
        error_handler_keywords = {"uncaughtexception", "unhandledrejection", "error handler", "crash report", "onerror"}
        if has_category(file_findings, secret_exposure_keywords) and has_category(file_findings, error_handler_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Secrets Leaked via Error Handler",
                description="process.env is logged or serialized in a file that also contains error handling. Any crash exposes all environment secrets to logs or files.",
                file=filepath,
                line=0,
                snippet="[compound: process.env exposure + error handler]",
                category="secret-leak-chain"
            ))

        # Rule 21: Devcontainer host secret mount + credential access pattern
        devcontainer_keywords = {"host-secret-exposure", "host secret mount", "pulls host secret", "localenv"}
        credential_access_keywords = {"credential-exfiltration", "credential exfiltration", "credential theft", "secret exfil", "token theft", "remote-code-execution"}
        if has_category(file_findings, devcontainer_keywords) and has_category(file_findings, credential_access_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Devcontainer Secret Exposure Chain",
                description="Devcontainer mounts host secrets AND code accesses credentials. Combined: full credential theft via container.",
                file=filepath,
                line=0,
                snippet="[compound: devcontainer host secret + credential access]",
                category="compound-threat"
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
