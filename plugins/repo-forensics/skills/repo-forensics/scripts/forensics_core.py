#!/usr/bin/env python3
"""
forensics_core.py - Core framework for repo-forensics v2
Provides Finding dataclass, severity system, output formatting,
correlation engine, and .forensicsignore support.

Created by Alex Greenshpun
"""

import math
import os
import re
import sys
import json
import time
import hashlib
import fnmatch
import urllib.parse
from dataclasses import dataclass, asdict

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


# Severity -> default confidence fallback map (KTD-8). Any code path that
# does not explicitly set confidence (legacy scanners, correlation-synthesized
# findings) gets a severity-derived value here. Confidence is ADDITIVE: it
# shapes verdict-tier messaging and adjudication only; severity still drives
# the 0/1/2/99 exit-code contract (KTD-7).
SEVERITY_CONFIDENCE = {
    "critical": 0.95,
    "high": 0.80,
    "medium": 0.60,
    "low": 0.40,
}


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
    rule_id: str = ""      # Stable rule id (e.g. "ST-PI-001"); "" for code-baked findings
    confidence: float = 0.0  # 0.0-1.0; 0.0/None means "fill from severity map"

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
        # rule_id is a plain string identifier; coerce non-strings/None to "".
        if not isinstance(self.rule_id, str):
            self.rule_id = "" if self.rule_id is None else str(self.rule_id)
        # Confidence dimension (KTD-7/8). When unset (None or exactly 0.0),
        # derive from the severity map so every finding carries a meaningful
        # confidence even on legacy code paths. Any explicitly-provided value
        # is clamped to [0.0, 1.0]. A non-numeric value (e.g. "high") or a
        # non-finite value (NaN / ±inf) falls back to the severity-derived
        # default rather than crashing the aggregator or producing non-standard
        # JSON (C4 fix: NaN compares False to every numeric test without isfinite).
        if self.confidence is None:
            self.confidence = SEVERITY_CONFIDENCE.get(self.severity, 0.40)
        else:
            try:
                conf = float(self.confidence)
            except (TypeError, ValueError):
                conf = 0.0
            # NaN and ±inf must be caught before < / > comparisons (C4).
            if not math.isfinite(conf) or conf == 0.0:
                conf = SEVERITY_CONFIDENCE.get(self.severity, 0.40)
            elif conf < 0.0:
                conf = 0.0
            elif conf > 1.0:
                conf = 1.0
            self.confidence = conf
        self._tags = (self.description + " " + self.title + " " + self.category).lower()

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
    """Loads PATH ignore patterns from a .forensicsignore file in the repo root.

    Backward compatible: returns the list of path-glob patterns used by the
    file walk. `rule:<id>[:<glob>]` lines are per-finding suppression
    directives (U1) handled separately by load_rule_suppressions() and are
    deliberately excluded here so they never act as path globs.
    """
    ignore_file = os.path.join(repo_path, '.forensicsignore')
    patterns = []

    if os.path.exists(ignore_file):
        try:
            with open(ignore_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and not line.startswith('rule:'):
                        patterns.append(line)
        except (OSError, UnicodeDecodeError) as e:
            print(f"[!] Warning: Could not read .forensicsignore: {e}", file=sys.stderr)

    return patterns


def load_rule_suppressions(repo_path):
    """Parse per-finding rule suppressions from a .forensicsignore file.

    Recognizes lines of the form:
        rule:<rule_id>            -> suppress that rule everywhere
        rule:<rule_id>:<glob>     -> suppress that rule only under <glob>

    The glob may itself contain ':' (e.g. a Windows-style path); only the
    first colon after the `rule:` prefix splits id from glob. A finding is
    suppressed when its rule_id matches and (if a glob is present) its file
    path matches the glob via fnmatch.

    Returns a list of dicts: {"rule_id": str, "glob": str|None, "raw": str}.
    Malformed lines (empty id) are skipped.
    """
    ignore_file = os.path.join(repo_path, '.forensicsignore')
    suppressions = []

    if not os.path.exists(ignore_file):
        return suppressions

    try:
        with open(ignore_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or not line.startswith('rule:'):
                    continue
                body = line[len('rule:'):]
                # Split id from optional glob on the FIRST colon.
                if ':' in body:
                    rule_id, glob = body.split(':', 1)
                    rule_id = rule_id.strip()
                    glob = glob.strip() or None
                else:
                    rule_id = body.strip()
                    glob = None
                if not rule_id:
                    continue
                suppressions.append({"rule_id": rule_id, "glob": glob, "raw": line})
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Warning: Could not read .forensicsignore: {e}", file=sys.stderr)

    return suppressions


def suppression_matches(suppression, rule_id, file_path):
    """Return True if a suppression directive applies to a finding.

    Match semantics (U5/U8 build on this):
      - rule_id must equal suppression["rule_id"] exactly (case-sensitive,
        matching the published `<SCANNER>-<CATEGORY>-<NNN>` id convention).
      - If suppression["glob"] is set, the finding's file path must also match
        that glob via fnmatch (forward-slash normalized for cross-platform
        consistency). A finding with no rule_id never matches.
    """
    if not rule_id:
        return False
    if suppression.get("rule_id") != rule_id:
        return False
    glob = suppression.get("glob")
    if not glob:
        return True
    path = (file_path or "").replace(os.sep, "/")
    return fnmatch.fnmatch(path, glob)


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
MAX_LINE_LENGTH = 10000  # Truncate lines longer than this to prevent ReDoS (C3)
# C2: coarse per-call wall-clock budget for scan_patterns / scan_rule_patterns.
# A regex that slips past the static heuristic + length cap still cannot wedge
# an entire scan indefinitely. The check fires every _SCAN_BUDGET_CHECK_INTERVAL
# lines; if elapsed > _SCAN_FILE_BUDGET_SEC the current file is aborted.
# This is deliberately coarse (not per-call SIGALRM) to stay cross-platform and
# keep overhead negligible on the hot loop (one time.monotonic() per N lines,
# not per regex call). The static heuristic (C1) + length cap remain the primary
# defence; this is defence-in-depth.
_SCAN_FILE_BUDGET_SEC = 10.0
_SCAN_BUDGET_CHECK_INTERVAL = 500  # lines between time checks


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


def walk_aux(repo_path, ignore_patterns=None, skip_dirs=None, *,
             apply_size_cap=False, reach_pycache=False, skip_lockfiles=True):
    """Auxiliary walk for the binary-reaching scanners (oversize, bytecode,
    archive). Yields (file_path, rel_path).

    Unlike walk_repo this NEVER skips files by BINARY_EXTENSIONS — these
    scanners do their own byte-level inspection — and it makes two of
    walk_repo's hard-coded behaviours explicit per call:

    - apply_size_cap: when False (the default for these scanners), files larger
      than MAX_FILE_SIZE_MB are STILL yielded. walk_repo skips them
      unconditionally (the `os.path.getsize(...) > cap: continue` guard) so an
      attacker pads a payload past 10 MB to fall off every scanner's radar. The
      oversize/bytecode/archive scanners MUST see those files (the headline
      blind spot in the origin audit).
    - reach_pycache: when True, the __pycache__ directory is traversed. It is in
      IGNORE_DIRS and therefore invisible to walk_repo; the bytecode scanner
      needs it.

    Symlinks are still refused (traversal safety), lockfiles still skipped by
    default, and .forensicsignore patterns are still honoured.
    """
    if skip_dirs is None:
        skip_dirs = set(IGNORE_DIRS)
        if reach_pycache:
            skip_dirs.discard('__pycache__')
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

            if apply_size_cap:
                try:
                    if os.path.getsize(file_path) > MAX_FILE_SIZE_MB * 1024 * 1024:
                        continue
                except OSError:
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

# Each regex matches ONLY actionable code patterns — method calls with parens,
# specific file paths, or named constant references. Bare descriptive keywords
# (`webhook`, `api_key`, `browser data`, `reverse shell`, `keychain`) were
# removed in the 2026-04-05 torture review (CRC-F2) because they matched
# legitimate code comments, variable names, and doc strings and caused
# false-positive Rule 19 hits on every CI/integration test repo.
_TRIFECTA_EXEC_RE = re.compile(
    r'(?:os\.system\s*\(|subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(|'
    r'child_process\.(?:exec|spawn|execSync)\s*\(|(?<![a-zA-Z_])eval\s*\(|'
    r'(?<![a-zA-Z_])exec\s*\(|shell\s*=\s*True)'
)
_TRIFECTA_NETWORK_RE = re.compile(
    # Only actionable outbound network primitives with concrete call syntax.
    # Removed bare `webhook`, `reverse[\s_-]?shell`, and `node-fetch` which
    # were prose-level keywords that matched comments and docstrings.
    r'(?:http\.client\.HTTPS?Connection|urllib\.request\.urlopen|'
    r'requests\.(?:post|get|put|delete)\s*\(|socket\.(?:connect|send|sendto)\s*\(|'
    r'axios\.(?:post|get|put|delete)\s*\(|'
    r'\bfetch\s*\(\s*[\'"]https?://|'
    r'/dev/tcp/)'
)
_TRIFECTA_CREDENTIAL_RE = re.compile(
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


# --- Registry-hijack raw correlation detector (GAP 3) -----------------------
# A skill that redirects npm/yarn/pip package resolution to a non-canonical host
# is a dependency-confusion / supply-chain vector. Hostname alone cannot prove
# malice (legitimate corporate mirrors look identical), so a bare redirect is
# MEDIUM/WARN. It escalates to HIGH only when it co-occurs with reviewer-directed
# "assurance" prose (engineered to disarm a human/LLM reviewer) or with an
# install-time / lifecycle script (a redirect that auto-runs persists on every
# future install). Calibrated for accuracy over aggression: the benign-corpus FP
# gate must stay green (a clean corporate mirror flags MEDIUM, never HIGH).
_REGISTRY_CANONICAL_HOSTS = (
    "registry.npmjs.org", "registry.yarnpkg.com", "registry.yarnpkg.org",
    "pypi.org", "files.pythonhosted.org", "registry.bower.io",
    "registry.npmmirror.com",  # well-known public mirror, not attacker-specific
)
_REGISTRY_SCAN_EXTS = {".sh", ".bash", ".zsh", ".ksh", ".conf", ".cfg", ".ini",
                       ".toml", ".cmd", ".ps1", ".js", ".ts", ".py", ".rb",
                       ".env", ".yml", ".yaml", ".npmrc", ".yarnrc"}
_REGISTRY_SCAN_NAMES = {".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini",
                        ".pip.conf", "bunfig.toml", ".bunfig.toml"}
_REGISTRY_MAX_SCAN_FILES = 2000
_REGISTRY_MAX_SCAN_BYTES = 512 * 1024
# A registry/index-url directive and the value it is set to (a literal URL or a
# ${VAR}/$VAR reference resolved against same-file assignments). Covers npm/pip
# (registry / index-url) and Yarn Berry (.yarnrc.yml npmRegistryServer). The
# `\s*(?:[=:]\s*)?` form avoids the catastrophic-backtracking (ReDoS) of two
# adjacent greedy `\s*` runs around an optional separator.
_REGISTRY_DIRECTIVE_RE = re.compile(
    r"""(?im)\b((?:extra-)?index-url|registry|npmRegistryServer|npmPublishRegistry)\b"""
    r"""\s*(?:[=:]\s*)?["']?"""
    r"""(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|https?://[^\s"']+)""")
_URL_VAR_ASSIGN_RE = re.compile(
    r"""(?im)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?(https?://[^\s"']+)""")
# Reviewer-directed assurance prose: self-justifying safety claims aimed at the
# reviewer to disarm scrutiny of the redirect. Each alternative is specific
# enough to be rare in benign docs — generic phrasing like "safe to use" or
# "standard practice" is deliberately excluded to keep the HIGH escalation
# false-positive-free.
_REGISTRY_ASSURANCE_RE = re.compile(
    r"""(?i)("""
    r"""already public(\s+information)?|"""
    r"""appsec[-\s]?audited|audited\s+(dependency|allowlist|allow-list)|"""
    r"""(does not|doesn't)\s+introduce\s+(new\s+)?(disclosure|attack|exposure)\s*(surface)?|"""
    r"""no\s+(new\s+)?(disclosure|attack|exposure)\s+surface|"""
    r"""(is|are)\s+the\s+same\s+value(s)?\s+(published|referenced|shown)|"""
    r"""no\s+(auth\w*|credentials?|secrets?)\s+(are\s+)?(written|stored|disclosed)"""
    r""")""")


_REGISTRY_VAR_REF_RE = re.compile(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")


def _registry_host(value, var_urls):
    """Resolve a registry directive value to a hostname. Handles ${VAR}/$VAR
    references via same-file URL assignments. Returns host or None."""
    val = value.strip().strip('"\'')
    var_ref = _REGISTRY_VAR_REF_RE.match(val)
    if var_ref:
        val = var_urls.get(var_ref.group(1))
        if not val:
            return None
    if not val.startswith(("http://", "https://")):
        return None
    try:
        return urllib.parse.urlsplit(val).hostname
    except ValueError:
        return None


def detect_registry_hijack_raw(repo_path, ignore_patterns=None):
    """Scan for package-registry redirection (GAP 3). Returns Finding objects:
    a MEDIUM `registry-redirect` per affected file, plus a HIGH `registry-hijack`
    when the redirect co-occurs with reviewer-assurance prose or an install-time
    script. Reads files directly (like detect_trifecta_raw) so the standalone
    assurance signal never surfaces on its own."""
    findings = []
    if not repo_path or not os.path.isdir(repo_path):
        return findings
    try:
        walker = walk_repo(repo_path, ignore_patterns=ignore_patterns,
                           skip_binary=True, skip_lockfiles=True)
    except OSError:
        return findings

    scanned = 0
    for file_path, rel_path in walker:
        if scanned >= _REGISTRY_MAX_SCAN_FILES:
            break
        base = os.path.basename(file_path).lower()
        ext = os.path.splitext(base)[1].lower()
        if ext not in _REGISTRY_SCAN_EXTS and base not in _REGISTRY_SCAN_NAMES:
            continue
        # Count toward the budget once a file passes the extension gate, so an
        # adversarial flood of large config-extension files still terminates.
        scanned += 1
        try:
            if os.path.getsize(file_path) > _REGISTRY_MAX_SCAN_BYTES:
                continue
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except (OSError, UnicodeDecodeError):
            continue

        # Strip comment lines before matching directives: a commented-out mirror
        # URL (common in setup.py / .npmrc docs) is not an active redirect.
        scan_lines = [ln for ln in content.splitlines()
                      if not ln.lstrip().startswith(("#", ";"))]
        scan_content = "\n".join(scan_lines)

        var_urls = {m.group(1): m.group(2)
                    for m in _URL_VAR_ASSIGN_RE.finditer(scan_content)}
        redirect_hosts = []
        redirect_line = 0
        for m in _REGISTRY_DIRECTIVE_RE.finditer(scan_content):
            host = _registry_host(m.group(2), var_urls)
            if host and not any(host == c or host.endswith("." + c)
                                for c in _REGISTRY_CANONICAL_HOSTS):
                if host not in redirect_hosts:
                    redirect_hosts.append(host)
                    if not redirect_line:
                        redirect_line = scan_content.count("\n", 0, m.start()) + 1
        if not redirect_hosts:
            continue

        hosts_str = ", ".join(redirect_hosts)
        findings.append(Finding(
            scanner="registry_hijack", severity="medium",
            title="Package registry redirected to non-canonical host",
            description=(
                "A package-manager configuration points dependency resolution at "
                f"a non-canonical endpoint ({hosts_str}). Corporate mirrors are "
                "legitimate, so review whether this endpoint is trusted; an "
                "untrusted one is a dependency-confusion / supply-chain redirect."),
            file=rel_path, line=redirect_line, snippet=hosts_str,
            category="registry-redirect"))

        # Escalate to HIGH only on reviewer-directed assurance prose — the
        # unambiguous manipulation signal. Install-script context alone is NOT
        # escalated: legitimate corporate bootstrap/setup scripts routinely set a
        # mirror, so escalating on filename would false-positive on every one.
        if _REGISTRY_ASSURANCE_RE.search(content):
            findings.append(Finding(
                scanner="registry_hijack", severity="high",
                title="Registry redirect wrapped in reviewer-disarming assurance prose",
                description=(
                    f"The registry redirect to {hosts_str} co-occurs with "
                    "self-justifying assurance language ('already public', "
                    "'audited', 'introduces no disclosure surface') engineered to "
                    "disarm a reviewer. A genuine corporate mirror does not need to "
                    "argue for its own safety — this is the dependency-confusion "
                    "social-engineering pattern."),
                file=rel_path, line=redirect_line, snippet=hosts_str,
                category="registry-hijack"))
    return findings


def scan_text_trifecta(text, rel_path):
    """Run the three Lethal-Trifecta primitive regexes over an in-memory text
    blob (a disassembled .pyc listing, an extracted archive member) and return
    one Finding per primitive that matches.

    Unlike detect_trifecta_raw — which is path-based, gated to source
    extensions, and emits only when ALL THREE primitives co-occur to feed Rule
    19 — this helper:
      * accepts text directly (no file on disk, no extension gate), and
      * emits each matched primitive INDIVIDUALLY, because a single exec or
        credential-read primitive hidden inside compiled bytecode or an archive
        member is itself worth surfacing (that hiding is the whole attack).

    Severity stays "high"; the caller re-labels title/category as needed (e.g.
    bytecode-hidden-logic, archive-indirection). Comment-only lines are skipped,
    matching detect_trifecta_raw, and only the first match per primitive is
    recorded (bounded — early-exits once all three are seen).
    """
    findings = []
    primitives = (
        (_TRIFECTA_EXEC_RE, "Code execution primitive", "code-execution",
         "Raw-content match for exec primitive (os.system, subprocess, eval, exec, shell=true)"),
        (_TRIFECTA_NETWORK_RE, "Outbound network primitive", "exfiltration",
         "Raw-content match for outbound network primitive (http.client, requests.post, urllib, socket, axios)"),
        (_TRIFECTA_CREDENTIAL_RE, "Credential read primitive", "credential-read",
         "Raw-content match for credential read primitive (.ssh/id_*, .aws/credentials, .netrc, GITHUB_TOKEN)"),
    )
    seen = [False, False, False]
    # split('\n') (not splitlines()) so a payload cannot be hidden across a
    # Unicode line-boundary char (\x0b,  , …) that splitlines would break
    # but a single-line regex would otherwise see as one line on the file path.
    for line_num, line in enumerate(text.split('\n'), start=1):
        stripped = line.lstrip()
        if stripped.startswith(('#', '//', ';;', '/*', '*')):
            continue
        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]
        for idx, (regex, title, category, desc) in enumerate(primitives):
            if not seen[idx] and regex.search(line):
                seen[idx] = True
                findings.append(Finding(
                    scanner="trifecta_raw", severity="high",
                    title=title, description=desc,
                    file=rel_path, line=line_num,
                    snippet=line.strip()[:120],
                    category=category,
                ))
        if all(seen):
            break
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
    return list(findings_from_dicts_iter(dicts))


def findings_from_dicts_iter(dicts):
    """Yield Finding instances lazily from a sequence of dicts.

    Generator variant of findings_from_dicts. Passing this directly to
    correlate() avoids holding a full parallel Finding list in memory
    alongside the source dicts -- correlate() builds its by_file dict
    by consuming the iterator once, so no separate list is ever created.
    """
    for d in dicts:
        if not isinstance(d, dict):
            continue
        try:
            yield Finding(
                scanner=d.get("scanner", "unknown"),
                severity=d.get("severity", "low"),
                title=d.get("title", ""),
                description=d.get("description", ""),
                file=d.get("file", ""),
                line=d.get("line", 0),
                snippet=d.get("snippet", ""),
                category=d.get("category", ""),
            )
        except (TypeError, ValueError):
            continue


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

    # Rules 22-27: Checkmarx-sourced compound threat keywords
    command_jacking_keywords = {"command-jacking", "shadows system command"}
    model_confusion_keywords = {"model-confusion", "from_pretrained", "trust_remote_code"}
    compromised_action_keywords = {"compromised-action", "compromised action"}
    secrets_keywords = {"secret", "credential", "token", "password", "api.key"}
    steg_keywords = {"audio-steganography", "steganography", "audio steg"}
    worm_keywords = {"worm-propagation", "npm publish", "package enumeration"}
    npm_token_keywords = {"npmrc", "npm_token", "npm-token", "credential-theft"}
    destructive_keywords = {"destructive-command", "shred", "cipher /w", "disk overwrite", "home directory"}
    locale_gating_keywords = {"locale-gating", "locale gating", "geoip", "country_code", "navigator.language"}
    proc_mem_keywords = {"memory-forensics", "process memory read"}
    process_enum_keywords = {"process-enumeration", "runner.worker", "process hunt"}
    llmo_keywords = {"llmo-suspicious", "llmo suspicious"}
    brand_new_keywords = {"freshness-brand-new-package", "brand new package", "single version"}

    def has_category(file_findings, keywords, exclude_scanner=None):
        for f in file_findings:
            if exclude_scanner and f.scanner == exclude_scanner:
                continue
            tags = f._tags
            for kw in keywords:
                if kw in tags:
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
        if has_category(file_findings, openclaw_keywords) and has_category(file_findings, prompt_injection_keywords, exclude_scanner="agent_skills"):
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
                tags = f._tags
                for kw in keywords:
                    if kw in tags:
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

        # Rule 22: Command-Jacking (entry point shadows system command)
        if has_category(file_findings, command_jacking_keywords) and has_category(file_findings, network_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Command-Jacking + Network Access",
                description="Package shadows a system CLI command AND makes network calls. Combined: command wrapping with credential exfiltration (Checkmarx Command-Jacking, October 2024).",
                file=filepath,
                line=0,
                snippet="[compound: command-jacking + network call]",
                category="command-jacking-chain"
            ))

        # Rule 23: Model Confusion + trust_remote_code
        if has_category(file_findings, model_confusion_keywords) and has_category(file_findings, exec_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Model Confusion + Code Execution",
                description="File loads AI models with bare paths AND enables code execution (trust_remote_code or torch.load). Combined: full RCE via model registry confusion (Checkmarx Model Confusion, January 2026).",
                file=filepath,
                line=0,
                snippet="[compound: model confusion + code execution]",
                category="model-confusion-chain"
            ))

        # Rule 24: Compromised GitHub Action + secrets exposure
        if has_category(file_findings, compromised_action_keywords) and has_category(file_findings, secrets_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Compromised Action + Secret Access",
                description="Workflow uses a known-compromised GitHub Action AND handles secrets. Combined: direct secret exfiltration via supply chain (TeamPCP/tj-actions pattern).",
                file=filepath,
                line=0,
                snippet="[compound: compromised action + secrets]",
                category="compromised-action-chain"
            ))

        # Rule 25: Audio steganography + network call
        if has_category(file_findings, steg_keywords) and has_category(file_findings, network_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Audio Steganography + Network Fetch",
                description="Audio file contains hidden executable content AND network calls detected in same context. Combined: steganographic payload delivery (TeamPCP Telnyx pattern, March 2026).",
                file=filepath,
                line=0,
                snippet="[compound: audio steganography + network]",
                category="steganography-chain"
            ))

        # Rule 26: NPM worm propagation pattern
        if has_category(file_findings, worm_keywords) and has_category(file_findings, npm_token_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="NPM Worm: Publish + Token Access",
                description="Code contains npm publish capabilities AND accesses npm tokens. Combined: self-propagating npm worm pattern (Shai-Hulud, September 2025).",
                file=filepath,
                line=0,
                snippet="[compound: npm publish + token theft]",
                category="worm-propagation-chain"
            ))

        # Rule 27: Destructive command + credential failure
        if has_category(file_findings, destructive_keywords) and has_category(file_findings, env_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Destructive Fallback + Credential Access",
                description="File contains destructive commands AND credential access. Combined: destructive fallback when exfiltration fails (Shai-Hulud v2 pattern, November 2025).",
                file=filepath,
                line=0,
                snippet="[compound: destructive command + credential access]",
                category="destructive-fallback-chain"
            ))

        # Rule 28: AI tool persistence + credential theft (Mini Shai-Hulud, April 2026)
        ai_persistence_keywords = {"ai-tool-persistence", "claude code hook", "sessionstart", "folder open", "vscode task"}
        if has_category(file_findings, ai_persistence_keywords) and has_category(file_findings, env_keywords | sensitive_read_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="AI Tool Persistence + Credential Theft",
                description="AI tool hook injection combined with credential access. Combined: Mini Shai-Hulud persistence pattern. Infected repos re-execute dropper on every Claude Code/VS Code session (TeamPCP Wave 6, April 2026).",
                file=filepath,
                line=0,
                snippet="[compound: AI tool hook + credential access]",
                category="ai-persistence-chain"
            ))

        # Rule 29: Git-based exfiltration + credential collection (Mini Shai-Hulud, April 2026)
        git_exfil_keywords = {"git-exfiltration", "repo creation", "content push", "commit search"}
        if has_category(file_findings, git_exfil_keywords) and has_category(file_findings, env_keywords | sensitive_read_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Git-Based Data Exfiltration Chain",
                description="GitHub API calls for repo creation/content push combined with credential access. Combined: Mini Shai-Hulud exfiltrates stolen data by committing to victim's own GitHub account (TeamPCP Wave 6, April 2026).",
                file=filepath,
                line=0,
                snippet="[compound: git API exfil + credential access]",
                category="git-exfiltration-chain"
            ))

        # Rule 37: Geofenced Destructive Command (mistralai v2.4.6 backdoor, May 2026)
        if has_category(file_findings, locale_gating_keywords) and has_category(file_findings, destructive_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Geofenced Destructive Command",
                description="Locale/country check combined with destructive command. Exact pattern from mistralai v2.4.6 backdoor (May 2026): code checks user locale then conditionally wipes files or exfiltrates data for targeted regions.",
                file=filepath,
                line=0,
                snippet="[compound: locale gating + destructive command]",
                category="geofenced-destructive"
            ))

        # Rule 38: CI Runner Memory Extraction (Mini Shai-Hulud SAP, TanStack CVE-2026-45321)
        if has_category(file_findings, proc_mem_keywords) and has_category(file_findings, process_enum_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="CI Runner Memory Extraction",
                description="Process memory read combined with process enumeration. Exact pattern from Mini Shai-Hulud (SAP April 2026): enumerates Runner.Worker processes via /proc, reads their memory to extract OIDC tokens.",
                file=filepath,
                line=0,
                snippet="[compound: /proc/mem read + process enumeration]",
                category="ci-runner-memory-extraction"
            ))

        # Rule 39: LLMO Attack (ReversingLabs PromptMink, April 2026)
        if has_category(file_findings, llmo_keywords) and has_category(file_findings, brand_new_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="high",
                title="LLMO Attack: AI-Named Brand-New Package",
                description="Brand-new single-version package with AI/crypto buzzword name. High probability of LLMO attack: attacker registers package names that LLMs hallucinate, waits for developers to install them (ReversingLabs PromptMink, April 2026).",
                file=filepath,
                line=0,
                snippet="[compound: brand-new package + AI/crypto naming pattern]",
                category="llmo-attack"
            ))

        # Rule 40: Entrypoint payload + credential theft
        # Matches entrypoint scanner categories: entrypoint-iife, entrypoint-import-exec
        entrypoint_keywords = {"entrypoint", "entrypoint-iife", "entrypoint-import-exec"}
        entrypoint_credential_keywords = {"credential", "env", "process.env", "os.environ"}
        if has_category(file_findings, entrypoint_keywords) and has_category(file_findings, entrypoint_credential_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Supply Chain Entrypoint: Credential Theft via require()/import",
                description="Entrypoint manipulation combined with credential access in the same file. This co-occurrence indicates a supply chain compromise: malicious code injected at the module entrypoint harvests environment variables or credentials on every require()/import.",
                file=filepath,
                line=0,
                snippet="[compound: entrypoint manipulation + credential access]",
                category="entrypoint-credential-chain"
            ))

        # Rule 41: Entrypoint payload + network exfiltration
        # Matches entrypoint scanner categories: entrypoint-iife, entrypoint-import-exec
        entrypoint_network_keywords = {"network", "fetch", "request", "http", "exfil", "socket"}
        if has_category(file_findings, entrypoint_keywords) and has_category(file_findings, entrypoint_network_keywords):
            correlated.append(Finding(
                scanner="correlation",
                severity="critical",
                title="Supply Chain Entrypoint: Data Exfiltration via require()/import",
                description="Entrypoint manipulation combined with network access in the same file. Code injected at the module entrypoint can silently exfiltrate data on every require()/import without triggering normal execution-path analysis.",
                file=filepath,
                line=0,
                snippet="[compound: entrypoint manipulation + network exfiltration]",
                category="entrypoint-exfiltration-chain"
            ))

    # ================================================================
    # Repo-wide correlation rules (not per-file)
    # These rules check for compound threats across the entire repo,
    # not limited to co-occurrence within a single file.
    # Proximity filtering: only correlate findings from files within
    # the same directory tree to reduce false positives.
    # Source: Terra Security OpenClaw vulnerability research (May 2026)
    # Source: DeepMind AI Agent Traps (March 2026)
    # ================================================================
    update_channel_keywords = {"update-channel", "deferred update channel", "update channel"}
    prose_imperative_keywords = {"prose-imperative", "prose imperative", "exfiltration instruction"}
    config_write_keywords = {"config-write-request", "config write request", "hook installation"}
    sub_agent_keywords = {"sub-agent-spawn", "sub-agent spawn", "agent spawn", "child agent"}
    authority_framing_kws = {"authority-framing", "authority claim", "safety theater", "trust escalation"}
    memory_poisoning_kws = {"memory-poisoning", "memory write", "rag poisoning", "provenance-stripping", "provenance stripping"}
    css_steg_keywords = {"css-steganography", "css hiding", "visual hiding"}
    cred_exfil_keywords = {"credential-exfiltration", "credential exfil", "credential theft", "exfil-pattern"}
    action_directive_keywords = {"code-execution", "shell-injection", "config-write-request", "code execution"}

    def _findings_by_dir(flist, keywords):
        """Return dict mapping directory -> list of findings matching keywords."""
        result = {}
        for f in flist:
            tags = f._tags
            for kw in keywords:
                if kw in tags:
                    d = os.path.dirname(f.file) if f.file else ""
                    result.setdefault(d, []).append(f)
                    break
        return result

    def _dirs_overlap(dirs_a, dirs_b):
        """True if any directory from set A shares a prefix with any from set B."""
        for da in dirs_a:
            for db in dirs_b:
                if da == db or da.startswith(db + "/") or db.startswith(da + "/") or da == "" or db == "":
                    return True
        return False

    update_dirs = _findings_by_dir(findings, update_channel_keywords)
    prose_dirs = _findings_by_dir(findings, prose_imperative_keywords)
    config_write_dirs = _findings_by_dir(findings, config_write_keywords)
    sub_agent_dirs = _findings_by_dir(findings, sub_agent_keywords)
    memory_dirs = _findings_by_dir(findings, memory_poisoning_kws)
    css_steg_dirs = _findings_by_dir(findings, css_steg_keywords)

    has_update_channel = bool(update_dirs)
    has_prose_imperative = bool(prose_dirs)
    has_config_write = bool(config_write_dirs)

    # Rule 30: Staged Injection Kill Chain (Terra Security OpenClaw, May 2026)
    if has_update_channel and has_prose_imperative and _dirs_overlap(update_dirs, prose_dirs):
        correlated.append(Finding(
            scanner="correlation",
            severity="critical",
            title="Staged Injection Kill Chain (update channel + prose exfiltration)",
            description="Skill creates an update channel AND contains prose exfiltration instructions in co-located files. Matches Terra Security staged injection pattern (May 2026).",
            file="",
            line=0,
            snippet="[compound: update channel + prose imperative across repo]",
            category="staged-injection-chain"
        ))

    # Rule 31: Workspace Persistence Setup (Terra Security OpenClaw, May 2026)
    if has_config_write and has_update_channel and _dirs_overlap(config_write_dirs, update_dirs):
        correlated.append(Finding(
            scanner="correlation",
            severity="critical",
            title="Workspace Persistence Setup (config write + update channel)",
            description="Skill requests writing to auto-executed config files AND creates an update channel in co-located files. Combined: persistent remote control via workspace file modification (Terra Security OpenClaw, May 2026).",
            file="",
            line=0,
            snippet="[compound: config write request + update channel across repo]",
            category="workspace-persistence-chain"
        ))

    # Rule 32: Sub-Agent Hijack Exfiltration Chain (DeepMind Agent Traps, March 2026)
    cred_exfil_dirs = _findings_by_dir(findings, cred_exfil_keywords)
    if sub_agent_dirs and cred_exfil_dirs and _dirs_overlap(sub_agent_dirs, cred_exfil_dirs):
        correlated.append(Finding(
            scanner="correlation",
            severity="critical",
            title="Sub-Agent Hijack Exfiltration Chain",
            description="Sub-agent spawn directive combined with credential access or exfiltration URL. DeepMind reports >80% success rate for file exfiltration via this vector (Agent Traps, March 2026).",
            file="",
            line=0,
            snippet="[compound: sub-agent spawn + credential exfil across repo]",
            category="sub-agent-hijack-chain"
        ))

    # Rule 33: Social Engineering Assisted Attack (DeepMind Agent Traps, March 2026)
    authority_dirs = _findings_by_dir(findings, authority_framing_kws)
    action_dirs = _findings_by_dir(findings, action_directive_keywords)
    if authority_dirs and action_dirs and _dirs_overlap(authority_dirs, action_dirs):
        correlated.append(Finding(
            scanner="correlation",
            severity="high",
            title="Social Engineering Assisted Attack",
            description="Authority framing or safety theater combined with action directives (code execution, file write, network call). Semantic manipulation lowers agent refusal threshold (DeepMind Agent Traps, March 2026).",
            file="",
            line=0,
            snippet="[compound: authority framing + action directive across repo]",
            category="social-engineering-chain"
        ))

    # Rule 34: Persistent Memory Backdoor (DeepMind Agent Traps, March 2026)
    pi_dirs = _findings_by_dir(findings, prompt_injection_keywords)
    if memory_dirs and pi_dirs and _dirs_overlap(memory_dirs, pi_dirs):
        correlated.append(Finding(
            scanner="correlation",
            severity="critical",
            title="Persistent Memory Backdoor",
            description="Memory/RAG poisoning indicator combined with prompt injection directive. Creates persistent backdoor that activates in future sessions (DeepMind Agent Traps, March 2026).",
            file="",
            line=0,
            snippet="[compound: memory poisoning + prompt injection across repo]",
            category="memory-backdoor-chain"
        ))

    # Rule 35: Hidden Instruction via Visual Steganography (DeepMind Agent Traps, March 2026)
    if css_steg_dirs and pi_dirs and _dirs_overlap(css_steg_dirs, pi_dirs):
        correlated.append(Finding(
            scanner="correlation",
            severity="critical",
            title="Hidden Instruction via Visual Steganography",
            description="CSS/HTML visual hiding combined with prompt injection keywords. Hidden instructions invisible to human reviewers but parseable by agents. 92.7% success rate (DeepMind Agent Traps, March 2026).",
            file="",
            line=0,
            snippet="[compound: CSS steganography + prompt injection across repo]",
            category="visual-steganography-chain"
        ))

    # Rule 36: Deferred Sub-Agent Injection (Terra + DeepMind combined)
    if update_dirs and sub_agent_dirs and _dirs_overlap(update_dirs, sub_agent_dirs):
        correlated.append(Finding(
            scanner="correlation",
            severity="critical",
            title="Deferred Sub-Agent Injection",
            description="Update channel combined with sub-agent spawn directive. The exact Terra Security attack pattern elevated with agent spawning: benign install creates update mechanism, future update spawns rogue sub-agent.",
            file="",
            line=0,
            snippet="[compound: update channel + sub-agent spawn across repo]",
            category="deferred-sub-agent-chain"
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
    _t0 = time.monotonic()
    for i, line in enumerate(lines):
        # C2: coarse per-file budget check every N lines to abort runaway scans.
        if i % _SCAN_BUDGET_CHECK_INTERVAL == 0 and i > 0:
            if time.monotonic() - _t0 > _SCAN_FILE_BUDGET_SEC:
                print(
                    f"[forensics_core] scan_patterns: per-file budget exceeded "
                    f"({_SCAN_FILE_BUDGET_SEC}s) scanning {rel_path!r} at line {i+1} "
                    f"— aborting remainder of file",
                    file=sys.stderr,
                )
                break
        # C3: truncate instead of skip — prefix is still scanned (closes the
        # detection-evasion hole where a secret on a >10000-char line was missed)
        # while bounding regex input length (ReDoS surface reduction).
        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]
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


def scan_rule_patterns(content, rel_path, rules, category, default_severity, scanner_name):
    """Pack-aware variant of scan_patterns (U4 rules-as-data).

    `rules` is an iterable of compiled rule objects (rule_loader.CompiledRule):
    each carries .regex, .title, .id, .confidence. Behaviorally identical to
    scan_patterns (same severity-from-call-site, same description, same snippet,
    same per-line/per-pattern emission order) but stamps the pack rule_id and
    confidence onto every finding. Severity stays the call-site default to
    preserve parity with the pre-extraction tuple-list scanners.

    This function does NOT import rule_loader (KTD-14): it only consumes the
    already-compiled rule objects the caller passes in.
    """
    findings = []
    lines = content.split('\n')
    _t0 = time.monotonic()
    for i, line in enumerate(lines):
        # C2: coarse per-file budget check every N lines.
        if i % _SCAN_BUDGET_CHECK_INTERVAL == 0 and i > 0:
            if time.monotonic() - _t0 > _SCAN_FILE_BUDGET_SEC:
                print(
                    f"[forensics_core] scan_rule_patterns: per-file budget exceeded "
                    f"({_SCAN_FILE_BUDGET_SEC}s) scanning {rel_path!r} at line {i+1} "
                    f"— aborting remainder of file",
                    file=sys.stderr,
                )
                break
        # C3: truncate instead of skip (same rationale as scan_patterns above).
        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]
        for rule in rules:
            if rule.regex.search(line):
                findings.append(Finding(
                    scanner=scanner_name, severity=default_severity,
                    title=rule.title,
                    description=f"Matched in {category} scan",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category=category,
                    rule_id=rule.id,
                    confidence=rule.confidence,
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
            print("\n[+] No issues found.")


# ---------------------------------------------------------------------------
# Shared atomic-write helper (consolidates the four near-duplicate impls
# previously scattered across vuln_feed, ioc_manager, session_scan, and
# refresh_threat_dbs). Always temp+fsync+chmod+replace, mode 0o600,
# explicit cleanup on any failure (including BaseException).
# ---------------------------------------------------------------------------

def _atomic_write_via(path, mode, write_fn):
    """Internal atomic-write engine. write_fn(file_obj) does the actual write."""
    import os as _os
    import uuid as _uuid

    dirpath = _os.path.dirname(path) or "."
    _os.makedirs(dirpath, exist_ok=True)
    tmp_path = f"{path}.tmp.{_os.getpid()}.{_uuid.uuid4().hex}"
    try:
        fd = _os.open(tmp_path, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, mode)
        try:
            # Explicit fchmod beats umask interference on shared systems.
            # os.fchmod is absent on Windows (AttributeError, NOT an OSError
            # subclass); the O_CREAT mode above already set the bits there.
            if hasattr(_os, "fchmod"):
                try:
                    _os.fchmod(fd, mode)
                except OSError:
                    pass
            # newline="" prevents the text-mode translation layer from
            # rewriting \n -> \r\n on Windows, which would otherwise corrupt
            # any byte-exact (e.g. signature-verified) payload.
            f = _os.fdopen(fd, "w", encoding="utf-8", newline="")
        except BaseException:
            # fdopen never took ownership of fd here: close it ourselves.
            try:
                _os.close(fd)
            except OSError:
                pass
            try:
                _os.unlink(tmp_path)
            except OSError:
                pass
            raise
        try:
            with f:
                write_fn(f)
                f.flush()
                _os.fsync(f.fileno())
        except BaseException:
            try:
                _os.unlink(tmp_path)
            except OSError:
                pass
            raise
        _os.replace(tmp_path, path)
    except OSError:
        try:
            _os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_write_json(path, data, mode=0o600):
    """Write `data` (any JSON-serializable value) to `path` atomically with
    fsync, fchmod, and rename. Mode defaults to 0o600 (user-only)."""
    import json as _json
    _atomic_write_via(path, mode, lambda f: _json.dump(data, f, indent=2))


def atomic_write_text(path, text, mode=0o600):
    """Write a plain text string atomically. Same guarantees as atomic_write_json."""
    _atomic_write_via(path, mode, lambda f: f.write(text))


def import_module_by_path(name, path):
    """Load a Python module by absolute path without polluting sys.path.

    Catches BaseException so SIGALRM / KeyboardInterrupt during exec_module
    can't leave a half-imported module wedged in sys.modules.

    Returns the module on success, None if the spec couldn't be built.
    """
    import importlib.util as _ilu
    import sys as _sys

    spec = _ilu.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    mod = _ilu.module_from_spec(spec)
    _sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        _sys.modules.pop(name, None)
        raise
    return mod
