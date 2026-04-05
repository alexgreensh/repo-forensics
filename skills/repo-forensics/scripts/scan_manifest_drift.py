#!/usr/bin/env python3
"""
scan_manifest_drift.py - Manifest Drift Scanner (v1)
Detects gaps between what a package DECLARES and what it actually USES:
phantom dependencies (imported but not declared), runtime package installs,
conditional import with install fallback, and declared-but-unused deps.

Pure static analysis using AST + manifest parsing. Zero new dependencies.

Research basis:
- PylangGhost RAT (March 2026): benign manifest, evil undeclared deps
- Snyk ToxicSkills (Feb 2026): 36.8% of skills have security flaws
- Socket.dev (2025-2026): supply chain attack via phantom dependencies

Created by Alex Greenshpun
"""

import os
import re
import ast
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "manifest_drift"

# Standard library modules (Python) - not expected in requirements
PYTHON_STDLIB = {
    'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio',
    'asyncore', 'atexit', 'base64', 'bdb', 'binascii', 'binhex',
    'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb', 'chunk',
    'cmath', 'cmd', 'code', 'codecs', 'codeop', 'collections',
    'colorsys', 'compileall', 'concurrent', 'configparser', 'contextlib',
    'contextvars', 'copy', 'copyreg', 'cProfile', 'crypt', 'csv',
    'ctypes', 'curses', 'dataclasses', 'datetime', 'dbm', 'decimal',
    'difflib', 'dis', 'distutils', 'doctest', 'email', 'encodings',
    'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput',
    'fnmatch', 'formatter', 'fractions', 'ftplib', 'functools', 'gc',
    'getopt', 'getpass', 'gettext', 'glob', 'grp', 'gzip', 'hashlib',
    'heapq', 'hmac', 'html', 'http', 'idlelib', 'imaplib', 'imghdr',
    'imp', 'importlib', 'inspect', 'io', 'ipaddress', 'itertools',
    'json', 'keyword', 'lib2to3', 'linecache', 'locale', 'logging',
    'lzma', 'mailbox', 'mailcap', 'marshal', 'math', 'mimetypes',
    'mmap', 'modulefinder', 'multiprocessing', 'netrc', 'nis', 'nntplib',
    'numbers', 'operator', 'optparse', 'os', 'ossaudiodev', 'parser',
    'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil',
    'platform', 'plistlib', 'poplib', 'posix', 'posixpath', 'pprint',
    'profile', 'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr',
    'pydoc', 'queue', 'quopri', 'random', 're', 'readline', 'reprlib',
    'resource', 'rlcompleter', 'runpy', 'sched', 'secrets', 'select',
    'selectors', 'shelve', 'shlex', 'shutil', 'signal', 'site',
    'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver', 'sqlite3',
    'ssl', 'stat', 'statistics', 'string', 'stringprep', 'struct',
    'subprocess', 'sunau', 'symtable', 'sys', 'sysconfig', 'syslog',
    'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios', 'test',
    'textwrap', 'threading', 'time', 'timeit', 'tkinter', 'token',
    'tokenize', 'tomllib', 'trace', 'traceback', 'tracemalloc', 'tty',
    'turtle', 'turtledemo', 'types', 'typing', 'unicodedata',
    'unittest', 'urllib', 'uu', 'uuid', 'venv', 'warnings', 'wave',
    'weakref', 'webbrowser', 'winreg', 'winsound', 'wsgiref',
    'xdrlib', 'xml', 'xmlrpc', 'zipapp', 'zipfile', 'zipimport', 'zlib',
    # Common internal/relative import markers
    '_thread', '__future__', '_io', '_collections_abc',
}

# Node built-in modules
NODE_BUILTINS = {
    'assert', 'buffer', 'child_process', 'cluster', 'console', 'constants',
    'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http', 'https',
    'module', 'net', 'os', 'path', 'process', 'punycode', 'querystring',
    'readline', 'repl', 'stream', 'string_decoder', 'timers', 'tls',
    'tty', 'url', 'util', 'v8', 'vm', 'worker_threads', 'zlib',
    'node:fs', 'node:path', 'node:http', 'node:https', 'node:crypto',
    'node:os', 'node:url', 'node:util', 'node:stream', 'node:events',
    'node:child_process', 'node:net', 'node:dns', 'node:tls',
    'node:buffer', 'node:process', 'node:vm', 'node:worker_threads',
}

# Runtime install patterns (critical - installs deps not in manifest)
RUNTIME_INSTALL_PATTERNS = [
    (re.compile(r'subprocess\.\w+\s*\(\s*\[?\s*["\']pip["\'],?\s*["\']install["\']'), "Runtime pip install via subprocess"),
    (re.compile(r'os\.system\s*\(\s*["\']pip\s+install'), "Runtime pip install via os.system()"),
    (re.compile(r'os\.system\s*\(\s*["\']pip3\s+install'), "Runtime pip3 install via os.system()"),
    (re.compile(r'subprocess\.\w+\s*\(\s*\[?\s*["\']npm["\'],?\s*["\']install["\']'), "Runtime npm install via subprocess"),
    (re.compile(r'os\.system\s*\(\s*["\']npm\s+install'), "Runtime npm install via os.system()"),
    (re.compile(r'subprocess\.\w+\s*\(\s*["\']pip\s+install'), "Runtime pip install via subprocess string"),
    (re.compile(r'check_call\s*\(\s*\[.*["\']pip["\'].*["\']install["\']'), "Runtime pip install via check_call"),
    (re.compile(r'check_call\s*\(\s*\[.*sys\.executable.*["\']-m["\'].*["\']pip["\']'), "Runtime pip install via sys.executable"),
]


def parse_python_requirements(repo_path):
    """Parse declared Python dependencies from requirements.txt / pyproject.toml / setup.py."""
    declared = set()

    # requirements.txt
    req_files = ['requirements.txt', 'requirements-dev.txt', 'requirements-test.txt']
    for req_name in req_files:
        req_path = os.path.join(repo_path, req_name)
        if os.path.exists(req_path):
            try:
                with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and not line.startswith('-'):
                            # Extract package name (before any version specifier)
                            pkg = re.split(r'[><=!~\[;]', line)[0].strip().lower()
                            if pkg:
                                # Normalize: underscores and hyphens are equivalent in pip
                                declared.add(pkg.replace('-', '_'))
            except (OSError, UnicodeDecodeError):
                pass

    # pyproject.toml (basic parsing)
    pyproject_path = os.path.join(repo_path, 'pyproject.toml')
    if os.path.exists(pyproject_path):
        try:
            with open(pyproject_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # Match dependencies = ["pkg>=1.0", ...] pattern
            dep_matches = re.findall(r'"([a-zA-Z0-9_-]+)(?:[><=!~\[].*?)?"', content)
            for pkg in dep_matches:
                declared.add(pkg.lower().replace('-', '_'))
        except (OSError, UnicodeDecodeError):
            pass

    # setup.py (basic parsing)
    setup_path = os.path.join(repo_path, 'setup.py')
    if os.path.exists(setup_path):
        try:
            with open(setup_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            dep_matches = re.findall(r'["\']([a-zA-Z0-9_-]+)(?:[><=!~\[].*?)?["\']', content)
            for pkg in dep_matches:
                declared.add(pkg.lower().replace('-', '_'))
        except (OSError, UnicodeDecodeError):
            pass

    return declared


def parse_node_dependencies(repo_path):
    """Parse declared Node.js dependencies from package.json."""
    declared = set()
    pkg_path = os.path.join(repo_path, 'package.json')

    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            for dep_key in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
                if dep_key in data and isinstance(data[dep_key], dict):
                    for pkg in data[dep_key]:
                        declared.add(pkg.lower())
        except (OSError, json.JSONDecodeError):
            pass

    return declared


class ImportExtractor(ast.NodeVisitor):
    """Extract all import statements from Python AST."""

    def __init__(self):
        self.imports = set()  # Set of top-level module names

    def visit_Import(self, node):
        for alias in node.names:
            top_module = alias.name.split('.')[0]
            self.imports.add(top_module.lower())
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            top_module = node.module.split('.')[0]
            if node.level == 0:  # Skip relative imports
                self.imports.add(top_module.lower())
        self.generic_visit(node)


def extract_python_imports(file_path):
    """Extract imported module names from a Python file using AST."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        tree = ast.parse(source)
        extractor = ImportExtractor()
        extractor.visit(tree)
        return extractor.imports
    except (OSError, SyntaxError, ValueError, RecursionError):
        return set()


def extract_js_imports(file_path):
    """Extract imported module names from JS/TS files using regex."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return set()

    imports = set()

    # require('module') or require("module")
    for m in re.finditer(r'require\s*\(\s*["\']([^"\']+)["\']', content):
        mod = m.group(1)
        if not mod.startswith('.'):  # Skip relative imports
            # Get package name (scoped: @scope/pkg -> @scope/pkg, unscoped: pkg/sub -> pkg)
            if mod.startswith('@'):
                parts = mod.split('/')
                if len(parts) >= 2:
                    imports.add('/'.join(parts[:2]).lower())
            else:
                imports.add(mod.split('/')[0].lower())

    # import ... from 'module' or import 'module'
    for m in re.finditer(r'(?:import|from)\s+.*?["\']([^"\']+)["\']', content):
        mod = m.group(1)
        if not mod.startswith('.'):
            if mod.startswith('@'):
                parts = mod.split('/')
                if len(parts) >= 2:
                    imports.add('/'.join(parts[:2]).lower())
            else:
                imports.add(mod.split('/')[0].lower())

    return imports


def detect_conditional_install(file_path, rel_path):
    """Detect try/except import with install fallback pattern."""
    if not file_path.endswith('.py'):
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
    except (OSError, UnicodeDecodeError):
        return []

    findings = []

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return []

    source_lines = source.split('\n')

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            # Check if body has an import
            has_import = False
            for item in node.body:
                if isinstance(item, (ast.Import, ast.ImportFrom)):
                    has_import = True
                    break

            if not has_import:
                continue

            # Check if any exception handler has pip install or os.system
            for handler in node.handlers:
                handler_src = ast.get_source_segment(source, handler) if hasattr(ast, 'get_source_segment') else ''
                if not handler_src:
                    # Fallback: check lines in range
                    start = getattr(handler, 'lineno', 0)
                    end = getattr(handler, 'end_lineno', start + 5)
                    handler_src = '\n'.join(source_lines[start - 1:end]) if start > 0 else ''

                if re.search(r'pip\s+install|subprocess|os\.system|check_call.*install', handler_src):
                    lineno = getattr(node, 'lineno', 0)
                    snippet = source_lines[lineno - 1].strip()[:120] if lineno > 0 and lineno <= len(source_lines) else ''
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title="Conditional Import with Install Fallback",
                        description="try/except import pattern that installs packages on failure. Package not declared in manifest.",
                        file=rel_path, line=lineno,
                        snippet=snippet,
                        category="runtime-install"
                    ))

    return findings


def scan_manifest_drift(repo_path):
    """Compare declared vs actual dependencies. Return findings."""
    findings = []

    # Collect declared deps
    py_declared = parse_python_requirements(repo_path)
    js_declared = parse_node_dependencies(repo_path)

    # No manifest files at all? Skip drift analysis (nothing to compare against)
    has_py_manifest = bool(py_declared) or any(
        os.path.exists(os.path.join(repo_path, f))
        for f in ('requirements.txt', 'pyproject.toml', 'setup.py')
    )
    has_js_manifest = bool(js_declared) or os.path.exists(os.path.join(repo_path, 'package.json'))

    # Collect actual imports
    py_imported = set()
    js_imported = set()

    ignore_patterns = core.load_ignore_patterns(repo_path)
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.py':
            py_imported.update(extract_python_imports(file_path))
        elif ext in ('.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'):
            js_imported.update(extract_js_imports(file_path))

    # Python: phantom deps (imported but not declared)
    if has_py_manifest:
        py_phantom = py_imported - py_declared - PYTHON_STDLIB
        # Filter out relative/local imports (single underscore prefix is okay)
        py_phantom = {p for p in py_phantom if not p.startswith('_') and len(p) > 1}
        for pkg in sorted(py_phantom):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"Phantom Dependency: {pkg}",
                description=f"Module '{pkg}' is imported in code but not declared in requirements/pyproject. Could be a shadow dependency.",
                file="(multiple files)", line=0,
                snippet=f"import {pkg} (not in manifest)",
                category="phantom-dependency"
            ))

    # JavaScript: phantom deps (imported but not declared)
    if has_js_manifest:
        js_phantom = js_imported - js_declared - NODE_BUILTINS
        for pkg in sorted(js_phantom):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"Phantom Dependency: {pkg}",
                description=f"Module '{pkg}' is required/imported but not in package.json. Could be a shadow dependency.",
                file="(multiple files)", line=0,
                snippet=f"require('{pkg}') / import '{pkg}' (not in manifest)",
                category="phantom-dependency"
            ))

    # Declared but never imported (potential confusion decoy)
    if has_py_manifest and py_imported:
        py_unused = py_declared - py_imported - {'setuptools', 'wheel', 'pip', 'build', 'twine', 'pytest', 'black', 'flake8', 'mypy', 'ruff', 'isort', 'pylint'}
        for pkg in sorted(py_unused):
            if pkg and not pkg.startswith('_'):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="low",
                    title=f"Declared but Unused: {pkg}",
                    description=f"Package '{pkg}' declared in manifest but never imported. Could be a dependency confusion decoy.",
                    file="requirements", line=0,
                    snippet=f"{pkg} in manifest, no import found",
                    category="unused-dependency"
                ))

    return findings


def scan_runtime_installs(repo_path):
    """Detect runtime package installation patterns."""
    findings = []

    ignore_patterns = core.load_ignore_patterns(repo_path)
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in ('.py', '.js', '.ts', '.sh'):
            continue

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            continue

        findings.extend(core.scan_patterns(
            content, rel_path, RUNTIME_INSTALL_PATTERNS,
            "runtime-install", "critical", SCANNER_NAME
        ))

        # Conditional import + install (Python AST-based)
        findings.extend(detect_conditional_install(file_path, rel_path))

    return findings


def scan_file(file_path, rel_path):
    """Scan a single file for runtime install patterns only.
    Manifest drift is repo-level, handled by scan_manifest_drift()."""
    findings = []

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in ('.py', '.js', '.ts', '.sh'):
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return []

    findings.extend(core.scan_patterns(
        content, rel_path, RUNTIME_INSTALL_PATTERNS,
        "runtime-install", "critical", SCANNER_NAME
    ))

    findings.extend(detect_conditional_install(file_path, rel_path))

    return findings


def main():
    args = core.parse_common_args(sys.argv, "Manifest Drift Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning {repo_path} for manifest drift...")

    all_findings = []

    # Repo-level: declared vs actual dependency comparison
    all_findings.extend(scan_manifest_drift(repo_path))

    # File-level: runtime install patterns + conditional imports
    all_findings.extend(scan_runtime_installs(repo_path))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
