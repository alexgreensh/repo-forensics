#!/usr/bin/env python3
"""
scan_entrypoint.py - Entrypoint Payload Injection Scanner (scanner #20)
Detects payloads injected into a repo's OWN source entrypoints that execute
on require()/import. Targets tampered repo code, NOT dependency entrypoints
(node_modules/ is excluded from walks). The IOC version-pinning in
compromised_versions.json handles the dependency case.

Two detection strategies:
  1. JavaScript CJS entrypoint injection (node-ipc pattern):
     - IIFE appended at end of file after legitimate exports
     - High-entropy blocks appended after last export
     - module.exports reassignment at file bottom

  2. Python import-time execution (durabletask pattern):
     - Top-level dangerous calls in __init__.py / setup.py
     - Uses Python AST to scope only to module body (outside FunctionDef/ClassDef)

Categories: entrypoint-iife, entrypoint-import-exec
Deduplication: distinct categories avoid double-firing with scan_sast/detect_trifecta_raw.

Created by Alex Greenshpun
"""

import os
import re
import sys
import ast
import json
import math

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "entrypoint"

# ---------------------------------------------------------------------------
# JavaScript CJS entrypoint injection detection
# ---------------------------------------------------------------------------

# Build tool banner comments that indicate a bundled/minified artifact,
# not a hand-tampered entrypoint. These are legitimate IIFEs.
_BUILD_TOOL_BANNERS = re.compile(
    r'(?:'
    r'/\*[*!]?\s*(?:webpack|rollup|esbuild|parcel|vite|browserify|uglify|terser|babel|swc)\b'
    r'|//\s*(?:webpack|rollup|esbuild|parcel|vite|browserify|uglify|terser|babel|swc)\b'
    r'|/\*!\s*bundled\b'
    r'|@license\b'
    r'|@preserve\b'
    r')',
    re.IGNORECASE,
)

# IIFE patterns at end of file. Captures the IIFE body for content analysis.
# Matches: (function(){...})() and (()=>{...})() with optional semicolons/whitespace
_IIFE_PATTERN = re.compile(
    r'(?:'
    r'\(\s*function\s*\([^)]*\)\s*\{' r'|'  # (function(){
    r'\(\s*\(\s*\)\s*=>\s*\n?\s*\{'          # (()=>{ or (()=>\n{
    r')',
)

# Dangerous patterns inside IIFE bodies that escalate to CRITICAL
_IIFE_DANGEROUS_PATTERNS = [
    (re.compile(r"require\s*\(\s*['\"]child_process['\"]"), "require('child_process')"),
    (re.compile(r"require\s*\(\s*['\"]net['\"]"), "require('net')"),
    (re.compile(r"require\s*\(\s*['\"]http['\"]"), "require('http')"),
    (re.compile(r"require\s*\(\s*['\"]https['\"]"), "require('https')"),
    (re.compile(r"require\s*\(\s*['\"]dgram['\"]"), "require('dgram')"),
    (re.compile(r"require\s*\(\s*['\"]dns['\"]"), "require('dns')"),
    (re.compile(r"require\s*\(\s*['\"]fs['\"]"), "require('fs')"),
    (re.compile(r'\bprocess\.env\b'), "process.env access"),
    (re.compile(r'\bexecSync\b'), "execSync call"),
    (re.compile(r'\bspawnSync\b'), "spawnSync call"),
    (re.compile(r'\beval\s*\('), "eval() call"),
    (re.compile(r'\bnew\s+Function\s*\('), "new Function() call"),
    (re.compile(r'\bfetch\s*\(\s*[\'"]https?://'), "fetch() to external URL"),
    (re.compile(r'\bXMLHttpRequest\b'), "XMLHttpRequest"),
]

# module.exports reassignment: detects a second module.exports = ... at bottom
_MODULE_EXPORTS_RE = re.compile(r'^\s*module\.exports\s*=', re.MULTILINE)

# High-entropy detection for appended obfuscated content
_HEX_BLOCK = re.compile(r'[0-9a-fA-F]{40,}')
_BASE64_BLOCK = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

CJS_EXTENSIONS = {'.js', '.cjs', '.mjs'}


def _shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_build_artifact(content):
    """Check if file content has build tool banner comments."""
    first_lines = '\n'.join(content.split('\n', 5)[:5])
    return bool(_BUILD_TOOL_BANNERS.search(first_lines))


def _find_package_json_main(repo_path, rel_dir):
    """Find the 'main' field from the nearest package.json.
    Returns the resolved relative path of the entrypoint, or None."""
    pkg_path = os.path.join(repo_path, rel_dir, 'package.json') if rel_dir else os.path.join(repo_path, 'package.json')
    if not os.path.isfile(pkg_path):
        return None
    try:
        with open(pkg_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        main = data.get('main', 'index.js')
        if not isinstance(main, str):
            return None
        return main
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def scan_js_entrypoint(file_path, rel_path, content):
    """Detect IIFE injection and suspicious patterns in JS entrypoint files."""
    findings = []
    lines = content.split('\n')

    if _is_build_artifact(content):
        return findings

    # Strategy 1: Detect IIFE at end of file
    # Look for IIFE in the last 30% of the file or last 50 lines
    total_lines = len(lines)
    if total_lines == 0:
        return findings

    # Find IIFEs by scanning from the bottom
    tail_start = max(0, total_lines - max(50, int(total_lines * 0.3)))
    tail_content = '\n'.join(lines[tail_start:])

    iife_matches = list(_IIFE_PATTERN.finditer(tail_content))
    for match in iife_matches:
        # Determine the line number in the original file
        match_offset = tail_content[:match.start()].count('\n')
        iife_line = tail_start + match_offset + 1

        # Check if the IIFE contains dangerous patterns
        # Extract content from match to end of file for pattern checking
        iife_region = tail_content[match.start():match.start() + 10240]
        dangerous_found = []
        for pattern, desc in _IIFE_DANGEROUS_PATTERNS:
            if pattern.search(iife_region):
                dangerous_found.append(desc)

        if dangerous_found:
            findings.append(core.Finding(
                scanner=SCANNER_NAME,
                severity="critical",
                title="Entrypoint IIFE Injection: Dangerous Code",
                description=(
                    f"IIFE at end of entrypoint file contains dangerous operations: "
                    f"{', '.join(dangerous_found[:3])}. Matches node-ipc supply chain "
                    f"attack pattern (May 2026)"
                ),
                file=rel_path,
                line=iife_line,
                snippet=lines[iife_line - 1].strip()[:120] if iife_line <= total_lines else "",
                category="entrypoint-iife",
            ))
        else:
            findings.append(core.Finding(
                scanner=SCANNER_NAME,
                severity="high",
                title="Entrypoint IIFE Injection: Structural Anomaly",
                description=(
                    "IIFE appended at end of entrypoint file. Legitimate modules "
                    "rarely end with self-executing functions. Review for injected payload."
                ),
                file=rel_path,
                line=iife_line,
                snippet=lines[iife_line - 1].strip()[:120] if iife_line <= total_lines else "",
                category="entrypoint-iife",
            ))

    # Strategy 2: Detect module.exports reassignment at bottom
    # If there are 2+ module.exports assignments, the last one may be injected
    exports_positions = [m.start() for m in _MODULE_EXPORTS_RE.finditer(content)]
    if len(exports_positions) >= 2:
        last_export_offset = exports_positions[-1]
        last_export_line = content[:last_export_offset].count('\n') + 1
        # Only flag if the last export is in the bottom 20% of the file
        if last_export_line > total_lines * 0.8:
            findings.append(core.Finding(
                scanner=SCANNER_NAME,
                severity="high",
                title="Entrypoint: Duplicate module.exports Reassignment",
                description=(
                    "module.exports reassigned at bottom of file after prior exports. "
                    "May indicate injected payload overriding legitimate exports."
                ),
                file=rel_path,
                line=last_export_line,
                snippet=lines[last_export_line - 1].strip()[:120] if last_export_line <= total_lines else "",
                category="entrypoint-iife",
            ))

    # Strategy 3: High-entropy appended content
    # Check last 10 lines for suspicious high-entropy blocks
    tail_lines = lines[max(0, total_lines - 10):]
    for i, line in enumerate(tail_lines):
        stripped = line.strip()
        if len(stripped) < 40:
            continue
        if _HEX_BLOCK.search(stripped) or _BASE64_BLOCK.search(stripped):
            entropy = _shannon_entropy(stripped)
            if entropy > 4.5:  # High entropy threshold
                actual_line = max(0, total_lines - 10) + i + 1
                findings.append(core.Finding(
                    scanner=SCANNER_NAME,
                    severity="medium",
                    title="Entrypoint: High-Entropy Appended Content",
                    description=(
                        f"High-entropy content (Shannon entropy: {entropy:.1f}) at end of "
                        f"entrypoint file. May indicate obfuscated injected payload."
                    ),
                    file=rel_path,
                    line=actual_line,
                    snippet=stripped[:120],
                    category="entrypoint-iife",
                ))
                break  # One finding per file for entropy

    return findings


# ---------------------------------------------------------------------------
# Python import-time execution detection
# ---------------------------------------------------------------------------

# Dangerous module.function combinations at import time
_PYTHON_DANGEROUS_TOPLEVEL_CALLS = {
    # (module, function_name): (severity, description)
    ('os', 'system'): ("high", "os.system() at import time"),
    ('os', 'popen'): ("high", "os.popen() at import time"),
    ('os', 'execv'): ("high", "os.execv() at import time"),
    ('os', 'execve'): ("high", "os.execve() at import time"),
    ('os', 'execvp'): ("high", "os.execvp() at import time"),
    ('subprocess', 'run'): ("critical", "subprocess.run() at import time"),
    ('subprocess', 'call'): ("critical", "subprocess.call() at import time"),
    ('subprocess', 'Popen'): ("critical", "subprocess.Popen() at import time"),
    ('subprocess', 'check_output'): ("critical", "subprocess.check_output() at import time"),
    ('subprocess', 'check_call'): ("critical", "subprocess.check_call() at import time"),
    ('urllib.request', 'urlopen'): ("critical", "urllib.request.urlopen() at import time"),
    ('requests', 'get'): ("critical", "requests.get() at import time (network call on import)"),
    ('requests', 'post'): ("critical", "requests.post() at import time (network call on import)"),
    ('requests', 'put'): ("critical", "requests.put() at import time (network call on import)"),
    ('requests', 'delete'): ("critical", "requests.delete() at import time (network call on import)"),
    ('socket', 'socket'): ("critical", "socket.socket() at import time"),
    ('socket', 'connect'): ("critical", "socket.connect() at import time"),
    ('socket', 'create_connection'): ("critical", "socket.create_connection() at import time"),
    ('http.client', 'HTTPConnection'): ("critical", "http.client.HTTPConnection() at import time"),
    ('http.client', 'HTTPSConnection'): ("critical", "http.client.HTTPSConnection() at import time"),
}

# Bare exec/eval with obfuscated arguments
_EXEC_EVAL_NAMES = {'exec', 'eval'}

# Safe top-level call patterns (os.path.*, os.getcwd, etc.)
_SAFE_OS_ATTRS = {
    'path', 'getcwd', 'getenv', 'environ', 'sep', 'linesep', 'name',
    'curdir', 'pardir', 'extsep', 'altsep', 'pathsep', 'defpath',
}

# Modules that are always safe at top level
_SAFE_MODULES_FOR_CALLS = {
    'os.path', 'pathlib', 'logging', 'warnings', 'typing',
    'collections', 'functools', 'itertools', 'operator',
    'abc', 'enum', 'dataclasses', 'contextlib',
}


def _is_inside_name_main_guard(node, source_lines):
    """Check if a node is inside an 'if __name__ == "__main__"' block."""
    # This is called for top-level If nodes. Check the test condition.
    if not isinstance(node, ast.If):
        return False
    test = node.test
    # Pattern: __name__ == "__main__" or "__main__" == __name__
    if isinstance(test, ast.Compare):
        left = test.left
        if (len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
                and len(test.comparators) == 1):
            comp = test.comparators[0]
            # Check both directions
            if _is_name_main_pair(left, comp) or _is_name_main_pair(comp, left):
                return True
    return False


def _is_name_main_pair(a, b):
    """Check if (a, b) matches (__name__, "__main__") in either form."""
    a_is_name = isinstance(a, ast.Name) and a.id == '__name__'
    # Support both ast.Constant (3.8+) and ast.Str (deprecated)
    b_is_main = (
        (isinstance(b, ast.Constant) and b.value == '__main__')
        or (hasattr(ast, 'Str') and isinstance(b, ast.Str) and b.s == '__main__')
    )
    return a_is_name and b_is_main


def _get_call_info(node):
    """Extract (module, function) tuple from a Call node, or None.

    Handles:
      - module.func()        -> ('module', 'func')
      - module.sub.func()    -> ('module.sub', 'func')
      - bare_func()          -> (None, 'func')
    """
    if not isinstance(node, ast.Call):
        return None

    func = node.func
    if isinstance(func, ast.Attribute):
        # module.func() or module.sub.func()
        parts = []
        current = func.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            parts.reverse()
            module = '.'.join(parts)
            return (module, func.attr)
    elif isinstance(func, ast.Name):
        return (None, func.id)

    return None


def _is_obfuscated_arg(node):
    """Check if an argument to exec/eval looks obfuscated."""
    if not node.args:
        return False
    arg = node.args[0]
    # Call expression as argument (e.g. exec(decode(...)), exec(compile(...)))
    if isinstance(arg, ast.Call):
        return True
    # Binary op (string concatenation)
    if isinstance(arg, ast.BinOp):
        return True
    # JoinedStr (f-string with variables)
    if isinstance(arg, ast.JoinedStr):
        return True
    # Subscript (e.g. exec(d["p"])), IfExp (e.g. exec(a if x else b)),
    # Attribute (e.g. exec(obj.payload))
    if isinstance(arg, (ast.Subscript, ast.IfExp, ast.Attribute)):
        return True
    return False


def scan_python_entrypoint(file_path, rel_path):
    """Detect dangerous top-level calls in Python entrypoint files.

    Only scans __init__.py and setup.py files. Uses Python AST to check
    ast.Module.body for dangerous calls NOT inside FunctionDef or ClassDef.
    """
    findings = []
    basename = os.path.basename(file_path)

    if basename not in ('__init__.py', 'setup.py'):
        return findings

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
    except OSError:
        return findings

    if not source.strip():
        return findings

    try:
        tree = ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return findings

    source_lines = source.split('\n')

    def snippet(lineno):
        if lineno and 1 <= lineno <= len(source_lines):
            return source_lines[lineno - 1].strip()[:120]
        return ""

    # Walk only top-level statements in ast.Module.body
    for stmt in tree.body:
        # Skip class and function definitions (their bodies are not import-time)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        # Skip if __name__ == "__main__" blocks
        if isinstance(stmt, ast.If) and _is_inside_name_main_guard(stmt, source_lines):
            continue

        # Skip import statements, assignments of constants, type annotations, pass, etc.
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass,
                             ast.AnnAssign)):
            continue

        # For Assign and AugAssign, check if the value is a dangerous call
        # but skip simple constant assignments
        if isinstance(stmt, ast.Assign):
            if isinstance(stmt.value, (ast.Constant, ast.List, ast.Tuple,
                                       ast.Dict, ast.Set, ast.Name)):
                continue
            # Check if the value is a safe call (like os.path.dirname())
            if isinstance(stmt.value, ast.Call):
                call_info = _get_call_info(stmt.value)
                if call_info:
                    mod, func = call_info
                    if mod in _SAFE_MODULES_FOR_CALLS:
                        continue
                    if mod == 'os' and func in _SAFE_OS_ATTRS:
                        continue
                    # os.path.X is safe
                    if mod and mod.startswith('os.path'):
                        continue

        # Walk all Call nodes within this top-level statement
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue

            lineno = getattr(node, 'lineno', 0)
            call_info = _get_call_info(node)

            if call_info is None:
                continue

            mod, func = call_info

            # Check for dangerous module.function calls
            if mod is not None:
                key = (mod, func)
                if key in _PYTHON_DANGEROUS_TOPLEVEL_CALLS:
                    severity, desc = _PYTHON_DANGEROUS_TOPLEVEL_CALLS[key]
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME,
                        severity=severity,
                        title=f"Entrypoint Import-Time Execution: {desc}",
                        description=(
                            f"Top-level {mod}.{func}() call in {basename} executes on "
                            f"import. Matches durabletask supply chain attack pattern "
                            f"(May 2026). This code runs automatically when the "
                            f"package is imported."
                        ),
                        file=rel_path,
                        line=lineno,
                        snippet=snippet(lineno),
                        category="entrypoint-import-exec",
                    ))
                    continue

                # Safe os.path calls etc. - skip
                if mod in _SAFE_MODULES_FOR_CALLS or mod.startswith('os.path'):
                    continue
                if mod == 'os' and func in _SAFE_OS_ATTRS:
                    continue

            # Check for bare exec/eval at top level
            if mod is None and func in _EXEC_EVAL_NAMES:
                if _is_obfuscated_arg(node):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME,
                        severity="critical",
                        title=f"Entrypoint Import-Time Execution: {func}() with obfuscated argument",
                        description=(
                            f"Top-level {func}() with computed argument in {basename}. "
                            f"Executes obfuscated code at import time. Classic supply "
                            f"chain payload delivery."
                        ),
                        file=rel_path,
                        line=lineno,
                        snippet=snippet(lineno),
                        category="entrypoint-import-exec",
                    ))
                else:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME,
                        severity="high",
                        title=f"Entrypoint Import-Time Execution: {func}() at top level",
                        description=(
                            f"Top-level {func}() in {basename}. Executes arbitrary "
                            f"code at import time."
                        ),
                        file=rel_path,
                        line=lineno,
                        snippet=snippet(lineno),
                        category="entrypoint-import-exec",
                    ))

    return findings


# ---------------------------------------------------------------------------
# Main scanner entry point
# ---------------------------------------------------------------------------

def scan_file(file_path, rel_path):
    """Scan a single file for entrypoint payload injection.
    Returns list[core.Finding]."""
    findings = []
    basename = os.path.basename(file_path)
    ext = os.path.splitext(file_path)[1].lower()

    # Python entrypoint files
    if basename in ('__init__.py', 'setup.py'):
        findings.extend(scan_python_entrypoint(file_path, rel_path))

    # JavaScript/CJS entrypoint files
    # We scan all .js/.cjs files that could be entrypoints
    # The main heuristic: scan package.json main field targets + any index.js/index.cjs
    if ext in CJS_EXTENSIONS:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except OSError:
            return findings

        if content.strip():
            findings.extend(scan_js_entrypoint(file_path, rel_path, content))

    return findings


def main():
    args = core.parse_common_args(sys.argv, "Entrypoint Payload Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning entrypoint files in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    # Collect package.json main fields to identify JS entrypoints
    entrypoint_files = set()
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        if os.path.basename(file_path) == 'package.json':
            pkg_dir = os.path.dirname(rel_path)
            main_file = _find_package_json_main(repo_path, pkg_dir)
            if main_file:
                entrypoint_rel = os.path.normpath(os.path.join(pkg_dir, main_file)) if pkg_dir else main_file
                entrypoint_files.add(entrypoint_rel)

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        basename = os.path.basename(file_path)
        ext = os.path.splitext(file_path)[1].lower()

        # Always scan Python entrypoints
        if basename in ('__init__.py', 'setup.py'):
            all_findings.extend(scan_python_entrypoint(file_path, rel_path))

        # Scan JS files that are package.json entrypoints or index files
        elif ext in CJS_EXTENSIONS:
            is_entrypoint = (
                rel_path in entrypoint_files
                or os.path.normpath(rel_path) in entrypoint_files
                or basename in ('index.js', 'index.cjs', 'index.mjs')
            )
            if is_entrypoint:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except OSError:
                    continue
                if content.strip():
                    all_findings.extend(scan_js_entrypoint(file_path, rel_path, content))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
