#!/usr/bin/env python3
"""
scan_dataflow.py - Lightweight Source-to-Sink Taint Tracker
Tracks sensitive data from sources (env vars, credential files)
through assignments to sinks (network calls, code execution).

Single-pass forward analysis, regex-based (not AST).
Supports Python and JavaScript/TypeScript.

Created by Alex Greenshpun
"""

import ast
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "dataflow"

# === Sources: where sensitive data enters ===
PYTHON_SOURCES = [
    (re.compile(r'(\w+)\s*=\s*os\.environ\b', re.IGNORECASE), "os.environ access"),
    (re.compile(r'(\w+)\s*=\s*os\.environ\.copy\(\)', re.IGNORECASE), "os.environ.copy()"),
    (re.compile(r'(\w+)\s*=\s*os\.environ\.get\(', re.IGNORECASE), "os.environ.get()"),
    (re.compile(r'(\w+)\s*=\s*os\.environ\[', re.IGNORECASE), "os.environ[] access"),
    (re.compile(r'(\w+)\s*=\s*os\.getenv\(', re.IGNORECASE), "os.getenv() access"),
    (re.compile(r'(\w+)\s*=\s*getattr\s*\(\s*os\s*,\s*["\']environ["\']\)', re.IGNORECASE), "getattr(os, 'environ') evasion"),
    (re.compile(r'(\w+)\s*=\s*open\s*\([^)]*(?:\.env|\.ssh|\.aws|credentials|\.gnupg|\.config|\.claude|\.kiro|\.kube|\.terraform|sitemanager\.xml|recentservers\.xml|\.atomic|msal_token_cache|\.remmina|\.ovpn|\.npmrc|\.git-credentials)'), "Sensitive file read"),
    (re.compile(r'(\w+)\s*=\s*pathlib\.Path\s*\([^)]*(?:\.env|\.ssh|\.aws|credentials|\.claude|\.kiro|\.kube|\.terraform|msal_token_cache|sitemanager\.xml|\.atomic)'), "Sensitive path access"),
    (re.compile(r'(\w+)\s*=\s*dotenv\.dotenv_values\(', re.IGNORECASE), "dotenv values load"),
]

JS_SOURCES = [
    (re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*process\.env\b', re.IGNORECASE), "process.env access"),
    (re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*Object\.keys\s*\(\s*process\.env', re.IGNORECASE), "process.env enumeration"),
    (re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:fs\.)?readFileSync\s*\([^)]*(?:\.env|\.ssh|\.aws|credential|\.claude|\.kiro|\.kube|\.terraform|sitemanager\.xml|\.atomic|msal_token_cache|\.npmrc|\.git-credentials)'), "Sensitive file read"),
    (re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(["\']dotenv["\']\)', re.IGNORECASE), "dotenv require"),
    (re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*JSON\.parse\s*\(\s*(?:fs\.)?readFileSync', re.IGNORECASE), "JSON file parse"),
]

# === Sinks: where data leaves ===
PYTHON_SINKS = [
    re.compile(r'requests\.(post|put|patch|delete)\s*\(', re.IGNORECASE),
    re.compile(r'urllib\.request\.(urlopen|Request)\s*\(', re.IGNORECASE),
    re.compile(r'http\.client\.HTTPConnection', re.IGNORECASE),
    re.compile(r'httpx\.(post|put|patch|delete|AsyncClient)\s*\(', re.IGNORECASE),
    re.compile(r'aiohttp\.ClientSession', re.IGNORECASE),
    re.compile(r'subprocess\.(run|call|Popen|check_output)\s*\(', re.IGNORECASE),
    re.compile(r'os\.system\s*\(', re.IGNORECASE),
    re.compile(r'os\.popen\s*\(', re.IGNORECASE),
    re.compile(r'eval\s*\(', re.IGNORECASE),
    re.compile(r'exec\s*\(', re.IGNORECASE),
    re.compile(r'__import__\s*\(', re.IGNORECASE),
]

JS_SINKS = [
    re.compile(r'fetch\s*\(', re.IGNORECASE),
    re.compile(r'axios\.(post|put|patch|delete)\s*\(', re.IGNORECASE),
    re.compile(r'XMLHttpRequest', re.IGNORECASE),
    re.compile(r'require\s*\(["\']child_process["\']\)', re.IGNORECASE),
    re.compile(r'child_process\.(exec|spawn|execSync)\s*\(', re.IGNORECASE),
    re.compile(r'eval\s*\(', re.IGNORECASE),
    re.compile(r'Function\s*\(', re.IGNORECASE),
    re.compile(r'new\s+WebSocket\s*\(', re.IGNORECASE),
]

# === Assignment tracking ===
ASSIGN_PATTERN = re.compile(r'(?:(?:const|let|var)\s+)?(\w+)\s*=(?!=)\s*(.*)')
TAINT_PROPAGATORS = [
    re.compile(r'base64\.(b64encode|encode|urlsafe_b64encode)\s*\(', re.IGNORECASE),
    re.compile(r'json\.dumps\s*\(', re.IGNORECASE),
    re.compile(r'str\s*\(', re.IGNORECASE),
    re.compile(r'\.encode\s*\(', re.IGNORECASE),
    re.compile(r'Buffer\.from\s*\(', re.IGNORECASE),
    re.compile(r'btoa\s*\(', re.IGNORECASE),
    re.compile(r'JSON\.stringify\s*\(', re.IGNORECASE),
    re.compile(r'encodeURIComponent\s*\(', re.IGNORECASE),
]


def detect_language(rel_path):
    ext = os.path.splitext(rel_path)[1].lower()
    if ext in ('.py',):
        return 'python'
    elif ext in ('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'):
        return 'javascript'
    return None


class _ScopeBindings(ast.NodeVisitor):
    def __init__(self):
        self.globals = set()
        self.nonlocals = set()
        self.locals = set()

    def visit_Global(self, node):
        self.globals.update(node.names)

    def visit_Nonlocal(self, node):
        self.nonlocals.update(node.names)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self.locals.add(node.id)

    def visit_FunctionDef(self, node):
        self.locals.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef


def analyze_file(file_path, rel_path):
    """Single-pass forward taint analysis on one file."""
    lang = detect_language(rel_path)
    if lang is None:
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return []

    sources = PYTHON_SOURCES if lang == 'python' else JS_SOURCES
    sinks = PYTHON_SINKS if lang == 'python' else JS_SINKS

    tainted_vars = {}  # var_name -> (source_line, source_desc)
    scope_starts = defaultdict(list)
    if lang == 'python':
        try:
            tree = ast.parse(''.join(lines))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    bindings = _ScopeBindings()
                    for stmt in node.body:
                        bindings.visit(stmt)
                    params = set()
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        args = node.args
                        params.update(a.arg for a in args.posonlyargs + args.args + args.kwonlyargs)
                        params.update(a.arg for a in (args.vararg, args.kwarg) if a)
                    bindings.locals.update(params)
                    scope_starts[node.lineno].append((
                        node.end_lineno, bindings.globals, bindings.nonlocals,
                        bindings.locals, params, isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)),
                    ))
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            pass
    scopes = [(float('inf'), tainted_vars, set(), set(), set(), False)]
    findings = []

    for i, line in enumerate(lines):
        line_stripped = line.strip()
        line_no = i + 1
        if lang == 'python':
            while len(scopes) > 1 and line_no > scopes[-1][0]:
                scopes.pop()
            for end_line, global_names, nonlocal_names, local_names, params, is_function in sorted(
                scope_starts.get(line_no, []), key=lambda item: item[0], reverse=True,
            ):
                scoped_taints = scopes[-1][1].copy()
                for param in params:
                    scoped_taints.pop(param, None)
                scopes.append((end_line, scoped_taints, global_names, nonlocal_names, local_names, is_function))
            tainted_vars = scopes[-1][1]

        # Bound regex backtracking by TRUNCATING, never skipping: dropping the
        # line entirely lets a payload hide behind 10k characters of padding.
        line_stripped = core.clip_line(line_stripped)

        # Reassignment ends the old value's taint unless the RHS carries it.
        assign_m = ASSIGN_PATTERN.match(line_stripped)
        if assign_m:
            lhs = assign_m.group(1)
            rhs = assign_m.group(2)
            inherited = None
            for tvar in tainted_vars:
                if re.search(r'\b' + re.escape(tvar) + r'\b', rhs):
                    inherited = tainted_vars[tvar]
                    break
            targets = [tainted_vars]
            if lang == 'python' and lhs in scopes[-1][2]:
                targets.append(scopes[0][1])
            elif lang == 'python' and lhs in scopes[-1][3]:
                for scope in reversed(scopes[:-1]):
                    if scope[5] and lhs in scope[4]:
                        targets.append(scope[1])
                        break
            for target in targets:
                if inherited is None:
                    target.pop(lhs, None)
                else:
                    target[lhs] = inherited

        # Check if line introduces a tainted source
        for source_pat, source_desc in sources:
            m = source_pat.search(line_stripped)
            if m:
                var_name = m.group(1)
                tainted_vars[var_name] = (line_no, source_desc)
                if lang == 'python' and var_name in scopes[-1][2]:
                    scopes[0][1][var_name] = tainted_vars[var_name]
                elif lang == 'python' and var_name in scopes[-1][3]:
                    for scope in reversed(scopes[:-1]):
                        if scope[5] and var_name in scope[4]:
                            scope[1][var_name] = tainted_vars[var_name]
                            break

        # Check if any tainted variable reaches a sink
        sink_text = assign_m.group(2) if assign_m else line_stripped
        for sink_pat in sinks:
            if sink_pat.search(sink_text):
                for tvar, (src_line, src_desc) in tainted_vars.items():
                    if re.search(r'\b' + re.escape(tvar) + r'\b', sink_text):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME,
                            severity="critical",
                            title="Tainted Data Reaches Sink",
                            description=f"Variable '{tvar}' (from {src_desc} at line {src_line}) flows to sink",
                            file=rel_path,
                            line=line_no,
                            snippet=line_stripped[:120],
                            category="dataflow"
                        ))

    return findings


def build_import_graph(repo_path, ignore_patterns):
    """Build a simple import graph to check cross-file taint."""
    imports = defaultdict(set)  # file -> set of imported file stems

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        lang = detect_language(rel_path)
        if lang is None:
            continue

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Filter mega-lines to prevent O(n^2) regex backtracking
                content = ''.join(core.clip_line(line) for line in f)
        except (OSError, UnicodeDecodeError):
            continue

        if lang == 'python':
            for m in re.finditer(r'(?:from|import)\s+([\w.]+)', content):
                imports[rel_path].add(m.group(1).split('.')[0])
        elif lang == 'javascript':
            for m in re.finditer(r'(?:require|import)\s*\(?["\']\.?\.?/?([\w/.-]+)["\']', content):
                mod = m.group(1).split('/')[-1].replace('.js', '').replace('.ts', '')
                imports[rel_path].add(mod)

    return imports


def main():
    args = core.parse_common_args(sys.argv, "Dataflow Taint Tracker")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Running dataflow analysis on {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    # Per-file taint analysis
    file_findings = {}
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = analyze_file(file_path, rel_path)
        if findings:
            file_findings[rel_path] = findings
            all_findings.extend(findings)

    # Cross-file: if file A has tainted sources and file B imports A and has sinks
    import_graph = build_import_graph(repo_path, ignore_patterns)
    tainted_modules = set()
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        lang = detect_language(rel_path)
        if lang is None:
            continue
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Filter mega-lines to prevent O(n^2) regex backtracking
                content = ''.join(core.clip_line(line) for line in f)
        except (OSError, UnicodeDecodeError):
            continue

        sources = PYTHON_SOURCES if lang == 'python' else JS_SOURCES
        for source_pat, _ in sources:
            if source_pat.search(content):
                stem = os.path.splitext(os.path.basename(rel_path))[0]
                tainted_modules.add(stem)

    for rel_path, imported_modules in import_graph.items():
        for tmod in tainted_modules:
            if tmod in imported_modules:
                # Check if this file has sinks
                file_path_full = os.path.join(repo_path, rel_path)
                lang = detect_language(rel_path)
                if lang is None:
                    continue
                sinks = PYTHON_SINKS if lang == 'python' else JS_SINKS
                try:
                    with open(file_path_full, 'r', encoding='utf-8', errors='ignore') as f:
                        # Filter mega-lines to prevent O(n^2) regex backtracking
                        content = ''.join(core.clip_line(line) for line in f)
                except (OSError, UnicodeDecodeError):
                    continue

                content_lines = content.split('\n')
                for sink_pat in sinks:
                    m = sink_pat.search(content)
                    if m:
                        line_no = content[:m.start()].count('\n') + 1
                        snippet = content_lines[line_no - 1].strip()[:120] if line_no <= len(content_lines) else ""
                        all_findings.append(core.Finding(
                            scanner=SCANNER_NAME,
                            severity="high",
                            title="Cross-File Taint: Import from Tainted Module",
                            description=f"File imports from '{tmod}' (which accesses sensitive data) and contains sinks",
                            file=rel_path,
                            line=line_no,
                            snippet=snippet,
                            category="dataflow"
                        ))
                        break  # One finding per file per tainted module

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
