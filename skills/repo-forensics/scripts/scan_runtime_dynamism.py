#!/usr/bin/env python3
"""
scan_runtime_dynamism.py - Runtime Behavior Prediction Scanner (v1)
Detects static indicators that code will behave differently at runtime:
dynamic imports, fetch-then-execute, self-modification, time bombs,
and dynamic tool descriptions.

Pure static analysis. Zero new dependencies.

Research basis:
- CVE-2026-2297: Python SourcelessFileLoader audit bypass
- PylangGhost RAT (March 2026): benign v1.0.0 -> weaponized v1.0.1
- Socket.dev NuGet time bombs (Nov 2025): hardcoded activation dates
- Check Point MCP rug pull (Feb 2026): dynamic tool descriptions
- OWASP MCP03 (Tool Poisoning), MCP07 (Rug Pull)
- Lukas Kania: MCP contract diffs (March 2026)

Created by Alex Greenshpun
"""

import os
import re
import ast
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "runtime_dynamism"

# ============================================================
# Category 1: Dynamic Imports (medium-high)
# Code that loads modules at runtime based on variables/config.
# ============================================================
DYNAMIC_IMPORT_PATTERNS = [
    (re.compile(r'importlib\.import_module\s*\(\s*[^"\']'), "importlib.import_module() with variable argument"),
    (re.compile(r'__import__\s*\(\s*(os\.environ|os\.getenv|config|settings|variable|getattr|input)'), "__import__() with dynamic source"),
    (re.compile(r'__import__\s*\(\s*[a-zA-Z_]\w*\s*[\)\[]'), "__import__() with variable argument"),
    (re.compile(r'__import__\s*\(\s*["\'][a-zA-Z_]'), "__import__() call (dynamic import evasion)"),
    # JavaScript/TypeScript dynamic imports
    (re.compile(r'require\s*\(\s*[a-zA-Z_]\w*\s*\)'), "require() with variable argument (JS)"),
    (re.compile(r'import\s*\(\s*[a-zA-Z_]\w*\s*\)'), "dynamic import() with variable argument (ES)"),
    (re.compile(r'require\s*\(\s*(process\.env|config|options)'), "require() from config/env (JS)"),
    (re.compile(r'import\s*\(\s*(process\.env|config|options)'), "dynamic import() from config/env (ES)"),
]

# ============================================================
# Category 2: Fetch-then-Execute (critical)
# Downloads content from network, then executes it.
# ============================================================
FETCH_EXECUTE_PATTERNS = [
    # Python: requests/urllib -> eval/exec
    (re.compile(r'eval\s*\(\s*(requests\.(get|post)|urllib)'), "eval() of HTTP response content"),
    (re.compile(r'exec\s*\(\s*(requests\.(get|post)|urllib)'), "exec() of HTTP response content"),
    (re.compile(r'(requests\.(get|post)|urllib\w*\.urlopen)\s*\(.*\)\s*\.\s*(text|read|content|decode).*\beval\b'), "HTTP fetch piped to eval()"),
    (re.compile(r'(requests\.(get|post)|urllib\w*\.urlopen)\s*\(.*\)\s*\.\s*(text|read|content|decode).*\bexec\b'), "HTTP fetch piped to exec()"),
    # NOTE: Runtime pip/npm install patterns are owned by scan_manifest_drift.py
    # Download then run shell scripts
    (re.compile(r'(requests\.get|urllib\w*\.urlopen)\s*\(.*\).*\.(write|save).*\.(sh|py|ps1|bat)'), "Download and save executable script"),
    (re.compile(r'subprocess\.\w+\s*\(\s*\[?\s*["\']curl["\'].*\|\s*["\']?bash'), "curl piped to bash via subprocess"),
    # Two-line patterns: download to variable, then exec/eval the variable
    (re.compile(r'=\s*(requests\.(get|post)|urllib\w*\.urlopen)\s*\(.*https?://'), "HTTP response stored to variable (check for subsequent exec)"),
    # JavaScript: fetch -> eval
    (re.compile(r'eval\s*\(\s*await\s+fetch'), "eval() of fetched content (JS)"),
    (re.compile(r'new\s+Function\s*\(\s*await\s+fetch'), "new Function() from fetched content (JS)"),
]

# ============================================================
# Category 3: Self-Modification (critical)
# Code that constructs or mutates its own behavior at runtime.
# ============================================================
SELF_MOD_PATTERNS = [
    # NOTE: types.FunctionType, types.CodeType, marshal.loads/load, bytes([int_list]).decode(),
    # sys.addaudithook, and open(__file__,'w') are detected by scan_ast.py (patterns 6-12).
    # This scanner only covers patterns NOT in scan_ast.py.
    (re.compile(r'SourcelessFileLoader'), "SourcelessFileLoader - bytecode loading bypass (CVE-2026-2297)"),
    (re.compile(r'spec_from_file_location\s*\(.*\.pyc'), "spec_from_file_location loading .pyc (CVE-2026-2297 variant)"),
    (re.compile(r'module_from_spec\s*\('), "module_from_spec() - runtime module loading from spec"),
    (re.compile(r'compile\s*\(\s*[a-zA-Z_]\w*\s*,\s*["\']'), "compile() with variable source - runtime code generation"),
    # JavaScript self-modification (scan_ast.py is Python-only)
    (re.compile(r'new\s+Function\s*\(\s*[a-zA-Z_]'), "new Function() with variable body (JS)"),
    (re.compile(r'eval\s*\(\s*atob\s*\('), "eval(atob()) - base64 decode and execute (JS)"),
]

# ============================================================
# Category 4: Time Bombs (high)
# Conditional logic triggered by date, time, or counter.
# ============================================================
TIME_BOMB_PATTERNS = [
    # Python datetime comparisons
    (re.compile(r'datetime\.\w*\(\s*\d{4}\s*,'), "Hardcoded future datetime comparison (potential time bomb)"),
    (re.compile(r'datetime\.now\(\)\s*[><=]+'), "datetime.now() comparison (potential activation trigger)"),
    (re.compile(r'date\.today\(\)\s*[><=]+'), "date.today() comparison (potential activation trigger)"),
    # Unix timestamp comparisons
    (re.compile(r'time\.time\(\)\s*[><=]+\s*\d{9,}'), "time.time() compared to hardcoded unix timestamp"),
    (re.compile(r'time\.time\(\)\s*[><=]+\s*\w'), "time.time() compared to variable (potential time bomb)"),
    (re.compile(r'int\(time\.time\(\)\)\s*[><=]+\s*\d{9,}'), "Unix timestamp comparison (potential time bomb)"),
    # Counter/attempt-based activation
    (re.compile(r'(?:count|counter|attempts?|calls?|invocations?)\s*[><=]+\s*\d{2,}'), "Counter-based activation threshold"),
    # Random/probabilistic triggers
    (re.compile(r'random\.\w+\(\)\s*[<>=]+\s*0\.\d+.*(?:exec|eval|system|subprocess|import)'), "Probabilistic trigger with code execution"),
    # JavaScript time comparisons
    (re.compile(r'Date\.now\(\)\s*[><=]+\s*\d{12,}'), "Date.now() compared to hardcoded timestamp (JS)"),
    (re.compile(r'new\s+Date\(\)\s*[><=]+\s*new\s+Date\s*\(\s*["\']'), "Date comparison with hardcoded date (JS)"),
]

# NOTE: Dynamic Tool Description patterns (Category 5) are now owned by
# scan_mcp_security.py (RUG_PULL_PATTERNS). Removed from here to avoid
# duplicate findings on MCP server files.


class RuntimeDynamismASTVisitor(ast.NodeVisitor):
    """AST visitor for patterns that regex alone can't reliably catch."""

    def __init__(self, rel_path, source_lines):
        self.rel_path = rel_path
        self.source_lines = source_lines
        self.findings = []

    def _snippet(self, lineno):
        if lineno and 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()[:120]
        return ""

    def _add(self, severity, title, description, lineno, category):
        self.findings.append(core.Finding(
            scanner=SCANNER_NAME, severity=severity,
            title=title, description=description,
            file=self.rel_path, line=lineno or 0,
            snippet=self._snippet(lineno),
            category=category
        ))

    def _is_variable(self, node):
        """Check if a node is a variable (not a string literal)."""
        return isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call, ast.IfExp))

    def visit_Call(self, node):
        lineno = getattr(node, 'lineno', None)

        # importlib.import_module(variable) - AST-level check
        if (isinstance(node.func, ast.Attribute) and
                node.func.attr == 'import_module' and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'importlib'):
            if node.args and self._is_variable(node.args[0]):
                self._add(
                    "high",
                    "Dynamic Import: importlib.import_module(variable)",
                    "Module loaded at runtime from variable. Actual module unknown at install time.",
                    lineno,
                    "dynamic-import"
                )

        # importlib.reload() - runtime code replacement
        if (isinstance(node.func, ast.Attribute) and
                node.func.attr == 'reload' and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'importlib'):
            self._add(
                "high",
                "Runtime Module Reload: importlib.reload()",
                "Module reloaded at runtime. Code can change between calls.",
                lineno,
                "dynamic-import"
            )

        # NOTE: types.FunctionType, types.CodeType, marshal.loads/load,
        # sys.addaudithook are detected by scan_ast.py (patterns 8-10).
        # This AST visitor only covers patterns unique to runtime dynamism.

        self.generic_visit(node)

    def visit_Compare(self, node):
        """Detect time bomb patterns in AST: datetime comparisons."""
        lineno = getattr(node, 'lineno', None)

        # Check for datetime.now() > datetime(...) or date.today() > date(...)
        left = node.left
        for comparator in node.comparators:
            if self._is_datetime_call(left) and self._is_datetime_constructor(comparator):
                self._add(
                    "high",
                    "Time Bomb Pattern: datetime comparison with hardcoded date",
                    "Code path activated based on current date/time reaching a hardcoded value.",
                    lineno,
                    "time-bomb"
                )
            elif self._is_datetime_call(comparator) and self._is_datetime_constructor(left):
                self._add(
                    "high",
                    "Time Bomb Pattern: hardcoded date compared to current datetime",
                    "Code path activated based on current date/time reaching a hardcoded value.",
                    lineno,
                    "time-bomb"
                )

        self.generic_visit(node)

    def _is_datetime_call(self, node):
        """Check if node is datetime.now(), date.today(), time.time()."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in ('now', 'today', 'utcnow'):
                return True
        return False

    def _is_datetime_constructor(self, node):
        """Check if node is datetime(YYYY, ...) or date(YYYY, ...) with a literal year."""
        if isinstance(node, ast.Call):
            if node.args and isinstance(node.args[0], ast.Constant):
                val = node.args[0].value
                if isinstance(val, int) and 2020 <= val <= 2099:
                    return True
        return False


def scan_file_regex(file_path, rel_path):
    """Run regex-based detection on a single file."""
    ext = os.path.splitext(file_path)[1].lower()
    target_exts = {'.py', '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.mts'}
    if ext not in target_exts:
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return []

    if not content.strip():
        return []

    findings = []

    # Category 1: Dynamic imports
    findings.extend(core.scan_patterns(
        content, rel_path, DYNAMIC_IMPORT_PATTERNS,
        "dynamic-import", "high", SCANNER_NAME
    ))

    # Category 2: Fetch-then-execute
    findings.extend(core.scan_patterns(
        content, rel_path, FETCH_EXECUTE_PATTERNS,
        "fetch-execute", "critical", SCANNER_NAME
    ))

    # Category 3: Self-modification
    findings.extend(core.scan_patterns(
        content, rel_path, SELF_MOD_PATTERNS,
        "self-modification", "critical", SCANNER_NAME
    ))

    # Category 4: Time bombs (medium severity alone; escalated via correlation rule 10)
    findings.extend(core.scan_patterns(
        content, rel_path, TIME_BOMB_PATTERNS,
        "time-bomb", "medium", SCANNER_NAME
    ))

    # NOTE: Category 5 (Dynamic Tool Descriptions) moved to scan_mcp_security.py

    return findings


def scan_file_ast(file_path, rel_path):
    """Run AST-based detection on Python files."""
    if not file_path.endswith('.py'):
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
    except (OSError, UnicodeDecodeError):
        return []

    if not source.strip():
        return []

    try:
        tree = ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError, RecursionError):
        return []

    source_lines = source.split('\n')
    visitor = RuntimeDynamismASTVisitor(rel_path, source_lines)
    visitor.visit(tree)
    return visitor.findings


def scan_file(file_path, rel_path):
    """Scan a single file for runtime dynamism indicators."""
    findings = []
    findings.extend(scan_file_regex(file_path, rel_path))
    findings.extend(scan_file_ast(file_path, rel_path))

    # Deduplicate findings on same line with same category
    seen = set()
    deduped = []
    for f in findings:
        key = (f.file, f.line, f.category)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


def main():
    args = core.parse_common_args(sys.argv, "Runtime Behavior Prediction Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning {repo_path} for runtime dynamism indicators...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
