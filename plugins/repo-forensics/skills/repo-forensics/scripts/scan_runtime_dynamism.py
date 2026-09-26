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
import ast
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import rule_loader
import _context_gate

SCANNER_NAME = "runtime_dynamism"

# ============================================================
# Detection rules load from the shipped pack at import time (rule_loader
# memoizes, so this parses once per process). The 8 categories below preserve
# the pre-extraction severity-per-category mapping (severity drives the parity
# key). The AST visitor, two-stage scan, and dedup are scanning *algorithm* and
# stay in code (KTD-3). load_pack returns None only on a missing/tampered
# install -> PACK_LOAD_ERROR, one loud diagnostic, no hardcoded fallback.
# ============================================================
_PACK = rule_loader.load_pack(SCANNER_NAME)
PACK_LOAD_ERROR = _PACK is None

# Output category -> emitted severity (the pre-extraction call-site default).
# Rules carry their category in the pack; we group by it so each category emits
# at its historical severity, preserving the (title, severity, ...) parity key.
_CATEGORY_SEVERITY = {
    "dynamic-import": "high",
    "fetch-execute": "critical",
    "self-modification": "critical",
    "time-bomb": "medium",
    "worm-propagation": "critical",
    "probabilistic-activation": "high",
    "environment-detection": "medium",
    "cloud-ide-detection": "low",
    "locale-gating": "medium",
}


def _rules_by_category():
    """Group the loaded pack's rules by output category (stable order)."""
    grouped = {}
    if _PACK is not None:
        for rule in _PACK.all_rules:
            grouped.setdefault(rule.category, []).append(rule)
    return grouped


_RULES_BY_CATEGORY = _rules_by_category()


def _pack_load_finding(rel_path):
    """One loud diagnostic emitted when the rule pack failed to load. We do NOT
    fall back to a hardcoded copy (a corrupted install is caught independently
    by the integrity scanner)."""
    return core.Finding(
        scanner=SCANNER_NAME, severity="critical",
        title="Runtime-dynamism rule pack failed to load",
        description=("data/rulepacks/runtime_dynamism.json is missing or "
                     "schema-incompatible; regex-based runtime-dynamism "
                     "detection is disabled. Reinstall repo-forensics to "
                     "restore detection."),
        file=rel_path, line=0,
        snippet="rule pack failed to load",
        category="scanner-integrity",
    )


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
    target_exts = {'.py', '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.mts', '.sh', '.bash'}
    if ext not in target_exts:
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return []

    if not content.strip():
        return []

    if PACK_LOAD_ERROR:
        return [_pack_load_finding(rel_path)]

    findings = []

    # Each pack rule carries its output category; emit per category at the
    # historical severity (preserves the (title, severity, file, line, category)
    # parity key). scan_rule_patterns stamps rule_id + confidence onto every
    # finding. The two probabilistic-activation tiers and the environment vs
    # locale split that used to be slice-based are now expressed by the rule's
    # own category, so the call-site no longer needs slice arithmetic.
    for category, severity in _CATEGORY_SEVERITY.items():
        rules = _RULES_BY_CATEGORY.get(category)
        if not rules:
            continue
        findings.extend(core.scan_rule_patterns(
            content, rel_path, rules, category, severity, SCANNER_NAME
        ))

    # The shipped or signed-overlay regex can match import(node) at the end
    # of a helper name such as _render_import(node). Require the JS keyword.
    content_lines = content.splitlines()
    js_import_call = re.compile(r"(?<![\w$.])import\s*\(")
    findings = [
        f for f in findings
        if f.rule_id not in {"RD-DYN-006", "RD-DYN-008"}
        or not (1 <= f.line <= len(content_lines))
        or js_import_call.search(content_lines[f.line - 1])
    ]

    # module_from_spec constructs a module but does not execute it. Treat a
    # standalone call as HIGH; retain CRITICAL when its function writes a file
    # before loading and executes the resulting module. Test fixtures keep the
    # existing inferred-evidence cap, and the finding always stays visible.
    loader_tree = None
    if any(f.rule_id in {"RD-SMOD-003", "RD-SMOD-004"} for f in findings) and ext == '.py':
        try:
            loader_tree = ast.parse(content, filename=file_path)
        except (SyntaxError, ValueError, RecursionError):
            pass
    is_test = (any(f.rule_id in {"RD-SMOD-003", "RD-SMOD-004"} for f in findings)
               and _context_gate.classify_file_context(rel_path, content).is_test_fixture)
    for f in findings:
        if f.rule_id == "RD-SMOD-003":
            try:
                if is_test:
                    f.evidence_class = "inferred"
                elif loader_tree is not None and not _write_then_load(loader_tree, f.line):
                    if _fixed_sibling_loader(loader_tree, f.line):
                        f.evidence_class = "inferred"
                    else:
                        f.severity = "high"
            except Exception:
                pass
        elif (f.rule_id == "RD-SMOD-004" and is_test and loader_tree is not None
              and _test_generated_compile(loader_tree, f.line)):
            f.evidence_class = "inferred"

    return findings


def _write_then_load(tree, load_line):
    """Find a file write and exec_module around one loader in its Python scope."""
    scope = tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= load_line <= getattr(node, 'end_lineno', node.lineno):
                if scope is tree or (node.end_lineno - node.lineno
                                     < scope.end_lineno - scope.lineno):
                    scope = node

    wrote = False
    executed = False
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        if load_line - 30 <= node.lineno < load_line:
            if isinstance(node.func, ast.Attribute) and node.func.attr in ('write_text', 'write_bytes'):
                wrote = True
            elif isinstance(node.func, ast.Name) and node.func.id == 'open':
                mode = node.args[1] if len(node.args) > 1 else next(
                    (kw.value for kw in node.keywords if kw.arg == 'mode'), None)
                if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
                    wrote = wrote or any(flag in mode.value for flag in 'wax+')
        elif (load_line <= node.lineno <= load_line + 30
              and isinstance(node.func, ast.Attribute)
              and node.func.attr == 'exec_module'):
            executed = True
    return wrote and executed


def _test_generated_compile(tree, compile_line):
    """Recognize a test compiling source returned by a local generator."""
    scope = tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= compile_line <= getattr(node, 'end_lineno', node.lineno):
                if scope is tree or (node.end_lineno - node.lineno
                                     < scope.end_lineno - scope.lineno):
                    scope = node
    if scope is tree:
        return False

    generated = set()
    for node in sorted(ast.walk(scope), key=lambda item: getattr(item, 'lineno', 0)):
        if isinstance(node, ast.Assign) and node.lineno < compile_line:
            value = node.value
            from_generator = (isinstance(value, ast.Call)
                              and isinstance(value.func, ast.Attribute)
                              and value.func.attr.startswith('_generate_'))
            from_slice = (isinstance(value, ast.Subscript)
                          and isinstance(value.value, ast.Name)
                          and value.value.id in generated)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if from_generator or from_slice:
                        generated.add(target.id)
                    else:
                        generated.discard(target.id)
        if (isinstance(node, ast.Call) and node.lineno == compile_line
                and isinstance(node.func, ast.Name) and node.func.id == 'compile'
                and node.args and isinstance(node.args[0], ast.Name)
                and node.args[0].id in generated):
            return True
    return False


def _fixed_sibling_loader(tree, load_line):
    """Prove the spec path is a literal .py sibling rooted at __file__."""
    scope = tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= load_line <= getattr(node, 'end_lineno', node.lineno):
                if scope is tree or (node.end_lineno - node.lineno
                                     < scope.end_lineno - scope.lineno):
                    scope = node

    assignments = {}
    ambiguous = set()
    def collect(body):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, ast.Assign) and node.lineno < load_line:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if target.id in assignments:
                            ambiguous.add(target.id)
                        assignments[target.id] = node.value
            for field in ('body', 'orelse', 'finalbody'):
                nested = getattr(node, field, None)
                if isinstance(nested, list):
                    collect(nested)
            for handler in getattr(node, 'handlers', ()):
                collect(handler.body)

    collect(tree.body)
    if scope is not tree:
        collect(scope.body)

    def path_proof(expr, seen=frozenset()):
        if isinstance(expr, ast.Name):
            if expr.id == '__file__':
                return True, True
            if expr.id in seen or expr.id not in assignments or expr.id in ambiguous:
                return False, False
            return path_proof(assignments[expr.id], seen | {expr.id})
        if isinstance(expr, ast.Attribute) and expr.attr in ('parent', 'resolve'):
            rooted, fixed_py = path_proof(expr.value, seen)
            return rooted, fixed_py if expr.attr == 'resolve' else False
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            rooted, _ = path_proof(expr.left, seen)
            if rooted and isinstance(expr.right, ast.Constant) and isinstance(expr.right.value, str):
                part = expr.right.value
                if part not in ('', '.', '..') and '/' not in part and '\\' not in part and ':' not in part:
                    return True, part.endswith('.py')
            return False, False
        if isinstance(expr, ast.Call):
            name = (expr.func.id if isinstance(expr.func, ast.Name)
                    else expr.func.attr if isinstance(expr.func, ast.Attribute) else '')
            if name in ('Path', 'str') and expr.args:
                return path_proof(expr.args[0], seen)
            if name in ('resolve', 'expanduser') and isinstance(expr.func, ast.Attribute):
                return path_proof(expr.func.value, seen)
            if name == 'next' and expr.args and isinstance(expr.args[0], ast.GeneratorExp):
                gen = expr.args[0]
                if len(gen.generators) == 1:
                    return path_proof(gen.generators[0].iter, seen)
        if isinstance(expr, (ast.Tuple, ast.List)) and expr.elts:
            proofs = [path_proof(item, seen) for item in expr.elts]
            return all(root for root, _ in proofs), all(fixed for _, fixed in proofs)
        return False, False

    for node in ast.walk(scope):
        if not (isinstance(node, ast.Call) and node.lineno == load_line
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == 'module_from_spec'
                and node.args and isinstance(node.args[0], ast.Name)):
            continue
        if node.args[0].id in ambiguous:
            return False
        spec = assignments.get(node.args[0].id)
        if not (isinstance(spec, ast.Call) and isinstance(spec.func, ast.Attribute)
                and spec.func.attr == 'spec_from_file_location' and len(spec.args) >= 2):
            return False
        return path_proof(spec.args[1]) == (True, True)
    return False


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
