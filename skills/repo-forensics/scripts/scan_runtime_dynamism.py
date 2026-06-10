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
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import rule_loader

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
