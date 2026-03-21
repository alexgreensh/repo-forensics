#!/usr/bin/env python3
"""
scan_ast.py - Python AST Obfuscation Detector (v3)
Detects obfuscated exec chains, dangerous dynamic attribute access,
and pickle deserialization backdoors that regex-based scanners miss.

Uses stdlib ast.parse() only. Zero new dependencies.
Scans Python files only. Full audit mode (not --skill-scan, slower).

Created by Alex Greenshpun
"""

import os
import ast
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "ast_analysis"

# Modules that are dangerous to access dynamically
SENSITIVE_MODULES = {'os', 'subprocess', 'shutil', 'sys', 'socket', 'builtins', 'importlib'}
# Dangerous attributes/functions on those modules
DANGEROUS_ATTRS = {'system', 'popen', 'Popen', 'call', 'run', 'check_output',
                   'exec', 'eval', 'execve', 'execvp', 'spawnl', 'spawnle'}
# Encoding/decoding functions that precede obfuscated exec
DECODE_FUNCS = {'b64decode', 'decodebytes', 'decodestring',
                'decompress', 'loads', 'fromhex', 'decode', 'unhexlify'}


class ObfuscationVisitor(ast.NodeVisitor):
    """AST visitor detecting obfuscation and dangerous dynamic patterns."""

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

    def _call_name(self, node):
        """Return string name of a call expression."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            obj = node.func.value.id if isinstance(node.func.value, ast.Name) else "?"
            return f"{obj}.{node.func.attr}"
        return "?"

    def visit_Call(self, node):
        lineno = getattr(node, 'lineno', None)

        # Pattern 1: exec(base64.b64decode(...)) or exec(codecs.decode(...)) etc.
        if isinstance(node.func, ast.Name) and node.func.id in ('exec', 'eval'):
            if node.args and isinstance(node.args[0], ast.Call):
                inner_name = self._call_name(node.args[0])
                # Check if the inner call is a decode/decompress function
                inner_func_part = inner_name.split('.')[-1]
                if inner_func_part in DECODE_FUNCS:
                    self._add(
                        severity="critical",
                        title="Obfuscated Exec: Encoded Payload",
                        description=f"exec/eval of decoded content via {inner_name}() - hides payload from static analysis",
                        lineno=lineno,
                        category="obfuscated-exec"
                    )

        # Pattern 2: eval(compile(bytes(...), '', 'exec')) or eval(compile(...))
        if isinstance(node.func, ast.Name) and node.func.id == 'eval':
            if node.args and isinstance(node.args[0], ast.Call):
                inner = node.args[0]
                if isinstance(inner.func, ast.Name) and inner.func.id == 'compile':
                    self._add(
                        severity="critical",
                        title="Obfuscated Exec: eval(compile(...))",
                        description="eval(compile(...)) pattern used for runtime code generation and execution",
                        lineno=lineno,
                        category="obfuscated-exec"
                    )

        # Pattern 3: __import__('os').system(...) dynamic import + execute
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Call):
                inner_call = node.func.value
                if isinstance(inner_call.func, ast.Name) and inner_call.func.id == '__import__':
                    attr_name = node.func.attr
                    if attr_name in DANGEROUS_ATTRS:
                        self._add(
                            severity="critical",
                            title=f"Dynamic Import Execution: __import__().{attr_name}",
                            description=f"__import__() used to evade static analysis, then calls dangerous .{attr_name}()",
                            lineno=lineno,
                            category="obfuscated-exec"
                        )

        # Pattern 4: getattr(os, 'system') or getattr(builtins, 'exec') evasion
        if isinstance(node.func, ast.Name) and node.func.id == 'getattr':
            if len(node.args) >= 2:
                obj_arg = node.args[0]
                attr_arg = node.args[1]
                obj_name = obj_arg.id if isinstance(obj_arg, ast.Name) else None
                # Support both ast.Str (old) and ast.Constant (new)
                if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                    attr_val = attr_arg.value
                elif isinstance(attr_arg, ast.Str):
                    attr_val = attr_arg.s
                else:
                    attr_val = None
                if obj_name in SENSITIVE_MODULES and attr_val in DANGEROUS_ATTRS:
                    self._add(
                        severity="critical",
                        title=f"Dynamic Attribute Access: getattr({obj_name}, '{attr_val}')",
                        description=f"getattr() evasion: calling dangerous '{attr_val}' on '{obj_name}' dynamically",
                        lineno=lineno,
                        category="obfuscated-exec"
                    )

        # Pattern 5: os.system(a + b) or subprocess.call(['/bin/sh', '-c', var])
        # String concatenation into shell commands
        if isinstance(node.func, ast.Attribute):
            obj_name = (node.func.value.id
                        if isinstance(node.func.value, ast.Name) else None)
            attr_name = node.func.attr
            if obj_name in ('os', 'subprocess') and attr_name in ('system', 'popen', 'call', 'run', 'Popen', 'check_output'):
                if node.args:
                    first_arg = node.args[0]
                    # Check for BinOp (string concatenation) as first argument
                    if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                        self._add(
                            severity="critical",
                            title=f"String Concat into Shell: {obj_name}.{attr_name}(a + b)",
                            description=f"Dynamic string construction passed directly to {obj_name}.{attr_name}() (command injection risk)",
                            lineno=lineno,
                            category="shell-injection"
                        )

        # Pattern 6: importlib.import_module(variable) - dynamic import with non-literal arg
        if (isinstance(node.func, ast.Attribute) and
                node.func.attr == 'import_module' and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'importlib'):
            _str_types = (ast.Constant,) + ((ast.Str,) if hasattr(ast, 'Str') else ())
            if node.args and not isinstance(node.args[0], _str_types):
                self._add(
                    severity="critical",
                    title="Dynamic Import: importlib.import_module(variable)",
                    description="importlib.import_module() with non-literal argument. Actual module unknown at analysis time.",
                    lineno=lineno,
                    category="obfuscated-exec"
                )

        # Pattern 7: importlib.reload() - runtime code replacement
        if (isinstance(node.func, ast.Attribute) and
                node.func.attr == 'reload' and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'importlib'):
            self._add(
                severity="high",
                title="Runtime Module Reload: importlib.reload()",
                description="Module reloaded at runtime. Code can change between invocations.",
                lineno=lineno,
                category="obfuscated-exec"
            )

        # Pattern 8: marshal.loads() / marshal.load() - bytecode deserialization
        if (isinstance(node.func, ast.Attribute) and
                node.func.attr in ('loads', 'load') and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'marshal'):
            self._add(
                severity="critical",
                title=f"Bytecode Deserialization: marshal.{node.func.attr}()",
                description="Python bytecode deserialized at runtime. Can contain arbitrary code invisible to source analysis.",
                lineno=lineno,
                category="obfuscated-exec"
            )

        # Pattern 9: types.FunctionType() / types.CodeType() - runtime code construction
        if (isinstance(node.func, ast.Attribute) and
                node.func.attr in ('FunctionType', 'CodeType') and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'types'):
            self._add(
                severity="critical",
                title=f"Runtime Code Construction: types.{node.func.attr}()",
                description=f"types.{node.func.attr}() constructs executable code from raw bytecode at runtime.",
                lineno=lineno,
                category="obfuscated-exec"
            )

        # Pattern 10: sys.addaudithook() - audit system manipulation
        if (isinstance(node.func, ast.Attribute) and
                node.func.attr == 'addaudithook' and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'sys'):
            self._add(
                severity="critical",
                title="Audit Hook Manipulation: sys.addaudithook()",
                description="Adding audit hook can suppress or intercept security events (CVE-2026-2297 related).",
                lineno=lineno,
                category="obfuscated-exec"
            )

        # Pattern 11: bytes([int, int, ...]).decode() - string obfuscation via byte array
        if (isinstance(node.func, ast.Attribute) and
                node.func.attr == 'decode'):
            val = node.func.value
            if isinstance(val, ast.Call):
                if isinstance(val.func, ast.Name) and val.func.id in ('bytes', 'bytearray'):
                    if val.args and isinstance(val.args[0], ast.List):
                        if val.args[0].elts and isinstance(val.args[0].elts[0], ast.Constant):
                            self._add(
                                severity="high",
                                title="String Obfuscation: bytes([int_list]).decode()",
                                description="String constructed from integer byte array. Evades string-matching scanners.",
                                lineno=lineno,
                                category="obfuscated-exec"
                            )

        # Pattern 12: open(__file__, 'w') - self-modification
        if isinstance(node.func, ast.Name) and node.func.id == 'open':
            if len(node.args) >= 2:
                first_arg = node.args[0]
                second_arg = node.args[1]
                if isinstance(first_arg, ast.Name) and first_arg.id == '__file__':
                    if isinstance(second_arg, ast.Constant) and isinstance(second_arg.value, str):
                        if 'w' in second_arg.value or 'a' in second_arg.value:
                            self._add(
                                severity="critical",
                                title="Self-Modification: open(__file__, 'w')",
                                description="Code opens its own source file for writing. Can rewrite itself at runtime.",
                                lineno=lineno,
                                category="obfuscated-exec"
                            )

        self.generic_visit(node)

    def visit_ClassDef(self, node):
        """Detect __reduce__ overrides - classic pickle deserialization backdoor."""
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name in ('__reduce__', '__reduce_ex__', '__setstate__'):
                lineno = getattr(item, 'lineno', None)
                # Check if the function body references dangerous modules/functions
                for sub in ast.walk(item):
                    if isinstance(sub, ast.Name) and sub.id in ('os', 'subprocess', 'exec', 'eval', '__import__'):
                        self._add(
                            severity="critical",
                            title=f"Pickle Backdoor: __reduce__ in class '{node.name}'",
                            description=f"Class '{node.name}' overrides __reduce__ with dangerous calls. Serialized objects of this class execute code on deserialization.",
                            lineno=lineno,
                            category="deserialization"
                        )
                        break
        self.generic_visit(node)


def scan_file(file_path, rel_path):
    """Run AST analysis on a single Python file."""
    if not file_path.endswith('.py'):
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
    except Exception:
        return []

    if not source.strip():
        return []

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        # SyntaxError in Python code is suspicious - may be intentionally broken
        # or using obfuscation that prevents parsing
        return [core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="Python SyntaxError (Unparseable)",
            description="File could not be parsed by Python AST parser. May indicate obfuscation or intentionally malformed code.",
            file=rel_path, line=0,
            snippet="SyntaxError during ast.parse()",
            category="obfuscated-exec"
        )]
    except Exception:
        return []

    source_lines = source.split('\n')
    visitor = ObfuscationVisitor(rel_path, source_lines)
    visitor.visit(tree)
    return visitor.findings


def main():
    args = core.parse_common_args(sys.argv, "Python AST Obfuscation Detector")
    repo_path = args.repo_path

    print(f"[*] Running AST analysis on Python files in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        if not file_path.endswith('.py'):
            continue
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
