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
import _context_gate

SCANNER_NAME = "ast_analysis"

# Modules that are dangerous to access dynamically
SENSITIVE_MODULES = {'os', 'subprocess', 'shutil', 'sys', 'socket', 'builtins', 'importlib'}
# Dangerous attributes/functions on those modules
DANGEROUS_ATTRS = {'system', 'popen', 'Popen', 'call', 'run', 'check_output',
                   'exec', 'eval', 'execve', 'execvp', 'spawnl', 'spawnle'}
# Encoding/decoding functions that precede obfuscated exec
DECODE_FUNCS = {'b64decode', 'decodebytes', 'decodestring',
                'decompress', 'loads', 'fromhex', 'decode', 'unhexlify'}

# Call shapes that retrieve remote content/commands at runtime (fetch sources
# for fetch-then-execute taint). Attribute-name based so both
# `urllib.request.urlopen(...)` and `from urllib.request import urlopen` forms
# resolve; module-scoped verbs cover requests/httpx/urllib3/aiohttp.
FETCH_ATTR_CALLS = {'urlopen', 'HTTPConnection', 'HTTPSConnection'}
FETCH_MODULE_VERBS = {'get', 'post', 'put', 'delete', 'head', 'request',
                      'poolmanager'}
FETCH_MODULES = {'requests', 'httpx', 'urllib3', 'aiohttp'}


class _Scope:
    """Per-scope name bindings collected before the detection pass.

    Tracks only what reflective-call detection needs: foldable string
    constants ("po" + "pen"), module aliases (o = os), module-dict aliases
    (d = os.__dict__ or d = vars(os)), dangerous-callable aliases
    (launch = os.__dict__["po" + "pen"]), and fetch-tainted names (values
    derived from a runtime remote fetch). Names are removed from every map
    on reassignment to something unrecognised, so a stale alias can never
    convict unrelated later code.
    """

    def __init__(self):
        self.const = {}            # name -> constant string
        self.module_aliases = {}   # name -> sensitive module name
        self.dict_aliases = {}     # name -> module name (module.__dict__ / vars(module))
        self.callable_aliases = {} # name -> (module, dangerous attr)
        self.tainted = set()       # names holding fetch-derived values
        self.blocked = set()       # names killed here - shadow outer scopes

    def kill(self, name):
        self.const.pop(name, None)
        self.module_aliases.pop(name, None)
        self.dict_aliases.pop(name, None)
        self.callable_aliases.pop(name, None)
        self.tainted.discard(name)
        self.blocked.add(name)


def _binding_in(scope, name):
    """The binding `name` holds in one _Scope as a (kind, value) tuple:
    ('const', str), ('mod', module), ('dict', module),
    ('callable', (module, attr)), or ('taint', True). None when unbound."""
    if name in scope.const:
        return ('const', scope.const[name])
    if name in scope.module_aliases:
        return ('mod', scope.module_aliases[name])
    if name in scope.dict_aliases:
        return ('dict', scope.dict_aliases[name])
    if name in scope.callable_aliases:
        return ('callable', scope.callable_aliases[name])
    if name in scope.tainted:
        return ('taint', True)
    return None


def _lookup_binding(scopes, name):
    """Innermost binding for `name` across the scope chain (innermost
    first). A branch-killed name is blocked and shadows every outer
    binding, matching Python's assignment-shadows-outer semantics."""
    for scope in scopes:
        if name in scope.blocked:
            return None
        binding = _binding_in(scope, name)
        if binding is not None:
            return binding
    return None


def _apply_binding(scope, name, binding):
    """Write a (kind, value) binding into a scope, replacing anything
    the name held there before (including a branch-kill shadow)."""
    kind, value = binding
    scope.kill(name)
    scope.blocked.discard(name)
    if kind == 'const':
        scope.const[name] = value
    elif kind == 'mod':
        scope.module_aliases[name] = value
    elif kind == 'dict':
        scope.dict_aliases[name] = value
    elif kind == 'callable':
        scope.callable_aliases[name] = value
    elif kind == 'taint':
        scope.tainted.add(name)


def _fold_str(node, scopes):
    """Constant-fold a string expression: literals, literal concatenation
    ("po" + "pen"), and names bound to foldable strings in any enclosing
    collected scope. Returns None when not statically foldable."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_str(node.left, scopes)
        right = _fold_str(node.right, scopes)
        if left is not None and right is not None:
            return left + right
        return None
    if isinstance(node, ast.Name):
        binding = _lookup_binding(scopes, node.id)
        if binding is not None and binding[0] == 'const':
            return binding[1]
        return None
    if isinstance(node, ast.JoinedStr):
        # f"sys{'tem'}" / f"{a}{b}": foldable only when every piece is a
        # literal or a plain (no !r, no :spec) interpolation that itself folds.
        parts = []
        for piece in node.values:
            if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                parts.append(piece.value)
            elif (isinstance(piece, ast.FormattedValue)
                  and piece.conversion == -1 and piece.format_spec is None):
                folded = _fold_str(piece.value, scopes)
                if folded is None:
                    return None
                parts.append(folded)
            else:
                return None
        return "".join(parts)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'join' and len(node.args) == 1
            and not node.keywords):
        # "".join(["sys", "tem"]) / "-".join(("a", "b")): literal separator,
        # literal sequence of foldable strings.
        sep = _fold_str(node.func.value, scopes)
        seq = node.args[0]
        if sep is not None and isinstance(seq, (ast.List, ast.Tuple)):
            parts = [_fold_str(elt, scopes) for elt in seq.elts]
            if all(part is not None for part in parts):
                return sep.join(parts)
    return None


def _resolve_module(node, scopes):
    """Resolve an expression to a sensitive-module name, following module
    aliases (o = os, import os as o) and the runtime-import forms that yield
    the same module object: __import__("os"), importlib.import_module("os"),
    sys.modules["os"]. Returns the module name or None."""
    if isinstance(node, ast.Name):
        if node.id in SENSITIVE_MODULES:
            return node.id
        binding = _lookup_binding(scopes, node.id)
        if binding is not None and binding[0] == 'mod':
            return binding[1]
        return None
    if (isinstance(node, ast.Call) and len(node.args) == 1
            and not node.keywords):
        func = node.func
        is_import = (
            (isinstance(func, ast.Name) and func.id == '__import__')
            or (isinstance(func, ast.Attribute) and func.attr == 'import_module'
                and _resolve_module(func.value, scopes) == 'importlib')
        )
        if is_import:
            name = _fold_str(node.args[0], scopes)
            if name in SENSITIVE_MODULES:
                return name
        return None
    if isinstance(node, ast.Subscript):
        base = node.value
        if (isinstance(base, ast.Attribute) and base.attr == 'modules'
                and _resolve_module(base.value, scopes) == 'sys'):
            sl = node.slice
            if hasattr(ast, 'Index') and isinstance(sl, ast.Index):
                sl = sl.value
            name = _fold_str(sl, scopes)
            if name in SENSITIVE_MODULES:
                return name
    return None


def _dict_base_module(node, scopes):
    """Resolve a module-dict expression to its module name:
    os.__dict__, vars(os), or an alias of either (d = os.__dict__)."""
    if isinstance(node, ast.Attribute) and node.attr == '__dict__':
        return _resolve_module(node.value, scopes)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'vars' and len(node.args) == 1):
        return _resolve_module(node.args[0], scopes)
    if isinstance(node, ast.Name):
        binding = _lookup_binding(scopes, node.id)
        if binding is not None and binding[0] == 'dict':
            return binding[1]
    return None


def _reflective_target(node, scopes):
    """Resolve a reflective-retrieval expression to (module, dangerous attr):
    os.__dict__["po" + "pen"], vars(os)["system"], aliases of those, and the
    dict.get("sy" + "stem") form. Returns None when the expression is not a
    dangerous reflective retrieval."""
    if isinstance(node, ast.Subscript):
        mod = _dict_base_module(node.value, scopes)
        sl = node.slice
        # Python 3.8 wraps the subscript key in ast.Index (removed in 3.9+).
        if hasattr(ast, 'Index') and isinstance(sl, ast.Index):
            sl = sl.value
        key = _fold_str(sl, scopes)
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
          and node.func.attr == 'get' and node.args):
        mod = _dict_base_module(node.func.value, scopes)
        key = _fold_str(node.args[0], scopes)
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
          and node.func.attr == '__getattribute__' and len(node.args) == 1):
        # os.__getattribute__("sys" + "tem"): attribute retrieval by method
        # call, the same evasion as getattr(os, "system").
        mod = _resolve_module(node.func.value, scopes)
        key = _fold_str(node.args[0], scopes)
    else:
        return None
    if mod in SENSITIVE_MODULES and key in DANGEROUS_ATTRS:
        return (mod, key)
    return None


def _is_fetch_call(node, scopes):
    """True when a Call node retrieves remote content/commands at runtime."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == 'urlopen'
    if isinstance(func, ast.Attribute):
        if func.attr in ('urlopen', 'HTTPConnection', 'HTTPSConnection'):
            return True
        if func.attr in ('create_connection', 'connect'):
            # Socket-shaped connects only: a bare `conn.connect()` on an
            # arbitrary object (db, websocket client) is not a fetch source.
            base = func.value
            if isinstance(base, ast.Name) and base.id == 'socket':
                return True
            if (isinstance(base, ast.Attribute)
                    and base.attr == 'socket'):
                return True
            if isinstance(base, ast.Name):
                if _lookup_binding(scopes, base.id) == ('mod', 'socket'):
                    return True
            return False
        if func.attr.lower() in FETCH_MODULE_VERBS:
            base = func.value
            if isinstance(base, ast.Name) and base.id in FETCH_MODULES:
                return True
            if isinstance(base, ast.Name):
                binding = _lookup_binding(scopes, base.id)
                if (binding is not None and binding[0] == 'mod'
                        and binding[1] in FETCH_MODULES):
                    return True
    return False


def _is_tainted(node, scopes):
    """True when an expression derives from a runtime remote fetch: it
    contains a fetch call or a name previously bound to fetch-derived data
    (propagating through .read()/.json()/json.loads(...).get(...) chains)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            if _lookup_binding(scopes, sub.id) == ('taint', True):
                return True
        elif _is_fetch_call(sub, scopes):
            return True
    return False


def _collect_scope(body, outer_scopes, fetch_funcs, reflective_funcs):
    """Walk one statement body in source order, collecting bindings.

    `outer_scopes` are enclosing scopes (read fallback). FunctionDefs are
    analysed recursively with a fresh local scope and registered in
    fetch_funcs / reflective_funcs when they return fetch-tainted data or a
    dangerous reflective retrieval, so `command = fetch_cmd()` taints and
    `sink = get_launcher()` aliases at the call site.
    """
    scope = _Scope()
    scopes = [scope] + list(outer_scopes)

    def merge_branch_bodies(bodies, include_incoming):
        """Join conditional branches conservatively. Each branch body is
        collected into its own scope seeded from the current chain; a
        binding survives the join only when EVERY reachable exit agrees on
        it (branches that do not bind the name contribute the incoming
        binding). Otherwise the name is killed here, shadowing outer
        scopes, so a branch-only alias or taint can never convict
        post-join code.

        Safe against evasion because Pattern 13 / visit_Subscript convict the
        reflective retrieval expression itself, wherever it appears, whether
        or not an alias survives the join; only the secondary
        Fetch-then-Execute finding needs the alias, so losing it post-join
        costs one corroborating finding, never the detection."""
        branch_scopes = [
            _collect_scope(b, scopes, fetch_funcs, reflective_funcs)
            for b in bodies if b
        ]
        names = set()
        for bs in branch_scopes:
            names |= (set(bs.const) | set(bs.module_aliases)
                      | set(bs.dict_aliases) | set(bs.callable_aliases)
                      | bs.tainted | bs.blocked)
        for name in names:
            exits = []
            for bs in branch_scopes:
                if name in bs.blocked:
                    # The branch re-bound the name to something
                    # unrecognised: that exit's binding is unknown,
                    # not the incoming one.
                    exits.append(None)
                    continue
                bound = _binding_in(bs, name)
                exits.append(bound if bound is not None
                             else _lookup_binding(scopes, name))
            if include_incoming:
                exits.append(_lookup_binding(scopes, name))
            first = exits[0]
            if first is not None and all(e == first for e in exits):
                _apply_binding(scope, name, first)
            else:
                scope.kill(name)

    def handle_stmt(stmt):
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            # `import os as o` / `from . import os as o` bind a sensitive
            # module under a new name. Unaliased forms resolve by name
            # already; only a rebinding needs recording.
            for alias in stmt.names:
                if alias.asname and alias.name in SENSITIVE_MODULES \
                        and (isinstance(stmt, ast.Import)
                             or (stmt.module is None and stmt.level > 0)):
                    scope.blocked.discard(alias.asname)
                    scope.module_aliases[alias.asname] = alias.name
                elif alias.asname:
                    scope.kill(alias.asname)
            return
        if isinstance(stmt, ast.FunctionDef):
            local = _collect_scope(stmt.body, scopes, fetch_funcs,
                                   reflective_funcs)
            local_scopes = [local] + scopes
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Return) and sub.value is not None:
                    if _is_tainted(sub.value, local_scopes):
                        fetch_funcs.add(stmt.name)
                    target = _reflective_target(sub.value, local_scopes)
                    if target is not None:
                        reflective_funcs[stmt.name] = target
            return
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if (item.optional_vars is not None
                        and isinstance(item.optional_vars, ast.Name)
                        and _is_tainted(item.context_expr, scopes)):
                    scope.blocked.discard(item.optional_vars.id)
                    scope.tainted.add(item.optional_vars.id)
            for sub in stmt.body:
                handle_stmt(sub)
            return
        if isinstance(stmt, ast.If):
            # if/else: post-join bindings must agree across branch exits.
            # With no else, the incoming state is itself an exit.
            bodies = [stmt.body] + ([stmt.orelse] if stmt.orelse else [])
            merge_branch_bodies(bodies, include_incoming=not stmt.orelse)
            return
        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            # Loops may execute zero times: the incoming state is always a
            # reachable exit, so a body-only binding never survives.
            bodies = [stmt.body] + ([stmt.orelse] if stmt.orelse else [])
            merge_branch_bodies(bodies, include_incoming=True)
            if isinstance(stmt, (ast.For, ast.AsyncFor)) \
                    and isinstance(stmt.target, ast.Name):
                # The loop target holds the last iterated value (or the
                # incoming binding after zero iterations) - never a
                # reliable alias or taint carrier.
                scope.kill(stmt.target.id)
            return
        if isinstance(stmt, ast.Try):
            # Post-join code is reachable only via the body exit or a
            # handler exit (an uncaught exception never reaches it), so the
            # incoming state is not an exit of its own; handlers that leave
            # the name untouched resolve to the incoming binding through
            # the merge. finally runs on every path, so its bindings apply
            # unconditionally afterwards.
            bodies = [stmt.body] + [h.body for h in stmt.handlers]
            if stmt.orelse:
                bodies.append(stmt.orelse)
            merge_branch_bodies(bodies, include_incoming=False)
            for sub in stmt.finalbody:
                handle_stmt(sub)
            return
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0], ast.Name):
            name = stmt.targets[0].id
            value = stmt.value
            folded = _fold_str(value, scopes)
            if folded is not None:
                scope.blocked.discard(name)
                scope.const[name] = folded
                return
            mod = _resolve_module(value, scopes)
            if mod is not None:
                scope.blocked.discard(name)
                scope.module_aliases[name] = mod
                return
            dict_mod = _dict_base_module(value, scopes)
            if dict_mod is not None:
                scope.blocked.discard(name)
                scope.dict_aliases[name] = dict_mod
                return
            target = _reflective_target(value, scopes)
            if target is not None:
                scope.blocked.discard(name)
                scope.callable_aliases[name] = target
                return
            if (isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)):
                if value.func.id in reflective_funcs:
                    scope.blocked.discard(name)
                    scope.callable_aliases[name] = \
                        reflective_funcs[value.func.id]
                    return
                if value.func.id in fetch_funcs:
                    scope.blocked.discard(name)
                    scope.tainted.add(name)
                    return
            if _is_tainted(value, scopes):
                scope.blocked.discard(name)
                scope.tainted.add(name)
                return
            # Unrecognised reassignment: the name no longer aliases anything.
            scope.kill(name)
            return
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            scope.kill(stmt.target.id)
            return
        if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            scope.kill(stmt.target.id)

    for stmt in body:
        handle_stmt(stmt)
    return scope



class ObfuscationVisitor(ast.NodeVisitor):
    """AST visitor detecting obfuscation and dangerous dynamic patterns."""

    def __init__(self, rel_path, source_lines, budget=None):
        self.rel_path = rel_path
        self.source_lines = source_lines
        self.findings = []
        # Encoded blobs already handed to scan_decode (per file), so the same
        # literal blob is decoded only once (dedup).
        self.decoded_seen = set()
        # ONE shared scan_decode budget threaded from main() across every file so
        # the decode deadline + byte cap span the whole scan, never re-armed.
        self.budget = budget
        # Reflective-call / taint state, populated by bind() before visiting:
        # scope stack (innermost first), functions returning fetch-tainted
        # values, functions returning dangerous reflective retrievals.
        self._scopes = [_Scope()]
        self._fetch_funcs = set()
        self._reflective_funcs = {}

    def bind(self, tree):
        """Run the binding pre-pass over a parsed module. Must be called
        before visit(); scan_file() does this. Collects constants, aliases,
        taint, and helper-return shapes used by the reflective-sink and
        fetch-then-execute patterns."""
        self._scopes = [_collect_scope(tree.body, [], self._fetch_funcs,
                                       self._reflective_funcs)]

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

    def _decode_and_rescan(self, blob):
        """Hand an already-flagged encoded string literal to scan_decode and
        extend findings with any decoded-payload hits (additive; the
        Encoded Payload finding stays). Decodes each unique blob once per file
        (dedup). Guarded so a scan_decode failure never breaks the AST scan.

        The blob here is an AST string LITERAL (not a regex-detected run), so it
        is fed directly via the hoisted scan_decode.feed_blobs plumbing rather
        than detect_encoded_blobs."""
        try:
            import scan_decode
        except Exception:
            return
        if self.budget is None:
            self.budget = scan_decode.host_budget()
        scan_decode.feed_blobs(
            [blob], self.rel_path, self.decoded_seen, self.findings, self.budget
        )

    def _literal_str_args(self, node):
        """Yield each string-literal argument of a Call node (the encoded blob
        carried inline, e.g. base64.b64decode('....'))."""
        for arg in getattr(node, 'args', []):
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                yield arg.value

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

        # Pattern 0 (torture H2): ANY decode-family call with a string-literal arg
        # — e.g. base64.b64decode("<payload>"), bytes.fromhex("..."),
        # codecs.decode("...") — even when NOT wrapped in exec/eval. Previously the
        # decode-and-rescan branch only ran inside exec(decode(...)), so a plain
        # literal `base64.b64decode("...os.system(chr(...))...")` assigned to a
        # variable was extracted by nobody and surfaced 0 decoded payloads
        # end-to-end. Extract the literal and route it to scan_decode directly.
        # Findings are additive and scan_decode only emits when the DECODED
        # plaintext trips a rule, so a benign decode literal stays silent.
        if self._call_name(node).split('.')[-1] in DECODE_FUNCS:
            for blob in self._literal_str_args(node):
                self._decode_and_rescan(blob)

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
                    # Decode-and-rescan the inline encoded literal (additive; Gap 4(a)).
                    for blob in self._literal_str_args(node.args[0]):
                        self._decode_and_rescan(blob)

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
                obj_name = _resolve_module(obj_arg, self._scopes)
                # Support both ast.Constant (3.8+) and ast.Str (deprecated 3.8,
                # REMOVED 3.12+). Guard the bare ast.Str reference with hasattr so
                # evaluating it does not AttributeError on 3.12+ (it crashed the whole
                # scanner on modern Python), mirroring the guarded sites below and in
                # scan_entrypoint.py. ast.Constant already covers every string literal
                # on 3.8+, so this branch is dead weight there and live only on <3.12.
                # The key is then constant-folded so getattr(os, "po" + "pen")
                # and getattr(os, KEY) with KEY bound to a literal resolve too.
                if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                    attr_val = attr_arg.value
                elif hasattr(ast, "Str") and isinstance(attr_arg, ast.Str):
                    attr_val = attr_arg.s
                else:
                    attr_val = self._fold(attr_arg)
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
                    shell_kw = next((kw.value for kw in node.keywords if kw.arg == 'shell'), None)
                    uses_shell = obj_name == 'os' or (
                        shell_kw is not None
                        and not (isinstance(shell_kw, ast.Constant) and shell_kw.value is False)
                    )
                    if (uses_shell and isinstance(first_arg, ast.BinOp)
                            and isinstance(first_arg.op, ast.Add)):
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

        # Pattern 13: reflective dangerous sink invoked through a module
        # __dict__ / vars() subscript, a .get() on the module dict, or a
        # callable alias (launch = os.__dict__["po" + "pen"]; launch(cmd)).
        # The retrieval itself is flagged by visit_Subscript (or at the
        # assignment for aliases); here we resolve the sink for the
        # fetch-then-execute taint check and for the .get() form, which has
        # no Subscript node.
        sink = None
        sink_from_get = False
        if isinstance(node.func, ast.Subscript):
            sink = _reflective_target(node.func, self._scopes)
        elif isinstance(node.func, ast.Name):
            binding = _lookup_binding(self._scopes, node.func.id)
            if binding is not None and binding[0] == 'callable':
                sink = binding[1]
        elif (isinstance(node.func, ast.Attribute)
              and node.func.attr in ('get', '__getattribute__')):
            sink = _reflective_target(node, self._scopes)
            sink_from_get = sink is not None
        if sink_from_get:
            if node.func.attr == '__getattribute__':
                via = f"{sink[0]}.__getattribute__('{sink[1]}')"
                how = "via .__getattribute__() with a folded key"
            else:
                via = f"{sink[0]}.__dict__.get('{sink[1]}')"
                how = "via .__dict__.get() with a folded key"
            self._add(
                severity="critical",
                title=f"Reflective Attribute Access: {via}",
                description=f"Reflective attribute access evasion: dangerous '{sink[1]}' retrieved from '{sink[0]}' {how}",
                lineno=lineno,
                category="obfuscated-exec"
            )

        # Pattern 14: fetch-then-execute. A command fetched from a remote
        # source at call time (urlopen/requests/... through .read()/.json()/
        # json.loads().get() or a helper return) flows into a reflective
        # shell sink. This is the runtime-fetched RCE shape that per-call
        # metadata scanning cannot see.
        if sink is not None:
            tainted_arg = any(
                _is_tainted(arg, self._scopes)
                for arg in list(node.args) + [kw.value for kw in node.keywords]
            )
            if tainted_arg:
                self._add(
                    severity="critical",
                    title=f"Fetch-then-Execute: remote content passed to reflective {sink[0]}.{sink[1]}",
                    description=(f"Command/content fetched from a remote source at runtime is "
                                 f"passed to a reflectively-resolved {sink[0]}.{sink[1]} sink. "
                                 f"The executed payload is invisible to static and metadata scanning."),
                    lineno=lineno,
                    category="remote-code-execution"
                )

        self.generic_visit(node)

    def _fold(self, node):
        """Constant-fold a string expression against collected bindings."""
        return _fold_str(node, self._scopes)

    def visit_Subscript(self, node):
        """Flag dangerous reflective retrieval: os.__dict__["po" + "pen"],
        vars(os)["system"], or an alias of the module dict subscripted with a
        foldable dangerous key. Fires at the retrieval site whether or not
        the result is ever called - the retrieval alone hides the sink from
        call-based scanners."""
        target = _reflective_target(node, self._scopes)
        if target is not None:
            self._add(
                severity="critical",
                title=f"Reflective Attribute Access: {target[0]}.__dict__['{target[1]}']",
                description=f"Reflective dict access evasion: dangerous '{target[1]}' retrieved from '{target[0]}' via __dict__/vars() with a folded key",
                lineno=getattr(node, 'lineno', None),
                category="obfuscated-exec"
            )
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        """Track function-local binding scopes so aliases/constants/taint
        declared inside a function resolve for its body, and never leak out
        to sibling code."""
        local = _collect_scope(node.body, self._scopes, self._fetch_funcs,
                               self._reflective_funcs)
        self._scopes.insert(0, local)
        self.generic_visit(node)
        self._scopes.pop(0)

    def _visit_branch_bodies(self, bodies):
        """Visit conditional branch bodies with a branch-local binding
        scope pushed, so aliases/taint resolve INSIDE the branch that
        defines them (the pre-pass join keeps them out of the post-join
        scope)."""
        for body in bodies:
            if not body:
                continue
            local = _collect_scope(body, self._scopes, self._fetch_funcs,
                                   self._reflective_funcs)
            self._scopes.insert(0, local)
            for sub in body:
                self.visit(sub)
            self._scopes.pop(0)

    def visit_If(self, node):
        self.visit(node.test)
        self._visit_branch_bodies([node.body, node.orelse])

    def visit_While(self, node):
        self.visit(node.test)
        self._visit_branch_bodies([node.body, node.orelse])

    def visit_For(self, node):
        self.visit(node.target)
        self.visit(node.iter)
        self._visit_branch_bodies([node.body, node.orelse])

    visit_AsyncFor = visit_For

    def visit_Try(self, node):
        bodies = [node.body] + [h.body for h in node.handlers]
        bodies += [node.orelse, node.finalbody]
        self._visit_branch_bodies(bodies)

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


def scan_file(file_path, rel_path, budget=None):
    """Run AST analysis on a single Python file.

    `budget`: optional shared scan_decode budget (see main()). When None the
    visitor mints a fresh per-file budget on first decode (correct for a
    single-file caller / tests); main() threads ONE budget across all files."""
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
    except (ValueError, RecursionError):
        return []

    source_lines = source.split('\n')
    visitor = ObfuscationVisitor(rel_path, source_lines, budget=budget)
    visitor.bind(tree)
    visitor.visit(tree)
    try:
        if _context_gate.classify_file_context(rel_path, source).is_test_fixture:
            for finding in visitor.findings:
                if finding.title == "Dynamic Import: importlib.import_module(variable)":
                    finding.severity = "high"
    except Exception:
        pass
    return visitor.findings


def main():
    args = core.parse_common_args(sys.argv, "Python AST Obfuscation Detector")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Running AST analysis on Python files in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    # ONE shared decode budget across every file (see scan_decode.new_budget):
    # the wall-clock deadline + byte cap span the whole scan, never re-armed.
    try:
        import scan_decode
        budget = scan_decode.host_budget()
    except Exception:
        budget = None

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        if not file_path.endswith('.py'):
            continue
        findings = scan_file(file_path, rel_path, budget=budget)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
