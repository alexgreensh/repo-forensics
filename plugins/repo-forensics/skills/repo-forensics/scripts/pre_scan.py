#!/usr/bin/env python3
"""
pre_scan.py - pre-execution hook handler for repo-forensics v2.
Lightweight gate that blocks known-malicious packages and pipe-to-shell
patterns BEFORE the command runs.

Runs as a Claude Code / Codex / OpenClaw **PreToolUse** hook and as a Cursor
**beforeShellExecution** hook (`--adapter cursor`). Reads JSON from stdin,
outputs JSON to stdout. Fast path (<10ms for non-matching commands). IOC-only
— no subprocess calls, no full scans (those run post-execution in auto_scan.py).

Design constraints (all critical for safety):
  - MUST NOT call subprocess or spawn any child process (avoids recursive
    hook triggers and keeps latency under 200ms even on IOC matches)
  - MUST NOT block commands when IOC database is unavailable (graceful
    degradation — approve on error, never silently block legitimate work)
  - MUST output valid JSON to stdout in all code paths (empty {} = approve
    on the Claude shape, {"permission": ...} on the Cursor shape)
  - MUST exit 0 for approve/ask, exit 2 for block

Adapters (PRD v3 R2/G3): envelope normalisation and verdict rendering live in
hook_adapter.py so both wires run the SAME detection code. hook_adapter is a
leaf (stdlib only, no repo imports); importing it does not weaken the
"pre_scan stays standalone" rule, which is about never pulling in auto_scan or
the scanner fan-out.

Verdict precedence on the blocking path (PRD v3 R8/R11 — see
hook_adapter.PRECEDENCE_DOC):

    REPO_FORENSICS_PRE_SCAN=unsafe-off   allow everything, loudly
  > install-manifest tamper              deny  (NOT user-suppressible)
  > envelope drift on a failClosed wire  deny  (NOT user-suppressible)
  > REPO_FORENSICS_PRE_SCAN=0            allow, loudly
  > detection verdict                    deny / ask / allow

The two integrity states outrank the ordinary kill switch on purpose: the
switch is read from the session environment, so an earlier command in the same
session can plant it. If it could also mask a deleted scanner or a spoofed
envelope, one planted variable would buy an attacker the whole gate.

Created by Alex Greenshpun
"""

import json
import os
import re
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

import hook_adapter  # noqa: E402  (leaf module, stdlib-only)

# --- Pattern Detection ---
# NOTE: These patterns are intentionally duplicated from auto_scan.py.
# pre_scan.py MUST remain standalone (no imports from auto_scan, no subprocess)
# to guarantee <10ms latency and zero recursion risk. If you update patterns
# here, update auto_scan.py too (and vice versa).

# Optional package-manager flags between the tool name and its subcommand
# (`pnpm -r add x`, `pnpm --filter web add x`, `uv --project /p add x`). Each
# unit is one -flag (first char after the dash(es) is a non-dash, so dash runs
# fail fast — no ReDoS) plus an optional value token that must NOT be a
# subcommand keyword. Kept identical in auto_scan.py — update both.
_PM_FLAGS = (
    r'(?:-{1,2}[^-\s]\S*'
    r'(?:\s+(?!(?:install|i|add|update|sync|pip|tool|remove|run)\b)[^-\s]\S*)?'
    r'\s+)*'
)

INSTALL_PATTERNS = [
    # uv/pnpm must precede pip/npm: the patterns are unanchored, so
    # 'uv pip install x' / 'pnpm install x' substring-match the pip/npm entries.
    # _PM_FLAGS covers flags between the tool and subcommand (monorepo forms).
    (re.compile(r'uv\s+' + _PM_FLAGS + r'(?:add|pip\s+install|tool\s+install)\s+(.+)'), 'uv_install'),
    (re.compile(r'pip3?\s+install\s+(.+)'), 'pip_install'),
    (re.compile(r'pnpm\s+' + _PM_FLAGS + r'(?:install|i|add|update)\s+(.+)'), 'pnpm_install'),
    (re.compile(r'bun\s+' + _PM_FLAGS + r'(?:install|i|add|update)\s+(.+)'), 'bun_install'),
    (re.compile(r'npm\s+(?:install|i)\s+(.+)'), 'npm_install'),
    (re.compile(r'npm\s+update\s+(.+)'), 'npm_install'),
    (re.compile(r'yarn\s+add\s+(.+)'), 'yarn_add'),
    (re.compile(r'gem\s+(?:install|update)\s+(.+)'), 'gem_install'),
    (re.compile(r'cargo\s+install\s+(.+)'), 'cargo_install'),
    (re.compile(r'go\s+(?:get|install)\s+(.+)'), 'go_install'),
    (re.compile(r'brew\s+(?:install|upgrade)\s+(.+)'), 'brew_install'),
    (re.compile(r'openclaw\s+(?:skills|plugins)\s+(?:install|update)\s+(.+)'), 'openclaw_install'),
    (re.compile(r'clawhub\s+(?:install|publish)\s+(.+)'), 'openclaw_install'),
]

_DOWNLOADERS = r'(?:curl|wget|aria2c|http|Invoke-WebRequest)'
_SHELLS = r'(?:sudo\s+)?(?:/[\w/.-]*/)?(?:bash|zsh|dash|ksh|csh|tcsh|fish|pwsh|sh)(?!\w)'
_BASE64_PIPE = r'base64\s+(?:-d|--decode)\s*\|'

PIPE_TO_SHELL = re.compile(
    r'(?:'
    r'(?:' + _DOWNLOADERS + r')\s+[^|]*\|\s*(?:' + _BASE64_PIPE + r'\s*)?(?:' + _SHELLS + r'|iex)'
    r'|' + _BASE64_PIPE + r'\s*(?:' + _SHELLS + r'|iex)'
    r'|(?:' + _DOWNLOADERS + r')\s+[^>]*>\s*/tmp/[^\s;]+\s*(?:;|&&?)\s*(?:' + _SHELLS + r')\s+/tmp/'
    r')',
    re.IGNORECASE,
)

# Strip ONLY the flag token itself, never a following "value" — otherwise a
# boolean flag swallows the next package (`npm install foo --save-exact keyv@6.0.0`
# hid keyv). A real value-flag's argument (a URL, a path) is left as a token, but
# it harmlessly matches no IOC. Every non-flag token must reach the IOC checks.
INSTALL_FLAGS = re.compile(r'\s+--?[a-zA-Z][\w-]*')


def parse_hook_input():
    """Read and parse PreToolUse JSON from stdin."""
    try:
        raw = sys.stdin.read(1_048_576)  # 1MB max
        if not raw.strip():
            return None
        return json.loads(raw)
    except (json.JSONDecodeError, IOError):
        return None


def extract_command(data):
    """Extract the bash command from hook payload."""
    if not data:
        return None
    if data.get('tool_name', '') != 'Bash':
        return None
    tool_input = data.get('tool_input', {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except json.JSONDecodeError:
            return None
    return tool_input.get('command', '')


# --- Inert quote carriers ---------------------------------------------------
# A pipe-to-shell pattern inside a quoted argument to a command that never
# executes its arguments is someone WRITING ABOUT the attack, not performing
# it — a `git commit -m` whose message warns against downloader-to-shell
# pipelines, a `grep` searching the docs for them, an `echo` telling the reader
# not to. Blocking those is the false positive that gets a blocking hook
# uninstalled, and it fires on this repo's own commit messages, which discuss
# pipe-to-shell constantly. (These examples are deliberately paraphrased rather
# than written out: pre_scan.py and auto_scan.py are the blocking gate and stay
# OUT of .forensicsignore, so a literal payload here would be a finding the
# scanner reports against itself — see tests/test_cursor_wiring.py.)
#
# This is the command-string analogue of the evidence model forensics_core
# already applies to files (a README that DESCRIBES an attack is not the
# attack). The suppression is deliberately narrow, because the obvious wide
# version — "ignore anything inside quotes" — is a bypass, not a fix: a
# downloader-to-shell pipeline handed to `sh -c` as a quoted argument is both
# quoted AND executed. So two conditions must BOTH hold: the command starts
# with a known inert carrier, and the residue left after deleting every quoted
# span contains no shell execution of its own. An `echo` whose quoted argument
# is itself piped onward to a shell keeps that residual pipe and still blocks.
# Kept identical in auto_scan.py — update both.
# Only commands whose job is to RECORD or SEARCH FOR text, never to produce a
# stream someone would plausibly pipe onward. `cat`, `jq` and friends are
# deliberately absent: their output being piped to a shell is a normal thing to
# do, so they do not belong on a list whose whole premise is "this argument is
# inert prose". (The residual-exec check below would catch a piped `cat` too,
# but a suppression list should not lean on a second layer to stay safe.)
_INERT_CARRIERS = re.compile(
    r'^\s*(?:'
    r'echo|printf|grep|egrep|fgrep|rg|ag|ack'
    r'|git\s+(?:commit|tag|notes|stash\s+save|config)'
    r'|gh\s+(?:issue|pr|release)\s+[a-z-]+'
    r')\b',
    re.IGNORECASE,
)

# Quoted spans: single- or double-quoted, non-greedy, no cross-line matching.
_QUOTED_SPAN = re.compile(r"'[^']*'|\"[^\"]*\"")

# Residual shell execution after quoted spans are removed. Any of these means
# the command really does hand something to a shell, so no suppression.
_RESIDUAL_EXEC = re.compile(
    r'\|\s*(?:' + _SHELLS + r'|iex)'
    r'|(?:^|[\s;&|(])(?:eval|exec|source)\b'
    r'|\B-c(?:\s|$)'
    r'|(?:^|[\s;&|(])' + _SHELLS + r'\s+-c',
    re.IGNORECASE,
)


def is_inert_quote_carrier(command):
    """True when every pipe-to-shell signal in *command* sits inside a quoted
    argument to a command that does not execute its arguments."""
    if not command or not _INERT_CARRIERS.match(command):
        return False
    residue = _QUOTED_SPAN.sub(' ', command)
    if _RESIDUAL_EXEC.search(residue):
        return False
    # The signal must be gone once the quotes are removed. If it survives, it
    # was never inside a quoted argument in the first place — an inert carrier
    # followed by `;` and then a real downloader-to-shell pipeline.
    return not PIPE_TO_SHELL.search(residue)


# PowerShell download/execution gate. Deliberately duplicated in auto_scan:
# pre_scan must not import the post-hook (scanner fan-out / recursion risk).
_PS_FETCH = frozenset(('irm', 'iwr', 'curl', 'wget', 'invoke-restmethod',
                       'invoke-webrequest', 'start-bitstransfer'))
_PS_HINT = re.compile(r'(?:irm|iwr|curl|wget|invoke-restmethod|invoke-webrequest|start-bitstransfer|downloadstring|downloadfile|powershell|pwsh)', re.IGNORECASE)
_PS_EXEC = frozenset(('iex', 'invoke-expression'))
_PS_SHELL = frozenset(('sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'tcsh', 'fish'))
_PS_HOST = frozenset(('powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'))
_PS_ENCODED = frozenset(('e', 'ec', 'en', 'enc', 'enco', 'encod', 'encode',
                         'encoded', 'encodedc', 'encodedco', 'encodedcom',
                         'encodedcomm', 'encodedcomma', 'encodedcomman',
                         'encodedcommand'))


def _ps_tokens(command, dialect='shell'):
    """A bounded lexical view, not a PowerShell evaluator. Never runs code.

    Keep literal strings separate from code; command/Invoke-Expression strings
    are inspected only at their execution sites. Remove PowerShell backtick
    escapes from names and join escaped line continuations. Comments are inert.
    """
    tokens = []
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c.isspace():
            start = i
            while i < n and command[i].isspace():
                i += 1
            if '\n' in command[start:i] and tokens and tokens[-1] != ('symbol', '|') and command[i:i + 1] != '|':
                tokens.append(('symbol', ';'))
        elif command.startswith('<#', i):
            end = command.find('#>', i + 2)
            i = n if end < 0 else end + 2
        elif c == '#':
            end = command.find('\n', i)
            if end >= 0 and tokens and tokens[-1] != ('symbol', '|'):
                tokens.append(('symbol', ';'))
            i = n if end < 0 else end + 1
        elif c in "'\"":
            quote, value = c, []
            i += 1
            while i < n:
                if command[i] == quote:
                    if i + 1 < n and command[i + 1] == quote:
                        value.append(quote)
                        i += 2
                        continue
                    i += 1
                    break
                if dialect == 'shell' and quote == '"' and command[i] == '\\' and i + 1 < n and command[i + 1] in ('"', '\\'):
                    # Shell -c strings escape nested quotes with backslashes.
                    value.append(command[i + 1])
                    i += 2
                    continue
                if quote == '"' and command[i] == '`' and i + 1 < n:
                    # Retain the escape marker so an escaped dollar is inert.
                    value.append('`')
                    i += 1
                value.append(command[i])
                i += 1
            tokens.append(('double' if quote == '"' else 'string', ''.join(value)))
        elif c in '|;(){}&,=':
            tokens.append(('symbol', c))
            i += 1
        else:
            value = []
            while i < n and not command[i].isspace() and command[i] not in "'\"|;(){}&,=#":
                if command[i] == '`' and i + 1 < n:
                    i += 1
                    if command[i] in '\r\n':
                        if command[i] == '\r' and i + 1 < n and command[i + 1] == '\n':
                            i += 1
                        i += 1
                        continue
                value.append(command[i])
                i += 1
            tokens.append(('word', ''.join(value).lower()))
    return tokens


def _ps_name(tokens, index):
    kind, value = tokens[index]
    # Quoted names are invoked ONLY after &, never just because text names a tool.
    if kind in ('string', 'double') and not (index and tokens[index - 1] in (('symbol', '&'), ('word', '.'))):
        return ''
    if kind not in ('word', 'string', 'double'):
        return ''
    return value.lower().replace('`', '').replace('\\', '/').rsplit('/', 1)[-1]


def _ps_fetches(tokens):
    for i, (kind, value) in enumerate(tokens):
        name = _ps_name(tokens, i)
        if name in _PS_FETCH:
            # Require a command/expression position, not an argument or URL.
            if i == 0 or tokens[i - 1][1] in ('(', '|', ';', '{', '&', '=', '.', '-command', '-c', '/c', '/command'):
                return True
        if kind == 'word' and ('.downloadstring' in value or '.downloadfile' in value) and (value.startswith('$') or (value.startswith('.') and i and tokens[i - 1][1] == ')')):
            return True
    return False


def _ps_subexpressions(value):
    i = 0
    while i < len(value):
        if value[i] == '`':
            i += 2
        elif value.startswith('$(', i):
            start, balance = i + 2, 1
            i += 2
            while i < len(value) and balance:
                if value[i] == '`':
                    i += 2
                    continue
                if value[i] == '(':
                    balance += 1
                elif value[i] == ')':
                    balance -= 1
                i += 1
            yield value[start:i - 1] if not balance else value[start:i]
        else:
            i += 1


def _ps_pipe_before(tokens, index, start):
    while index > start and tokens[index - 1][1] in ('&', 'sudo'):
        index -= 1
    return index > start and tokens[index - 1][1] == '|'


def _ps_literal_heredoc_directives(line):
    """Read quoted shell heredoc delimiters outside strings and comments."""
    i = 0
    while i < len(line):
        c = line[i]
        if c == '#':
            break
        if c == '\\':
            i += 2
            continue
        if c in "'\"":
            quote = c
            i += 1
            while i < len(line):
                if quote == '"' and line[i] == '\\':
                    i += 2
                    continue
                if line[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if line.startswith('<<', i) and (i == 0 or line[i - 1] != '<') and line[i + 2:i + 3] != '<':
            match = re.match(r"<<(-?)\s*(['\"])([^'\"\r\n]+)\2", line[i:])
            if match and (i + match.end() == len(line) or line[i + match.end()].isspace() or line[i + match.end()] in '<>|;&()'):
                yield match.group(3), bool(match.group(1))
                i += match.end()
                continue
        i += 1


def _ps_remove_heredoc_operators(line):
    # The directive lexer already checked quote/comment context. Replace only
    # accepted operators, preserving other header expressions for inspection.
    result, i = [], 0
    while i < len(line):
        c = line[i]
        if c == '#':
            result.append(line[i:])
            break
        if c == '\\':
            result.append(line[i:i + 2])
            i += 2
            continue
        if c in "'\"":
            quote, start = c, i
            i += 1
            while i < len(line):
                if quote == '"' and line[i] == '\\':
                    i += 2
                    continue
                if line[i] == quote:
                    i += 1
                    break
                i += 1
            result.append(line[start:i])
            continue
        if line.startswith('<<', i) and (i == 0 or line[i - 1] != '<') and line[i + 2:i + 3] != '<':
            match = re.match(r"<<(-?)\s*(['\"])([^'\"\r\n]+)\2", line[i:])
            if match and (i + match.end() == len(line) or line[i + match.end()].isspace() or line[i + match.end()] in '<>|;&()'):
                result.append(' ')
                i += match.end()
                continue
        result.append(c)
        i += 1
    return ''.join(result)


def _ps_shell_quote_state(line, quote=None):
    i = 0
    while i < len(line):
        c = line[i]
        if quote is None and c == '#':
            break
        if c == '\\' and quote != "'":
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        i += 1
    return quote


def _ps_without_literal_heredocs(command):
    # Only quoted delimiters have inert shell bodies. Unquoted bodies expand
    # command substitutions and remain visible to the gate.
    lines = command.splitlines(keepends=True)
    output, pending = [], []
    quote = None
    for line in lines:
        if pending:
            delimiter, strip_tabs = pending[0]
            check = line.rstrip('\r\n')
            if strip_tabs:
                check = check.lstrip('\t')
            if check == delimiter:
                pending.pop(0)
            output.append('\n')
            continue
        output.append(line)
        inside_quote = quote is not None
        quote = _ps_shell_quote_state(line, quote)
        # Mask only doc-writing cat/tee bodies. Shell consumers execute their
        # stdin, and a quoted << inside a string is not a heredoc operator.
        if inside_quote or not re.match(r'^\s*(?:cat|tee)\b', line) or re.search(r'[|;&]', line):
            continue
        pending.extend(_ps_literal_heredoc_directives(line))
        if pending:
            output[-1] = _ps_remove_heredoc_operators(line)

    return ''.join(output)


# Only identity-style members keep the payload text (`.Trim()`, `.ToString()`,
# iwr's `.Content`). Other string methods (.Replace, .Substring, indexing) are
# obfuscation transforms and are a separate follow-up; non-string members
# (.Length, .Contains(), .name) never carry taint.
_PS_COPY_METHODS = frozenset(('tostring', 'trim', 'trimstart', 'trimend', 'clone', 'content', 'rawcontent'))
# Casts that produce a plain value (Boolean, number, date, ...) and so drop the
# payload text. Every other cast, including unknown ones, keeps the text; array
# casts also make the value a collection.
_PS_SANITIZING_CASTS = frozenset((
    'bool', 'boolean', 'system.boolean', 'int', 'int16', 'int32', 'int64', 'uint16', 'uint32', 'uint64',
    'long', 'ulong', 'short', 'ushort', 'byte', 'sbyte', 'double', 'float', 'single', 'decimal',
    'system.int16', 'system.int32', 'system.int64', 'system.uint16', 'system.uint32', 'system.uint64',
    'system.double', 'system.single', 'system.decimal', 'system.byte', 'system.sbyte',
    'char', 'system.char', 'datetime', 'system.datetime', 'timespan', 'system.timespan',
    'guid', 'system.guid', 'version', 'system.version'))
_PS_ARRAY_CASTS = frozenset(('array', 'system.array'))

_PS_INTERPOLATED = re.compile(r'(?<!`)\$(?:\{([^}]*)\}|([\w:]+))')


_PS_CAST_ONE = r'\[((?:[^\[\]]|\[[^\[\]]*\])*)\]'
_PS_CAST = re.compile(r'^(?:' + _PS_CAST_ONE + r')+')


def _ps_cast_info(value):
    """(drops the text, collection shape: True, False or None for unchanged) for a word's leading [type] casts."""
    match = _PS_CAST.match(value)
    names = [c.strip().lower() for c in re.findall(_PS_CAST_ONE, match.group(0))] if match else []
    if not names:
        return False, None
    sanitizes = any(n in _PS_SANITIZING_CASTS for n in names)
    # The left-most cast that sets a shape (applied last) decides it: an array
    # cast makes a collection, [string] joins into one string, others keep it.
    for n in names:
        if n.endswith('[]') or n in _PS_ARRAY_CASTS:
            return sanitizes, True
        if n in ('string', 'system.string'):
            return sanitizes, False
    return sanitizes, None


def _ps_text_cast(value):
    """True when the leading [type] casts on a word keep the payload text (or there are none)."""
    return not _ps_cast_info(value)[0]


def _ps_assignments(tokens, start, stop):
    """Find `$a = $b = <rhs>` (also `[type]$a`, `$a += <rhs>`) in tokens[start:stop].

    Candidates start at the segment start and after every `(` or `{`, so
    `($b=$a)` and `if (...) { $b=$a }` are seen. The RHS runs to the next `;`
    outside brackets, so a multiline `$b = (` ... `)` stays one value.
    Yields (targets, rhs tokens, append, index of the first target).
    """
    starts = [start] + [i + 1 for i in range(start, stop) if tokens[i] in (('symbol', '{'), ('symbol', '('))]
    for first in starts:
        targets, shapes, sans, append, i = [], [], [], False, first
        while i < stop:
            k, casts = i, []
            while k < stop and tokens[k][0] == 'word' and _PS_CAST.fullmatch(tokens[k][1]):
                casts.append(tokens[k][1])
                k += 1
            if casts and not (k < stop and tokens[k][0] == 'word' and tokens[k][1].startswith('$')):
                break  # a cast that is not applied to a target
            here = not all(_ps_text_cast(c) for c in casts)
            if k >= stop or tokens[k][0] != 'word':
                break
            here = here or not _ps_text_cast(tokens[k][1])
            name, j = _PS_CAST.sub('', tokens[k][1]), k + 1
            if not name.startswith('$'):
                break
            plus = name.endswith('+')
            if not plus and j < len(tokens) and tokens[j] == ('word', '+'):
                plus, j = True, j + 1
            if j >= len(tokens) or tokens[j] != ('symbol', '='):
                break
            sans.append(here)
            shapes.append(_ps_cast_info(''.join(casts) + tokens[k][1])[1])
            targets.append(name.rstrip('+'))
            append = append or plus
            i = j + 1
        if not targets or i >= len(tokens):
            continue
        depth, end = 0, i
        while end < len(tokens):
            kind, value = tokens[end]
            if kind == 'symbol' and value in ('(', '{'):
                depth += 1
            elif kind == 'symbol' and value in (')', '}'):
                depth -= 1
                if depth < 0 and first != start:
                    break
            elif tokens[end] == ('symbol', ';') and depth <= 0:
                break
            end += 1
        # `sans[n]` marks a target whose own cast stores a value, not the payload text.
        yield targets, tokens[i:end], append, first, shapes, sans


def _ps_brace_scopes(tokens):
    """Per token: innermost brace kind ('def', 'flow' or None) and the tuple of
    enclosing definition-brace indexes. A `{` that follows `function name`,
    `=` (script block literal) or `@` (hashtable) only defines code or data;
    other braces (if/foreach/try/...) run in place.
    """
    kinds, chains, stack, chain = [], [], [], ()
    for i, token in enumerate(tokens):
        kinds.append(stack[-1][1] if stack else None)
        chains.append(chain)
        if token == ('symbol', '{'):
            p, definition = i - 1, False
            if p >= 0 and tokens[p] == ('symbol', ')'):
                depth = 0
                while p >= 0:
                    if tokens[p] == ('symbol', ')'):
                        depth += 1
                    elif tokens[p] == ('symbol', '('):
                        depth -= 1
                        if depth == 0:
                            break
                    p -= 1
                p -= 1
                definition = p >= 1 and tokens[p - 1][1] in ('function', 'filter', 'workflow')
            elif p >= 0:
                definition = (tokens[p] == ('symbol', '=') or tokens[p][1].endswith('@')
                              or (p >= 1 and tokens[p - 1][1] in ('function', 'filter', 'workflow')))
            stack.append((i, 'def' if definition else 'flow'))
            if definition:
                chain = chain + (i,)
        elif token == ('symbol', '}') and stack:
            index, kind = stack.pop()
            if kind == 'def':
                chain = chain[:-1]
    return kinds, chains


def _ps_copy_source(value):
    """Variable named by `$a`, `[string]$a`, `$a.Trim` or `$a.Content` words."""
    if _ps_cast_info(value)[0]:
        return None
    value = _PS_CAST.sub('', value)
    match = re.match(r'\$[\w:]+', value)
    if not match:
        return None
    rest = value[match.end():]
    if rest.strip('+') and not (rest.startswith('.') and rest[1:] in _PS_COPY_METHODS):
        return None
    return match.group(0)


_PS_RESULT_OP = re.compile(r'-[ci]?(?:contains|notcontains|in|notin|is|isnot|and|or|xor|not)$|-(?:band|bor|bxor|bnot|shl|shr)$')
_PS_FILTER_OP = re.compile(r'-[ci]?(?:eq|ne|gt|lt|ge|le|like|notlike|match|notmatch)$')


def _ps_group_end(tokens, i):
    """Index of the bracket closing tokens[i], or len(tokens) when unbalanced."""
    depth = 0
    for j in range(i, len(tokens)):
        if tokens[j][0] == 'symbol' and tokens[j][1] in ('(', '{'):
            depth += 1
        elif tokens[j][0] == 'symbol' and tokens[j][1] in (')', '}'):
            depth -= 1
            if depth == 0:
                return j
    return len(tokens)


def _ps_top_level(tokens, test):
    """First index of a token at bracket depth 0 for which test(token) holds."""
    i = 0
    while i < len(tokens):
        if tokens[i][0] == 'symbol' and tokens[i][1] in ('(', '{'):
            i = _ps_group_end(tokens, i)
        elif test(tokens[i]):
            return i
        i += 1
    return -1


class _PsView:
    """Read-only union of name sets (top level plus enclosing function bodies).

    Sets are shared, never copied, so memory stays flat however many
    assignments a body has.
    """
    __slots__ = ('sets',)

    def __init__(self, sets):
        self.sets = sets

    def __contains__(self, name):
        return any(name in names for names in self.sets)

    def __bool__(self):
        return any(self.sets)

    def isdisjoint(self, names):
        names = list(names)
        return all(group.isdisjoint(names) for group in self.sets)


def _ps_expr(tokens, remote_vars, collection_vars, dialect='shell', depth=0):
    """Judge an expression by its result: (may carry payload text, collection-shaped).

    Scalar Boolean/numeric results (-and, -or, -not, -contains, -in, -is, a
    scalar -eq/-like/-match, [bool]/[int] casts) are not payload. Comparison
    operators on a collection FILTER it and keep the text, and concatenation
    or any other operator keeps text from any operand. Collection shape is
    tracked even for clean values, because text appended later joins it.
    Interpolation always yields a string. Unsure means tainted.
    """
    if depth > 16:
        # Too deeply nested to judge cheaply: assume any mention keeps the text.
        return _ps_derives_remote(tokens, remote_vars), True

    def is_op(pattern):
        return lambda token: token[0] == 'word' and pattern.fullmatch(token[1]) is not None
    if _ps_top_level(tokens, is_op(_PS_RESULT_OP)) >= 0:
        return False, False
    # `x -as A -as B` runs left to right, so the last -as converts last.
    as_at, offset = -1, 0
    while True:
        found = _ps_top_level(tokens[offset:], lambda t: t == ('word', '-as'))
        if found < 0:
            break
        as_at = offset + found
        offset = as_at + 1
    if as_at >= 0 and as_at + 1 < len(tokens) and tokens[as_at + 1][0] == 'word' and _PS_CAST.fullmatch(tokens[as_at + 1][1]):
        sanitizes, collection = _ps_cast_info(tokens[as_at + 1][1])
        if sanitizes:
            return False, False
        tainted, left_collection = _ps_expr(tokens[:as_at], remote_vars, collection_vars, dialect, depth + 1)
        return tainted, left_collection if collection is None else collection
    cmp_at = _ps_top_level(tokens, is_op(_PS_FILTER_OP))
    if cmp_at >= 0:
        tainted, collection = _ps_expr(tokens[:cmp_at], remote_vars, collection_vars, dialect, depth + 1)
        return (tainted and collection), collection
    tainted = collection = False
    pending = None  # (sanitizes, shape) of a standalone cast waiting for its operand
    i = 0
    while i < len(tokens):
        kind, value = tokens[i]
        if kind == 'word' and _PS_CAST.fullmatch(value):
            info = _ps_cast_info(value)
            if pending is not None:
                # Contiguous casts compose: any sanitizer drops the text and the
                # left-most (applied last) cast that sets a shape decides it.
                info = (pending[0] or info[0], pending[1] if pending[1] is not None else info[1])
            pending = info
            i += 1
            continue
        sanitized = pending is not None and pending[0]
        shape = pending[1] if pending is not None else None
        if kind == 'symbol' and value in ('(', '{'):
            end = _ps_group_end(tokens, i)
            inner_t, inner_c = _ps_expr(tokens[i + 1:end], remote_vars, collection_vars, dialect, depth + 1)
            if not sanitized:
                tainted = tainted or inner_t
                collection = collection or (inner_c if shape is None else shape)
            pending = None
            i = end + 1
            continue
        if kind == 'symbol' and value == ',' or (kind == 'word' and value in ('@', '-split', '-csplit', '-isplit')):
            collection = True
        elif kind == 'word':
            sources = [_ps_copy_source(part) for part in value.split('+') if part]
            fused_sanitizes, fused_shape = _ps_cast_info(value)
            if not sanitized and not fused_sanitizes:
                if any(s in remote_vars for s in sources):
                    tainted = True
                explicit = shape if shape is not None else fused_shape
                if explicit is True or (explicit is None and any(s in collection_vars for s in sources)):
                    collection = True
            if not value.startswith('-') and value != '+':
                pending = None
        elif kind == 'double':
            if not sanitized:
                text = value
                for expr in _ps_subexpressions(value):
                    text = text.replace('$(' + expr + ')', '', 1)
                    inner_t, _ = _ps_expr(_ps_tokens(expr, dialect), remote_vars, collection_vars, dialect, depth + 1)
                    tainted = tainted or inner_t
                names = {'$' + (m[0] or m[1]).lower() for m in _PS_INTERPOLATED.findall(text)}
                if not remote_vars.isdisjoint(names):
                    tainted = True
            pending = None
        i += 1
    return tainted, collection


def _ps_derives_remote(tokens, remote_vars):
    """True when a value is built from a remote-fetched variable.

    Covers plain copies ($b=$a, ($a), [string]$a, "$a", $a.Trim()), appends
    and concatenation. Unrelated members ($a.Length) stay untainted.
    """
    if not remote_vars:
        return False
    for kind, value in tokens:
        if kind == 'word' and any(_ps_copy_source(part) in remote_vars for part in value.split('+') if part):
            return True
        if kind == 'double' and not remote_vars.isdisjoint('$' + (m[0] or m[1]).lower() for m in _PS_INTERPOLATED.findall(value)):
            return True
    return False


def detects_powershell_execution(command, depth=0, heredocs_masked=False, dialect='shell'):
    """Block coupled remote fetch+execution and opaque EncodedCommand calls.

    This intentionally does not claim general PowerShell deobfuscation or
    dataflow analysis. Recursion is limited to quoted executable code bodies.
    """
    if not command or depth > 8:
        return False
    # Reject non-candidates before allocating the lexical view on the hot path.
    if not _PS_HINT.search(command.replace('`', '')):
        return False
    if not heredocs_masked and dialect == 'shell':
        command = _ps_without_literal_heredocs(command)
    tokens = _ps_tokens(command, dialect)
    # Inspect only the balanced executable subexpression, not trailing prose.
    for kind, value in tokens:
        if kind == 'double':
            for expression in _ps_subexpressions(value):
                if detects_powershell_execution(expression, depth + 1, dialect=dialect):
                    return True
    # Cheap bracket pairing prevents quadratic rescans of nested expressions.
    ends, stack = {}, []
    for i, (kind, value) in enumerate(tokens):
        if kind == 'symbol' and value == '(':
            stack.append(i)
        elif kind == 'symbol' and value == ')' and stack:
            ends[stack.pop()] = i
    remote_vars, local_vars = set(), {}
    collection_vars, local_shapes = set(), {}
    scoped = any(token == ('symbol', '{') for token in tokens)
    kinds, chains = _ps_brace_scopes(tokens) if scoped else ([], [])

    def view(i, base, locals_):
        """Names seen at token i: top level plus enclosing definitions (no copies)."""
        if not scoped or not chains[i] or not locals_:
            return base
        return _PsView([base] + [locals_[owner] for owner in chains[i] if owner in locals_])

    def visible(i):
        """Remote variables seen at token i."""
        return view(i, remote_vars, local_vars)

    start = 0
    for stop in range(len(tokens) + 1):
        if stop < len(tokens) and tokens[stop] != ('symbol', ';'):
            continue
        for targets, rhs, append, at, target_shapes, target_sans in _ps_assignments(tokens, start, stop):
            seen = visible(at)
            expr_tainted, expr_collection = _ps_expr(rhs, seen, view(at, collection_vars, local_shapes), dialect)
            tainted = (_ps_fetches(rhs)
                       or any(kind == 'double' and any(_ps_fetches(_ps_tokens(expr, dialect)) for expr in _ps_subexpressions(value)) for kind, value in rhs)
                       or expr_tainted)
            # Writes inside a brace never clear outer taint: an if body may not
            # run and a function or script block may never be called.
            if not scoped or kinds[at] is None:
                owner, shapes, clears = remote_vars, collection_vars, not append and at == start
            elif not chains[at]:
                owner, shapes, clears = remote_vars, collection_vars, False
            else:
                owner = local_vars.setdefault(chains[at][-1], set())
                shapes = local_shapes.setdefault(chains[at][-1], set())
                clears = kinds[at] == 'def' and not append and at == start
            # Collection shape is tracked for clean values too (text appended
            # later joins it); `+=` keeps the old shape.
            # A typed target converts the value: [string]$b = @($a) is a string.
            # Chained targets convert right to left: each target casts the value
            # the target to its right received. A sanitizing cast on one target
            # therefore only clears that target and the ones outside it.
            as_collection, shape = [], expr_collection
            for t, kind in reversed(list(zip(targets, target_shapes))):
                shape = shape if kind is None else kind
                if shape:
                    as_collection.append(t)
            clean = {t for n, t in enumerate(targets) if any(target_sans[n:])}
            as_scalar = [t for t in targets if t not in as_collection]
            if as_collection:
                shapes.update(as_collection)
            if clears and as_scalar:
                shapes.difference_update(as_scalar)
            if tainted:
                owner.update(t for t in targets if t not in clean)
            if clears:
                owner.difference_update(t for t in targets if t in clean or not tainted)
        for j in range(start, stop):
            rv = visible(j)
            name = _ps_name(tokens, j)
            positioned = j == start or tokens[j - 1][1] in ('(', '|', '{', '&', '.', 'sudo', 'env', '-command', '-c', '/c', '/command', '=')
            if (name in _PS_HOST or name in _PS_SHELL) and positioned:
                for k in range(j + 1, stop):
                    kind, value = tokens[k]
                    if kind == 'symbol' and value in ('|', ')', '}'):
                        break
                    if kind == 'word' and value in ('-f', '-file'):
                        break
                    if name in _PS_HOST and kind == 'word' and value.lstrip('-/').split(':', 1)[0] in _PS_ENCODED and value.startswith(('-', '/')):
                        return True
                    if kind == 'word' and value in ('-c', '-command', '-commandwithargs', '/c', '/command', '/commandwithargs'):
                        if k + 1 < stop and tokens[k + 1][0] == 'word' and _ps_derives_remote(tokens[k + 1:k + 2], rv):
                            return True
                        if k + 1 < stop and tokens[k + 1][0] in ('string', 'double'):
                            if detects_powershell_execution(tokens[k + 1][1], depth + 1, dialect='powershell' if name in _PS_HOST else 'shell'):
                                return True
                        break
                if _ps_pipe_before(tokens, j, start) and _ps_fetches(tokens[start:j]):
                    return True
            executor = name in _PS_EXEC and positioned
            method = tokens[j][0] == 'word' and ((tokens[j][1].startswith('$') and '.invokescript' in tokens[j][1]) or (tokens[j][1].startswith('.invokescript') and j > start and tokens[j - 1][1] == ')') or '[scriptblock]::create' == tokens[j][1])
            if method and (j + 1 >= stop or tokens[j + 1] != ('symbol', '(')):
                continue
            if method and '[scriptblock]::create' == tokens[j][1]:
                # Creating a block is inert until invoked with & or .Invoke().
                k = j + 1
                end = ends.get(k, stop)
                before = j - 1
                while before >= start and tokens[before][1] == '(':
                    before -= 1
                invoked = before >= start and tokens[before] in (('symbol', '&'), ('word', '.'))
                after = end + 1
                while after < stop and tokens[after][1] == ')':
                    after += 1
                invoked = invoked or (after < stop and tokens[after][1].startswith('.invoke'))
                if not invoked:
                    continue
            if not (executor or method):
                continue
            if _ps_pipe_before(tokens, j, start):
                upstream = tokens[start:j]
                if _ps_fetches(upstream) or (executor and _ps_derives_remote(upstream, rv)):
                    return True
                if executor and any(kind in ('string', 'double') and detects_powershell_execution(value, depth + 1, dialect='powershell') for kind, value in upstream):
                    return True
            k = j + 1
            # Execution cmdlet flags can precede the expression.
            while k < stop and tokens[k][0] == 'word' and tokens[k][1].startswith('-'):
                k += 1
                if k < stop and tokens[k][0] == 'word' and not tokens[k][1].startswith('$'):
                    k += 1
            if k < stop and tokens[k] == ('symbol', '('):
                end = ends.get(k, stop)
                body = tokens[k + 1:end]
            else:
                body = tokens[k:stop]
            if _ps_fetches(body) or _ps_derives_remote(body, rv):
                return True
            if executor and any(value == '$_' for kind, value in body) and (_ps_fetches(tokens[start:j]) or _ps_derives_remote(tokens[start:j], rv)):
                return True
            if executor and body and body[0][0] == 'double':
                if any(_ps_fetches(_ps_tokens(expr, dialect)) or _ps_derives_remote(_ps_tokens(expr, dialect), rv) for expr in _ps_subexpressions(body[0][1])) or _ps_derives_remote(body[:1], rv):
                    return True
            if executor and body and body[0][0] in ('string', 'double'):
                if detects_powershell_execution(body[0][1], depth + 1, dialect='powershell'):
                    return True
        start = stop + 1
    return False


def detect_install_command(command):
    """Match command against install patterns.
    Returns (pattern_type, match_obj) or (None, None)."""
    if not command:
        return None, None
    executable = _ps_without_literal_heredocs(command)
    if detects_powershell_execution(executable, heredocs_masked=True) or (PIPE_TO_SHELL.search(executable) and not is_inert_quote_carrier(executable)):
        return 'pipe_to_shell', None
    for pattern, ptype in INSTALL_PATTERNS:
        m = pattern.search(command)
        if m:
            return ptype, m
    return None, None


def extract_package_names(pattern_type, match):
    """Extract package names from install command match."""
    if not match:
        return []
    if pattern_type not in ('pip_install', 'npm_install', 'yarn_add', 'gem_install',
                            'cargo_install', 'go_install', 'brew_install', 'openclaw_install',
                            'uv_install', 'bun_install', 'pnpm_install'):
        return []
    raw = match.group(1)
    cleaned = INSTALL_FLAGS.sub('', raw).strip()
    names = [n.strip() for n in cleaned.split() if n.strip() and not n.startswith('-')]
    if pattern_type in ('pip_install', 'uv_install'):
        names = [re.split(r'[>=<!\[\];@]', n)[0] for n in names]
    return names


# npm-family installers pin versions as `name@version`, which the pip/uv strip
# in extract_package_names() deliberately leaves untouched. These are the
# pattern types whose tokens get the split treatment below.
NPM_FAMILY_INSTALLS = ('npm_install', 'yarn_add', 'pnpm_install', 'bun_install')


def split_npm_name_version(token):
    """Split an npm-family install token into (base_name, version).

    The version separator `@` collides with the leading `@` of a scoped name,
    so split on the LAST `@` and only when it is not that scope marker:
      keyv@6.0.0        -> ('keyv', '6.0.0')
      @scope/pkg@1.2.3  -> ('@scope/pkg', '1.2.3')
      @scope/pkg        -> ('@scope/pkg', None)
      keyv              -> ('keyv', None)

    Also resolves the install forms that used to smuggle a malicious package
    past the name/version checks:
      npm alias   local@npm:keyv@6.0.0        -> ('keyv', '6.0.0')
      tarball URL https://reg/keyv/-/keyv-6.0.0.tgz -> ('keyv', '6.0.0')
      git URL     git+https://gh/x/keyv.git   -> ('keyv', None)
    """
    # npm alias: <localname>@npm:<realname>@<version> — resolve to the REAL pkg.
    alias = re.search(r'@npm:(.+)$', token)
    if alias:
        token = alias.group(1)  # realname[@version]

    # URL / git / tarball forms: extract the package name (and version if a
    # tarball encodes one). check_ioc_packages compares whole tokens, so a URL
    # never matches a name — pull the name out so the IOC checks see it.
    if re.match(r'(?i)^(https?://|git\+|git://|ssh://|file:)', token):
        # scoped tarball: .../@scope/name/-/name-1.2.3.tgz -> ('@scope/name', '1.2.3')
        scoped = re.search(
            r'/(@[^/@\s]+/[^/@\s]+)/-/[^/@\s]+-(\d+\.\d+\.\d+[^/\s]*)\.(?:tgz|tar\.gz)$', token)
        if scoped:
            return scoped.group(1), scoped.group(2)
        # unscoped tarball: .../<name>-<version>.tgz
        tgz = re.search(r'/([^/@\s]+)-(\d+\.\d+\.\d+[^/\s]*)\.(?:tgz|tar\.gz)$', token)
        if tgz:
            return tgz.group(1), tgz.group(2)
        # git repo: .../<name>(.git)
        git = re.search(r'/([^/@\s]+?)(?:\.git)?(?:#.*)?$', token)
        if git:
            return git.group(1), None
        return token, None

    idx = token.rfind('@')
    if idx <= 0:
        return token, None
    version = token[idx + 1:]
    return token[:idx], (version or None)


def _semver_tuple(v):
    """Best-effort (major, minor, patch) from a version string. Non-numeric
    trailing segments (prerelease/build) are ignored for comparison."""
    nums = []
    for part in re.split(r'[.\-+]', v.strip()):
        if part.isdigit():
            nums.append(int(part))
        else:
            break
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def _spec_could_match(spec, concrete):
    """Could the npm version SPEC (^1.2.0, ~1.2, >=1.0.0, 1.x, 1.2.3, =1.2.3)
    resolve to the concrete COMPROMISED version? The offline gate cannot query
    the registry, so this is deliberately CONSERVATIVE: it returns True whenever
    a range could include the compromised version (better to over-block one
    package than wave a worm through), but False for a clean exact version and
    for dist-tags like `latest`/`next`, which point at the maintainer's current
    — now-fixed — release and must stay installable.
    """
    spec = (spec or '').strip()
    if not spec:
        return False
    if spec.startswith('='):
        spec = spec[1:].strip()
    # A leading `v` on a numeric version (v6.0.0, =v6.0.0) is a VERSION, not a
    # dist-tag — strip it before the dist-tag test below, or `keyv@v6.0.0` (which
    # npm installs as exactly 6.0.0) would be waved through as if it were `latest`.
    spec = re.sub(r'^v(?=\d)', '', spec)
    # dist-tag / non-semver (latest, next, a branch) -> resolves to fixed release
    if re.match(r'^[A-Za-z]', spec):
        return False
    c = _semver_tuple(concrete)
    low = spec.lower().replace('*', 'x')
    # x-ranges: 6.x, 6.*, 6, 6.0.x
    if 'x' in low or re.match(r'^\d+(?:\.\d+)?$', spec):
        parts = low.split('.')
        for i, part in enumerate(parts):
            if part in ('x', ''):
                break
            if not part.isdigit() or (i < len(c) and int(part) != c[i]):
                return False
        return True
    m = re.match(r'^(\^|~|>=|<=|>|<)?\s*v?(\d+(?:\.\d+){0,2}[^\s]*)$', spec)
    if not m:
        return True  # unparseable range -> conservative block
    op = m.group(1) or '='
    t = _semver_tuple(m.group(2))
    if op == '=':
        return c == t
    if op == '^':  # >= t, < next-major (special-cased for 0.x per npm semantics)
        if t[0] > 0:
            return c >= t and c[0] == t[0]
        if t[1] > 0:
            return c >= t and c[0] == 0 and c[1] == t[1]
        return c == t
    if op == '~':  # >= t, < next-minor
        return c >= t and c[0] == t[0] and c[1] == t[1]
    if op == '>=':
        return c >= t
    if op == '>':
        return c > t
    if op == '<=':
        return c <= t
    if op == '<':
        return c < t
    return True


def check_ioc_pinned_versions(pattern_type, package_names, iocs=None):
    """Check npm-family `name@version` tokens against the IOC database.

    Complements check_ioc_packages(), which compares whole tokens against the
    name sets: a pinned token like `rimarf@1.0.0` matches no name, so it used
    to be approved while bare `rimarf` was blocked. Blocks when either the base
    name is a known-malicious package, or the exact pinned version appears in
    the shipped compromised_versions map. Returns a list of description strings.

    `iocs` may be passed pre-loaded so main() loads the IOC set once instead of
    each checker paying the disk+verify cost (the npm path calls both). When
    None, loads on its own (standalone/test use). Fail-open on load failure.
    """
    if pattern_type not in NPM_FAMILY_INSTALLS:
        return []
    if iocs is None:
        try:
            import ioc_manager
            iocs = ioc_manager.get_iocs()
        except (ImportError, AttributeError, KeyError, TypeError):
            return []

    all_malicious = iocs.get('malicious_npm', set()) | iocs.get('malicious_pypi', set())
    compromised_versions = iocs.get('compromised_versions', {})

    blocked = []
    for pkg in package_names:
        base, version = split_npm_name_version(pkg)
        base_lower = base.lower()
        # Check the RESOLVED base name first — for alias (foo@npm:rimarf) and git/URL
        # forms the base is malicious even with no pinned version, and the raw token
        # (which check_ioc_packages compares) never equals the resolved base. Must
        # run before the version-less skip below or these smuggle forms escape.
        if base_lower in all_malicious:
            label = f"{base}@{version}" if version is not None else base
            blocked.append(f"{label} (known-malicious package, any version)")
            continue
        if version is None:
            continue  # bare in-registry names are covered by check_ioc_packages()
        pkg_bad = compromised_versions.get(base_lower, {})
        if not pkg_bad:
            continue
        # exact pin
        if version in pkg_bad:
            blocked.append(f"{base}@{version} (compromised version, campaign: {pkg_bad[version]})")
            continue
        # range / x-range / comparator spec that could resolve to a compromised
        # version (e.g. keyv@^6.0.0 resolving to the bad 6.0.0). Conservative.
        for bad_ver, campaign in pkg_bad.items():
            if _spec_could_match(version, bad_ver):
                blocked.append(
                    f"{base}@{version} (version range may resolve to compromised "
                    f"{bad_ver}, campaign: {campaign})"
                )
                break
    return blocked


def check_ioc_packages(package_names, iocs=None):
    """Check package names against IOC database. Returns list of malicious names.

    Fail-open: if ioc_manager cannot be loaded at all, returns [] (approve).
    When the remote-feed cache is stale or absent, approves but emits a WARNING
    to stderr so the operator knows threat intelligence is degraded.

    `iocs` may be passed pre-loaded so main() loads the IOC set once (the npm
    path runs both checkers); when None it loads on its own.
    """
    if iocs is None:
        try:
            import ioc_manager
            iocs = ioc_manager.get_iocs()
        except (ImportError, AttributeError, KeyError, TypeError):
            return []

    # Warn when operating without a fresh remote IOC feed. We still approve
    # (fail-open) to avoid blocking legitimate work, but the degraded flag
    # tells the operator to run `ioc_manager.py --update` to refresh.
    if iocs.get('_ioc_degraded'):
        print(
            "[repo-forensics] WARNING: IOC database unavailable, operating without "
            "threat intelligence. Remote feed cache is absent or stale. Run "
            "`python3 ioc_manager.py --update` to refresh. Only hardcoded IOCs "
            "are active; recently-discovered malicious packages may not be detected.",
            file=sys.stderr,
        )

    malicious_npm = iocs.get('malicious_npm', set())
    malicious_pypi = iocs.get('malicious_pypi', set())
    all_malicious = malicious_npm | malicious_pypi

    blocked = []
    for pkg in package_names:
        if pkg.lower() in all_malicious:
            blocked.append(pkg)
    return blocked


# --- Registry risk (the `ask` tier) -----------------------------------------
#
# An install command pointed at a plaintext-HTTP index, or at a registry host
# that is not the ecosystem's canonical one, is the setup step for dependency
# confusion and for registry MITM. It is NOT block-worthy on its own: corporate
# mirrors and internal indexes are legitimate and common, which is exactly why
# forensics_core grades the file-based version of this signal MEDIUM rather
# than HIGH. On an adapter that has a third verdict (Cursor's `ask`) this is
# the signal that tier exists for: surface it to the human, do not hard-stop
# the agent. On the Claude shape, which has no `ask`, it degrades to an
# approve plus a stderr note so the operator still sees it.
_INDEX_FLAG = re.compile(
    r'--(?:index-url|extra-index-url|registry|repository|default-index)'
    r'(?:[=\s]+)(["\']?)([a-zA-Z][a-zA-Z0-9+.-]*://[^\s"\';|&]+)\1',
    re.IGNORECASE,
)

# Canonical first-party registry hosts per ecosystem. A redirect away from
# these is what makes the flag interesting.
CANONICAL_REGISTRY_HOSTS = frozenset({
    'pypi.org', 'www.pypi.org', 'files.pythonhosted.org', 'pypi.python.org',
    'registry.npmjs.org', 'registry.yarnpkg.com', 'npm.pkg.github.com',
    'rubygems.org', 'index.rubygems.org',
    'crates.io', 'static.crates.io', 'index.crates.io',
    'proxy.golang.org',
})


def _registry_host(url):
    """Host portion of a registry URL, lowercased, port and creds stripped."""
    rest = url.split('://', 1)[1] if '://' in url else url
    authority = re.split(r'[/?#]', rest, 1)[0]
    if '@' in authority:
        authority = authority.rsplit('@', 1)[1]
    if authority.startswith('['):  # IPv6 literal
        return authority.split(']', 1)[0].lstrip('[').lower()
    return authority.split(':', 1)[0].lower()


def detect_registry_risk(command):
    """Return a human-readable reason when an install command redirects its
    package index, else None. Never blocks — the caller maps this to `ask`."""
    if not command:
        return None
    for match in _INDEX_FLAG.finditer(command):
        url = match.group(2)
        scheme = url.split('://', 1)[0].lower()
        host = _registry_host(url)
        if scheme == 'http':
            return (f"package index redirected to a plaintext HTTP endpoint "
                    f"({url}) — credentials and package payloads are readable "
                    f"and rewritable in transit")
        if scheme in ('https', 'ftp', 'ftps') and host not in CANONICAL_REGISTRY_HOSTS:
            return (f"package index redirected to the non-canonical host "
                    f"'{host}' — legitimate for an internal mirror, and also "
                    f"how dependency-confusion attacks are staged")
    return None


def output_block(reason):
    """Output JSON that tells the agent to block the command.

    Claude Code reads the JSON decision on stdout; Kimi Code blocks on exit
    code 2 and surfaces stderr as the reason. Emit both so either host shows
    the operator why the command was blocked."""
    result = {
        "decision": "block",
        "reason": reason
    }
    print(json.dumps(result))
    print(reason, file=sys.stderr)
    sys.exit(2)


def output_approve():
    """Output empty JSON — command proceeds normally (Claude shape)."""
    print('{}')
    sys.exit(0)


BLOCK_PIPE_TO_SHELL = (
    "[repo-forensics] BLOCKED: Command executes downloaded content or uses "
    "an opaque PowerShell EncodedCommand. This bypasses package manager "
    "security checks and can execute arbitrary code."
)


def _block_packages_reason(pkg_list):
    return (
        f"[repo-forensics] BLOCKED: Known malicious package(s) detected: "
        f"{pkg_list}. These packages match the IOC database and should NOT "
        f"be installed. Remove them from the command and try again."
    )


def decide(command):
    """Run the detection gate on a shell command string.

    Returns (permission, message) with permission in {allow, ask, deny}. This
    is the ONE detection path; every adapter reaches the gate through here, so
    a verdict can never diverge between wires (PRD v3 G3/N1).
    """
    if not command:
        return hook_adapter.ALLOW, ""

    # Detect install/update pattern (also catches pipe-to-shell)
    pattern_type, match = detect_install_command(command)

    # Pipe-to-shell: instant block
    if pattern_type == 'pipe_to_shell':
        return hook_adapter.DENY, BLOCK_PIPE_TO_SHELL

    if not pattern_type:
        return hook_adapter.ALLOW, ""

    # Extract package names and check IOC
    package_names = extract_package_names(pattern_type, match)
    if not package_names:
        risk = detect_registry_risk(command)
        return (hook_adapter.ASK, _registry_ask_reason(risk)) if risk else (hook_adapter.ALLOW, "")

    # Load the IOC set ONCE and pass it to both checkers. The npm-family path
    # runs both check_ioc_packages() and check_ioc_pinned_versions(); without
    # sharing, get_iocs() (disk read + Ed25519 verify + set rebuild) ran twice.
    shared_iocs = None
    try:
        import ioc_manager
        shared_iocs = ioc_manager.get_iocs()
    except Exception:
        # Any failure loading IOCs must fail OPEN cleanly (the checkers re-load and
        # also fail open). Catch broadly so an unexpected error never crashes the
        # hook without emitting the approve JSON the PreToolUse contract requires.
        shared_iocs = None

    blocked_packages = check_ioc_packages(package_names, iocs=shared_iocs)
    if blocked_packages:
        return hook_adapter.DENY, _block_packages_reason(', '.join(blocked_packages))

    # Version-pinned npm-family tokens (`name@version`) never match the name
    # sets above, so re-check them by base name and exact pinned version.
    blocked_pinned = check_ioc_pinned_versions(pattern_type, package_names, iocs=shared_iocs)
    if blocked_pinned:
        return hook_adapter.DENY, _block_packages_reason(', '.join(blocked_pinned))

    # No IOC match. A redirected package index is the one remaining signal
    # worth a human's attention without stopping the agent.
    risk = detect_registry_risk(command)
    if risk:
        return hook_adapter.ASK, _registry_ask_reason(risk)

    return hook_adapter.ALLOW, ""


def _registry_ask_reason(risk):
    return (f"[repo-forensics] REVIEW: {risk}. Approve only if you recognise "
            f"this index as your own.")


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    adapter, adapter_error = hook_adapter.normalize_adapter(
        hook_adapter.adapter_from_argv(argv))
    if adapter_error:
        # A typo in our own installed hook command must not brick every shell
        # command, so this warns and runs the fail-open adapter. Anyone who can
        # edit the hook command line could equally have deleted the hook.
        print(f"[repo-forensics] WARNING: {adapter_error}; falling back to "
              f"'{hook_adapter.ADAPTER_CLAUDE}'", file=sys.stderr)

    fail_closed = adapter in hook_adapter.FAIL_CLOSED_ADAPTERS

    def emit(permission, message="", note=None):
        sys.exit(hook_adapter.emit_verdict(
            adapter, permission, user_message=message, agent_message=message,
            stderr_note=note))

    # (1) Blanket disable. Documented as the last resort precisely because it
    # also switches off the fail-closed denials below.
    switch = hook_adapter.kill_switch_state()
    if switch == "unsafe":
        emit(hook_adapter.ALLOW, "", note=(
            f"[repo-forensics] WARNING: {hook_adapter.KILL_SWITCH_ENV}="
            f"{hook_adapter.KILL_SWITCH_UNSAFE} — the pre-execution gate is FULLY "
            f"disabled, including tamper and schema-drift detection. Nothing is "
            f"being checked before this command runs."))

    # (2) Install-manifest integrity (R8). Checked BEFORE the allow branch and
    # before the ordinary kill switch: a scanner that the manifest says should
    # be here but is not is tampering, not a missing optional feature.
    root = hook_adapter.plugin_root()
    integrity, integrity_detail = hook_adapter.check_install_integrity(root)
    if integrity == hook_adapter.INTEGRITY_TAMPER:
        note = (f"[repo-forensics] TAMPER: {integrity_detail}. Refusing to "
                f"approve while the install is in an inconsistent state; "
                f"reinstall repo-forensics or unset {hook_adapter.PLUGIN_ROOT_ENV}.")
        if fail_closed:
            emit(hook_adapter.DENY, note, note=note)
        # Fail-open adapters keep their shipped behaviour (a PreToolUse hook
        # that starts denying on upgrade would be a breaking change), but the
        # operator is told loudly.
        print(note, file=sys.stderr)

    # (3) Envelope. Drift denies on a failClosed wire, approves on the others.
    request = hook_adapter.parse_request(adapter, hook_adapter.read_stdin())
    if request.drift:
        note = (f"[repo-forensics] SCHEMA DRIFT: {request.drift}. A hook that "
                f"cannot read its own input cannot vouch for the command.")
        if fail_closed:
            emit(hook_adapter.DENY, note, note=note)
        emit(hook_adapter.ALLOW, "")

    # (4) Genuinely not installed at this root: allow, but never silently.
    if integrity == hook_adapter.INTEGRITY_UNCLAIMED:
        emit(hook_adapter.ALLOW, "", note=(
            f"[repo-forensics] WARNING: {integrity_detail}. The pre-execution "
            f"gate is NOT protecting this command."))

    # (5) Ordinary kill switch: detection off, integrity still enforced.
    if switch == "detection":
        emit(hook_adapter.ALLOW, "", note=(
            f"[repo-forensics] WARNING: {hook_adapter.KILL_SWITCH_ENV}="
            f"{hook_adapter.KILL_SWITCH_OFF} — malicious-package and "
            f"pipe-to-shell detection is disabled for this command. "
            f"Precedence: {hook_adapter.PRECEDENCE_DOC}."))

    # (6) Detection.
    permission, message = decide(request.command)
    emit(permission, message)


if __name__ == '__main__':
    main()
