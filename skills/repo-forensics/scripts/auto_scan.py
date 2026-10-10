#!/usr/bin/env python3
"""
auto_scan.py - post-execution hook handler for repo-forensics v2.
Detects install/clone commands in shell tool calls and auto-triggers security scans.

Runs as a Claude Code / Codex / OpenClaw PostToolUse hook and as a Cursor
afterShellExecution hook (`--adapter cursor`). Reads JSON from stdin, writes its
report to stdout. Fast path (<10ms for non-matching commands).

OBSERVE-ONLY on every adapter. This is where the deep 28-scanner audit runs, so
it deliberately never gates execution — the blocking decision belongs to
pre_scan.py, which is the only thing fast enough to sit in front of the agent's
inner loop (PRD v3 R2).

Created by Alex Greenshpun
"""

import json
import os
import re
import sys
# subprocess and concurrent.futures are lazy-imported in run_scanner/run_targeted_scan
# to keep the no-match fast path under 10ms

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

import hook_adapter  # noqa: E402  (leaf module, stdlib-only)

# --- Install/Clone Pattern Detection ---

# Optional package-manager flags that can sit between the tool name and its
# subcommand, e.g. `pnpm -r add x`, `pnpm --filter web add x`,
# `uv --project /p add x`. Each unit is one -flag (whose first char after the
# leading dash(es) is a non-dash — this makes dash runs fail fast and avoids
# ReDoS) plus an OPTIONAL value token that must NOT itself be a subcommand
# keyword (the lookahead stops a flag value from swallowing `add`/`install`).
# Kept identical in pre_scan.py — update both.
_PM_FLAGS = (
    r'(?:-{1,2}[^-\s]\S*'
    r'(?:\s+(?!(?:install|i|add|update|sync|pip|tool|remove|run)\b)[^-\s]\S*)?'
    r'\s+)*'
)

INSTALL_PATTERNS = [
    # git clone
    (re.compile(r'git\s+clone\s+(?:--[^\s]+\s+)*(?:https?://|git@)([^\s]+)(?:\s+([^\s]+))?'), 'git_clone'),
    # git pull (update — scans CWD after pull)
    (re.compile(r'git\s+pull(?:\s|$)'), 'git_pull'),
    # uv add / uv pip install / uv tool install — must precede pip: patterns are
    # unanchored, so 'uv pip install x' substring-matches the pip entry.
    # _PM_FLAGS allows global options before the subcommand (`uv --project p add x`).
    (re.compile(r'uv\s+' + _PM_FLAGS + r'(?:add|pip\s+install|tool\s+install)\s+(.+)'), 'uv_install'),
    # uv sync (lockfile install — scans CWD after sync, like git_pull)
    (re.compile(r'uv\s+sync(?:\s|$)'), 'uv_sync'),
    # pip install (with package names) — also catches --upgrade
    (re.compile(r'pip3?\s+install\s+(.+)'), 'pip_install'),
    # pnpm install/add/update — must precede npm: 'pnpm install x'
    # substring-matches the npm entry. _PM_FLAGS covers monorepo/workspace
    # forms: `pnpm -r add x`, `pnpm --filter web add x`.
    (re.compile(r'pnpm\s+' + _PM_FLAGS + r'(?:install|i|add|update)\s+(.+)'), 'pnpm_install'),
    # bun install/add/update
    (re.compile(r'bun\s+' + _PM_FLAGS + r'(?:install|i|add|update)\s+(.+)'), 'bun_install'),
    # npm install (with package names)
    (re.compile(r'npm\s+(?:install|i)\s+(.+)'), 'npm_install'),
    # npm update (missed update commands)
    (re.compile(r'npm\s+update\s+(.+)'), 'npm_install'),
    # Bare lockfile installs (no package args) — scan CWD like uv_sync/git_pull.
    # MUST come after the with-args npm/pnpm/bun entries above so
    # 'pnpm install express' still classifies as pnpm_install. Anchored to
    # end-of-command (optionally trailing flags) so it only fires for the
    # arg-less form: `npm install`, `npm ci`, `pnpm install --frozen-lockfile`,
    # `bun install`, and `cd app && pnpm install`.
    (re.compile(r'(?:npm|pnpm|bun)\s+(?:ci|install|i)(?:\s+--?\S+)*\s*$'), 'lockfile_install'),
    (re.compile(r'yarn(?:\s+install)?(?:\s+--?\S+)*\s*$'), 'lockfile_install'),
    # yarn add
    (re.compile(r'yarn\s+add\s+(.+)'), 'yarn_add'),
    # gem install
    (re.compile(r'gem\s+install\s+(.+)'), 'gem_install'),
    # gem update
    (re.compile(r'gem\s+update\s+(.+)'), 'gem_install'),
    # cargo install
    (re.compile(r'cargo\s+install\s+(.+)'), 'cargo_install'),
    # go get/install
    (re.compile(r'go\s+(?:get|install)\s+(.+)'), 'go_install'),
    # brew install
    (re.compile(r'brew\s+install\s+(.+)'), 'brew_install'),
    # brew upgrade
    (re.compile(r'brew\s+upgrade\s+(.+)'), 'brew_install'),
    # openclaw skills/plugins install or update
    (re.compile(r'openclaw\s+(?:skills|plugins)\s+(?:install|update)\s+(.+)'), 'openclaw_install'),
    # clawhub install
    (re.compile(r'clawhub\s+(?:install|publish)\s+(.+)'), 'openclaw_install'),
    # claude plugins install/update/add (CLI variants: `claude plugins install`,
    # `claude plugins:install`, `claude /plugins install`, `claude plugins enable`)
    (re.compile(r'claude\s+/?plugins[:\s]+(?:install|update|add|enable)\s+(.+)'), 'claude_plugin_install'),
]

# Pipe-to-shell patterns (instant CRITICAL)
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
    """Read and parse PostToolUse JSON from stdin."""
    try:
        raw = sys.stdin.read(1_048_576)  # 1MB max to prevent memory exhaustion
        if not raw.strip():
            return None
        data = json.loads(raw)
        return data
    except (json.JSONDecodeError, IOError):
        return None


def extract_command(data):
    """Extract the bash command from hook payload."""
    if not data:
        return None
    tool_name = data.get('tool_name', '')
    if tool_name != 'Bash':
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
# Kept identical in pre_scan.py — update both.
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
    """Match command against install/clone patterns.
    Returns (pattern_type, match_obj) or (None, None)."""
    if not command:
        return None, None

    # Check pipe-to-shell first (instant CRITICAL)
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
    if pattern_type in ('pip_install', 'npm_install', 'yarn_add', 'gem_install',
                        'cargo_install', 'go_install', 'brew_install', 'openclaw_install',
                        'claude_plugin_install', 'uv_install', 'bun_install', 'pnpm_install'):
        raw = match.group(1)
        # Strip flags
        cleaned = INSTALL_FLAGS.sub('', raw).strip()
        # Split on whitespace, filter empties and flags
        names = [n.strip() for n in cleaned.split() if n.strip() and not n.startswith('-')]
        # Strip version specifiers for pip; .strip() handles `pkg @ url` form
        # which leaves trailing whitespace after the @ split.
        if pattern_type in ('pip_install', 'uv_install'):
            names = [re.split(r'[>=<!\[\];@]', n)[0].strip() for n in names]
            names = [n for n in names if n]
        return names
    return []


def _is_safe_scan_path(resolved_path):
    """Ensure resolved path is within CWD to prevent scanning sensitive directories."""
    from pathlib import PurePath
    cwd = os.getcwd()
    try:
        # PurePath.is_relative_to handles all edge cases (cwd='/', symlinks, etc.)
        p = PurePath(resolved_path)
        return (p.is_relative_to(cwd)
                or p.is_relative_to('/tmp')
                or p.is_relative_to('/private/tmp'))
    except (TypeError, ValueError):
        return False


def extract_clone_target(match):
    """Extract directory path from git clone command."""
    if not match:
        return None
    url = match.group(1)
    explicit_dir = match.group(2) if match.lastindex >= 2 else None

    if explicit_dir:
        resolved = os.path.realpath(explicit_dir)
    else:
        # Derive directory from URL
        repo_name = url.rstrip('/').split('/')[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        resolved = os.path.realpath(repo_name)

    # Path containment: refuse to scan outside CWD or /tmp
    if not _is_safe_scan_path(resolved):
        return None
    return resolved


# npm-family installers pin versions as `name@version`, which the pip/uv strip
# in extract_package_names() deliberately leaves untouched. These are the
# pattern types whose tokens get the split treatment below.
# Kept in sync with pre_scan.py — duplicated rather than imported so each hook
# script stays standalone-loadable.
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
        # tarball: .../<name>-<version>.tgz  (name may be scoped .../@scope/name/-/name-1.2.3.tgz)
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


def check_ioc_pinned_versions(pattern_type, package_names):
    """Check npm-family `name@version` tokens against the IOC database.

    Complements check_ioc_packages(), which compares whole tokens against the
    name sets: a pinned token like `rimarf@1.0.0` matches no name, so the
    install used to sail through while bare `rimarf` was flagged. Flags when
    either the base name is a known-malicious package, or the exact pinned
    version appears in the shipped compromised_versions map.

    Fail-open on IOC-load failure, same contract as check_ioc_packages().
    """
    if pattern_type not in NPM_FAMILY_INSTALLS:
        return []
    try:
        import ioc_manager
        iocs = ioc_manager.get_iocs()
    except (ImportError, AttributeError, KeyError, TypeError):
        return []

    all_malicious = iocs.get('malicious_npm', set()) | iocs.get('malicious_pypi', set())
    compromised_versions = iocs.get('compromised_versions', {})

    findings = []
    for pkg in package_names:
        base, version = split_npm_name_version(pkg)
        if version is None:
            continue  # bare names are already covered by check_ioc_packages()
        base_lower = base.lower()
        if base_lower in all_malicious:
            findings.append({
                'scanner': 'auto_scan',
                'severity': 'critical',
                'title': f"Known Malicious Package: '{base}@{version}'",
                'description': f"Package '{base}' matches IOC database at any version. DO NOT INSTALL.",
                'file': 'N/A',
                'line': 0,
                'snippet': f"'{base}' is a known malicious package (IOC match)",
                'category': 'known-ioc'
            })
            continue
        pkg_bad = compromised_versions.get(base_lower, {})
        if not pkg_bad:
            continue
        # exact pin
        if version in pkg_bad:
            findings.append({
                'scanner': 'auto_scan',
                'severity': 'critical',
                'title': f"Compromised Package Version: '{base}@{version}'",
                'description': (
                    f"Version {version} of '{base}' was published in supply-chain "
                    f"campaign '{pkg_bad[version]}'. DO NOT INSTALL this version."
                ),
                'file': 'N/A',
                'line': 0,
                'snippet': f"'{base}@{version}' is a known-compromised release ({pkg_bad[version]})",
                'category': 'known-ioc'
            })
            continue
        # range / x-range / comparator spec that could resolve to a compromised
        # version (e.g. keyv@^6.0.0 resolving to the bad 6.0.0). Conservative.
        for bad_ver, campaign in pkg_bad.items():
            if _spec_could_match(version, bad_ver):
                findings.append({
                    'scanner': 'auto_scan',
                    'severity': 'critical',
                    'title': f"Compromised Package Version: '{base}@{version}'",
                    'description': (
                        f"Version range '{version}' of '{base}' may resolve to "
                        f"compromised {bad_ver}, published in supply-chain campaign "
                        f"'{campaign}'. DO NOT INSTALL this version."
                    ),
                    'file': 'N/A',
                    'line': 0,
                    'snippet': f"'{base}@{version}' may resolve to compromised {bad_ver} ({campaign})",
                    'category': 'known-ioc'
                })
                break

    return findings


def check_ioc_packages(package_names):
    """Check package names against IOC database. Returns findings list."""
    try:
        import ioc_manager
        iocs = ioc_manager.get_iocs()
    except ImportError:
        return []

    findings = []
    malicious_npm = iocs.get('malicious_npm', set())
    malicious_pypi = iocs.get('malicious_pypi', set())
    all_malicious = malicious_npm | malicious_pypi

    for pkg in package_names:
        pkg_lower = pkg.lower()
        if pkg_lower in all_malicious:
            findings.append({
                'scanner': 'auto_scan',
                'severity': 'critical',
                'title': f"Known Malicious Package: '{pkg}'",
                'description': f"Package '{pkg}' matches IOC database. DO NOT INSTALL.",
                'file': 'N/A',
                'line': 0,
                'snippet': f"'{pkg}' is a known malicious package (IOC match)",
                'category': 'known-ioc'
            })

        # Also check for liteLLM specifically
        if pkg_lower == 'litellm':
            findings.append({
                'scanner': 'auto_scan',
                'severity': 'critical',
                'title': f"Supply Chain Risk: '{pkg}' (liteLLM)",
                'description': "liteLLM had a malicious .pth file injection in v1.82.8 (March 2026). "
                               "Verify version is not compromised before installing.",
                'file': 'N/A',
                'line': 0,
                'snippet': "liteLLM PyPI supply chain attack: .pth file auto-exfiltrates credentials",
                'category': 'supply-chain'
            })

    return findings


def _scan_incomplete_finding(scanner_script, reason):
    """Build a LOUD synthetic finding for a scanner that failed to complete.

    A scanner that times out, is killed by a signal (SIGKILL/OOM), exits with
    an error code, or emits unparseable JSON used to return [] silently here —
    meaning the user got a CLEAN verdict with NO indication the scan was
    incomplete. That is a detection bypass: an attacker who pushes any scanner
    past the 15s wall-clock (or OOMs it) thereby SUPPRESSES all of that
    scanner's findings without a trace. Fail LOUD instead: emit a high-severity
    finding so the verdict flips and the gap is visible. (Closes the
    "SIGKILL -> silent zero" class; torture 2026-06-17.)
    """
    name = scanner_script[:-3] if scanner_script.endswith('.py') else scanner_script
    return [{
        'scanner': name,
        'severity': 'high',
        'title': 'Scanner did not complete — results may be incomplete',
        'description': (
            f"{name} {reason}; its findings are MISSING from this report. "
            f"A repo can trigger this (e.g. by making the scanner overrun its "
            f"time budget or exhaust memory) to suppress detection, so treat a "
            f"clean verdict from this scan as UNTRUSTWORTHY for {name}'s surface. "
            f"Re-run the scanner in isolation to obtain complete results."
        ),
        'file': '',
        'line': 0,
        'snippet': '',
        'category': 'scan-incomplete',
    }]


def run_scanner(scanner_script, repo_path):
    """Run a single scanner and return parsed findings.

    On any failure mode that would otherwise yield a SILENT empty result
    (timeout, signal-kill, scanner error, unparseable JSON on non-empty stdout,
    or a NON-zero exit with empty stdout — the uncaught-exception crash door),
    returns a LOUD synthetic 'scan-incomplete' finding instead of [] so the
    incompleteness surfaces in the verdict. A clean [] is returned when rc==0
    with empty stdout, or whenever stdout parses to valid JSON (including an
    empty list) at rc<=2 — a scanner may exit non-zero while still emitting its
    findings JSON, and that output is trusted. The crash door is specifically a
    NON-zero exit with EMPTY or unparseable stdout, which now fails loud.
    """
    import subprocess
    script_path = os.path.join(SCRIPTS_DIR, scanner_script)
    if not os.path.exists(script_path):
        return []

    try:
        result = subprocess.run(
            [sys.executable, script_path, repo_path, '--format', 'json'],
            capture_output=True, text=True, timeout=15,
            cwd=SCRIPTS_DIR
        )
    except subprocess.TimeoutExpired:
        return _scan_incomplete_finding(
            scanner_script, "TIMED OUT (exceeded the 15s wall-clock budget)")
    except OSError as e:
        return _scan_incomplete_finding(
            scanner_script, f"could not be launched (OSError: {e})")

    rc = result.returncode
    # Killed by a signal: subprocess returncode is negative (e.g. -9 = SIGKILL,
    # the classic OOM / wall-clock kill). This is the core silent-zero vector.
    if rc < 0:
        return _scan_incomplete_finding(
            scanner_script,
            f"was KILLED by signal {-rc} (e.g. SIGKILL/OOM or wall-clock kill)")
    # Scanner errored out (rc > 2 is outside the success/findings-present band).
    if rc > 2:
        return _scan_incomplete_finding(
            scanner_script, f"exited with error code {rc}")

    out = result.stdout.strip()
    if not out:
        # ONLY rc==0 with empty stdout is a legitimate "ran clean, found
        # nothing" result. A NON-zero rc with EMPTY stdout means the scanner
        # did NOT produce results — the classic uncaught-exception crash exits
        # rc==1 (or 2) and writes its traceback to STDERR, leaving stdout empty.
        # Treating that as "[] = benign" silently suppresses the whole scanner:
        # the same silent-zero detection-bypass class as the timeout/SIGKILL
        # doors, just via the crash door. Fail LOUD instead. (P1, CE review
        # 2026-06-17.)
        if rc == 0:
            return []
        return _scan_incomplete_finding(
            scanner_script,
            f"exited non-zero (rc {rc}) with no output — likely crashed")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return _scan_incomplete_finding(
            scanner_script, "produced UNPARSEABLE JSON output")


def run_targeted_scan(repo_path):
    """Run 19 targeted scanners in parallel on a cloned/installed repo."""
    if not os.path.isdir(repo_path):
        return []

    targeted_scanners = [
        'scan_dependencies.py',
        'scan_secrets.py',
        'scan_lifecycle.py',
        'scan_skill_threats.py',
        'scan_manifest_drift.py',
        'scan_runtime_dynamism.py',
        'scan_agent_skills.py',
        'scan_sast.py',
        'scan_mcp_security.py',
        'scan_infra.py',
        'scan_entrypoint.py',
        'scan_oversize.py',
        'scan_splitstream.py',
        'scan_provenance.py',
        'scan_archive.py',
        'scan_bytecode.py',
        'scan_dead_anchors.py',
        'scan_yara.py',
        'scan_git_config.py',
    ]

    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_findings = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(run_scanner, s, repo_path): s
            for s in targeted_scanners
        }
        for future in as_completed(futures):
            try:
                findings = future.result()
                if isinstance(findings, list):
                    all_findings.extend(findings)
            except Exception as e:
                print(f"[!] Scanner {futures[future]} failed: {e}", file=sys.stderr)

    # Raw-content correlation fallbacks (Lethal Trifecta + registry hijack), run
    # before correlate() so the hook path has the same raw-content feed as the
    # full-scan build_report path. Without these the PostToolUse hook gives a
    # false-clean on registry-hijack and trifecta payloads at install time — the
    # exact moment interception matters most.
    try:
        import forensics_core as core
        all_findings.extend(f.to_dict() for f in core.detect_trifecta_raw(repo_path))
        all_findings.extend(f.to_dict() for f in core.detect_registry_hijack_raw(repo_path))
    except (ImportError, OSError, AttributeError) as e:
        print(f"[!] Raw-content scan failed: {e}", file=sys.stderr)

    # Run correlation engine on collected findings to detect compound threats.
    # Uses the shared findings_from_dicts helper to stay in sync with
    # aggregate_json.run_correlation_pass (PR-F1, 2026-04-05).
    try:
        import forensics_core as core
        finding_objs = core.findings_from_dicts(all_findings)
        if finding_objs:
            correlated = core.correlate(finding_objs, repo_path=repo_path)
            all_findings.extend(cf.to_dict() for cf in correlated)
    except (ImportError, AttributeError, KeyError, TypeError, ValueError) as e:
        print(f"[!] Correlation failed: {e}", file=sys.stderr)

    return [f for f in all_findings if f.get("scanner") != "trifecta_raw"]


def build_pipe_to_shell_warning(command):
    """Build CRITICAL warning for pipe-to-shell commands."""
    return [{
        'scanner': 'auto_scan',
        'severity': 'critical',
        'title': 'Pipe-to-Shell Execution Detected',
        'description': (
            'Command executes downloaded content or uses an opaque PowerShell '
            'EncodedCommand. This bypasses package manager security checks '
            'and can execute arbitrary code.'
        ),
        'file': 'N/A',
        'line': 0,
        'snippet': command[:200] if command else '',
        'category': 'pipe-to-shell'
    }]


def format_output(findings, command='', pattern_type='', scanned_target=''):
    """Format scan results as plain text so Claude Code surfaces it to the model.

    Always produces output when a scan ran (even if clean) so the model knows
    the security check happened. Returns empty string only when no scan was
    triggered (non-matching command).
    """
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

    if not findings:
        if scanned_target:
            return f"[repo-forensics] auto-scan complete: {scanned_target} — no issues found."
        return ''

    findings.sort(key=lambda f: severity_order.get(f.get('severity', 'low'), 3))

    critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
    high_count = sum(1 for f in findings if f.get('severity') == 'high')

    lines = []
    lines.append(f"[repo-forensics] auto-scan: {len(findings)} finding(s)")
    if pattern_type:
        lines.append(f"Triggered by: {pattern_type} command")

    # Sanitize the scanner-authored title/description (defense in depth) and do
    # NOT echo the raw `snippet` here. The snippet is the attacker-controlled
    # payload; the only place it appears is inside the injection-safe
    # adjudication block below, behind the `> SNIPPET: ` prefix. Echoing it
    # unprefixed in this summary list would reintroduce the exact prompt-injection
    # surface U8 closes ("no unprefixed attacker text anywhere in the output").
    try:
        import adjudication as _adj
        _clean = _adj.sanitize_snippet
    except ImportError:
        # B4 fix: inline fallback must cover \r, U+2028/2029, BIDI, C1 range,
        # and collapse all whitespace/line-separator chars to a single space.
        # Kept self-contained since the import failed.
        import re as _re
        _FALLBACK_CTRL_RE = _re.compile(
            r"[\x00-\x1f\x7f\x80-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\u2060-\u2064\ufeff]"
        )

        def _clean(text, max_len=160):
            if not isinstance(text, str):
                return ""
            cleaned = _FALLBACK_CTRL_RE.sub("", text or "")
            cleaned = _re.sub(r"\s+", " ", cleaned).strip()
            return cleaned[:max_len]

    for f in findings[:15]:
        sev = f.get('severity', 'low').upper()
        title = _clean(f.get('title', 'Unknown'), max_len=160)
        desc = _clean(f.get('description', ''), max_len=300)
        lines.append(f"[{sev}] {title}: {desc}")

    if len(findings) > 15:
        lines.append(f"... and {len(findings) - 15} more findings. Run full scan for details.")

    if critical_count > 0:
        lines.append(f"VERDICT: {critical_count} CRITICAL finding(s). Do not proceed without review.")
    elif high_count > 0:
        lines.append(f"VERDICT: {high_count} HIGH finding(s). Review before proceeding.")

    # Adjudication block (U8): WARN-tier findings get an injection-safe block
    # the host agent reads as tool output. auto_scan does not run aggregate_json,
    # so needs_adjudication is not pre-set; the helper falls back to the WARN
    # confidence band and excludes correlation-synthesized findings itself.
    try:
        import adjudication
        block = adjudication.build_adjudication_block(findings)
        if block:
            lines.append(block)
    except ImportError:
        pass

    return '\n'.join(lines)


def emit_report(adapter, text):
    """Write the post-execution report in *adapter*'s output shape.

    Claude/Codex/OpenClaw surface plain text from a PostToolUse hook, which is
    what has always been printed here. Cursor parses hook stdout as JSON, so the
    same report is carried in the canonical verdict triple with an `allow`
    permission — the event is observe-only, so there is no other verdict it
    could carry.
    """
    if not text:
        if adapter == hook_adapter.ADAPTER_CURSOR:
            hook_adapter.emit_verdict(adapter, hook_adapter.ALLOW)
        return
    if adapter == hook_adapter.ADAPTER_CURSOR:
        hook_adapter.emit_verdict(adapter, hook_adapter.ALLOW,
                                  user_message=text, agent_message=text)
        return
    print(text)


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    adapter, adapter_error = hook_adapter.normalize_adapter(
        hook_adapter.adapter_from_argv(argv))
    if adapter_error:
        print(f"[repo-forensics] WARNING: {adapter_error}; falling back to "
              f"'{hook_adapter.ADAPTER_CLAUDE}'", file=sys.stderr)

    # Parse hook input through the shared adapter so the Cursor envelope reaches
    # the SAME detection code as the Claude one. Drift is not fatal here: this
    # hook cannot block, so an unreadable envelope means "nothing to scan",
    # never "deny" (that policy belongs to pre_scan.py).
    request = hook_adapter.parse_request(adapter, hook_adapter.read_stdin())
    if request.drift:
        print(f"[repo-forensics] WARNING: post-execution audit skipped: "
              f"{request.drift}", file=sys.stderr)
        emit_report(adapter, "")
        sys.exit(0)
    command = request.command

    if not command:
        emit_report(adapter, "")
        sys.exit(0)

    # Detect install/clone pattern
    pattern_type, match = detect_install_command(command)

    if not pattern_type:
        emit_report(adapter, "")
        sys.exit(0)

    # Pipe-to-shell: instant CRITICAL, no scan needed
    if pattern_type == 'pipe_to_shell':
        findings = build_pipe_to_shell_warning(command)
        output = format_output(findings, command, pattern_type, scanned_target='pipe-to-shell')
        emit_report(adapter, output)
        sys.exit(0)

    all_findings = []
    scanned_target = ''

    # For package install commands: check IOC list
    package_names = []
    if pattern_type != 'git_clone':
        package_names = extract_package_names(pattern_type, match)
        if package_names:
            scanned_target = ', '.join(package_names)
            ioc_findings = check_ioc_packages(package_names)
            all_findings.extend(ioc_findings)
            # Version-pinned npm-family tokens (`name@version`) never match the
            # name sets above, so re-check them by base name and exact version.
            all_findings.extend(check_ioc_pinned_versions(pattern_type, package_names))

    # For git clone: scan the cloned directory
    if pattern_type == 'git_clone':
        clone_dir = extract_clone_target(match)
        if clone_dir and os.path.isdir(clone_dir):
            scanned_target = clone_dir
            scan_findings = run_targeted_scan(clone_dir)
            all_findings.extend(scan_findings)

    # For git pull / uv sync / bare lockfile install: scan CWD (repo or its
    # deps were updated in place from the lockfile — no package args to target).
    # A with-args install that extracted zero packages is also a lockfile
    # install: its args were all flags (`pnpm install --frozen-lockfile`,
    # `npm install --production`) — deps still changed, so scan CWD.
    _lockfile_like = pattern_type in ('git_pull', 'uv_sync', 'lockfile_install') or (
        pattern_type in ('pip_install', 'npm_install', 'uv_install',
                         'bun_install', 'pnpm_install') and not package_names)
    if _lockfile_like:
        cwd = os.getcwd()
        if os.path.isdir(cwd) and _is_safe_scan_path(cwd):
            scanned_target = cwd
            scan_findings = run_targeted_scan(cwd)
            all_findings.extend(scan_findings)

    # For pip/npm-style install with a local path: scan it (with path containment)
    if pattern_type in ('pip_install', 'npm_install', 'uv_install', 'bun_install',
                        'pnpm_install'):
        for pkg in package_names:
            pkg_path = os.path.realpath(pkg)
            if os.path.isdir(pkg_path) and _is_safe_scan_path(pkg_path):
                scanned_target = pkg_path
                scan_findings = run_targeted_scan(pkg_path)
                all_findings.extend(scan_findings)

    output = format_output(all_findings, command, pattern_type, scanned_target)
    emit_report(adapter, output)
    sys.exit(0)


if __name__ == '__main__':
    main()
