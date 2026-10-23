#!/usr/bin/env python3
"""
scan_sast.py - Static Application Security Testing (rules-as-data)

Identifies dangerous functions, injection patterns, and code vulnerabilities.
As of v2.10 the per-language detection patterns live in a JSON rule pack
(data/rulepacks/sast.json), loaded at module import via rule_loader and indexed
by file extension so the hot loop stays O(rules-for-ext). The pack is the
single source of truth; there is no hardcoded fallback table. If the pack
cannot be loaded (a corrupted or tampered install), the scanner emits one loud
diagnostic finding and scans no patterns. tests/ is deliberately NOT excluded
from the walk (attackers hide malware there per Snyk research).

The CSS-steganography pass and the MAX_LINE_LENGTH / binary skips are scanning
context machinery, not pattern tables, so they stay in code.

Created by Alex Greenshpun
"""

import ast
import os
import re
import html as _html
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import rule_loader

SCANNER_NAME = "sast"


# SA-SH-004 (nested command substitution). These inner substitutions only
# read a path, the time or a fixed setting, and $(( )) is arithmetic, so they
# are replaced by a plain word before the rule is applied again: nesting that
# remains around any other command is still reported.
_INERT_SUBSTITUTION = re.compile(
    r'\$\(\(\s*[^()]*\)\)'
    r'|\$\(\s*(?:dirname|basename|pwd|realpath|readlink|date|nproc|mktemp|getconf'
    r'|tput|command\s+-v|type\s+-[Pp]|git\s+rev-parse)\b(?:[^()$`]|\$(?!\())*\)')
_MAX_INERT_PASSES = 16


# `case` arm pattern list (`a|b|c) cmd`): the `|` separates patterns, it is not
# a pipe. Only the command after the closing paren is checked by the rule.
# Two conditions must both hold before the pattern list is skipped: the line
# sits inside a `case ... in` ... `esac` block, and no pattern token carries
# brace-expansion characters. `{curl,-s,url}|sh)` closing a subshell is a real
# pipe-to-shell, not an arm, and a file with no case block never skips anything.
_CASE_ARM = re.compile(r'^\s*[^(){},\s|;&$`]*(?:\|[^(){},\s|;&$`]*)+\)\s*')
_CASE_OPEN = re.compile(r'(?:^|[;&|(]\s*)case\b[^\n]*?\bin\b')
_ESAC = re.compile(r'(?:^|[;&|(\s])esac\b')
_SHELL_CASE_EXTS = frozenset({'.sh', '.bash', '.zsh', '.ksh'})


def _case_depth_after(depth, line):
    """Track `case ... in` / `esac` nesting across logical lines (shell only).

    Returns (depth, arm_next): arm_next is True only when the next line can
    start a new arm, i.e. this line opened the block (`... in`) or ended an
    earlier arm (`;;`, `;&`, `;;&`). A line inside an arm body is never an arm,
    so `(\ncurl|sh)` placed in a body is still checked.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return depth, None
    opened = _CASE_OPEN.search(stripped)
    if opened:
        depth += 1
    depth -= len(_ESAC.findall(stripped))
    depth = max(depth, 0)
    arm_next = depth > 0 and (
        bool(re.search(r'\bin\s*$', stripped)) and bool(opened)
        or stripped.endswith((';;', ';&', ';;&')))
    return depth, arm_next


def _nesting_survives(rule, line, in_case=False):
    if rule.id == "SA-SH-003":
        m = _CASE_ARM.match(line) if in_case else None
        if m:
            return rule.regex.search(line[m.end():]) is not None
        return True
    if rule.id != "SA-SH-004":
        return True
    for _ in range(_MAX_INERT_PASSES):
        stripped = _INERT_SUBSTITUTION.sub('X', line)
        if stripped == line:
            break
        line = stripped
    return rule.regex.search(line) is not None


_DYNAMIC_IMPORT_IDS = frozenset({"SA-PY-003"})


def _filter_python_shell_docstring_examples(findings, source, ext):
    """A quoted historical shell call in a docstring is not executable code."""
    if ext != ".py" or not any(f.rule_id == "SA-PY-006" for f in findings):
        return findings
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return findings
    interior_lines = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", ())
        if not body or not isinstance(body[0], ast.Expr):
            continue
        value = body[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            interior_lines.update(range(body[0].lineno + 1, body[0].end_lineno))
    return [f for f in findings
            if not (f.rule_id == "SA-PY-006" and f.line in interior_lines)]

# Per-language detection rules load from the shipped pack at import time
# (rule_loader memoizes -> parsed once per process). by_extension is the
# pre-built index; rules_for_extension(ext) returns the rules gated to `ext`
# plus any extension-agnostic rules, preserving the original O(rules-for-ext)
# per-line cost. load_pack returns None only for a missing/incompatible pack
# (corrupted/tampered install), surfaced as PACK_LOAD_ERROR below.
_PACK = rule_loader.load_pack(SCANNER_NAME)
PACK_LOAD_ERROR = _PACK is None
# Extensions the pack actually covers (used to short-circuit non-target files,
# matching the old `if ext not in SAST_PATTERNS` guard).
_PACK_EXTENSIONS = (
    {e for e in _PACK.by_extension if e} if _PACK is not None else set()
)

# B6 fix: emit the pack-load-failure diagnostic exactly ONCE per scanner run,
# not once per scanned file (which could flood a large repo with thousands of
# duplicate criticals and cause OOM in the aggregator).
_pack_error_emitted = False


def _pack_load_finding(rel_path):
    """The single loud diagnostic emitted when the SAST rule pack failed to
    load. Critical so it cannot be missed; the operator is told to reinstall.
    We deliberately do NOT fall back to a hardcoded copy of the patterns."""
    return core.Finding(
        scanner=SCANNER_NAME, severity="critical",
        title="SAST rule pack failed to load",
        description=("data/rulepacks/sast.json is missing or "
                     "schema-incompatible; SAST scanning is disabled. "
                     "Reinstall repo-forensics to restore detection."),
        file=rel_path, line=0,
        snippet="rule pack failed to load",
        category="scanner-integrity",
    )


CSS_STEG_PATTERNS = [
    (re.compile(r'display:\s*none', re.IGNORECASE), "CSS hiding: display:none"),
    (re.compile(r'visibility:\s*hidden', re.IGNORECASE), "CSS hiding: visibility:hidden"),
    (re.compile(r'opacity:\s*0(?:\s*[;},!]|\s*$)', re.IGNORECASE), "CSS hiding: opacity:0"),
    (re.compile(r'font-size:\s*(?:0+(?![\d.]*[1-9])|0*\.0|0+\.\d+\s*(?:px|pt|%)(?=[\s;},!]|$))', re.IGNORECASE), "CSS hiding: zero-size text"),
    (re.compile(r'position:\s*absolute.*left:\s*-\d{4,}', re.IGNORECASE), "CSS hiding: positioned off-screen"),
    (re.compile(r'clip:\s*rect\(0', re.IGNORECASE), "CSS hiding: clipped to zero area"),
    (re.compile(r'text-indent:\s*-\d{4,}', re.IGNORECASE), "CSS hiding: text pushed off-screen"),
    (re.compile(r'overflow:\s*hidden[^;]*height:\s*0', re.IGNORECASE), "CSS hiding: zero-height container"),
    (re.compile(r'color:\s*(?:white|#fff(?:fff)?|rgba?\([^)]*,\s*0\s*\))', re.IGNORECASE), "CSS hiding: text matching background"),
]

CSS_STEG_EXTENSIONS = {'.html', '.htm', '.svg', '.jsx', '.tsx', '.vue', '.md'}

# --- CSS compounding shrink -------------------------------------------------
# Each parent-relative font-size under 1 (em, %, smaller, calc(<one literal>))
# shrinks text relative to its parent, so a chain of nested elements can render
# below one pixel even though no single declaration looks hidden. This is a
# count-and-multiply bound, not a layout engine: every element that carries such
# a size (through a class, id, tag or attribute rule, or inline style) is counted
# once and the factors are multiplied as if all of them were nested. Nesting is
# not verified, so the finding is LOW and says so.
#
# Known limits (accepted for a LOW heuristic): a bare *, :is()/:where(),
# calc() beyond one literal, min()/max()/clamp()/var(), ex/lh/ch units, escapes
# inside custom properties, and declarations nested under @media or & that lose
# the enclosing selector are not resolved. Long sibling lists can flag.
_CSS_SPECIAL = re.compile(r'["\'{}/<\\-]')


_CSS_STR_END = {'"': re.compile(r'\\\r\n|\\.|["\n\r\f]', re.DOTALL),
                "'": re.compile(r"\\\r\n|\\.|['\n\r\f]", re.DOTALL)}


_TAG_BODY = re.compile(r'(?:"[^"]*"|\'[^\']*\'|[^>"\'])*')


_CSS_TAG_MAX = 20000


_CSS_INPUT_MAX = 2000000


_CSS_BRACE_LIMIT = 100000


_RAW_BODY_TAGS = frozenset(('script', 'style', 'textarea', 'title', 'noscript'))
_NEST_TAG = re.compile(r'<[a-zA-Z][\w:-]*')
_MARKUP_NEXT = re.compile(r'<!--|<(/?)([a-zA-Z][\w:-]*)')


def _blank_dead_markup(content, live_templates=False):
    """Blank (keeping newlines, so offsets and lines hold) the parts of an HTML
    document that are never rendered: comments, script/textarea/title/noscript
    bodies and whole <template> subtrees (nested templates are counted).
    <style> bodies stay live; a Vue single-file component keeps its top-level
    <template> live (live_templates). A tag that never closes blanks nothing. One forward pass over real tags only, so a
    "<style>" inside a script string or a quoted attribute is not a marker."""
    spans = []
    pos = 0
    n = len(content)
    depth = 0
    tstart = 0
    no_close = set()                          # raw tags with no close tag from some point on
    while True:
        m = _MARKUP_NEXT.search(content, pos)
        if not m:
            break
        if m.group() == '<!--':
            e = content.find('-->', m.end())
            end = n if e < 0 else e + 3
            spans.append((m.start(), end))
            pos = end
            continue
        body = _TAG_BODY.match(content, m.end(), min(n, m.end() + _CSS_TAG_MAX))
        tag_end = max(m.end(), body.end())
        gt = min(n, tag_end + 1)
        tag = m.group(2).lower()
        if m.group(1):
            if tag == 'template' and depth:
                depth -= 1
                if depth == 0:
                    spans.append((tstart, gt))
            pos = gt
            continue
        selfclose = content[tag_end - 1:tag_end] == '/'
        if tag in _RAW_BODY_TAGS and not selfclose:
            ce = None
            if tag not in no_close:
                ce = re.compile(r'</' + tag + r'(?=[\s>/])', re.IGNORECASE).search(content, gt)
                if ce is None:
                    no_close.add(tag)         # absent here means absent for every later search
            if ce is None:
                pos = gt                      # unclosed: stay live, never blank to EOF
                continue
            if tag != 'style':
                spans.append((m.start(), ce.end()))
            pos = ce.end()
            continue
        if tag == 'template' and not selfclose and not live_templates:
            if depth == 0:
                tstart = m.start()
            depth += 1
        pos = gt
    if not spans:
        return content
    spans.sort()
    out = []
    last = 0
    for a, b in spans:
        if b <= last:
            continue
        a = max(a, last)
        out.append(content[last:a])
        out.append(re.sub(r'[^\n]', ' ', content[a:b]))
        last = b
    out.append(content[last:])
    return ''.join(out)


def _css_clean(content):
    """One linear pass: comments become a space and quoted strings become "".
    A string or comment left open runs to end of line (strings) or end of file
    and is consumed once. Returns (clean_text, [(position, '{' or '}')], truncated)."""
    parts = []
    braces = []
    out_len = 0
    seg = 0
    i = 0
    n = len(content)
    truncated = False
    depth = 0
    while True:
        m = _CSS_SPECIAL.search(content, i)
        if not m:
            break
        j = m.start()
        c = content[j]
        if c in '{}':
            if len(braces) >= _CSS_BRACE_LIMIT:
                truncated = True
                break
            depth += 1 if c == '{' else -1
            parts.append(content[seg:j])
            out_len += j - seg
            braces.append((out_len, c))
            parts.append(c)
            out_len += 1
            seg = i = j + 1
        elif c in '"\'' and depth <= 0 and not (
                content.rfind('[', max(0, j - 200), j) > content.rfind(']', max(0, j - 200), j)):
            i = j + 1                         # outside a block and an attribute selector a quote is prose
        elif c in '"\'':
            k = j + 1
            end = -1
            rx = _CSS_STR_END[c]
            while True:
                mm = rx.search(content, k)
                if not mm:
                    break
                g = mm.group()
                if g == c:
                    end = mm.end()
                    break
                if g in '\n\r\f':
                    break
                k = mm.end()
            if end < 0:
                i = j + 1                     # unterminated: an ordinary character
            else:
                parts.append(content[seg:j])
                parts.append('""')
                out_len += (j - seg) + 2
                seg = i = end
        elif c == '/' and content.startswith('/*', j):
            e = content.find('*/', j + 2)
            end = n if e < 0 else e + 2
            parts.append(content[seg:j])
            parts.append(' ')
            out_len += (j - seg) + 1
            seg = i = end
        elif c == '\\':
            i = j + 2                         # an escaped character is never a delimiter
        elif (c == '<' and content.startswith('<!--', j)) or (
                c == '-' and content.startswith('-->', j)):
            n_tok = 4 if c == '<' else 3      # CDO/CDC end a statement and are otherwise ignored
            parts.append(content[seg:j])
            parts.append(';')
            out_len += (j - seg) + 1
            seg = i = j + n_tok
        else:
            i = j + 1
    parts.append(content[seg:])
    return ''.join(parts), braces, truncated


_NUM_PAT = r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?'   # \d+\.?\d* backtracks quadratically


_NEST_SIZE = re.compile(
    r'(?<![\w-])font-size\s*:\s*(?:calc\(\s*(' + _NUM_PAT + r')\s*(em|%)\s*\)|(' + _NUM_PAT
    + r')\s*(em|%)|(smaller))', re.IGNORECASE)


_SMALLER = 0.833


_NEST_MAX_ITEMS = 200000
_PRELUDE_MAX = 100000
_COMPOUND_BUCKET_MAX = 64
# JSX/TSX: className is class, and a style object spells the size fontSize or 'font-size'.
_JSX_SIZE = re.compile(
    r'(?:\bfontSize|["\']font-size["\'])\s*:\s*["\']\s*(' + _NUM_PAT + r')\s*(em|%)\s*["\']', re.IGNORECASE)


_NEST_SHORT = re.compile(r'(?<![\w-])font\s*:\s*([^;{}]{0,200})', re.IGNORECASE)


def _css_ident(sel, i):
    """Read a CSS identifier starting at i, resolving backslash escapes."""
    out = []
    n = len(sel)
    while i < n:
        c = sel[i]
        if c == '\\':
            i += 1
            if i >= n:
                break
            j = i
            while j < n and j - i < 6 and sel[j] in '0123456789abcdefABCDEF':
                j += 1
            if j > i:
                try:
                    out.append(chr(int(sel[i:j], 16)))
                except (ValueError, OverflowError):
                    pass
                i = j + 1 if j < n and sel[j] in ' \t\n\r\f' else j
            else:
                out.append(sel[i])
                i += 1
        elif c.isalnum() or c in '-_' or ord(c) > 127:
            out.append(c)
            i += 1
        else:
            break
    return ''.join(out), i


def _split_selector_list(text):
    """Split a selector list at top-level commas only (not inside parentheses,
    brackets or strings, and not after a backslash)."""
    parts = []
    start = depth = 0
    quote = ''
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '\\':
            i += 2
            continue
        if quote:
            if c == quote:
                quote = ''
        elif c in '"\'':
            quote = c
        elif c in '([':
            depth += 1
        elif c in ')]':
            depth = max(0, depth - 1)
        elif c == ',' and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def _subject_keys(sel):
    """(kind, name) keys of the last compound selector in `sel`: tag, class, id
    and attribute names. Pseudo-classes are ignored, so the result is an
    over-approximation of the elements the selector can match."""
    keys = []
    sel = sel.strip(' \t\r\n\f')
    i, n = 0, len(sel)
    while i < n:
        c = sel[i]
        if c in ' \t\r\n\f>+~':
            keys = []
            i += 1
        elif c in '.#':
            name, i = _css_ident(sel, i + 1)
            if name:
                keys.append(('class' if c == '.' else 'id', name))
        elif c == '[':
            j, quote = i + 1, ''
            while j < n and (quote or sel[j] != ']'):
                if quote and sel[j] == quote:
                    quote = ''
                elif not quote and sel[j] in '"\'':
                    quote = sel[j]
                j += 1
            inner = sel[i + 1:j].lstrip()
            if inner.startswith('*|'):
                inner = inner[2:]
            elif inner.startswith('|') and not inner.startswith('|='):
                inner = inner[1:]
            else:
                pre, k = _css_ident(inner, 0)
                if inner[k:k + 1] == '|' and inner[k + 1:k + 2] != '=':
                    inner = inner[k + 1:]
            name, _ = _css_ident(inner, 0)
            if name:
                keys.append(('attr', name.lower()))
            i = j + 1
        elif c == ':':
            i += 1
            if sel[i:i + 1] == ':':
                i += 1
            _, i = _css_ident(sel, i)
            if sel[i:i + 1] == '(':
                depth = 0
                while i < n:
                    depth += 1 if sel[i] == '(' else -1 if sel[i] == ')' else 0
                    i += 1
                    if depth == 0:
                        break
        elif c == '*':
            i += 1
        else:
            name, j = _css_ident(sel, i)
            if j == i:
                i += 1
            else:
                keys.append(('tag', name.lower()))
                i = j
    return keys


_NEST_ATTR_NAME = re.compile(
    r'([^\s=/"\'<>]+)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+)))?')


_NEST_QUOTED = re.compile(r'"[^"]*"|\'[^\']*\'')


def _factor_of(value, unit):
    v = float(value)
    v = v / 100.0 if unit == '%' else v
    return v if 0 < v < 1 else None


def _strip_css_comments(text):
    """Replace /* ... */ comments with a space (an unclosed one runs to the end)."""
    if '/*' not in text:
        return text
    parts = []
    i = 0
    while True:
        j = text.find('/*', i)
        if j < 0:
            parts.append(text[i:])
            break
        parts.append(text[i:j])
        parts.append(' ')
        k = text.find('*/', j + 2)
        if k < 0:
            break
        i = k + 2
    return ''.join(parts)


_CSS_ESC = re.compile(r'\\([0-9a-fA-F]{1,6})[ \t\r\n\f]?|\\([^\n\r\f])')


def _css_unescape(text):
    """Resolve CSS backslash escapes (\\6f, \\o) so an escaped property or value reads plainly."""
    def one(m):
        if m.group(1):
            try:
                return chr(int(m.group(1), 16)) or ''
            except (ValueError, OverflowError):
                return ''
        return m.group(2)
    return _CSS_ESC.sub(one, text) if '\\' in text else text


_SHORT_SKIP = frozenset(('normal italic oblique bold bolder lighter small-caps ultra-condensed '
                         'extra-condensed condensed semi-condensed semi-expanded expanded '
                         'extra-expanded ultra-expanded').split())


_ANGLE = re.compile(_NUM_PAT + r'(?:deg|grad|rad|turn)\Z', re.IGNORECASE)


_BARE_NUM = re.compile(_NUM_PAT + r'\Z')


_SIZE_TOKEN = re.compile(
    r'(?:calc\(\s*(' + _NUM_PAT + r')\s*(em|%)\s*\)|(' + _NUM_PAT + r')(em|%)|(smaller))\Z',
    re.IGNORECASE)


def _shorthand_size_token(text):
    """The font-size slot of a font shorthand: the first token after the optional
    style, weight and stretch tokens, ended by whitespace or a slash."""
    i, n = 0, len(text)
    prev = ''
    while i < n:
        while i < n and text[i] in ' \t\r\n\f':
            i += 1
        j, depth = i, 0
        while j < n:
            c = text[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth = max(0, depth - 1)
            elif depth == 0 and c in ' \t\r\n\f/':
                break
            j += 1
        tok = text[i:j].lower()
        if not tok:
            return ''
        if tok in _SHORT_SKIP or _BARE_NUM.match(tok) or (prev == 'oblique' and _ANGLE.match(tok)):
            prev = tok
            i = j
            continue
        return tok
    return ''


def _relative_factor(block):
    """Smallest parent-relative factor (0 < f < 1) among the em/% sizes in a
    declaration block, from font-size and from the font shorthand, or None. The
    minimum is taken so a later declaration or !important cannot hide one."""
    best = None
    block = _css_unescape(_strip_css_comments(block))
    block = _NEST_QUOTED.sub('""', block)
    for m in _NEST_SIZE.finditer(block):
        if m.group(5):
            f = _SMALLER
        elif m.group(1):
            f = _factor_of(m.group(1), m.group(2))
        else:
            f = _factor_of(m.group(3), m.group(4))
        if f is not None and (best is None or f < best):
            best = f
    for m in _NEST_SHORT.finditer(block):
        sm = _SIZE_TOKEN.match(_shorthand_size_token(m.group(1)))
        if sm is None:
            continue
        if sm.group(5):
            f = _SMALLER
        elif sm.group(1):
            f = _factor_of(sm.group(1), sm.group(2))
        else:
            f = _factor_of(sm.group(3), sm.group(4))
        if f is not None and (best is None or f < best):
            best = f
    return best


def _line_of(content, position):
    return content.count('\n', 0, position) + 1


_CLOSE_TAG = re.compile(r'</([a-zA-Z][\w:-]*)')
_VOID_TAGS = frozenset('area base br col embed hr img input link meta source track wbr'.split())


def _nested_shrink_line(content, live_templates=False):
    """Conservative bound on compounding em/% shrink, with no full HTML parse.
    Every element that carries a parent-relative size under 1 (a class with such
    a rule, or an inline style) is a hit. Nesting is estimated from open and
    close tags: factors multiply only along hits that are still open, so
    siblings do not compound. A closing tag pops its element and anything left
    open inside it; void and self-closed elements never nest; unclosed elements
    stay open, which errs toward flagging. Returns (line, limit_line,
    shrink_seen): the line of the element where the product times the root size
    drops below one pixel (or None), the line where reading stopped short (or
    None), and whether any shrinking size was seen at all."""
    limited = len(content) > _CSS_INPUT_MAX
    content = _blank_dead_markup(content[:_CSS_INPUT_MAX], live_templates)
    clean, _braces, _lim = _css_clean(content)
    limit_line = _line_of(content, len(content)) if (limited or _lim) else None
    factors = {}
    stack = []                                # [cursor, parts, prelude] per open block
    for idx, (bpos, bc) in enumerate(_braces):
        if bc == '{':
            start = _braces[idx - 1][0] + 1 if idx else 0
            if stack:
                stack[-1][1].append(clean[stack[-1][0]:bpos])
            if limit_line is None and bpos - start > _PRELUDE_MAX:
                limit_line = _line_of(content, bpos)      # selector too long to read whole
            stack.append([bpos + 1, [], clean[max(start, bpos - _PRELUDE_MAX):bpos].rsplit(';', 1)[-1]])
            continue
        if not stack:
            continue
        cursor, parts, prelude = stack.pop()
        parts.append(clean[cursor:bpos])
        if stack:
            stack[-1][0] = bpos + 1
        f = _relative_factor(';'.join(parts))  # declarations at this block's own depth
        if f is None or prelude.lstrip().startswith('@'):
            continue
        for sel in _split_selector_list(prelude):
            keys = _subject_keys(sel)
            if not keys:
                continue
            # One entry per full compound (td.small needs both td and .small),
            # filed under its first key. A key with many compounds folds the
            # rest into that key alone, which only over-counts.
            keyset = frozenset(keys)
            bucket = factors.setdefault(keys[0], {})
            if keyset not in bucket and len(bucket) >= _COMPOUND_BUCKET_MAX:
                keyset = frozenset((keys[0],))
            bucket[keyset] = min(f, bucket.get(keyset, 1.0))
    hits = []
    pos = 0
    while True:
        m = _NEST_TAG.search(content, pos)
        if not m:
            break
        body = _TAG_BODY.match(content, m.end(), min(len(content), m.end() + _CSS_TAG_MAX))
        pos = max(m.end(), body.end())
        if limit_line is None and (body.end() - m.end() >= _CSS_TAG_MAX):
            limit_line = _line_of(content, m.start())
        attrs = body.group()
        f = 1.0
        amap = {}
        for am in _NEST_ATTR_NAME.finditer(attrs):
            key = am.group(1).lower()
            if key == 'classname':
                key = 'class'                 # JSX spelling
            if key not in amap:               # the first occurrence of an attribute wins
                amap[key] = _html.unescape(am.group(2) or am.group(3) or am.group(4) or '')
        if factors:
            present = {('tag', content[m.start() + 1:m.end()].lower())}
            present.update(('attr', key) for key in amap)
            present.update(('class', cls) for cls in amap.get('class', '').split())
            if 'id' in amap:
                present.add(('id', amap['id']))
            for key in present:
                for keyset, fv in factors.get(key, {}).items():
                    if fv < f and keyset <= present:
                        f = fv
        if 'style' in amap:
            sf = _relative_factor(amap['style'])
            if sf is not None:
                f = min(f, sf)
        for jm in _JSX_SIZE.finditer(attrs):
            jf = _factor_of(jm.group(1), jm.group(2))
            if jf is not None:
                f = min(f, jf)
        if f < 1.0:
            tag = content[m.start() + 1:m.end()].lower()
            closed = tag in _VOID_TAGS or attrs.rstrip().endswith('/')
            hits.append((m.start(), f, tag, closed))
    shrink_seen = bool(factors or hits)
    if not hits:
        return (None, limit_line, shrink_seen)
    # Multiply only along elements that are still open: a closing tag pops its
    # element (and anything left open inside it), so siblings do not compound.
    events = [(pos, 1, f, tag, closed) for pos, f, tag, closed in hits]
    names = {tag for _p, _f, tag, _c in hits}
    events.extend((cm.start(), 0, None, cm.group(1).lower(), False)
                  for cm in _CLOSE_TAG.finditer(content)
                  if cm.group(1).lower() in names)
    events.sort()
    root = 16.0
    stack = []                                # (tag, product including this element)
    open_count = {}
    count = 0
    for pos, kind, f, tag, closed in events:
        if kind == 0:
            if open_count.get(tag):
                while stack:
                    t, _ = stack.pop()
                    open_count[t] -= 1
                    if t == tag:
                        break
            continue
        count += 1
        product = (stack[-1][1] if stack else 1.0) * f
        if product * root < 1.0 or count > _NEST_MAX_ITEMS:
            return (_line_of(content, pos), limit_line, shrink_seen)
        if not closed:
            stack.append((tag, product))
            open_count[tag] = open_count.get(tag, 0) + 1
    return (None, limit_line, shrink_seen)


def scan_css_steganography(file_path, rel_path):
    ext = core.normalized_ext(file_path)
    if ext not in CSS_STEG_EXTENSIONS:
        return []
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return []
    lines = content.split('\n')
    for i, line in enumerate(lines):
        line = core.clip_line(line)
        for pat, title in CSS_STEG_PATTERNS:
            if pat.search(line):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title=title,
                    description="Visual hiding technique that could conceal instructions from human reviewers (DeepMind AI Agent Traps, March 2026).",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="css-steganography"
                ))
                break
    # Every size rule needs the word "font" (checked after unescaping, since an
    # escaped property name still applies).
    lowered = content.lower()
    if ('font' in lowered
            or ('\\' in content and 'font' in _css_unescape(content).lower())
            or ('&' in content and 'font' in _html.unescape(lowered))):
        nested, limit_line, shrink_seen = _nested_shrink_line(content, ext == '.vue')
        # Only report an unverifiable input when there is evidence to verify: a
        # shrinking size in the part that was read, or `font` in the unread tail.
        unread_font = len(content) > _CSS_INPUT_MAX and 'font' in content[_CSS_INPUT_MAX:].lower()
        if (limit_line and not nested and (shrink_seen or unread_font)
                and not any(x.line == limit_line for x in findings)):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="low",
                title="CSS hiding: possible compounding shrink (input too large to verify)",
                description="The file or one tag exceeds the size this check reads, so a nested font-size shrink could not be ruled out.",
                file=rel_path, line=limit_line,
                snippet=lines[limit_line - 1].strip()[:120] if limit_line <= len(lines) else "",
                category="css-steganography"))
        if nested and not any(x.line == nested for x in findings):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="low",
                title="CSS hiding: possible compounding shrink (nesting estimated from tags)",
                description="Parent-relative font sizes under 1 on elements nested inside one another (estimated from open and close tags) shrink text below one pixel.",
                file=rel_path, line=nested,
                snippet=lines[nested - 1].strip()[:120] if nested <= len(lines) else "",
                category="css-steganography"))
    return findings


# Extensions where a trailing backslash is a real line-continuation the
# interpreter honors, so a split token must be rejoined before matching. For
# every other language (JS/TS/JSON/...) a `\` at EOL is not a statement
# continuation, and joining there only mis-attributes a finding to a preceding
# `//`-comment line -- so those files are scanned physical-line-for-physical-
# line, exactly as before this pack existed.
_CONTINUATION_EXTS = frozenset({
    ".sh", ".bash", ".zsh", ".ksh", ".py", ".pyw", ".mk", "makefile",
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
})


def _trailing_backslash_count(s):
    n = 0
    for ch in reversed(s):
        if ch == "\\":
            n += 1
        else:
            break
    return n


def _logical_lines(lines, ext=None):
    r"""Join backslash-continued physical lines into logical lines for matching.

    A trailing (odd count of) backslash is a shell/Python/make/C line
    continuation that lets an attacker split a matched token across physical
    lines (`unshare \\\n-Urn sh`), dodging every per-line pattern. Joining
    restores the logical line the interpreter actually sees. Yields
    (start_index, text); start_index is the 0-based physical line where the
    yielded text begins so findings keep accurate line numbers.

    Two safety properties that prior revisions lacked:

    * The join is CAPPED at MAX_LINE_LENGTH. clip_line() truncates any line
      past that bound, so an unbounded join let an attacker pad a continued
      statement past 10k and push the real payload into the clipped tail --
      a FALSE NEGATIVE that plain physical-line scanning (main's behavior)
      never had. Once the running join reaches the cap we stop joining and
      yield the remaining physical lines of the group individually, so every
      physical line is still scanned. (Regression fix, PR #44 review.)
    * Joining only happens for languages where `\` at EOL is a real
      continuation (_CONTINUATION_EXTS). Elsewhere each physical line is
      yielded unchanged -- byte-for-byte the pre-pack behavior.

    A comment line never starts a continuation join (a trailing `\` in a
    comment is inert), and an EVEN number of trailing backslashes is a literal
    backslash, not a continuation.
    """
    n = len(lines)
    join_lang = (ext or "").lower() in _CONTINUATION_EXTS
    i = 0
    while i < n:
        start = i
        raw = lines[i]
        stripped = raw.rstrip("\r\n")
        if (not join_lang
                or stripped.lstrip().startswith("#")
                or _trailing_backslash_count(stripped) % 2 == 0
                or i + 1 >= n):
            yield start, raw
            i += 1
            continue
        # Accumulate a continuation group, bounded by MAX_LINE_LENGTH.
        parts = []
        joined_len = 0
        capped = False
        while (_trailing_backslash_count(stripped) % 2 == 1 and i + 1 < n):
            seg = stripped[:-1]
            if joined_len + len(seg) > core.MAX_LINE_LENGTH:
                capped = True
                break
            parts.append(seg)
            joined_len += len(seg)
            i += 1
            stripped = lines[i].rstrip("\r\n")
        if capped:
            # Cap hit: emit what we joined so far, then let the loop scan the
            # remaining physical lines of the group one by one, so a payload
            # past the 10k bound is never clipped out of every match.
            if parts:
                yield start, "".join(parts)
            continue
        parts.append(lines[i])
        yield start, "".join(parts)
        i += 1


_STRUCTURED_TLS_IDS = {"SA-PY-032", "SA-JS-040", "SA-TS-020", "SA-TSX-003"}
_NODE_TLS_RE = re.compile(
    r"\brejectUnauthorized\s*:\s*false\b|"
    r"[\"']rejectUnauthorized[\"']\s*:\s*false\b|"
    r"\b(?:[A-Za-z_$][\w$]*\.)+rejectUnauthorized\s*=\s*false\b|"
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']0[\"']",
    re.MULTILINE,
)


def _js_code_starts(text):
    """Mark source positions outside comments and string contents."""
    code = bytearray(b"\x01") * len(text)
    mode = "code"
    template_braces = []
    i = 0
    while i < len(text):
        char = text[i]
        next_char = text[i + 1] if i + 1 < len(text) else ""
        if mode == "code":
            if char == "/" and next_char == "/":
                end = text.find("\n", i)
                if end < 0:
                    end = len(text)
                code[i:end] = b"\x00" * (end - i)
                i = end
                continue
            if char == "/" and next_char == "*":
                end = text.find("*/", i + 2)
                end = len(text) if end < 0 else end + 2
                code[i:end] = b"\x00" * (end - i)
                i = end
                continue
            if char in ("'", '"'):
                mode = char
            elif char == "`":
                mode = "template"
                code[i] = 0
            elif template_braces:
                if char == "{":
                    template_braces[-1] += 1
                elif char == "}":
                    template_braces[-1] -= 1
                    if template_braces[-1] == 0:
                        template_braces.pop()
                        mode = "template"
                        code[i] = 0
        elif mode == "template":
            code[i] = 0
            if char == "\\":
                if i + 1 < len(text):
                    code[i + 1] = 0
                    i += 1
            elif char == "`":
                mode = "code"
            elif char == "$" and next_char == "{":
                code[i + 1] = 0
                template_braces.append(1)
                mode = "code"
                i += 1
        else:
            code[i] = 0
            if char == "\\":
                if i + 1 < len(text):
                    code[i + 1] = 0
                    i += 1
            elif char == mode:
                mode = "code"
        i += 1
    return code


def _rule_finding(rule, rel_path, text, offset, snippet=None):
    line = text.count("\n", 0, offset) + 1
    if snippet is None:
        snippet = text.splitlines()[line - 1] if text.splitlines() else ""
    return core.Finding(
        scanner=SCANNER_NAME, severity=rule.severity,
        title=rule.title, description=f"Potential {rule.category} vulnerability",
        file=rel_path, line=line, snippet=snippet.strip()[:120],
        category=rule.category, rule_id=rule.id, confidence=rule.confidence,
        attacker=rule.attacker, boundary=rule.boundary, asset=rule.asset,
    )


def _qualified_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _scan_structured_tls(text, rel_path, ext, rules):
    """Parse TLS-disable forms that line regexes cannot safely model.

    Python calls use AST keyword analysis, so nested calls and multiline calls
    cannot hide verify=False. Node-family property forms use a whole-file regex
    because whitespace/newlines do not change their syntax.
    """
    by_id = {r.id: r for r in rules}
    findings = []
    if ext == ".py" and "SA-PY-032" in by_id:
        rule = by_id["SA-PY-032"]
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, TypeError, RecursionError):
            tree = None
        if tree is None:
            # Extracted archive/bytecode text and parity corpora may be
            # intentionally non-parseable. Preserve the old per-line fallback
            # there; valid Python always takes the AST path below.
            for match in rule.regex.finditer(text):
                findings.append(_rule_finding(rule, rel_path, text, match.start(), match.group(0)))
        else:
            http_methods = {"request", "get", "post", "put", "patch", "delete", "head", "options"}
            parents = {}
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    parents[child] = parent
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and _qualified_name(node) == "ssl.CERT_NONE":
                    offset = sum(len(x) + 1 for x in text.splitlines()[:node.lineno - 1]) + node.col_offset
                    findings.append(_rule_finding(rule, rel_path, text, offset))
                if not isinstance(node, ast.Call):
                    continue
                name = _qualified_name(node.func)
                if name in {"ssl._create_unverified_context"}:
                    # Avoid double reporting: the surrounding assignment to
                    # verify_mode=ssl.CERT_NONE is the stronger same-line form.
                    parent = parents.get(node)
                    grand = parents.get(parent)
                    if not (isinstance(grand, ast.Assign) and
                            isinstance(grand.value, ast.Attribute) and
                            _qualified_name(grand.value) == "ssl.CERT_NONE"):
                        offset = sum(len(x) + 1 for x in text.splitlines()[:node.lineno - 1]) + node.col_offset
                        findings.append(_rule_finding(rule, rel_path, text, offset))
                    continue
                root, _, method = name.partition(".")
                if root not in {"requests", "httpx"} or method not in http_methods:
                    continue
                if any(kw.arg == "verify" and isinstance(kw.value, ast.Constant)
                       and kw.value.value is False for kw in node.keywords):
                    offset = sum(len(x) + 1 for x in text.splitlines()[:node.lineno - 1]) + node.col_offset
                    findings.append(_rule_finding(rule, rel_path, text, offset))
    elif ext in {".js", ".jsx", ".ts", ".tsx"}:
        rid = {".js": "SA-JS-040", ".jsx": "SA-JS-040", ".ts": "SA-TS-020", ".tsx": "SA-TSX-003"}[ext]
        rule = by_id.get(rid)
        if rule:
            matches = list(_NODE_TLS_RE.finditer(text))
            code_starts = _js_code_starts(text) if matches else ()
            for match in matches:
                if not code_starts[match.start()]:
                    continue
                findings.append(_rule_finding(rule, rel_path, text, match.start(), match.group(0)))
    return findings


def scan_file(file_path, rel_path):
    global _pack_error_emitted

    if PACK_LOAD_ERROR:
        # B6: emit the diagnostic only on the first call; subsequent files get
        # an empty list so the aggregator is not flooded with duplicates.
        if not _pack_error_emitted:
            _pack_error_emitted = True
            return [_pack_load_finding(rel_path)]
        return []

    # Resolve through the SHARED gate. It normalizes the trailing
    # dot/space that Windows strips when executing (`evil.py ` / `evil.py.`
    # both run as evil.py but keyed as ".py " / "." here, missing every
    # allowlist and skipping the ENTIRE ruleset), and routes language variants
    # (.mjs/.cjs/.pyw/.phtml) to their family's rules instead of dropping them.
    ext = core.resolve_scan_ext(file_path, _PACK_EXTENSIONS)
    ext = {".bash": ".sh", ".zsh": ".sh", ".ksh": ".sh"}.get(ext, ext)
    if not ext:
        return []

    # rules_for_extension keeps the hot loop O(rules-for-ext) per line.
    rules = _PACK.rules_for_extension(ext)
    findings = []
    source = ""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            source = ''.join(lines)
            text = source
            case_depth = 0
            arm_ok = False
            for i, line in _logical_lines(lines, ext):
                line = core.clip_line(line)
                in_case = arm_ok
                if ext in _SHELL_CASE_EXTS:
                    case_depth, nxt = _case_depth_after(case_depth, line)
                    if nxt is not None:
                        arm_ok = nxt
                for rule in rules:
                    if rule.id in _STRUCTURED_TLS_IDS:
                        continue
                    if rule.regex.search(line) and _nesting_survives(rule, line, in_case):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME,
                            severity=rule.severity,
                            title=rule.title,
                            description=f"Potential {rule.category} vulnerability",
                            file=rel_path,
                            line=i + 1,
                            snippet=line.strip()[:120],
                            category=rule.category,
                            rule_id=rule.id,
                            confidence=rule.confidence,
                            attacker=rule.attacker,
                            boundary=rule.boundary,
                            asset=rule.asset,
                        ))
            findings.extend(_scan_structured_tls(text, rel_path, ext, rules))
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    findings = core.downgrade_inert_literal_imports(findings, source, _DYNAMIC_IMPORT_IDS,
                                                    file_path, rel_path)
    return _filter_python_shell_docstring_examples(findings, source, ext)


def scan_text(text, rel_path, ext=None):
    """SAST scan over an in-memory text blob — an extracted archive member or a
    disassembled .pyc listing — instead of a file on disk.

    Mirrors scan_file's per-rule emission exactly (rule.severity, rule.category,
    rule_id, confidence) so a finding surfaced from inside an archive is
    indistinguishable in shape from one surfaced from a plain source file. The
    KTD7 text shim the bytecode (U2) and archive (U3) scanners share for SAST,
    placed here rather than in forensics_core so the single _PACK source of
    truth is not forked. `ext` overrides the rule-selection extension (defaults
    to rel_path's extension); pass e.g. ".py" when scanning a bytecode listing.
    """
    global _pack_error_emitted
    if PACK_LOAD_ERROR:
        if not _pack_error_emitted:
            _pack_error_emitted = True
            return [_pack_load_finding(rel_path)]
        return []

    if ext is None:
        ext = core.resolve_scan_ext(rel_path, _PACK_EXTENSIONS)
    if ext not in _PACK_EXTENSIONS:
        return []

    rules = _PACK.rules_for_extension(ext)
    findings = []
    # split('\n') for parity with scan_file's readlines() (line numbers + no
    # Unicode-line-boundary split-evasion). _logical_lines applies the same
    # continuation joining as scan_file so in-memory text cannot smuggle a
    # split token past the per-line patterns either.
    case_depth = 0
    arm_ok = False
    for i, line in _logical_lines(text.split('\n'), ext):
        line = core.clip_line(line)
        in_case = arm_ok
        if ext in _SHELL_CASE_EXTS:
            case_depth, nxt = _case_depth_after(case_depth, line)
            if nxt is not None:
                arm_ok = nxt
        for rule in rules:
            if rule.id in _STRUCTURED_TLS_IDS:
                continue
            if rule.regex.search(line) and _nesting_survives(rule, line, in_case):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME,
                    severity=rule.severity,
                    title=rule.title,
                    description=f"Potential {rule.category} vulnerability",
                    file=rel_path,
                    line=i + 1,
                    snippet=line.strip()[:120],
                    category=rule.category,
                    rule_id=rule.id,
                    confidence=rule.confidence,
                    attacker=rule.attacker,
                    boundary=rule.boundary,
                    asset=rule.asset,
                ))
    findings.extend(_scan_structured_tls(text, rel_path, ext, rules))
    findings = core.downgrade_inert_literal_imports(findings, text, _DYNAMIC_IMPORT_IDS)
    return _filter_python_shell_docstring_examples(findings, text, ext)


def main():
    args = core.parse_common_args(sys.argv, "SAST Vulnerability Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Starting SAST scan on {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    if ignore_patterns:
        core.emit_status(args.format, f"[*] Loaded {len(ignore_patterns)} custom ignore patterns from .forensicsignore")

    all_findings = []

    # Use custom skip_dirs to NOT exclude tests/
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)
        all_findings.extend(scan_css_steganography(file_path, rel_path))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
