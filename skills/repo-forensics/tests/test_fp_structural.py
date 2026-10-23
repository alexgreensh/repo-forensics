"""Structural false-positive fixes: each benign case must go quiet and each
malicious twin must keep its finding at full severity."""
import os
import py_compile
import struct
import sys
import time

import pytest

import aggregate_json as agg
import scan_bytecode
import scan_dependencies
import scan_lifecycle

DEADMAN = "Dead-Man's Switch: Home Directory Resolved and Recursively Deleted"
HEAD = 'import { mkdtempSync, rmSync } from "node:fs";\nimport os from "node:os";\n'
RM = 'rmSync(HOME, { recursive: true, force: true });\n'


# --- temp-folder deletes are not home wipes ------------------------------------

def _deadman(tmp_path, text):
    p = tmp_path / "t.test.mjs"
    p.write_text(text)
    return any(f.title == DEADMAN for f in scan_lifecycle.scan_second_coming_indicators(str(p), "t.test.mjs"))


@pytest.mark.parametrize("text", [
    HEAD + 'const HOME = mkdtempSync(join(tmpdir(), "x-"));\nprocess.env.HOME = HOME;\n'
           'const p = join(HOME, ".claude");\n' + RM,
    HEAD + 'const HOME = await fs.promises.mkdtemp("x");\nprocess.env.HOME = HOME;\n' + RM,
])
def test_fresh_temp_dir_delete_is_not_a_home_wipe(tmp_path, text):
    assert not _deadman(tmp_path, text)


@pytest.mark.parametrize("text", [
    HEAD + 'rmSync(os.homedir(), { recursive: true });\n',
    HEAD + 'let HOME = mkdtempSync("x");\nHOME = os.homedir();\n' + RM,
    HEAD + 'const HOME = mkdtempSync("x") || os.homedir();\n' + RM,
    HEAD + 'const HOME = mkdtempSync("x");\nfunction f() { const HOME = os.homedir(); ' + RM + '}\n',
    HEAD + 'const HOME = mkdtempSync("x");\nfunction wipe(HOME) { ' + RM + '}\nwipe(os.homedir());\n',
    HEAD + 'const HOME = mkdtempSync("x");\nconst wipe = (HOME) => ' + RM + 'wipe(os.homedir());\n',
    HEAD + 'const HOME = mkdtempSync("x");\nclass A { w(HOME) { ' + RM + '} }\nnew A().w(os.homedir());\n',
    HEAD + 'const HOME = mkdtempSync("x");\nprocess.env.HOME = os.homedir();\n({ HOME } = process.env);\n' + RM,
    HEAD + 'const HOME = mkdtempSync("x");\nfor (const HOME of [os.homedir()]) ' + RM,
    HEAD + 'const HOME = mkdtempSync("x");\ntry { throw os.homedir() } catch (HOME) { ' + RM + '}\n',
    HEAD + 'const HOME = mkdtempSync("x");\neval("HOME = os.homedir()");\n' + RM,
    HEAD + 'const HOME = mkdtempSync("x");\n' + RM + 'rmSync(process.env.HOME, { recursive: true });\n',
    HEAD + 'const home = os.homedir();\nrmSync(home, { recursive: true });\n',
])
def test_real_home_wipes_still_reported(tmp_path, text):
    assert _deadman(tmp_path, text)


# --- capability findings -------------------------------------------------------

def _cap(rule, path, sev="high"):
    return {"scanner": "skill_threats", "rule_id": rule, "severity": sev, "file": path,
            "title": "Accessing user home directories", "category": "scope-escalation",
            "line": 3, "snippet": "~/x"}


def test_capability_in_code_without_outbound_graded_low():
    findings = [_cap("ST-SP-002", "a.py"),
                {"scanner": "skill_threats", "rule_id": "ST-EX-008", "severity": "low",
                 "file": "a.py", "title": "Environment variable access",
                 "category": "credential-exfiltration"}]
    agg.apply_capability_caps(findings)
    f = findings[0]
    assert f["severity"] == "low" and f["original_severity"] == "high" and f["capability"]
    assert any(m.get("title") == "Capability findings graded to LOW" for m in findings)


@pytest.mark.parametrize("sink", [
    {"title": "Potential Data Exfiltration", "category": "exfiltration"},
    {"title": "Outbound network request", "category": "network"},
    {"title": "Lethal Trifecta (exec + network + credential read)", "category": "lethal-trifecta"},
    {"title": "Webhook URL", "category": "webhook"},
])
def test_capability_next_to_outbound_keeps_severity(sink):
    findings = [_cap("ST-SP-002", "a.py"), dict(sink, scanner="x", severity="medium", file="a.py")]
    agg.apply_capability_caps(findings)
    assert findings[0]["severity"] == "high"


def test_capability_in_agent_instructions_keeps_severity():
    findings = [_cap("ST-SP-005", "skills/x/SKILL.md")]
    agg.apply_capability_caps(findings)
    assert findings[0]["severity"] == "high"


def test_credential_rules_never_capped():
    findings = [_cap("ST-EX-004", "a.py", "critical"), _cap("ST-CR-002", "a.py")]
    agg.apply_capability_caps(findings)
    assert [f["severity"] for f in findings] == ["critical", "high"]


def test_postgres_word_is_not_an_outbound_sink():
    findings = [_cap("ST-SP-002", "a.py"),
                {"scanner": "secrets", "title": "PostgreSQL Connection URI", "category": "secret",
                 "severity": "high", "file": "a.py"}]
    agg.apply_capability_caps(findings)
    assert findings[0]["severity"] == "low"


# --- identical copies ------------------------------------------------------------

def _f(path, **kw):
    base = {"scanner": "sast", "rule_id": "R1", "title": "t", "severity": "high",
            "line": 2, "snippet": "x", "category": "c", "file": path}
    base.update(kw)
    return base


def test_identical_copies_collapse_with_every_path_listed(tmp_path):
    for d in ("a", "b/c", "z"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "m.py").write_text("x = 1\n")
    out = agg.collapse_identical_copies(
        [_f("z/m.py"), _f("a/m.py"), _f("b/c/m.py")], str(tmp_path))
    assert len(out) == 1
    assert out[0]["file"] == "a/m.py" and out[0]["also_in"] == ["b/c/m.py", "z/m.py"]
    assert out[0]["severity"] == "high"


def test_near_copies_do_not_collapse(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("x = 1  # changed\n")
    out = agg.collapse_identical_copies([_f("a.py"), _f("b.py")], str(tmp_path))
    assert len(out) == 2


def test_different_findings_on_identical_files_do_not_collapse(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("x = 1\n")
    out = agg.collapse_identical_copies([_f("a.py"), _f("b.py", line=3)], str(tmp_path))
    assert len(out) == 2


def test_symlinked_copy_never_collapses(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    os.symlink("a.py", tmp_path / "b.py")
    out = agg.collapse_identical_copies([_f("a.py"), _f("b.py")], str(tmp_path))
    assert len(out) == 2


def test_meta_findings_without_file_untouched(tmp_path):
    meta = {"scanner": "meta", "title": "m", "severity": "medium", "file": ""}
    out = agg.collapse_identical_copies([dict(meta), dict(meta)], str(tmp_path))
    assert len(out) == 2


# --- dependency freshness budget ----------------------------------------------

@pytest.fixture
def freshness_state():
    saved = dict(scan_dependencies._FRESHNESS_STATE)
    scan_dependencies._FRESHNESS_STATE.update(
        enabled=True, offline=False, queried=set(), query_count=0, max_queries=100,
        started_at=None, time_skipped=0)
    yield scan_dependencies._FRESHNESS_STATE
    scan_dependencies._FRESHNESS_STATE.clear()
    scan_dependencies._FRESHNESS_STATE.update(saved)


def test_freshness_stops_at_time_budget(freshness_state, monkeypatch):
    calls = []

    def slow_fetch(name, version, offline=False):
        calls.append(name)
        return None
    import vuln_feed
    monkeypatch.setattr(vuln_feed, "fetch_npm_freshness", slow_fetch)
    freshness_state["time_budget_s"] = 0.0
    freshness_state["started_at"] = time.monotonic() - 1
    findings = scan_dependencies._check_freshness(
        "npm", {f"obscure-pkg-{i}": "1.0.0" for i in range(5)}, "package.json")
    assert calls == []
    cap = [f for f in findings if f.title == "Freshness check time limit reached"]
    assert len(cap) == 1 and "5 packages" in cap[0].description


def test_cap_notices_merge_into_one(freshness_state):
    core = scan_dependencies.core
    mk = lambda path, n: core.Finding(
        scanner="dependencies", severity="medium", title="Freshness check query limit reached",
        description=f"{n} packages skipped due to 100 query limit.", file=path, line=0,
        snippet="", category="freshness-query-cap")
    other = core.Finding(scanner="dependencies", severity="high", title="x", description="",
                         file="p", line=0, snippet="", category="ioc")
    out = scan_dependencies._merge_freshness_cap_findings([mk("a/package.json", 3), other,
                                                           mk("b/package-lock.json", 4)])
    caps = [f for f in out if f.category == "freshness-query-cap"]
    assert len(caps) == 1 and caps[0].description.startswith("7 packages")
    assert "a/package.json" in caps[0].description and "b/package-lock.json" in caps[0].description
    assert other in out


# --- bytecode: stale caches and primitives already in source ----------------------

def _compile(directory, code, name="mod"):
    src = directory / f"{name}.py"
    src.write_text(code)
    pyc = directory / f"{name}.pyc"
    py_compile.compile(str(src), cfile=str(pyc), doraise=True)
    return src, pyc


def test_stale_cache_with_extra_markers_is_low(tmp_path):
    src, pyc = _compile(tmp_path, "import json\nx = json.loads('1')\n")
    src.write_text("x = 1  # loads removed in a later edit\n".replace("loads", "parse"))
    os.utime(src, (time.time() + 100, time.time() + 100))
    findings = scan_bytecode.scan_pyc(str(pyc), "mod.pyc")
    assert not [f for f in findings if f.severity in ("high", "critical")]
    assert any(f.category == "bytecode-stale" for f in findings)


def test_header_valid_poison_with_new_marker_is_high(tmp_path):
    # `run` is one of the names newly diffed against source.
    src, pyc = _compile(tmp_path, "import subprocess\nsubprocess.run(['id'])\n")
    src.write_text("x = 1\n")
    st = os.stat(src)
    raw = bytearray(pyc.read_bytes())
    raw[8:16] = struct.pack("<II", int(st.st_mtime) & 0xFFFFFFFF, st.st_size & 0xFFFFFFFF)
    pyc.write_bytes(bytes(raw))
    findings = scan_bytecode.scan_pyc(str(pyc), "mod.pyc")
    poison = [f for f in findings if f.category == "bytecode-poisoning"]
    assert poison and poison[0].severity == "high"


def test_hash_based_pyc_never_treated_as_stale(tmp_path):
    src, pyc = _compile(tmp_path, "x = 1\n")
    raw = bytearray(pyc.read_bytes())
    raw[4:8] = struct.pack("<I", 1)  # unchecked-hash pyc: always loaded
    pyc.write_bytes(bytes(raw))
    src.write_text("x = 2  # different\n")
    assert scan_bytecode._pyc_is_stale(pyc.read_bytes(), str(src)) is False


@pytest.mark.skipif(not hasattr(scan_bytecode, "_disassemble_best"), reason="no disassembler")
def test_primitives_already_in_source_are_low(tmp_path):
    _compile(tmp_path, "import subprocess\nsubprocess.run(['id'])\n")
    findings = scan_bytecode.scan_pyc(str(tmp_path / "mod.pyc"), "mod.pyc")
    assert not [f for f in findings if f.severity in ("high", "critical")]
    assert not [f for f in findings if f.title.startswith("Hidden logic in bytecode")]
    if sys.platform in ("darwin", "linux"):
        # Proves the reader parsed this interpreter's bytecode (3.15 included)
        # rather than falling back to "opaque bytecode".
        assert any(f.title.startswith("Bytecode primitive (also in source)") for f in findings)


def test_import_names_decoded_on_this_interpreter(tmp_path):
    if sys.platform not in ("darwin", "linux"):
        pytest.skip("disassembly requires macOS Seatbelt or Linux seccomp")
    _, pyc = _compile(tmp_path, "import os, socket\nimport a.b as x\nfrom z import y\n")
    blob, err = scan_bytecode._disassemble_best(str(pyc), 16)
    assert err is None
    _, _, imported = scan_bytecode._parse_blob(blob)
    assert {"os", "socket", "a.b", "z"} <= imported


# --- shell variables are case-sensitive -------------------------------------------

@pytest.mark.parametrize("name,text,want", [
    ("tmp_lower.sh", 'home=$(mktemp -d)\nrm -rf "$home"\n', False),
    ("real_HOME.sh", 'rm -rf "$HOME"\n', True),
    ("real_braced.sh", "rm -rf ${HOME}\n", True),
    ("tilde.sh", "rm -rf ~\n", True),
    ("mixed_line.sh", 'rm -rf "$home"; rm -rf $HOME\n', True),
    ("ps_lower.ps1", "rm -r -f $home\n", True),
    ("del_profile.bat", "del /s /q %USERPROFILE%\n", True),
])
def test_shell_home_wipe_is_case_exact_outside_powershell(tmp_path, name, text, want):
    p = tmp_path / name
    p.write_text(text)
    got = any(f.title.startswith("Dead-Man's Switch")
              for f in scan_lifecycle.scan_second_coming_indicators(str(p), name))
    assert got is want


def test_sarif_keeps_one_result_per_identical_copy():
    import sarif_export
    finding = _f("a/m.py")
    finding["also_in"] = ["b/m.py", "c/m.py"]
    sarif = sarif_export.report_to_sarif({"findings": [finding], "suppressed": []})
    uris = sorted(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                  for r in sarif["runs"][0]["results"])
    assert uris == ["a/m.py", "b/m.py", "c/m.py"]
