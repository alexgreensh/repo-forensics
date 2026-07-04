"""Tests for dead_anchors_extract.py — U1 anchor extraction (zero network)."""

import os

import pytest

import dead_anchors_extract as extract
import rule_loader


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return tmp_path


def _anchors(tmp_path):
    return extract.extract_anchors(str(tmp_path))


def _by_type(anchors, t):
    return [a for a in anchors if a.type == t]


# --- GitHub extraction -------------------------------------------------------

def test_github_url_extracts_owner_repo(tmp_path):
    _write(tmp_path, "SKILL.md", "source at github.com/torvalds/linux here")
    gh = _by_type(_anchors(tmp_path), "github")
    assert len(gh) == 1 and gh[0].owner == "torvalds" and gh[0].repo == "linux"


def test_github_shorthand_extracts_same_shape(tmp_path):
    _write(tmp_path, "SKILL.md", "install github:hexiaochun/seedance2-api now")
    gh = _by_type(_anchors(tmp_path), "github")
    assert len(gh) == 1 and gh[0].target == "hexiaochun/seedance2-api"


def test_reserved_word_owner_excluded(tmp_path):
    _write(tmp_path, "SKILL.md", "visit github.com/about for info")
    assert _by_type(_anchors(tmp_path), "github") == []


def test_npx_skills_does_not_double_fire(tmp_path):
    # Not an install verb, not github: prefixed -> extracts NOTHING.
    _write(tmp_path, "SKILL.md", "run npx skills hexiaochun/seedance2-api")
    anchors = _anchors(tmp_path)
    assert _by_type(anchors, "github") == []
    assert _by_type(anchors, "package") == []


def test_github_dedup_single_anchor(tmp_path):
    _write(tmp_path, "SKILL.md",
           "github.com/x/y\nlater again https://github.com/x/y done")
    assert len(_by_type(_anchors(tmp_path), "github")) == 1


# --- package extraction ------------------------------------------------------

def test_pip_install_strips_version(tmp_path):
    _write(tmp_path, "SKILL.md", "pip install requests==2.31.0")
    pk = _by_type(_anchors(tmp_path), "package")
    assert len(pk) == 1 and pk[0].ecosystem == "PyPI"
    assert pk[0].target == "PyPI:requests"


def test_npm_install_strips_flag_and_specifier(tmp_path):
    _write(tmp_path, "SKILL.md", "npm install --save lodash@^4.17.0")
    pk = _by_type(_anchors(tmp_path), "package")
    assert len(pk) == 1 and pk[0].target == "npm:lodash"


def test_gem_cargo_not_probed_in_p0(tmp_path):
    _write(tmp_path, "SKILL.md", "gem install rails\ncargo install ripgrep")
    # ecosystem=None entries are dropped from the returned set (not probed).
    assert _by_type(_anchors(tmp_path), "package") == []


def test_no_package_from_prose(tmp_path):
    _write(tmp_path, "SKILL.md", "we install the software manually")
    assert _by_type(_anchors(tmp_path), "package") == []


# --- domain / cloud extraction ----------------------------------------------

def test_bare_cloud_suffix_without_subdomain_excluded(tmp_path):
    _write(tmp_path, "SKILL.md", "hosted somewhere on https://vercel.app today")
    a = _anchors(tmp_path)
    assert _by_type(a, "cloud") == []
    # And it is not RDAP-probed as a bare domain either.
    assert _by_type(a, "domain") == []


def test_cloud_subdomain_flagged_free_tier(tmp_path):
    _write(tmp_path, "SKILL.md", "app at https://myapp.vercel.app/home")
    cl = _by_type(_anchors(tmp_path), "cloud")
    assert len(cl) == 1 and cl[0].suffix == "vercel.app" and cl[0].is_free_tier


def test_safe_domain_allowlist_skipped(tmp_path):
    _write(tmp_path, "SKILL.md", "docs https://docs.python.org/3/library/os.html")
    assert _by_type(_anchors(tmp_path), "domain") == []


def test_compound_tld_reduction(tmp_path):
    _write(tmp_path, "SKILL.md", "link https://sub.example.co.uk/x page")
    dm = _by_type(_anchors(tmp_path), "domain")
    assert len(dm) == 1 and dm[0].target == "example.co.uk"


def test_plain_domain_reduction(tmp_path):
    _write(tmp_path, "SKILL.md", "link https://a.b.example.com/x page")
    dm = _by_type(_anchors(tmp_path), "domain")
    assert len(dm) == 1 and dm[0].target == "example.com"


# --- discovery / robustness --------------------------------------------------

def test_reads_multiple_seed_files(tmp_path):
    _write(tmp_path, "SKILL.md", "github.com/a/b")
    (tmp_path / "AGENTS.md").write_text("pip install flask", encoding="utf-8")
    a = _anchors(tmp_path)
    assert _by_type(a, "github") and _by_type(a, "package")


def test_line_and_file_tracked(tmp_path):
    _write(tmp_path, "SKILL.md", "intro\nsee github.com/a/b\n")
    gh = _by_type(_anchors(tmp_path), "github")[0]
    assert gh.file == "SKILL.md" and gh.line == 2


def test_empty_repo_no_anchors(tmp_path):
    (tmp_path / "main.py").write_text("print('hi')", encoding="utf-8")
    assert _anchors(tmp_path) == []


# --- rulepack self-test ------------------------------------------------------

def test_rulepack_self_tests_pass():
    pack = rule_loader.load_pack("dead_anchors")
    assert pack is not None
    results = rule_loader.self_test_pack(pack)
    failed = [r for r in results if not r.passed]
    assert not failed, f"pack self-test failures: {failed}"
    assert len(pack.all_rules) == 8


# --- torture-room regressions ------------------------------------------------

def test_fifo_seed_file_is_skipped_no_hang(tmp_path):
    # A FIFO named SKILL.md (shippable inside a malicious tar/repo) must be
    # skipped, never opened for read — otherwise extract_anchors blocks forever
    # (python-redos F1). Hard watchdog: the call must complete well under 5s.
    import os
    import threading
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo unavailable on this platform")
    os.mkfifo(str(tmp_path / "SKILL.md"))
    (tmp_path / "AGENTS.md").write_text("github.com/live/repo", encoding="utf-8")
    # Preload the pack in the main thread (rule_loader's SIGALRM ReDoS guard only
    # works in the main thread); the watchdog thread just runs extraction.
    pack = rule_loader.load_pack("dead_anchors")
    result = {}

    def _run():
        result["anchors"] = extract.extract_anchors(str(tmp_path), pack=pack)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(5.0)
    assert not t.is_alive(), "extract_anchors hung on a FIFO seed file"
    # The FIFO is skipped; the real AGENTS.md is still processed.
    assert _by_type(result["anchors"], "github")


def test_malformed_pack_non_keyword_rule_no_crash(tmp_path):
    # A pack whose keyword id (DA-CL-001) is tampered into a non-keyword type
    # (rule.values is then None) must degrade to a no-op, never set(None) crash
    # (python-redos F2 / never-hard-fail).
    class _FakeRule:
        def __init__(self, rid, rtype, regex=None, values=None):
            self.id = rid
            self.type = rtype
            self.regex = regex
            self.values = values

    import re as _re

    class _FakePack:
        all_rules = [
            _FakeRule("DA-GH-001", "regex", regex=_re.compile(r"github\.com/(\w+)/(\w+)")),
            _FakeRule("DA-CL-001", "regex", regex=_re.compile(r"x")),  # tampered: no .values
        ]

    _write(tmp_path, "SKILL.md", "github.com/a/b")
    # Must not raise even though DA-CL-001 has values=None.
    anchors = extract.extract_anchors(str(tmp_path), pack=_FakePack())
    assert isinstance(anchors, list)


def test_github_case_variants_dedup_single_anchor(tmp_path):
    _write(tmp_path, "SKILL.md",
           "github.com/Torvalds/Linux\ngithub.com/torvalds/linux\n"
           "github.com/TORVALDS/LINUX")
    assert len(_by_type(_anchors(tmp_path), "github")) == 1


def test_pypi_separator_variants_dedup_single_anchor(tmp_path):
    _write(tmp_path, "SKILL.md",
           "pip install My_Package\npip install my-package\npip install my.package")
    assert len(_by_type(_anchors(tmp_path), "package")) == 1
