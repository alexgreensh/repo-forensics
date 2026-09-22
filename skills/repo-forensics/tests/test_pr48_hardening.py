"""Regression tests for the PR #48 hardening pass.

Maps to overnight-2026-09-22/findings/pr-48.md:
  CRITICAL  scan_git_forensics git calls no longer execute a repo's gpg.program
            / core.fsmonitor (the %G? RCE, now also reachable in --skill-scan)
  MED       coverage-gap FP on a bare catalog manifest; installer "verified"
            check scoped to the checkout's own flow (whole-file FN closed)
  LOW       vendored dirs pruned from the pin walk
"""

import os
import json
import subprocess

import forensics_core as core
import scan_git_forensics as gitf


def _run(repo, *args):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t",
                           "-c", "user.name=t", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def _hostile_signed_repo(tmp_path, marker):
    """An agent-plugin git repo whose .git/config arms gpg.program AND
    core.fsmonitor with a marker-writing script, and whose HEAD commit carries a
    gpgsig header so `%G?` would attempt signature verification."""
    repo = tmp_path / "plug"
    repo.mkdir()
    _run(repo, "init")
    payload = tmp_path / "payload.sh"
    payload.write_text("#!/bin/sh\nprintf pwned > '%s'\nexit 0\n" % marker)
    payload.chmod(0o755)
    (repo / "SKILL.md").write_text("---\nname: x\ndescription: y\n---\nhi\n")
    _run(repo, "add", "SKILL.md")
    tree = _run(repo, "write-tree")
    commit_body = (
        f"tree {tree}\n"
        "author A <a@a> 1700000000 +0000\n"
        "committer A <a@a> 1700000000 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEz\n"
        " -----END PGP SIGNATURE-----\n\nsigned\n"
    )
    cf = tmp_path / "commit.txt"
    cf.write_text(commit_body)
    with open(cf, "rb") as fh:
        sha = subprocess.run(
            ["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"],
            check=True, capture_output=True, text=True, stdin=fh).stdout.strip()
    _run(repo, "update-ref", "refs/heads/main", sha)
    _run(repo, "symbolic-ref", "HEAD", "refs/heads/main")
    _run(repo, "config", "gpg.program", str(payload))
    _run(repo, "config", "core.fsmonitor", str(payload))
    return repo


class TestGpgRceHardening:
    def test_get_git_log_does_not_execute_repo_gpg_program(self, tmp_path):
        marker = tmp_path / "MARKER"
        repo = _hostile_signed_repo(tmp_path, marker)
        gitf.get_git_log(str(repo))
        gitf.scan_replace_refs(str(repo))
        gitf.scan_plugin_checkout_provenance(str(repo))
        assert not marker.exists(), "scanning a hostile repo executed its gpg.program/fsmonitor -- RCE"

    def test_hardened_signature_verify_is_inert(self, tmp_path):
        marker = tmp_path / "MARKER2"
        repo = _hostile_signed_repo(tmp_path, marker)
        # Even an explicit signature-verifying invocation must not run the repo program.
        core.run_git_hardened(str(repo), "log", "--show-signature",
                              "--pretty=format:%H%x00%G?", "-n", "5")
        assert not marker.exists()


class TestCoverageGapFalsePositive:
    def _plugin_repo(self, tmp_path):
        repo = tmp_path / "p"
        repo.mkdir()
        _run(repo, "init")
        (repo / "SKILL.md").write_text("---\nname: x\n---\n")
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", "x")
        return repo

    def test_bare_marketplace_catalog_is_clean(self, tmp_path):
        repo = self._plugin_repo(tmp_path)
        (repo / "marketplace.json").write_text(json.dumps(
            {"plugins": [{"name": "x", "source": "https://e/x"}]}))
        titles = {f.title for f in gitf.scan_plugin_checkout_provenance(str(repo))}
        assert "Agent Plugin Provenance Pin Unavailable" not in titles
        assert "Agent Plugin Lockfile Missing Commit Pin" not in titles

    def test_lockfile_without_pin_is_low(self, tmp_path):
        repo = self._plugin_repo(tmp_path)
        (repo / "plugin-lock.json").write_text(json.dumps({"name": "x", "version": "1"}))
        gap = [f for f in gitf.scan_plugin_checkout_provenance(str(repo))
               if f.title == "Agent Plugin Lockfile Missing Commit Pin"]
        assert gap and all(f.severity == "low" for f in gap)

    def test_vendored_manifest_not_walked_for_pins(self, tmp_path):
        # A foreign pin in node_modules must not become the repo's pin.
        repo = self._plugin_repo(tmp_path)
        vend = repo / "node_modules" / "dep"
        vend.mkdir(parents=True)
        (vend / "plugin.json").write_text(json.dumps({"sha": "a" * 40}))
        pins, _ = gitf._recover_recorded_pins(str(repo))
        assert "a" * 40 not in pins


class TestInstallerHeuristicScoping:
    def _plugin_repo(self, tmp_path):
        repo = tmp_path / "p"
        repo.mkdir()
        _run(repo, "init")
        (repo / "SKILL.md").write_text("---\nname: x\n---\n")
        return repo

    def _install(self, tmp_path, body):
        repo = self._plugin_repo(tmp_path)
        (repo / "install.sh").write_text(body)
        return gitf.scan_plugin_installers(str(repo))

    def test_distant_tokens_do_not_excuse_unsafe_checkout(self, tmp_path):
        pad = "\n".join("do_step_%d work padding to exceed the window" % i for i in range(60))
        body = ("#!/bin/sh\ngit fetch origin $COMMIT_SHA\ngit checkout $COMMIT_SHA\n"
                + pad + "\n# far: sha == expected checked in ci\n"
                "log() { git rev-parse HEAD; }\ndie() { exit 1; }\n")
        titles = {f.title for f in self._install(tmp_path, body)}
        assert "Agent Plugin Installer Does Not Verify Resolved Commit" in titles

    def test_in_flow_verification_is_clean(self, tmp_path):
        body = ("#!/bin/sh\ngit fetch origin $PINNED_SHA\ngit checkout $PINNED_SHA\n"
                "actual=$(git rev-parse HEAD)\n"
                "[ \"$actual\" != \"$PINNED_SHA\" ] && exit 1\n")
        assert self._install(tmp_path, body) == []

    def test_fetch_head_is_high_not_critical(self, tmp_path):
        out = self._install(tmp_path, "#!/bin/sh\ngit fetch origin $SHA\ngit checkout FETCH_HEAD\n")
        fh = [f for f in out if f.title == "Agent Plugin Installer Trusts Ambiguous FETCH_HEAD"]
        assert fh and all(f.severity == "high" for f in fh)
