"""Regression test for the git gpg.program RCE (fix/gpg-rce-hotfix, v2.14.9).

A repository under audit controls its own .git/config. Config keys such as
`gpg.program` name an external program git executes during ordinary read-only
operations: the `%G?` pretty format / `--show-signature` makes `git log` run
gpg.program to verify each commit's signature. The scanner runs inside the
untrusted tree, so before the fix, merely scanning a hostile repo whose config
set `gpg.program` to an attacker script executed that script -- a critical RCE
with the scan reporting nothing.

These tests build such a hostile repo (a commit carrying a gpgsig header, and a
gpg.program pointed at a marker-writing script) and assert the scanner never
runs it. They cover the direct scanner (scan_git_forensics), the shared
hardened runner (forensics_core.run_git_hardened), and the verify_install
ls-files path (core.fsmonitor is the exec-capable key there).
"""

import os
import subprocess

import forensics_core as core
import scan_git_forensics as scanner


def _git(path, *args):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(path)}
    return subprocess.run(
        ["git", "-C", str(path), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True, capture_output=True, text=True, env=env,
    ).stdout.strip()


def _hostile_repo(tmp_path, marker):
    """A git repo whose .git/config arms gpg.program (and core.fsmonitor) with a
    script that writes *marker*, and whose HEAD commit carries a gpgsig header so
    signature verification would be attempted."""
    repo = tmp_path / "hostile"
    repo.mkdir()
    _git(repo, "init")

    payload = tmp_path / "payload.sh"
    payload.write_text(
        "#!/bin/sh\n"
        f'printf pwned > "{marker}"\n'
        # exit 0 so a signature check that DID run would look "good"
        "exit 0\n"
    )
    payload.chmod(0o755)

    (repo / "SKILL.md").write_text("---\nname: x\ndescription: y\n---\nhi\n")
    _git(repo, "add", "SKILL.md")
    tree = _git(repo, "write-tree")

    # Hand-build a commit object carrying a gpgsig header, so git treats HEAD as
    # signed and invokes gpg.program on %G? / --show-signature. No real gpg key
    # is needed to trigger the invocation.
    commit_body = (
        f"tree {tree}\n"
        "author A <a@a> 1700000000 +0000\n"
        "committer A <a@a> 1700000000 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n"
        " \n"
        " iQEzBAABCAAdFiEE\n"
        " -----END PGP SIGNATURE-----\n"
        "\nsigned\n"
    )
    commit_file = tmp_path / "commit.txt"
    commit_file.write_bytes(commit_body.encode("ascii"))
    with open(commit_file, "rb") as fh:
        sha = subprocess.run(
            ["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"],
            check=True, capture_output=True, text=True, stdin=fh,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(repo)},
        ).stdout.strip()
    _git(repo, "update-ref", "refs/heads/master", sha)
    _git(repo, "symbolic-ref", "HEAD", "refs/heads/master")

    # Arm the exec-capable config keys, using both an absolute and an in-tree
    # relative program path.
    _git(repo, "config", "gpg.program", str(payload))
    _git(repo, "config", "core.fsmonitor", str(payload))
    return repo


def test_scan_git_forensics_does_not_execute_repo_gpg_program(tmp_path):
    marker = tmp_path / "MARKER"
    repo = _hostile_repo(tmp_path, marker)

    commits = scanner.get_git_log(str(repo))
    findings = scanner.analyze_commits(commits, str(repo)) if commits else []
    findings += scanner.scan_replace_refs(str(repo))
    findings += scanner.scan_grafts(str(repo))

    assert not marker.exists(), (
        "scanning a hostile repo executed its gpg.program/core.fsmonitor -- RCE"
    )
    # The scan must still complete and return a list (not crash on the tree).
    assert isinstance(findings, list)


def test_run_git_hardened_does_not_execute_repo_gpg_program(tmp_path):
    marker = tmp_path / "MARKER_HARDENED"
    repo = _hostile_repo(tmp_path, marker)

    # Even explicitly asking for signature status must not run the repo program,
    # because the hardened runner overrides gpg.program.
    result = core.run_git_hardened(
        str(repo), "log", "--show-signature", "--pretty=format:%H%x00%G?", "-n", "10",
    )
    assert result is not None
    assert not marker.exists(), (
        "run_git_hardened let the repo's gpg.program execute during verification"
    )


def test_verify_install_ls_files_does_not_execute_fsmonitor(tmp_path):
    import verify_install

    marker = tmp_path / "MARKER_LSFILES"
    repo = _hostile_repo(tmp_path, marker)

    files = verify_install.get_tracked_files(str(repo))

    assert not marker.exists(), (
        "verify_install git ls-files executed the repo's core.fsmonitor -- RCE"
    )
    assert isinstance(files, list)
