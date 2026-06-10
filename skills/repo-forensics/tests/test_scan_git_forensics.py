"""Tests for scan_git_forensics.py — git replace objects and grafts detection."""

import os
import subprocess
import scan_git_forensics as scanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _init_git_repo(path):
    """Create a minimal real git repo so git for-each-ref works."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(path)}
    subprocess.run(
        ["git", "init", str(path)], check=True, capture_output=True, env=env
    )
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "test@test.com"],
        check=True, capture_output=True, env=env,
    )
    subprocess.run(
        ["git", "-C", str(path), "config", "user.name", "Test"],
        check=True, capture_output=True, env=env,
    )
    subprocess.run(
        ["git", "-C", str(path), "commit", "--allow-empty", "-m", "init"],
        check=True, capture_output=True, env=env,
    )


def _add_replace_ref(path):
    """Add a real git replace ref using two real empty commits and git replace.

    git for-each-ref validates that the target object exists, so we must use
    real commit objects. We create a second commit and replace the first with
    it using 'git replace', which writes .git/refs/replace/<orig-sha>.
    """
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(path)}
    subprocess.run(
        ["git", "-C", str(path), "commit", "--allow-empty", "-m", "replacement-target"],
        check=True, capture_output=True, env=env,
    )
    # HEAD is the new commit; HEAD~1 is the original to be replaced
    orig = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD~1"],
        check=True, capture_output=True, text=True, env=env,
    ).stdout.strip()
    repl = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, env=env,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(path), "replace", orig, repl],
        check=True, capture_output=True, env=env,
    )


# ---------------------------------------------------------------------------
# scan_replace_refs
# ---------------------------------------------------------------------------

class TestScanReplaceRefs:
    """Tests for replace object detection via refs/replace/."""

    def test_repo_with_replace_refs_triggers_critical(self, tmp_path):
        """A repo that has refs/replace/ entries must produce a critical finding."""
        _init_git_repo(tmp_path)
        _add_replace_ref(tmp_path)

        findings = scanner.scan_replace_refs(str(tmp_path))
        assert len(findings) > 0, (
            "A repo with refs/replace/ entries must trigger scan_replace_refs findings."
        )
        assert findings[0].severity == "critical"
        assert findings[0].category == "git-history-tampering"
        assert "replace" in findings[0].title.lower()

    def test_clean_repo_no_replace_refs(self, tmp_path):
        """A repo without refs/replace/ must produce no findings."""
        _init_git_repo(tmp_path)

        # Sanity: no refs/replace/ directory at all
        assert not (tmp_path / ".git" / "refs" / "replace").exists()

        findings = scanner.scan_replace_refs(str(tmp_path))
        assert len(findings) == 0, (
            "A clean repo with no replace refs must produce zero findings."
        )

    def test_not_a_git_repo_no_crash(self, tmp_path):
        """A directory without git must not crash — CalledProcessError is caught."""
        findings = scanner.scan_replace_refs(str(tmp_path))
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_finding_references_replace_path(self, tmp_path):
        """Finding file path should reference refs/replace/ for auditor clarity."""
        _init_git_repo(tmp_path)
        _add_replace_ref(tmp_path)

        findings = scanner.scan_replace_refs(str(tmp_path))
        assert len(findings) > 0
        assert "replace" in findings[0].file.lower()


# ---------------------------------------------------------------------------
# scan_grafts
# ---------------------------------------------------------------------------

class TestScanGrafts:
    """Tests for .git/info/grafts detection."""

    def test_repo_with_grafts_file_triggers_high(self, tmp_path):
        """A non-empty grafts file must produce a high-severity finding."""
        git_info = tmp_path / ".git" / "info"
        git_info.mkdir(parents=True, exist_ok=True)
        grafts = git_info / "grafts"
        # A graft line: <commit-sha> <parent-sha>
        grafts.write_text("aabbccdd" * 5 + " " + "11223344" * 5 + "\n")

        findings = scanner.scan_grafts(str(tmp_path))
        assert len(findings) > 0, (
            "A repo with a non-empty grafts file must trigger scan_grafts findings."
        )
        assert findings[0].severity == "high"
        assert findings[0].category == "git-history-tampering"
        assert "graft" in findings[0].title.lower()

    def test_empty_grafts_file_no_finding(self, tmp_path):
        """An empty grafts file must not trigger a finding."""
        git_info = tmp_path / ".git" / "info"
        git_info.mkdir(parents=True, exist_ok=True)
        (git_info / "grafts").write_text("")

        findings = scanner.scan_grafts(str(tmp_path))
        assert len(findings) == 0, (
            "An empty grafts file must not trigger a finding — no graft entries present."
        )

    def test_comment_only_grafts_file_no_finding(self, tmp_path):
        """A grafts file with only comments must not trigger a finding."""
        git_info = tmp_path / ".git" / "info"
        git_info.mkdir(parents=True, exist_ok=True)
        (git_info / "grafts").write_text("# This is a comment\n# Another comment\n")

        findings = scanner.scan_grafts(str(tmp_path))
        assert len(findings) == 0

    def test_missing_grafts_file_no_finding(self, tmp_path):
        """A repo without a grafts file must produce no findings."""
        git_info = tmp_path / ".git" / "info"
        git_info.mkdir(parents=True, exist_ok=True)
        # Deliberately do NOT create a grafts file

        findings = scanner.scan_grafts(str(tmp_path))
        assert len(findings) == 0, (
            "Absence of .git/info/grafts must produce zero findings."
        )

    def test_finding_file_path_is_grafts(self, tmp_path):
        """Finding file path must point to .git/info/grafts for auditor clarity."""
        git_info = tmp_path / ".git" / "info"
        git_info.mkdir(parents=True, exist_ok=True)
        (git_info / "grafts").write_text("aabbccdd" * 5 + " " + "11223344" * 5 + "\n")

        findings = scanner.scan_grafts(str(tmp_path))
        assert len(findings) > 0
        assert "grafts" in findings[0].file.lower()

    def test_multiple_grafts_count_reported(self, tmp_path):
        """Description should mention the number of graft entries."""
        git_info = tmp_path / ".git" / "info"
        git_info.mkdir(parents=True, exist_ok=True)
        lines = "\n".join(
            [f"{'aabbccdd' * 5} {'11223344' * 5}"] * 3
        )
        (git_info / "grafts").write_text(lines + "\n")

        findings = scanner.scan_grafts(str(tmp_path))
        assert len(findings) > 0
        assert "3" in findings[0].description


# ---------------------------------------------------------------------------
# Clean repo: neither replace refs nor grafts
# ---------------------------------------------------------------------------

class TestCleanGitRepo:
    """Integration check: a clean real git repo triggers neither detector."""

    def test_clean_repo_no_tampering_findings(self, tmp_path):
        """A clean git repo must produce zero history-tampering findings."""
        _init_git_repo(tmp_path)

        replace_findings = scanner.scan_replace_refs(str(tmp_path))
        graft_findings = scanner.scan_grafts(str(tmp_path))

        tampering = [
            f for f in replace_findings + graft_findings
            if f.category == "git-history-tampering"
        ]
        assert len(tampering) == 0, (
            f"Clean git repo must produce zero git-history-tampering findings. "
            f"Got: {[(f.title, f.description) for f in tampering]}"
        )
