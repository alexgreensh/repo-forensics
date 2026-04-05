"""Tests for verify_install.py symlink integrity tracking.

Added 2026-04-05 after torture-room security-sentinel Finding 3.

The backward-compat `skill` symlink at the repo root points into
skills/repo-forensics/ but lives outside what get_tracked_files walks.
Without the symlink integrity check added in verify_install.py, an
attacker could ship a poisoned fork or tarball that replaces the
symlink target (e.g., skill -> /tmp/evil/ instead of
skills/repo-forensics/) and verification would still pass.

These tests exercise the full tamper-detection path: build a minimal
repo-like structure with a skill root and a root-level symlink, generate
checksums, tamper the symlink, and assert verification fails.
"""

import json
import os
import sys

import pytest

# The scripts dir is on sys.path via conftest.
import verify_install


def _build_fake_repo(tmp_path, include_symlink=True, symlink_target="skills/repo-forensics"):
    """Build a minimal repo root + skill root + optional root symlink.

    Layout:
        tmp_path/
            skills/
                repo-forensics/
                    scripts/
                        verify_install.py  (copy)
                        forensics_core.py  (copy)
                    SKILL.md
                    data/
                        something.json
            skill -> skills/repo-forensics  (optional)
    """
    skill_root = tmp_path / "skills" / "repo-forensics"
    skill_root.mkdir(parents=True)

    # Minimal file tree
    (skill_root / "SKILL.md").write_text("# Test Skill\n")
    (skill_root / "data").mkdir()
    (skill_root / "data" / "something.json").write_text('{"k":"v"}')
    (skill_root / "scripts").mkdir()
    (skill_root / "scripts" / "noop.py").write_text("pass\n")

    if include_symlink:
        os.symlink(symlink_target, tmp_path / "skill")

    return str(skill_root)


class TestSymlinkTracking:
    """Symlink integrity tracking in verify_install.py."""

    def test_get_tracked_symlinks_finds_inward_pointing_symlink(self, tmp_path):
        skill_root = _build_fake_repo(tmp_path)
        repo_root = str(tmp_path)
        symlinks = verify_install.get_tracked_symlinks(repo_root, skill_root)
        assert "skill" in symlinks
        assert symlinks["skill"] == "skills/repo-forensics"

    def test_get_tracked_symlinks_ignores_outward_pointing_symlink(self, tmp_path):
        """Symlinks pointing outside skill_root are not in our domain."""
        skill_root = _build_fake_repo(tmp_path, include_symlink=False)
        # Create an outward-pointing symlink
        outside = tmp_path / "outside_target"
        outside.mkdir()
        os.symlink("outside_target", tmp_path / "rogue")

        repo_root = str(tmp_path)
        symlinks = verify_install.get_tracked_symlinks(repo_root, skill_root)
        assert "rogue" not in symlinks, (
            "Symlinks whose targets resolve outside skill_root must NOT be "
            "tracked. They are outside our security domain."
        )

    def test_get_tracked_symlinks_handles_missing_repo_root(self, tmp_path):
        skill_root = _build_fake_repo(tmp_path, include_symlink=False)
        # Point repo_root at a nonexistent path
        result = verify_install.get_tracked_symlinks("/nonexistent/path", skill_root)
        assert result == {}

    def test_generate_checksums_includes_symlink(self, tmp_path, monkeypatch):
        """Generate step writes symlink into checksums.json."""
        skill_root = _build_fake_repo(tmp_path)
        verify_install.generate_checksums(skill_root)

        checksums_path = os.path.join(skill_root, "checksums.json")
        with open(checksums_path) as f:
            data = json.load(f)

        assert "repo_symlinks" in data
        assert data["repo_symlinks"]["skill"] == "skills/repo-forensics"
        assert data["symlink_count"] == 1

    def test_verify_passes_when_symlink_matches(self, tmp_path):
        """Happy path: generate + verify on same tree should pass."""
        skill_root = _build_fake_repo(tmp_path)
        verify_install.generate_checksums(skill_root)
        passed, report = verify_install.verify_checksums(skill_root)
        assert passed, f"Verification should pass. Report:\n" + "\n".join(report)

    def test_verify_fails_when_symlink_target_tampered(self, tmp_path):
        """Tamper attack: attacker replaces skill symlink target."""
        skill_root = _build_fake_repo(tmp_path)
        verify_install.generate_checksums(skill_root)

        # Simulate tamper: remove the legitimate symlink and plant a new one
        # pointing at a different location (still inside skill_root to keep
        # it in our tracking domain, but with a different target string).
        os.remove(tmp_path / "skill")
        # Create a decoy target inside skill_root
        decoy = tmp_path / "skills" / "decoy"
        decoy.mkdir()
        (decoy / "SKILL.md").write_text("# Decoy\n")
        os.symlink("skills/decoy", tmp_path / "skill")

        passed, report = verify_install.verify_checksums(skill_root)
        # The symlink check should detect tampering — but the new target
        # points outside skill_root (skills/decoy is not in skills/repo-forensics)
        # so get_tracked_symlinks won't include it in current_symlinks.
        # That makes it appear as "missing", which still counts as tamper.
        # Either way, verification must fail.
        assert not passed, (
            "Verification must fail when the skill symlink target is "
            "tampered. If this passes, the torture-room security-sentinel "
            "Finding 3 attack vector is live again."
        )
        report_text = "\n".join(report)
        assert ("SYMLINK" in report_text or "FAILED" in report_text), (
            f"Failure report must mention the symlink tamper. Got:\n{report_text}"
        )

    def test_verify_fails_when_symlink_deleted(self, tmp_path):
        """Deletion attack: attacker removes the backward-compat symlink."""
        skill_root = _build_fake_repo(tmp_path)
        verify_install.generate_checksums(skill_root)

        # Delete the symlink
        os.remove(tmp_path / "skill")

        passed, report = verify_install.verify_checksums(skill_root)
        assert not passed
        report_text = "\n".join(report)
        assert "MISSING" in report_text or "FAILED" in report_text

    def test_verify_reports_new_unexpected_symlink(self, tmp_path):
        """A new symlink appearing after manifest generation is flagged."""
        skill_root = _build_fake_repo(tmp_path, include_symlink=False)
        verify_install.generate_checksums(skill_root)

        # Now add a new symlink pointing into skill_root
        os.symlink("skills/repo-forensics", tmp_path / "sneaky")

        passed, report = verify_install.verify_checksums(skill_root)
        report_text = "\n".join(report)
        # New symlinks don't fail verification (they're extra, not tampered),
        # but they must be reported for human review.
        assert "NEW SYMLINK" in report_text or "sneaky" in report_text
