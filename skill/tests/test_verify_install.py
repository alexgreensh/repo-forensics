"""Tests for verify_install.py."""

import json

import verify_install as verifier


def test_generate_and_verify_checksums_round_trip(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "scan.py").write_text("print('ok')\n")
    (tmp_path / "SKILL.md").write_text("# Skill\n")

    verifier.generate_checksums(str(tmp_path))
    passed, report = verifier.verify_checksums(str(tmp_path))

    assert passed
    assert report[0].startswith("[+] VERIFIED:")


def test_generate_checksums_ignores_ds_store(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "scan.py").write_text("print('ok')\n")
    (tmp_path / ".DS_Store").write_text("finder metadata")

    verifier.generate_checksums(str(tmp_path))

    with open(tmp_path / "checksums.json", "r", encoding="utf-8") as handle:
        data = json.load(handle)

    assert ".DS_Store" not in data["files"]
    assert data["file_count"] == 1
