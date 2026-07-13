import json
from pathlib import Path

from validate_manifests import validate_manifests


REPO_ROOT = Path(__file__).resolve().parents[3]


def write_manifest(root, relative, content):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(content), encoding="utf-8")


def valid_root(tmp_path):
    write_manifest(tmp_path, ".claude-plugin/plugin.json", {
        "name": "repo-forensics", "version": "1.0.0", "author": {"name": "Example"},
    })


def errors_for(tmp_path):
    _, violations = validate_manifests(tmp_path)
    return ["{}: {}".format(item["field"], item["message"]) for item in violations]


def test_real_manifests_are_valid():
    _, violations = validate_manifests(REPO_ROOT)
    assert violations == []


def test_rejects_string_author(tmp_path):
    valid_root(tmp_path)
    write_manifest(tmp_path, ".codex-plugin/plugin.json", {
        "name": "repo-forensics", "version": "1.0.0", "author": "Example",
    })
    assert any("author: must be an object with a string name" in error for error in errors_for(tmp_path))


def test_rejects_string_marketplace_author_and_owner(tmp_path):
    valid_root(tmp_path)
    write_manifest(tmp_path, ".claude-plugin/marketplace.json", {
        "name": "example-marketplace", "owner": "Example", "plugins": [{
            "name": "repo-forensics", "version": "1.0.0", "author": "Example",
        }],
    })
    errors = errors_for(tmp_path)
    assert any("owner: must be an object" in error for error in errors)
    assert any("plugins[0].author: must be an object with a string name" in error for error in errors)


def test_rejects_invalid_json(tmp_path):
    valid_root(tmp_path)
    path = tmp_path / ".codex-plugin/plugin.json"
    path.parent.mkdir()
    path.write_text("{invalid", encoding="utf-8")
    assert any("JSON: invalid JSON" in error for error in errors_for(tmp_path))


def test_rejects_uppercase_or_space_name(tmp_path):
    valid_root(tmp_path)
    write_manifest(tmp_path, ".codex-plugin/plugin.json", {"name": "Bad Name", "version": "1.0.0"})
    assert any("name: must be kebab-case" in error for error in errors_for(tmp_path))


def test_rejects_reserved_name_prefix(tmp_path):
    valid_root(tmp_path)
    write_manifest(tmp_path, ".codex-plugin/plugin.json", {"name": "claude-tool", "version": "1.0.0"})
    assert any("name: must not start with claude-" in error for error in errors_for(tmp_path))


def test_rejects_version_drift(tmp_path):
    valid_root(tmp_path)
    write_manifest(tmp_path, ".codex-plugin/plugin.json", {"name": "repo-forensics", "version": "9.9.9"})
    assert any("version 9.9.9 does not match canonical version 1.0.0" in error for error in errors_for(tmp_path))
