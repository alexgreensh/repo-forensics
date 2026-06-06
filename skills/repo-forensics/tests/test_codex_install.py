import importlib.util
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
CODEX_INSTALL = REPO_ROOT / "scripts" / "codex_install.py"


def _load_codex_install():
    spec = importlib.util.spec_from_file_location("codex_install_under_test", CODEX_INSTALL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_hooks(codex_home):
    return json.loads((codex_home / "hooks.json").read_text())


def _external_hook(command="echo external"):
    return {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": command,
                "timeout": 5,
            }
        ],
    }


def test_codex_install_writes_nested_hooks_schema(monkeypatch, tmp_path):
    codex_home = tmp_path / "codex"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    codex_install = _load_codex_install()

    assert codex_install.install() == 0

    data = _read_hooks(codex_home)
    assert isinstance(data.get("hooks"), dict)
    for event in codex_install.HOOK_EVENTS:
        assert event not in data
        assert event in data["hooks"]
        assert any(codex_install._is_ours(entry) for entry in data["hooks"][event])


def test_codex_install_preserves_existing_nested_hooks(monkeypatch, tmp_path):
    codex_home = tmp_path / "codex"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    codex_install = _load_codex_install()
    existing_post = _external_hook()
    existing_stop = _external_hook("echo stop")
    (codex_home / "hooks.json").write_text(json.dumps({
        "description": "keep me",
        "hooks": {
            "PostToolUse": [existing_post],
            "Stop": [existing_stop],
        },
    }))

    assert codex_install.install() == 0

    data = _read_hooks(codex_home)
    assert data["description"] == "keep me"
    assert existing_post in data["hooks"]["PostToolUse"]
    assert existing_stop in data["hooks"]["Stop"]
    assert any(codex_install._is_ours(entry) for entry in data["hooks"]["PostToolUse"])


def test_codex_install_cleans_legacy_top_level_repo_forensics_hooks(monkeypatch, tmp_path):
    codex_home = tmp_path / "codex"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    codex_install = _load_codex_install()
    legacy_repo_forensics = {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": 'CLAUDE_PLUGIN_ROOT="/tmp/repo-forensics" bash "/tmp/repo-forensics/hooks/run_pre_scan.sh"',
            }
        ],
    }
    unrelated_legacy = _external_hook()
    (codex_home / "hooks.json").write_text(json.dumps({
        "PreToolUse": [legacy_repo_forensics],
        "PostToolUse": [unrelated_legacy],
        "hooks": {
            "SessionStart": [_external_hook("echo nested session")],
        },
    }))

    assert codex_install.install() == 0

    data = _read_hooks(codex_home)
    assert "PreToolUse" not in data
    assert data["PostToolUse"] == [unrelated_legacy]
    for event in codex_install.HOOK_EVENTS:
        legacy_entries = data.get(event, [])
        assert not any(codex_install._is_ours(entry) for entry in legacy_entries)
        assert any(codex_install._is_ours(entry) for entry in data["hooks"][event])


def test_codex_uninstall_removes_only_repo_forensics_nested_hooks(monkeypatch, tmp_path):
    codex_home = tmp_path / "codex"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    codex_install = _load_codex_install()
    external_pre = _external_hook()
    managed = codex_install._managed_hooks()
    (codex_home / "hooks.json").write_text(json.dumps({
        "hooks": {
            "PreToolUse": [external_pre] + managed["PreToolUse"],
            "PostToolUse": managed["PostToolUse"],
            "SessionStart": managed["SessionStart"],
        },
    }))

    assert codex_install.uninstall() == 0

    data = _read_hooks(codex_home)
    assert data == {"hooks": {"PreToolUse": [external_pre]}}


def test_codex_plugin_manifest_points_to_nested_hooks_schema():
    plugin = json.loads((REPO_ROOT / ".codex-plugin" / "plugin.json").read_text())
    hooks_path = REPO_ROOT / plugin["hooks"]
    hook_data = json.loads(hooks_path.read_text())

    assert isinstance(hook_data.get("hooks"), dict)
    for event in ("PreToolUse", "PostToolUse", "SessionStart"):
        assert event in hook_data["hooks"]
        assert event not in {key for key in hook_data.keys() if key != "hooks"}


def test_codex_install_session_start_matches_marketplace_hook_commands(monkeypatch, tmp_path):
    codex_home = tmp_path / "codex"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    codex_install = _load_codex_install()

    assert codex_install.install() == 0

    data = _read_hooks(codex_home)
    session_commands = [
        hook["command"]
        for entry in data["hooks"]["SessionStart"]
        for hook in entry["hooks"]
    ]
    assert any("run_session_scan.sh" in command for command in session_commands)
    assert any("first-run-nudge.sh" in command for command in session_commands)


def test_codex_verify_can_require_registration_state(monkeypatch, tmp_path):
    codex_home = tmp_path / "codex"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    codex_install = _load_codex_install()
    assert codex_install.install() == 0
    hooks_path = codex_home / "hooks.json"
    state_blocks = "\n".join(
        f'[hooks.state."{hooks_path}:{event}:0:0"]\ntrusted = true\n'
        for event in ("pre_tool_use", "post_tool_use", "session_start")
    )
    (codex_home / "config.toml").write_text(state_blocks)

    assert codex_install.verify(require_registered=True) == 0
