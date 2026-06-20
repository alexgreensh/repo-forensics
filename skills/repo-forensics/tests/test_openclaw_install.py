"""Tests for scripts/openclaw_install.py."""

import importlib.util
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
OPENCLAW_INSTALL = REPO_ROOT / "scripts" / "openclaw_install.py"


def _load_openclaw_install():
    spec = importlib.util.spec_from_file_location("openclaw_install_under_test", OPENCLAW_INSTALL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_openclaw_install_preserves_security_install_policy(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({"security": {"installPolicy": "operator"}}))
    monkeypatch.setenv("OPENCLAW_HOME", str(home))

    openclaw_install = _load_openclaw_install()
    assert openclaw_install.install() == 0
    assert openclaw_install.verify() == 0

    data = json.loads(cfg.read_text())
    assert data["security"]["installPolicy"] == "operator"
    for event in openclaw_install.HOOK_EVENTS:
        assert any(openclaw_install._is_ours(entry) for entry in data["hooks"][event])


def test_openclaw_verify_fails_without_registered_hooks(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    (home / "openclaw.json").write_text(json.dumps({"hooks": {}}))
    monkeypatch.setenv("OPENCLAW_HOME", str(home))

    openclaw_install = _load_openclaw_install()
    assert openclaw_install.verify() == 1


def test_openclaw_upgrade_replaces_managed_hooks_after_checkout_move(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    cfg = home / "openclaw.json"
    stale = {
        event: [{"hooks": [{"type": "command",
                             "command": f'bash "/tmp/old-repo-forensics/hooks/{script}"'}]}]
        for event, script in {
            "PreToolUse": "run_pre_scan.sh",
            "PostToolUse": "run_auto_scan.sh",
            "SessionStart": "run_session_scan.sh",
        }.items()
    }
    cfg.write_text(json.dumps({"hooks": stale}))
    monkeypatch.setenv("OPENCLAW_HOME", str(home))
    installer = _load_openclaw_install()

    assert installer.install() == 0

    data = json.loads(cfg.read_text())
    assert all(len(data["hooks"][event]) == 1 for event in installer.HOOK_EVENTS)
    assert all("/tmp/old-repo-forensics" not in json.dumps(data["hooks"][event])
               for event in installer.HOOK_EVENTS)


def test_openclaw_same_basename_third_party_hook_survives_upgrade(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    cfg = home / "openclaw.json"
    third_party = {
        "hooks": [{"type": "command", "command": 'bash "/opt/acme/hooks/run_session_scan.sh"'}]
    }
    stale_ours = {
        "hooks": [{"type": "command",
                   "command": 'bash "/tmp/old-repo-forensics/hooks/run_session_scan.sh"'}]
    }
    cfg.write_text(json.dumps({"hooks": {"SessionStart": [third_party, stale_ours]}}))
    monkeypatch.setenv("OPENCLAW_HOME", str(home))
    installer = _load_openclaw_install()

    assert installer.install() == 0

    entries = json.loads(cfg.read_text())["hooks"]["SessionStart"]
    assert third_party in entries
    assert stale_ours not in entries


def test_openclaw_third_party_command_survives_inside_shared_matcher(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    monkeypatch.setenv("OPENCLAW_HOME", str(home))
    installer = _load_openclaw_install()
    third_party_command = {
        "type": "command", "command": 'bash "/opt/acme/hooks/run_pre_scan.sh"'
    }
    owned_command = {
        "type": "command",
        "command": 'bash "/tmp/old-repo-forensics/hooks/run_pre_scan.sh"',
    }
    shared = {"matcher": "Bash", "hooks": [third_party_command, owned_command]}
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({"hooks": {"PreToolUse": [shared]}}))

    assert installer.install() == 0
    commands = [hook for entry in json.loads(cfg.read_text())["hooks"]["PreToolUse"]
                for hook in entry.get("hooks", [])]
    assert third_party_command in commands
    assert owned_command not in commands


def test_openclaw_verify_rejects_stale_owned_command(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    monkeypatch.setenv("OPENCLAW_HOME", str(home))
    installer = _load_openclaw_install()
    assert installer.install() == 0
    cfg = home / "openclaw.json"
    data = json.loads(cfg.read_text())
    command = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = command.replace(
        str(REPO_ROOT), "/tmp/old-repo-forensics"
    )
    cfg.write_text(json.dumps(data))

    assert installer.verify() == 1


def test_openclaw_uninstall_removes_hooks_and_scheduler(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    monkeypatch.setenv("OPENCLAW_HOME", str(home))
    installer = _load_openclaw_install()
    assert installer.install() == 0
    lifecycle = []
    monkeypatch.setattr(
        installer, "_run_refresh_controller",
        lambda command: lifecycle.append(command) or 0,
    )

    assert installer.uninstall() == 0
    assert lifecycle == ["uninstall"]
    data = json.loads((home / "openclaw.json").read_text())
    assert all(not entries for entries in data.get("hooks", {}).values())


def test_openclaw_uninstall_controller_failure_preserves_hooks(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    monkeypatch.setenv("OPENCLAW_HOME", str(home))
    installer = _load_openclaw_install()
    assert installer.install() == 0
    cfg = home / "openclaw.json"
    before = cfg.read_text()
    monkeypatch.setattr(installer, "_run_refresh_controller", lambda _command: 8)

    assert installer.uninstall() == 1
    assert cfg.read_text() == before


def test_openclaw_uninstall_without_config_still_removes_scheduler(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENCLAW_HOME", str(tmp_path / ".openclaw"))
    installer = _load_openclaw_install()
    lifecycle = []
    monkeypatch.setattr(
        installer, "_run_refresh_controller",
        lambda command: lifecycle.append(command) or 0,
    )

    assert installer.uninstall() == 0
    assert lifecycle == ["uninstall"]


def test_openclaw_invalid_json_is_preserved(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text("{broken")
    monkeypatch.setenv("OPENCLAW_HOME", str(home))
    installer = _load_openclaw_install()

    with pytest.raises(ValueError):
        installer.install()

    assert cfg.read_text() == "{broken"
