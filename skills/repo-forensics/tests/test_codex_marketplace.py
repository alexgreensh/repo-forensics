import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_codex_marketplace_catalog_points_to_real_nested_plugin():
    catalog = json.loads((REPO_ROOT / ".agents" / "plugins" / "marketplace.json").read_text())
    plugin = catalog["plugins"][0]
    nested = (REPO_ROOT / plugin["source"]["path"]).resolve()

    assert plugin["name"] == "repo-forensics"
    assert nested.is_dir()
    assert (nested / ".codex-plugin" / "plugin.json").is_file()
    assert (nested / "hooks" / "hooks.json").is_file()
    assert (nested / "hooks" / "python-launcher.sh").is_file()
    assert (nested / "skills" / "repo-forensics" / "SKILL.md").is_file()
    assert (nested / "skills" / "forensify" / "SKILL.md").is_file()
    assert not list(nested.rglob("__pycache__"))
    assert not list(nested.rglob("tests"))


def test_codex_cli_can_discover_and_install_local_marketplace(tmp_path):
    codex = shutil.which("codex")
    if not codex:
        pytest.skip("codex CLI not installed")

    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    env = {
        **os.environ,
        "CODEX_HOME": str(codex_home),
    }

    subprocess.run(
        [codex, "plugin", "marketplace", "add", str(REPO_ROOT)],
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
        check=True,
    )

    available = subprocess.run(
        [codex, "plugin", "list", "--available", "--json"],
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
        check=True,
    )
    available_data = json.loads(available.stdout)
    assert any(
        item["pluginId"] == "repo-forensics@alexgreensh-repo-forensics"
        for item in available_data["available"]
    )

    subprocess.run(
        [codex, "plugin", "add", "repo-forensics@alexgreensh-repo-forensics"],
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
        check=True,
    )

    installed = subprocess.run(
        [codex, "plugin", "list", "--json"],
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
        check=True,
    )
    installed_data = json.loads(installed.stdout)
    assert any(
        item["pluginId"] == "repo-forensics@alexgreensh-repo-forensics"
        and item["installed"]
        and item["enabled"]
        for item in installed_data["installed"]
    )

    installed_hooks = list(codex_home.glob(
        "plugins/cache/alexgreensh-repo-forensics/repo-forensics/*/hooks/hooks.json"
    ))
    assert len(installed_hooks) == 1
    hook_data = json.loads(installed_hooks[0].read_text())
    assert {"PreToolUse", "PostToolUse", "SessionStart"} <= set(hook_data["hooks"])

    installed_root = installed_hooks[0].parents[1]
    verify = subprocess.run(
        [
            "python3",
            str(installed_root / "skills" / "repo-forensics" / "scripts" / "verify_install.py"),
            "--verify",
        ],
        text=True,
        capture_output=True,
        timeout=20,
        check=True,
    )
    assert "VERIFIED" in verify.stdout
    assert "PARTIAL" not in verify.stdout
