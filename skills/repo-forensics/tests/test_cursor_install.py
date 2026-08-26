"""Install merge safety — PRD v3 §5.6 row 9 (R6a). P1.

`~/.cursor/hooks.json` is a SHARED file. Other tools write to it, and the user
writes to it by hand. An installer that reads it, forgets a key, and writes it
back has not installed a security hook — it has silently disabled whatever else
was there, which is a worse outcome than not installing at all.

Pinned here:
  - foreign hooks survive install AND uninstall, byte for byte
  - the required `version` field is never dropped (Cursor ignores the whole
    file without it, including hooks we did not write)
  - writes are atomic, with a `.bak`, and roll back on validation failure
  - `--uninstall` removes only entries carrying REPO_FORENSICS_MANAGED=1
  - re-installing replaces our entries instead of stacking duplicates
"""

import json
import os
import sys
from pathlib import Path

import cursor_helpers as ch
import pytest

sys.path.insert(0, os.path.join(ch.REPO_ROOT, "scripts"))
import cursor_install  # noqa: E402

FOREIGN_CONFIG = {
    "version": 1,
    "hooks": {
        "beforeShellExecution": [{"command": "/opt/other-tool/gate.sh"}],
        "stop": [{"command": "notify-send done"}],
    },
    "someOtherToolsKey": {"keep": "me"},
}


@pytest.fixture
def cursor_home(tmp_path, monkeypatch):
    home = tmp_path / "cursor-home"
    home.mkdir()
    monkeypatch.setenv("CURSOR_HOME", str(home))
    return home


def _write(home, config):
    path = home / "hooks.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def _read(home):
    return json.loads((home / "hooks.json").read_text(encoding="utf-8"))


@pytest.fixture
def plugin_root(tmp_path):
    """A throwaway plugin root so tests never write install-manifest.json into
    the real checkout."""
    root = tmp_path / "plugin"
    (root / "hooks" / "cursor").mkdir(parents=True)
    (root / "skills" / "repo-forensics" / "scripts").mkdir(parents=True)
    for name in ("run_pre_scan.sh", "run_auto_scan.sh", "run_session_scan.sh"):
        (root / "hooks" / "cursor" / name).write_text("#!/bin/bash\n", encoding="utf-8")
    for name in ("pre_scan.py", "auto_scan.py", "session_scan.py", "hook_adapter.py"):
        (root / "skills" / "repo-forensics" / "scripts" / name).write_text("", encoding="utf-8")
    return str(root)


class TestMergeSafety:
    def test_install_preserves_foreign_hooks(self, cursor_home, plugin_root):
        _write(cursor_home, FOREIGN_CONFIG)
        assert cursor_install.install(root=plugin_root) == 0

        config = _read(cursor_home)
        commands = [e["command"] for e in config["hooks"]["beforeShellExecution"]]
        assert "/opt/other-tool/gate.sh" in commands, "foreign hook was dropped"
        assert config["hooks"]["stop"] == [{"command": "notify-send done"}]
        assert config["someOtherToolsKey"] == {"keep": "me"}, \
            "installer clobbered an unrelated top-level key"

    def test_install_keeps_the_version_field(self, cursor_home, plugin_root):
        _write(cursor_home, FOREIGN_CONFIG)
        cursor_install.install(root=plugin_root)
        assert _read(cursor_home)["version"] == 1

    def test_install_adds_version_when_creating_the_file(self, cursor_home, plugin_root):
        assert not (cursor_home / "hooks.json").exists()
        cursor_install.install(root=plugin_root)
        assert _read(cursor_home)["version"] == cursor_install.HOOKS_SCHEMA_VERSION

    def test_install_does_not_rewrite_a_deliberate_version(self, cursor_home, plugin_root):
        _write(cursor_home, {"version": 99, "hooks": {}})
        cursor_install.install(root=plugin_root)
        assert _read(cursor_home)["version"] == 99, \
            "a version the user or a newer Cursor set must not be overwritten"

    def test_install_writes_all_three_hooks_with_the_ownership_marker(
            self, cursor_home, plugin_root):
        cursor_install.install(root=plugin_root)
        hooks = _read(cursor_home)["hooks"]
        for event in ("beforeShellExecution", "afterShellExecution", "sessionStart"):
            ours = [e for e in hooks[event]
                    if cursor_install.OWNERSHIP_MARKER in e.get("command", "")]
            assert len(ours) == 1, f"expected exactly one owned hook on {event}"

    def test_blocking_hook_declares_fail_closed(self, cursor_home, plugin_root):
        cursor_install.install(root=plugin_root)
        entry = [e for e in _read(cursor_home)["hooks"]["beforeShellExecution"]
                 if cursor_install.OWNERSHIP_MARKER in e.get("command", "")][0]
        assert entry.get("failClosed") is True

    def test_plugin_root_is_baked_absolute(self, cursor_home, plugin_root):
        """§4.2: the installed command carries an absolute root rather than
        resolving one at hook time."""
        cursor_install.install(root=plugin_root)
        command = [e["command"] for e in _read(cursor_home)["hooks"]["beforeShellExecution"]
                   if cursor_install.OWNERSHIP_MARKER in e["command"]][0]
        # Compare against the ESCAPED root, not the raw one. _dq() escapes
        # backslashes, so on Windows a real path (C:\Users\...) is legitimately
        # rewritten as C:\\Users\\... inside the double-quoted command. The
        # invariant is "the absolute root is baked in", not "the string survives
        # byte-for-byte".
        assert f'CLAUDE_PLUGIN_ROOT="{cursor_install._dq(plugin_root)}"' in command
        assert os.path.isabs(plugin_root)

    def test_blocking_gate_launches_via_baked_absolute_interpreter(
            self, cursor_home, plugin_root):
        """The installed blocking gate must launch the cross-platform Python
        entrypoint via the interpreter that ran the installer (absolute
        sys.executable), NOT a literal `python3`.

        The python.org Windows installer -- the dominant Windows Python -- ships
        only `python.exe` and the `py` launcher, no `python3.exe`. A failClosed
        gate launched as `python3` there cannot start and would DENY every shell
        command (the WSL-`bash` failure class again). The installer necessarily
        ran under a WORKING interpreter, so baking sys.executable is guaranteed
        valid on that box, Windows included."""
        cursor_install.install(root=plugin_root)
        entry = [e for e in _read(cursor_home)["hooks"]["beforeShellExecution"]
                 if cursor_install.OWNERSHIP_MARKER in e.get("command", "")][0]
        command = entry["command"]
        # Launches the shipped Python gate via the baked absolute interpreter.
        expected_tail = (
            f'"{cursor_install._dq(sys.executable)}" '
            f'"{cursor_install._dq(plugin_root)}/'
            f'skills/repo-forensics/scripts/cursor_pre_scan.py"')
        assert expected_tail in command, command
        assert os.path.isabs(sys.executable)
        # NOT the un-baked literal `python3` launcher, and NOT bash.
        assert 'python3 "${CLAUDE_PLUGIN_ROOT}' not in command
        assert "hooks/cursor/run_pre_scan.sh" not in command
        assert "bash " not in command
        # No fallback chaining: a legit exit-2 DENY must not trip a second
        # interpreter attempt and double-run the scanner.
        assert "||" not in command and "&&" not in command
        # Contract preserved.
        assert entry.get("failClosed") is True
        assert entry.get("timeout") == 10

    def test_reinstall_replaces_instead_of_stacking(self, cursor_home, plugin_root):
        cursor_install.install(root=plugin_root)
        cursor_install.install(root=plugin_root)
        cursor_install.install(root=plugin_root)
        hooks = _read(cursor_home)["hooks"]
        ours = [e for e in hooks["beforeShellExecution"]
                if cursor_install.OWNERSHIP_MARKER in e.get("command", "")]
        assert len(ours) == 1, f"reinstall stacked {len(ours)} copies of the hook"


class TestAtomicityAndBackup:
    def test_backup_is_written(self, cursor_home, plugin_root):
        _write(cursor_home, FOREIGN_CONFIG)
        cursor_install.install(root=plugin_root)
        backup = cursor_home / "hooks.json.bak"
        assert backup.is_file()
        assert json.loads(backup.read_text(encoding="utf-8")) == FOREIGN_CONFIG

    def test_unreadable_config_is_refused_not_overwritten(self, cursor_home, plugin_root):
        path = cursor_home / "hooks.json"
        path.write_text("{ this is not json", encoding="utf-8")
        with pytest.raises(ValueError):
            cursor_install.install(root=plugin_root)
        assert path.read_text(encoding="utf-8") == "{ this is not json", \
            "an unparseable config must be left exactly as found"

    def test_non_object_config_is_refused(self, cursor_home, plugin_root):
        path = cursor_home / "hooks.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(ValueError):
            cursor_install.install(root=plugin_root)
        assert path.read_text(encoding="utf-8") == "[1, 2, 3]"

    def test_non_object_hooks_value_is_refused(self, cursor_home, plugin_root):
        _write(cursor_home, {"version": 1, "hooks": ["not", "an", "object"]})
        with pytest.raises(ValueError):
            cursor_install.install(root=plugin_root)

    def test_validation_failure_restores_from_backup(self, cursor_home, plugin_root,
                                                     monkeypatch):
        """Force the read-back validation to fail and assert the original file
        is restored rather than left half-written."""
        _write(cursor_home, FOREIGN_CONFIG)
        monkeypatch.setattr(cursor_install, "_validate_config",
                            lambda cfg: ["synthetic validation failure"])
        with pytest.raises(ValueError):
            cursor_install.install(root=plugin_root)
        assert _read(cursor_home) == FOREIGN_CONFIG, \
            "a failed install must roll the config back"

    def test_no_temp_files_are_left_behind(self, cursor_home, plugin_root, monkeypatch):
        _write(cursor_home, FOREIGN_CONFIG)
        monkeypatch.setattr(cursor_install, "_validate_config",
                            lambda cfg: ["synthetic validation failure"])
        with pytest.raises(ValueError):
            cursor_install.install(root=plugin_root)
        leftovers = [p.name for p in cursor_home.iterdir()
                     if p.name.startswith(".repo-forensics.")]
        assert not leftovers, f"temp files left behind: {leftovers}"


class TestUninstall:
    def test_uninstall_removes_only_owned_entries(self, cursor_home, plugin_root):
        _write(cursor_home, FOREIGN_CONFIG)
        cursor_install.install(root=plugin_root)
        assert cursor_install.uninstall(root=plugin_root) == 0

        config = _read(cursor_home)
        assert config["hooks"]["beforeShellExecution"] == [
            {"command": "/opt/other-tool/gate.sh"}]
        assert config["hooks"]["stop"] == [{"command": "notify-send done"}]
        assert config["someOtherToolsKey"] == {"keep": "me"}
        assert config["version"] == 1

    def test_uninstall_leaves_no_empty_event_scaffolding(self, cursor_home, plugin_root):
        _write(cursor_home, {"version": 1, "hooks": {}})
        cursor_install.install(root=plugin_root)
        cursor_install.uninstall(root=plugin_root)
        assert _read(cursor_home)["hooks"] == {}

    def test_uninstall_is_idempotent(self, cursor_home, plugin_root):
        _write(cursor_home, FOREIGN_CONFIG)
        cursor_install.install(root=plugin_root)
        cursor_install.uninstall(root=plugin_root)
        first = _read(cursor_home)
        cursor_install.uninstall(root=plugin_root)
        assert _read(cursor_home) == first

    def test_uninstall_with_no_config_is_not_an_error(self, cursor_home, plugin_root):
        assert cursor_install.uninstall(root=plugin_root) == 0

    def test_uninstall_removes_the_install_manifest(self, cursor_home, plugin_root):
        cursor_install.install(root=plugin_root)
        manifest = os.path.join(plugin_root, cursor_install.INSTALL_MANIFEST_NAME)
        assert os.path.isfile(manifest)
        cursor_install.uninstall(root=plugin_root)
        assert not os.path.exists(manifest), \
            "a stale manifest would make every later command a tamper denial"


class TestOwnershipDetection:
    @pytest.mark.parametrize("command,owned", [
        ("REPO_FORENSICS_MANAGED=1 bash /x/hooks/cursor/run_pre_scan.sh", True),
        # Pre-marker installs are recognised structurally so an upgrade replaces
        # them instead of leaving a second copy behind.
        ('CLAUDE_PLUGIN_ROOT="/x" bash "/x/hooks/cursor/run_pre_scan.sh"', True),
        ("/opt/other-tool/gate.sh", False),
        ("bash /home/me/hooks/my_own_pre_scan.sh", False),
        ("echo repo-forensics is great", False),
        ("", False),
        (None, False),
    ])
    def test_command_ownership(self, command, owned):
        assert cursor_install._command_is_ours(command) is owned

    def test_a_foreign_hook_mentioning_us_is_not_ours(self, cursor_home, plugin_root):
        """Someone else's wrapper that merely calls repo-forensics must survive
        uninstall — we only own what we wrote."""
        _write(cursor_home, {"version": 1, "hooks": {"beforeShellExecution": [
            {"command": "/opt/wrapper.sh --then repo-forensics"}]}})
        cursor_install.install(root=plugin_root)
        cursor_install.uninstall(root=plugin_root)
        assert _read(cursor_home)["hooks"]["beforeShellExecution"] == [
            {"command": "/opt/wrapper.sh --then repo-forensics"}]


class TestInstallManifest:
    def test_manifest_lists_only_files_that_exist(self, plugin_root):
        path, missing = cursor_install.write_install_manifest(plugin_root)
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        for rel in payload["files"]:
            assert os.path.isfile(os.path.join(plugin_root, rel))
        assert "ioc_manager.py" in " ".join(missing), \
            "files absent at install time must be reported, not silently claimed"

    def test_manifest_claiming_absent_files_would_be_self_inflicted(self, plugin_root):
        """The manifest is a tamper oracle. Claiming a file we never shipped
        would turn every subsequent command into a denial."""
        path, _missing = cursor_install.write_install_manifest(plugin_root)
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        assert payload["files"], "an empty manifest disables the tamper check"
        assert all(os.path.exists(os.path.join(plugin_root, f))
                   for f in payload["files"])


class TestVerify:
    def test_verify_passes_after_install(self, cursor_home, plugin_root):
        cursor_install.install(root=plugin_root)
        assert cursor_install.verify(root=plugin_root) == 0

    def test_verify_fails_when_not_installed(self, cursor_home, plugin_root):
        assert cursor_install.verify(root=plugin_root) == 1

    def test_verify_fails_after_uninstall(self, cursor_home, plugin_root):
        cursor_install.install(root=plugin_root)
        cursor_install.uninstall(root=plugin_root)
        assert cursor_install.verify(root=plugin_root) == 1

    def test_verify_detects_a_stale_hook_from_a_moved_checkout(
            self, cursor_home, plugin_root, tmp_path):
        """A hook pointing at an old path is worse than no hook: it looks
        installed and protects nothing."""
        cursor_install.install(root=plugin_root)
        config = _read(cursor_home)
        config["hooks"]["beforeShellExecution"] = [{
            "command": (f'{cursor_install.OWNERSHIP_MARKER} '
                        f'CLAUDE_PLUGIN_ROOT="/gone" bash "/gone/hooks/cursor/run_pre_scan.sh"')
        }]
        _write(cursor_home, config)
        assert cursor_install.verify(root=plugin_root) == 1

    def test_verify_fails_without_an_install_manifest(self, cursor_home, plugin_root):
        cursor_install.install(root=plugin_root)
        os.unlink(os.path.join(plugin_root, cursor_install.INSTALL_MANIFEST_NAME))
        assert cursor_install.verify(root=plugin_root) == 1


class TestShellEscaping:
    @pytest.mark.parametrize("hostile", [
        'root"; rm -rf /; echo "',
        "root$(whoami)",
        "root`id`",
        "root\\evil",
        "root\nrm -rf /",
    ])
    def test_hostile_plugin_root_is_escaped(self, hostile):
        """The root is interpolated into a command Cursor stores and evaluates
        on every hook event, so a repo at a hostile path must not become
        command injection."""
        command = cursor_install._managed_hooks(hostile)["beforeShellExecution"][0]["command"]

        # What must hold is the SECURITY property, not string identity. The
        # installer routes the root through pathlib, and on Windows Path()
        # normalises '/' to '\\' -- so the hostile string does not survive
        # verbatim there, while remaining just as escaped. Asserting the literal
        # input reappears tests pathlib's normalisation, not our escaping.
        for dangerous in ('";', "$(", "`", "\n"):
            assert dangerous not in command.replace('\\' + dangerous[0], ""), \
                f"unescaped {dangerous!r} survived into the hook command"

        # And the command must still be one well-formed shell token per field:
        # an unbalanced quote is exactly how an injected root breaks out.
        assert command.count('"') % 2 == 0, f"unbalanced quoting: {command!r}"
