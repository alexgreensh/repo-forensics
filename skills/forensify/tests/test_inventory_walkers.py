"""
Test suite for build_inventory.py surface walkers.

Covers the path primitives (_safe_stat, _file_record, safe_resolve_glob) and
the skills surface walker across all four ecosystem shapes using isolated
tmp_path fixture trees. Tests never touch the developer's real filesystem
for their assertions — only the real-filesystem smoke at the bottom does,
and it only verifies non-crash and JSON serializability.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from build_inventory import (  # noqa: E402
    BidiOverrideRejected,
    _file_record,
    _path_depth_under,
    build_inventory as build_inventory_fn,
    load_ecosystem_roots,
    safe_resolve_glob,
    walk_skills_surface,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_skill(root: Path, name: str, description: str = "test skill") -> Path:
    """Create a minimal SKILL.md under root/name/ and return the file path."""
    skill_dir = root / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_md = skill_dir / "SKILL.md"
    skill_md.write_text(
        "---\nname: %s\ndescription: %s\n---\n\n# %s\n" % (name, description, name)
    )
    return skill_md


# ---------------------------------------------------------------------------
# Path depth calculator
# ---------------------------------------------------------------------------


class TestPathDepth:
    def test_direct_child_is_depth_1(self, tmp_path):
        child = tmp_path / "a.txt"
        child.write_text("")
        assert _path_depth_under(str(child), str(tmp_path)) == 1

    def test_nested_child_counts_segments(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c.txt"
        nested.parent.mkdir(parents=True)
        nested.write_text("")
        assert _path_depth_under(str(nested), str(tmp_path)) == 3

    def test_root_itself_is_depth_0(self, tmp_path):
        assert _path_depth_under(str(tmp_path), str(tmp_path)) == 0


# ---------------------------------------------------------------------------
# safe_resolve_glob
# ---------------------------------------------------------------------------


class TestSafeResolveGlob:
    def test_simple_wildcard(self, tmp_path):
        (tmp_path / "a.md").write_text("")
        (tmp_path / "b.md").write_text("")
        (tmp_path / "c.txt").write_text("")
        env = {"HOME": str(tmp_path)}
        matches = safe_resolve_glob("~/*.md", env)
        assert len(matches) == 2
        assert all(m.endswith(".md") for m in matches)

    def test_recursive_wildcard(self, tmp_path):
        (tmp_path / "level1" / "level2").mkdir(parents=True)
        (tmp_path / "level1" / "a.md").write_text("")
        (tmp_path / "level1" / "level2" / "b.md").write_text("")
        env = {"HOME": str(tmp_path)}
        matches = safe_resolve_glob("~/**/*.md", env)
        assert len(matches) == 2

    def test_skill_md_pattern(self, tmp_path):
        skills_root = tmp_path / ".claude" / "skills"
        _make_skill(skills_root, "alpha")
        _make_skill(skills_root, "beta")
        _make_skill(skills_root, "gamma")
        env = {"HOME": str(tmp_path)}
        matches = safe_resolve_glob("~/.claude/skills/*/SKILL.md", env)
        assert len(matches) == 3
        # All matches must end in SKILL.md
        assert all(m.endswith("SKILL.md") for m in matches)

    def test_sorted_deterministic(self, tmp_path):
        skills_root = tmp_path / ".claude" / "skills"
        for name in ["zebra", "alpha", "mango", "beta"]:
            _make_skill(skills_root, name)
        env = {"HOME": str(tmp_path)}
        matches = safe_resolve_glob("~/.claude/skills/*/SKILL.md", env)
        assert matches == sorted(matches)

    def test_no_matches_returns_empty(self, tmp_path):
        env = {"HOME": str(tmp_path)}
        assert safe_resolve_glob("~/does/not/exist/*.md", env) == []

    def test_walk_depth_cap_excludes_deep_paths(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "h" / "i"
        deep.mkdir(parents=True)
        (deep / "SKILL.md").write_text("")
        shallow = tmp_path / "shallow"
        shallow.mkdir()
        (shallow / "SKILL.md").write_text("")
        env = {"HOME": str(tmp_path)}
        # Cap of 3 should only allow paths within 3 segments of the prefix
        matches = safe_resolve_glob("~/**/SKILL.md", env, walk_depth_cap=3)
        assert any("shallow" in m for m in matches)
        assert not any("/i/" in m for m in matches)

    def test_bidi_filename_on_disk_skipped(self, tmp_path):
        # A filename with a real bidi override codepoint must not enter clean
        # inventory output. The glob may return the raw path but the walker
        # filters it.
        safe = tmp_path / "safe.md"
        safe.write_text("")
        # Create a poisoned filename with U+202E. Must be handled gracefully.
        try:
            poisoned = tmp_path / ("attack" + chr(0x202E) + "md.exe")
            poisoned.write_text("")
        except OSError:
            pytest.skip("filesystem rejects bidi filenames")
        env = {"HOME": str(tmp_path)}
        matches = safe_resolve_glob("~/*", env)
        # Safe file present
        assert any("safe.md" in m for m in matches)
        # Poisoned file filtered out (bidi character would fail normalize_text)
        assert not any(chr(0x202E) in m for m in matches)


# ---------------------------------------------------------------------------
# _file_record
# ---------------------------------------------------------------------------


class TestFileRecord:
    def test_basic_file_record(self, tmp_path):
        f = tmp_path / "sample.md"
        f.write_text("hello world")
        record = _file_record(str(f))
        assert record["path"] == str(f)
        assert record["size_bytes"] == 11
        assert record["is_symlink"] is False
        assert "file_mode_octal" in record
        assert record["file_mode_octal"].startswith("0o")
        assert "last_modified_iso" in record
        assert "+00:00" in record["last_modified_iso"]

    def test_symlink_target_recorded(self, tmp_path):
        real = tmp_path / "real.sh"
        real.write_text("#!/bin/sh\necho hi\n")
        link = tmp_path / "link.sh"
        link.symlink_to(real)
        record = _file_record(str(link))
        assert record["is_symlink"] is True
        assert record["symlink_target"] == str(real.resolve())

    def test_relative_path_computed(self, tmp_path):
        skills_root = tmp_path / "skills"
        skills_root.mkdir()
        f = skills_root / "alpha" / "SKILL.md"
        f.parent.mkdir(parents=True)
        f.write_text("")
        record = _file_record(str(f), root_for_relative=str(skills_root))
        assert record.get("relative_path") == os.path.join("alpha", "SKILL.md")

    def test_nonexistent_file_returns_error(self, tmp_path):
        record = _file_record(str(tmp_path / "ghost.md"))
        assert record.get("_error") == "stat_failed"


# ---------------------------------------------------------------------------
# Skills surface walker: per-ecosystem behaviors
# ---------------------------------------------------------------------------


class TestSkillsWalkerClaudeCode:
    def test_enumerates_user_skills(self, tmp_path):
        skills_root = tmp_path / ".claude" / "skills"
        _make_skill(skills_root, "alpha")
        _make_skill(skills_root, "beta")
        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        records = walk_skills_surface(
            "claude_code", config["ecosystems"]["claude_code"], env
        )
        names = sorted(r.get("skill_name", "") for r in records)
        assert names == ["alpha", "beta"]

    def test_enumerates_plugin_skills(self, tmp_path):
        plugin_skills = tmp_path / ".claude" / "plugins" / "myplugin" / "skills"
        _make_skill(plugin_skills, "nested")
        user_skills = tmp_path / ".claude" / "skills"
        _make_skill(user_skills, "standalone")
        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        records = walk_skills_surface(
            "claude_code", config["ecosystems"]["claude_code"], env
        )
        names = {r.get("skill_name", "") for r in records}
        assert "nested" in names
        assert "standalone" in names

    def test_empty_stack_returns_empty_list(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        records = walk_skills_surface(
            "claude_code", config["ecosystems"]["claude_code"], env
        )
        assert records == []


class TestSkillsWalkerCodex:
    def test_codex_home_env_respected(self, tmp_path):
        custom_codex = tmp_path / "custom_codex"
        skills_root = custom_codex / "skills"
        _make_skill(skills_root, "gamma")
        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path), "CODEX_HOME": str(custom_codex)}
        # The walker receives the effective env with CODEX_HOME default applied
        from build_inventory import _resolve_env_for_ecosystem

        eco_cfg = config["ecosystems"]["codex"]
        effective_env = _resolve_env_for_ecosystem(eco_cfg, env)
        records = walk_skills_surface("codex", eco_cfg, effective_env)
        names = [r.get("skill_name", "") for r in records]
        assert "gamma" in names


class TestSkillsWalkerOpenClaw:
    def test_precedence_rank_decorated(self, tmp_path):
        # Build a fake OpenClaw stack with skills at multiple precedence levels
        workspace = tmp_path / ".openclaw" / "workspace"
        workspace_skills = workspace / "skills"
        _make_skill(workspace_skills, "top_priority")

        agents_skills = tmp_path / ".agents" / "skills"
        _make_skill(agents_skills, "personal_level")

        managed_skills = tmp_path / ".openclaw" / "skills"
        _make_skill(managed_skills, "managed_level")

        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        records = walk_skills_surface(
            "openclaw", config["ecosystems"]["openclaw"], env
        )
        # Every record must carry precedence_rank (OpenClaw uses precedence_chain)
        for r in records:
            assert "precedence_rank" in r
            assert isinstance(r["precedence_rank"], int)

        # workspace/skills/ is rank 0 (highest precedence)
        workspace_record = next(
            (r for r in records if r.get("skill_name") == "top_priority"), None
        )
        assert workspace_record is not None
        assert workspace_record["precedence_rank"] == 0

        # ~/.openclaw/skills/ is rank 3 (per docs.openclaw.ai: workspace > project > personal > managed)
        managed_record = next(
            (r for r in records if r.get("skill_name") == "managed_level"), None
        )
        assert managed_record is not None
        assert managed_record["precedence_rank"] == 3


class TestSkillsWalkerNanoClaw:
    def test_nanoclaw_walker_returns_empty_without_detection(self, tmp_path):
        # Until the signature-based detection lands, NanoClaw walker should
        # gracefully return an empty list when no root is known. ${root}
        # will not expand so globs become literal ${root}/... paths that
        # match nothing.
        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        records = walk_skills_surface(
            "nanoclaw", config["ecosystems"]["nanoclaw"], env
        )
        assert records == []


# ---------------------------------------------------------------------------
# build_inventory integration: surfaces populated per ecosystem
# ---------------------------------------------------------------------------


class TestBuildInventoryWithSurfaces:
    def test_detected_ecosystems_have_surfaces_key(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.json").write_text("{}")
        _make_skill(tmp_path / ".claude" / "skills", "one")
        inv = build_inventory_fn(env={"HOME": str(tmp_path)})
        claude = next(e for e in inv["ecosystems"] if e["key"] == "claude_code")
        assert claude["detected"] is True
        assert "surfaces" in claude
        assert "skills" in claude["surfaces"]
        assert len(claude["surfaces"]["skills"]) == 1

    def test_undetected_ecosystems_have_empty_surfaces(self, tmp_path):
        inv = build_inventory_fn(env={"HOME": str(tmp_path)})
        for eco in inv["ecosystems"]:
            if not eco["detected"]:
                assert eco.get("surfaces") == {}

    def test_full_inventory_serializable_with_walkers(self, tmp_path):
        _make_skill(tmp_path / ".claude" / "skills", "alpha")
        _make_skill(tmp_path / ".claude" / "skills", "beta")
        (tmp_path / ".claude" / "settings.json").write_text("{}")
        inv = build_inventory_fn(env={"HOME": str(tmp_path)})
        # Must round-trip through json without errors
        serialized = json.dumps(inv)
        round_tripped = json.loads(serialized)
        claude = next(
            e for e in round_tripped["ecosystems"] if e["key"] == "claude_code"
        )
        assert len(claude["surfaces"]["skills"]) == 2


# ---------------------------------------------------------------------------
# Real filesystem smoke: walker must not crash on live data
# ---------------------------------------------------------------------------


class TestCommandsAgentsMemoryWalker:
    def test_commands_and_agents_enumerated(self, tmp_path):
        claude = tmp_path / ".claude"
        cmds = claude / "commands"
        cmds.mkdir(parents=True)
        (cmds / "review.md").write_text("# review")
        (cmds / "deploy.md").write_text("# deploy")
        agents = claude / "agents"
        agents.mkdir()
        (agents / "coder.md").write_text("# coder")
        (claude / "settings.json").write_text("{}")

        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        from build_inventory import walk_commands_agents_memory, _resolve_env_for_ecosystem

        eco_cfg = config["ecosystems"]["claude_code"]
        eco_env = _resolve_env_for_ecosystem(eco_cfg, env)
        result = walk_commands_agents_memory("claude_code", eco_cfg, eco_env)
        assert len(result["commands"]) == 2
        assert len(result["agents"]) == 1

    def test_memory_files_found(self, tmp_path):
        claude = tmp_path / ".claude"
        claude.mkdir()
        (claude / "CLAUDE.md").write_text("# global memory")
        proj = claude / "projects" / "test" / "memory"
        proj.mkdir(parents=True)
        (proj / "MEMORY.md").write_text("# project memory")

        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        from build_inventory import walk_commands_agents_memory, _resolve_env_for_ecosystem

        eco_cfg = config["ecosystems"]["claude_code"]
        eco_env = _resolve_env_for_ecosystem(eco_cfg, env)
        result = walk_commands_agents_memory("claude_code", eco_cfg, eco_env)
        assert len(result["memory"]) >= 1


class TestHooksWalker:
    def test_hooks_with_symlinks(self, tmp_path):
        claude = tmp_path / ".claude"
        hooks = claude / "hooks"
        hooks.mkdir(parents=True)
        real = tmp_path / "external" / "guard.sh"
        real.parent.mkdir()
        real.write_text("#!/bin/sh\necho guard")
        link = hooks / "guard.sh"
        link.symlink_to(real)

        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        from build_inventory import walk_hooks_surface, _resolve_env_for_ecosystem

        eco_cfg = config["ecosystems"]["claude_code"]
        eco_env = _resolve_env_for_ecosystem(eco_cfg, env)
        records = walk_hooks_surface("claude_code", eco_cfg, eco_env)
        sym_records = [r for r in records if r.get("is_symlink")]
        assert len(sym_records) >= 1
        assert sym_records[0]["symlink_target"] == str(real.resolve())


class TestMCPWalker:
    def test_json_mcp_server_count(self, tmp_path):
        claude_json = tmp_path / ".claude.json"
        claude_json.write_text(json.dumps({
            "mcpServers": {"fs": {}, "github": {}, "slack": {}}
        }))

        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        from build_inventory import walk_mcp_surface, _resolve_env_for_ecosystem

        eco_cfg = config["ecosystems"]["claude_code"]
        eco_env = _resolve_env_for_ecosystem(eco_cfg, env)
        records = walk_mcp_surface("claude_code", eco_cfg, eco_env)
        json_rec = next((r for r in records if r["path"].endswith(".claude.json")), None)
        assert json_rec is not None
        assert json_rec["mcp_server_count"] == 3

    def test_toml_mcp_server_count(self, tmp_path):
        codex_dir = tmp_path / ".codex"
        codex_dir.mkdir()
        (codex_dir / "config.toml").write_text(
            '[mcp_servers.filesystem]\ncommand = "npx"\n\n'
            '[mcp_servers.github]\ncommand = "npx"\n'
        )
        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        from build_inventory import walk_mcp_surface, _resolve_env_for_ecosystem

        eco_cfg = config["ecosystems"]["codex"]
        eco_env = _resolve_env_for_ecosystem(eco_cfg, env)
        records = walk_mcp_surface("codex", eco_cfg, eco_env)
        toml_rec = next((r for r in records if r["path"].endswith("config.toml")), None)
        assert toml_rec is not None
        assert toml_rec["mcp_server_count"] == 2


class TestCredentialsWalker:
    def test_auth_json_shape_inspection(self, tmp_path):
        codex_dir = tmp_path / ".codex"
        codex_dir.mkdir()
        auth = codex_dir / "auth.json"
        auth.write_text(json.dumps({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": None,
            "tokens": {"access_token": "x" * 100, "refresh_token": "y" * 50},
            "last_refresh": "2026-04-01T12:00:00+00:00",
        }))
        os.chmod(str(auth), 0o600)

        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        from build_inventory import walk_credentials_surface, _resolve_env_for_ecosystem

        eco_cfg = config["ecosystems"]["codex"]
        eco_env = _resolve_env_for_ecosystem(eco_cfg, env)
        records = walk_credentials_surface("codex", eco_cfg, eco_env)
        assert len(records) == 1
        rec = records[0]
        assert rec["auth_mode"] == "chatgpt"
        assert rec["auth_mode_risk_weight"] == "medium"
        assert rec["is_world_readable"] is False
        assert "json_shape" in rec
        # Shape must NOT contain actual token values
        shape = rec["json_shape"]
        assert "x" * 100 not in str(shape)
        assert shape["tokens"] == "dict(2 keys)"

    def test_world_readable_flagged(self, tmp_path):
        codex_dir = tmp_path / ".codex"
        codex_dir.mkdir()
        auth = codex_dir / "auth.json"
        auth.write_text(json.dumps({"auth_mode": "apikey", "OPENAI_API_KEY": "sk-test"}))
        os.chmod(str(auth), 0o644)  # world-readable = bad

        config = load_ecosystem_roots()
        env = {"HOME": str(tmp_path)}
        from build_inventory import walk_credentials_surface, _resolve_env_for_ecosystem

        eco_cfg = config["ecosystems"]["codex"]
        eco_env = _resolve_env_for_ecosystem(eco_cfg, env)
        records = walk_credentials_surface("codex", eco_cfg, eco_env)
        assert len(records) == 1
        assert records[0]["is_world_readable"] is True
        assert records[0]["auth_mode_risk_weight"] == "high"


class TestCrossToolIOCs:
    def test_ioc_fires_when_both_installed(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.json").write_text("{}")
        (tmp_path / ".codex").mkdir()
        (tmp_path / ".codex" / "config.toml").write_text("")
        (tmp_path / ".agents" / "skills").mkdir(parents=True)

        inv = build_inventory_fn(env={"HOME": str(tmp_path)})
        iocs = inv["cross_ecosystem"]["iocs"]
        assert len(iocs) >= 1
        assert iocs[0]["id"] == "openai/codex#54506"
        assert iocs[0]["severity"] == "high"

    def test_ioc_does_not_fire_without_openclaw(self, tmp_path):
        (tmp_path / ".codex").mkdir()
        (tmp_path / ".codex" / "config.toml").write_text("")

        inv = build_inventory_fn(env={"HOME": str(tmp_path)})
        iocs = inv["cross_ecosystem"]["iocs"]
        assert len(iocs) == 0


class TestRealFilesystemWalkerSmoke:
    def test_all_surfaces_populated_for_detected_ecosystems(self):
        inv = build_inventory_fn()
        expected_surface_keys = {
            "skills", "commands", "agents", "memory", "brain_files",
            "hooks", "mcp", "plugins", "settings", "credentials",
        }
        for eco in inv["ecosystems"]:
            if eco["detected"]:
                assert "surfaces" in eco
                assert expected_surface_keys.issubset(set(eco["surfaces"].keys()))
                for surface_name, surface_data in eco["surfaces"].items():
                    assert isinstance(surface_data, list)
        json.dumps(inv)
