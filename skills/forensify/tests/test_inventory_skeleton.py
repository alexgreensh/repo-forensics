"""
Test suite for build_inventory.py skeleton layer.

Covers config loading, NFKC normalization, bidi rejection, environment
variable expansion, and ecosystem detection. Per-surface walker tests
land in subsequent commits alongside the walker code.

Invariant: stdlib-only. No pytest plugins beyond the core. No fixtures
directory — tests build their own isolated trees under tmp_path so they
never touch the real ~/.claude or ~/.codex on the developer's machine.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# Import path: this test lives at skills/forensify/tests/, script lives at
# skills/forensify/scripts/. Add scripts/ to sys.path for direct import.
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import build_inventory  # noqa: E402
from build_inventory import (  # noqa: E402
    BidiOverrideRejected,
    SchemaMismatch,
    build_inventory as build_inventory_fn,
    detect_ecosystems,
    expand_env_vars,
    load_ecosystem_roots,
    normalize_text,
    reject_bidi,
)

CONFIG_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "ecosystem_roots.json"
)


# ---------------------------------------------------------------------------
# Bidi override rejection
# ---------------------------------------------------------------------------


class TestBidiRejection:
    def test_plain_ascii_passes(self):
        assert reject_bidi("hello world") == "hello world"

    def test_unicode_without_bidi_passes(self):
        # Hebrew, CJK, emoji — all fine
        assert reject_bidi("שלום") == "שלום"
        assert reject_bidi("你好") == "你好"
        assert reject_bidi("hello 👋") == "hello 👋"

    @pytest.mark.parametrize(
        "codepoint",
        [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069],
    )
    def test_every_bidi_codepoint_rejected(self, codepoint):
        poisoned = "safe" + chr(codepoint) + "name.md"
        with pytest.raises(BidiOverrideRejected) as exc:
            reject_bidi(poisoned)
        assert "U+%04X" % codepoint in str(exc.value)

    def test_rtl_override_filename_attack(self):
        # RLO inside a filename turns "exploit.sh.txt" into "exploit.txt.hs"
        # visually. Classic bidi spoof. Must be blocked.
        poisoned = "exploit" + chr(0x202E) + "txt.sh"
        with pytest.raises(BidiOverrideRejected):
            reject_bidi(poisoned)


# ---------------------------------------------------------------------------
# NFKC normalization
# ---------------------------------------------------------------------------


class TestNFKCNormalization:
    def test_ascii_unchanged(self):
        assert normalize_text("skills/claude.md") == "skills/claude.md"

    def test_fullwidth_latin_collapsed(self):
        # Full-width Latin "ＡＢＣ" (U+FF21..U+FF23) -> ASCII "ABC"
        assert normalize_text("ＡＢＣ") == "ABC"

    def test_ligature_collapsed(self):
        # "ﬁ" (U+FB01) -> "fi"
        assert normalize_text("ﬁle") == "file"

    def test_non_breaking_space_collapsed_or_preserved(self):
        # NFKC decomposes NBSP (U+00A0) to regular space
        result = normalize_text("skill\u00a0name")
        assert result == "skill name"

    def test_normalize_rejects_bidi_after_nfkc(self):
        # NFKC does not strip bidi overrides; our normalize_text chain must.
        with pytest.raises(BidiOverrideRejected):
            normalize_text("file" + chr(0x202E) + "name")


# ---------------------------------------------------------------------------
# Environment variable expansion
# ---------------------------------------------------------------------------


class TestExpandEnvVars:
    def test_simple_brace_var(self):
        env = {"CODEX_HOME": "/custom/codex"}
        assert expand_env_vars("${CODEX_HOME}/config.toml", env) == (
            "/custom/codex/config.toml"
        )

    def test_default_when_unset(self):
        env = {}
        assert expand_env_vars("${CODEX_HOME:-/fallback}/x", env) == "/fallback/x"

    def test_env_value_wins_over_default(self):
        env = {"CODEX_HOME": "/real"}
        assert expand_env_vars("${CODEX_HOME:-/fallback}/x", env) == "/real/x"

    def test_tilde_expansion(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        result = expand_env_vars("~/test", env={"HOME": str(tmp_path)})
        # expanduser uses HOME from the real environment, not the passed dict,
        # so we set it via monkeypatch.
        assert result == str(tmp_path / "test")

    def test_no_bare_dollar_expansion(self):
        # $NAME without braces is intentionally not expanded
        env = {"NAME": "value"}
        assert expand_env_vars("$NAME/path", env) == "$NAME/path"

    def test_dangling_brace_preserved(self):
        # Unclosed ${ is left as-is rather than crashing
        env = {}
        result = expand_env_vars("${UNCLOSED/path", env)
        assert "${UNCLOSED" in result or "$" in result

    def test_expansion_rejects_bidi(self):
        env = {"EVIL": "safe" + chr(0x202E) + "name"}
        with pytest.raises(BidiOverrideRejected):
            expand_env_vars("${EVIL}", env)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


class TestLoadEcosystemRoots:
    def test_default_config_loads(self):
        config = load_ecosystem_roots()
        assert config["schema_version"] == 1
        assert set(config["ecosystems"].keys()) == {
            "claude_code",
            "codex",
            "openclaw",
            "nanoclaw",
        }

    def test_schema_version_mismatch_raises(self, tmp_path):
        bad = {"schema_version": 999, "ecosystems": {}, "invariants": {}}
        config_file = tmp_path / "bad_roots.json"
        config_file.write_text(json.dumps(bad))
        with pytest.raises(SchemaMismatch) as exc:
            load_ecosystem_roots(config_file)
        assert "999" in str(exc.value)

    def test_missing_schema_version_raises(self, tmp_path):
        bad = {"ecosystems": {}}
        config_file = tmp_path / "no_version.json"
        config_file.write_text(json.dumps(bad))
        with pytest.raises(SchemaMismatch):
            load_ecosystem_roots(config_file)

    def test_invalid_json_raises(self, tmp_path):
        config_file = tmp_path / "broken.json"
        config_file.write_text("{ not valid json")
        with pytest.raises(json.JSONDecodeError):
            load_ecosystem_roots(config_file)

    def test_bidi_in_config_rejected(self, tmp_path):
        poisoned = {
            "schema_version": 1,
            "ecosystems": {"evil" + chr(0x202E) + "key": {}},
            "invariants": {},
        }
        config_file = tmp_path / "poisoned.json"
        config_file.write_text(json.dumps(poisoned, ensure_ascii=False))
        with pytest.raises(BidiOverrideRejected):
            load_ecosystem_roots(config_file)

    def test_invariants_key_present(self):
        config = load_ecosystem_roots()
        inv = config["invariants"]
        assert inv["path_normalization"] == "NFKC"
        assert inv["bidi_override_policy"] == "reject"
        assert inv["credential_value_reads"] == "forbidden"

    def test_cross_tool_iocs_registered(self):
        config = load_ecosystem_roots()
        iocs = config["cross_tool_iocs"]
        assert len(iocs) >= 1
        # openai/codex#54506 is the seed entry and must stay registered
        ids = [ioc["id"] for ioc in iocs]
        assert "openai/codex#54506" in ids


# ---------------------------------------------------------------------------
# Ecosystem detection
# ---------------------------------------------------------------------------


class TestDetectEcosystems:
    def test_empty_environment_detects_nothing(self, tmp_path):
        """A clean tmp dir with no stack installs should return all ecosystems
        with detected=False."""
        fake_home = tmp_path / "clean_home"
        fake_home.mkdir()
        config = load_ecosystem_roots()
        # Isolate HOME so ~ expansion points at the clean dir
        env = {"HOME": str(fake_home)}
        results = detect_ecosystems(config, env=env)
        assert len(results) == 4
        for eco in results:
            assert eco["detected"] is False
            assert eco["matched_signals"] == []

    def test_claude_code_detection(self, tmp_path):
        fake_home = tmp_path / "claude_home"
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir(parents=True)
        (claude_dir / "settings.json").write_text("{}")

        config = load_ecosystem_roots()
        env = {"HOME": str(fake_home)}
        results = detect_ecosystems(config, env=env)
        claude = next(r for r in results if r["key"] == "claude_code")
        assert claude["detected"] is True
        assert any("settings.json" in sig for sig in claude["matched_signals"])

    def test_codex_detection_via_default_path(self, tmp_path):
        fake_home = tmp_path / "codex_home"
        codex_dir = fake_home / ".codex"
        codex_dir.mkdir(parents=True)
        (codex_dir / "config.toml").write_text("model = 'o4-mini'")

        config = load_ecosystem_roots()
        env = {"HOME": str(fake_home)}
        results = detect_ecosystems(config, env=env)
        codex = next(r for r in results if r["key"] == "codex")
        assert codex["detected"] is True

    def test_codex_detection_via_codex_home_env(self, tmp_path):
        fake_home = tmp_path / "codex_home"
        custom_codex = tmp_path / "custom_codex_location"
        custom_codex.mkdir(parents=True)
        (custom_codex / "config.toml").write_text("model = 'o4-mini'")

        config = load_ecosystem_roots()
        env = {"HOME": str(fake_home), "CODEX_HOME": str(custom_codex)}
        results = detect_ecosystems(config, env=env)
        codex = next(r for r in results if r["key"] == "codex")
        assert codex["detected"] is True
        # resolved roots should point at the env-var override
        assert any(str(custom_codex) in root for root in codex["resolved_roots"])

    def test_openclaw_detection_via_agents_skills(self, tmp_path):
        fake_home = tmp_path / "oc_home"
        agents_skills = fake_home / ".agents" / "skills"
        agents_skills.mkdir(parents=True)

        config = load_ecosystem_roots()
        env = {"HOME": str(fake_home)}
        results = detect_ecosystems(config, env=env)
        openclaw = next(r for r in results if r["key"] == "openclaw")
        assert openclaw["detected"] is True

    def test_multi_ecosystem_detection(self, tmp_path):
        """A single machine with Claude Code + Codex + OpenClaw all installed
        should report all three as detected, NanoClaw as not detected."""
        fake_home = tmp_path / "multi_home"
        (fake_home / ".claude").mkdir(parents=True)
        (fake_home / ".claude" / "settings.json").write_text("{}")
        (fake_home / ".codex").mkdir(parents=True)
        (fake_home / ".codex" / "config.toml").write_text("")
        (fake_home / ".agents" / "skills").mkdir(parents=True)

        config = load_ecosystem_roots()
        env = {"HOME": str(fake_home)}
        results = detect_ecosystems(config, env=env)
        by_key = {r["key"]: r for r in results}

        assert by_key["claude_code"]["detected"] is True
        assert by_key["codex"]["detected"] is True
        assert by_key["openclaw"]["detected"] is True
        assert by_key["nanoclaw"]["detected"] is False

    def test_target_override_narrows_results(self, tmp_path):
        fake_home = tmp_path / "narrow_home"
        (fake_home / ".claude").mkdir(parents=True)
        (fake_home / ".claude" / "settings.json").write_text("{}")
        (fake_home / ".codex").mkdir(parents=True)
        (fake_home / ".codex" / "config.toml").write_text("")

        config = load_ecosystem_roots()
        env = {"HOME": str(fake_home)}
        results = detect_ecosystems(
            config, env=env, target_override=str(fake_home / ".claude")
        )
        # Only claude_code should pass the target filter
        assert len(results) == 1
        assert results[0]["key"] == "claude_code"


# ---------------------------------------------------------------------------
# Top-level build_inventory shape
# ---------------------------------------------------------------------------


class TestBuildInventoryShape:
    def test_inventory_has_required_top_level_keys(self, tmp_path):
        fake_home = tmp_path / "shape_home"
        fake_home.mkdir()
        config = load_ecosystem_roots()
        inv = build_inventory_fn(config=config, env={"HOME": str(fake_home)})
        required_keys = {
            "schema_version",
            "forensify_version",
            "generated_at",
            "invariants",
            "ecosystems",
            "shadow_surfaces",
            "cross_ecosystem",
        }
        assert required_keys.issubset(set(inv.keys()))

    def test_inventory_generated_at_is_iso_utc(self, tmp_path):
        fake_home = tmp_path / "iso_home"
        fake_home.mkdir()
        config = load_ecosystem_roots()
        inv = build_inventory_fn(config=config, env={"HOME": str(fake_home)})
        # Must end with +00:00 (UTC) and parse via fromisoformat
        assert "+00:00" in inv["generated_at"] or inv["generated_at"].endswith("Z")
        from datetime import datetime

        # Sanity parse — should not raise
        datetime.fromisoformat(inv["generated_at"].replace("Z", "+00:00"))

    def test_inventory_schema_version_matches(self, tmp_path):
        fake_home = tmp_path / "sv_home"
        fake_home.mkdir()
        inv = build_inventory_fn(env={"HOME": str(fake_home)})
        assert inv["schema_version"] == 1

    def test_inventory_ecosystems_list_is_ordered(self, tmp_path):
        fake_home = tmp_path / "order_home"
        fake_home.mkdir()
        inv = build_inventory_fn(env={"HOME": str(fake_home)})
        # Order must match config declaration order for stable JSON diffs
        keys = [e["key"] for e in inv["ecosystems"]]
        assert keys == ["claude_code", "codex", "openclaw", "nanoclaw"]


# ---------------------------------------------------------------------------
# Non-breaking invariant: inventory runs against real filesystem without
# crashing, regardless of what is or isn't installed.
# ---------------------------------------------------------------------------


class TestRealFilesystemSmoke:
    def test_build_inventory_runs_against_real_home(self):
        """Smoke test: build_inventory must not crash when pointed at the
        real $HOME, whatever its contents. This is the minimum production
        safety invariant."""
        inv = build_inventory_fn()
        assert inv["schema_version"] == 1
        assert isinstance(inv["ecosystems"], list)
        assert len(inv["ecosystems"]) == 4

    def test_json_serializable(self):
        """Every field in the inventory must be JSON-serializable."""
        inv = build_inventory_fn()
        # Round-trip through json.dumps; will raise TypeError on bad types
        serialized = json.dumps(inv)
        assert len(serialized) > 0
        round_tripped = json.loads(serialized)
        assert round_tripped["schema_version"] == 1
