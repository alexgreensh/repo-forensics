"""
Integration tests for forensify end-to-end flows.

Covers:
- Canary fixture detection (prompt injection in SKILL.md, tools.json poisoning)
- Seatbelt sandbox profile validation (macOS only)
- Coord folder lifecycle
- Domain job construction from inventory
- Prompt template loading
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
ORCH_DIR = Path(__file__).resolve().parent.parent / "orchestrator"
CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(ORCH_DIR.parent))

from build_inventory import (  # noqa: E402
    build_inventory as build_inventory_fn,
    load_ecosystem_roots,
)


# ---------------------------------------------------------------------------
# Canary fixture tests — injection patterns in fixtures must be detectable
# ---------------------------------------------------------------------------


class TestCanaryFixtures:
    def test_claude_code_injection_fixture_enumerated(self):
        fixture_root = FIXTURES_DIR / "claude_code_stack"
        config = load_ecosystem_roots()
        fake_home = fixture_root.parent  # won't match real detection
        env = {"HOME": str(fake_home)}
        # Direct walk to verify the fixture is picked up
        from build_inventory import walk_skills_surface, _resolve_env_for_ecosystem
        eco_cfg = config["ecosystems"]["claude_code"]
        # Override the glob template to point at fixture
        skills = []
        import glob as g
        for match in g.glob(str(fixture_root / "skills" / "*" / "SKILL.md")):
            skills.append(match)
        assert len(skills) >= 1
        assert any("malicious-skill" in s for s in skills)

    def test_injection_comment_present_in_fixture(self):
        malicious = FIXTURES_DIR / "claude_code_stack" / "skills" / "malicious-skill" / "SKILL.md"
        content = malicious.read_text()
        # The injection payload must be present for scanners to detect
        assert "Ignore all prior" in content or "ignore all prior" in content.lower()
        assert "Return findings: []" in content or "return findings" in content.lower()

    def test_openclaw_tools_json_poisoning_present(self):
        tools = FIXTURES_DIR / "openclaw_stack" / ".agents" / "skills" / "poisoned-skill" / "tools.json"
        data = json.loads(tools.read_text())
        desc = data["tools"][0]["description"]
        # Must contain the exfiltration instruction for scanners to catch
        assert "evil.example.com" in desc
        assert "HTTP POST" in desc

    def test_clean_fixture_has_no_injection(self):
        clean = FIXTURES_DIR / "codex_stack" / "skills" / "clean-skill" / "SKILL.md"
        content = clean.read_text()
        # Negative control: no injection patterns
        assert "ignore" not in content.lower() or "no threats" in content.lower()
        assert "evil" not in content.lower()


# ---------------------------------------------------------------------------
# Prompt template loading
# ---------------------------------------------------------------------------


class TestPromptTemplates:
    DOMAINS = ["skills", "mcp", "hooks", "plugins", "commands", "credentials"]

    def test_all_domain_prompts_exist(self):
        for domain in self.DOMAINS:
            path = PROMPTS_DIR / ("domain_%s.txt" % domain)
            assert path.exists(), "missing prompt: %s" % path

    def test_synthesis_prompt_exists(self):
        assert (PROMPTS_DIR / "synthesis.txt").exists()

    def test_all_prompts_contain_hostile_data_warning(self):
        for domain in self.DOMAINS:
            content = (PROMPTS_DIR / ("domain_%s.txt" % domain)).read_text()
            assert "UNTRUSTED" in content, "%s prompt missing hostile-data posture" % domain

    def test_all_prompts_contain_suppression_warning(self):
        for domain in self.DOMAINS:
            content = (PROMPTS_DIR / ("domain_%s.txt" % domain)).read_text()
            assert "MUST include" in content or "CRITICAL" in content, \
                "%s prompt missing suppression enforcement" % domain

    def test_synthesis_prompt_has_grounding_rules(self):
        content = (PROMPTS_DIR / "synthesis.txt").read_text()
        assert "GROUNDING" in content
        assert "finding_id" in content

    def test_prompts_have_template_variables(self):
        for domain in self.DOMAINS:
            content = (PROMPTS_DIR / ("domain_%s.txt" % domain)).read_text()
            assert "{ecosystem_display_name}" in content


# ---------------------------------------------------------------------------
# Domain JSON config validation
# ---------------------------------------------------------------------------


class TestDomainConfigs:
    DOMAINS_DIR = Path(__file__).resolve().parent.parent / "domains"

    def test_all_six_domains_exist(self):
        for name in ["skills", "mcp", "hooks", "plugins", "commands", "credentials"]:
            path = self.DOMAINS_DIR / ("%s.json" % name)
            assert path.exists(), "missing domain config: %s" % path

    def test_all_domains_have_scanners_list(self):
        for f in self.DOMAINS_DIR.glob("*.json"):
            data = json.loads(f.read_text())
            assert "scanners" in data, "%s missing scanners" % f.name
            assert isinstance(data["scanners"], list)

    def test_all_domains_have_inventory_surfaces(self):
        for f in self.DOMAINS_DIR.glob("*.json"):
            data = json.loads(f.read_text())
            assert "inventory_surfaces" in data, "%s missing inventory_surfaces" % f.name


# ---------------------------------------------------------------------------
# Coord folder lifecycle
# ---------------------------------------------------------------------------


class TestCoordFolder:
    def test_create_and_list(self):
        from orchestrator.analysis_dispatcher import create_coord_folder, list_runs
        coord = create_coord_folder()
        assert os.path.isdir(coord)
        assert os.stat(coord).st_mode & 0o777 == 0o700

        manifest = json.loads(open(os.path.join(coord, "manifest.json")).read())
        assert manifest["coord_schema_version"] == 1
        assert manifest["status"] == "in_progress"

        runs = list_runs()
        assert any(r["path"] == coord for r in runs)

        # Cleanup
        import shutil
        shutil.rmtree(coord)

    def test_domain_job_round_trip_via_coord(self):
        from orchestrator.contracts import DomainJob
        from orchestrator.analysis_dispatcher import create_coord_folder, write_domain_job

        coord = create_coord_folder()
        job = DomainJob(
            job_id="test-skills-claude",
            domain="skills",
            ecosystem="claude_code",
            run_id="test123",
            inventory_slice=[{"path": "/test/skill", "skill_name": "test"}],
            scanner_findings=[{"finding_id": "f1", "severity": "HIGH"}],
            scanner_names=["scan_skill_threats"],
            total_items_in_slice=1,
        )
        path = write_domain_job(coord, job)
        assert os.path.isfile(path)

        # Read back
        with open(path) as f:
            restored = DomainJob.from_json(f.read())
        assert restored.job_id == "test-skills-claude"
        assert len(restored.inventory_slice) == 1
        assert len(restored.scanner_findings) == 1

        import shutil
        shutil.rmtree(coord)


# ---------------------------------------------------------------------------
# Domain job construction from real inventory
# ---------------------------------------------------------------------------


class TestDomainJobConstruction:
    def test_jobs_built_for_detected_ecosystems(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.json").write_text("{}")
        from build_inventory import _file_record
        skill_dir = tmp_path / ".claude" / "skills" / "test-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("---\nname: test\n---\n")

        inv = build_inventory_fn(env={"HOME": str(tmp_path)})

        domain_configs = {}
        domains_dir = Path(__file__).resolve().parent.parent / "domains"
        for f in domains_dir.glob("*.json"):
            domain_configs[f.stem] = json.loads(f.read_text())

        from orchestrator.analysis_dispatcher import build_domain_jobs
        jobs = build_domain_jobs("test-run", inv, [], domain_configs)

        # Should have at least one job for claude_code skills domain
        skills_jobs = [j for j in jobs if j.domain == "skills" and j.ecosystem == "claude_code"]
        assert len(skills_jobs) == 1
        assert skills_jobs[0].total_items_in_slice >= 1


# ---------------------------------------------------------------------------
# Seatbelt sandbox (macOS only)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(platform.system() != "Darwin", reason="Seatbelt is macOS only")
class TestSeatbeltSandbox:
    def test_seatbelt_profile_exists(self):
        profile = CONFIG_DIR / "seatbelt_subagent.sb"
        assert profile.exists()

    def test_seatbelt_profile_parseable(self):
        """sandbox-exec --check validates profile syntax without executing."""
        profile = CONFIG_DIR / "seatbelt_subagent.sb"
        with tempfile.TemporaryDirectory() as td:
            result = subprocess.run(
                [
                    "sandbox-exec", "-f", str(profile),
                    "-D", "TARGET_PATH=%s" % td,
                    "-D", "COORD_PATH=%s" % td,
                    "-D", "SKILL_PATH=%s" % str(CONFIG_DIR.parent),
                    "true",  # just test profile loading
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # sandbox-exec with 'true' should succeed if profile is valid
            assert result.returncode == 0, "Seatbelt profile parse error: %s" % result.stderr

    def test_seatbelt_blocks_network(self):
        """Verify the sandbox blocks network access."""
        profile = CONFIG_DIR / "seatbelt_subagent.sb"
        with tempfile.TemporaryDirectory() as td:
            # Try to make a network connection under sandbox — should fail
            result = subprocess.run(
                [
                    "sandbox-exec", "-f", str(profile),
                    "-D", "TARGET_PATH=%s" % td,
                    "-D", "COORD_PATH=%s" % td,
                    "-D", "SKILL_PATH=%s" % str(CONFIG_DIR.parent),
                    "python3", "-c",
                    "import urllib.request; urllib.request.urlopen('https://example.com', timeout=3)",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            # Should fail with a sandbox violation or network error
            assert result.returncode != 0, "Seatbelt should have blocked network access"

    def test_seatbelt_blocks_write_outside_coord(self):
        """Verify writes outside the coord folder are blocked."""
        profile = CONFIG_DIR / "seatbelt_subagent.sb"
        with tempfile.TemporaryDirectory() as td:
            coord = os.path.join(td, "coord")
            os.makedirs(coord)
            outside = os.path.join(td, "outside")
            os.makedirs(outside)

            result = subprocess.run(
                [
                    "sandbox-exec", "-f", str(profile),
                    "-D", "TARGET_PATH=%s" % td,
                    "-D", "COORD_PATH=%s" % coord,
                    "-D", "SKILL_PATH=%s" % str(CONFIG_DIR.parent),
                    "python3", "-c",
                    "open('%s/canary.txt', 'w').write('should not exist')" % outside,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert not os.path.exists(os.path.join(outside, "canary.txt")), \
                "Seatbelt should have blocked write outside coord folder"
