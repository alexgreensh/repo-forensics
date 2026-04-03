"""Tests for scan_infra.py - Infrastructure Security Scanner."""

import os
import pytest
import scan_infra as scanner


def _scan_repo(repo_path):
    """Dispatch to appropriate scan_infra functions by filename."""
    import forensics_core as core
    findings = []
    for fp, rp in core.walk_repo(str(repo_path), skip_lockfiles=False):
        basename = os.path.basename(fp)
        if basename == 'Dockerfile' or basename.endswith('.dockerfile'):
            findings.extend(scanner.scan_dockerfile(fp, rp))
        elif fp.endswith(('.yml', '.yaml')):
            if '.github/workflows' in fp:
                findings.extend(scanner.scan_github_actions(fp, rp))
            else:
                findings.extend(scanner.scan_kubernetes(fp, rp))
        elif basename in ('settings.json', 'claude_desktop_config.json'):
            findings.extend(scanner.scan_claude_config(fp, rp))
    return findings


class TestDockerfile:
    def test_detects_secrets_in_env(self, repo_with_infra_issues):
        findings = scanner.scan_dockerfile(
            str(repo_with_infra_issues / "Dockerfile"), "Dockerfile"
        )
        assert any("secret" in f.title.lower() or "secret" in f.snippet.lower() for f in findings)


class TestGitHubActions:
    def test_detects_pull_request_target(self, repo_with_infra_issues):
        ci_path = str(repo_with_infra_issues / ".github" / "workflows" / "ci.yml")
        findings = scanner.scan_github_actions(ci_path, ".github/workflows/ci.yml")
        assert any("pull_request_target" in f.snippet for f in findings)

    def test_detects_unpinned_action(self, repo_with_infra_issues):
        ci_path = str(repo_with_infra_issues / ".github" / "workflows" / "ci.yml")
        findings = scanner.scan_github_actions(ci_path, ".github/workflows/ci.yml")
        assert any("pin" in f.title.lower() or "@main" in f.snippet for f in findings)

    def test_detects_expression_injection(self, repo_with_infra_issues):
        ci_path = str(repo_with_infra_issues / ".github" / "workflows" / "ci.yml")
        findings = scanner.scan_github_actions(ci_path, ".github/workflows/ci.yml")
        assert any("expression" in f.title.lower() or "github.event" in f.snippet for f in findings)

    def test_detects_npm_install_in_run_block(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        ci.write_text(
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: npm install\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        assert any("npm install" in f.title.lower() for f in findings)

    def test_detects_npm_install_in_multiline_run_block(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        ci.write_text(
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          npm install\n"
            "          npm test\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        assert any("multi-line run block" in f.title.lower() for f in findings)


class TestNpmrc:
    def test_detects_strict_ssl_false(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("strict-ssl=false\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert any(f.severity == "critical" and "ssl" in f.title.lower() for f in findings)

    def test_detects_package_lock_false(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("package-lock=false\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert any(f.severity == "high" and "lockfile" in f.title.lower() for f in findings)

    def test_detects_missing_ignore_scripts(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("registry=https://registry.npmjs.org/\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert any("ignore-scripts" in f.title.lower() for f in findings)

    def test_ignore_scripts_true_no_finding(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("ignore-scripts=true\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert not any("ignore-scripts" in f.title.lower() for f in findings)

    def test_all_hardening_present_no_findings(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("ignore-scripts=true\nallow-git=none\nmin-release-age=3\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert not any("ignore-scripts" in f.title.lower() for f in findings)
        assert not any("allow-git" in f.title.lower() for f in findings)
        assert not any("min-release-age" in f.title.lower() for f in findings)

    def test_detects_missing_allow_git_none(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("ignore-scripts=true\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert any("allow-git" in f.title.lower() for f in findings)

    def test_allow_git_none_no_finding(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("ignore-scripts=true\nallow-git=none\nmin-release-age=3\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert not any("allow-git" in f.title.lower() for f in findings)

    def test_detects_missing_min_release_age(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("ignore-scripts=true\nallow-git=none\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert any("min-release-age" in f.title.lower() for f in findings)

    def test_min_release_age_three_no_finding(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("ignore-scripts=true\nallow-git=none\nmin-release-age=3\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert not any("min-release-age" in f.title.lower() for f in findings)

    def test_detects_custom_git_override(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("git=/tmp/evil-git\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert any(f.severity == "critical" and "git" in f.title.lower() for f in findings)

    def test_system_git_path_ok(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("git=/usr/bin/git\n")
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        assert not any("git" in f.title.lower() and "override" in f.title.lower() for f in findings)

    def test_elevated_severity_with_hooks(self, tmp_path):
        """Missing ignore-scripts should be HIGH when lifecycle hooks exist."""
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("registry=https://registry.npmjs.org/\n")
        pkg = tmp_path / "package.json"
        pkg.write_text('{"scripts":{"postinstall":"node setup.js"}}')
        findings = scanner.scan_npmrc(str(npmrc), ".npmrc")
        ignore_findings = [f for f in findings if "ignore-scripts" in f.title.lower()]
        assert any(f.severity == "high" for f in ignore_findings)


class TestPnpmWorkspace:
    def test_detects_dangerously_allow_all_builds(self, tmp_path):
        ws = tmp_path / "pnpm-workspace.yaml"
        ws.write_text("packages:\n  - apps/*\nonlyBuiltDependencies:\n  dangerouslyAllowAllBuilds: true\n")
        findings = scanner.scan_pnpm_workspace(str(ws), "pnpm-workspace.yaml")
        assert any(f.severity == "critical" for f in findings)


class TestCleanRepo:
    def test_clean_repo_minimal_findings(self, clean_repo):
        findings = _scan_repo(clean_repo)
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) == 0
