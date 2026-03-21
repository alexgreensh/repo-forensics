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


class TestCleanRepo:
    def test_clean_repo_minimal_findings(self, clean_repo):
        findings = _scan_repo(clean_repo)
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) == 0
