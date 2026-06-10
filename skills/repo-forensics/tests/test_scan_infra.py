"""Tests for scan_infra.py - Infrastructure Security Scanner."""

import os
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


class TestDockerArgSecrets:
    def test_detects_arg_with_secret_keyword(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu:latest\nARG API_KEY=sk-live-1234567890\nRUN echo $API_KEY\n")
        findings = scanner.scan_dockerfile(str(df), "Dockerfile")
        assert any("ARG" in f.title for f in findings)

    def test_arg_secret_is_critical(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM node:20\nARG DB_PASSWORD=hunter2\n")
        findings = scanner.scan_dockerfile(str(df), "Dockerfile")
        arg_findings = [f for f in findings if "ARG" in f.title]
        assert all(f.severity == "critical" for f in arg_findings)

    def test_no_false_positive_on_safe_arg(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:3.12\nARG APP_VERSION=1.0.0\nARG NODE_ENV=production\n")
        findings = scanner.scan_dockerfile(str(df), "Dockerfile")
        assert not any("ARG" in f.title for f in findings)


class TestDockerEnvCopy:
    def test_detects_copy_env_file(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM node:20\nCOPY .env /app/.env\nRUN node app.js\n")
        findings = scanner.scan_dockerfile(str(df), "Dockerfile")
        assert any(".env File Copied" in f.title for f in findings)

    def test_detects_add_env_file(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM node:20\nADD .env.production /app/\n")
        findings = scanner.scan_dockerfile(str(df), "Dockerfile")
        assert any(".env File Copied" in f.title for f in findings)

    def test_no_false_positive_env_example(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM node:20\nCOPY .env.example /app/.env.example\n")
        findings = scanner.scan_dockerfile(str(df), "Dockerfile")
        assert not any(".env File Copied" in f.title for f in findings)

    def test_no_false_positive_environment_dir(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM node:20\nCOPY environments/ /app/environments/\n")
        findings = scanner.scan_dockerfile(str(df), "Dockerfile")
        assert not any(".env File Copied" in f.title for f in findings)


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

    def test_does_not_flag_npm_install_ci_test_single_line(self, tmp_path):
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
            "      - run: npm install-ci-test\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        assert not any("npm install" in f.title.lower() for f in findings)

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

    def test_does_not_flag_npm_install_in_shell_comment(self, tmp_path):
        """Quote-aware comment stripping correctly handles # in comments."""
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
            "      - run: echo test # npm install was here\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        assert not any("npm install" in f.title.lower() for f in findings)

    def test_detects_npm_install_after_url_fragment(self, tmp_path):
        """Quote-aware stripping does NOT strip # inside URLs without quotes."""
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
            '      - run: curl "https://example.com/setup#v2" && npm install\n'
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        assert any("npm install" in f.title.lower() for f in findings)

    def test_does_not_flag_npm_install_in_multiline_comment(self, tmp_path):
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
            "          # Don't use npm install in production\n"
            "          npm ci\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        assert not any("npm install" in f.title.lower() for f in findings)

    def test_does_not_flag_npm_install_ci_test_multiline(self, tmp_path):
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
            "          npm install-ci-test\n"
            "          echo done\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        assert not any("npm install" in f.title.lower() for f in findings)


class TestAgenticCI:
    """Claude Code GitHub Action secret exposure guardrails."""

    def test_claude_action_untrusted_trigger_with_secrets_and_tools(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "claude.yml"
        ci.write_text(
            "name: Claude\n"
            "on:\n"
            "  issue_comment:\n"
            "permissions:\n"
            "  contents: write\n"
            "  issues: write\n"
            "jobs:\n"
            "  agent:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: anthropics/claude-code-action@v2\n"
            "        with:\n"
            "          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n"
            "          allowed_tools: Read,Bash,WebFetch,mcp__github\n"
            "          show_full_output: true\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/claude.yml")
        agentic = [f for f in findings if f.category == "agentic-ci"]
        assert any("Agentic CI Secret Exposure" in f.title for f in agentic)
        assert any(f.severity == "critical" for f in agentic)

    def test_claude_action_scalar_untrusted_trigger_with_secrets_and_tools(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "claude.yml"
        ci.write_text(
            "name: Claude\n"
            "on: issue_comment\n"
            "jobs:\n"
            "  agent:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: anthropics/claude-code-action@v2\n"
            "        with:\n"
            "          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n"
            "          allowed_tools: Read,Bash,WebFetch,mcp__github\n"
            "          show_full_output: true\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/claude.yml")
        agentic = [f for f in findings if f.category == "agentic-ci"]
        assert any("Agentic CI Secret Exposure" in f.title for f in agentic)

    def test_claude_action_quoted_scalar_untrusted_trigger_with_secrets_and_tools(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "claude.yml"
        ci.write_text(
            "name: Claude\n"
            "'on': 'pull_request'\n"
            "jobs:\n"
            "  agent:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: anthropics/claude-code-action@v2\n"
            "        with:\n"
            "          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n"
            "          allowed_tools: Read,Bash,WebFetch,mcp__github\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/claude.yml")
        agentic = [f for f in findings if f.category == "agentic-ci"]
        assert any("Agentic CI Secret Exposure" in f.title for f in agentic)

    def test_proc_environ_path_is_critical(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "claude.yml"
        ci.write_text(
            "name: Claude\n"
            "on: [pull_request]\n"
            "jobs:\n"
            "  agent:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo /proc/self/environ\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/claude.yml")
        assert any(f.category == "agentic-ci" and f.severity == "critical" for f in findings)

    def test_push_only_claude_action_with_secrets_not_agentic_ci(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "claude.yml"
        ci.write_text(
            "name: Claude\n"
            "on:\n"
            "  push:\n"
            "jobs:\n"
            "  agent:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: anthropics/claude-code-action@v2\n"
            "        with:\n"
            "          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n"
            "          allowed_tools: Read,Bash\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/claude.yml")
        assert not any("Agentic CI Secret Exposure" in f.title for f in findings)


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

    def test_non_utf8_package_json_does_not_crash(self, tmp_path):
        """A non-UTF8 sibling package.json must NOT abort the npmrc scan with a
        UnicodeDecodeError (a ValueError subclass that the old narrow except did
        not catch). The scan should still surface the missing-ignore-scripts
        finding."""
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("registry=https://registry.npmjs.org/\n")
        # Invalid UTF-8 bytes that decode-replace can tolerate but utf-8 cannot.
        (tmp_path / "package.json").write_bytes(b'{"scripts": {"\xff\xfe": "x"}}')
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


class TestTanStackCIVector:
    """pull_request_target + id-token: write combo detection."""

    def test_prt_plus_id_token_write_critical(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        ci.write_text(
            "name: CI\non:\n  pull_request_target:\n"
            "permissions:\n  id-token: write\n  contents: read\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        combo = [f for f in findings if "TanStack" in f.title]
        assert len(combo) >= 1
        assert combo[0].severity == "critical"

    def test_id_token_write_alone_medium(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        ci.write_text(
            "name: CI\non:\n  push:\n"
            "permissions:\n  id-token: write\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        id_token = [f for f in findings if "id-token" in f.title.lower()]
        assert len(id_token) >= 1
        assert any(f.severity == "medium" for f in id_token)

    def test_prt_without_id_token_no_combo(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        ci.write_text(
            "name: CI\non:\n  pull_request_target:\n"
            "permissions:\n  contents: read\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        combo = [f for f in findings if "TanStack" in f.title]
        assert len(combo) == 0


class TestCachePoisoningPRT:
    """pull_request_target + actions/cache = cache poisoning via forked PR."""

    def test_prt_plus_cache_critical(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        ci.write_text(
            "name: CI\non:\n  pull_request_target:\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/cache@v3\n"
            "        with:\n"
            "          key: npm-${{ hashFiles('package-lock.json') }}\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        cache = [f for f in findings if "Cache Poisoning" in f.title]
        assert len(cache) >= 1
        assert cache[0].severity == "critical"

    def test_pull_request_no_target_no_cache_poison(self, tmp_path):
        """pull_request (not _target) + cache -> no cache poisoning finding."""
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        ci.write_text(
            "name: CI\non:\n  pull_request:\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/cache@v3\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        cache = [f for f in findings if "Cache Poisoning" in f.title]
        assert len(cache) == 0

    def test_prt_no_cache_no_poison(self, tmp_path):
        """pull_request_target without cache -> no cache poisoning finding."""
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        ci.write_text(
            "name: CI\non:\n  pull_request_target:\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        cache = [f for f in findings if "Cache Poisoning" in f.title]
        assert len(cache) == 0

    def test_push_plus_cache_no_poison(self, tmp_path):
        """push trigger + cache -> no cache poisoning finding."""
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        ci.write_text(
            "name: CI\non:\n  push:\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/cache@v3\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        cache = [f for f in findings if "Cache Poisoning" in f.title]
        assert len(cache) == 0


class TestCacheLineTracking:
    """Cache action line tracking: enumerate() vs list.index() regression."""

    def test_second_cache_action_reports_correct_line(self, tmp_path):
        """When two identical 'uses: actions/cache@v3' lines exist, the unsafe
        second occurrence must be reported at its own line, not the first line.

        With list.index() (bug): processing the second cache resolves back to
        the first occurrence's index, looks ahead and finds the safe hashFiles
        key -> emits zero findings (silent miss).

        With enumerate() (fix): uses the current iteration index -> looks ahead
        from the second cache line, finds the static key -> emits one finding
        at the correct line number.
        """
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        # Both 'uses:' lines are textually identical (same indentation) so that
        # list.index() always resolves to the first occurrence.
        ci.write_text(
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: Restore npm cache\n"
            "        uses: actions/cache@v3\n"
            "        with:\n"
            "          key: ${{ hashFiles('**/package-lock.json') }}\n"
            "      - name: Restore pip cache\n"
            "        uses: actions/cache@v3\n"
            "        with:\n"
            "          key: pip-static-key\n"
        )
        # Line numbers: the second 'uses: actions/cache@v3' is line 12 (1-indexed).
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        cache_findings = [f for f in findings if "Cache Key Without Content Hash" in f.title]
        assert len(cache_findings) == 1, (
            f"Expected 1 cache-key finding, got {len(cache_findings)}. "
            "If 0, list.index() resolved second occurrence to first line and "
            "looked up the safe hashFiles key instead of the static key."
        )
        assert cache_findings[0].line == 12, (
            f"Expected finding at line 12 (second cache action), got line {cache_findings[0].line}. "
            "list.index() would have returned line 8 (first occurrence)."
        )


class TestBase64DecodeAndExecute:
    """Megalodon-style base64 decode-and-execute detection (May 2026)."""

    def _make_workflow(self, tmp_path, run_line):
        """Helper: create a minimal workflow with the given single-line run command."""
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
            f"      - run: {run_line}\n"
        )
        return str(ci)

    def _make_multiline_workflow(self, tmp_path, *run_lines):
        """Helper: create a workflow with a multi-line run block."""
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        body = "\n".join(f"          {ln}" for ln in run_lines)
        ci.write_text(
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            f"{body}\n"
        )
        return str(ci)

    def _megalodon_findings(self, findings):
        return [f for f in findings if "Megalodon" in f.title]

    # ------------------------------------------------------------------ #
    # True-positive: decode-and-pipe patterns                              #
    # ------------------------------------------------------------------ #

    def test_echo_pipe_base64_d_pipe_bash(self, tmp_path):
        """echo ... | base64 -d | bash is the canonical Megalodon pattern."""
        ci = self._make_workflow(
            tmp_path,
            'echo "Q0I9Imh0dHBzOi8vZXZpbC5jb20vcGF5bG9hZCI=" | base64 -d | bash'
        )
        findings = scanner.scan_github_actions(ci, ".github/workflows/ci.yml")
        hits = self._megalodon_findings(findings)
        assert len(hits) >= 1
        assert hits[0].severity == "critical"
        assert hits[0].category == "ci-cd"

    def test_echo_env_pipe_base64_decode_sh(self, tmp_path):
        """echo $SECRET | base64 --decode | sh variant."""
        ci = self._make_workflow(
            tmp_path,
            "echo $SECRET | base64 --decode | sh"
        )
        findings = scanner.scan_github_actions(ci, ".github/workflows/ci.yml")
        hits = self._megalodon_findings(findings)
        assert len(hits) >= 1
        assert hits[0].severity == "critical"

    def test_base64_d_heredoc_pipe_python3(self, tmp_path):
        """base64 -d <<< "$PAYLOAD" | python3 heredoc variant."""
        ci = self._make_workflow(
            tmp_path,
            'base64 -d <<< "$PAYLOAD" | python3'
        )
        findings = scanner.scan_github_actions(ci, ".github/workflows/ci.yml")
        hits = self._megalodon_findings(findings)
        assert len(hits) >= 1
        assert hits[0].severity == "critical"

    # ------------------------------------------------------------------ #
    # False-positive: encode-only patterns must NOT fire                   #
    # ------------------------------------------------------------------ #

    def test_no_false_positive_base64_encode_only(self, tmp_path):
        """base64 -w0 < file > output.b64 (encoding, not decoding) must not fire."""
        ci = self._make_workflow(
            tmp_path,
            "base64 -w0 < service_account.json > encoded.b64"
        )
        findings = scanner.scan_github_actions(ci, ".github/workflows/ci.yml")
        hits = self._megalodon_findings(findings)
        assert len(hits) == 0

    def test_no_false_positive_base64_env_var_read_no_pipe(self, tmp_path):
        """Legitimate base64 env var read that is NOT piped to a shell must not fire."""
        ci = self._make_workflow(
            tmp_path,
            "DECODED=$(echo $GCP_SA_KEY | base64 --decode) && echo $DECODED > sa.json"
        )
        findings = scanner.scan_github_actions(ci, ".github/workflows/ci.yml")
        hits = self._megalodon_findings(findings)
        assert len(hits) == 0

    # ------------------------------------------------------------------ #
    # workflow_dispatch trigger + decode-and-execute                       #
    # ------------------------------------------------------------------ #

    def test_workflow_dispatch_trigger_with_decode_and_execute(self, tmp_path):
        """workflow_dispatch trigger + decode-and-execute is still CRITICAL."""
        workflow = tmp_path / ".github" / "workflows"
        workflow.mkdir(parents=True)
        ci = workflow / "ci.yml"
        ci.write_text(
            "name: Deploy\n"
            "on:\n"
            "  workflow_dispatch:\n"
            "    inputs:\n"
            "      payload:\n"
            "        description: 'Encoded payload'\n"
            "        required: true\n"
            "jobs:\n"
            "  run:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo ${{ inputs.payload }} | base64 -d | bash\n"
        )
        findings = scanner.scan_github_actions(str(ci), ".github/workflows/ci.yml")
        hits = self._megalodon_findings(findings)
        assert len(hits) >= 1
        assert hits[0].severity == "critical"

    # ------------------------------------------------------------------ #
    # Multi-line run block variants                                        #
    # ------------------------------------------------------------------ #

    def test_multiline_block_base64_decode_pipe_bash(self, tmp_path):
        """Multi-line run block containing base64 -d | bash must be detected."""
        ci = self._make_multiline_workflow(
            tmp_path,
            "echo 'Setting up environment'",
            'echo "cGF5bG9hZA==" | base64 -d | bash',
            "echo 'Done'",
        )
        findings = scanner.scan_github_actions(ci, ".github/workflows/ci.yml")
        hits = self._megalodon_findings(findings)
        assert len(hits) >= 1
        assert hits[0].severity == "critical"
