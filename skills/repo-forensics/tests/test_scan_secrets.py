"""Tests for scan_secrets.py - Secret Scanner."""

import scan_secrets as scanner


class TestSecretDetection:
    def test_detects_aws_key(self, repo_with_secrets):
        findings = _scan_repo(repo_with_secrets)
        assert any("AWS" in f.title for f in findings)

    def test_detects_openai_key(self, tmp_path):
        config = tmp_path / "config.py"
        # Use a realistic OpenAI key format that matches the scanner pattern
        config.write_text("OPENAI_KEY = 'sk-abcdefghijklmnopqrstuvwxyz123456789012345678'\n")
        findings = _scan_repo(tmp_path)
        assert any("OpenAI" in f.title or "AI Provider" in f.title or "API" in f.title.upper()
                    for f in findings)

    def test_detects_stripe_key(self, tmp_path):
        config = tmp_path / "config.py"
        config.write_text("STRIPE = 'sk_live_abcdefghijklmnopqrstuvwx'\n")
        findings = _scan_repo(tmp_path)
        assert any("Stripe" in f.title or "sk_live" in f.snippet for f in findings)

    def test_detects_db_uri(self, repo_with_secrets):
        findings = _scan_repo(repo_with_secrets)
        assert any("database" in f.title.lower() or "postgresql" in f.snippet.lower() for f in findings)

    def test_detects_codex_api_key_env_var(self, tmp_path):
        config = tmp_path / ".env"
        config.write_text("CODEX_API_KEY=codex_live_abcdefghijklmnopqrstuvwxyz123456\n")
        findings = _scan_repo(tmp_path)
        assert any("CODEX_API_KEY" in f.title for f in findings)


class TestFrameworkEnvPrefixLeaks:
    def test_detects_next_public_secret(self, repo_with_framework_env_leak):
        findings = _scan_repo(repo_with_framework_env_leak)
        assert any("NEXT_PUBLIC" in f.title for f in findings)

    def test_detects_react_app_secret(self, repo_with_framework_env_leak):
        findings = _scan_repo(repo_with_framework_env_leak)
        assert any("REACT_APP" in f.title for f in findings)

    def test_detects_vite_secret(self, repo_with_framework_env_leak):
        findings = _scan_repo(repo_with_framework_env_leak)
        assert any("VITE" in f.title for f in findings)

    def test_detects_expo_public_secret(self, repo_with_framework_env_leak):
        findings = _scan_repo(repo_with_framework_env_leak)
        assert any("EXPO_PUBLIC" in f.title for f in findings)

    def test_detects_gatsby_secret(self, repo_with_framework_env_leak):
        findings = _scan_repo(repo_with_framework_env_leak)
        assert any("GATSBY" in f.title for f in findings)

    def test_detects_nx_public_secret(self, repo_with_framework_env_leak):
        findings = _scan_repo(repo_with_framework_env_leak)
        assert any("NX_PUBLIC" in f.title for f in findings)


class Test1PasswordTokens:
    def test_detects_op_connect_token(self, repo_with_1password_token):
        findings = _scan_repo(repo_with_1password_token)
        assert any("1Password Connect" in f.title or "OP_CONNECT_TOKEN" in f.title for f in findings)

    def test_detects_ops_service_account_token(self, repo_with_1password_token):
        findings = _scan_repo(repo_with_1password_token)
        assert any("Service Account" in f.title or "ops_" in f.snippet for f in findings)


class TestEnvVariantFiles:
    def test_flags_committed_env_file(self, repo_with_env_files):
        findings = _scan_repo(repo_with_env_files)
        env_findings = [f for f in findings if "Unencrypted" in f.title]
        flagged_files = {f.title for f in env_findings}
        assert any(".env " in t or ".env File" in t for t in flagged_files)

    def test_flags_env_production(self, repo_with_env_files):
        findings = _scan_repo(repo_with_env_files)
        assert any(".env.production" in f.title for f in findings)

    def test_flags_env_local(self, repo_with_env_files):
        findings = _scan_repo(repo_with_env_files)
        assert any(".env.local" in f.title for f in findings)

    def test_does_not_flag_env_example(self, repo_with_env_files):
        findings = _scan_repo(repo_with_env_files)
        assert not any(".env.example" in f.title for f in findings)

    def test_env_file_severity_is_high(self, repo_with_env_files):
        findings = _scan_repo(repo_with_env_files)
        env_findings = [f for f in findings if "Unencrypted" in f.title]
        assert all(f.severity == "high" for f in env_findings)

    def test_env_file_category_is_secret_storage(self, repo_with_env_files):
        findings = _scan_repo(repo_with_env_files)
        env_findings = [f for f in findings if "Unencrypted" in f.title]
        assert all(f.category == "secret-storage" for f in env_findings)


class TestCleanRepo:
    def test_no_false_positives(self, clean_repo):
        findings = _scan_repo(clean_repo)
        high_plus = [f for f in findings if f.severity in ("critical", "high")]
        assert len(high_plus) == 0


def _scan_repo(repo_path):
    import forensics_core as core
    findings = []
    for fp, rp in core.walk_repo(str(repo_path)):
        findings.extend(scanner.scan_file(fp, rp))
    return findings


# ---------------------------------------------------------------------------
# B6 regression: pack-load-failure finding emitted exactly once per run
# ---------------------------------------------------------------------------

class TestPackLoadErrorDeduplication:
    """B6: when the rule pack fails to load, scan_file must emit the diagnostic
    finding exactly ONCE across all files, never once per file."""

    def test_pack_load_error_emitted_once_not_per_file(self, tmp_path, monkeypatch):
        """Simulate pack-load failure and verify exactly one critical finding
        across multiple files — NOT one per file."""
        # Create several files so the walker visits multiple paths.
        for i in range(5):
            (tmp_path / f"file{i}.py").write_text(f"x = {i}\n")

        # Force PACK_LOAD_ERROR and reset the per-run guard so the test is
        # isolated from import-time state.
        monkeypatch.setattr(scanner, "PACK_LOAD_ERROR", True)
        monkeypatch.setattr(scanner, "_pack_error_emitted", False)

        import forensics_core as core
        findings = []
        for fp, rp in core.walk_repo(str(tmp_path)):
            findings.extend(scanner.scan_file(fp, rp))

        pack_errors = [f for f in findings if f.category == "scanner-integrity"]
        assert len(pack_errors) == 1, (
            f"Expected exactly 1 pack-load-error finding, got {len(pack_errors)}"
        )
        assert pack_errors[0].severity == "critical"

    def test_pack_load_error_finding_is_critical(self, tmp_path, monkeypatch):
        """The single emitted pack-load finding must be critical severity."""
        (tmp_path / "a.py").write_text("x = 1\n")
        monkeypatch.setattr(scanner, "PACK_LOAD_ERROR", True)
        monkeypatch.setattr(scanner, "_pack_error_emitted", False)

        finding = scanner.scan_file(str(tmp_path / "a.py"), "a.py")
        assert len(finding) == 1
        assert finding[0].severity == "critical"
        assert "reinstall" in finding[0].description.lower()

    def test_second_call_returns_empty_on_pack_error(self, tmp_path, monkeypatch):
        """After the first pack-load finding is emitted, subsequent scan_file
        calls must return [] (not another copy of the diagnostic)."""
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        monkeypatch.setattr(scanner, "PACK_LOAD_ERROR", True)
        monkeypatch.setattr(scanner, "_pack_error_emitted", False)

        first = scanner.scan_file(str(tmp_path / "a.py"), "a.py")
        second = scanner.scan_file(str(tmp_path / "b.py"), "b.py")
        assert len(first) == 1  # diagnostic
        assert second == []     # guard fired, no duplicate
