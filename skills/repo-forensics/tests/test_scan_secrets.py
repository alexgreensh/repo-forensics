"""Tests for scan_secrets.py - Secret Scanner."""

import pytest
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
