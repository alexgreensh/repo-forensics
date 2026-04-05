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


class TestCleanRepo:
    def test_no_false_positives(self, clean_repo):
        findings = _scan_repo(clean_repo)
        # Clean repo shouldn't have secret findings
        high_plus = [f for f in findings if f.severity in ("critical", "high")]
        assert len(high_plus) == 0


def _scan_repo(repo_path):
    import forensics_core as core
    findings = []
    for fp, rp in core.walk_repo(str(repo_path)):
        findings.extend(scanner.scan_file(fp, rp))
    return findings
