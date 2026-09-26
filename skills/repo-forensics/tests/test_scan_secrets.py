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

    def test_does_not_match_english_prose_after_ops_prefix(self, tmp_path):
        """The ops_ regex must NOT fire on all-lowercase-and-underscore prose
        that happens to start with ops_. The tightened regex requires at least
        one digit, uppercase letter, or base64 symbol in the token body so
        strings like 'ops_only_our_stale_entries_leaving_others_byte_identical'
        do not false-positive."""
        (tmp_path / "notes.py").write_text(
            "# See ops_only_our_stale_entries_leaving_others_byte_identical\n"
        )
        findings = _scan_repo(tmp_path)
        ops_findings = [f for f in findings if "Service Account" in f.title]
        assert ops_findings == [], (
            f"ops_ regex fired on prose; "
            f"got {[f.snippet for f in ops_findings]}"
        )


class TestDocPlaceholderSuppression:
    """Canonical placeholder values must NOT be flagged as real secrets.
    The scanner suppresses them at the scanner layer (not the regex) so the
    rulepack examples still document what the regex matches."""

    def test_aws_example_key_not_flagged(self, tmp_path):
        """AKIAIOSFODNN7EXAMPLE is a canonical placeholder AWS key ID."""
        (tmp_path / "docs.md").write_text(
            "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
            "AKIAIOSFODNN7EXAMPLE\n"
        )
        findings = _scan_repo(tmp_path)
        aws_findings = [f for f in findings if "AWS Access Key" in f.title]
        assert aws_findings == [], (
            f"placeholder AWS key was flagged; "
            f"got {[f.snippet for f in aws_findings]}"
        )

    def test_sequential_aws_fixture_is_exact_only(self, tmp_path):
        (tmp_path / "fixture.mjs").write_text(
            "AWS_ACCESS_KEY_ID=AKIA1234567890123456\n"
            "AWS_ACCESS_KEY_ID=AKIANY4M7KQP9XJR2E3F\n"
        )
        findings = _scan_repo(tmp_path)
        aws_keys = [finding.snippet for finding in findings if "AWS Access Key" in finding.title]
        assert "AKIA1234567890123456" not in aws_keys
        assert "AKIANY4M7KQP9XJR2E3F" in aws_keys

    def test_github_example_pat_not_flagged(self, tmp_path):
        """ghp_0123456789abcdefghijklmnopqrstuvwxyz is a canonical placeholder
        GitHub PAT (sequential alphabet)."""
        (tmp_path / "docs.md").write_text(
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"
        )
        findings = _scan_repo(tmp_path)
        ghp_findings = [f for f in findings if "GitHub Personal Access Token" in f.title]
        assert ghp_findings == [], (
            f"placeholder GitHub PAT was flagged; "
            f"got {[f.snippet for f in ghp_findings]}"
        )

    def test_example_com_db_uri_with_real_password_flagged(self, tmp_path):
        """DB URIs with example.com hosts and real-looking passwords ARE
        flagged. The example.com substring alone does not suppress a real
        credential (red-team FN-20/FN-24). Only exact known placeholder URIs
        are suppressed."""
        (tmp_path / "docs.md").write_text(
            "postgres://admin:SuperSecret123@db.example.com:5432/app\n"
        )
        findings = _scan_repo(tmp_path)
        db_findings = [f for f in findings
                       if "Connection URI" in f.title or "Embedded Password" in f.title]
        assert db_findings, (
            f"DB URI with real password at example.com was NOT flagged; "
            f"got {[f.snippet for f in db_findings]}"
        )

    def test_jwt_sample_not_flagged(self, tmp_path):
        """The canonical full example JWT (header.payload.signature) from
        jwt.io is a placeholder and is not flagged. Only the EXACT full token
        is suppressed; a token sharing the header.payload but with a different
        signature is still flagged (red-team FN-23)."""
        (tmp_path / "docs.md").write_text(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
        )
        findings = _scan_repo(tmp_path)
        jwt_findings = [f for f in findings if "JWT" in f.title]
        assert jwt_findings == [], (
            f"placeholder JWT was flagged; "
            f"got {[f.snippet for f in jwt_findings]}"
        )

    def test_jwt_with_different_signature_flagged(self, tmp_path):
        """A JWT that shares the jwt.io sample header.payload but has a
        different (real) signature IS flagged. The signature is the
        secret-bearing segment and must not be ignored (red-team FN-23)."""
        (tmp_path / "docs.md").write_text(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "ZmFrZVJlYWxTaWduYXR1cmVWYWx1ZQ\n"
        )
        findings = _scan_repo(tmp_path)
        jwt_findings = [f for f in findings if "JWT" in f.title]
        assert jwt_findings, (
            f"JWT with different signature was NOT flagged; "
            f"got {[f.snippet for f in jwt_findings]}"
        )

    def test_sk_live_dash_flagged(self, tmp_path):
        """sk-live- (with dash) is NOT suppressed as a placeholder because
        a real payment processor could use a dash prefix. Only exact known
        placeholder values are suppressed (red-team FN-22)."""
        (tmp_path / "docs.md").write_text(
            "NEXT_PUBLIC_SECRET_KEY='sk-live-abc123def456ghi789jkl012'\n"
        )
        findings = _scan_repo(tmp_path)
        live_findings = [f for f in findings if "NEXT_PUBLIC" in f.title]
        assert live_findings, (
            f"sk-live- key was NOT flagged; "
            f"got {[f.snippet for f in live_findings]}"
        )

    def test_real_aws_key_still_flagged(self, tmp_path):
        """A non-placeholder AWS key must still be flagged (no false
        negatives from the placeholder suppression)."""
        (tmp_path / "config.py").write_text(
            "AWS_KEY = 'AKIANY4M7KQP9XJR2E3F'\n"
        )
        findings = _scan_repo(tmp_path)
        aws_findings = [f for f in findings if "AWS Access Key" in f.title]
        assert aws_findings, (
            "real AWS key was NOT flagged; placeholder suppression was too aggressive"
        )

    def test_real_db_uri_still_flagged(self, tmp_path):
        """A non-placeholder DB URI must still be flagged."""
        (tmp_path / "config.py").write_text(
            "DB_URL = 'postgresql://user:p@ssword@localhost/db'\n"
        )
        findings = _scan_repo(tmp_path)
        db_findings = [f for f in findings if "PostgreSQL" in f.title]
        assert db_findings, (
            "real DB URI was NOT flagged; placeholder suppression was too aggressive"
        )


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
