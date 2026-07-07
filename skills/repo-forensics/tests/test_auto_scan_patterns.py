"""
Tests for auto_scan.py install/clone pattern detection and package-name
extraction. Mirrors the detect_install_command coverage in test_pre_scan.py
(auto_scan previously had no pattern tests of its own).
"""

import os
import sys
import pytest

# Ensure scripts dir is importable
SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'scripts')
sys.path.insert(0, os.path.abspath(SCRIPTS_DIR))

import auto_scan  # noqa: E402


# --- detect_install_command ---

class TestDetectInstallCommand:
    def test_no_command(self):
        assert auto_scan.detect_install_command("") == (None, None)
        assert auto_scan.detect_install_command(None) == (None, None)

    def test_non_install_command(self):
        ptype, match = auto_scan.detect_install_command("echo hello")
        assert ptype is None

    @pytest.mark.parametrize("cmd,expected_type", [
        ("git clone https://github.com/user/repo", "git_clone"),
        ("git pull", "git_pull"),
        ("pip install requests", "pip_install"),
        ("pip3 install flask", "pip_install"),
        ("npm install express", "npm_install"),
        ("npm i lodash", "npm_install"),
        ("npm update webpack", "npm_install"),
        ("yarn add react", "yarn_add"),
        ("gem install rails", "gem_install"),
        ("gem update bundler", "gem_install"),
        ("cargo install ripgrep", "cargo_install"),
        ("go get github.com/user/pkg", "go_install"),
        ("go install github.com/user/pkg@latest", "go_install"),
        ("brew install node", "brew_install"),
        ("brew upgrade python", "brew_install"),
        ("openclaw skills install my-skill", "openclaw_install"),
        ("clawhub install my-pkg", "openclaw_install"),
        ("claude plugins install my-plugin", "claude_plugin_install"),
        ("uv add requests", "uv_install"),
        ("uv pip install flask", "uv_install"),
        ("uv tool install ruff", "uv_install"),
        ("uv sync", "uv_sync"),
        ("uv sync --frozen", "uv_sync"),
        ("pnpm install express", "pnpm_install"),
        ("pnpm i lodash", "pnpm_install"),
        ("pnpm add react", "pnpm_install"),
        ("pnpm update webpack", "pnpm_install"),
        ("bun install express", "bun_install"),
        ("bun i lodash", "bun_install"),
        ("bun add react", "bun_install"),
        ("bun update webpack", "bun_install"),
    ])
    def test_install_patterns(self, cmd, expected_type):
        ptype, match = auto_scan.detect_install_command(cmd)
        assert ptype == expected_type

    def test_pnpm_not_classified_as_npm(self):
        """Unanchored npm pattern substring-matches 'pnpm install x';
        the pnpm pattern must win (list order)."""
        ptype, _ = auto_scan.detect_install_command("pnpm install express")
        assert ptype == 'pnpm_install'

    def test_uv_pip_not_classified_as_pip(self):
        """Unanchored pip pattern substring-matches 'uv pip install x';
        the uv pattern must win (list order)."""
        ptype, _ = auto_scan.detect_install_command("uv pip install requests")
        assert ptype == 'uv_install'


# --- extract_package_names ---

class TestExtractPackageNames:
    def test_uv_add_strips_flags(self):
        _, match = auto_scan.detect_install_command("uv add requests --dev")
        names = auto_scan.extract_package_names('uv_install', match)
        assert names == ['requests']

    def test_uv_add_with_version_specifier(self):
        _, match = auto_scan.detect_install_command("uv add flask>=2.0")
        names = auto_scan.extract_package_names('uv_install', match)
        assert names == ['flask']

    def test_pnpm_multiple_packages(self):
        _, match = auto_scan.detect_install_command("pnpm add react react-dom")
        names = auto_scan.extract_package_names('pnpm_install', match)
        assert set(names) == {'react', 'react-dom'}

    def test_bun_scoped_package(self):
        _, match = auto_scan.detect_install_command("bun add @scope/pkg")
        names = auto_scan.extract_package_names('bun_install', match)
        assert names == ['@scope/pkg']

    def test_uv_sync_has_no_packages(self):
        """uv sync installs from the lockfile — no package args to extract."""
        ptype, match = auto_scan.detect_install_command("uv sync")
        assert ptype == 'uv_sync'
        assert auto_scan.extract_package_names(ptype, match) == []

    def test_npm_with_flags(self):
        _, match = auto_scan.detect_install_command("npm install --save express")
        names = auto_scan.extract_package_names('npm_install', match)
        assert 'express' in names
