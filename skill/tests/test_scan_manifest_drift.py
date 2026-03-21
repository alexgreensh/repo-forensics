"""Tests for scan_manifest_drift.py - Manifest Drift Scanner."""

import os
import json
import pytest
import scan_manifest_drift as scanner


class TestPythonPhantomDeps:
    def test_detects_phantom_import(self, tmp_path):
        """Import not in requirements.txt should be flagged."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\nrequests>=2.28\n")

        app = tmp_path / "app.py"
        app.write_text(
            "import flask\n"
            "import requests\n"
            "import evil_helper\n"  # Not in requirements
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        phantom = [f for f in findings if "phantom" in f.category.lower()]
        pkg_names = [f.title for f in phantom]
        assert any("evil_helper" in t for t in pkg_names)

    def test_stdlib_not_flagged(self, tmp_path):
        """Standard library imports should not be flagged as phantom."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\n")

        app = tmp_path / "app.py"
        app.write_text(
            "import os\nimport json\nimport sys\nimport datetime\n"
            "import flask\n"
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        phantom = [f for f in findings if "phantom" in f.category.lower()]
        assert len(phantom) == 0

    def test_no_manifest_no_findings(self, tmp_path):
        """No requirements file = no phantom dependency findings."""
        app = tmp_path / "app.py"
        app.write_text("import requests\n")

        findings = scanner.scan_manifest_drift(str(tmp_path))
        phantom = [f for f in findings if "phantom" in f.category.lower()]
        assert len(phantom) == 0

    def test_underscore_hyphen_normalization(self, tmp_path):
        """Hyphens and underscores should be normalized (PEP 503)."""
        req = tmp_path / "requirements.txt"
        req.write_text("my-package>=1.0\n")

        app = tmp_path / "app.py"
        app.write_text("import my_package\n")

        findings = scanner.scan_manifest_drift(str(tmp_path))
        phantom = [f for f in findings if "phantom" in f.category.lower()]
        # my_package should NOT be flagged since my-package == my_package
        assert not any("my_package" in f.title for f in phantom)


class TestNodePhantomDeps:
    def test_detects_phantom_require(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"express": "^4.18.0"}
        }))

        app = tmp_path / "app.js"
        app.write_text(
            "const express = require('express');\n"
            "const evilLib = require('evil-lib');\n"
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        phantom = [f for f in findings if "phantom" in f.category.lower()]
        assert any("evil-lib" in f.title for f in phantom)

    def test_builtin_not_flagged(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {}}))

        app = tmp_path / "app.js"
        app.write_text(
            "const fs = require('fs');\n"
            "const path = require('path');\n"
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        phantom = [f for f in findings if "phantom" in f.category.lower()]
        assert len(phantom) == 0


class TestRuntimeInstalls:
    def test_pip_install_subprocess(self, tmp_path):
        f = tmp_path / "setup.py"
        f.write_text(
            "import subprocess\n"
            "subprocess.run(['pip', 'install', 'evil-pkg'])\n"
        )

        findings = scanner.scan_file(str(f), "setup.py")
        cats = [f.category for f in findings]
        assert "runtime-install" in cats

    def test_pip_install_os_system(self, tmp_path):
        f = tmp_path / "install.py"
        f.write_text("import os\nos.system('pip install evil-pkg')\n")

        findings = scanner.scan_file(str(f), "install.py")
        cats = [f.category for f in findings]
        assert "runtime-install" in cats

    def test_npm_install_subprocess(self, tmp_path):
        f = tmp_path / "setup.py"
        f.write_text(
            "import subprocess\n"
            "subprocess.run(['npm', 'install', 'evil-pkg'])\n"
        )

        findings = scanner.scan_file(str(f), "setup.py")
        cats = [f.category for f in findings]
        assert "runtime-install" in cats


class TestConditionalInstall:
    def test_try_import_except_install(self, tmp_path):
        f = tmp_path / "plugin.py"
        f.write_text(
            "try:\n"
            "    import some_package\n"
            "except ImportError:\n"
            "    import subprocess\n"
            "    subprocess.check_call(['pip', 'install', 'some_package'])\n"
            "    import some_package\n"
        )

        findings = scanner.scan_file(str(f), "plugin.py")
        cats = [f.category for f in findings]
        assert "runtime-install" in cats

    def test_try_import_except_os_system(self, tmp_path):
        f = tmp_path / "plugin.py"
        f.write_text(
            "try:\n"
            "    import evil_module\n"
            "except ImportError:\n"
            "    os.system('pip install evil_module')\n"
        )

        findings = scanner.scan_file(str(f), "plugin.py")
        cats = [f.category for f in findings]
        assert "runtime-install" in cats


class TestDeclaredButUnused:
    def test_unused_dependency(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\nrequests>=2.28\nevil-decoy>=1.0\n")

        app = tmp_path / "app.py"
        app.write_text("import flask\nimport requests\n")

        findings = scanner.scan_manifest_drift(str(tmp_path))
        unused = [f for f in findings if "unused" in f.category.lower()]
        assert any("evil_decoy" in f.title for f in unused)


class TestCleanManifest:
    def test_clean_repo(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\nrequests>=2.28\n")

        app = tmp_path / "app.py"
        app.write_text("import flask\nimport requests\nimport os\nimport json\n")

        findings = scanner.scan_manifest_drift(str(tmp_path))
        phantom = [f for f in findings if "phantom" in f.category.lower()]
        assert len(phantom) == 0

    def test_no_code_files(self, tmp_path):
        """Repo with only manifest and no code should not crash."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\n")

        readme = tmp_path / "README.md"
        readme.write_text("# Hello\n")

        findings = scanner.scan_manifest_drift(str(tmp_path))
        # Should not crash, may have some unused deps
        assert isinstance(findings, list)


class TestPyprojectParsing:
    def test_pyproject_deps(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\n'
            'dependencies = [\n'
            '    "flask>=2.0",\n'
            '    "requests>=2.28",\n'
            ']\n'
        )

        app = tmp_path / "app.py"
        app.write_text("import flask\nimport requests\nimport mystery_pkg\n")

        findings = scanner.scan_manifest_drift(str(tmp_path))
        phantom = [f for f in findings if "phantom" in f.category.lower()]
        assert any("mystery_pkg" in f.title for f in phantom)
