"""Tests for scan_manifest_drift.py - Manifest Drift Scanner."""

import json
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


class TestJsImportExtraction:
    def test_prose_apostrophes_do_not_create_imports(self, tmp_path):
        source = tmp_path / "continuity.ts"
        source.write_text(
            "// Extracted from a checkpoint's content.\n"
            "const status = 'tokens saved';\n"
            "/* Migrated from Python's re.sub implementation. */\n"
            "expect(isResumeIntent('continue')).toBe(true);\n"
        )
        assert scanner.extract_js_imports(str(source)) == set()

    def test_real_import_forms_still_detected(self, tmp_path):
        source = tmp_path / "app.ts"
        source.write_text(
            'import { readFile } from "node:fs";\n'
            'import type { Thing } from "@scope/dep";\n'
            'import "side-effect";\n'
            'const helper = require("evil-lib");\n'
        )
        assert scanner.extract_js_imports(str(source)) == {
            "node:fs", "@scope/dep", "side-effect", "evil-lib",
        }


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


class TestIssue38PhantomProvenance:
    """Regression tests for Issue #38 phantom-dependency aggregation bug.

    Before the fix:
      - All phantom imports across the tree unioned into one synthetic path
        `"(multiple files)"`, losing provenance and creating 106 false HIGH
        findings on cluster-wide aggregation buckets.
      - Local first-party modules (top-level dirs / <name>.py / project's
        own package name) inflated the count.
      - Common dist/import aliases (e.g. `import yaml` from `PyYAML`) were
        also inflated.

    After the fix:
      - Phantom finding emits ONE per surviving phantom module, with `file=`
        the FIRST real importer rel_path (NOT `"(multiple files)"`).
      - Local first-party modules are excluded pre-flight.
      - Alias-declared distributions are excluded.
    """

    def _phantom(self, findings):
        return [f for f in findings if f.category.lower() == "phantom-dependency"]

    def test_no_synthetic_multiple_files_finding(self, tmp_path):
        """Defensive check (Issue #38): no phantom finding may be filed under
        the synthetic `"(multiple files)"` path; every phantom finding must
        retain a real importer rel_path."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\n")

        (tmp_path / "a.py").write_text("import flask\nimport foo_lib_a\n")
        (tmp_path / "b.py").write_text("import foo_lib_a\nimport foo_lib_b\n")

        findings = scanner.scan_manifest_drift(str(tmp_path))
        ph = self._phantom(findings)
        assert ph, f"expected at least one phantom finding; got: {findings}"
        for f in ph:
            assert f.file != "(multiple files)", (
                "Issue #38: phantom findings must not use the synthetic "
                "'(multiple files)' path. Got: "
                f"{[(f.title, f.file) for f in ph]}"
            )
            assert f.file and "/" in f.file or f.file.endswith(".py"), (
                f"phantom finding file must be a real importer path, got: {f.file!r}"
            )

    def test_local_top_level_module_is_not_phantom(self, tmp_path):
        """An `import mypkg` (where `mypkg/` is a top-level dir in the repo)
        must NOT be flagged as phantom. Issue #38: local first-party modules
        were inflating phantom counts."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\n")

        (tmp_path / "mypkg").mkdir()
        (tmp_path / "mypkg" / "__init__.py").write_text("")
        (tmp_path / "mypkg" / "core.py").write_text("def go(): pass\n")
        (tmp_path / "app.py").write_text(
            "import flask\n"
            "import mypkg.core\n"  # local import — must NOT be phantom
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        ph = self._phantom(findings)
        assert not any("mypkg" in f.title for f in ph), (
            "local first-party module 'mypkg' must not be flagged as phantom; "
            f"got: {[(f.title, f.file) for f in ph]}"
        )

    def test_local_top_level_py_file_is_not_phantom(self, tmp_path):
        """An `import local_module` (where `local_module.py` is a top-level
        file in the repo) must NOT be flagged as phantom."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\n")

        (tmp_path / "local_module.py").write_text("def go(): pass\n")
        (tmp_path / "app.py").write_text(
            "import flask\n"
            "import local_module\n"  # top-level .py — must NOT be phantom
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        ph = self._phantom(findings)
        assert not any("local_module" in f.title for f in ph), (
            "top-level .py file 'local_module' must not be flagged as phantom; "
            f"got: {[(f.title, f.file) for f in ph]}"
        )

    def test_local_module_via_pyproject_name_is_not_phantom(self, tmp_path):
        """`import myproject` where pyproject.toml declares `name = "myproject"`
        must NOT be flagged as phantom (project's own distribution name)."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\n'
            'name = "myproject"\n'
            'dependencies = ["flask>=2.0"]\n'
        )
        (tmp_path / "app.py").write_text(
            "import flask\n"
            "import myproject\n"  # own-name — must NOT be phantom
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        ph = self._phantom(findings)
        assert not any("myproject" in f.title for f in ph), (
            "project's own distribution name must not be flagged as phantom; "
            f"got: {[(f.title, f.file) for f in ph]}"
        )

    def test_true_undeclared_external_import_one_finding_real_path(self, tmp_path):
        """A real undeclared external import must produce ONE finding whose
        `file=` is the actual importer rel_path (not the synthetic
        `(multiple files)`)."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\n")

        importer = tmp_path / "consumer.py"
        importer.write_text(
            "import flask\n"
            "import genuine_undeclared_xyz\n"  # truly not declared
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        ph = self._phantom(findings)
        assert len(ph) == 1, f"expected exactly one phantom finding, got: {ph}"
        f = ph[0]
        assert "genuine_undeclared_xyz" in f.title
        assert f.file == "consumer.py", (
            f"phantom finding.file must be the real importer path, got: {f.file!r}"
        )
        assert "consumer.py" in f.description, (
            "phantom finding.description should mention the importer path; "
            f"got: {f.description!r}"
        )

    def test_true_undeclared_external_import_dedup_across_files(self, tmp_path):
        """Same phantom imported from MANY places must STILL emit ONE finding
        (not one per importer) and the importer count must be reflected in
        the description. The .file stays the first real importer."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\n")

        (tmp_path / "a.py").write_text("from flask import Flask\nimport shared_phantom\n")
        (tmp_path / "b.py").write_text("import shared_phantom\nimport os\n")
        (tmp_path / "c.py").write_text("from flask import Flask\nimport shared_phantom\n")

        findings = scanner.scan_manifest_drift(str(tmp_path))
        ph = [f for f in findings if "shared_phantom" in f.title]
        assert len(ph) == 1, f"exactly one phantom expected, got: {ph}"
        f = ph[0]
        # Description must reflect the importer count (>= 3). Accept either "3
        # locations" (defensive against order-dependent walk: keep min count)
        # or substring discovery.
        assert "3" in f.description, (
            f"phantom description must reflect importer count: {f.description!r}"
        )
        # file is the FIRST importer seen, which is whichever rel_path the
        # walk yields first. We assert it is one of the three real paths, not
        # the synthetic aggregate.
        assert f.file in {"a.py", "b.py", "c.py"}, (
            f"phantom.file must be one of the real importers, got: {f.file!r}"
        )

    def test_aliased_yaml_import_with_pyyaml_declared_is_not_phantom(self, tmp_path):
        """`import yaml` is satisfied by the `pyyaml` distribution. When
        `PyYAML` (case-insensitive, normalized to `pyyaml`) is declared in
        requirements.txt, `yaml` must NOT be flagged as phantom."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\nPyYAML>=6.0\n")

        (tmp_path / "app.py").write_text(
            "import flask\n"
            "import yaml\n"  # import name 'yaml', dist 'PyYAML' is declared
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        ph = self._phantom(findings)
        assert not any("yaml" in f.title for f in ph), (
            "`import yaml` is satisfied by declared `PyYAML` and must not be "
            f"phantom; got: {[(f.title, f.file) for f in ph]}"
        )

    def test_aliased_yaml_import_unresolved_remains_phantom(self, tmp_path):
        """`import yaml` with NO declaration of `pyyaml` in requirements still
        flags as a phantom (sanity). The alias map does not magically invent
        declarations; it only suppresses when the dist name is present."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\nrequests>=2.28\n")

        (tmp_path / "app.py").write_text(
            "import flask\n"
            "import yaml\n"  # no PyYAML declared — must still flag
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        ph = self._phantom(findings)
        assert any("yaml" in f.title for f in ph), (
            f"`import yaml` with no PyYAML declared must still be phantom; "
            f"got: {[(f.title, f.file) for f in ph]}"
        )

    def test_aliased_yaml_normalized_lowercase(self, tmp_path):
        """The alias match is case-insensitive on the declared name. `pyyaml`
        (lowercase) in requirements must still suppress `import yaml`."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\npyyaml>=6.0\n")

        (tmp_path / "app.py").write_text(
            "import flask\nimport yaml\n"
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        ph = self._phantom(findings)
        assert not any("yaml" in f.title for f in ph), (
            f"case-insensitive alias match failed; got: {[(f.title, f.file) for f in ph]}"
        )

    def test_aliased_pil_import_with_pillow_declared_is_not_phantom(self, tmp_path):
        """Second alias sanity: `import PIL` from declared `pillow`."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\nPillow>=10.0\n")

        (tmp_path / "app.py").write_text(
            "import flask\nfrom PIL import Image\n"
        )

        findings = scanner.scan_manifest_drift(str(tmp_path))
        ph = self._phantom(findings)
        assert not any("pil" in f.title for f in ph), (
            f"`import PIL` is satisfied by declared `Pillow`; got: "
            f"{[(f.title, f.file) for f in ph]}"
        )
