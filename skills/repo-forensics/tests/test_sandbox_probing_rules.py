"""Tests for sandbox-presence probing rules (RD-CP-010..015).

Environment-detection (medium) rules adjacent to the existing CI /
GITHUB_ACTIONS environment-gating family: code that checks whether it runs
inside a known agent sandbox, cloud dev environment, or container, a classic
evasion signal.

Round-2 contract:
* Access-form coverage: dotted and subscript env access (process.env.X,
  process.env["X"], os.environ.get("X"), os.environ["X"]), bare getenv /
  environ after a from-import, and shell ${VAR:-default} expansions.
* RD-CP-013 requires the container-artifact probe to GATE BEHAVIOR on the
  same line (if/&&/||/exit/return/?/unless/assert/while, plus Python or/and after the
  probe, plus an existence-test call). A
  bare existence check does not fire: container-detection helpers such as
  sindresorhus/is-docker are detection tooling, not sandbox evasion.
  Documented gap: a probe wrapped in a helper whose gating happens on another
  line is not seen by a per-line regex pack; that is the accepted trade for
  not flagging legitimate detectors.
"""

import scan_runtime_dynamism as scanner


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def _scan(tmp_path, body, name):
    f = tmp_path / name
    f.write_text(body)
    return scanner.scan_file(str(f), name)


class TestProcessEnvMarkers:
    def test_cursor_sandbox_conditional(self, tmp_path):
        findings = _scan(tmp_path, "if (process.env.CURSOR_SANDBOX) exit(0)\n", "a.js")
        assert "RD-CP-010" in _rule_ids(findings)

    def test_codespaces_logical_and(self, tmp_path):
        findings = _scan(tmp_path, "process.env.CODESPACES && benign()\n", "a.js")
        assert "RD-CP-010" in _rule_ids(findings)

    def test_repl_id_read(self, tmp_path):
        findings = _scan(tmp_path, "const id = process.env.REPL_ID\n", "a.mjs")
        assert "RD-CP-010" in _rule_ids(findings)

    def test_unrelated_env_negative(self, tmp_path):
        findings = _scan(tmp_path, "const p = process.env.PORT\n", "a.js")
        assert "RD-CP-010" not in _rule_ids(findings)


class TestPythonEnvMarkers:
    def test_environ_get_cursor_sandbox(self, tmp_path):
        findings = _scan(tmp_path, "import os\nos.environ.get('CURSOR_SANDBOX')\n", "a.py")
        assert "RD-CP-011" in _rule_ids(findings)

    def test_getenv_gitpod(self, tmp_path):
        findings = _scan(tmp_path, "import os\nos.getenv('GITPOD_WORKSPACE_ID')\n", "a.py")
        assert "RD-CP-012" in _rule_ids(findings)

    def test_unrelated_env_negative(self, tmp_path):
        findings = _scan(tmp_path, "import os\nos.environ.get('PATH')\nos.getenv('HOME')\n", "a.py")
        assert "RD-CP-011" not in _rule_ids(findings)
        assert "RD-CP-012" not in _rule_ids(findings)


class TestContainerArtifacts:
    def test_dockerenv_python_gated(self, tmp_path):
        findings = _scan(tmp_path, "if os.path.exists('/.dockerenv'): sys.exit(0)\n", "a.py")
        assert "RD-CP-013" in _rule_ids(findings)

    def test_dockerenv_shell(self, tmp_path):
        findings = _scan(tmp_path, "test -f /.dockerenv && echo container\n", "a.sh")
        assert "RD-CP-013" in _rule_ids(findings)

    def test_dockerenv_shell_bracket_gated(self, tmp_path):
        findings = _scan(tmp_path, "[ -f /.dockerenv ] && exit 0\n", "a.sh")
        assert "RD-CP-013" in _rule_ids(findings)

    def test_containerenv_js_gated(self, tmp_path):
        findings = _scan(tmp_path, "if (fs.existsSync('/run/.containerenv')) process.exit(0)\n", "a.js")
        assert "RD-CP-013" in _rule_ids(findings)

    def test_dockerenv_python_or_gate(self, tmp_path):
        # Round-3 gap closed: Python truthiness gates. A probe whose result
        # selects payload execution via `or` is sandbox evasion, not
        # detection tooling.
        findings = _scan(tmp_path, "os.path.exists('/.dockerenv') or payload()\n", "a.py")
        assert "RD-CP-013" in _rule_ids(findings)

    def test_containerenv_python_and_gate(self, tmp_path):
        findings = _scan(tmp_path, "os.path.exists('/run/.containerenv') and payload()\n", "a.py")
        assert "RD-CP-013" in _rule_ids(findings)

    def test_bare_check_negative(self, tmp_path):
        findings = _scan(tmp_path, "os.path.exists('/.dockerenv')\n", "a.py")
        assert "RD-CP-013" not in _rule_ids(findings)

    def test_dockerenv_assert_gate(self, tmp_path):
        # Round-4 gap closed: an assertion on the probe result is a
        # run-only-outside-docker gate, not detection tooling.
        findings = _scan(tmp_path, 'assert not os.path.exists("/.dockerenv")\n', "a.py")
        assert "RD-CP-013" in _rule_ids(findings)

    def test_dockerenv_while_gate(self, tmp_path):
        findings = _scan(tmp_path, "while os.path.exists('/.dockerenv'):\n", "a.py")
        assert "RD-CP-013" in _rule_ids(findings)

    def test_combined_detector_chained_probes_fire(self, tmp_path):
        # A combined detector chaining probes with boolean composition is a
        # gate on the same line and fires intentionally (documented).
        findings = _scan(
            tmp_path,
            "fs.existsSync('/.dockerenv') || fs.existsSync('/run/.containerenv')\n",
            "a.js",
        )
        assert "RD-CP-013" in _rule_ids(findings)

    def test_is_docker_regressions(self, tmp_path):
        # sindresorhus/is-docker shapes: a container-DETECTION package is not
        # sandbox evasion. Bare statSync probe, a mock comparing the path, and
        # prose in a test name must all stay quiet.
        body = (
            "function hasDockerEnv() {\n"
            "  try {\n"
            "    fs.statSync('/.dockerenv');\n"
            "    return true;\n"
            "  } catch {\n"
            "    return false;\n"
            "  }\n"
            "}\n"
        )
        findings = _scan(tmp_path, body, "index.js")
        assert "RD-CP-013" not in _rule_ids(findings)
        test_body = (
            "test('detects Docker via /.dockerenv', async () => {\n"
            "  if (path === '/.dockerenv') {\n"
            "    return true\n"
            "  }\n"
            "})\n"
        )
        findings = _scan(tmp_path, test_body, "test.js")
        assert "RD-CP-013" not in _rule_ids(findings)

    def test_negative(self, tmp_path):
        findings = _scan(tmp_path, "ls /.docker\nls /run/containerd\n", "a.sh")
        assert "RD-CP-013" not in _rule_ids(findings)


class TestVirtDetection:
    def test_systemd_detect_virt_shell(self, tmp_path):
        findings = _scan(tmp_path, "VIRT=$(systemd-detect-virt)\n", "a.sh")
        assert "RD-CP-014" in _rule_ids(findings)

    def test_systemd_detect_virt_python(self, tmp_path):
        findings = _scan(tmp_path, "subprocess.run(['systemd-detect-virt'])\n", "a.py")
        assert "RD-CP-014" in _rule_ids(findings)

    def test_negative(self, tmp_path):
        findings = _scan(tmp_path, "systemd-analyze blame\n", "a.sh")
        assert "RD-CP-014" not in _rule_ids(findings)


class TestShellEnvMarkers:
    def test_cursor_sandbox_test(self, tmp_path):
        findings = _scan(tmp_path, '[ -n "$CURSOR_SANDBOX" ] && exit 0\n', "a.sh")
        assert "RD-CP-015" in _rule_ids(findings)

    def test_braced_codespaces(self, tmp_path):
        findings = _scan(tmp_path, "echo ${CODESPACES}\n", "a.bash")
        assert "RD-CP-015" in _rule_ids(findings)

    def test_negative(self, tmp_path):
        findings = _scan(tmp_path, "echo $HOME\n", "a.sh")
        assert "RD-CP-015" not in _rule_ids(findings)


class TestSeverityAndCategory:
    def test_medium_environment_detection(self, tmp_path):
        findings = _scan(tmp_path, "if os.path.exists('/.dockerenv'): sys.exit(0)\n", "a.py")
        ours = [f for f in findings if f.rule_id == "RD-CP-013"]
        assert ours and all(f.severity == "medium" for f in ours)
        assert all(f.category == "environment-detection" for f in ours)


class TestAccessFormEvasion:
    """Round-2 access-form coverage (subscript, from-import, expansion)."""

    def test_process_env_subscript(self, tmp_path):
        findings = _scan(tmp_path, 'if (process.env["CODESPACES"]) exit(0)\n', "a.js")
        assert "RD-CP-010" in _rule_ids(findings)

    def test_environ_subscript(self, tmp_path):
        findings = _scan(tmp_path, 'flag = os.environ["CURSOR_SANDBOX"]\n', "a.py")
        assert "RD-CP-011" in _rule_ids(findings)

    def test_environ_get_after_from_import(self, tmp_path):
        findings = _scan(tmp_path, "from os import environ\nenviron.get(\"GITPOD_WORKSPACE_ID\")\n", "a.py")
        assert "RD-CP-011" in _rule_ids(findings)

    def test_getenv_after_from_import(self, tmp_path):
        findings = _scan(tmp_path, "from os import getenv\ngetenv(\"REPL_ID\")\n", "a.py")
        assert "RD-CP-012" in _rule_ids(findings)

    def test_os_getenv_still_fires(self, tmp_path):
        findings = _scan(tmp_path, "os.getenv('CURSOR_SANDBOX')\n", "a.py")
        assert "RD-CP-012" in _rule_ids(findings)

    def test_unrelated_subscript_negative(self, tmp_path):
        findings = _scan(tmp_path, 'port = os.environ["PORT"]\nconst p = process.env["NODE_ENV"]\n', "a.py")
        assert "RD-CP-011" not in _rule_ids(findings)
        assert "RD-CP-010" not in _rule_ids(findings)

    def test_shell_default_expansion(self, tmp_path):
        findings = _scan(tmp_path, '[ -n "${GITPOD_WORKSPACE_ID:-}" ] && exit 0\n', "a.sh")
        assert "RD-CP-015" in _rule_ids(findings)

    def test_shell_error_expansion(self, tmp_path):
        findings = _scan(tmp_path, 'echo "${CODESPACES:?required}"\n', "a.sh")
        assert "RD-CP-015" in _rule_ids(findings)

    def test_shell_unrelated_expansion_negative(self, tmp_path):
        findings = _scan(tmp_path, 'echo "${PATH:-/usr/bin}"\n', "a.sh")
        assert "RD-CP-015" not in _rule_ids(findings)
