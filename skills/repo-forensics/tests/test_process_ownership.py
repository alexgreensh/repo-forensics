"""Startup must leave processes owned by other tools alone."""

import contextlib
import io
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import session_scan


class ProcessOwnershipTests(unittest.TestCase):
    def test_session_start_does_not_inspect_or_signal_unrelated_editor(self):
        listing = subprocess.CompletedProcess(
            [], 0, stdout="424242 03:00 editor /tmp/repo-forensics/scripts/scan_sast.py\n"
        )
        with (
            patch.object(session_scan.os, "environ", {session_scan.ENV_KILL_SWITCH: "1"}),
            patch.object(session_scan, "refresh_threat_databases", return_value=[]),
            patch.object(session_scan, "discover_items", return_value=[]),
            patch.object(session_scan, "save_baseline"),
            patch.object(session_scan.subprocess, "run", return_value=listing) as enumerate_processes,
            patch.object(session_scan.os, "kill") as signal_process,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as result:
                session_scan.main([])
            self.assertEqual(result.exception.code, 0)
            enumerate_processes.assert_not_called()
            signal_process.assert_not_called()

    @unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "requires POSIX Bash")
    def test_cli_start_does_not_inspect_or_signal_unrelated_editor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            shims = root / "bin"
            scripts.mkdir()
            shims.mkdir()
            shutil.copyfile(SCRIPTS / "run_forensics.sh", scripts / "run_forensics.sh")
            (scripts / "verify_install.py").write_text("print('verified')\n")
            log = root / "process-calls"
            for name, body in {
                "ps": "printf '%s\\n' '424242 03:00 editor /tmp/repo-forensics/scripts/scan_sast.py'",
                "xargs": "cat >/dev/null",
            }.items():
                shim = shims / name
                shim.write_text(f"#!/bin/sh\nprintf '%s\\n' {name} >>{shlex.quote(str(log))}\n{body}\n")
                shim.chmod(0o755)
            result = subprocess.run(
                [shutil.which("bash"), str(scripts / "run_forensics.sh"), str(root), "--verify-install"],
                capture_output=True, text=True, timeout=10,
                env={"PATH": str(shims) + os.pathsep + os.defpath, "HOME": str(root)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("verified", result.stdout)
            self.assertFalse(log.exists(), "startup inspected processes or attempted signalling")

    def test_owned_process_cleanup_still_kills_and_waits(self):
        process = Mock()
        with patch.object(session_scan.os, "killpg", None), patch.object(session_scan.signal, "SIGKILL", None):
            session_scan._kill_process_group(12345, process)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=2)


if __name__ == "__main__":
    unittest.main()
