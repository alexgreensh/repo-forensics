"""Tests for scan_bytecode.py — U2 isolated .pyc disassembly scanner."""

import os
import py_compile
import subprocess
import sys
import pytest
import scan_bytecode as scanner
import _pyc_unmarshal as child

_NEEDS_NATIVE_SANDBOX = pytest.mark.skipif(
    sys.platform not in ("darwin", "linux"),
    reason="disassembly requires macOS Seatbelt or Linux seccomp",
)


def _compile_to_pyc(src_code, directory, name="mod"):
    src = directory / f"{name}.py"
    src.write_text(src_code)
    pyc = directory / f"{name}.pyc"
    py_compile.compile(str(src), cfile=str(pyc), doraise=True)
    return src, pyc


def _cats(findings):
    return {f.category for f in findings}


def _poison_pyc(directory, malicious_code, benign_source, name="mod"):
    """Simulate bytecode poisoning: compile MALICIOUS source to .pyc, then swap
    the .py for BENIGN source. The loaded .pyc steals/execs; the visible source
    is innocent — the Trail of Bits simple-formatter pattern."""
    src = directory / f"{name}.py"
    src.write_text(malicious_code)
    pyc = directory / f"{name}.pyc"
    py_compile.compile(str(src), cfile=str(pyc), doraise=True)
    src.write_text(benign_source)  # decoy source replaces the real one
    return src, pyc


class TestHeaderLen:
    def test_modern_pyc_header_16(self):
        # 3.7+ magic: version int >= 3390, followed by \r\n.
        magic = bytes([0x50, 0x0D]) + b"\r\n"  # 0x0D50 = 3408 -> 16
        assert scanner.pyc_header_len(magic) == 16

    def test_legacy_header_12(self):
        n = 3200
        magic = bytes([n & 0xFF, (n >> 8) & 0xFF]) + b"\r\n"
        assert scanner.pyc_header_len(magic) == 12

    def test_unrecognized_magic_none(self):
        assert scanner.pyc_header_len(b"\x00\x00\x00\x00") is None
        assert scanner.pyc_header_len(b"PK\x03\x04") is None
        assert scanner.pyc_header_len(b"ab") is None


class TestBytecodePoisoning:
    """GAP 1 (Trail of Bits simple-formatter): benign .py source, malicious
    bytecode in the .pyc. Detection is raw-bytes vs source diff — no execution,
    no matching interpreter required."""

    _BENIGN = "def format_text(t):\n    return t.strip().title()\n"
    _MALICIOUS = (
        "import os\n"
        "for k, v in os.environ.items():\n"
        "    print(k, v)\n"
        "eval(\"print('x')\")\n"
        "def format_text(t):\n    return t.strip().title()\n"
    )

    def test_poisoned_pyc_flagged_high(self, tmp_path):
        _poison_pyc(tmp_path, self._MALICIOUS, self._BENIGN)
        findings = scanner.scan_repo(str(tmp_path))
        assert "bytecode-poisoning" in _cats(findings)
        poison = [f for f in findings if f.category == "bytecode-poisoning"]
        assert all(f.severity == "high" for f in poison)
        assert "environ" in poison[0].snippet

    def test_poison_detected_without_disassembly(self, tmp_path, monkeypatch):
        # Force ALL disassembly to fail (simulates a .pyc no installed interpreter
        # can read). The raw-bytes detector must still fire — proving detection
        # never depends on unmarshalling attacker code.
        _poison_pyc(tmp_path, self._MALICIOUS, self._BENIGN)
        monkeypatch.setattr(scanner, "_disassemble_best",
                            lambda *a, **k: (None, "could not unmarshal bytecode (corrupt or cross-version)"))
        findings = scanner.scan_repo(str(tmp_path))
        assert "bytecode-poisoning" in _cats(findings)

    def test_clean_compiled_module_no_poison(self, tmp_path):
        # Source legitimately uses os.environ -> the marker is in BOTH source and
        # bytecode -> the diff cancels -> no false positive.
        code = "import os\ndef cfg():\n    return os.environ.get('HOME')\n"
        _compile_to_pyc(code, tmp_path)
        findings = scanner.scan_repo(str(tmp_path))
        assert "bytecode-poisoning" not in _cats(findings)

    def test_opaque_pyc_with_source_flagged_medium(self, tmp_path, monkeypatch):
        # An unreadable .pyc beside readable source is suspicious but also matches
        # a benign cross-version-committed-.pyc shape -> MEDIUM review, not HIGH
        # (the raw-marker poison detector is the load-bearing HIGH signal).
        _compile_to_pyc("def f():\n    return 1\n", tmp_path)
        monkeypatch.setattr(scanner, "_disassemble_best",
                            lambda *a, **k: (None, "could not unmarshal bytecode (corrupt or cross-version)"))
        findings = scanner.scan_repo(str(tmp_path))
        assert "opaque-bytecode-with-source" in _cats(findings)
        assert any(f.severity == "medium" for f in findings
                   if f.category == "opaque-bytecode-with-source")

    @_NEEDS_NATIVE_SANDBOX
    def test_obfuscated_getattr_gadget_flagged(self, tmp_path):
        # getattr(os, chr(115)+"ystem")("id") hides the attribute name from the
        # raw-marker + co_name detectors; the gadget co-occurrence catches it.
        code = ("import os\n"
                "f = getattr(os, chr(115) + 'ystem')\n"
                "f('id')\n")
        src, _pyc = _compile_to_pyc(code, tmp_path)
        src.unlink()  # orphan, so poison-diff is skipped and gadget must carry it
        findings = scanner.scan_repo(str(tmp_path))
        assert "bytecode-hidden-logic" in _cats(findings)

    def test_plain_getattr_no_false_positive(self, tmp_path):
        # getattr without char-building + sensitive import must NOT fire.
        code = "import os\nx = getattr(os.path, 'join')\n"
        _compile_to_pyc(code, tmp_path)
        findings = scanner.scan_repo(str(tmp_path))
        assert "bytecode-hidden-logic" not in _cats(findings)

    def test_decoy_source_substring_does_not_cancel_poison(self, tmp_path):
        # A decoy source containing `exec_command` must NOT cancel the standalone
        # `exec` co_name in the poisoned .pyc (word-boundary source match).
        malicious = "exec('bad')\ndef run():\n    return 1\n"
        benign = "def exec_command(c):\n    return c\ndef run():\n    return 1\n"
        _poison_pyc(tmp_path, malicious, benign)
        findings = scanner.scan_repo(str(tmp_path))
        assert "bytecode-poisoning" in _cats(findings)

@_NEEDS_NATIVE_SANDBOX
class TestBytecodeDetection:
    def test_exec_primitive_in_function_body_orphan_elevated(self, tmp_path):
        # os.system inside a function -> lives in a NESTED code object, which the
        # recursive co_consts walk must reach. .py deleted -> orphan.
        code = "def run():\n    import os\n    os.system('id')\n"
        src, _pyc = _compile_to_pyc(code, tmp_path)
        src.unlink()
        findings = scanner.scan_repo(str(tmp_path))
        assert "bytecode-hidden-logic" in _cats(findings)
        assert "orphan-bytecode" in _cats(findings)
        assert any(f.category == "orphan-bytecode" and f.severity == "high"
                   for f in findings), "orphan + primitive must elevate to high"

    def test_credential_path_in_constants(self, tmp_path):
        code = "def f():\n    p = '/home/u/.ssh/id_rsa'\n    return open(p).read()\n"
        _compile_to_pyc(code, tmp_path)
        findings = scanner.scan_repo(str(tmp_path))
        cats = _cats(findings)
        assert "bytecode-hidden-logic" in cats

    def test_url_in_constants(self, tmp_path):
        code = "def f():\n    return 'http://evil.example/payload'\n"
        _compile_to_pyc(code, tmp_path)
        findings = scanner.scan_repo(str(tmp_path))
        assert "bytecode-hidden-logic" in _cats(findings)

    def test_benign_pyc_with_sibling_no_finding(self, tmp_path):
        code = "def add(a, b):\n    return a + b\n\n\nclass C:\n    x = 1\n"
        _compile_to_pyc(code, tmp_path)  # leaves the .py in place (has sibling)
        findings = scanner.scan_repo(str(tmp_path))
        assert findings == []

    def test_benign_orphan_outside_vendor_is_low_note(self, tmp_path):
        code = "def add(a, b):\n    return a + b\n"
        src, _pyc = _compile_to_pyc(code, tmp_path)
        src.unlink()
        findings = scanner.scan_repo(str(tmp_path))
        # Orphan but benign -> low note, never critical/high.
        assert "orphan-bytecode" in _cats(findings)
        assert all(f.severity == "low" for f in findings if f.category == "orphan-bytecode")
        assert not any(f.severity in ("critical", "high") for f in findings)

    def test_benign_orphan_in_vendor_suppressed(self, tmp_path):
        # Source-stripped wheel: loose .pyc under site-packages, no .py, benign.
        vendor = tmp_path / "site-packages" / "pkg"
        vendor.mkdir(parents=True)
        code = "def util():\n    return 42\n"
        src, _pyc = _compile_to_pyc(code, vendor)
        src.unlink()
        findings = scanner.scan_repo(str(tmp_path))
        # Benign orphan in a vendor root produces NO finding (R9 FP guard).
        assert findings == []


class TestGracefulDegradation:
    def test_corrupt_pyc_unanalyzable_no_crash(self, tmp_path):
        # Valid 3.7+ magic header but garbage marshal body -> child fails ->
        # parent records 'unanalyzable', scan survives. This is the safety test.
        pyc = tmp_path / "evil.pyc"
        magic = bytes([0x50, 0x0D]) + b"\r\n"  # 16-byte header
        pyc.write_bytes(magic + b"\x00" * 12 + b"\xff\xfe\xfd garbage marshal body")
        findings = scanner.scan_repo(str(tmp_path))
        assert "unanalyzable-bytecode" in _cats(findings)

    def test_unrecognized_magic_unanalyzable(self, tmp_path):
        pyc = tmp_path / "weird.pyc"
        pyc.write_bytes(b"\x00\x00\x00\x00" + b"x" * 64)
        findings = scanner.scan_repo(str(tmp_path))
        assert "unanalyzable-bytecode" in _cats(findings)

    def test_oversized_pyc_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scanner, "MAX_PYC_BYTES", 100)
        pyc = tmp_path / "big.pyc"
        magic = bytes([0x50, 0x0D]) + b"\r\n"
        pyc.write_bytes(magic + b"\x00" * 200)
        findings = scanner.scan_repo(str(tmp_path))
        assert "unanalyzable-bytecode" in _cats(findings)


class TestBudget:
    def test_pyc_count_cap_emits_incomplete(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scanner, "MAX_PYC", 1)
        for i in range(3):
            code = f"x = {i}\n"
            _compile_to_pyc(code, tmp_path, name=f"m{i}")
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-scan-incomplete" in _cats(findings)


class TestSiblingResolution:
    def test_pycache_sibling_mapping(self, tmp_path):
        pkg = tmp_path / "pkg"
        cache = pkg / "__pycache__"
        cache.mkdir(parents=True)
        (pkg / "mod.py").write_text("x = 1\n")
        pyc = cache / "mod.cpython-314.pyc"
        assert scanner._sibling_py(str(pyc)) == str(pkg / "mod.py")


class TestBytecodeSandbox:
    @pytest.mark.parametrize("limit", ["MAX_DEPTH", "MAX_CODE_OBJECTS"])
    def test_traversal_limit_never_returns_partial_success(self, monkeypatch, limit):
        monkeypatch.setattr(child, limit, 0)
        code = compile("def nested():\n    return 1\n", "trusted-test.py", "exec")
        with pytest.raises(ValueError, match="traversal limit"):
            child._walk_code(code, [], set(), 0)

    def test_bad_disassembly_never_returns_partial_success(self, monkeypatch):
        def bad_instructions(_):
            raise ValueError("malformed opcode")
        monkeypatch.setattr(child.dis, "get_instructions", bad_instructions)
        with pytest.raises(ValueError, match="malformed opcode"):
            child._walk_code(compile("x = 1", "trusted-test.py", "exec"), [], set(), 0)

    def test_output_limit_never_returns_partial_success(self, tmp_path, monkeypatch):
        _, pyc = _compile_to_pyc("x = 'output exceeds cap'\n", tmp_path)
        monkeypatch.setattr(child.sys, "argv", ["child", str(pyc), "16"])
        monkeypatch.setattr(child, "_apply_limits", lambda: None)
        # This trusted fixture runs in the test process; never sandbox pytest.
        monkeypatch.setattr(child, "_apply_sandbox", lambda: True)
        monkeypatch.setattr(child, "MAX_OUTPUT_CHARS", 1)
        with pytest.raises(ValueError, match="output limit"):
            child.main()

    def test_output_collection_is_bounded_before_join(self, monkeypatch):
        monkeypatch.setattr(child, "MAX_OUTPUT_CHARS", 4)
        lines = child._BoundedLines()
        lines.append("abcd")
        with pytest.raises(child.AnalysisLimitExceeded):
            lines.append("excess")
        assert lines == ["abcd"]

    def test_analysis_limit_maps_to_incomplete_reason(self, monkeypatch):
        monkeypatch.setattr(scanner.subprocess, "run", lambda *args, **kwargs:
                            subprocess.CompletedProcess(args[0], child.ANALYSIS_LIMIT, b"", b""))
        blob, error = scanner._disassemble("input.pyc", 16)
        assert blob is None
        assert "safety limit" in error and "incomplete" in error

    def test_sandbox_unavailable_is_visible_in_scan(self, tmp_path, monkeypatch):
        _compile_to_pyc("value = 42\n", tmp_path)
        monkeypatch.setattr(scanner, "_disassemble_best", lambda *args: (
            None, "OS sandbox unavailable; unsafe bytecode disassembly was skipped"))
        findings = scanner.scan_repo(str(tmp_path))
        assert "unanalyzable-bytecode" in _cats(findings)
        assert any("OS sandbox unavailable" in f.description for f in findings)

    def test_unsupported_platform_refuses_sandbox(self, monkeypatch):
        monkeypatch.setattr(child.sys, "platform", "unsupported")
        assert child._apply_sandbox() is False

    def test_no_sandbox_never_unmarshals(self, tmp_path, monkeypatch):
        pyc = tmp_path / "input.pyc"
        pyc.write_bytes(b"untrusted")
        monkeypatch.setattr(child.sys, "argv", ["child", str(pyc), "0"])
        monkeypatch.setattr(child, "_apply_limits", lambda: None)
        monkeypatch.setattr(child, "_apply_sandbox", lambda: False)
        monkeypatch.setattr(child.marshal, "loads", lambda _: pytest.fail("parsed without sandbox"))
        with pytest.raises(SystemExit) as exc:
            child.main()
        assert exc.value.code == child.SANDBOX_UNAVAILABLE

    def test_missing_linux_library_fails_closed(self, monkeypatch):
        monkeypatch.setattr(child.sys, "platform", "linux")
        monkeypatch.setattr(child.ctypes.util, "find_library", lambda _: None)
        assert child._apply_sandbox() is False

    def test_launcher_removes_environment_and_reports_sandbox_failure(self, monkeypatch):
        def run(command, **kwargs):
            assert command[1:3] == ["-I", "-S"]
            assert set(kwargs["env"]) == {"PATH", "LANG"}
            assert kwargs["close_fds"] is True
            assert kwargs["stdin"] == subprocess.DEVNULL
            return subprocess.CompletedProcess(command, child.SANDBOX_UNAVAILABLE, b"", b"")
        monkeypatch.setattr(scanner.subprocess, "run", run)
        blob, error = scanner._disassemble("input.pyc", 16)
        assert blob is None
        assert "OS sandbox unavailable" in error

    @pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="native sandbox unavailable")
    def test_native_sandbox_denies_host_capabilities(self, tmp_path):
        secret = tmp_path / "secret.txt"
        secret.write_text("PRIVATE_CANARY")
        target = tmp_path / "write-target"
        probe = '''
import errno, os, socket, sys
sys.path.insert(0, sys.argv[1])
import _pyc_unmarshal as child
network = socket.socket()
if not child._apply_sandbox():
    sys.exit(5)
for operation in (
    lambda: open(sys.argv[2]).read(),
    lambda: open(sys.argv[3], "w"),
    lambda: network.connect(("127.0.0.1", 9)),
    os.fork,
):
    try:
        operation()
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES):
            raise
        continue
    sys.exit(7)
print("all denied")
'''
        proc = subprocess.run(
            [sys.executable, "-I", "-S", "-c", probe,
             os.path.dirname(scanner._UNMARSHAL), str(secret), str(target)],
            capture_output=True, text=True, timeout=10,
            stdin=subprocess.DEVNULL,
        )
        if proc.returncode == child.SANDBOX_UNAVAILABLE:
            pytest.skip("OS sandbox cannot activate on this host")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "all denied"
        assert not target.exists()
