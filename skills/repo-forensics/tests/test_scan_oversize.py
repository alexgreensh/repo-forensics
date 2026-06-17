"""Tests for scan_oversize.py — U1 oversize + whitespace-inflation scanner."""

import os
import pytest
import scan_oversize as scanner


def _cats(findings):
    return {f.category for f in findings}


def _has_exec_primitive(findings):
    return any(f.category == "code-execution" for f in findings)


class TestOversizedFile:
    def test_oversized_with_payload_at_tail(self, tmp_path):
        # 12 MB: padding then an exec primitive at the very end (the bypass).
        f = tmp_path / "padded.bin"
        payload = b"\n" * (100 * 1000) + b'os.system("id")\n'
        body = b"A" * (12 * 1024 * 1024 - len(payload)) + payload
        f.write_bytes(body)
        findings = scanner.scan_repo(str(tmp_path))
        assert "oversized-file" in _cats(findings)
        assert _has_exec_primitive(findings), "tail-window scan must catch the padded payload"

    def test_benign_large_bundle_only_low_note(self, tmp_path):
        # 11 MB of benign minified-style content, no malicious patterns.
        f = tmp_path / "bundle.min.js"
        f.write_bytes((b"var x=1;" * 64) * (11 * 1024 * 1024 // (8 * 64) + 1))
        findings = scanner.scan_repo(str(tmp_path))
        assert "oversized-file" in _cats(findings)
        # No critical/high false positive on a benign bundle.
        assert all(f.severity in ("low",) for f in findings if f.category == "oversized-file")
        assert not any(f.severity in ("critical", "high") for f in findings)

    def test_small_file_no_oversize_finding(self, tmp_path):
        f = tmp_path / "small.py"
        f.write_text("def add(a, b):\n    return a + b\n")
        findings = scanner.scan_repo(str(tmp_path))
        assert "oversized-file" not in _cats(findings)

    def test_nonexistent_window_read_no_crash(self):
        assert scanner._read_window("/nonexistent/path/file", 1024) == ""


class TestWhitespaceInflation:
    def test_whitespace_run_with_payload_under_cap(self, tmp_path):
        # 2 MB file, under the 10 MB cap, with a 60 KB newline run then a payload.
        f = tmp_path / "inflated.py"
        body = b"x = 1\n" + b"\n" * (60 * 1024) + b'os.system("id")\n'
        body += b"# filler\n" * 1000
        f.write_bytes(body)
        findings = scanner.scan_repo(str(tmp_path))
        assert "whitespace-inflation" in _cats(findings)
        assert _has_exec_primitive(findings), "non-whitespace regions must be scanned"

    def test_normal_blank_lines_no_finding(self, tmp_path):
        f = tmp_path / "normal.py"
        f.write_text("import os\n\n\ndef f():\n    return 1\n\n\nx = f()\n")
        findings = scanner.scan_repo(str(tmp_path))
        assert "whitespace-inflation" not in _cats(findings)

    def test_all_whitespace_file_no_finding(self, tmp_path):
        # A blank file is benign even though it's all whitespace.
        f = tmp_path / "blank.txt"
        f.write_bytes(b"\n" * (60 * 1024))
        findings = scanner.scan_repo(str(tmp_path))
        assert "whitespace-inflation" not in _cats(findings)

    def test_whitespace_read_is_bounded(self, tmp_path, monkeypatch):
        # The whitespace heuristic must never read more than the cap.
        f = tmp_path / "big.txt"
        f.write_bytes(b" " * (60 * 1024) + b"content")
        real_open = open
        reads = {"max": 0}

        class _Tracking:
            def __init__(self, fh):
                self._fh = fh

            def read(self, n=-1):
                data = self._fh.read(n)
                reads["max"] = max(reads["max"], len(data))
                return data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self._fh.close()
                return False

        def fake_open(path, mode="r", *a, **k):
            if "b" in mode and str(path) == str(f):
                return _Tracking(real_open(path, mode, *a, **k))
            return real_open(path, mode, *a, **k)

        monkeypatch.setattr("builtins.open", fake_open)
        scanner.scan_whitespace_inflation(str(f), "big.txt")
        assert reads["max"] <= scanner.WHITESPACE_READ_CAP


class TestFileCountCap:
    def test_file_count_cap_emits_incomplete(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scanner, "MAX_FILES", 2)
        for i in range(5):
            (tmp_path / f"f{i}.txt").write_text("hello")
        findings = scanner.scan_repo(str(tmp_path))
        assert "archive-scan-incomplete" in _cats(findings)


class TestWhitespaceAnalysis:
    def test_max_run_counting(self):
        max_run, ws, total = scanner._whitespace_analysis(b"ab   cd\n\n\n")
        assert max_run == 3  # the "\n\n\n" run (3) vs the 3 spaces — tie at 3
        assert ws == 6
        assert total == 10

    def test_no_whitespace(self):
        max_run, ws, total = scanner._whitespace_analysis(b"abcdef")
        assert max_run == 0
        assert ws == 0
        assert total == 6
