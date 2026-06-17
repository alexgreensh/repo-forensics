"""Tests for scan_entropy.py - Entropy & Encoding Scanner.

Covers the U2 decode-and-rescan wiring: a flagged base64/hex blob is handed to
scan_decode, so a payload hidden one encoding layer deep is surfaced as an
additive decoded-payload finding without dropping the existing blob finding.
"""

import base64

import scan_entropy as scanner

# Plaintext that trips the SAST/trifecta heuristics once decoded.
# (chr(114) avoids embedding a literal shell pipe in the test source.)
MALICIOUS = b'import os\nos.system(chr(114))\nimport socket\nsubprocess.Popen([])\n'
ENCODED = base64.b64encode(MALICIOUS).decode()


def _cats(findings):
    return [f.category for f in findings]


class TestDecodeAndRescan:
    def test_base64_payload_flags_both_findings(self, tmp_path):
        """A base64 blob encoding os.system produces BOTH the existing encoding
        finding AND an additive decoded-payload finding."""
        f = tmp_path / "evil.txt"
        f.write_text('payload = "%s"\n' % ENCODED)
        findings = scanner.scan_file(str(f), "evil.txt")
        cats = _cats(findings)
        assert "encoding" in cats, "existing base64 block finding must remain"
        assert "decoded-payload" in cats, "decoded os.system must be surfaced"

    def test_same_blob_twice_decodes_once(self, tmp_path):
        """The same blob on two lines is decoded only once (dedup): exactly one
        unique decode, so decoded-payload findings are not duplicated per line."""
        f = tmp_path / "evil.txt"
        f.write_text('a = "%s"\nb = "%s"\n' % (ENCODED, ENCODED))
        findings = scanner.scan_file(str(f), "evil.txt")
        # Two encoding findings (one per line) but the decode ran once. scan_decode
        # emits a fixed set of findings per decode; that count must not double.
        single = tmp_path / "single.txt"
        single.write_text('a = "%s"\n' % ENCODED)
        single_payloads = [c for c in _cats(scanner.scan_file(str(single), "single.txt"))
                           if c == "decoded-payload"]
        double_payloads = [c for c in _cats(findings) if c == "decoded-payload"]
        assert len(double_payloads) == len(single_payloads), \
            "repeated blob must decode once, not once per occurrence"

    def test_benign_base64_no_payload(self, tmp_path):
        """Regression: benign base64 (harmless text) must NOT add a
        decoded-payload finding (no severity inflation)."""
        benign = base64.b64encode(
            b'the quick brown fox jumps over the lazy dog repeatedly today and tomorrow'
        ).decode()
        f = tmp_path / "benign.txt"
        f.write_text('blob = "%s"\n' % benign)
        findings = scanner.scan_file(str(f), "benign.txt")
        assert "decoded-payload" not in _cats(findings), \
            "benign base64 must not inflate into a decoded-payload finding"


# A short base64 payload (just over the 50-char pattern floor, UNDER the old
# 80-char visible-finding gate that used to gate the decode feed too: torture C1).
_SHORT_PLAIN = b'import os\nos.system(chr(105))\nimport socket'
_SHORT_ENCODED = base64.b64encode(_SHORT_PLAIN).decode()


class TestShortBase64Decoded:
    def test_short_base64_under_80_is_decoded(self, tmp_path):
        """A base64 blob of 50-79 chars (no visible Base64 Block finding) is STILL
        routed to scan_decode, so a short payload one layer deep is caught
        (torture C1: the 80-char floor on the decode feed defeated short payloads)."""
        assert 50 <= len(_SHORT_ENCODED) < 80, "fixture must be in the 50-79 band"
        f = tmp_path / "short.txt"
        f.write_text('x = "%s"\n' % _SHORT_ENCODED)
        findings = scanner.scan_file(str(f), "short.txt")
        titles = [x.title for x in findings]
        assert "Base64 Encoded Block" not in titles, \
            "a <80 char base64 must not raise the visible block finding"
        assert "decoded-payload" in _cats(findings), \
            "a short (<80) base64 payload must still be decoded and flagged"


class TestBase85Base32Routed:
    """torture H1: scan_entropy only routed base64/hex; base85/base32-hidden
    payloads slipped through end-to-end even though scan_decode handles them."""

    def test_base85_payload_routed(self, tmp_path):
        enc = base64.a85encode(MALICIOUS).decode()
        f = tmp_path / "b85.txt"
        f.write_text('y = "%s"\n' % enc)
        findings = scanner.scan_file(str(f), "b85.txt")
        assert "decoded-payload" in _cats(findings), "base85 payload must be flagged"

    def test_base32_payload_routed(self, tmp_path):
        enc = base64.b32encode(MALICIOUS).decode()
        f = tmp_path / "b32.txt"
        f.write_text('z = "%s"\n' % enc)
        findings = scanner.scan_file(str(f), "b32.txt")
        assert "decoded-payload" in _cats(findings), "base32 payload must be flagged"

    def test_benign_base85_no_payload(self, tmp_path):
        benign = base64.a85encode(
            b'the quick brown fox jumps over the lazy dog repeatedly today tomorrow'
        ).decode()
        f = tmp_path / "benign85.txt"
        f.write_text('y = "%s"\n' % benign)
        assert "decoded-payload" not in _cats(scanner.scan_file(str(f), "benign85.txt"))

    def test_rfc1924_b85_payload_routed(self, tmp_path):
        """Adversarial P1-1 regression at the entropy ROUTING level: a real
        base64.b85encode payload (RFC1924, uses v-z/{|}~) was split by the old
        `[!-u]` regex into sub-floor fragments and never routed. The hoisted
        detect_encoded_blobs now matches it whole."""
        enc = base64.b85encode(MALICIOUS).decode()
        assert any(c in enc for c in "vwxyz{|}~"), "fixture must exercise the gap"
        f = tmp_path / "b85rfc.txt"
        f.write_text('w = "%s"\n' % enc)
        findings = scanner.scan_file(str(f), "b85rfc.txt")
        assert "decoded-payload" in _cats(findings), \
            "a real RFC1924 b85 payload must now be routed + flagged"


class TestSharedBudgetBounded:
    """torture: re-arming a fresh 12s deadline per blob let N blobs blow the 15s
    auto_scan SIGKILL into a silent zero. One shared budget across all blobs in a
    file (and across files in main()) keeps the whole scan fast and bounded."""

    def test_many_blobs_one_file_fast(self, tmp_path):
        import time
        enc = base64.b64encode(MALICIOUS).decode()
        lines = "\n".join('v%d = "%s"' % (i, enc + ("A" * (i % 4)))
                          for i in range(40))
        f = tmp_path / "many.txt"
        f.write_text(lines)
        t0 = time.monotonic()
        findings = scanner.scan_file(str(f), "many.txt")
        elapsed = time.monotonic() - t0
        # 40 distinct blobs. With per-blob re-arm this could approach 40*12s; with
        # ONE shared budget it must finish in a small bounded time, well under the
        # 12s single-budget deadline.
        assert elapsed < 11, "shared budget must keep the whole scan well bounded"
        assert any(x.category == "decoded-payload" for x in findings)

    def test_main_threads_one_budget(self, tmp_path, monkeypatch):
        """main() must mint exactly ONE budget and thread it into every file."""
        import scan_decode
        calls = {"n": 0}
        real = scan_decode.new_budget

        def counting_new_budget(deadline=None):
            calls["n"] += 1
            return real(deadline=deadline)

        monkeypatch.setattr(scan_decode, "new_budget", counting_new_budget)
        enc = base64.b64encode(MALICIOUS).decode()
        for name in ("a.txt", "b.txt", "c.txt"):
            (tmp_path / name).write_text('p = "%s"\n' % enc)
        monkeypatch.setattr("sys.argv", ["scan_entropy.py", str(tmp_path), "--format", "json"])
        scanner.main()
        assert calls["n"] == 1, "main() must mint exactly one shared budget for the scan"
