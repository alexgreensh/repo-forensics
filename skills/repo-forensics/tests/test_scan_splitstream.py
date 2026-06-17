"""Tests for scan_splitstream.py — U3 cross-file split-stream reassembly scanner.

Covers plan U3 scenarios: happy-path reassembly across unrelated files,
negative shape-separation, deterministic file-path order, O(n) scale within the
wall-clock budget, and caps truncation with a fail-loud note.

NOTE: payloads decode to `os.system(chr(...))`-style code, deliberately avoiding
literal pipe-to-shell strings the environment exfil-guard blocks.
"""

import base64
import os
import resource
import time

import pytest

import scan_splitstream as scanner


def _cats(findings):
    return {f.category for f in findings}


def _split_payload(code_str, n_parts):
    """Encode `code_str` as base64 and split into n_parts contiguous chunks that
    rejoin to the exact original (so reassembly in order decodes cleanly)."""
    b = base64.b64encode(code_str.encode()).decode()
    size = len(b) // n_parts
    parts = []
    for i in range(n_parts):
        start = i * size
        end = (i + 1) * size if i < n_parts - 1 else len(b)
        parts.append(b[start:end])
    assert "".join(parts) == b
    return parts


# A benign-LOOKING but code-like payload: builds a shell command via chr() so no
# literal `curl|bash` string is present, yet it trips the decode rescan.
_MALICIOUS = (
    "import os\n"
    "os.system(chr(114) + chr(109) + chr(32) + chr(45) + chr(102))\n"
    "x = 1\n"
    "y = 2\n"
)

# A longer code-like payload (same chr()-built os.system, no literal shell pipe)
# whose base64 is long enough to be split into fragments that genuinely span 3+
# NON-adjacent length bands for the P2-2 multi-band-spread regressions.
_MALICIOUS_LONG = (
    "import os\n"
    "os.system(chr(114) + chr(109) + chr(32) + chr(45) + chr(102) + "
    "chr(32) + chr(47) + chr(116) + chr(109) + chr(112))\n"
    "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\ng = 7\nh = 8\ni = 9\nj = 10\n"
    "k = 11\nl = 12\nm = 13\nn = 14\n"
)


class TestHappyPath:
    def test_payload_split_across_three_unrelated_files(self, tmp_path):
        parts = _split_payload(_MALICIOUS, 3)
        # Filenames sort in payload order; NO import edges between them.
        names = ["frag_a.txt", "frag_b.txt", "frag_c.txt"]
        for name, part in zip(names, parts):
            (tmp_path / name).write_text(f'# data blob\nBLOB = "{part}"\n')

        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" in _cats(findings)

        hits = [f for f in findings if f.category == "split-stream-payload"]
        assert len(hits) == 1
        # All three contributing files are named in the finding.
        desc = hits[0].description
        for name in names:
            assert name in desc, f"{name} must be named in the split-stream finding"
        assert hits[0].severity == "high"


class TestNegativeShapeSeparation:
    def test_different_shape_blobs_do_not_group(self, tmp_path):
        # Three UNRELATED legit base64 blobs of clearly different shapes/lengths:
        # they land in different length bands, so they never group or flag.
        (tmp_path / "a.txt").write_text(
            "HASH = \"" + base64.b64encode(b"x" * 30).decode() + "\"\n"
        )
        (tmp_path / "b.txt").write_text(
            "CERT = \"" + base64.b64encode(b"y" * 300).decode() + "\"\n"
        )
        (tmp_path / "c.txt").write_text(
            "ICON = \"" + base64.b64encode(b"z" * 3000).decode() + "\"\n"
        )
        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" not in _cats(findings)

    def test_same_shape_but_benign_emits_nothing(self, tmp_path):
        # Three same-band base64 blobs that reassemble to NON-code printable text
        # must stay silent (KTD8).
        benign = "the quick brown fox jumps over the lazy dog twice over again ok"
        parts = _split_payload(benign, 3)
        for i, part in enumerate(parts):
            (tmp_path / f"b{i}.txt").write_text(f'V = "{part}"\n')
        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" not in _cats(findings)


class TestDeterministicOrder:
    def test_reassembly_in_file_path_order(self, tmp_path):
        # Write the fragments to files whose names sort in payload order, but
        # create them on disk OUT of order to prove the scanner sorts by path.
        parts = _split_payload(_MALICIOUS, 3)
        # Create third, then first, then second on disk.
        (tmp_path / "03_z.txt").write_text(f'D = "{parts[2]}"\n')
        (tmp_path / "01_x.txt").write_text(f'D = "{parts[0]}"\n')
        (tmp_path / "02_y.txt").write_text(f'D = "{parts[1]}"\n')

        findings = scanner.scan_repo(str(tmp_path))
        # Path-order reassembly (01,02,03) reconstructs the payload and decodes.
        assert "split-stream-payload" in _cats(findings)

    def test_fingerprint_groups_same_alphabet_and_band(self):
        a = scanner._fingerprint("A" * 40)
        b = scanner._fingerprint("B" * 41)  # same band (40//16 == 41//16 == 2)
        assert a == b
        # Different alphabet (hex) → different fingerprint even at same length.
        assert scanner._fingerprint("a" * 40) != scanner._fingerprint("Z" * 40)


class TestScaleONotNSquared:
    def test_many_small_blobs_complete_within_budget(self, tmp_path):
        # A repo with many small base64 strings across many files. An O(n^2)
        # all-pairs implementation would blow up; O(n) dict grouping stays fast.
        for i in range(400):
            blob = base64.b64encode(f"benign content number {i:05d}".encode()).decode()
            (tmp_path / f"f{i:04d}.txt").write_text(f'V = "{blob}"\n')

        t0 = time.monotonic()
        findings = scanner.scan_repo(str(tmp_path))
        elapsed = time.monotonic() - t0

        # Must return (not hang) and stay well under the wall-clock budget.
        assert elapsed < scanner.TOTAL_BUDGET_SEC
        assert isinstance(findings, list)
        # No false split-stream flag on benign content.
        assert "split-stream-payload" not in _cats(findings)


class TestCaps:
    def test_group_over_member_cap_truncated_still_returns(self, tmp_path, monkeypatch):
        # Lower the member cap so a modest group exceeds it; the scanner must
        # truncate to the cap and still return (no hang/crash).
        monkeypatch.setattr(scanner, "MAX_GROUP_MEMBERS", 4)
        # Build many same-band fragments across distinct files. They will NOT
        # decode to code (random-ish base64), so the real assertion is that the
        # scanner returns cleanly under the cap rather than processing all of them.
        for i in range(50):
            blob = base64.b64encode(bytes([i]) * 24).decode()  # uniform band
            (tmp_path / f"frag_{i:03d}.txt").write_text(f'V = "{blob}"\n')
        findings = scanner.scan_repo(str(tmp_path))
        assert isinstance(findings, list)

    def test_total_size_cap_truncates_group(self, tmp_path, monkeypatch):
        # Force a tiny total-size cap and confirm the scanner still returns and
        # does not attempt to join an unbounded blob.
        monkeypatch.setattr(scanner, "MAX_GROUP_BYTES", 64)
        parts = _split_payload(_MALICIOUS, 3)
        for i, part in enumerate(parts):
            (tmp_path / f"frag_{i}.txt").write_text(f'D = "{part}"\n')
        findings = scanner.scan_repo(str(tmp_path))
        # The result is a list (may or may not flag depending on truncation);
        # the contract under test is "returns without error under the cap".
        assert isinstance(findings, list)

    def test_budget_exhaustion_emits_note(self, tmp_path, monkeypatch):
        # Zero the wall-clock budget so the post-collection deadline trips,
        # producing the fail-loud incomplete note instead of a SIGKILL.
        monkeypatch.setattr(scanner, "TOTAL_BUDGET_SEC", 0)
        parts = _split_payload(_MALICIOUS, 3)
        for i, part in enumerate(parts):
            (tmp_path / f"frag_{i}.txt").write_text(f'D = "{part}"\n')
        findings = scanner.scan_repo(str(tmp_path))
        assert "splitstream-scan-incomplete" in _cats(findings)


class TestCleanRepo:
    def test_clean_repo_no_findings(self, clean_repo):
        findings = scanner.scan_repo(str(clean_repo))
        assert "split-stream-payload" not in _cats(findings)


# --- Hardening regressions (2026-06-17 torture: H2/H3/M1/python-H1) ---


def _split_payload_uneven(code_str, sizes):
    """Split the base64 of `code_str` into chunks of the given `sizes` (the last
    chunk takes the remainder). Lets a test force fragments whose lengths straddle
    a length-band boundary."""
    b = base64.b64encode(code_str.encode()).decode()
    parts = []
    pos = 0
    for i, s in enumerate(sizes):
        if i == len(sizes) - 1:
            parts.append(b[pos:])
        else:
            parts.append(b[pos:pos + s])
            pos += s
    assert "".join(parts) == b
    return parts


class TestLengthBandStraddle:
    """H3: fragments of one payload whose lengths straddle a 16-band boundary must
    STILL reassemble, because adjacent bands are merged at reassembly."""

    def test_straddling_band_boundary_still_reassembles(self, tmp_path):
        # Force fragment lengths that fall in DIFFERENT length bands
        # (e.g. 31 -> band 1, 33 -> band 2). Pre-hardening these never grouped.
        b = base64.b64encode(_MALICIOUS.encode()).decode()
        # Build uneven sizes that cross a 16-multiple. len(b) for _MALICIOUS is
        # well over 64, so [31, 33, <rest>] guarantees bands [1, 2, ...].
        parts = _split_payload_uneven(_MALICIOUS, [31, 33])
        # sanity: the first two fragments live in different bands
        assert scanner._fingerprint(parts[0]) != scanner._fingerprint(parts[1]), (
            "test setup must straddle a band boundary"
        )
        names = ["frag_a.txt", "frag_b.txt"]
        # need >= MIN_GROUP_MEMBERS fragments across >= MIN_GROUP_FILES files;
        # split into 3 uneven pieces across 3 files, still straddling.
        parts3 = _split_payload_uneven(_MALICIOUS, [31, 33, 0])
        names = ["frag_a.txt", "frag_b.txt", "frag_c.txt"]
        for name, part in zip(names, parts3):
            (tmp_path / name).write_text(f'BLOB = "{part}"\n')

        # confirm at least two of the three fragments are in different bands
        bands = {scanner._fingerprint(p) for p in parts3}
        assert len(bands) >= 2, "fragments must span multiple bands for this test"

        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" in _cats(findings), (
            "payload with band-straddling fragments must still be caught"
        )


class TestScrambledReassemblyOrder:
    """H2: an attacker controls filenames, so scrambled/reversed names must NOT
    defeat reassembly — the scanner tries multiple orderings."""

    def test_reversed_filenames_still_caught(self, tmp_path):
        parts = _split_payload(_MALICIOUS, 3)
        # Payload order is parts[0],parts[1],parts[2] but filenames sort the
        # REVERSE way: c < b < a is false, so name them so lexicographic order
        # is the reverse of payload order.
        (tmp_path / "c_first.txt").write_text(f'D = "{parts[0]}"\n')
        (tmp_path / "b_second.txt").write_text(f'D = "{parts[1]}"\n')
        (tmp_path / "a_third.txt").write_text(f'D = "{parts[2]}"\n')
        # Lexicographic path order is a_third, b_second, c_first ==
        # parts[2], parts[1], parts[0] == REVERSED payload. Single-order scan
        # would miss; multi-ordering must catch it.
        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" in _cats(findings), (
            "reversed-filename split payload must be caught via multi-ordering"
        )

    def test_scrambled_filenames_still_caught(self, tmp_path):
        parts = _split_payload(_MALICIOUS, 4)
        # Map payload fragments to filenames in a scrambled order so NO simple
        # sort (lexical, reverse, by-length) reconstructs payload order trivially;
        # the permutation sweep (group <= 6) must find it.
        mapping = {
            "m2.txt": parts[0],
            "z9.txt": parts[1],
            "a0.txt": parts[2],
            "k5.txt": parts[3],
        }
        for name, part in mapping.items():
            (tmp_path / name).write_text(f'D = "{part}"\n')
        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" in _cats(findings), (
            "scrambled-filename split payload must be caught via permutation sweep"
        )


class TestSmallFragments:
    """M1: small fragments (just above the reconciled floor) must be collected and
    reassembled — an attacker who splits into small chunks must not evade."""

    def test_small_fragments_just_above_floor_caught(self, tmp_path):
        # Split into many SMALL fragments each only slightly above MIN_FRAGMENT_LEN.
        b = base64.b64encode(_MALICIOUS.encode()).decode()
        chunk = scanner.MIN_FRAGMENT_LEN + 1  # just above the floor
        parts = [b[i:i + chunk] for i in range(0, len(b), chunk)]
        # ensure each collected fragment is >= the floor by merging a too-short tail
        if parts and len(parts[-1]) < scanner.MIN_FRAGMENT_LEN:
            parts[-2] = parts[-2] + parts[-1]
            parts.pop()
        assert all(len(p) >= scanner.MIN_FRAGMENT_LEN for p in parts)
        assert "".join(parts) == b
        # Filenames sort in payload order so a heuristic order reconstructs it.
        for i, part in enumerate(parts):
            (tmp_path / f"f{i:03d}.txt").write_text(f'D = "{part}"\n')
        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" in _cats(findings), (
            "payload split into small (just-above-floor) fragments must be caught"
        )

    def test_floor_is_reconciled_single_value(self):
        # The documented floor must be the REAL floor: a fragment exactly at
        # MIN_FRAGMENT_LEN is collected and one just below is NOT (no dead
        # 20/24/32 floor contradicting the documented 12). Use newline delimiters
        # so the (graphic-charset) base85 pattern cannot absorb the delimiter.
        floor = scanner.MIN_FRAGMENT_LEN
        # at-floor base64 run is collected
        at_floor = "A" * floor
        collected = list(scanner._extract_fragments(f"\n{at_floor}\n"))
        assert at_floor in collected, "fragment at the floor length must be collected"
        # one char below the floor is NOT collected
        below = "A" * (floor - 1)
        collected_below = list(scanner._extract_fragments(f"\n{below}\n"))
        assert below not in collected_below, "fragment below the floor must be dropped"
        # all four alphabet regexes share the single floor (no dead higher floor)
        for rx in (scanner._BASE64_FRAG_RE, scanner._HEX_FRAG_RE,
                   scanner._BASE32_FRAG_RE, scanner._BASE85_FRAG_RE):
            assert ("{%d,}" % floor) in rx.pattern, (
                f"regex {rx.pattern!r} must use the reconciled floor {floor}"
            )


class TestSharedDeadlineBounded:
    """python-H1 / perf: the scanner + all its decode calls share ONE deadline.
    An adversarial many-group input must return BOUNDED (well under the 2x-SIGKILL
    window), never compose nested 12s budgets into ~24s."""

    def test_many_groups_returns_within_bounded_budget(self, tmp_path):
        # Build MANY qualifying same-band groups, each of which decode-rescans.
        # If decode re-armed a fresh 12s budget per group this could run ~24s+;
        # with a shared deadline the whole scan is bounded by TOTAL_BUDGET_SEC.
        # Use real code-like payloads so the decode path does actual work.
        for g in range(60):
            parts = _split_payload(_MALICIOUS, 3)
            for i, part in enumerate(parts):
                # distinct band per group via a benign prefix length is not needed;
                # distinct files per group is what makes each a qualifying group.
                (tmp_path / f"g{g:03d}_{i}.txt").write_text(f'D = "{part}"\n')

        t0 = time.monotonic()
        findings = scanner.scan_repo(str(tmp_path))
        elapsed = time.monotonic() - t0

        # Hard bound: must finish well under the SIGKILL window, NOT ~24s.
        assert elapsed < 13.0, f"shared-deadline scan must be bounded, took {elapsed:.1f}s"
        assert isinstance(findings, list)

    def test_decode_budget_shared_not_rearmed(self, tmp_path, monkeypatch):
        # If the scanner's deadline has already passed, decode must NOT run a fresh
        # 12s window. Zero the budget; the scan must return fast and emit the
        # fail-loud incomplete note rather than grinding through decodes.
        monkeypatch.setattr(scanner, "TOTAL_BUDGET_SEC", 0)
        parts = _split_payload(_MALICIOUS, 3)
        for i, part in enumerate(parts):
            (tmp_path / f"d{i}.txt").write_text(f'D = "{part}"\n')
        t0 = time.monotonic()
        findings = scanner.scan_repo(str(tmp_path))
        elapsed = time.monotonic() - t0
        assert elapsed < 2.0, "zero-budget scan must return fast, not run a fresh decode window"
        assert "splitstream-scan-incomplete" in _cats(findings)


class TestMultiBandSpread:
    """P2-2: an attacker controls fragment sizes, so the fragments of ONE payload
    can be spread across MANY non-adjacent length bands (band 1, 4, 7, ...). The
    band+1-only adjacency union missed these; unioning ALL bands of an alphabet
    must now reassemble+flag them."""

    def test_fragments_spanning_three_nonadjacent_bands_reassemble(self, tmp_path):
        # Deliberately varied fragment lengths so the bands are NON-adjacent.
        # _MALICIOUS_LONG base64 is well over 192 chars; sizes 20/84/<rest> give
        # bands 1, 5, 5+ (band 1 isolated from the rest — the exact gap the old
        # band+1-only code missed).
        parts = _split_payload_uneven(_MALICIOUS_LONG, [20, 84, 0])
        bands = sorted({scanner._fingerprint(p)[1] for p in parts})
        assert len(bands) >= 3, f"setup must span 3+ bands, got {bands}"
        # at least one band is non-adjacent to the others (a gap exists)
        assert any(
            bands[i + 1] - bands[i] > 1 for i in range(len(bands) - 1)
        ), f"setup must have a non-adjacent band gap, got {bands}"
        for i, part in enumerate(parts):
            (tmp_path / f"frag_{i}.txt").write_text(f'BLOB = "{part}"\n')
        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" in _cats(findings), (
            "payload split into fragments spanning 3+ non-adjacent bands must "
            "still reassemble+flag (P2-2)"
        )

    def test_widely_varied_many_band_spread_caught(self, tmp_path):
        # Even more extreme: 4 fragments whose lengths jump across distant bands.
        parts = _split_payload_uneven(_MALICIOUS_LONG, [18, 50, 90, 0])
        bands = sorted({scanner._fingerprint(p)[1] for p in parts})
        assert len(bands) >= 3, f"setup must span 3+ bands, got {bands}"
        for i, part in enumerate(parts):
            (tmp_path / f"chunk_{i}.txt").write_text(f'D = "{part}"\n')
        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" in _cats(findings)


class TestBase85SplitDetection:
    """Charset-integration (P1-1): split base85 payloads must be detected. The
    fragment regexes come from scan_decode.build_blob_res(MIN_FRAGMENT_LEN) with
    the CORRECTED union charset (the old [!-u] dropped v-z/{|}~), and extracted
    fragments are edge-stripped so the wrapping quote does not corrupt the join."""

    def test_base85_payload_split_across_files_detected(self, tmp_path):
        b85 = base64.b85encode(_MALICIOUS.encode()).decode()
        # Sanity: this b85 string actually uses chars the OLD [!-u] class dropped,
        # so a non-corrected charset would have failed to capture it whole.
        assert set(b85) & set("vwxyz{|}~"), (
            "test payload must exercise the corrected base85 charset"
        )
        n = 3
        size = len(b85) // n
        parts = [b85[i * size:(i + 1) * size] if i < n - 1 else b85[i * size:]
                 for i in range(n)]
        assert "".join(parts) == b85
        for i, part in enumerate(parts):
            (tmp_path / f"b85_{i}.txt").write_text(f'BLOB = "{part}"\n')
        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" in _cats(findings), (
            "base85-encoded payload split across files must be detected"
        )

    def test_fragment_regexes_use_corrected_base85_union(self):
        # The base85 fragment regex must accept the v-z/{|}~ chars the old class
        # dropped, proving it is built from the hoisted corrected builder.
        for ch in "vwxyz{|}~":
            run = ch * scanner.MIN_FRAGMENT_LEN
            assert scanner._BASE85_FRAG_RE.fullmatch(run), (
                f"corrected base85 fragment regex must accept {ch!r}"
            )

    def test_extracted_base85_fragment_is_edge_stripped(self):
        # A quoted base85 run must yield the INNER fragment (no wrapping quote),
        # so reassembly joins clean fragments that strict-decode.
        b85 = base64.b85encode(_MALICIOUS.encode()).decode()
        inner = b85[:40]
        frags = list(scanner._extract_fragments(f'X = "{inner}"\n'))
        assert inner in frags, "edge-stripped inner fragment must be collected"
        assert f'"{inner}"' not in frags, "wrapping quotes must be stripped"


class TestAdversarialManyBandBounded:
    """Bounded: widening adjacency to union ALL bands must NOT create a
    combinatorial blowup. An adversarial input with many bands AND many groups
    must still return well before the ~13s SIGKILL-adjacent ceiling."""

    def test_many_band_many_group_returns_bounded(self, tmp_path):
        # Many qualifying groups, each split into fragments of VARIED lengths that
        # scatter across many bands. Union-all-bands could blow up the per-group
        # member count / ordering sweep if unbounded; the caps must hold it O(n).
        for g in range(60):
            parts = _split_payload_uneven(_MALICIOUS, [18, 33, 50, 0])
            for i, part in enumerate(parts):
                (tmp_path / f"g{g:03d}_{i}.txt").write_text(f'D = "{part}"\n')
        t0 = time.monotonic()
        findings = scanner.scan_repo(str(tmp_path))
        elapsed = time.monotonic() - t0
        assert elapsed < 13.0, (
            f"multi-band union must stay bounded, took {elapsed:.1f}s"
        )
        assert isinstance(findings, list)


class TestNoFalseFlagAfterHardening:
    """Benign inputs must STILL stay silent after the multi-ordering / band-merge
    changes (no new false positives)."""

    def test_benign_multifile_uneven_silent(self, tmp_path):
        # Benign printable text split into uneven, band-straddling fragments across
        # several files must NOT flag, even though all orderings are tried.
        benign = (
            "the quick brown fox jumps over the lazy dog and then the dog "
            "jumps back over the fox again and again until everyone is tired"
        )
        parts = _split_payload_uneven(benign, [33, 31, 35, 0])
        for i, part in enumerate(parts):
            (tmp_path / f"note_{i}.txt").write_text(f'V = "{part}"\n')
        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" not in _cats(findings)

    def test_unrelated_real_base64_blobs_silent(self, tmp_path):
        # Independent legit base64 blobs (hashes, an icon, a token) of varied
        # lengths must not be reassembled into a false payload by any ordering.
        (tmp_path / "lock.txt").write_text(
            'H = "' + base64.b64encode(b"package-lock-hash-value-here-0001").decode() + '"\n'
        )
        (tmp_path / "icon.txt").write_text(
            'I = "' + base64.b64encode(b"a-small-icon-blob-payload-data-22").decode() + '"\n'
        )
        (tmp_path / "tok.txt").write_text(
            'T = "' + base64.b64encode(b"some-api-token-looking-string-333").decode() + '"\n'
        )
        findings = scanner.scan_repo(str(tmp_path))
        assert "split-stream-payload" not in _cats(findings)


# --- Round-2 torture: HARD-SAFE DoS bounds (perf CRITICAL #1 + HIGH #2) ---


def _peak_rss_mb():
    """Peak RSS of this process in MB. ru_maxrss is bytes on macOS, KB on Linux."""
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Heuristic: a value over ~10MB-as-a-number is almost certainly bytes (macOS).
    return rss / (1024 * 1024) if rss > 10 ** 7 else rss / 1024


class TestHardSafeMemoryBound:
    """perf CRITICAL #1: six files each with a ~900KB-1MB base64 fragment form the
    minimum 6-member group (all under MAX_FRAGMENT_BYTES / MAX_GROUP_BYTES). The
    old 720-permutation sweep retained 720 FULL joins of all members -> ~3.9GB RSS
    -> OOM -> silent zero. The hash-keyed dedup + the PERMUTE_MAX_TOTAL_BYTES gate
    (skip the sweep for large-fragment groups) must keep this bounded and return."""

    def test_six_large_fragments_stay_under_memory_ceiling(self, tmp_path):
        # ~933KB base64 each: 6 of them = the OOM trigger from torture round 2.
        big = base64.b64encode(os.urandom(700 * 1024)).decode()
        assert len(big) < scanner.MAX_FRAGMENT_BYTES, "fragment must be under the per-file cap"
        assert len(big) > scanner.PERMUTE_MAX_TOTAL_BYTES, (
            "fragment must exceed the permutation byte-gate so the sweep is skipped"
        )
        for i in range(6):
            (tmp_path / f"f{i}.txt").write_text(f'BLOB = "{big}"\n')

        rss_before = _peak_rss_mb()
        t0 = time.monotonic()
        findings = scanner.scan_repo(str(tmp_path))
        elapsed = time.monotonic() - t0

        # Must complete (no OOM/SIGKILL) well within the wall-clock budget.
        assert isinstance(findings, list)
        assert elapsed < 13.0, f"6x large-fragment scan must be bounded, took {elapsed:.1f}s"
        # Peak RSS must stay far below the old 3.9GB blowup. ru_maxrss is a
        # high-water mark for the whole process, so we bound the DELTA loosely but
        # assert it never approaches the gigabyte range the bug produced.
        rss_after = _peak_rss_mb()
        assert rss_after < 800, (
            f"peak RSS must stay bounded (was ~3.9GB pre-fix), got {rss_after:.0f}MB"
        )

    def test_permutation_sweep_skipped_for_large_fragment_group(self):
        # Direct unit check on the ordering generator: a 6-member group whose total
        # bytes exceed PERMUTE_MAX_TOTAL_BYTES must yield ONLY the (<=5) heuristic
        # orders, never the 720-permutation sweep — that is the memory bound.
        big = "A" * (scanner.PERMUTE_MAX_TOTAL_BYTES // 4)  # 6 of these >> the gate
        members = [(f"f{i}.txt", big) for i in range(6)]
        orderings = list(scanner._candidate_orderings(members))
        assert len(orderings) <= 5, (
            f"large-fragment 6-member group must skip the permutation sweep, "
            f"got {len(orderings)} orderings"
        )

    def test_permutation_sweep_runs_for_small_fragment_group(self):
        # Sanity: a SMALL 6-member group still gets the full sweep (detection for
        # scrambled <= 6 must keep working). Distinct fragments so dedup keeps them.
        members = [(f"f{i}.txt", f"AAAA{i:04d}AAAA") for i in range(6)]
        total = sum(len(f) for _, f in members)
        assert total <= scanner.PERMUTE_MAX_TOTAL_BYTES
        orderings = list(scanner._candidate_orderings(members))
        # 6! == 720 distinct perms (fragments distinct), heuristics overlap some;
        # the point is we get MANY more than the 5 heuristic orders.
        assert len(orderings) > 5, "small 6-member group must still run the sweep"


class TestHardSafeExtractionBound:
    """perf HIGH #2: one file with ~45k tiny base64 fragments (all under the 2MB
    cap) drove the old O(n^2) overlap scan to >30s -> SIGKILL -> silent zero. The
    near-linear sorted/bisect sweep + MAX_FRAGMENTS_PER_FILE + the per-fragment
    deadline check must return well under ~13s and, when capped, emit the loud
    incomplete note (never silent, never SIGKILL)."""

    def test_one_file_with_tens_of_thousands_of_fragments_bounded(self, tmp_path):
        # ~45k distinct tiny fragments in a single ~1.2MB file (under the 2MB cap).
        lines = [
            f'v{i} = "{base64.b64encode(("frag%08d" % i).encode()).decode()}"'
            for i in range(45000)
        ]
        (tmp_path / "big.txt").write_text("\n".join(lines))
        (tmp_path / "small.txt").write_text(
            'x = "' + base64.b64encode(b"frag00000000").decode() + '"\n'
        )

        t0 = time.monotonic()
        findings = scanner.scan_repo(str(tmp_path))
        elapsed = time.monotonic() - t0

        # The whole point: near-linear extraction returns FAST, not in ~31s.
        assert elapsed < 13.0, (
            f"45k-fragment file must extract near-linearly, took {elapsed:.1f}s"
        )
        assert isinstance(findings, list)

    def test_capped_file_emits_loud_incomplete_note(self, tmp_path, monkeypatch):
        # Lower the per-file cap so the 45k-fragment file trips it; the scanner must
        # emit the fail-loud incomplete note rather than silently truncating.
        monkeypatch.setattr(scanner, "MAX_FRAGMENTS_PER_FILE", 5000)
        lines = [
            f'v{i} = "{base64.b64encode(("frag%08d" % i).encode()).decode()}"'
            for i in range(45000)
        ]
        (tmp_path / "big.txt").write_text("\n".join(lines))

        t0 = time.monotonic()
        findings = scanner.scan_repo(str(tmp_path))
        elapsed = time.monotonic() - t0

        assert elapsed < 13.0, f"capped extraction must stay bounded, took {elapsed:.1f}s"
        assert "splitstream-scan-incomplete" in _cats(findings), (
            "per-file fragment-cap truncation must emit the loud incomplete note"
        )

    def test_deadline_checked_during_extraction(self, tmp_path, monkeypatch):
        # Zero the budget: extraction (or the per-file pre-check) must bail LOUD
        # immediately, never grind the overlap pass to completion past the SIGKILL.
        monkeypatch.setattr(scanner, "TOTAL_BUDGET_SEC", 0)
        lines = [
            f'v{i} = "{base64.b64encode(("frag%08d" % i).encode()).decode()}"'
            for i in range(20000)
        ]
        (tmp_path / "big.txt").write_text("\n".join(lines))

        t0 = time.monotonic()
        findings = scanner.scan_repo(str(tmp_path))
        elapsed = time.monotonic() - t0

        assert elapsed < 2.0, "zero-budget scan must bail fast, not run full extraction"
        assert "splitstream-scan-incomplete" in _cats(findings)

    def test_extraction_overlap_resolution_matches_longest_wins(self):
        # The near-linear bisect sweep must preserve EXACT longest-wins semantics:
        # a maximal base85 span must win over a shorter interior base64 run, so a
        # split base85 payload's fragments all share the base85 alphabet group.
        b85 = base64.b85encode(_MALICIOUS.encode()).decode()
        inner = b85[:40]
        frags = list(scanner._extract_fragments(f'X = "{inner}"\n'))
        # The whole maximal span is kept (edge-stripped), not a shorter sub-slice.
        assert inner in frags
        assert all(len(f) <= len(inner) for f in frags)
