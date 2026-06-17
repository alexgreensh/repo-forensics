#!/usr/bin/env python3
"""
scan_splitstream.py - Cross-file split-stream reassembly scanner (U3)

Closes scanner-bypass Gap 4(b) from the 2026-06 audit. A payload chopped into
inert encoded fragments and scattered across UNRELATED files (no import edge),
then concatenated and decoded at runtime, walks straight past every current
path: per-file scanners see only a short opaque token in each file, and
scan_dataflow's cross-file taint requires an `import` relationship that a
split-stream attacker never creates.

This scanner does its OWN bounded traversal via core.walk_aux (mirroring
scan_oversize). In a SINGLE O(n) collection pass it:
  - extracts candidate encoded fragments from each text file (reusing the
    scan_entropy base64/hex fragment patterns, plus base85/base32 charset
    fragments), requiring a minimum length so short tokens are not collected;
  - fingerprints each fragment by NORMALIZED ALPHABET + a LENGTH-BAND bucket and
    buckets fragments into a dict keyed by that fingerprint (KTD5 — NEVER an
    all-pairs O(n^2) comparison).

Reassembly then unions ALL length bands of the same alphabet into one logical
group (P2-2): an attacker controls fragment sizes, so a single payload's
fragments can be spread across MANY non-adjacent bands (band 1, 4, 7, ...); the
band is only an O(1) collection-bucketing key (KTD5) and must NOT gate
reassembly. The bounded multi-ordering (capped at MAX_GROUP_MEMBERS members,
MAX_ORDERINGS_PER_GROUP orderings) does the actual reassembly. For each logical
group with >= MIN_GROUP_MEMBERS fragments spanning >= MIN_GROUP_FILES distinct
files,
it tries a BOUNDED set of reassembly orderings (the attacker controls filenames,
so a single lexicographic order catches only 1/k! of arrangements — H2):
lexicographic path, reverse, fragment-length asc/desc, appearance order, and —
for SMALL groups only — a capped sweep of permutations. Each candidate ordering's
joined blob (capped at MAX_GROUP_BYTES, never materialized larger) goes to
scan_decode.rescan_blob ONCE; if ANY ordering decodes to a code-like payload the
group is flagged.

User-safety north star: every read is bounded (MAX_FRAGMENT_BYTES per file); the
WHOLE scanner shares ONE wall-clock deadline (TOTAL_BUDGET_SEC, finishing before
the 15 s auto_scan SIGKILL like scan_oversize) — and that SAME deadline is threaded
into scan_decode via a shared budget so decode never re-arms a fresh 12 s window
(which previously composed to ~24 s -> SIGKILL -> silent zero). The deadline is
checked frequently (per group AND per ordering AND DURING per-file fragment
extraction); on exhaustion a fail-loud "splitstream-scan-incomplete" note is
emitted and the scan returns. Group reassembly and the per-group ordering count
are capped so a pathological repo cannot OOM or hang.

HARD-SAFE invariant (round-2 torture): NO input — huge fragments, tens of
thousands of tiny fragments, many groups, many bands — may drive this scanner
past the wall-clock deadline OR past a bounded memory ceiling. The auto_scan hook
SIGKILLs any scanner at ~15 s and maps a negative/non-zero return code to a SILENT
ZERO (= a detection bypass that is WORSE than a miss), and an OOM-kill is the same
silent-zero. So both a wall overrun and a memory blowup are treated as security
bugs. Three structural bounds enforce the invariant:
  - extraction is near-linear (sorted single-sweep overlap check, not all-pairs),
    capped at MAX_FRAGMENTS_PER_FILE, and checks the SHARED deadline every
    DEADLINE_CHECK_EVERY fragments so one pathological file cannot outrun it;
  - the permutation sweep only runs when the group's fragments are SMALL
    (total bytes <= PERMUTE_MAX_TOTAL_BYTES), so the 6! sweep never materializes
    hundreds of large joins;
  - ordering de-dup stores a fixed-size HASH of each join, never the full joined
    text, so the dedup set cannot grow with fragment size.

KNOWN LIMITATION (accepted best-effort ceiling, Alex's call 2026-06-18): a payload
split into MORE THAN PERMUTE_MAX_MEMBERS (~6) EQUAL-LENGTH fragments placed in a
fully-scrambled, attacker-controlled order can EVADE reassembly. Exhaustive
ordering of k fragments is k! (combinatorial), and bounding that sweep is MANDATORY
to avoid the DoS above. For groups over the permutation cap we fall back to a
handful of cheap heuristic orders (lexicographic, reverse, fragment-length
asc/desc, appearance order); when fragments are all equal length the two
length-sort heuristics are degenerate and the rest derive from filename order,
which the attacker controls. We catch naive splits, band-union spreads, scrambled
groups of <= PERMUTE_MAX_MEMBERS, and base85; the >6-equal-length-deranged case is
the documented residual we accept rather than chase the combinatorial tail into an
unbounded (DoS-prone) reassembly search.

Created by Alex Greenshpun
"""

import bisect
import hashlib
import itertools
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import scan_decode

SCANNER_NAME = "splitstream"

# --- Fragment extraction (reuse scan_entropy fragment shapes) ---
# Floors reconciled to ONE value (MIN_FRAGMENT_LEN). An attacker who splits a
# payload into SMALL chunks must still be caught, so the floor is low enough to
# collect realistic small fragments (12 base64 chars = 9 payload bytes) but high
# enough to skip everyday short tokens/words. All four regex floors equal
# MIN_FRAGMENT_LEN so the documented minimum is the REAL minimum (no dead floor).
MIN_FRAGMENT_LEN = 12

# Fragment regexes built from the HOISTED single-source-of-truth builder in
# scan_decode (so the alphabets — including the CORRECTED base85 charset that now
# covers RFC1924 v-z/{|}~ — cannot drift from the host scanners). splitstream
# intentionally uses a SMALLER fragment floor (its fragments are small by design),
# so it passes MIN_FRAGMENT_LEN to the builder rather than the default 50-floor.
(_BASE64_FRAG_RE, _BASE85_FRAG_RE,
 _BASE32_FRAG_RE, _HEX_FRAG_RE) = scan_decode.build_blob_res(MIN_FRAGMENT_LEN)

# --- O(n) fingerprint: alphabet + length-band ---
# Width of a length bucket. Fragments whose lengths fall in the same band AND
# share an alphabet share a fingerprint, so they BUCKET in O(1) per fragment via
# a dict (KTD5). Never compare fragments pairwise. The band is ONLY a collection
# bucketing key — at reassembly _merged_groups unions ALL bands of an alphabet
# into one group (P2-2), so fragments spread across non-adjacent bands by an
# attacker still reassemble. The bounded ordering sweep does the rest.
LENGTH_BAND_WIDTH = 16

# --- Grouping / reassembly thresholds ---
# A (merged) group must have at least this many fragments to be worth reassembling.
MIN_GROUP_MEMBERS = 3
# ...spanning at least this many DISTINCT files (a single file's fragments are a
# per-file concern, not a split-stream one).
MIN_GROUP_FILES = 2

# --- Containment caps (KTD3) ---
# Cap on fragments concatenated per group; extras are dropped with a note.
MAX_GROUP_MEMBERS = 256
# Cap on total joined bytes per group handed to the decoder.
MAX_GROUP_BYTES = 1 * 1024 * 1024  # 1 MB
# Cap on bytes of fragment text we will read+scan from any single file.
MAX_FRAGMENT_BYTES = 2 * 1024 * 1024  # 2 MB
# Cap on number of files scanned (defence against a huge file count).
MAX_FILES = 20000
# Cap on total fragments retained across the whole repo (defence against a repo
# crafted to explode memory with millions of tiny fragments).
MAX_TOTAL_FRAGMENTS = 200000
# Cap on fragments collected from ANY SINGLE file (round-2 perf HIGH #2). A single
# ~1MB file packed with tens of thousands of tiny base64 runs (all under
# MAX_FRAGMENT_BYTES) previously drove the O(n^2) overlap scan to >30 s -> SIGKILL
# -> silent zero. With the sorted single-sweep overlap below the work is already
# near-linear, but this hard cap guarantees a single file can never dominate the
# budget no matter how the spans interleave.
MAX_FRAGMENTS_PER_FILE = 20000
# Check the shared wall-clock deadline once every this many fragments DURING a
# single file's extraction, so one pathological file bails LOUD (incomplete note)
# before the SIGKILL instead of running uninterrupted to completion.
DEADLINE_CHECK_EVERY = 2048
# Whole-scanner wall-clock budget. scan_splitstream runs in the auto_scan hook,
# which SIGKILLs a scanner at 15 s and maps that to a silent zero; we must finish
# and emit a fail-loud finding before that, never get killed mid-scan. This same
# deadline is shared with scan_decode (see scan_repo) so the two budgets compose
# to ONE 12 s ceiling, not two.
TOTAL_BUDGET_SEC = 12

# --- Bounded multi-ordering (H2) ---
# The attacker controls filenames, so a single deterministic order catches only
# 1/k! of reassembly arrangements. We try a BOUNDED set of orderings per group:
# a handful of cheap heuristic orders for any group, PLUS a capped permutation
# sweep for SMALL groups (<= PERMUTE_MAX_MEMBERS fragments). Every ordering's
# joined blob is decode-rescanned, sharing the single wall-clock budget.
#
# Groups with at most this many fragments get the full permutation sweep; larger
# groups get only the heuristic orders (keeps total work bounded / O(n) overall).
PERMUTE_MAX_MEMBERS = 6
# Hard cap on the number of distinct orderings attempted per group, INCLUDING the
# heuristic orders. 6! == 720, so we never exceed this even for a 6-fragment
# group, and a deadline check runs between every ordering.
MAX_ORDERINGS_PER_GROUP = 720
# MEMORY bound on the permutation sweep (round-2 perf CRITICAL #1). PERMUTE_MAX_MEMBERS
# caps the COUNT of orderings (6! == 720) but NOT the fragment SIZE: a 6-member group
# of ~933KB fragments (trivially under every other cap) previously drove the sweep to
# ~3.9GB RSS -> OOM -> silent zero, because the de-dup work and the 720 candidate
# joins scale with total fragment bytes. We now only run the permutation sweep when
# the group's TOTAL fragment bytes are small enough that 720 joins are cheap; larger
# small-COUNT groups still get the (few) heuristic orders, which are O(members) memory,
# not O(720 * members). 64KB total across <= 6 fragments keeps the sweep's worst-case
# transient well under a few MB.
PERMUTE_MAX_TOTAL_BYTES = 64 * 1024  # 64 KB

# Files this large are skipped (binary/oversize), matching the spirit of the
# shared walk's binary handling without dragging huge blobs into the regex.
_TEXT_READ_CAP = MAX_FRAGMENT_BYTES


def _alphabet_of(fragment):
    """Classify a fragment into a normalized alphabet name. The order matters:
    the most restrictive alphabet that fully covers the fragment wins, so a pure
    hex string is 'hex' (not 'base64'), and a pure A-Z2-7 string is 'base32'."""
    if re.fullmatch(r"(?:0x)?[a-fA-F0-9]+", fragment):
        return "hex"
    if re.fullmatch(r"[A-Z2-7]+={0,6}", fragment):
        return "base32"
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", fragment):
        return "base64"
    # Anything left over that is graphic-only we treat as base85-ish.
    return "base85"


def _fingerprint(fragment):
    """O(1) bucket key (KTD5): (alphabet, length_band). Fragments with the same
    key bucket together via a dict; no pairwise comparison is ever performed.
    ALL bands of the same alphabet are unioned at reassembly (see _merged_groups)
    so a payload whose fragments are spread across any number of bands — even
    deliberately non-adjacent ones — still reassembles (P2-2)."""
    alphabet = _alphabet_of(fragment)
    band = len(fragment) // LENGTH_BAND_WIDTH
    return (alphabet, band)


def _extract_fragments(text, deadline=None, stats=None):
    """Yield candidate encoded fragments from a text blob, reusing the entropy
    base64/hex shapes plus the base85/base32 charset runs from the hoisted
    builder (build_blob_res, with the corrected base85 union charset).

    MAXIMAL-SPAN selection. We collect every match from all four regexes, strip
    wrapping source-string delimiters (scan_decode.EDGE_DELIMS), then keep only
    the LONGEST non-overlapping fragments (longest-wins). This matters because the
    base85 union charset is a SUPERSET of base64/hex: a single real base85
    fragment can contain an interior run that ALSO matches the narrower base64
    pattern. If the shorter base64 slice were kept (or were allowed to suppress
    the longer base85 run), that one fragment would be classified base64 and land
    in a DIFFERENT alphabet group than its siblings, so a split base85 payload
    would never reassemble. Keeping the maximal span makes the whole base85
    fragment win, so all of a payload's base85 fragments share the base85 group.

    Edge-stripping mirrors scan_decode.detect_encoded_blobs: the base85 charset
    includes the `"` quote, so a captured `"X>D+...na"` would otherwise carry its
    wrapping quotes into the reassembly join (`"frag1""frag2"...`) and never
    strict-decode. Exact duplicates are dropped (a repeated token counts once).

    HARD-SAFE (round-2 perf HIGH #2). Overlap resolution is NEAR-LINEAR, not the
    old O(n^2) all-pairs scan, while preserving EXACT longest-wins semantics. We
    still process candidates longest-first, but test overlap against the set of
    already-accepted spans with a bisect over their START offsets (the accepted
    spans are non-overlapping, so they stay sorted by start): only the nearest
    accepted span on each side can overlap, so each test is O(log k) instead of
    O(k). A file packed with tens of thousands of tiny fragments can no longer
    drive a quadratic blowup. Two further bounds make a single file
    uninterruptible-proof:
      - at most MAX_FRAGMENTS_PER_FILE accepted fragments per file;
      - the SHARED `deadline` is checked every DEADLINE_CHECK_EVERY candidates so
        extraction bails before the auto_scan SIGKILL instead of running to the end.
    If either bound trips, `stats['truncated']` (and `stats['deadline_hit']` for
    the deadline) are set so the caller can emit the fail-loud incomplete note."""
    if stats is None:
        stats = {}
    # Collect (start, end, fragment) for every match across all alphabets, after
    # edge-stripping. Track the stripped span so containment/overlap is accurate.
    candidates = []
    for rx in (_BASE64_FRAG_RE, _HEX_FRAG_RE, _BASE32_FRAG_RE, _BASE85_FRAG_RE):
        for m in rx.finditer(text):
            raw = m.group(0)
            stripped = raw.strip(scan_decode.EDGE_DELIMS)
            if len(stripped) < MIN_FRAGMENT_LEN:
                continue
            lead = len(raw) - len(raw.lstrip(scan_decode.EDGE_DELIMS))
            start = m.start() + lead
            candidates.append((start, start + len(stripped), stripped))

    # Longest-first (then by start for determinism) so a maximal span is accepted
    # before any shorter span it overlaps — identical ordering to the old code.
    candidates.sort(key=lambda c: (c[1] - c[0], -c[0]), reverse=True)

    # Accepted spans kept as two parallel sorted-by-start lists for O(log k)
    # overlap tests via bisect (the accepted set is non-overlapping, so inserting
    # keeps both lists sorted). Only the accepted span immediately left of a
    # candidate's start can reach across it, so one bisect + neighbour check
    # decides overlap.
    acc_starts = []  # sorted accepted start offsets
    acc_ends = []    # accepted end offsets, parallel to acc_starts
    seen = set()
    accepted = []    # (start, frag)
    processed = 0

    def _overlaps(s, e):
        # index of the first accepted span starting at/after s
        i = bisect.bisect_left(acc_starts, s)
        # the accepted span just before i may extend past s (overlap on the left)
        if i > 0 and acc_ends[i - 1] > s:
            return True
        # the accepted span at i starts before e (overlap on the right)
        if i < len(acc_starts) and acc_starts[i] < e:
            return True
        return False

    for start, end, frag in candidates:
        processed += 1
        if deadline is not None and (processed % DEADLINE_CHECK_EVERY == 0):
            if time.monotonic() > deadline:
                stats["deadline_hit"] = True
                stats["truncated"] = True
                break
        if frag in seen or _overlaps(start, end):
            continue
        seen.add(frag)
        i = bisect.bisect_left(acc_starts, start)
        acc_starts.insert(i, start)
        acc_ends.insert(i, end)
        accepted.append((start, frag))
        if len(accepted) >= MAX_FRAGMENTS_PER_FILE:
            stats["truncated"] = True
            break

    # Yield in left-to-right document order for stable, deterministic output.
    for _, frag in sorted(accepted, key=lambda sf: sf[0]):
        yield frag


def _read_text(file_path):
    """Read up to _TEXT_READ_CAP bytes of a file as utf-8 text (errors replaced).
    Returns '' on error or on an apparently-binary file (NUL byte in the sample)."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(_TEXT_READ_CAP)
    except OSError:
        return ""
    if b"\x00" in data:
        return ""  # binary; skip like the shared walk would
    return data.decode("utf-8", errors="replace")


def _merged_groups(groups):
    """Union ALL length bands of the SAME ALPHABET into one logical group (P2-2
    fix). `groups` maps (alphabet, band) -> list[(rel_path, frag)].

    The length-band was only ever an O(1) BUCKETING key for the collection pass
    (KTD5: no all-pairs comparison). It must NOT also gate reassembly: an attacker
    controls fragment sizes, so the fragments of a single split payload can be
    spread across MANY non-adjacent bands (band 1, 4, 7, ...). The previous
    band+1-only adjacency union left such fragments in separate runs and they
    never reassembled — a real evasion. We now drop the band from the reassembly
    grouping entirely and union every band of an alphabet into one candidate
    group; the bounded multi-ordering (capped at MAX_GROUP_MEMBERS members and
    MAX_ORDERINGS_PER_GROUP orderings) does the actual reassembly.

    Bound: this is O(total fragments) — one pass appending each fragment into its
    alphabet bucket — and the alphabet count is fixed (4). The per-group ordering
    cost is bounded downstream by MAX_GROUP_MEMBERS (members truncated before
    permuting) and PERMUTE_MAX_MEMBERS (permutation sweep only on tiny groups), so
    widening adjacency does NOT create a combinatorial blowup.

    Yields (alphabet, band_lo, members) for each alphabet group. `band_lo` is the
    lowest band present (kept for the finding's human-readable length-band note).
    """
    # alphabet -> (lowest band seen, accumulated members). One linear pass.
    by_alpha = {}
    for (alphabet, band), members in groups.items():
        if alphabet not in by_alpha:
            by_alpha[alphabet] = [band, []]
        slot = by_alpha[alphabet]
        if band < slot[0]:
            slot[0] = band
        slot[1].extend(members)

    for alphabet, (band_lo, members) in by_alpha.items():
        yield (alphabet, band_lo, members)


def _candidate_orderings(members):
    """Yield a BOUNDED set of fragment-ordering candidates for `members`
    (a list of (rel_path, frag) tuples). Each candidate is itself a list of those
    tuples in some order. The set is capped at MAX_ORDERINGS_PER_GROUP and
    de-duplicated so the same join is not rescanned twice.

    The attacker controls filenames, so we try several cheap heuristic orders for
    any group, plus a full permutation sweep for SMALL groups only (so total work
    stays bounded and the O(n) repo-wide guarantee is preserved — permutation cost
    is paid only on groups of <= PERMUTE_MAX_MEMBERS fragments).

    MEMORY-SAFE (round-2 perf CRITICAL #1). The de-dup set stores a fixed-size
    BLAKE2b HASH of each join, NEVER the full joined text, so it cannot grow with
    fragment size (the old set retained up to 720 FULL concatenations of all
    members -> ~3.9GB RSS on six ~933KB fragments -> OOM -> silent zero). The
    permutation sweep ALSO only runs when the group's TOTAL fragment bytes are
    small (<= PERMUTE_MAX_TOTAL_BYTES): for large-but-few-fragment groups we emit
    only the handful of heuristic orders, whose memory is O(members), never
    O(720 * members). Together these keep the ordering work's transient footprint
    bounded regardless of fragment size.
    """
    n = len(members)
    total_bytes = sum(len(f) for _, f in members)
    seen_join_hashes = set()
    emitted = 0

    def _emit(order):
        nonlocal emitted
        # de-dup on a fixed-size HASH of the joined text so identical reassemblies
        # are not rescanned, WITHOUT retaining the (potentially huge) join string.
        h = hashlib.blake2b(digest_size=16)
        for _, f in order:
            h.update(b"\x00")
            h.update(f.encode("utf-8", "surrogatepass"))
        key = h.digest()
        if key in seen_join_hashes:
            return None
        seen_join_hashes.add(key)
        emitted += 1
        return order

    # Heuristic orders (cheap, useful for ANY group size):
    heuristics = [
        sorted(members, key=lambda rf: (rf[0], rf[1])),          # lexicographic path
        sorted(members, key=lambda rf: (rf[0], rf[1]), reverse=True),  # reverse lex
        sorted(members, key=lambda rf: (len(rf[1]), rf[0])),     # fragment length asc
        sorted(members, key=lambda rf: (len(rf[1]), rf[0]), reverse=True),  # len desc
        list(members),                                           # by appearance (collection order)
    ]
    for order in heuristics:
        if emitted >= MAX_ORDERINGS_PER_GROUP:
            return
        got = _emit(order)
        if got is not None:
            yield got

    # Full permutation sweep for SMALL groups only — bounded in BOTH count
    # (<= 6! == 720) AND total fragment bytes (<= PERMUTE_MAX_TOTAL_BYTES), so the
    # 6! sweep never materializes hundreds of LARGE joins. Large-but-few-fragment
    # groups (the OOM vector) get only the heuristic orders above.
    if n <= PERMUTE_MAX_MEMBERS and total_bytes <= PERMUTE_MAX_TOTAL_BYTES:
        for perm in itertools.permutations(members):
            if emitted >= MAX_ORDERINGS_PER_GROUP:
                return
            got = _emit(list(perm))
            if got is not None:
                yield got


def _join_under_cap(order):
    """Concatenate `order`'s fragments under MAX_GROUP_BYTES WITHOUT materializing
    a string larger than the cap. Returns (joined_text, contributing_paths,
    capped_bool)."""
    pieces = []
    contributing = []
    size = 0
    capped = False
    for rel, frag in order:
        if size + len(frag) > MAX_GROUP_BYTES:
            capped = True
            break
        pieces.append(frag)
        size += len(frag)
        contributing.append(rel)
    return "".join(pieces), contributing, capped


def scan_repo(repo_path, ignore_patterns=None):
    """Single bounded O(n) collection pass, then a bounded reassembly pass over
    groups formed by unioning ALL same-alphabet length bands (not just adjacent
    ones) with multiple candidate orderings. The WHOLE scanner shares ONE
    wall-clock deadline, threaded into scan_decode as a shared budget so decode
    never re-arms a fresh window. Returns list[core.Finding]."""
    all_findings = []
    t0 = time.monotonic()
    deadline = t0 + TOTAL_BUDGET_SEC
    # ONE shared decode budget keyed to the SAME deadline (H1 / python H1): every
    # rescan_blob call below shares this, so collection + all decodes finish under
    # the single 12 s ceiling — they never compose to ~24 s and SIGKILL.
    decode_budget = scan_decode.new_budget(deadline=deadline)

    # (alphabet, band) -> list of (rel_path, fragment). dict bucketing is the O(n) core.
    groups = {}
    total_fragments = 0
    scanned = 0
    budget_note_added = False

    def _add_budget_note(rel_path, category):
        nonlocal budget_note_added
        if budget_note_added:
            return
        budget_note_added = True
        all_findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="Split-stream scan incomplete (budget reached)",
            description=(
                "Stopped split-stream collection/reassembly after the "
                "file-count/time/fragment budget; remaining work not performed. "
                "Re-run a full forensics scan for complete split-stream coverage."
            ),
            file=rel_path, line=0, snippet="", category=category,
        ))

    for file_path, rel_path in core.walk_aux(
        repo_path, ignore_patterns=ignore_patterns, apply_size_cap=False
    ):
        if (scanned >= MAX_FILES
                or total_fragments >= MAX_TOTAL_FRAGMENTS
                or time.monotonic() > deadline):
            _add_budget_note(rel_path, "splitstream-scan-incomplete")
            break
        scanned += 1

        text = _read_text(file_path)
        if not text:
            continue

        # Thread the SHARED deadline into extraction so a single pathological file
        # (tens of thousands of tiny fragments) bails LOUD before the SIGKILL,
        # never running its overlap pass uninterrupted past the budget.
        ex_stats = {}
        for frag in _extract_fragments(text, deadline=deadline, stats=ex_stats):
            fp = _fingerprint(frag)
            groups.setdefault(fp, []).append((rel_path, frag))
            total_fragments += 1
            if total_fragments >= MAX_TOTAL_FRAGMENTS:
                _add_budget_note(rel_path, "splitstream-scan-incomplete")
                break
        # Per-file extraction cap or mid-extraction deadline tripped: emit the
        # fail-loud note (idempotent) so a truncated/timed-out file is never silent.
        if ex_stats.get("truncated"):
            _add_budget_note(rel_path, "splitstream-scan-incomplete")
        if ex_stats.get("deadline_hit"):
            break

    # --- Reassembly pass over groups merging ALL same-alphabet bands (P2-2) ---
    for alphabet, band_lo, members in _merged_groups(groups):
        if time.monotonic() > deadline:
            _add_budget_note("<splitstream>", "splitstream-scan-incomplete")
            break
        if len(members) < MIN_GROUP_MEMBERS:
            continue
        distinct_files = {rel for rel, _ in members}
        if len(distinct_files) < MIN_GROUP_FILES:
            continue

        # Cap members BEFORE permuting so a large group cannot blow up the
        # ordering sweep or the join. Keep a deterministic prefix (sorted) so the
        # cap is stable. Permutation work below is gated on PERMUTE_MAX_MEMBERS,
        # which is far below this cap, so only heuristic orders run on big groups.
        capped = False
        if len(members) > MAX_GROUP_MEMBERS:
            members = sorted(members, key=lambda rf: (rf[0], rf[1]))[:MAX_GROUP_MEMBERS]
            capped = True

        hit_finding = None
        contributing_for_hit = None
        # Try the bounded set of orderings; the FIRST that decodes to a payload wins.
        for order in _candidate_orderings(members):
            if time.monotonic() > deadline:
                _add_budget_note("<splitstream>", "splitstream-scan-incomplete")
                break

            joined, contributing, join_capped = _join_under_cap(order)
            if len(joined) < scan_decode.MIN_BLOB_LEN:
                continue

            decoded_findings = scan_decode.rescan_blob(
                joined, "<splitstream>", budget=decode_budget
            )
            # rescan_blob emits its own low max-depth / budget notes; the signal we
            # care about is a real decoded-payload hit (KTD8: benign groups emit
            # nothing here).
            hit = [f for f in decoded_findings if f.category == "decoded-payload"]
            if hit:
                hit_finding = hit[0]
                contributing_for_hit = contributing
                if join_capped:
                    capped = True
                break

        if hit_finding is None:
            continue

        files_sorted = sorted(set(contributing_for_hit))
        indicator = hit_finding.snippet or hit_finding.title
        cap_note = " (group truncated to caps)" if capped else ""
        all_findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="high",
            title="Split-stream payload reassembled across files",
            description=(
                f"{len(files_sorted)} unrelated files each contributed a "
                f"{alphabet} fragment (length band {band_lo}+); concatenated in "
                f"a reconstructed order they decode to a code-like payload that "
                f"trips '{hit_finding.category}': {indicator}. Contributing files: "
                f"{', '.join(files_sorted)}{cap_note}"
            ),
            file=files_sorted[0], line=0,
            snippet=indicator,
            category="split-stream-payload",
        ))

    return all_findings


def main():
    args = core.parse_common_args(sys.argv, "Split-stream Reassembly Scanner")
    repo_path = args.repo_path

    core.emit_status(
        args.format,
        f"[*] Scanning for split-stream encoded payloads in {repo_path}...",
    )

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = scan_repo(repo_path, ignore_patterns)
    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
