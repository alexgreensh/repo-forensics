#!/usr/bin/env python3
"""
scan_oversize.py - Oversize & Whitespace-Inflation Scanner

Closes the headline scanner-bypass blind spot from the 2026-06 CSA / Trail of
Bits audit: the shared walk_repo skips any file over MAX_FILE_SIZE_MB (10 MB)
with a bare `continue`, so a payload parked after ~100k newlines that inflates a
file past 10 MB is never read by ANY scanner. Whitespace inflation is the
documented mechanism of that bypass.

This scanner does its OWN traversal via core.walk_aux(apply_size_cap=False) so
oversized files are never dropped, then:
  - emits an `oversized-file` note (low tier) for any file over the cap and
    scans its first + last 1 MB through the shared SAST/trifecta patterns
    (head+tail windows — padding attacks put the real body at one end), and
  - detects whitespace inflation at ANY size (a contiguous whitespace run over
    a threshold, or a mostly-whitespace file with content after it) under a
    bounded read, then scans the non-whitespace regions.

User-safety north star (KTD6): every read is bounded (no unbounded scan of an
arbitrarily large file), and the scanner never silently drops a file the way the
shared walker does.

Created by Alex Greenshpun
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import scan_sast

SCANNER_NAME = "oversize"

# Threshold above which a file is reported as oversized (matches the shared cap).
OVERSIZE_BYTES = core.MAX_FILE_SIZE_MB * 1024 * 1024  # 10 MB
# How much of an oversized file we sample at each end for pattern scanning.
WINDOW_BYTES = 1 * 1024 * 1024  # 1 MB head + 1 MB tail
# Hard cap on how much of any file the whitespace heuristic will read. Bounds
# I/O on an arbitrarily large file (R7) — a 50 MB sample is more than enough to
# decide "this file is mostly whitespace with a payload after it".
WHITESPACE_READ_CAP = 50 * 1024 * 1024  # 50 MB
# A single contiguous whitespace run longer than this is the inflation signal.
WHITESPACE_RUN_THRESHOLD = 50 * 1024  # 50 KB
# Fraction of sampled bytes that must be whitespace to call a file inflated.
WHITESPACE_RATIO_THRESHOLD = 0.5
# Cap on number of files scanned (defence against a repo with a huge file count).
MAX_FILES = 20000
# Whole-scanner wall-clock budget. scan_oversize runs in the auto_scan hook,
# which SIGKILLs a scanner at 15s and maps that to a silent zero; we must finish
# and emit a fail-loud finding before that, never get killed mid-scan.
TOTAL_BUDGET_SEC = 12

_WS_BYTESEQ = b" \t\r\n\x0b\x0c"
# Compiled once: a contiguous whitespace run, matched at C speed over bytes.
_WS_RUN_RE = re.compile(rb"[ \t\r\n\x0b\x0c]+")


def _scan_text_blob(text, rel_path, ext):
    """Run the shared SAST + trifecta patterns over an in-memory text blob and
    return the combined findings (re-pathed to rel_path)."""
    findings = []
    findings.extend(scan_sast.scan_text(text, rel_path, ext=ext))
    findings.extend(core.scan_text_trifecta(text, rel_path))
    return findings


def _read_window(file_path, size, from_end=False):
    """Read up to `size` bytes from the start or end of a file. Returns text
    (utf-8, errors replaced) or "" on error."""
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            if from_end and file_size > size:
                f.seek(file_size - size)
            chunk = f.read(size)
        return chunk.decode("utf-8", errors="replace")
    except OSError:
        return ""


def scan_oversized_file(file_path, rel_path):
    """Emit the oversized-file note and scan head+tail windows."""
    findings = []
    ext = os.path.splitext(file_path)[1].lower()
    try:
        size = os.path.getsize(file_path)
    except OSError:
        return findings

    findings.append(core.Finding(
        scanner=SCANNER_NAME, severity="low",
        title="Oversized file skipped by default scanners",
        description=(
            f"File is {size // (1024 * 1024)} MB, over the {core.MAX_FILE_SIZE_MB} MB "
            f"cap that the shared scanners skip. Scanned here via head+tail windows; "
            f"a payload padded past the cap is a known bypass."
        ),
        file=rel_path, line=0,
        snippet=f"{size} bytes",
        category="oversized-file",
    ))

    head = _read_window(file_path, WINDOW_BYTES, from_end=False)
    tail = _read_window(file_path, WINDOW_BYTES, from_end=True)
    findings.extend(_scan_text_blob(head, rel_path, ext))
    findings.extend(_scan_text_blob(tail, rel_path, ext))
    return findings


def _whitespace_analysis(data):
    """Return (max_run, ws_count, total) for a byte sample. max_run is the
    longest contiguous whitespace run; ws_count is total whitespace bytes.

    Vectorized: ws_count via a single C-level translate-delete, max_run via a
    compiled bytes regex. ~50x faster than a Python byte loop, so a 50 MB sample
    cannot blow the wall-clock budget."""
    total = len(data)
    if total == 0:
        return 0, 0, 0
    ws_count = total - len(data.translate(None, _WS_BYTESEQ))
    max_run = 0
    for m in _WS_RUN_RE.finditer(data):
        run = m.end() - m.start()
        if run > max_run:
            max_run = run
    return max_run, ws_count, total


def scan_whitespace_inflation(file_path, rel_path):
    """Detect whitespace-inflation at any size and scan the non-whitespace
    regions. Bounded by WHITESPACE_READ_CAP so an arbitrarily large file cannot
    drive an unbounded read."""
    findings = []
    ext = os.path.splitext(file_path)[1].lower()
    try:
        with open(file_path, "rb") as f:
            data = f.read(WHITESPACE_READ_CAP)
    except OSError:
        return findings

    max_run, ws_count, total = _whitespace_analysis(data)
    if total == 0:
        return findings

    inflated = (
        max_run >= WHITESPACE_RUN_THRESHOLD
        or (ws_count / total) >= WHITESPACE_RATIO_THRESHOLD
    )
    # A mostly-whitespace file with NO real content is benign (blank file);
    # require some non-whitespace content to flag inflation.
    has_content = ws_count < total
    if not (inflated and has_content):
        return findings

    findings.append(core.Finding(
        scanner=SCANNER_NAME, severity="medium",
        title="Whitespace-inflation padding detected",
        description=(
            f"File has a {max_run}-byte contiguous whitespace run "
            f"({ws_count}/{total} bytes whitespace in the sampled region). This is "
            f"the documented technique for padding a payload past the size cap. "
            f"Non-whitespace regions scanned for hidden code."
        ),
        file=rel_path, line=0,
        snippet=f"max whitespace run {max_run} bytes",
        category="whitespace-inflation",
    ))

    # Scan the non-whitespace regions: collapse long whitespace runs so the
    # payload (which may sit after the padding) lands in the scanned text.
    text = data.decode("utf-8", errors="replace")
    # Split on whitespace runs and rejoin with single newlines, preserving the
    # actual code tokens for pattern matching.
    non_ws = "\n".join(part for part in text.split() if part)
    findings.extend(_scan_text_blob(non_ws, rel_path, ext))
    return findings


def scan_repo(repo_path, ignore_patterns=None):
    """Scan a repo for oversized files and whitespace inflation."""
    all_findings = []
    scanned = 0
    t0 = time.monotonic()
    for file_path, rel_path in core.walk_aux(
        repo_path, ignore_patterns=ignore_patterns, apply_size_cap=False
    ):
        if scanned >= MAX_FILES or (time.monotonic() - t0) > TOTAL_BUDGET_SEC:
            all_findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="low",
                title="Oversize scan incomplete (budget reached)",
                description=(
                    "Stopped scanning after the file-count/time budget; remaining "
                    "files not scanned for oversize/whitespace inflation."
                ),
                file=rel_path, line=0, snippet="", category="archive-scan-incomplete",
            ))
            break
        scanned += 1
        try:
            size = os.path.getsize(file_path)
        except OSError:
            continue

        if size > OVERSIZE_BYTES:
            all_findings.extend(scan_oversized_file(file_path, rel_path))
        # Whitespace inflation can hide under the cap too — always check.
        all_findings.extend(scan_whitespace_inflation(file_path, rel_path))

    return all_findings


def main():
    args = core.parse_common_args(sys.argv, "Oversize & Whitespace-Inflation Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning for oversized / whitespace-inflated files in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = scan_repo(repo_path, ignore_patterns)
    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
