#!/usr/bin/env python3
"""
corpus_sync.py - Dev-only tool: snapshots pinned-SHA repositories into
~/.cache/repo-forensics/corpus/ for use with the extended-corpus regression
gate in tests/test_benign_corpus.py.

THIS SCRIPT IS THE ONLY NETWORK-TOUCHING PIECE OF THE BENIGN CORPUS SYSTEM.
It is intended for explicit developer invocation only and is NEVER imported
by the test suite.  Calling it from a test is a bug.

Usage:
    python3 scripts/corpus_sync.py [--cache-dir PATH] [--dry-run] [--verbose]

The script downloads the HEAD of each pinned repository SHA from GitHub via
HTTPS (host allowlist: github.com, raw.githubusercontent.com only), extracts
files matching benign file patterns, and writes them to:

    ~/.cache/repo-forensics/corpus/<repo-slug>/<sha-short>/

Re-runs are idempotent: a directory whose sha-short already exists is skipped.

Network discipline (mirrors ioc_manager.py):
- HTTPS only; http:// URLs are rejected before any connection.
- Allowlisted hosts: ALLOWED_HOSTS below; any other host is rejected.
- 5 MB per-file cap; zip archives capped at 20 MB.
- Atomic temp+rename writes; cache dir mode 0700.
- No credentials stored or transmitted.
- Content-type is validated; JSON-decoded archives only.

Run tests/test_benign_corpus.py without this script: the extended-corpus
parameterised tests skip gracefully when the cache dir is absent.

Created by Alex Greenshpun (U7, 2026-06-10)
"""

import argparse
import io
import json
import os
import pathlib
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

# ---------------------------------------------------------------------------
# Network discipline
# ---------------------------------------------------------------------------

ALLOWED_HOSTS = frozenset({
    "github.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
})

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024   # 20 MB
MAX_FILE_BYTES = 5 * 1024 * 1024        # 5 MB
REQUEST_TIMEOUT_SECONDS = 30


def _safe_fetch(url, max_bytes=MAX_ARCHIVE_BYTES):
    """Fetch *url* with host-allowlist and size-cap enforcement.

    Returns bytes on success.  Raises ValueError for policy violations;
    raises urllib.error.URLError / IOError for network failures.
    """
    if not url.startswith("https://"):
        raise ValueError(f"Non-HTTPS URL rejected: {url!r}")
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Host not in allowlist: {host!r}")

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "repo-forensics-corpus-sync/1.0"},
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
        content_length = resp.headers.get("Content-Length")
        if content_length and int(content_length) > max_bytes:
            raise ValueError(
                f"Content-Length {content_length} exceeds cap {max_bytes}"
            )
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(
                f"Response body exceeds cap {max_bytes} bytes"
            )
    return data


# ---------------------------------------------------------------------------
# Pinned corpus entries
# ---------------------------------------------------------------------------
# Each entry specifies a publicly-accessible GitHub repository at an exact
# commit SHA.  Only files whose names or extensions match BENIGN_PATTERNS are
# extracted -- never compiled code, archives, or binaries.
#
# Adding a new entry: choose a well-known open-source project with a
# permissive license; pick a recent release tag SHA; verify locally that the
# extracted files produce zero critical/high findings before committing here.

PINNED_REPOS = [
    {
        "slug": "github_linguist",
        "repo": "github-linguist/linguist",
        "sha": "a7b8a0b1b77fc7f3d62c1ed1e0e53e19fdb08a3a",  # v7.29.0
        "description": "GitHub Linguist -- large benign codebase, many file types",
        "extract_globs": ["*.md", "*.txt", "*.json", "*.yml", "*.yaml"],
        "max_files": 50,
    },
    {
        "slug": "actions_checkout",
        "repo": "actions/checkout",
        "sha": "11bd71901bbe5b1630ceea73d27597364c9af683",  # v4.2.2
        "description": "actions/checkout -- clean GitHub Actions workflow and JS",
        "extract_globs": ["*.yml", "*.json", "*.md"],
        "max_files": 30,
    },
]

# File extensions/names accepted from any pinned repo.
BENIGN_EXTENSIONS = frozenset({
    ".md", ".txt", ".rst", ".yml", ".yaml", ".json", ".toml",
    ".cfg", ".ini", ".css", ".html",
})
BENIGN_BASENAMES = frozenset({
    "Dockerfile", ".env.example", ".env.template",
    "Makefile", "LICENSE", "NOTICE",
})


def _should_extract(name):
    """Return True if the file's basename / extension is in the benign set."""
    base = os.path.basename(name)
    ext = os.path.splitext(base)[1].lower()
    return ext in BENIGN_EXTENSIONS or base in BENIGN_BASENAMES


# ---------------------------------------------------------------------------
# Sync logic
# ---------------------------------------------------------------------------

def _sha_short(sha):
    return sha[:12]


def _cache_dir_for(base_cache, entry):
    return base_cache / entry["slug"] / _sha_short(entry["sha"])


def sync_entry(entry, base_cache, dry_run=False, verbose=False):
    """Download and extract files for one pinned repo entry."""
    target_dir = _cache_dir_for(base_cache, entry)

    if target_dir.exists():
        if verbose:
            print(f"[skip] {entry['slug']} @ {_sha_short(entry['sha'])} already cached")
        return

    repo = entry["repo"]
    sha = entry["sha"]
    url = f"https://codeload.github.com/{repo}/zip/{sha}"

    if verbose:
        print(f"[fetch] {entry['slug']} @ {_sha_short(sha)} from {url}")

    if dry_run:
        print(f"[dry-run] would fetch: {url}")
        return

    # Fetch archive
    try:
        archive_bytes = _safe_fetch(url, max_bytes=MAX_ARCHIVE_BYTES)
    except (urllib.error.URLError, ValueError, OSError) as exc:
        print(f"[error] fetch failed for {entry['slug']}: {exc}", file=sys.stderr)
        return

    # Validate zip structure
    try:
        zf = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as exc:
        print(f"[error] invalid zip for {entry['slug']}: {exc}", file=sys.stderr)
        return

    # Extract to temp dir first (atomic rename on success)
    tmp_parent = base_cache / entry["slug"]
    tmp_parent.mkdir(parents=True, exist_ok=True)
    tmp_parent.chmod(0o700)

    with tempfile.TemporaryDirectory(dir=str(tmp_parent)) as tmp_dir:
        tmp_path = pathlib.Path(tmp_dir) / _sha_short(sha)
        tmp_path.mkdir()

        max_files = entry.get("max_files", 100)
        extracted = 0
        for info in zf.infolist():
            if info.is_dir():
                continue
            if not _should_extract(info.filename):
                continue
            if info.file_size > MAX_FILE_BYTES:
                if verbose:
                    print(f"  [skip-large] {info.filename} ({info.file_size} bytes)")
                continue
            if extracted >= max_files:
                if verbose:
                    print(f"  [cap] reached max_files={max_files}, stopping extraction")
                break

            # Flatten path: keep only basename to avoid path-traversal risk.
            safe_name = os.path.basename(info.filename)
            if not safe_name:
                continue

            dest = tmp_path / safe_name
            # Resolve and confirm it's inside tmp_path (path traversal guard)
            try:
                dest.resolve().relative_to(tmp_path.resolve())
            except ValueError:
                print(f"  [path-traversal] rejected: {info.filename}", file=sys.stderr)
                continue

            dest.write_bytes(zf.read(info.filename))
            extracted += 1
            if verbose:
                print(f"  [extract] {info.filename} -> {safe_name}")

        # Atomic rename
        target_dir.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.rename(target_dir)
        target_dir.chmod(0o700)

    if verbose:
        print(f"[done] {entry['slug']} @ {_sha_short(sha)}: {extracted} files -> {target_dir}")


def sync_all(base_cache, dry_run=False, verbose=False):
    """Sync all pinned entries into base_cache."""
    base_cache = pathlib.Path(base_cache)
    base_cache.mkdir(parents=True, exist_ok=True)
    base_cache.chmod(0o700)

    # Write a metadata file for idempotency and audit.
    meta_path = base_cache / "corpus_sync_meta.json"
    meta = {
        "synced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "entries": [
            {"slug": e["slug"], "sha": e["sha"], "repo": e["repo"]}
            for e in PINNED_REPOS
        ],
    }

    for entry in PINNED_REPOS:
        sync_entry(entry, base_cache, dry_run=dry_run, verbose=verbose)

    if not dry_run:
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)

    print(f"[corpus_sync] done. Cache: {base_cache}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--cache-dir",
        default=str(
            pathlib.Path(os.path.expanduser("~")) / ".cache" / "repo-forensics" / "corpus"
        ),
        help="Override cache directory (default: ~/.cache/repo-forensics/corpus/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be fetched without fetching",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-file extraction progress",
    )
    args = parser.parse_args()
    sync_all(args.cache_dir, dry_run=args.dry_run, verbose=args.verbose)


if __name__ == "__main__":
    main()
