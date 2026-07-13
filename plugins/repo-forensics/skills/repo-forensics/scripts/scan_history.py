#!/usr/bin/env python3
"""Content-addressed scan attestations and deferred enrichment state."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sqlite3
import sys
import time
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS attestations (
    id INTEGER PRIMARY KEY,
    run_ts REAL NOT NULL,
    tree_hash TEXT NOT NULL,
    rulepack_digest TEXT NOT NULL,
    scanner_versions TEXT NOT NULL,
    env_fingerprint TEXT NOT NULL,
    core_verdict TEXT NOT NULL,
    coverage_status TEXT NOT NULL,
    enrichment_status TEXT NOT NULL,
    evidence_hashes TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS attestations_tree_idx ON attestations(tree_hash);
CREATE TABLE IF NOT EXISTS tree_files (
    tree_hash TEXT NOT NULL,
    path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    PRIMARY KEY (tree_hash, path)
);
CREATE TABLE IF NOT EXISTS evidence_state (
    evidence_key TEXT PRIMARY KEY,
    evidence_type TEXT NOT NULL,
    status TEXT NOT NULL,
    checked_at REAL NOT NULL,
    ttl_seconds REAL NOT NULL,
    details TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS retry_queue (
    id INTEGER PRIMARY KEY,
    source_attestation_id INTEGER,
    capability TEXT NOT NULL,
    reason TEXT NOT NULL,
    queued_at REAL NOT NULL,
    completed_attestation_id INTEGER
);
"""


def default_db_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".cache", "repo-forensics", "history.db")


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def tree_manifest(repo_path: str) -> dict[str, str]:
    """Return stable relative-path to content-hash entries for regular files."""
    root = Path(repo_path).resolve()
    manifest = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        rel = path.relative_to(root).as_posix()
        try:
            manifest[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
    return manifest


def compute_tree_hash(repo_path: str) -> tuple[str, dict[str, str]]:
    manifest = tree_manifest(repo_path)
    return _digest(manifest), manifest


def environment_fingerprint() -> str:
    return _digest({
        "platform": platform.platform(),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
    })


def compute_rulepack_digest(base_dir: str | None = None) -> str:
    """Hash shipped rule data without loading executable scanner modules."""
    root = Path(base_dir) if base_dir else Path(__file__).resolve().parent.parent / "data" / "rulepacks"
    entries = {}
    try:
        for path in sorted(root.glob("*.json")):
            entries[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "unavailable"
    return _digest(entries)


def scanner_versions(scanners: list[dict]) -> dict[str, str]:
    return {
        str(item.get("name", "unknown")): str(item.get("version", "unknown"))
        for item in scanners
    }


def evidence_hashes(findings: list[dict]) -> list[str]:
    return sorted(_digest(item) for item in findings)


class HistoryStore:
    def __init__(self, path: str | None = None):
        self.path = path or default_db_path()

    def connect(self):
        parent = os.path.dirname(self.path)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            os.chmod(self.path, 0o600)
            connection.executescript(SCHEMA)
            connection.commit()
        except Exception:
            connection.close()
            raise
        return connection

    def record(self, repo_path: str, report: dict, rulepack_digest: str | None = None) -> dict:
        tree_hash, manifest = compute_tree_hash(repo_path)
        rulepack_digest = rulepack_digest or compute_rulepack_digest()
        versions = scanner_versions(report.get("scanners", []))
        env = environment_fingerprint()
        evidence = evidence_hashes(report.get("findings", []))
        fields = (
            time.time(), tree_hash, rulepack_digest, _canonical(versions), env,
            _canonical(report.get("core_verdict", {})),
            _canonical(report.get("coverage_status", {})),
            _canonical(report.get("enrichment_status", {})), _canonical(evidence),
        )
        with self.connect() as db:
            cursor = db.execute(
                "INSERT INTO attestations (run_ts, tree_hash, rulepack_digest, "
                "scanner_versions, env_fingerprint, core_verdict, coverage_status, "
                "enrichment_status, evidence_hashes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                fields,
            )
            db.executemany(
                "INSERT OR IGNORE INTO tree_files (tree_hash, path, content_hash) VALUES (?, ?, ?)",
                [(tree_hash, path, digest) for path, digest in manifest.items()],
            )
            attestation_id = cursor.lastrowid
        return {
            "id": attestation_id,
            "tree_hash": tree_hash,
            "rulepack_digest": rulepack_digest,
            "scanner_versions": versions,
            "env_fingerprint": env,
            "evidence_hashes": evidence,
        }

    def get(self, attestation_id: int) -> dict | None:
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM attestations WHERE id = ?", (attestation_id,)).fetchone()
        return dict(row) if row else None

    def diff(self, tree_hash_a: str, tree_hash_b: str) -> dict:
        with self.connect() as db:
            rows = db.execute(
                "SELECT tree_hash, path, content_hash FROM tree_files WHERE tree_hash IN (?, ?)",
                (tree_hash_a, tree_hash_b),
            ).fetchall()
        left = {path: digest for tree, path, digest in rows if tree == tree_hash_a}
        right = {path: digest for tree, path, digest in rows if tree == tree_hash_b}
        return {
            "added": sorted(right.keys() - left.keys()),
            "removed": sorted(left.keys() - right.keys()),
            "changed": sorted(path for path in left.keys() & right.keys() if left[path] != right[path]),
        }

    def put_evidence_state(self, key: str, evidence_type: str, status: str,
                           checked_at: float, ttl_seconds: float, details=None):
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO evidence_state VALUES (?, ?, ?, ?, ?, ?)",
                (key, evidence_type, status, checked_at, ttl_seconds, _canonical(details or {})),
            )

    def evidence_freshness(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        with self.connect() as db:
            rows = db.execute(
                "SELECT evidence_key, evidence_type, status, checked_at, ttl_seconds, details "
                "FROM evidence_state"
            ).fetchall()
        result = []
        for key, kind, status, checked, ttl, details in rows:
            stale = now - checked > ttl
            result.append({
                "key": key, "type": kind,
                "status": "RECHECK_REQUIRED" if stale and kind == "dead_anchor" else "STALE" if stale else status,
                "checked_at": checked, "ttl_seconds": ttl, "details": json.loads(details),
            })
        return result

    def enqueue_retry(self, capability: str, reason: str, source_attestation_id=None) -> int:
        with self.connect() as db:
            cursor = db.execute(
                "INSERT INTO retry_queue (source_attestation_id, capability, reason, queued_at) "
                "VALUES (?, ?, ?, ?)",
                (source_attestation_id, capability, reason, time.time()),
            )
            return cursor.lastrowid

    def complete_retry(self, retry_id: int, new_attestation_id: int):
        with self.connect() as db:
            db.execute(
                "UPDATE retry_queue SET completed_attestation_id = ? WHERE id = ?",
                (new_attestation_id, retry_id),
            )


def record_report_safely(repo_path: str, report: dict, db_path: str | None = None,
                         rulepack_digest: str | None = None) -> dict | None:
    """Persist an attestation without allowing storage failure onto the scan path."""
    try:
        return HistoryStore(db_path).record(repo_path, report, rulepack_digest)
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        print(f"[!] Scan history unavailable: {exc}", file=sys.stderr)
        return None


def evidence_history_enabled() -> bool:
    """Evidence freshness is opt-in, gated by the same HISTORY flag as attestations."""
    return os.environ.get("REPO_FORENSICS_HISTORY") == "1"


def evidence_db_path() -> str | None:
    """Return an explicit DB path if one is configured, otherwise None for the default."""
    if not evidence_history_enabled():
        return None
    return os.environ.get("REPO_FORENSICS_HISTORY_DB") or None


def put_evidence_state_safely(key: str, evidence_type: str, status: str,
                              checked_at: float, ttl_seconds: float,
                              details=None,
                              db_path: str | None = None) -> dict | None:
    """Persist per-anchor evidence state without allowing DB failures to crash a scan."""
    if db_path is None:
        db_path = evidence_db_path()
    if db_path is None:
        return None
    try:
        HistoryStore(db_path).put_evidence_state(
            key, evidence_type, status, checked_at, ttl_seconds, details
        )
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        print(f"[!] Evidence state unavailable: {exc}", file=sys.stderr)
        return None
    return {"key": key, "status": status}


def evidence_freshness_safely(db_path: str | None = None, now: float | None = None) -> list[dict]:
    """Read evidence freshness without allowing DB failures to block a scan."""
    if db_path is None:
        db_path = evidence_db_path()
    if db_path is None:
        return []
    try:
        return HistoryStore(db_path).evidence_freshness(now)
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        print(f"[!] Evidence freshness unavailable: {exc}", file=sys.stderr)
        return []
