import os
import stat

from scripts import scan_history


def report():
    return {
        "scanners": [{"name": "static", "version": "1"}],
        "core_verdict": {"tier": "clean", "exit_code": 0},
        "coverage_status": {"overall": "COMPLETE"},
        "enrichment_status": {"overall": "COMPLETE"},
        "findings": [],
    }


def test_identical_content_produces_reproducible_attestation(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.txt").write_text("same")
    store = scan_history.HistoryStore(str(tmp_path / "history.db"))
    first = store.record(str(repo), report(), "packs")
    second = store.record(str(repo), report(), "packs")
    for key in ("tree_hash", "rulepack_digest", "scanner_versions", "env_fingerprint", "evidence_hashes"):
        assert first[key] == second[key]


def test_changed_content_is_visible_in_diff(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "a.txt"
    target.write_text("before")
    store = scan_history.HistoryStore(str(tmp_path / "history.db"))
    before = store.record(str(repo), report())
    target.write_text("after")
    (repo / "new.txt").write_text("new")
    after = store.record(str(repo), report())
    assert store.diff(before["tree_hash"], after["tree_hash"]) == {
        "added": ["new.txt"], "removed": [], "changed": ["a.txt"]
    }


def test_database_has_private_permissions(tmp_path):
    path = tmp_path / "history.db"
    scan_history.HistoryStore(str(path)).connect().close()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_storage_failure_does_not_change_report(tmp_path):
    original = report()
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("x")
    assert scan_history.record_report_safely(str(tmp_path), original, str(blocked / "db")) is None
    assert original["core_verdict"]["exit_code"] == 0


def test_stale_external_evidence_requests_recheck(tmp_path):
    store = scan_history.HistoryStore(str(tmp_path / "history.db"))
    store.put_evidence_state("anchor", "dead_anchor", "LIVE", 10, 5)
    assert store.evidence_freshness(now=20)[0]["status"] == "RECHECK_REQUIRED"


def test_retry_completion_preserves_source_attestation(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    store = scan_history.HistoryStore(str(tmp_path / "history.db"))
    source = store.record(str(repo), report())
    retry = store.enqueue_retry("dead_anchors", "offline", source["id"])
    newer = store.record(str(repo), report())
    store.complete_retry(retry, newer["id"])
    assert store.get(source["id"])["id"] == source["id"]


def test_rulepack_digest_changes_with_rule_data(tmp_path):
    pack = tmp_path / "rules.json"
    pack.write_text('{"rules": []}')
    before = scan_history.compute_rulepack_digest(str(tmp_path))
    pack.write_text('{"rules": [1]}')
    assert scan_history.compute_rulepack_digest(str(tmp_path)) != before
