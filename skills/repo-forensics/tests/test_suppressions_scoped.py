import hashlib
import json
import time

from scripts import aggregate_json
from scripts import forensics_core


def finding():
    return {
        "scanner": "static", "severity": "high", "title": "unsafe",
        "description": "unsafe", "file": "src/a.py", "line": 1,
        "category": "execution", "rule_id": "R-1", "confidence": 0.8,
    }


def write_suppression(repo, expiry, content_hash):
    entry = {
        "rule_id": "R-1", "scope": "src/**", "author": "reviewer",
        "reason": "known generated wrapper", "expiry": expiry,
        "content_hash": content_hash,
    }
    entry["signature"] = forensics_core.suppression_signature(entry)
    (repo / ".forensicsignore").write_text("suppress:" + json.dumps(entry))


def test_valid_scoped_suppression_applies(tmp_path):
    path = tmp_path / "src" / "a.py"
    path.parent.mkdir()
    path.write_text("stable")
    write_suppression(tmp_path, time.time() + 60, hashlib.sha256(b"stable").hexdigest())
    active, suppressed = aggregate_json.apply_suppressions([finding()], str(tmp_path))
    assert not active
    assert suppressed == [finding()]


def test_expired_suppression_does_not_hide_finding(tmp_path):
    path = tmp_path / "src" / "a.py"
    path.parent.mkdir()
    path.write_text("stable")
    write_suppression(tmp_path, 1, hashlib.sha256(b"stable").hexdigest())
    active, suppressed = aggregate_json.apply_suppressions([finding()], str(tmp_path))
    assert not suppressed
    assert finding() in active


def test_changed_content_voids_suppression(tmp_path):
    path = tmp_path / "src" / "a.py"
    path.parent.mkdir()
    path.write_text("changed")
    write_suppression(tmp_path, time.time() + 60, hashlib.sha256(b"before").hexdigest())
    active, suppressed = aggregate_json.apply_suppressions([finding()], str(tmp_path))
    assert not suppressed
    assert finding() in active
