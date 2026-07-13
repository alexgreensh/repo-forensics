import hashlib
import json
import time

from scripts import aggregate_json
from scripts import forensics_core


def test_content_mutation_resurfaces_security_finding(tmp_path):
    target = tmp_path / "payload.py"
    target.write_text("safe")
    entry = {
        "rule_id": "EXEC-1", "scope": "*.py", "author": "reviewer",
        "reason": "reviewed content", "expiry": time.time() + 60,
        "content_hash": hashlib.sha256(b"safe").hexdigest(),
    }
    entry["signature"] = forensics_core.suppression_signature(entry)
    (tmp_path / ".forensicsignore").write_text("suppress:" + json.dumps(entry))
    target.write_text("exec(input())")
    finding = {"rule_id": "EXEC-1", "file": "payload.py", "severity": "high"}
    active, suppressed = aggregate_json.apply_suppressions([finding], str(tmp_path))
    assert finding in active
    assert not suppressed
