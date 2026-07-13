import json

from scripts import vuln_feed


def test_expired_cache_is_stale_without_rewriting_it(tmp_path):
    cache = tmp_path / "feed.json"
    original = {"_cached_at": 10, "items": ["CVE-1"]}
    cache.write_text(json.dumps(original))
    assert vuln_feed.cache_freshness(str(cache), 1, now=4000)["status"] == "STALE"
    assert json.loads(cache.read_text()) == original


def test_missing_cache_requires_recheck(tmp_path):
    state = vuln_feed.cache_freshness(str(tmp_path / "missing"), 24)
    assert state["status"] == "RECHECK_REQUIRED"


def test_recent_cache_is_fresh(tmp_path):
    cache = tmp_path / "feed.json"
    cache.write_text(json.dumps({"_cached_at": 100}))
    assert vuln_feed.cache_freshness(str(cache), 1, now=101)["status"] == "FRESH"
