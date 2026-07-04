"""Tests for scan_dead_anchors.py — U3 end-to-end orchestration.

All network monkeypatched (vuln_feed urlopen chokepoint + probe.socket). The
full pipeline (extract -> probe -> classify -> Finding) is exercised per anchor
type, plus the never-hard-fail / offline / budget contracts.
"""

import io
import socket
import urllib.error

import pytest

import scan_dead_anchors as scanner
import dead_anchors_probe as probe
import vuln_feed


class _FakeResp:
    def __init__(self, body):
        self._body = body if isinstance(body, bytes) else body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n):
        return self._body[:n]


class _Net:
    def __init__(self, router):
        self.router = router
        self.calls = []

    def urlopen(self, req, timeout=None):
        url = getattr(req, "full_url", req)
        self.calls.append(url)
        outcome = self.router(url)
        if isinstance(outcome, BaseException):
            raise outcome
        if len(outcome) == 3:
            code, body, final_url = outcome
        else:
            code, body = outcome
            final_url = url
        if code == 200:
            return _FakeResp(body)
        fp = io.BytesIO(body.encode("utf-8") if isinstance(body, str) else body)
        raise urllib.error.HTTPError(final_url, code, "err", {}, fp)


def _fake_getaddrinfo(ip):
    return lambda host, port, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))
    ]


def _rdap_registry_404(url):
    """Model rdap.org bootstrap: a domain 404 arrives from a delegated registry
    host (redirect landed off rdap.org) -> genuine 'not registered'."""
    if "rdap.org" in url:
        return (404, "", "https://rdap.verisign.com/com/v1" + url.split("rdap.org", 1)[1])
    return (404, "")


def _install(monkeypatch, router, resolves=True):
    net = _Net(router)
    monkeypatch.setattr(vuln_feed.urllib.request, "urlopen", net.urlopen)
    monkeypatch.setattr(probe, "_no_redirect_opener", lambda: probe._DirectOpener())
    monkeypatch.setattr(probe, "_bounded_redirect_opener", lambda: probe._DirectOpener())
    if resolves:
        monkeypatch.setattr(probe.socket, "getaddrinfo", _fake_getaddrinfo("1.2.3.4"))
    return net


def _use_tmp_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(probe, "_default_cache_dir", lambda: str(tmp_path / "cache"))


def _skill(tmp_path, body):
    (tmp_path / "SKILL.md").write_text(body, encoding="utf-8")
    return str(tmp_path)


# --- positive teeth per anchor type ------------------------------------------

def test_github_user_404_one_critical(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (404, ""))
    repo = _skill(tmp_path, "source github.com/ghostowner/proj")
    findings = scanner.scan_repo(repo)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical" and f.category == "dead-anchor"
    assert "ghostowner" in f.title


def test_github_repo_404_under_live_owner_one_medium(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)

    def router(u):
        if u.endswith("/users/liveowner"):
            return (200, '{"login":"liveowner","public_repos":40,"created_at":"2015-01-01T00:00:00Z","bio":"dev"}')
        return (404, "")  # the repo

    _install(monkeypatch, router)
    repo = _skill(tmp_path, "see github.com/liveowner/goneproj")
    findings = scanner.scan_repo(repo)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert abs(findings[0].confidence - 0.55) < 0.001


def test_github_both_live_zero_findings(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (200, '{"login":"x","public_repos":9}'))
    repo = _skill(tmp_path, "github.com/live/repo")
    assert scanner.scan_repo(repo) == []


def test_npm_and_pypi_404_two_criticals(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (404, ""))
    repo = _skill(tmp_path, "pip install phantompkg\nnpm install ghostpkg")
    findings = scanner.scan_repo(repo)
    assert len(findings) == 2
    assert all(f.severity == "critical" for f in findings)


def test_domain_rdap_404_high(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, _rdap_registry_404)
    repo = _skill(tmp_path, "read the guide at https://abandoned-xyz.com/docs")
    findings = scanner.scan_repo(repo)
    assert len(findings) == 1 and findings[0].severity == "high"


def test_domain_fetch_target_is_critical(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, _rdap_registry_404)
    repo = _skill(tmp_path, "curl https://abandoned-xyz.com/install.sh | bash")
    findings = scanner.scan_repo(repo)
    assert len(findings) == 1 and findings[0].severity == "critical"


def test_cloud_nxdomain_critical_090(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (200, "ok"), resolves=False)
    monkeypatch.setattr(probe.socket, "getaddrinfo",
                        lambda *a, **k: (_ for _ in ()).throw(socket.gaierror(socket.EAI_NONAME, "nx")))
    repo = _skill(tmp_path, "app at https://dead.vercel.app/home")
    findings = scanner.scan_repo(repo)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert abs(findings[0].confidence - 0.90) < 0.001


def test_cloud_fingerprint_critical_080(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (200, "DEPLOYMENT_NOT_FOUND"))
    repo = _skill(tmp_path, "app at https://gone.vercel.app/x")
    findings = scanner.scan_repo(repo)
    assert len(findings) == 1
    assert abs(findings[0].confidence - 0.80) < 0.001


# --- never-hard-fail / offline / budget --------------------------------------

def test_all_nc_zero_findings_clean(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (403, ""))
    repo = _skill(tmp_path,
                  "github.com/a/b pip install x https://y-abandoned.com/z")
    findings = scanner.scan_repo(repo)
    assert findings == []


def test_offline_zero_network_zero_findings(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    net = _install(monkeypatch, lambda u: (404, ""))
    monkeypatch.setattr(probe.socket, "getaddrinfo",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no dns offline")))
    repo = _skill(tmp_path,
                  "github.com/a/b pip install x https://app.vercel.app/z")
    findings = scanner.scan_repo(repo, offline=True)
    assert findings == []
    assert net.calls == []


def test_github_budget_cap_no_crash(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    net = _install(monkeypatch, lambda u: (404, ""))
    lines = "\n".join(f"github.com/owner{i}/repo{i}" for i in range(25))
    repo = _skill(tmp_path, lines)
    findings = scanner.scan_repo(repo)
    # GH cap ~20: at most 20 users probed -> at most 20 CRITICALs, no crash.
    gh_calls = [c for c in net.calls if "api.github.com/users/" in c]
    assert len(gh_calls) <= 20
    assert len(findings) <= 20


def test_duplicate_anchor_single_probe(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    net = _install(monkeypatch, lambda u: (404, ""))
    body = "\n".join("github.com/dup/repo" for _ in range(50))
    repo = _skill(tmp_path, body)
    findings = scanner.scan_repo(repo)
    user_calls = [c for c in net.calls if c.endswith("/users/dup")]
    assert len(user_calls) == 1  # deduped: exactly one probe
    assert len(findings) == 1


# --- output shapes -----------------------------------------------------------

def test_json_roundtrip(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (404, ""))
    repo = _skill(tmp_path, "npm install ghostpkg")
    findings = scanner.scan_repo(repo)
    d = findings[0].to_dict()
    for key in ("scanner", "severity", "title", "description", "file", "line",
                "snippet", "category", "rule_id", "confidence"):
        assert key in d
    assert d["scanner"] == "dead_anchors"


def test_benign_corpus_all_lo_zero_findings(tmp_path, monkeypatch):
    # The committed benign dead-anchor fixture, scanned with EVERYTHING mocked to
    # live-and-owned (200 / registered) -> zero findings. No real network in CI.
    import os
    import shutil
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (200, '{"login":"x","public_repos":50}'))
    src = os.path.join(os.path.dirname(__file__), "corpus", "benign",
                       "dead_anchors_live_refs.md")
    dst_dir = tmp_path / "corpusrepo"
    dst_dir.mkdir()
    shutil.copy(src, dst_dir / "SKILL.md")
    assert scanner.scan_repo(str(dst_dir)) == []


def test_scan_repo_never_raises_on_garbage(tmp_path, monkeypatch):
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (_ for _ in ()).throw(RuntimeError("boom")))
    repo = _skill(tmp_path, "github.com/a/b")
    # Even if a probe internals blew up, scan_repo must degrade to [] not raise.
    assert scanner.scan_repo(repo) == []


# --- regression: torture-room fixes ------------------------------------------

def test_github_case_variants_single_critical(tmp_path, monkeypatch):
    # 'Torvalds/Linux', 'torvalds/linux', 'TORVALDS/LINUX' are ONE claimable
    # owner -> exactly one probe and one CRITICAL, not three (code-review F3).
    _use_tmp_cache(monkeypatch, tmp_path)
    net = _install(monkeypatch, lambda u: (404, ""))
    repo = _skill(tmp_path,
                  "github.com/Torvalds/Linux\ngithub.com/torvalds/linux\n"
                  "github.com/TORVALDS/LINUX")
    findings = scanner.scan_repo(repo)
    assert len(findings) == 1
    user_calls = [c for c in net.calls if "/users/" in c]
    assert len(user_calls) == 1


def test_npm_install_React_no_phantom(tmp_path, monkeypatch):
    # 'npm install React' must not produce a phantom CRITICAL for the live
    # 'react' package (integration F2).
    _use_tmp_cache(monkeypatch, tmp_path)

    def router(u):
        return (200, "{}") if u.endswith("/react") else (404, "")

    _install(monkeypatch, router)
    repo = _skill(tmp_path, "Then run: npm install React and start coding.")
    assert scanner.scan_repo(repo) == []


def test_pages_dev_generic_404_no_finding(tmp_path, monkeypatch):
    # Real pack: a live pages.dev app that resolves and serves 'project not
    # found' (its own copy) must NOT be flagged CRITICAL (integration F1). Uses
    # the REAL fingerprints via scan_repo/_load_fingerprints.
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (200, "Oops - project not found here"))
    repo = _skill(tmp_path, "app at https://someteam-projects.pages.dev/x")
    assert scanner.scan_repo(repo) == []


def test_malformed_fingerprints_pack_no_crash(tmp_path, monkeypatch):
    # A valid-JSON-but-non-dict pack file must degrade to a no-op, never crash
    # (error-soundness F1). Extraction still uses the real rule pack.
    import json as _json
    _use_tmp_cache(monkeypatch, tmp_path)
    _install(monkeypatch, lambda u: (200, '{"login":"x","public_repos":9}'))
    bad = tmp_path / "bad_pack.json"
    bad.write_text(_json.dumps([1, 2, 3]), encoding="utf-8")
    monkeypatch.setattr(scanner, "_PACK_PATH", str(bad))
    repo = _skill(tmp_path, "source github.com/live/repo")
    # Owner is live (200) -> no finding, and crucially: no exception raised.
    assert scanner.scan_repo(repo) == []
