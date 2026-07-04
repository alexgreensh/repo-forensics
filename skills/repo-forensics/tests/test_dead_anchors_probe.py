"""Tests for dead_anchors_probe.py — U2 network claimability layer.

EVERY network call is monkeypatched: vuln_feed's urllib.request.urlopen (the one
real HTTPS chokepoint, reached through vuln_feed._https_fetch) and the probe
module's socket.gethostbyname. NO test ever performs a real HTTP request or DNS
lookup. A module-level call counter backs the "zero real network" assertions,
the budget/ceiling caps, the circuit breaker, and the no-retry guarantee.
"""

import io
import socket
import urllib.error

import pytest

import dead_anchors_probe as probe
import vuln_feed


# --- network doubles ---------------------------------------------------------

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
    """Routes a request URL to a 2-tuple (code, body), a 3-tuple
    (code, body, final_url) — final_url models the URL a redirect chain actually
    landed on, used to test rdap.org registry-vs-bootstrap 404 discrimination —
    or an Exception. Counts every urlopen invocation."""

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


def _install(monkeypatch, router):
    net = _Net(router)
    monkeypatch.setattr(vuln_feed.urllib.request, "urlopen", net.urlopen)
    # Route the scanner's no-redirect / bounded-redirect openers back through the
    # single mocked chokepoint (see probe._DirectOpener). Production uses the
    # real openers; here every probe still hits the mock, never real network.
    monkeypatch.setattr(probe, "_no_redirect_opener", lambda: probe._DirectOpener())
    monkeypatch.setattr(probe, "_bounded_redirect_opener", lambda: probe._DirectOpener())
    # getaddrinfo defaults to "resolves to a public IP" unless a test overrides.
    monkeypatch.setattr(probe.socket, "getaddrinfo", _fake_getaddrinfo("1.2.3.4"))
    return net


def _fake_getaddrinfo(ip):
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return lambda host, port, *a, **k: [
        (fam, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))
    ]


def _nxdomain_getaddrinfo(host, port, *a, **k):
    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


def _ctx(tmp_path, offline=False, github_token=None):
    return probe.ProbeContext(offline=offline, cache_dir=str(tmp_path),
                              github_token=github_token)


_FPS = {
    "vercel.app": [{"s": "DEPLOYMENT_NOT_FOUND", "confidence": 0.8, "strict": True}],
    "pages.dev": [{"s": "project not found", "confidence": 0.7}],  # non-strict
}


# --- positive CC verdicts ----------------------------------------------------

def test_github_user_404_is_cc(tmp_path, monkeypatch):
    _install(monkeypatch, lambda u: (404, ""))
    verdict, _ = probe.probe_github_user("ghostowner", _ctx(tmp_path))
    assert verdict == "CC"


def test_npm_and_pypi_404_are_cc(tmp_path, monkeypatch):
    _install(monkeypatch, lambda u: (404, ""))
    assert probe.probe_npm("phantom-pkg", _ctx(tmp_path))[0] == "CC"
    assert probe.probe_pypi("phantom-pkg", _ctx(tmp_path))[0] == "CC"


def test_rdap_404_is_cc(tmp_path, monkeypatch):
    # A registry RDAP server (reached after the rdap.org bootstrap redirect)
    # returning 404 means the domain genuinely does not exist => CC.
    _install(monkeypatch, lambda u: (
        404, "", "https://rdap.verisign.com/com/v1/domain/expired-example.com"))
    assert probe.probe_domain_rdap("expired-example.com", _ctx(tmp_path))[0] == "CC"


def test_rdap_bootstrap_gap_404_is_nc(tmp_path, monkeypatch):
    # A bare 404 straight from rdap.org (no redirect happened -> final host is
    # still rdap.org) means it could not bootstrap a server for this TLD; that is
    # ambiguous and must NOT fire a false CRITICAL on a possibly-live domain.
    _install(monkeypatch, lambda u: (404, ""))  # final_url defaults to rdap.org
    assert probe.probe_domain_rdap("some-cctld-domain.zz", _ctx(tmp_path))[0] == "NC"


def test_cloud_nxdomain_is_cc(tmp_path, monkeypatch):
    _install(monkeypatch, lambda u: (200, "ok"))
    monkeypatch.setattr(probe.socket, "getaddrinfo", _nxdomain_getaddrinfo)
    verdict, extra = probe.probe_cloud_subdomain("dead.vercel.app", "vercel.app",
                                                 _ctx(tmp_path), fingerprints=_FPS)
    assert verdict == "CC" and extra.get("reason") == "nxdomain"


def test_cloud_ipv6_only_is_not_nxdomain(tmp_path, monkeypatch):
    # AAAA-only host resolves fine via getaddrinfo -> must NOT be a false CC
    # (security-sentinel F3: gethostbyname is IPv4-only and would misread it).
    _install(monkeypatch, lambda u: (200, "<html>live app</html>"))
    monkeypatch.setattr(probe.socket, "getaddrinfo",
                        _fake_getaddrinfo("2606:4700::1111"))
    verdict, _ = probe.probe_cloud_subdomain("live.vercel.app", "vercel.app",
                                             _ctx(tmp_path), fingerprints=_FPS)
    assert verdict == "LO"


def test_cloud_internal_ip_not_fetched(tmp_path, monkeypatch):
    # A subdomain that resolves into a private/metadata range is never fetched
    # (structural SSRF backstop, security-sentinel F1/F4) -> NC, no HTTP call.
    net = _install(monkeypatch, lambda u: (200, "DEPLOYMENT_NOT_FOUND"))
    monkeypatch.setattr(probe.socket, "getaddrinfo",
                        _fake_getaddrinfo("169.254.169.254"))
    verdict, _ = probe.probe_cloud_subdomain("evil.vercel.app", "vercel.app",
                                             _ctx(tmp_path), fingerprints=_FPS)
    assert verdict == "NC"
    assert net.calls == []  # no HTTP fetch to the internal address


def test_cloud_fingerprint_vercel_is_cc(tmp_path, monkeypatch):
    _install(monkeypatch, lambda u: (200, "<h1>DEPLOYMENT_NOT_FOUND</h1>"))
    verdict, extra = probe.probe_cloud_subdomain("gone.vercel.app", "vercel.app",
                                                 _ctx(tmp_path), fingerprints=_FPS)
    assert verdict == "CC" and extra.get("reason") == "fingerprint"


def test_cloud_non_strict_fingerprint_is_lo(tmp_path, monkeypatch):
    # pages.dev 'project not found' is a NON-strict entry now (generic phrase
    # that collides with live apps) -> must never fire CC on a resolving host.
    _install(monkeypatch, lambda u: (200, "project not found"))
    verdict, _ = probe.probe_cloud_subdomain("x.pages.dev", "pages.dev",
                                             _ctx(tmp_path), fingerprints=_FPS)
    assert verdict == "LO"


def test_cloud_resolving_404_no_fingerprint_is_lo(tmp_path, monkeypatch):
    # Resolving host + bare 404 + no strict fingerprint -> LO (silent), NEVER a
    # false CRITICAL (error-soundness F2). netlify has no fingerprint at all.
    _install(monkeypatch, lambda u: (404, "Page not found"))
    verdict, _ = probe.probe_cloud_subdomain("app.netlify.app", "netlify.app",
                                             _ctx(tmp_path), fingerprints=_FPS)
    assert verdict == "LO"


def test_cloud_fingerprint_on_404_body_is_cc(tmp_path, monkeypatch):
    # A strict provider token present in a 404 error body still fires CC — the
    # body must be captured on the non-200 path (error-soundness F2 fix).
    _install(monkeypatch, lambda u: (404, "<h1>DEPLOYMENT_NOT_FOUND</h1>"))
    verdict, extra = probe.probe_cloud_subdomain("gone.vercel.app", "vercel.app",
                                                 _ctx(tmp_path), fingerprints=_FPS)
    assert verdict == "CC" and extra.get("reason") == "fingerprint"


def test_cloud_generic_netlify_is_lo(tmp_path, monkeypatch):
    # netlify.app is deliberately NOT in the fingerprint map -> generic 404 copy
    # is never trusted -> LO (spec §4 "do not guess").
    _install(monkeypatch, lambda u: (200, "Page not found - back to home"))
    verdict, _ = probe.probe_cloud_subdomain("app.netlify.app", "netlify.app",
                                             _ctx(tmp_path), fingerprints=_FPS)
    assert verdict == "LO"


# --- negative / LO verdicts --------------------------------------------------

def test_all_types_200_are_lo(tmp_path, monkeypatch):
    _install(monkeypatch, lambda u: (200, '{"login":"x","public_repos":50}'))
    assert probe.probe_github_user("torvalds", _ctx(tmp_path))[0] == "LO"
    assert probe.probe_npm("lodash", _ctx(tmp_path))[0] == "LO"
    assert probe.probe_pypi("requests", _ctx(tmp_path))[0] == "LO"
    assert probe.probe_domain_rdap("python.org", _ctx(tmp_path))[0] == "LO"


@pytest.mark.parametrize("code", [403, 429, 500, 502, 418])
def test_error_codes_are_nc_no_raise(tmp_path, monkeypatch, code):
    _install(monkeypatch, lambda u: (code, ""))
    # None of these may raise; all degrade to NC.
    assert probe.probe_github_user("someone", _ctx(tmp_path))[0] == "NC"
    assert probe.probe_npm("pkg", _ctx(tmp_path))[0] == "NC"


@pytest.mark.parametrize("exc", [
    urllib.error.URLError("boom"),
    socket.timeout("slow"),
    TimeoutError("slow"),
    OSError("io"),
])
def test_network_exceptions_are_nc_no_raise(tmp_path, monkeypatch, exc):
    _install(monkeypatch, lambda u: exc)
    assert probe.probe_github_user("someone", _ctx(tmp_path))[0] == "NC"
    assert probe.probe_domain_rdap("example.com", _ctx(tmp_path))[0] == "NC"


def test_rdap_past_expiration_sets_flag(tmp_path, monkeypatch):
    body = '{"events":[{"eventAction":"expiration","eventDate":"2000-01-01T00:00:00Z"}]}'
    _install(monkeypatch, lambda u: (200, body))
    verdict, extra = probe.probe_domain_rdap("lapsing.com", _ctx(tmp_path))
    assert verdict == "LO" and extra and extra.get("imminent_expiry") is True


# --- offline: cheapest path, zero sockets ------------------------------------

def test_offline_all_probes_nc_zero_network(tmp_path, monkeypatch):
    net = _install(monkeypatch, lambda u: (404, ""))

    def _boom(*a, **k):
        raise AssertionError("DNS must not be resolved offline")

    monkeypatch.setattr(probe.socket, "getaddrinfo", _boom)
    ctx = _ctx(tmp_path, offline=True)
    assert probe.probe_github_user("x", ctx)[0] == "NC"
    assert probe.probe_github_repo("x", "y", ctx)[0] == "NC"
    assert probe.probe_npm("x", ctx)[0] == "NC"
    assert probe.probe_pypi("x", ctx)[0] == "NC"
    assert probe.probe_domain_rdap("x.com", ctx)[0] == "NC"
    assert probe.probe_cloud_subdomain("a.vercel.app", "vercel.app", ctx,
                                       fingerprints=_FPS)[0] == "NC"
    assert net.calls == []  # zero urlopen calls


# --- budget / ceiling / deadline (loop-safety) -------------------------------

def test_github_budget_exhausted_no_urlopen(tmp_path, monkeypatch):
    net = _install(monkeypatch, lambda u: (404, ""))
    ctx = _ctx(tmp_path)
    ctx.budget = probe._ProbeBudget(0, 50)  # GH cap exhausted
    verdict, _ = probe.probe_github_user("x", ctx)
    assert verdict == "NC"
    assert net.calls == []  # never issued a request


def test_total_ceiling_caps_probes(tmp_path, monkeypatch):
    net = _install(monkeypatch, lambda u: (200, "{}"))
    ctx = _ctx(tmp_path)
    ctx.budget = probe._ProbeBudget(100, 50)  # generous GH, total ceiling 50
    attempted = 0
    for i in range(60):
        probe.probe_npm(f"pkg-{i}", ctx)
        attempted += 1
    assert len(net.calls) <= 50
    assert attempted == 60  # all called, but ceiling capped real requests


def test_global_deadline_stops_probes(tmp_path, monkeypatch):
    net = _install(monkeypatch, lambda u: (200, "{}"))
    monkeypatch.setattr(probe, "NETWORK_DEADLINE_SEC", 0.0)
    ctx = _ctx(tmp_path)  # deadline already expired at construction
    assert probe.probe_github_user("x", ctx)[0] == "NC"
    assert probe.probe_npm("y", ctx)[0] == "NC"
    assert net.calls == []


# --- circuit breaker + no-retry ----------------------------------------------

def test_circuit_breaker_trips_on_429(tmp_path, monkeypatch):
    net = _install(monkeypatch, lambda u: (429, ""))
    ctx = _ctx(tmp_path)
    assert probe.probe_github_user("owner1", ctx)[0] == "NC"  # trips breaker
    # A DIFFERENT owner on the SAME host must not touch the network.
    calls_before = len(net.calls)
    assert probe.probe_github_user("owner2", ctx)[0] == "NC"
    assert len(net.calls) == calls_before  # zero further api.github.com calls


def test_circuit_breaker_is_per_host(tmp_path, monkeypatch):
    net = _install(monkeypatch,
                   lambda u: (429, "") if "github" in u else (404, ""))
    ctx = _ctx(tmp_path)
    assert probe.probe_github_user("owner1", ctx)[0] == "NC"  # GH breaker trips
    # npm host is unaffected -> still probes and returns CC on 404.
    assert probe.probe_npm("phantom", ctx)[0] == "CC"


def test_no_retry_single_attempt(tmp_path, monkeypatch):
    net = _install(monkeypatch, lambda u: (429, ""))
    ctx = _ctx(tmp_path)
    probe.probe_github_user("owner1", ctx)
    # Exactly one urlopen for that owner; the breaker prevents OTHERS, and there
    # is no retry of the original anchor.
    assert net.calls.count("https://api.github.com/users/owner1") == 1


# --- 24h atomic result cache -------------------------------------------------

def test_cache_hit_avoids_network(tmp_path, monkeypatch):
    net = _install(monkeypatch, lambda u: (404, ""))
    ctx = _ctx(tmp_path)
    # Pre-populate a fresh LO verdict for the exact key.
    ctx.cache_put("gh_user::torvalds", "LO", {"public_repos": 99})
    net.calls.clear()
    verdict, meta = probe.probe_github_user("torvalds", ctx)
    assert verdict == "LO"
    assert net.calls == []  # served from cache, zero network


def test_cache_miss_expired_reprobes(tmp_path, monkeypatch):
    net = _install(monkeypatch, lambda u: (200, "{}"))
    ctx = _ctx(tmp_path)
    # Write a stale (>24h) entry by hand.
    import time
    path = ctx._cache_path("npm::lodash")
    vuln_feed._atomic_write(path, {"_cached_at": time.time() - 90000,
                                   "verdict": "CC", "extra": {}})
    verdict, _ = probe.probe_npm("lodash", ctx)
    assert verdict == "LO"  # re-probed, not the stale CC
    assert len(net.calls) == 1


def test_malformed_cache_tolerated(tmp_path, monkeypatch):
    net = _install(monkeypatch, lambda u: (404, ""))
    ctx = _ctx(tmp_path)
    path = ctx._cache_path("npm::brokenpkg")
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("{ this is not valid json")
    # Must fall through to a normal probe, no exception.
    verdict, _ = probe.probe_npm("brokenpkg", ctx)
    assert verdict == "CC"


def test_cache_write_uses_atomic_replace(tmp_path, monkeypatch):
    # Simulate two racing writes for the same key: both complete, final file is
    # valid JSON (never torn) — os.replace is the mechanism (via _atomic_write).
    import os
    import json as _json
    _install(monkeypatch, lambda u: (200, "{}"))
    ctx = _ctx(tmp_path)
    ctx.cache_put("npm::race", "LO", {"n": 1})
    ctx.cache_put("npm::race", "LO", {"n": 2})
    path = ctx._cache_path("npm::race")
    with open(path) as f:
        data = _json.load(f)  # parses cleanly => not torn
    assert data["verdict"] == "LO"


def test_nc_is_never_cached(tmp_path, monkeypatch):
    _install(monkeypatch, lambda u: (403, ""))
    ctx = _ctx(tmp_path)
    probe.probe_npm("throttled", ctx)
    import os
    path = ctx._cache_path("npm::throttled")
    assert not os.path.exists(path)  # transient NC not persisted


# --- assert the suite itself never hit real network --------------------------

def test_no_real_network_sentinel(tmp_path, monkeypatch):
    # If any probe reached real urlopen, that means the monkeypatch missed. Prove
    # the chokepoint is vuln_feed._https_fetch -> urllib.request.urlopen (routed
    # through the no-redirect opener, seamed via _DirectOpener in tests). A fresh
    # tmp cache dir guarantees a real network attempt (no cache short-circuit).
    hit = {"n": 0}
    monkeypatch.setattr(probe, "_no_redirect_opener", lambda: probe._DirectOpener())
    monkeypatch.setattr(vuln_feed.urllib.request, "urlopen",
                        lambda *a, **k: hit.__setitem__("n", hit["n"] + 1) or (_ for _ in ()).throw(urllib.error.URLError("blocked")))
    ctx = probe.ProbeContext(offline=False, cache_dir=str(tmp_path))
    probe.probe_npm("anything", ctx)
    assert hit["n"] == 1  # went through the mocked chokepoint, not the real net


# --- redirect / SSRF hardening -----------------------------------------------

def test_no_redirect_handler_refuses_all_redirects():
    # The production no-redirect handler never follows a 3xx (returns None so
    # urllib raises the redirect as its own HTTPError instead of auto-fetching).
    h = probe._NoRedirectHandler()
    assert h.redirect_request(None, None, 302, "Found", {},
                              "http://169.254.169.254/latest/meta-data/") is None


def test_bounded_redirect_rejects_http_scheme():
    # RDAP's bounded opener refuses a downgrade to http:// (and only follows
    # https hops to non-internal hosts).
    h = probe._BoundedRedirectHandler()
    assert h.redirect_request(None, None, 302, "Found", {},
                              "http://rdap.verisign.com/x") is None


def test_3xx_not_followed_single_call_breaker_intact(tmp_path, monkeypatch):
    # A 3xx from an anchor host is treated as COULDN'T-CHECK, NOT auto-followed:
    # exactly one call, no extra request to the Location, breaker untouched.
    net = _install(monkeypatch, lambda u: (
        302, "", "http://169.254.169.254/latest/meta-data/"))
    ctx = _ctx(tmp_path)
    verdict, _ = probe.probe_github_user("someowner", ctx)
    assert verdict == "NC"
    assert len(net.calls) == 1  # no follow to the redirect target
    assert not ctx.breaker.is_tripped(probe._HOST_GITHUB)


# --- name normalization (no phantom on brand-cased / separator-variant) -------

def test_npm_brand_case_resolves_live_not_phantom(tmp_path, monkeypatch):
    # 'React' must probe the canonical 'react' (live) -> LO, never a phantom CC.
    def router(u):
        return (200, "{}") if u.endswith("/react") else (404, "")
    net = _install(monkeypatch, router)
    assert probe.probe_npm("React", _ctx(tmp_path))[0] == "LO"


def test_pypi_pep503_normalization_resolves_live(tmp_path, monkeypatch):
    # 'My_Package' must probe canonical 'my-package' -> LO, never a phantom CC.
    def router(u):
        return (200, "{}") if "/my-package/" in u else (404, "")
    _install(monkeypatch, router)
    assert probe.probe_pypi("My_Package", _ctx(tmp_path))[0] == "LO"


def test_github_token_does_not_inflate_budget(tmp_path, monkeypatch):
    # A GITHUB_TOKEN must NOT raise the call cap (it is never attached to a
    # request), so the budget stays at the unauthenticated ceiling.
    _install(monkeypatch, lambda u: (200, "{}"))
    ctx = _ctx(tmp_path, github_token="ghp_dummy")
    assert ctx.budget.gh_remaining == probe.GITHUB_CALL_CAP


def test_cache_symlinked_dir_not_written(tmp_path, monkeypatch):
    # If the cache dir is a symlink, no verdict is written through it
    # (cache-poisoning backstop, security-sentinel F6).
    import os
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    os.symlink(str(real), str(link))
    _install(monkeypatch, lambda u: (404, ""))
    ctx = probe.ProbeContext(offline=False, cache_dir=str(link))
    ctx.cache_put("npm::x", "CC", None)
    assert os.listdir(str(real)) == []  # nothing written through the symlink
