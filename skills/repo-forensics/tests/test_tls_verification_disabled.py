import importlib.util
from pathlib import Path

SCRIPTS = Path(__file__).parents[1] / "scripts"

def load(name):
    spec=importlib.util.spec_from_file_location(name,SCRIPTS/f"{name}.py")
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

sast=load("scan_sast")
skill=load("scan_skill_threats")

def ids(text, ext):
    return {f.rule_id for f in sast.scan_text(text, "fixture"+ext, ext)}

def test_curl_short_bundle_k_any_position_and_long_form():
    for text in ("curl -sk https://x", "curl -ks https://x", "curl -kLs https://x", "curl -sSfk https://x", "curl --insecure https://x"):
        assert "SA-SH-025" in ids(text, ".sh")

def test_wget_long_form_but_not_convert_links_short_k():
    assert "SA-SH-025" in ids("wget --no-check-certificate https://x", ".sh")
    assert "SA-SH-025" not in ids("wget -k https://example.com/page", ".sh")

def test_shell_benign_controls():
    for text in ("curl -s https://x", "curl --key client.pem https://x", "wget https://x"):
        assert "SA-SH-025" not in ids(text, ".sh")

def test_python_known_tls_apis():
    for text in ("requests.get(url, verify=False)", "httpx.post(url, verify = False)", "ssl._create_unverified_context()", "ctx.verify_mode = ssl.CERT_NONE"):
        assert "SA-PY-032" in ids(text, ".py")

def test_python_non_tls_verify_controls_stay_clean():
    for text in ("build_artifact(data, verify=False)", "def parse(value, verify=False): pass", "ctx.check_hostname = False", "requests.get(url, verify=True)"):
        assert "SA-PY-032" not in ids(text, ".py")

def test_node_object_quoted_property_assignment_and_env():
    cases=("new https.Agent({rejectUnauthorized:false})", "const x = {'rejectUnauthorized': false}", "opts.rejectUnauthorized = false", 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"')
    for ext,rid in ((".js","SA-JS-040"),(".ts","SA-TS-020"),(".tsx","SA-TSX-003")):
        for text in cases: assert rid in ids(text,ext)

def test_node_benign_controls():
    for ext,rid in ((".js","SA-JS-040"),(".ts","SA-TS-020"),(".tsx","SA-TSX-003")):
        for text in ("rejectUnauthorized: true", "opts.rejectUnauthorized = true", 'NODE_TLS_REJECT_UNAUTHORIZED = "1"', "authorized = false"):
            assert rid not in ids(text,ext)

def test_skill_prose_catches_insecure_downloads_and_keeps_wget_k_clean(tmp_path):
    bad=tmp_path/'bad.md'; bad.write_text('Install: curl -kLs https://x\nThen wget --no-check-certificate https://x\n')
    good=tmp_path/'good.md'; good.write_text('Mirror a page: wget -k https://example.com/page\n')
    bad_ids={f.rule_id for f in skill.scan_file(str(bad),'bad.md')}
    good_ids={f.rule_id for f in skill.scan_file(str(good),'good.md')}
    assert 'ST-PR-017' in bad_ids
    assert 'ST-PR-017' not in good_ids

def test_python_nested_call_before_verify_false():
    text = "requests.get(url, headers=dict(token='x'), verify=False)"
    assert "SA-PY-032" in ids(text, ".py")

def test_python_multiline_call_verify_false():
    text = '''requests.get(
        url,
        headers={"x": make_header("y")},
        verify=False,
    )'''
    assert "SA-PY-032" in ids(text, ".py")

def test_httpx_nested_and_multiline_verify_false():
    text = '''httpx.post(
        url,
        json=build_payload(item=value()),
        verify = False,
    )'''
    assert "SA-PY-032" in ids(text, ".py")

def test_python_verify_false_must_be_literal_false():
    for text in ("requests.get(url, verify=disabled)", "requests.get(url, verify=0)", "requests.get(url, **opts)"):
        assert "SA-PY-032" not in ids(text, ".py")

def test_python_aliases_not_claimed_without_binding_analysis():
    assert "SA-PY-032" not in ids("r.get(url, verify=False)", ".py")

def test_node_tls_multiline_forms():
    text = '''const agent = new https.Agent({
      rejectUnauthorized:
        false
    });
    opts.rejectUnauthorized =
      false;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED =
      "0";'''
    assert "SA-JS-040" in ids(text, ".js")

def test_node_nested_object_before_tls_option():
    text = '''const opts = {
      headers: { authorization: token() },
      rejectUnauthorized: false,
    };'''
    assert "SA-JS-040" in ids(text, ".js")
