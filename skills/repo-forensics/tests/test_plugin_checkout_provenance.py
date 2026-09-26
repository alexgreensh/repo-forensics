import json, os, subprocess, sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import scan_git_forensics as gitf

def git(repo,*args):
    return subprocess.run(['git',*args],cwd=repo,text=True,capture_output=True,check=True).stdout.strip()

def repo(tmp_path, plugin=True):
    p=tmp_path/'repo';p.mkdir();git(p,'init','-q');git(p,'config','user.name','Fixture');git(p,'config','user.email','f@example.test')
    if plugin:
        (p/'.claude-plugin').mkdir();(p/'.claude-plugin/plugin.json').write_text('{"name":"x"}')
    (p/'plugin.js').write_text('export const ok=true;\n');git(p,'add','.');git(p,'commit','-qm','reviewed');return p,git(p,'rev-parse','HEAD')

def titles(findings): return {f.title for f in findings}

def test_sha_shaped_branch_collision_in_plugin_is_critical(tmp_path):
    p,pin=repo(tmp_path);(p/'plugin.js').write_text('export const changed=true;\n');git(p,'commit','-am','changed','-q');git(p,'branch',pin);git(p,'checkout','-q',pin)
    fs=gitf.scan_plugin_checkout_provenance(str(p)); assert 'Agent Plugin Ambiguous Git Ref' in titles(fs); assert 'Agent Plugin Checked Out on Ambiguous Ref' in titles(fs); assert all(f.severity=='critical' for f in fs)

def test_fetch_head_branch_in_plugin_is_critical(tmp_path):
    p,_=repo(tmp_path);git(p,'branch','-M','FETCH_HEAD');fs=gitf.scan_plugin_checkout_provenance(str(p));assert 'Agent Plugin Ambiguous Git Ref' in titles(fs);assert 'Agent Plugin Checked Out on Ambiguous Ref' in titles(fs)

def test_odd_branches_in_generic_repo_are_scoped_out(tmp_path):
    p,pin=repo(tmp_path,plugin=False);git(p,'branch',pin);git(p,'branch','FETCH_HEAD');assert gitf.scan_plugin_checkout_provenance(str(p))==[]

def test_standalone_skill_and_agent_config_are_not_plugin_checkouts(tmp_path):
    p,pin=repo(tmp_path,plugin=False)
    (p/'SKILL.md').write_text('# A standalone skill\n')
    (p/'.agents').mkdir()
    git(p,'branch',pin)
    assert gitf.scan_plugin_checkout_provenance(str(p)) == []
    assert gitf.scan_plugin_installers(str(p)) == []

def test_normal_plugin_branch_without_pin_metadata_is_clean(tmp_path):
    p,_=repo(tmp_path);assert gitf.scan_plugin_checkout_provenance(str(p))==[]

def test_plugin_without_git_reports_provenance_gap(tmp_path):
    p=tmp_path/'plugin';p.mkdir();(p/'.claude-plugin').mkdir()
    (p/'.claude-plugin/plugin.json').write_text('{"name":"x"}')
    assert 'Agent Plugin Git Provenance Unavailable' in titles(gitf.scan_plugin_checkout_provenance(str(p)))

def test_recorded_pin_mismatch_is_critical(tmp_path):
    p,pin=repo(tmp_path);(p/'.claude-plugin/plugin.json').write_text(json.dumps({'name':'x','commitSha':pin}));git(p,'add','.');git(p,'commit','-qm','metadata after pin')
    fs=gitf.scan_plugin_checkout_provenance(str(p));assert 'Agent Plugin Checkout Does Not Match Recorded Pin' in titles(fs)

def test_matching_pin_requires_detached_head(tmp_path):
    p,pin=repo(tmp_path);(p/'.claude-plugin/plugin.json').write_text(json.dumps({'name':'x','commit':pin}))
    fs=gitf.scan_plugin_checkout_provenance(str(p));assert 'SHA-Pinned Agent Plugin Is Not Detached' in titles(fs)
    git(p,'checkout','--detach','-q',pin);fs=gitf.scan_plugin_checkout_provenance(str(p));assert 'SHA-Pinned Agent Plugin Is Not Detached' not in titles(fs);assert 'Agent Plugin Checkout Does Not Match Recorded Pin' not in titles(fs)

def test_metadata_without_pin_reports_coverage_gap(tmp_path):
    p,_=repo(tmp_path);(p/'marketplace.json').write_text(json.dumps({'plugins':[{'name':'x','source':'https://example.test/x'}]}));fs=gitf.scan_plugin_checkout_provenance(str(p));assert 'Agent Plugin Provenance Pin Unavailable' in titles(fs)

def write_installer(tmp_path,text,plugin=True):
    p=tmp_path/'x';p.mkdir();
    if plugin:(p/'.claude-plugin').mkdir()
    (p/'install.sh').write_text(text);return p

def test_unverified_sha_variable_checkout_is_high(tmp_path):
    p=write_installer(tmp_path,'git clone "$repo" plugin\ncd plugin\ngit checkout "$pinned_sha"\n');fs=gitf.scan_plugin_installers(str(p));assert 'Agent Plugin Installer Does Not Verify Resolved Commit' in titles(fs)

def test_fetch_head_sequence_is_critical(tmp_path):
    p=write_installer(tmp_path,'git fetch origin "$pinned_sha"\ngit checkout FETCH_HEAD\n');fs=gitf.scan_plugin_installers(str(p));assert 'Agent Plugin Installer Trusts Ambiguous FETCH_HEAD' in titles(fs)

def test_verified_checkout_is_clean(tmp_path):
    p=write_installer(tmp_path,'git checkout --detach "$pinned_sha"\nactual=$(git rev-parse HEAD)\nif [ "$actual" != "$pinned_sha" ]; then exit 1; fi\n');assert gitf.scan_plugin_installers(str(p))==[]

def test_installer_patterns_in_generic_repo_are_scoped_out(tmp_path):
    p=write_installer(tmp_path,'git checkout "$pinned_sha"\n',plugin=False);assert gitf.scan_plugin_installers(str(p))==[]

@pytest.mark.parametrize('name,text', [
 ('install.js', 'execFileSync("git", ["checkout", pinnedSha]);\n'),
 ('install.ts', 'await execa("git", ["checkout", commitSha]);\n'),
 ('install.py', 'subprocess.run(["git", "checkout", revision], check=True)\n'),
])
def test_unverified_checkout_across_installer_languages(tmp_path,name,text):
    p=tmp_path/'x';p.mkdir();(p/'.claude-plugin').mkdir();(p/name).write_text(text)
    assert 'Agent Plugin Installer Does Not Verify Resolved Commit' in titles(gitf.scan_plugin_installers(str(p)))

@pytest.mark.parametrize('name,text', [
 ('install.js', 'execFileSync("git", ["checkout", "--detach", pinnedSha]);\nconst actual=execFileSync("git", ["rev-parse", "HEAD"]);\nif (actual !== pinnedSha) { throw new Error("mismatch"); }\n'),
 ('install.py', 'subprocess.run(["git", "checkout", "--detach", commit_sha], check=True)\nactual=subprocess.check_output(["git", "rev-parse", "HEAD"])\nif actual != commit_sha: raise RuntimeError("mismatch")\n'),
])
def test_verified_checkout_across_installer_languages(tmp_path,name,text):
    p=tmp_path/'x';p.mkdir();(p/'.claude-plugin').mkdir();(p/name).write_text(text)
    assert gitf.scan_plugin_installers(str(p)) == []

def test_main_scans_installer_without_git_history(tmp_path, monkeypatch, capsys):
    p=write_installer(tmp_path,'git checkout "$pinned_sha"\n')
    monkeypatch.setattr(sys,'argv',['scan_git_forensics.py',str(p),'--format','json'])
    gitf.main()
    out=json.loads(capsys.readouterr().out)
    assert any(f['title']=='Agent Plugin Installer Does Not Verify Resolved Commit' for f in out)


def test_arbitrary_40_hex_text_is_not_treated_as_pin(tmp_path):
    p,_=repo(tmp_path);(p/'marketplace.json').write_text(json.dumps({'description':'a'*40,'checksum':'b'*40}))
    fs=gitf.scan_plugin_checkout_provenance(str(p));assert 'Agent Plugin Checkout Does Not Match Recorded Pin' not in titles(fs)

def test_malformed_metadata_does_not_crash_or_invent_pin(tmp_path):
    p,_=repo(tmp_path);(p/'marketplace.json').write_text('{not json')
    fs=gitf.scan_plugin_checkout_provenance(str(p))
    assert 'Agent Plugin Provenance Pin Unavailable' in titles(fs)
    assert 'Agent Plugin Checkout Does Not Match Recorded Pin' not in titles(fs)

def test_huge_metadata_is_bounded(tmp_path):
    p,_=repo(tmp_path);(p/'marketplace.json').write_text(' '*(1024*1024+1))
    assert 'Agent Plugin Provenance Pin Unavailable' in titles(gitf.scan_plugin_checkout_provenance(str(p)))

def test_symlinked_metadata_is_not_read(tmp_path):
    p,_=repo(tmp_path)
    outside=tmp_path/'outside.json'
    outside.write_text(json.dumps({'plugins':[{'name':'x','commit':'a'*40}]}))
    try:
        (p/'marketplace.json').symlink_to(outside)
    except OSError:
        pytest.skip('symlink creation unavailable')
    fs=gitf.scan_plugin_checkout_provenance(str(p))
    assert 'Agent Plugin Provenance Pin Unavailable' in titles(fs)
    assert 'Agent Plugin Checkout Does Not Match Recorded Pin' not in titles(fs)

def test_symlinked_plugin_manifest_directory_cannot_read_outside_repo(tmp_path):
    p,_=repo(tmp_path,plugin=False)
    outside=tmp_path/'outside'
    outside.mkdir()
    (outside/'plugin.json').write_text(json.dumps({'name':'x','commit':'a'*40}))
    try:
        (p/'.claude-plugin').symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('directory symlink creation unavailable')
    fs=gitf.scan_plugin_checkout_provenance(str(p))
    assert 'Agent Plugin Checkout Does Not Match Recorded Pin' not in titles(fs)
    assert 'Agent Plugin Provenance Pin Unavailable' in titles(fs)

def test_plugin_walk_limit_reports_gap_without_scanning_unbounded_tree(tmp_path, monkeypatch):
    p,_=repo(tmp_path)
    for index in range(8):
        (p/f'file-{index}.py').write_text('pass\n')
    monkeypatch.setattr(gitf, '_MAX_PLUGIN_WALK_ENTRIES', 5)
    assert 'Agent Plugin Provenance Pin Unavailable' in titles(gitf.scan_plugin_checkout_provenance(str(p)))
    assert 'Agent Plugin Installer Source Not Scanned' in titles(gitf.scan_plugin_installers(str(p)))

def test_deep_metadata_is_a_coverage_gap(tmp_path):
    p,_=repo(tmp_path)
    (p/'marketplace.json').write_text('['*1100+'0'+']'*1100)
    assert 'Agent Plugin Provenance Pin Unavailable' in titles(gitf.scan_plugin_checkout_provenance(str(p)))

def test_oversize_installer_is_a_coverage_gap(tmp_path):
    p,_=repo(tmp_path)
    (p/'install.sh').write_text('x'*(gitf._MAX_PROVENANCE_FILE_BYTES+1))
    fs=gitf.scan_plugin_installers(str(p))
    assert 'Agent Plugin Installer Source Not Scanned' in titles(fs)

def test_lowercase_sha_branch_only_exact_40_hex(tmp_path):
    p,_=repo(tmp_path);git(p,'branch','a'*39);git(p,'branch','g'*40);assert gitf.scan_plugin_checkout_provenance(str(p)) == []

def test_fetch_head_tag_does_not_false_fire_local_branch_rule(tmp_path):
    p,_=repo(tmp_path);git(p,'tag','FETCH_HEAD');assert gitf.scan_plugin_checkout_provenance(str(p)) == []

def test_other_plugins_pin_cannot_mask_this_plugin_mismatch(tmp_path):
    p,_=repo(tmp_path)
    (p/'.claude-plugin/plugin.json').write_text(json.dumps({'name':'target'}))
    head=git(p,'rev-parse','HEAD')
    (p/'plugins.json').write_text(json.dumps({'plugins':[
        {'name':'target','commit':'a'*40},
        {'name':'other','commit':head},
    ]}))
    fs=gitf.scan_plugin_checkout_provenance(str(p))
    assert 'Agent Plugin Checkout Does Not Match Recorded Pin' in titles(fs)

def test_ambiguous_installed_identity_is_coverage_gap_not_acceptance(tmp_path):
    p,_=repo(tmp_path)
    (p/'.claude-plugin/plugin.json').write_text(json.dumps({'name':'one'}))
    (p/'.codex-plugin').mkdir()
    (p/'.codex-plugin/plugin.json').write_text(json.dumps({'name':'two'}))
    head=git(p,'rev-parse','HEAD')
    (p/'plugins.json').write_text(json.dumps({'plugins':[{'name':'one','commit':head}]}))
    fs=gitf.scan_plugin_checkout_provenance(str(p))
    assert 'Agent Plugin Provenance Pin Unavailable' in titles(fs)

def test_duplicate_matching_records_with_conflicting_pins_are_coverage_gap(tmp_path):
    p,_=repo(tmp_path)
    (p/'.claude-plugin/plugin.json').write_text(json.dumps({'name':'target'}))
    (p/'plugins.json').write_text(json.dumps({'plugins':[
        {'name':'target','commit':'a'*40}, {'name':'target','commit':'b'*40}
    ]}))
    fs=gitf.scan_plugin_checkout_provenance(str(p))
    assert 'Agent Plugin Provenance Pin Unavailable' in titles(fs)
    assert 'Agent Plugin Checkout Does Not Match Recorded Pin' not in titles(fs)
