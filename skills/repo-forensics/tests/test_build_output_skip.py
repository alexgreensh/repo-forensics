"""Generated build output (`.next`, `.nuxt`, ...) and `.gitignore` trust.

Default: everything is scanned. A repository under audit ships both its
folders and its `.gitignore`, so repository-supplied ignore rules never
narrow coverage on their own. The gitignore-driven skip exists only as an
operator opt-in (FORENSICS_SKIP_BUILD_OUTPUT) for scanning your own
projects, and every folder excluded under that opt-in is disclosed as a
finding (build_output_skip_findings).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import forensics_core as core  # noqa: E402

ENV = core.BUILD_OUTPUT_SKIP_ENV_VAR


@pytest.fixture
def skip_on(monkeypatch):
    monkeypatch.setenv(ENV, '1')
    return ENV


@pytest.fixture
def skip_off(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    return ENV


def _tree(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')


def _walked(root, walker=core.walk_repo):
    return {rel.replace(os.sep, '/') for _, rel in walker(str(root))}


# --- Default mode: repository-supplied .gitignore never narrows coverage ---

def test_default_scans_gitignored_build_output(tmp_path, skip_off):
    _tree(tmp_path, {'.gitignore': '/.next/\nnode_modules\n', 'app/page.js': 'x',
                     '.next/dev/chunk.js': 'y'})
    walked = _walked(tmp_path)
    assert 'app/page.js' in walked
    assert '.next/dev/chunk.js' in walked


def test_default_scans_gitignored_payload_in_build_output(tmp_path, skip_off):
    """The evasion this file exists to pin: a hostile repo ships a payload in
    a build-output-named folder plus a .gitignore that excludes it. The
    payload must reach the scanners."""
    _tree(tmp_path, {'.gitignore': '/.next/\n', 'src/control.js': 'x',
                     '.next/server/evil.js': 'y'})
    walked = _walked(tmp_path)
    assert '.next/server/evil.js' in walked
    assert 'src/control.js' in walked


def test_default_aux_walker_scans_gitignored_build_output(tmp_path, skip_off):
    _tree(tmp_path, {'.gitignore': '/.next/\n', '.next/dev/big.bin': 'y', 'keep.js': 'x'})
    walked = _walked(tmp_path, core.walk_aux)
    assert 'keep.js' in walked
    assert '.next/dev/big.bin' in walked


def test_default_scans_gitignored_tsbuildinfo(tmp_path, skip_off):
    _tree(tmp_path, {'.gitignore': '*.tsbuildinfo\n', 'tsconfig.tsbuildinfo': '{}', 'src/a.ts': 'x'})
    walked = _walked(tmp_path)
    assert 'tsconfig.tsbuildinfo' in walked
    assert 'src/a.ts' in walked


def test_default_no_disclosure_findings(tmp_path, skip_off):
    _tree(tmp_path, {'.gitignore': '/.next/\n', '.next/a.js': 'y'})
    assert core.build_output_skip_findings(str(tmp_path)) == []


# --- Opt-in mode: FORENSICS_SKIP_BUILD_OUTPUT restores the 2.14.17 skip ---

def test_optin_gitignored_next_build_is_skipped(tmp_path, skip_on):
    _tree(tmp_path, {'.gitignore': '/.next/\nnode_modules\n', 'app/page.js': 'x', '.next/dev/chunk.js': 'y'})
    walked = _walked(tmp_path)
    assert 'app/page.js' in walked
    assert not any(p.startswith('.next/') for p in walked)


def test_optin_committed_build_folder_is_scanned(tmp_path, skip_on):
    _tree(tmp_path, {'app/page.js': 'x', '.next/server/payload.js': 'y'})
    assert '.next/server/payload.js' in _walked(tmp_path)


def test_optin_reincluded_build_folder_is_scanned(tmp_path, skip_on):
    _tree(tmp_path, {'.gitignore': '.next\n!.next\n', '.next/a.js': 'y'})
    assert '.next/a.js' in _walked(tmp_path)


def test_optin_nested_app_gitignore_covers_its_own_build(tmp_path, skip_on):
    _tree(tmp_path, {'apps/web/.gitignore': '/.next/\n', 'apps/web/.next/dev/c.js': 'y',
                     'apps/web/app/page.js': 'x'})
    walked = _walked(tmp_path)
    assert 'apps/web/app/page.js' in walked
    assert not any('/.next/' in p for p in walked)


def test_optin_anchored_root_pattern_does_not_reach_subfolders(tmp_path, skip_on):
    _tree(tmp_path, {'.gitignore': '/.next/\n', 'apps/web/.next/c.js': 'y'})
    assert 'apps/web/.next/c.js' in _walked(tmp_path)


def test_optin_unanchored_pattern_matches_any_depth(tmp_path, skip_on):
    _tree(tmp_path, {'.gitignore': '.nuxt/\n**/.svelte-kit\n', 'a/.nuxt/x.js': 'y',
                     'b/c/.svelte-kit/z.js': 'y', 'a/real.js': 'x'})
    assert _walked(tmp_path) == {'.gitignore', 'a/real.js'}


def test_optin_only_known_build_folder_names_are_eligible(tmp_path, skip_on):
    _tree(tmp_path, {'.gitignore': 'payload/\n.cache/\n', 'payload/run.js': 'y', '.cache/x.js': 'y'})
    assert {'payload/run.js', '.cache/x.js'} <= _walked(tmp_path)


def test_optin_aux_walker_matches(tmp_path, skip_on):
    _tree(tmp_path, {'.gitignore': '/.next/\n', '.next/dev/big.bin': 'y', 'keep.js': 'x'})
    walked = _walked(tmp_path, core.walk_aux)
    assert 'keep.js' in walked and not any(p.startswith('.next/') for p in walked)


def test_optin_symlinked_gitignore_is_not_trusted(tmp_path, skip_on):
    (tmp_path / 'outside').mkdir()
    (tmp_path / 'outside' / 'ig').write_text('/.next/\n', encoding='utf-8')
    repo = tmp_path / 'repo'
    _tree(repo, {'.next/a.js': 'y'})
    try:
        os.symlink(tmp_path / 'outside' / 'ig', repo / '.gitignore')
    except (OSError, NotImplementedError):
        return
    assert '.next/a.js' in _walked(repo)


def test_optin_gitignored_typescript_build_cache_is_skipped(tmp_path, skip_on):
    _tree(tmp_path, {'.gitignore': '*.tsbuildinfo\n', 'tsconfig.tsbuildinfo': '{}', 'src/a.ts': 'x'})
    assert _walked(tmp_path) == {'.gitignore', 'src/a.ts'}


def test_optin_glob_patterns_match_build_folders(tmp_path, skip_on):
    _tree(tmp_path, {'.gitignore': '.next*\n', '.next/a.js': 'y', 'next.js': 'x'})
    assert _walked(tmp_path) == {'.gitignore', 'next.js'}


# --- Env var parsing ---

@pytest.mark.parametrize('value', ['1', 'true', 'TRUE', 'yes', 'on', ' On '])
def test_skip_enabled_truthy(monkeypatch, value):
    monkeypatch.setenv(ENV, value)
    assert core.build_output_skip_enabled() is True


@pytest.mark.parametrize('value', ['0', 'false', 'no', 'off', '', '2', 'enabled'])
def test_skip_enabled_falsy(monkeypatch, value):
    monkeypatch.setenv(ENV, value)
    assert core.build_output_skip_enabled() is False


def test_skip_enabled_unset(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    assert core.build_output_skip_enabled() is False


# --- Disclosure: an active skip is always named in the report ---

def test_disclosure_names_skipped_folder_and_count(tmp_path, skip_on):
    _tree(tmp_path, {'.gitignore': '/.next/\n', 'app/page.js': 'x',
                     '.next/a.js': 'y', '.next/b/c.js': 'z'})
    findings = core.build_output_skip_findings(str(tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == 'low'
    assert f.scanner == 'meta'
    assert f.category == 'build-output-excluded'
    assert f.file == '.next'
    assert '2' in f.description  # two files under .next
    assert core.BUILD_OUTPUT_SKIP_ENV_VAR in f.description


def test_disclosure_covers_nested_apps(tmp_path, skip_on):
    _tree(tmp_path, {'apps/web/.gitignore': '/.next/\n', 'apps/web/.next/x.js': 'y',
                     'apps/api/.gitignore': '/.nuxt/\n', 'apps/api/.nuxt/z.js': 'w'})
    files = {f.file for f in core.build_output_skip_findings(str(tmp_path))}
    assert files == {'apps/web/.next', 'apps/api/.nuxt'}


def test_disclosure_empty_when_nothing_skipped(tmp_path, skip_on):
    _tree(tmp_path, {'.gitignore': 'node_modules\n', 'src/a.js': 'x'})
    assert core.build_output_skip_findings(str(tmp_path)) == []


def test_disclosure_not_emitted_in_default_mode(tmp_path, skip_off):
    _tree(tmp_path, {'.gitignore': '/.next/\n', '.next/a.js': 'y'})
    assert core.build_output_skip_findings(str(tmp_path)) == []


def test_disclosure_does_not_descend_into_skipped_folder(tmp_path, skip_on):
    """A build folder nested inside a skipped build folder is one skip."""
    _tree(tmp_path, {'.gitignore': '/.next/\n', '.next/cache/.turbo/x.js': 'y'})
    findings = core.build_output_skip_findings(str(tmp_path))
    assert [f.file for f in findings] == ['.next']


# --- Aggregator wiring: the report can never claim COMPLETE over an exclusion ---

def _write(path, content):
    import json as _json
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if isinstance(content, str) else _json.dumps(content), encoding='utf-8')


def _report(tmp_path, monkeypatch, repo_files, scanner_out):
    import aggregate_json as module
    repo = tmp_path / 'repo'
    repo.mkdir()
    _tree(repo, repo_files)
    _write(tmp_path / 'secrets.out', scanner_out)
    _write(tmp_path / 'secrets.err', '')
    _write(tmp_path / 'secrets.exit', '0')
    return module.build_report(str(tmp_path), str(repo), 'false')


def test_aggregate_optin_discloses_and_marks_incomplete(tmp_path, skip_on):
    report = _report(tmp_path, skip_on,
                     {'.gitignore': '/.next/\n', '.next/a.js': 'y', 'src/ok.js': 'x'}, [])
    assert report['coverage_status']['overall'] == 'INCOMPLETE'
    assert report['coverage_status']['per_scanner']['meta']['status'] == 'INCOMPLETE'
    assert any(f['category'] == 'build-output-excluded' for f in report['findings'])
    # LOW finding, informational only: the exit-code contract is untouched.
    assert report['exit_code'] == 0


def test_aggregate_default_mode_has_no_exclusion_gap(tmp_path, skip_off):
    report = _report(tmp_path, skip_off,
                     {'.gitignore': '/.next/\n', '.next/a.js': 'y', 'src/ok.js': 'x'}, [])
    assert report['coverage_status']['overall'] == 'COMPLETE'
    assert not any(f['category'] == 'build-output-excluded' for f in report['findings'])
    assert report['exit_code'] == 0


def test_disclosure_overflow_is_itself_disclosed(tmp_path, skip_on):
    files = {}
    for i in range(27):
        files[f'apps/app{i:02d}/.gitignore'] = '/.next/\n'
        files[f'apps/app{i:02d}/.next/x.js'] = 'y'
    _tree(tmp_path, files)
    findings = core.build_output_skip_findings(str(tmp_path))
    titles = [f.title for f in findings]
    assert 'Build output exclusions truncated' in titles
    assert len([f for f in findings if f.title == 'Build output excluded from scan']) == 25
    summary = [f for f in findings if f.title == 'Build output exclusions truncated'][0]
    assert '2' in summary.description  # 27 total - 25 listed


def test_meta_findings_render_in_text_report(tmp_path, skip_on):
    import aggregate_json as module
    report = _report(tmp_path, skip_on,
                     {'.gitignore': '/.next/\n', '.next/a.js': 'y', 'src/ok.js': 'x'}, [])
    text = module.format_report_as_text(report)
    assert '--- [meta] ---' in text
    assert 'Build output excluded from scan' in text
    assert 'COVERAGE: INCOMPLETE' in text
