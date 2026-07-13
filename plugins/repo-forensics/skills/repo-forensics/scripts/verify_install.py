#!/usr/bin/env python3
"""
verify_install.py - Skill Installation Integrity Verifier (v2)
Verifies that repo-forensics itself hasn't been tampered with.

Modes:
  --generate    Create checksums.json for all skill files (run at release time)
  --verify      Check current files against checksums.json (run at install/audit time)

Uses SHA256 checksums. Ed25519 signatures can be added when a signing key
is established for marketplace distribution.

Created by Alex Greenshpun
"""

import os
import subprocess
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

sha256_file = core.sha256_file
SOURCE_ONLY_MANIFEST_FILES = {".agents/plugins/marketplace.json"}


def get_skill_root():
    """Get the root directory of the repo-forensics skill."""
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(scripts_dir)  # skills/repo-forensics/


def get_repo_root(skill_root):
    """Get the repository root (two levels up from skill_root).

    skill_root is skills/repo-forensics/, so repo root is the parent of skills/.
    Used by symlink integrity tracking — top-level repo symlinks (like the
    backward-compat skill -> skills/repo-forensics symlink added in v2.4.1)
    live outside skill_root and are invisible to get_tracked_files, so they
    need a separate check to prevent tarball-poisoning attacks that replace
    the symlink target.
    """
    return os.path.dirname(os.path.dirname(skill_root))


def is_plugin_cache_layout(repo_root):
    """Return True when repo_root is an installed agent plugin cache payload."""
    parts = os.path.realpath(repo_root).split(os.sep)
    return any(
        parts[i] == "plugins" and i + 1 < len(parts) and parts[i + 1] == "cache"
        for i in range(len(parts))
    )


def get_tracked_hook_files(repo_root):
    """Get load-bearing hook scripts at the repo-root hooks/ directory.

    These files live outside skill_root and are invisible to
    get_tracked_files, but they are invoked by the plugin's hooks.json at
    runtime. If an attacker tampers with hooks/first-run-nudge.sh or
    hooks/run_auto_scan.sh, the checksum registry (scoped to skill_root)
    would not detect the tamper.

    This function enumerates files in the repo-root hooks/ directory so
    their content hashes can be included in checksums.json under a
    separate repo_hooks field. Same rationale as get_tracked_symlinks:
    every load-bearing file invoked by the plugin manifest must be in
    the integrity registry, even if it lives outside skill_root.
    """
    hooks_dir = os.path.join(repo_root, "hooks")
    try:
        if not os.path.isdir(hooks_dir):
            return []
        entries = sorted(os.listdir(hooks_dir))
    except OSError:
        return []

    tracked = []
    skip_files = {'.DS_Store'}
    for entry in entries:
        full_path = os.path.join(hooks_dir, entry)
        if not os.path.isfile(full_path):
            continue
        if os.path.islink(full_path):
            continue
        if entry in skip_files:
            continue
        tracked.append(f"hooks/{entry}")
    return tracked


def get_tracked_runtime_manifest_files(repo_root):
    """Get load-bearing plugin manifest files under agent plugin dirs.

    Claude, Codex, and cross-agent marketplace manifests live outside
    skill_root but determine what hooks and skills the agent loads. Extending
    the integrity registry to cover them closes the same gap class as hook
    files (commit 64fbe57).
    """
    tracked = []
    for dirname in (".claude-plugin", ".codex-plugin"):
        manifest_dir = os.path.join(repo_root, dirname)
        try:
            if not os.path.isdir(manifest_dir):
                continue
            entries = sorted(os.listdir(manifest_dir))
        except OSError:
            continue

        for entry in entries:
            full_path = os.path.join(manifest_dir, entry)
            if not os.path.isfile(full_path):
                continue
            if entry.endswith('.json'):
                tracked.append(f"{dirname}/{entry}")

    return tracked


def get_tracked_source_manifest_files(repo_root):
    """Get source-checkout-only marketplace manifests.

    Codex discovers local marketplaces from .agents/plugins/marketplace.json in
    the source checkout, but installed plugin cache payloads do not retain that
    catalog. Track it for release/source verification without making installed
    Codex cache verification fail on a file that is not runtime payload.
    """
    tracked = []
    agents_marketplace = os.path.join(repo_root, ".agents", "plugins", "marketplace.json")
    if os.path.isfile(agents_marketplace):
        tracked.append(".agents/plugins/marketplace.json")
    return tracked


def get_tracked_manifest_files(repo_root):
    """Get all plugin and marketplace manifest files for compatibility."""
    return get_tracked_runtime_manifest_files(repo_root) + get_tracked_source_manifest_files(repo_root)


def get_tracked_symlinks(repo_root, skill_root):
    """Get top-level repo symlinks whose targets point into skill_root.

    Caught by torture-room security-sentinel Finding 3: the backward-compat
    'skill' symlink at the repo root points into skills/repo-forensics/ but
    is outside what get_tracked_files walks, so verify_install cannot detect
    if an attacker (via tarball swap or compromised fork) replaces the
    symlink target with '/tmp/evil/' or any other attacker-controlled path.

    This function enumerates repo-root symlinks whose targets resolve into
    skill_root, so their target strings can be hashed and verified alongside
    regular files.

    Only top-level repo entries are considered (no recursion) because
    forensify's symlink contract is specifically for root-level backward-
    compat glue. Deep symlink farms would require a more sophisticated
    policy and are out of scope for this hardening.
    """
    if not os.path.isdir(repo_root):
        return {}

    skill_root_real = os.path.realpath(skill_root)
    symlinks = {}

    for entry in os.listdir(repo_root):
        full_path = os.path.join(repo_root, entry)
        if not os.path.islink(full_path):
            continue
        target = os.readlink(full_path)
        # Only track symlinks whose resolved target is inside skill_root.
        # Other symlinks are outside our security domain.
        resolved = os.path.realpath(full_path)
        if resolved != skill_root_real and not resolved.startswith(skill_root_real + os.sep):
            continue
        symlinks[entry] = target

    return symlinks


def get_tracked_files(skill_root):
    """Get all files that should be integrity-checked."""
    skip_dirs = {'.git', '__pycache__', '.pytest_cache', 'tests', '.cache', '.ruff_cache'}
    skip_files = {'.DS_Store', '.forensics-baseline.json', '.forensics-iocs.json',
                  'checksums.json', 'checksums.json.sig'}

    # In a git repo, use git ls-files to avoid local-only artifacts
    try:
        result = subprocess.run(
            ['git', 'ls-files', '--cached'],
            capture_output=True, text=True, timeout=5, cwd=skill_root,
        )
        if result.returncode == 0 and result.stdout.strip():
            git_files = []
            for rel in result.stdout.strip().splitlines():
                if any(rel.startswith(d + '/') or rel.startswith(d + os.sep) for d in skip_dirs):
                    continue
                if os.path.basename(rel) in skip_files:
                    continue
                if rel.endswith(('.pyc', '.pyo')):
                    continue
                fp = os.path.join(skill_root, rel)
                if os.path.islink(fp) or not os.path.isfile(fp):
                    continue
                git_files.append(rel)
            return sorted(git_files)
    except Exception:
        pass

    # Fallback for non-git installs (marketplace/plugin path)
    tracked = []
    for root, dirs, files in os.walk(skill_root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if f in skip_files:
                continue
            if f.endswith(('.pyc', '.pyo')):
                continue
            fp = os.path.join(root, f)
            if os.path.islink(fp):
                continue
            # Normalize to forward slashes so checksum keys match the shipped
            # manifest on Windows (os.path.relpath yields backslashes there,
            # which would fail integrity verification during marketplace/plugin
            # installs — the non-git code path). No-op on POSIX.
            rel = os.path.relpath(fp, skill_root).replace(os.sep, '/')
            tracked.append(rel)

    return sorted(tracked)


def generate_checksums(skill_root):
    """Generate checksums.json for skill files + root symlinks + repo hooks."""
    files = get_tracked_files(skill_root)
    checksums = {}
    for rel in files:
        fp = os.path.join(skill_root, rel)
        checksums[rel] = sha256_file(fp)

    repo_root = get_repo_root(skill_root)
    symlinks = get_tracked_symlinks(repo_root, skill_root)

    # Hash repo-root hook scripts that the plugin manifest invokes. These
    # files live outside skill_root but are load-bearing — tampering would
    # compromise the plugin without being detected by the skill-local
    # integrity check.
    hook_files = get_tracked_hook_files(repo_root)
    hook_checksums = {}
    for rel in hook_files:
        fp = os.path.join(repo_root, rel)
        hook_checksums[rel] = sha256_file(fp)

    manifest_files = get_tracked_runtime_manifest_files(repo_root)
    manifest_checksums = {}
    for rel in manifest_files:
        fp = os.path.join(repo_root, rel)
        manifest_checksums[rel] = sha256_file(fp)

    source_manifest_files = get_tracked_source_manifest_files(repo_root)
    source_manifest_checksums = {}
    for rel in source_manifest_files:
        fp = os.path.join(repo_root, rel)
        source_manifest_checksums[rel] = sha256_file(fp)

    output = {
        'version': '2',
        'generator': 'repo-forensics/verify_install',
        'file_count': len(checksums),
        'files': checksums,
    }
    if symlinks:
        output['repo_symlinks'] = symlinks
        output['symlink_count'] = len(symlinks)
    if hook_checksums:
        output['repo_hooks'] = hook_checksums
        output['hook_count'] = len(hook_checksums)
    if manifest_checksums:
        output['repo_manifests'] = manifest_checksums
        output['manifest_count'] = len(manifest_checksums)
    if source_manifest_checksums:
        output['repo_source_manifests'] = source_manifest_checksums
        output['source_manifest_count'] = len(source_manifest_checksums)

    out_path = os.path.join(skill_root, 'checksums.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
        f.write('\n')

    extras = []
    if symlinks:
        extras.append(f"{len(symlinks)} symlinks")
    if hook_checksums:
        extras.append(f"{len(hook_checksums)} hook files")
    if manifest_checksums:
        extras.append(f"{len(manifest_checksums)} manifest files")
    if source_manifest_checksums:
        extras.append(f"{len(source_manifest_checksums)} source manifest files")
    extras_msg = f" + {' + '.join(extras)}" if extras else ""
    print(f"[+] Generated checksums.json: {len(checksums)} files tracked{extras_msg}")
    return out_path


def verify_checksums(skill_root):
    """Verify current files against checksums.json.
    Returns (passed: bool, report: list[str])."""
    checksum_path = os.path.join(skill_root, 'checksums.json')
    if not os.path.exists(checksum_path):
        return False, ["checksums.json not found. Run --generate first or download from release."]

    try:
        with open(checksum_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return False, [f"Failed to read checksums.json: {e}"]

    expected = data.get('files', {})
    report = []
    tampered = []
    missing = []
    extra = []

    skill_root_real = os.path.realpath(skill_root)

    # Validate file_count matches actual entries
    declared_count = data.get('file_count', -1)
    if declared_count != len(expected):
        report.append(f"  WARNING: file_count mismatch (manifest says {declared_count}, dict has {len(expected)} entries)")

    # Check all expected files
    for rel, expected_hash in expected.items():
        fp = os.path.realpath(os.path.join(skill_root, rel))
        if not fp.startswith(skill_root_real + os.sep):
            tampered.append(rel)
            report.append(f"  REJECTED: {rel} (path traversal attempt)")
            continue
        if not isinstance(expected_hash, str):
            tampered.append(rel)
            report.append(f"  REJECTED: {rel} (invalid hash type in manifest)")
            continue
        actual_hash = sha256_file(fp)
        if actual_hash is None:
            missing.append(rel)
            report.append(f"  UNREADABLE: {rel} (missing or permission denied)")
            continue
        if actual_hash != expected_hash:
            tampered.append(rel)
            report.append(f"  TAMPERED: {rel} (expected {expected_hash[:12]}..., got {actual_hash[:12]}...)")

    # Check for unexpected new files
    current_files = set(get_tracked_files(skill_root))
    expected_files = set(expected.keys())
    new_files = current_files - expected_files
    for rel in sorted(new_files):
        extra.append(rel)
        report.append(f"  NEW FILE: {rel} (not in checksums.json)")

    # Check repo-level hook files against manifest. Load-bearing hook
    # scripts at the repo-root hooks/ directory live outside skill_root but
    # are invoked by plugin manifest at runtime. Tampering would compromise
    # the plugin without being detected by the skill-local check.
    expected_hooks = data.get('repo_hooks', {})
    repo_root = get_repo_root(skill_root)
    repo_root_real = os.path.realpath(repo_root)
    plugin_cache_layout = is_plugin_cache_layout(repo_root)
    tampered_hooks = []
    missing_hooks = []
    for rel, expected_hash in expected_hooks.items():
        fp = os.path.realpath(os.path.join(repo_root, rel))
        if not fp.startswith(repo_root_real + os.sep):
            tampered_hooks.append(rel)
            report.append(f"  HOOK REJECTED: {rel} (path traversal attempt)")
            continue
        actual_hash = sha256_file(fp)
        if actual_hash is None:
            missing_hooks.append(rel)
            report.append(f"  HOOK MISSING: {rel} (not found on disk)")
            continue
        if actual_hash != expected_hash:
            tampered_hooks.append(rel)
            report.append(f"  HOOK TAMPERED: {rel} (expected {expected_hash[:12]}..., got {actual_hash[:12]}...)")

    # Check repo-level symlinks against manifest. Caught by torture-room
    # security-sentinel Finding 3 — the backward-compat skill symlink at
    # repo root points into skills/repo-forensics/, but it lives outside
    # skill_root and would otherwise be invisible to verification.
    expected_symlinks = data.get('repo_symlinks', {})
    current_symlinks = get_tracked_symlinks(repo_root, skill_root)

    tampered_symlinks = []
    missing_symlinks = []
    extra_symlinks = []
    skipped_symlinks = []

    for name, expected_target in expected_symlinks.items():
        if name not in current_symlinks:
            if plugin_cache_layout:
                skipped_symlinks.append(name)
                report.append(
                    f"  SYMLINK SKIPPED: {name} "
                    "(agent plugin cache layout does not preserve root compatibility symlinks)"
                )
                continue
            missing_symlinks.append(name)
            report.append(f"  SYMLINK MISSING: {name} (declared in manifest, not found on disk)")
            continue
        if current_symlinks[name] != expected_target:
            tampered_symlinks.append(name)
            report.append(
                f"  SYMLINK TAMPERED: {name} "
                f"(expected target '{expected_target}', got '{current_symlinks[name]}')"
            )

    for name in sorted(set(current_symlinks) - set(expected_symlinks)):
        extra_symlinks.append(name)
        report.append(f"  NEW SYMLINK: {name} -> {current_symlinks[name]} (not in checksums.json)")

    # Check agent plugin manifest files
    expected_manifests_raw = data.get('repo_manifests', {})
    expected_manifests = {}
    compat_source_manifests = {}
    for rel, expected_hash in expected_manifests_raw.items():
        if rel in SOURCE_ONLY_MANIFEST_FILES:
            compat_source_manifests[rel] = expected_hash
        else:
            expected_manifests[rel] = expected_hash
    expected_source_manifests = {
        **compat_source_manifests,
        **data.get('repo_source_manifests', {}),
    }
    tampered_manifests = []
    missing_manifests = []
    for rel, expected_hash in expected_manifests.items():
        fp = os.path.realpath(os.path.join(repo_root, rel))
        if not fp.startswith(repo_root_real + os.sep):
            tampered_manifests.append(rel)
            report.append(f"  MANIFEST REJECTED: {rel} (path traversal attempt)")
            continue
        actual_hash = sha256_file(fp)
        if actual_hash is None:
            missing_manifests.append(rel)
            report.append(f"  MANIFEST MISSING: {rel} (not found on disk)")
            continue
        if actual_hash != expected_hash:
            tampered_manifests.append(rel)
            report.append(f"  MANIFEST TAMPERED: {rel} (expected {expected_hash[:12]}..., got {actual_hash[:12]}...)")

    tampered_source_manifests = []
    missing_source_manifests = []
    skipped_source_manifests = []
    for rel, expected_hash in expected_source_manifests.items():
        fp = os.path.realpath(os.path.join(repo_root, rel))
        if not fp.startswith(repo_root_real + os.sep):
            tampered_source_manifests.append(rel)
            report.append(f"  SOURCE MANIFEST REJECTED: {rel} (path traversal attempt)")
            continue
        actual_hash = sha256_file(fp)
        if actual_hash is None:
            if plugin_cache_layout:
                skipped_source_manifests.append(rel)
                report.append(
                    f"  SOURCE MANIFEST SKIPPED: {rel} "
                    "(agent plugin cache layout does not include source marketplace catalogs)"
                )
                continue
            missing_source_manifests.append(rel)
            report.append(f"  SOURCE MANIFEST MISSING: {rel} (not found on disk)")
            continue
        if actual_hash != expected_hash:
            tampered_source_manifests.append(rel)
            report.append(
                f"  SOURCE MANIFEST TAMPERED: {rel} "
                f"(expected {expected_hash[:12]}..., got {actual_hash[:12]}...)"
            )

    # Summary
    all_tampered = (
        len(tampered) + len(tampered_symlinks) + len(tampered_hooks) +
        len(tampered_manifests) + len(tampered_source_manifests)
    )
    all_missing = (
        len(missing) + len(missing_symlinks) + len(missing_hooks) +
        len(missing_manifests) + len(missing_source_manifests)
    )
    all_extra = len(extra) + len(extra_symlinks)
    passed = all_tampered == 0 and all_missing == 0
    total_tracked = (
        len(expected) + len(expected_symlinks) + len(expected_hooks) +
        len(expected_manifests) + len(expected_source_manifests)
    )
    if passed and all_extra == 0:
        extras_note = []
        if expected_symlinks:
            checked_symlinks = len(expected_symlinks) - len(skipped_symlinks)
            if checked_symlinks:
                extras_note.append(f"{checked_symlinks} symlinks")
            if skipped_symlinks:
                extras_note.append(f"{len(skipped_symlinks)} cache-optional symlinks skipped")
        if expected_hooks:
            extras_note.append(f"{len(expected_hooks)} hooks")
        if expected_manifests:
            extras_note.append(f"{len(expected_manifests)} manifests")
        if expected_source_manifests:
            checked_source = len(expected_source_manifests) - len(skipped_source_manifests)
            if checked_source:
                extras_note.append(f"{checked_source} source manifests")
            if skipped_source_manifests:
                extras_note.append(f"{len(skipped_source_manifests)} source manifests skipped")
        extras_str = f" (+{', '.join(extras_note)})" if extras_note else ""
        report.insert(0, f"[+] VERIFIED: All {len(expected)} files{extras_str} match checksums.json (v{data.get('version', '?')})")
    elif passed:
        report.insert(0, f"[~] PARTIAL: All {total_tracked} tracked entries OK, but {all_extra} untracked entry/entries found")
    else:
        report.insert(0, f"[!] FAILED: {all_tampered} tampered, {all_missing} missing out of {total_tracked} tracked entries")

    return passed, report


def main():
    import argparse
    parser = argparse.ArgumentParser(description="repo-forensics Installation Verifier")
    parser.add_argument('--generate', action='store_true', help="Generate checksums.json (release-time)")
    parser.add_argument('--verify', action='store_true', help="Verify installation integrity")
    args = parser.parse_args()

    skill_root = get_skill_root()

    if args.generate:
        generate_checksums(skill_root)
        sys.exit(0)

    if args.verify:
        passed, report = verify_checksums(skill_root)
        for line in report:
            print(line)
        sys.exit(0 if passed else 1)

    parser.print_help()


if __name__ == "__main__":
    main()
