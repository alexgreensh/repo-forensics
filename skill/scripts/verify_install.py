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
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

sha256_file = core.sha256_file


def get_skill_root():
    """Get the root directory of the repo-forensics skill."""
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(scripts_dir)  # skill/


def get_tracked_files(skill_root):
    """Get all files that should be integrity-checked."""
    tracked = []
    skip_dirs = {'.git', '__pycache__', '.pytest_cache', 'tests', '.cache'}
    skip_files = {'.forensics-baseline.json', '.forensics-iocs.json', 'checksums.json'}

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
            rel = os.path.relpath(fp, skill_root)
            tracked.append(rel)

    return sorted(tracked)


def generate_checksums(skill_root):
    """Generate checksums.json for all skill files."""
    files = get_tracked_files(skill_root)
    checksums = {}
    for rel in files:
        fp = os.path.join(skill_root, rel)
        checksums[rel] = sha256_file(fp)

    output = {
        'version': '2',
        'generator': 'repo-forensics/verify_install',
        'file_count': len(checksums),
        'files': checksums,
    }

    out_path = os.path.join(skill_root, 'checksums.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
        f.write('\n')

    print(f"[+] Generated checksums.json: {len(checksums)} files tracked")
    return out_path


def verify_checksums(skill_root):
    """Verify current files against checksums.json.
    Returns (passed: bool, report: list[str])."""
    checksum_path = os.path.join(skill_root, 'checksums.json')
    if not os.path.exists(checksum_path):
        return False, ["checksums.json not found. Run --generate first or download from release."]

    with open(checksum_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

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

    # Summary
    passed = len(tampered) == 0 and len(missing) == 0
    if passed and len(extra) == 0:
        report.insert(0, f"[+] VERIFIED: All {len(expected)} files match checksums.json (v{data.get('version', '?')})")
    elif passed:
        report.insert(0, f"[~] PARTIAL: All {len(expected)} tracked files OK, but {len(extra)} untracked file(s) found")
    else:
        report.insert(0, f"[!] FAILED: {len(tampered)} tampered, {len(missing)} missing out of {len(expected)} tracked files")

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
