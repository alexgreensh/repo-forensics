#!/usr/bin/env python3
"""
scan_binary.py - Binary Camouflage Scanner (v2: severity system)
Detects executables hidden as images/text files.

Created by Alex Greenshpun
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "binary"

MAGIC_NUMBERS = {
    b'\x7fELF': 'ELF Executable (Linux)',
    b'MZ': 'PE Executable (Windows)',
    b'\xca\xfe\xba\xbe': 'Java Class / Mach-O Fat Binary',
    b'\xfe\xed\xfa\xce': 'Mach-O Binary (32-bit)',
    b'\xfe\xed\xfa\xcf': 'Mach-O Binary (64-bit)',
    b'\xca\xfe\xba\xbf': 'Mach-O Binary (64-bit)',
    b'#!': 'Shebang Script',
}

SAFE_MEDIA = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.mp4', '.pdf', '.txt', '.md', '.json', '.csv', '.ico', '.bmp'}


def get_file_type(filepath):
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4)
        for signature, description in MAGIC_NUMBERS.items():
            if header.startswith(signature):
                return description
        return None
    except (OSError, UnicodeDecodeError):
        return None


def main():
    args = core.parse_common_args(sys.argv, "Binary Camouflage Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning for masquerading binaries in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for filepath, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=False):
        ext = os.path.splitext(filepath)[1].lower()

        if ext in SAFE_MEDIA:
            description = get_file_type(filepath)
            if description and ('Executable' in description or 'Mach-O' in description):
                all_findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"Binary Masquerading as {ext}",
                    description=f"File has extension '{ext}' but magic number indicates: {description}",
                    file=rel_path, line=0,
                    snippet=f"Magic: {description}",
                    category="binary-camouflage"
                ))

        if os.name == 'posix':
            if os.access(filepath, os.X_OK) and ext in {'.png', '.jpg', '.txt', '.md', '.json', '.csv'}:
                all_findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Executable Permission on {ext}",
                    description=f"File has extension '{ext}' but is marked executable (+x)",
                    file=rel_path, line=0,
                    snippet=f"chmod +x on {ext} file",
                    category="binary-camouflage"
                ))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
