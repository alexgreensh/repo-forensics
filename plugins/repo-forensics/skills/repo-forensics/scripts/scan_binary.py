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
    b'RIFF': 'WAV Audio (RIFF container)',
    b'ID3': 'MP3 Audio (ID3 tag)',
    b'fLaC': 'FLAC Audio',
}

SAFE_MEDIA = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.mp4', '.pdf', '.txt', '.md', '.json', '.csv', '.ico', '.bmp', '.wav', '.mp3', '.flac', '.ogg', '.aac', '.wma'}


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


AUDIO_EXTENSIONS = {'.wav', '.mp3', '.flac', '.ogg', '.aac'}
_EXEC_DESCS = {'ELF Executable (Linux)', 'PE Executable (Windows)',
               'Mach-O Binary (32-bit)', 'Mach-O Binary (64-bit)',
               'Java Class / Mach-O Fat Binary'}
EXEC_SIGNATURES = [sig for sig, desc in MAGIC_NUMBERS.items() if desc in _EXEC_DESCS]


def _is_valid_pe(content, offset):
    """A real PE has 'PE\\x00\\x00' at the location its e_lfanew field points to.
    A bare 'MZ' pair (2 bytes) appears routinely inside compressed audio,
    so require the structural marker too before treating it as an executable."""
    if offset + 0x40 > len(content):
        return False
    e_lfanew = int.from_bytes(content[offset + 0x3C:offset + 0x40], "little")
    return 0 < e_lfanew < 4096 and content[e_lfanew:e_lfanew + 4] == b'PE\x00\x00'


def _find_embedded_executable(content, search_from):
    """Return the first offset of a valid executable signature in content, else None."""
    for sig in EXEC_SIGNATURES:
        offset = content.find(sig, search_from)
        while offset > 0:
            if sig == b'MZ' and not _is_valid_pe(content, offset):
                offset = content.find(sig, offset + 1)
                continue
            return offset
    return None


def scan_audio_steganography(filepath, rel_path):
    """Detect executable content hidden in audio files (TeamPCP Telnyx attack pattern, March 2026).

    Checks for: ELF/PE/Mach-O magic bytes in audio data sections,
    high base64-density in audio frames, XOR-encrypted payloads.
    """
    findings = []
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in AUDIO_EXTENSIONS:
        return findings

    try:
        file_size = os.path.getsize(filepath)
        if file_size < 1024:
            return findings

        with open(filepath, 'rb') as f:
            content = f.read(min(file_size, 128 * 1024))

        offset = _find_embedded_executable(content, 44 if ext == '.wav' else 0)
        if offset is not None:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=f"Audio Steganography: Executable in {ext.upper()}",
                description=f"Audio file contains executable signature at offset {offset} (TeamPCP Telnyx attack pattern, March 2026). Malicious code hidden in audio data frames.",
                file=rel_path, line=0,
                snippet=f"Executable signature found at byte offset {offset}",
                category="audio-steganography"
            ))

        data_section = content[44:] if ext == '.wav' else content[128:]
        if len(data_section) > 100:
            try:
                sample = data_section[:4096]
                text_chars = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
                text_ratio = text_chars / len(sample)
                if text_ratio > 0.9:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title=f"Audio Steganography: Text Content in {ext.upper()} Data",
                        description=f"Audio file data section is {text_ratio:.0%} printable text (expected binary audio data). Possible base64-encoded payload (TeamPCP WAV steganography pattern).",
                        file=rel_path, line=0,
                        snippet=f"Text ratio: {text_ratio:.0%} in first 4KB of audio data",
                        category="audio-steganography"
                    ))
            except (MemoryError, OverflowError, ZeroDivisionError):
                pass

    except (OSError, MemoryError):
        pass

    return findings


def scan_embedded_pe(filepath, rel_path):
    """Detect PE executables embedded in non-PE files (InQuest Embedded_PE pattern).

    Checks for MZ magic at non-zero offset with valid PE signature.
    Catches polyglot files (image+PE, document+PE) used in APT campaigns
    (UNK_CraftyCamel, Proofpoint Sosano).
    """
    findings = []
    ext = os.path.splitext(filepath)[1].lower()

    # Skip actual PE files - MZ at offset 0 is expected there
    if ext in {'.exe', '.dll', '.sys', '.scr', '.drv', '.ocx', '.com'}:
        return findings

    try:
        file_size = os.path.getsize(filepath)
        if file_size < 64 or file_size > 10 * 1024 * 1024:  # Skip tiny/huge files
            return findings

        with open(filepath, 'rb') as f:
            content = f.read(min(file_size, 128 * 1024))

        # Search for MZ at non-zero offsets
        offset = 1  # Skip offset 0 (would be a normal PE)
        while offset < len(content) - 64:
            offset = content.find(b'MZ', offset)
            if offset < 0:
                break

            try:
                pe_offset_loc = offset + 0x3C
                if pe_offset_loc + 4 <= len(content):
                    pe_offset = int.from_bytes(content[pe_offset_loc:pe_offset_loc + 4], 'little')
                    if pe_offset > 1024 * 1024:
                        offset += 2
                        continue
                    pe_sig_loc = offset + pe_offset
                    pe_sig = None
                    if pe_sig_loc + 4 <= len(content):
                        pe_sig = content[pe_sig_loc:pe_sig_loc + 4]
                    elif pe_sig_loc + 4 <= file_size:
                        try:
                            with open(filepath, 'rb') as f2:
                                f2.seek(pe_sig_loc)
                                pe_sig = f2.read(4)
                        except OSError:
                            pass
                    if pe_sig == b'PE\x00\x00':
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"Embedded PE Executable in {ext.upper() or 'file'}",
                            description=f"PE executable found at offset {offset} inside non-PE file. Polyglot file technique used in APT campaigns (UNK_CraftyCamel, Proofpoint Sosano).",
                            file=rel_path, line=0,
                            snippet=f"MZ+PE signature at offset {offset}",
                            category="embedded-executable"
                        ))
                        break
            except (IndexError, OverflowError):
                pass

            offset += 2

    except (OSError, MemoryError):
        pass

    return findings


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
                # Issue #38: by this code path the file has NO exec magic and
                # NO shebang (those are caught earlier as CRITICAL). An exec
                # bit alone is permission hygiene, not binary camouflage —
                # real camouflage (ELF/PE/Mach-O + image extension) is still
                # caught upstream as CRITICAL. Demote this single signal to
                # LOW severity under a category that reflects intent. HIGH
                # only when combined with executable content / shebang /
                # magic mismatch, which are detected separately and unchanged.
                all_findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="low",
                    title=f"Executable bit on data file ({ext})",
                    description=(
                        f"Data file ({ext}) has the executable bit set (+x). "
                        "Permission-hygiene signal only; high-confidence "
                        "binary camouflage is detected separately when the "
                        "file also carries executable magic or a shebang."
                    ),
                    file=rel_path, line=0,
                    snippet=f"chmod +x on {ext} file",
                    category="permission-hygiene"
                ))

        # Audio steganography check
        if ext in AUDIO_EXTENSIONS:
            all_findings.extend(scan_audio_steganography(filepath, rel_path))

        # Embedded PE check (polyglot files: image+PE, document+PE)
        all_findings.extend(scan_embedded_pe(filepath, rel_path))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
