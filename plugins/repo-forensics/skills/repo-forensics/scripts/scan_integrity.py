#!/usr/bin/env python3
"""
scan_integrity.py - File Integrity Monitor (v1)
SHA256 baseline checking for critical files (.claude/settings.json,
CLAUDE.md, hook scripts). Detects unauthorized modifications that
could indicate CVE-2025-59536-style attacks.

Python-only file-integrity monitor.

Modes:
  --watch    Store baselines on first run, alert on drift on subsequent runs.
             Baselines stored in .forensics-baseline.json in the repo root.
  (default)  Scan-only mode: check for suspicious file properties without
             baseline comparison.

Created by Alex Greenshpun
"""

import os
import re
import sys
import json
import hashlib
import hmac
import secrets
import time
import stat
import contextlib
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "integrity"

# Use shared sha256_file from forensics_core
sha256_file = core.sha256_file

# Critical files that attackers target for persistence/RCE
CRITICAL_FILES = [
    '.claude/settings.json',
    '.claude/settings.local.json',
    'CLAUDE.md',
    '.claude/CLAUDE.md',
    '.mcp.json',
    '.claude/commands',  # directory - check contents
]

# Suspicious permission bits
EXECUTABLE_CONFIG_EXTENSIONS = {'.json', '.md', '.toml', '.yml', '.yaml', '.txt'}

BASELINE_FILENAME = '.forensics-baseline.json'
SIGNING_KEY_FILENAME = '.forensics-key'


def _get_signing_key_path():
    """Return the path where the HMAC signing key is stored (outside the repo)."""
    return os.path.expanduser("~/.cache/repo-forensics/forensics-key")


def _get_legacy_signing_key_path(repo_path):
    """Return the pre-migration repo-local signing key path."""
    return os.path.join(repo_path, SIGNING_KEY_FILENAME)


def _read_signing_key(path):
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NOCTTY', 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError('Signing key is not a regular file')
        stream = os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise
    with stream:
        key = stream.read()
    if not key:
        raise OSError('Signing key is empty')
    return key


def _write_signing_key(path, key):
    """Publish a complete private key once without replacing an existing leaf."""
    if not key:
        raise OSError('Signing key is empty')
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.forensics-key-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link creation is atomic and fails if any destination already
        # exists. Readers see all persisted bytes, never an empty in-flight key.
        os.link(temporary, path)
    finally:
        if fd is not None:
            os.close(fd)
        os.unlink(temporary)


def _get_or_create_signing_key(repo_path):  # repo_path kept for API compatibility
    """Get or create a 32-byte HMAC signing key for baseline integrity verification.

    The key is stored in ~/.cache/repo-forensics/forensics-key so it is never
    committed or readable from inside the repository. A key found inside the
    repository is never used or copied: whoever ships the repo can ship a key
    plus a matching baseline, so it proves nothing.
    """
    key_path = _get_signing_key_path()
    try:
        return _read_signing_key(key_path)
    except FileNotFoundError:
        pass
    key = secrets.token_bytes(32)
    try:
        _write_signing_key(key_path, key)
    except FileExistsError:
        return _read_signing_key(key_path)
    return key


def _hook_commands(data, nested=True):
    """Yield (event, command) from settings hooks.

    Claude Code nests commands as {"matcher": ..., "hooks": [{"command": ...}]};
    older files put "command" on the entry itself. Anything malformed is skipped
    so a hostile settings file cannot crash the scanner.
    """
    hooks = data.get('hooks') if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return
    for event_name, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, str):
                yield str(event_name), entry
                continue
            if not isinstance(entry, dict):
                continue
            inner = entry.get('hooks') if nested else None
            for hook in [entry] + (inner if isinstance(inner, list) else []):
                command = hook.get('command') if isinstance(hook, dict) else None
                if isinstance(command, str):
                    yield str(event_name), command


def find_critical_files(repo_path):
    """Find critical config files and hook scripts in the repo.
    Intentionally scoped to security-critical paths only, not all of .claude/."""
    found = {}

    for rel in CRITICAL_FILES:
        full_path = os.path.join(repo_path, rel)
        if os.path.isfile(full_path):
            found[rel] = full_path
        elif os.path.isdir(full_path):
            # Scan directory contents (e.g., .claude/commands/) - one level only
            try:
                for f in os.listdir(full_path):
                    fp = os.path.join(full_path, f)
                    if os.path.isfile(fp):
                        rp = os.path.relpath(fp, repo_path)
                        found[rp] = fp
            except OSError:
                pass

    # Find hook scripts referenced in settings.json
    settings_path = os.path.join(repo_path, '.claude/settings.json')
    if os.path.exists(settings_path):
        try:
            with open(settings_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for _event_name, cmd in _hook_commands(data):
                # Extract script paths from hook commands
                for token in cmd.split():
                    if token.endswith(('.sh', '.bash', '.py', '.js')):
                        script_path = os.path.join(repo_path, token) if not os.path.isabs(token) else token
                        if os.path.isfile(script_path):
                            rp = os.path.relpath(script_path, repo_path)
                            found[rp] = script_path
        except (ValueError, OSError):
            pass

    return found


def check_hooks_in_settings(filepath, rel_path):
    """Check .claude/settings.json for hooks configuration (CVE-2025-59536 vector)."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            data = json.loads(content)

        # Nested hooks are reported by the infra, lifecycle and skill-threat
        # scanners; repeating them here would only add duplicates.
        for event_name, cmd in _hook_commands(data, nested=False):
            if cmd:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Hook registered: {event_name}",
                    description=f"Shell command executes on {event_name} event (verify this is intentional)",
                    file=rel_path, line=0,
                    snippet=cmd[:120],
                    category="hook-configuration"
                ))
                # Check for especially dangerous patterns
                dangerous = ['curl', 'wget', 'bash -c', 'eval', 'base64', '/dev/tcp']
                for d in dangerous:
                    if d in cmd.lower():
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"Dangerous command in hook: {event_name}",
                            description=f"Hook contains '{d}' pattern (potential RCE/exfiltration)",
                            file=rel_path, line=0,
                            snippet=cmd[:120],
                            category="hook-dangerous"
                        ))
                        break

    except (ValueError, OSError):
        pass
    return findings


def check_executable_configs(repo_path, critical_files):
    """Flag config/doc files with executable permissions."""
    findings = []
    for rel_path, full_path in critical_files.items():
        ext = os.path.splitext(rel_path)[1].lower()
        if ext in EXECUTABLE_CONFIG_EXTENSIONS:
            try:
                mode = os.stat(full_path).st_mode
                if mode & 0o111:  # any execute bit
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title=f"Executable config file: {rel_path}",
                        description="Configuration/documentation file has execute permission (unusual, may indicate tampering)",
                        file=rel_path, line=0,
                        snippet=f"mode: {oct(mode)}",
                        category="permission-anomaly"
                    ))
            except OSError:
                pass
    return findings


class _WindowsBaselineIO:
    """Handle-relative Windows I/O; no path-based fallback on API failure."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes as w
        self.c = ctypes
        self.w = w
        class UnicodeString(ctypes.Structure):
            _fields_ = [('Length', w.USHORT), ('MaximumLength', w.USHORT),
                        ('Buffer', w.LPWSTR)]
        class ObjectAttributes(ctypes.Structure):
            _fields_ = [('Length', w.ULONG), ('RootDirectory', w.HANDLE),
                        ('ObjectName', ctypes.POINTER(UnicodeString)),
                        ('Attributes', w.ULONG), ('SecurityDescriptor', w.LPVOID),
                        ('SecurityQualityOfService', w.LPVOID)]
        class IOStatus(ctypes.Structure):
            _fields_ = [('Status', ctypes.c_void_p), ('Information', ctypes.c_size_t)]
        class AttributeTag(ctypes.Structure):
            _fields_ = [('FileAttributes', w.DWORD), ('ReparseTag', w.DWORD)]
        class RenameInfo(ctypes.Structure):
            _fields_ = [('Flags', w.DWORD), ('RootDirectory', w.HANDLE),
                        ('FileNameLength', w.DWORD), ('FileName', w.WCHAR * 1)]
        self.UnicodeString, self.ObjectAttributes = UnicodeString, ObjectAttributes
        self.IOStatus, self.AttributeTag, self.RenameInfo = IOStatus, AttributeTag, RenameInfo
        self.nt = ctypes.WinDLL('ntdll', use_last_error=True)
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.nt.NtCreateFile.argtypes = [ctypes.POINTER(w.HANDLE), w.DWORD,
            ctypes.POINTER(ObjectAttributes), ctypes.POINTER(IOStatus),
            w.LPVOID, w.ULONG, w.ULONG, w.ULONG, w.ULONG, w.LPVOID, w.ULONG]
        self.nt.NtCreateFile.restype = w.LONG
        self.nt.NtSetInformationFile.argtypes = [w.HANDLE, ctypes.POINTER(IOStatus),
                                                w.LPVOID, w.ULONG, ctypes.c_int]
        self.nt.NtSetInformationFile.restype = w.LONG
        self.nt.RtlNtStatusToDosError.argtypes = [w.LONG]
        self.nt.RtlNtStatusToDosError.restype = w.ULONG
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        self.kernel.DuplicateHandle.argtypes = [w.HANDLE, w.HANDLE, w.HANDLE,
            ctypes.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD]
        self.kernel.DuplicateHandle.restype = w.BOOL
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.CloseHandle.restype = w.BOOL
        self.kernel.GetFileInformationByHandleEx.argtypes = [w.HANDLE, ctypes.c_int,
                                                             w.LPVOID, w.DWORD]
        self.kernel.GetFileInformationByHandleEx.restype = w.BOOL
        self.kernel.SetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.c_int,
                                                           w.LPVOID, w.DWORD]
        self.kernel.SetFileInformationByHandle.restype = w.BOOL

    def open(self, name, parent=None, directory=False, create=False):
        c, w = self.c, self.w
        text = c.create_unicode_buffer(name)
        size = len(name.encode('utf-16-le'))
        u = self.UnicodeString(size, size + 2, c.cast(text, w.LPWSTR))
        attrs = self.ObjectAttributes(c.sizeof(self.ObjectAttributes), parent,
                                      c.pointer(u), 0x40, None, None)
        result, status = w.HANDLE(), self.IOStatus()
        # Synchronize, read attributes/data; created files also need write/delete.
        access = 0x100000 | 0x80 | 1
        if create:
            access |= 0x10000 | 2
        options = 0x200000 | 0x20 | (1 if directory else 0x40)
        code = self.nt.NtCreateFile(c.byref(result), access, c.byref(attrs),
            c.byref(status), None, 0x80, 7, 2 if create else 1, options, None, 0)
        if code < 0:
            raise c.WinError(self.nt.RtlNtStatusToDosError(code))
        try:
            info = self.AttributeTag()
            if not self.kernel.GetFileInformationByHandleEx(result, 9,
                    c.byref(info), c.sizeof(info)):
                raise c.WinError(c.get_last_error())
            # Refuse only name-surrogate reparse points (symlinks, junctions,
            # mount points). OneDrive placeholders and dedup files carry other
            # tags and are ordinary folders/files for this purpose.
            surrogate = info.FileAttributes & 0x400 and info.ReparseTag & 0x20000000
            if surrogate or bool(info.FileAttributes & 0x10) != directory:
                raise OSError('Baseline path contains a link or wrong file type')
            return result
        except BaseException:
            self.close(result)
            raise

    def duplicate(self, handle):
        result = self.w.HANDLE()
        process = self.kernel.GetCurrentProcess()
        if not self.kernel.DuplicateHandle(process, handle, process,
                self.c.byref(result), 0, False, 2):
            raise self.c.WinError(self.c.get_last_error())
        return result

    def close(self, handle):
        self.kernel.CloseHandle(handle)

    @contextlib.contextmanager
    def directory(self, repo_path):
        import ntpath
        # Resolve the user's chosen path once (a junctioned parent is fine);
        # every component below it is then opened without following links.
        path = ntpath.realpath(repo_path)
        if path.startswith('\\\\?\\UNC\\'):
            path = '\\\\' + path[8:]
        elif path.startswith('\\\\?\\'):
            path = path[4:]
        drive, tail = ntpath.splitdrive(path)
        # Standard drive roots and UNC shares only, not device/pipe namespaces.
        if not drive or drive.startswith(('\\\\?\\', '\\\\.\\')):
            raise OSError('Unsupported baseline device path')
        root = ('\\??\\UNC\\' + drive[2:] if drive.startswith('\\\\')
                else '\\??\\' + drive) + '\\'
        handle = self.open(root, directory=True)
        try:
            for part in tail.split('\\'):
                if not part:
                    continue
                child = self.open(part, parent=handle, directory=True)
                self.close(handle)
                handle = child
            yield handle
        finally:
            self.close(handle)

    def file_object(self, handle, writing=False):
        import msvcrt
        try:
            fd = msvcrt.open_osfhandle(handle.value, os.O_BINARY | (os.O_WRONLY if writing else os.O_RDONLY))
        except BaseException:
            self.close(handle)
            raise
        try:
            return os.fdopen(fd, 'w' if writing else 'r', encoding='utf-8', newline='')
        except BaseException:
            os.close(fd)
            raise

    def rename(self, handle, directory, name):
        c = self.c
        encoded = name.encode('utf-16-le')
        length = self.RenameInfo.FileName.offset + len(encoded)
        buffer = c.create_string_buffer(max(length, c.sizeof(self.RenameInfo)))
        info = self.RenameInfo.from_buffer(buffer)
        info.Flags, info.RootDirectory, info.FileNameLength = 1, directory, len(encoded)
        c.memmove(c.addressof(buffer) + self.RenameInfo.FileName.offset, encoded, len(encoded))
        # The Win32 rename wrapper rejects a relative RootDirectory on some
        # supported systems. Use the native handle-relative operation directly.
        status = self.IOStatus()
        code = self.nt.NtSetInformationFile(handle, c.byref(status), buffer, length, 10)
        if code < 0:
            raise c.WinError(self.nt.RtlNtStatusToDosError(code))

    def delete(self, handle):
        c = self.c
        delete = self.c.c_ubyte(1)
        if not self.kernel.SetFileInformationByHandle(handle, 4, c.byref(delete), c.sizeof(delete)):
            raise c.WinError(c.get_last_error())


_BASELINE_MISSING = object()


def _windows_read_baseline(repo_path):
    api = _WindowsBaselineIO()
    with api.directory(repo_path) as directory:
        try:
            handle = api.open(BASELINE_FILENAME, parent=directory)
        except FileNotFoundError:
            return _BASELINE_MISSING
        with api.file_object(handle) as stream:
            return json.load(stream)


def _windows_write_baseline(repo_path, payload):
    api = _WindowsBaselineIO()
    with api.directory(repo_path) as directory:
        try:
            existing = api.open(BASELINE_FILENAME, parent=directory)
        except FileNotFoundError:
            pass
        else:
            api.close(existing)
        name = '.forensics-baseline-' + secrets.token_hex(16) + '.tmp'
        handle = api.open(name, parent=directory, create=True)
        committed = False
        try:
            # fdopen owns only the duplicate. Keep the original native handle
            # alive for handle-relative rename and failure cleanup.
            duplicate = api.duplicate(handle)
            with api.file_object(duplicate, writing=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            api.rename(handle, directory, BASELINE_FILENAME)
            committed = True
        finally:
            try:
                if not committed:
                    api.delete(handle)
            finally:
                api.close(handle)


@contextlib.contextmanager
def _baseline_directory(repo_path):
    """Pin every POSIX path component without following links.

    The path the user chose is resolved once, so a repo reached through a
    symlinked parent (~/code -> /Volumes/x, /home -> var/home) still works.
    The threat is links planted inside the repo, and the baseline sits at the
    repo root, so from the resolved path down nothing is followed. An opened
    directory remains the destination even if its pathname is renamed.
    Windows uses separate handle-relative native operations, never a path fallback.
    """
    if os.name == 'nt':
        raise OSError('Safe baseline directory access is unavailable')
    components = [part for part in os.path.realpath(repo_path).split(os.path.sep) if part]
    # Parents only need search permission; the repo directory itself is opened
    # for reading so it can be fsynced after the rename.
    search = getattr(os, 'O_PATH', 0) or getattr(os, 'O_SEARCH', 0) or os.O_RDONLY
    fd = os.open(os.path.sep, search | os.O_DIRECTORY)
    try:
        for index, part in enumerate(components):
            last = index == len(components) - 1
            child = os.open(part, (os.O_RDONLY if last else search) |
                            os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _baseline_stat(dir_fd):
    try:
        info = os.stat(BASELINE_FILENAME, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise OSError('Baseline destination is not a regular file')
    return info


def _read_baseline(repo_path):
    if os.name == 'nt':
        return _windows_read_baseline(repo_path)
    with _baseline_directory(repo_path) as directory:
        if _baseline_stat(directory) is None:
            return _BASELINE_MISSING
        fd = os.open(BASELINE_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError('Baseline source is not a regular file')
            handle = os.fdopen(fd, 'r', encoding='utf-8')
        except BaseException:
            os.close(fd)
            raise
        with handle:
            return json.load(handle)


def _write_baseline(repo_path, baseline):
    # Serialize before creating anything so invalid input cannot alter disk state.
    payload = json.dumps(baseline, indent=2)
    if os.name == 'nt':
        return _windows_write_baseline(repo_path, payload)
    with _baseline_directory(repo_path) as directory:
        _baseline_stat(directory)
        temporary = '.forensics-baseline-' + secrets.token_hex(16) + '.tmp'
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            try:
                os.fchmod(fd, 0o600)
                handle = os.fdopen(fd, 'w', encoding='utf-8', newline='')
            except BaseException:
                os.close(fd)
                raise
            with handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            # Do not knowingly replace a symlink or special file planted mid-write.
            # rename itself never follows the destination, even after this check.
            _baseline_stat(directory)
            os.replace(temporary, BASELINE_FILENAME,
                       src_dir_fd=directory, dst_dir_fd=directory)
            with contextlib.suppress(OSError):
                os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        _remove_stale_temporaries(directory)


_TEMPORARY_NAME = re.compile(r'\.forensics-baseline-[0-9a-f]{32}\.tmp')
_STALE_AFTER_SECONDS = 3600


def _remove_stale_temporaries(directory):
    """Delete our own temp files left by a writer that was killed mid-write.

    Only exact temp names, only regular files owned by this user, only when
    older than an hour so a concurrent writer is never disturbed. unlink with
    dir_fd never follows a link.
    """
    try:
        names = os.listdir(directory)
    except OSError:
        return
    cutoff = time.time() - _STALE_AFTER_SECONDS
    for name in names:
        if not _TEMPORARY_NAME.fullmatch(name):
            continue
        with contextlib.suppress(OSError):
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_mtime < cutoff):
                os.unlink(name, dir_fd=directory)


def _invalid_baseline_finding():
    return core.Finding(
        scanner=SCANNER_NAME, severity="high",
        title="Invalid integrity baseline",
        description="Baseline is not valid UTF-8 JSON with the expected structure. "
                    "It was preserved without replacement. Inspect it before deliberately "
                    "removing it to create a new baseline.",
        file=BASELINE_FILENAME, line=0, snippet="",
        category="integrity-baseline-format"
    )


def _valid_baseline_shape(baseline):
    """Validate fields used by verification and drift checks before reading them."""
    if not isinstance(baseline, dict) or not isinstance(baseline.get('files'), dict):
        return False
    if not all(isinstance(path, str) and isinstance(digest, str)
               for path, digest in baseline['files'].items()):
        return False
    if '_meta' in baseline:
        meta = baseline['_meta']
        if not isinstance(meta, dict):
            return False
        if 'created' in meta and not isinstance(meta['created'], str):
            return False
    if '_hmac' in baseline:
        signature = baseline['_hmac']
        if not isinstance(signature, str) or re.fullmatch(r'[0-9a-f]{64}', signature) is None:
            return False
    return True


def _signed_by_repo_key(repo_path, stored_hmac, content):
    """True when the baseline verifies only against a key stored in the repo."""
    try:
        key = _read_signing_key(_get_legacy_signing_key_path(repo_path))
    except OSError:
        return False
    return hmac.compare_digest(stored_hmac, hmac.new(key, content, hashlib.sha256).hexdigest())


def _repo_key_finding():
    return core.Finding(
        scanner=SCANNER_NAME, severity="high",
        title="Baseline signed with a key stored in the repository",
        description="The baseline verifies only against " + SIGNING_KEY_FILENAME + " inside the "
                    "repository. Anyone who ships the repository can ship that key and a "
                    "matching baseline, so it is not trusted and the key is not used. If you "
                    "created it with an older version, review the repository, then delete "
                    + SIGNING_KEY_FILENAME + " and " + BASELINE_FILENAME + " and run --watch "
                    "again.",
        file=BASELINE_FILENAME, line=0, snippet="", category="integrity-hmac")


def load_baseline(repo_path):
    """Load existing baseline from .forensics-baseline.json with HMAC verification.

    Returns (baseline_data, integrity_findings) tuple.
    integrity_findings contains any HMAC-related warnings/errors.
    """
    integrity_findings = []

    try:
        baseline = _read_baseline(repo_path)
    except (ValueError, RecursionError):
        return None, [_invalid_baseline_finding()]
    except OSError as exc:
        integrity_findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="high",
            title="Baseline access refused",
            description="Baseline could not be read safely: " + str(exc),
            file=BASELINE_FILENAME, line=0, snippet="", category="integrity-baseline-io"))
        return None, integrity_findings
    if baseline is _BASELINE_MISSING:
        return None, integrity_findings

    if not _valid_baseline_shape(baseline):
        return None, [_invalid_baseline_finding()]

    stored_hmac = baseline.pop('_hmac', None)

    if stored_hmac is not None:
        content = json.dumps(baseline, sort_keys=True).encode('utf-8')
        try:
            key = _read_signing_key(_get_signing_key_path())
        except FileNotFoundError:
            key = None
        except OSError as exc:
            integrity_findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Signing key unreadable",
                description="The signing key could not be read safely, so the baseline "
                            "cannot be verified: " + str(exc),
                file=BASELINE_FILENAME, line=0, snippet="", category="integrity-baseline-io"))
            return None, integrity_findings
        if key is not None and hmac.compare_digest(
                stored_hmac, hmac.new(key, content, hashlib.sha256).hexdigest()):
            return baseline, integrity_findings
        if _signed_by_repo_key(repo_path, stored_hmac, content):
            integrity_findings.append(_repo_key_finding())
            return None, integrity_findings
        if key is None:
            integrity_findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Signing key missing for HMAC-signed baseline",
                description="Baseline has HMAC signature but signing key is missing - cannot verify integrity. Baseline is untrusted.",
                file=BASELINE_FILENAME, line=0,
                snippet="",
                category="integrity-hmac"
            ))
            return None, integrity_findings
        integrity_findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Baseline integrity compromised",
            description="HMAC verification failed - baseline may have been tampered with",
            file=BASELINE_FILENAME, line=0,
            snippet=f"stored: {stored_hmac[:16]}...",
            category="integrity-hmac"
        ))
    elif baseline:
        # Baseline exists but has no HMAC (legacy or tampered)
        integrity_findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="high",
            title="Unsigned baseline detected",
            description="Baseline exists without HMAC signature - may be legacy or tampered",
            file=BASELINE_FILENAME, line=0,
            snippet="",
            category="integrity-hmac"
        ))

    return baseline, integrity_findings


def save_baseline(repo_path, baseline_data):
    """Save baseline to .forensics-baseline.json with HMAC-SHA256 signature."""
    baseline_data['_meta'] = {
        'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'tool': 'repo-forensics/scan_integrity',
        'version': 'v1',
    }
    # Compute HMAC-SHA256 over the canonical JSON content
    key = _get_or_create_signing_key(repo_path)
    content = json.dumps(baseline_data, sort_keys=True)
    baseline_data['_hmac'] = hmac.new(key, content.encode('utf-8'), hashlib.sha256).hexdigest()
    _write_baseline(repo_path, baseline_data)


def _baseline_write_finding(exc):
    return core.Finding(
        scanner=SCANNER_NAME, severity="high", title="Baseline write refused",
        description="Baseline could not be saved safely: " + str(exc),
        file=BASELINE_FILENAME, line=0, snippet="", category="integrity-baseline-io")


def watch_mode(repo_path, critical_files, output_format):
    """--watch mode: store baselines on first run, detect drift on subsequent runs."""
    findings = []
    existing, integrity_findings = load_baseline(repo_path)
    findings.extend(integrity_findings)
    if integrity_findings:
        core.emit_status(output_format,
                         "[!] Baseline is untrusted; preserved without replacement. "
                         "Inspect it before deliberately removing it to create a new baseline.")
        return findings

    current_hashes = {}
    for rel_path, full_path in critical_files.items():
        h = sha256_file(full_path)
        if h:
            current_hashes[rel_path] = h

    if existing is None:
        # First run: create baseline
        try:
            save_baseline(repo_path, {'files': current_hashes})
        except OSError as exc:
            findings.append(_baseline_write_finding(exc))
            return findings
        core.emit_status(output_format, f"[+] Baseline created: {len(current_hashes)} files tracked in {BASELINE_FILENAME}")
        return findings

    # Subsequent run: compare against baseline
    baseline_files = existing.get('files', {})
    meta = existing.get('_meta', {})
    created = meta.get('created', 'unknown')

    for rel_path, current_hash in current_hashes.items():
        if rel_path in baseline_files:
            if current_hash != baseline_files[rel_path]:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"File modified since baseline: {rel_path}",
                    description=f"SHA256 changed since baseline ({created}). Verify this change was intentional.",
                    file=rel_path, line=0,
                    snippet=f"was: {baseline_files[rel_path][:16]}... now: {current_hash[:16]}...",
                    category="integrity-drift"
                ))
        else:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"New critical file since baseline: {rel_path}",
                description=f"File did not exist when baseline was created ({created})",
                file=rel_path, line=0,
                snippet=f"hash: {current_hash[:32]}...",
                category="integrity-new-file"
            ))

    for rel_path in baseline_files:
        if rel_path not in current_hashes:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"File removed since baseline: {rel_path}",
                description=f"File existed in baseline ({created}) but is now missing",
                file=rel_path, line=0,
                snippet=f"was: {baseline_files[rel_path][:32]}...",
                category="integrity-removed"
            ))

    # Update baseline with current state
    try:
        save_baseline(repo_path, {'files': current_hashes})
    except OSError as exc:
        findings.append(_baseline_write_finding(exc))
        return findings
    core.emit_status(output_format, f"[+] Baseline updated: {len(current_hashes)} files tracked")

    return findings


def check_hardcoded_plugin_paths(repo_path):
    """Detect plugin scripts that resolve __file__ and write to settings.json.

    When a plugin runs from the Claude plugin cache (/plugins/cache/name/version/...),
    Path(__file__).resolve() produces a version-specific absolute path. If that path
    gets written to settings.json (e.g. as a hook command), it breaks when the plugin
    version bumps and the cache directory changes.

    Fix: use ${CLAUDE_PLUGIN_ROOT}/relative/path instead of the resolved absolute path.
    """
    findings = []
    ignore_patterns = core.load_ignore_patterns(repo_path)

    # Patterns that resolve __file__ to an absolute path
    file_resolve_patterns = [
        re.compile(r'''Path\s*\(\s*__file__\s*\)\s*\.resolve\s*\('''),
        re.compile(r'''os\.path\.abspath\s*\(\s*__file__\s*\)'''),
        re.compile(r'''os\.path\.realpath\s*\(\s*__file__\s*\)'''),
        re.compile(r'''os\.path\.dirname\s*\(\s*os\.path\.(abspath|realpath)\s*\(\s*__file__\s*\)\s*\)'''),
    ]

    # Patterns that write to settings.json or other persistent config
    config_write_patterns = [
        re.compile(r'''settings\.json'''),
        re.compile(r'''settings\.local\.json'''),
        re.compile(r'''claude_desktop_config\.json'''),
    ]

    # The safe escape hatch
    safe_pattern = re.compile(r'''CLAUDE_PLUGIN_ROOT''')

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        if not rel_path.endswith('.py'):
            continue

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except OSError:
            continue

        has_file_resolve = any(p.search(content) for p in file_resolve_patterns)
        has_config_write = any(p.search(content) for p in config_write_patterns)
        has_safe_escape = safe_pattern.search(content)

        if has_file_resolve and has_config_write and not has_safe_escape:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"Hardcoded plugin path risk: {rel_path}",
                description=(
                    "Script resolves __file__ to absolute path AND references settings.json, "
                    "but does not use ${CLAUDE_PLUGIN_ROOT}. If running from plugin cache, "
                    "the resolved path includes a version-specific directory that breaks on "
                    "version bumps. Use ${CLAUDE_PLUGIN_ROOT}/relative/path instead."
                ),
                file=rel_path, line=0,
                snippet="__file__ resolve + settings.json write without CLAUDE_PLUGIN_ROOT",
                category="hardcoded-plugin-path"
            ))

    return findings


def main():
    import argparse
    parser = argparse.ArgumentParser(description="repo-forensics: File Integrity Monitor")
    parser.add_argument('repo_path', help="Path to repository to scan")
    parser.add_argument('--format', choices=['text', 'json', 'summary'], default='text',
                        help="Output format (default: text)")
    parser.add_argument('--watch', action='store_true',
                        help="Store baselines and detect drift on subsequent runs")
    args = parser.parse_args()
    repo_path = os.path.abspath(args.repo_path)

    core.emit_status(args.format, f"[*] Scanning file integrity in {repo_path}...")

    critical_files = find_critical_files(repo_path)

    if not critical_files:
        core.emit_status(args.format, "[+] No critical configuration files found.")
        core.output_findings([], args.format, SCANNER_NAME)
        return

    core.emit_status(args.format, f"[*] Found {len(critical_files)} critical file(s)")

    all_findings = []

    # Check for hooks in settings.json
    settings_path = os.path.join(repo_path, '.claude/settings.json')
    if os.path.exists(settings_path):
        all_findings.extend(check_hooks_in_settings(
            settings_path,
            '.claude/settings.json'
        ))

    # Check for executable config files
    all_findings.extend(check_executable_configs(repo_path, critical_files))

    # Check for hardcoded plugin paths (version-specific cache paths in config)
    all_findings.extend(check_hardcoded_plugin_paths(repo_path))

    # Watch mode: baseline comparison
    if args.watch:
        all_findings.extend(watch_mode(repo_path, critical_files, args.format))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
