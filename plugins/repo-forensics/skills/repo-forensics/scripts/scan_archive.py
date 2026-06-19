#!/usr/bin/env python3
"""
scan_archive.py - Archive / Document Indirection Scanner

Closes the highest-severity scanner-bypass gap from the 2026-06 CSA / Trail of
Bits audit: .zip/.docx/.jar/.whl and friends are treated as opaque binary and
never unpacked, so a payload inside a Word doc or a zip is invisible to every
scanner. (Trail of Bits used exactly this against ClawHub.)

User-safety north star (KTD6, founder directive): this scanner NEVER writes
attacker-controlled bytes to the user's disk and never spawns a subprocess per
member. Top-level archives are opened by path (read from their own on-disk
location, never re-written); nested archives are read from bounded in-memory
buffers. Members are scanned IN PROCESS. That removes the zip-slip,
symlink-escape, device-file, temp-leak, and subprocess-timeout risks an
extract-to-disk design carries.

For each archive it streams each member under a hard safety budget:
  - a running byte counter (decompressed size is MEASURED, never trusted from
    the attacker-controlled header) with per-entry, per-archive, and cumulative
    cross-nesting caps,
  - lazy member iteration so a decompression bomb (a .tgz that expands to
    gigabytes) is bounded by the entry/time caps instead of being fully
    expanded by getmembers(),
  - a compression-ratio guard that aborts a zip member as a `zip-bomb`,
  - a tar member-type allow-list: regular files only; symlink / hardlink /
    device / FIFO members are refused (a `path-traversal` finding),
  - a per-member SCAN cap and a wall-clock budget so one large member cannot
    overrun the pipeline timeout,
  - a nesting-depth cap for archives inside archives.
Surviving members are decoded and run through the shared SAST + trifecta +
secret + skill-threat detectors in process. Because the member NAME is
attacker-controlled, SAST is not gated on its extension: unknown-extension
members are sniffed as code so a payload cannot dodge detection by dropping its
extension. Inner findings are re-pathed `outer.ext -> inner/path` and the
archive is tagged `archive-indirection`.

Fail loud, never silent (R12): a budget exhaustion emits `archive-scan-incomplete`
(naming the affected archive); an archive format we cannot open
(.7z/.xz/.zst/.rar/.cab, encrypted/corrupt members) emits
`unsupported-archive-type` / `opaque-archive`; one malformed archive can never
crash the whole scan (each is isolated).

Created by Alex Greenshpun
"""

import io
import os
import sys
import tarfile
import time
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import scan_sast
import scan_secrets
import scan_skill_threats

SCANNER_NAME = "archive"

# Zip-family (incl. OOXML office docs, jars, wheels, apks) and tar-family.
_ZIP_EXTS = {".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
             ".jar", ".war", ".ear", ".whl", ".egg", ".apk", ".ipa", ".nupkg"}
_TAR_EXTS = {".tar", ".tgz", ".tar.gz", ".tbz2", ".tar.bz2", ".txz", ".tar.xz"}
# Formats we deliberately do NOT support yet — surfaced loudly, not silently.
_UNSUPPORTED_EXTS = {".7z", ".xz", ".zst", ".rar", ".cab", ".lz4", ".br"}

MAX_ENTRY_BYTES = 10 * 1024 * 1024          # per-member uncompressed READ cap
MEMBER_SCAN_BYTES = 1 * 1024 * 1024         # per-member text fed to the detectors
MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024  # per-archive uncompressed cap
MAX_ENTRIES_PER_ARCHIVE = 1000
MAX_TOTAL_FILES = 2000                       # cumulative across all nesting levels
MAX_DEPTH = 2
RATIO_LIMIT = 100                            # uncompressed/compressed bomb threshold
TOTAL_BUDGET_SEC = 12                        # whole-scanner wall-clock (< 15s pipeline)
MAX_ARCHIVES = 2000
_CHUNK = 65536

# Exceptions a hostile/corrupt member can raise while being read. zlib.error
# (corrupt DEFLATE stream) inherits straight from Exception, NOT from any of the
# zipfile/tarfile/OS error classes, so it must be named explicitly or it crashes
# the whole scan.
_MEMBER_READ_ERRORS = (OSError, EOFError, zipfile.BadZipFile, tarfile.TarError,
                       RuntimeError, zlib.error)

# Extensions to try when a member's own extension is unrecognized — the member
# name is attacker-controlled, so a payload must not be able to dodge SAST by
# omitting or forging its extension.
_SNIFF_EXTS = (".py", ".js", ".sh")

# Leading-byte signatures. An archive renamed to a non-archive extension (e.g. a
# zip saved as `.instructions.docx.txt`, the Trail of Bits context-loader bypass)
# is invisible to extension gating, so we sniff CONTENT before deciding. tar has
# no leading magic — its `ustar` marker sits at offset 257.
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_UNSUPPORTED_MAGIC = (
    b"7z\xbc\xaf\x27\x1c",   # 7-Zip
    b"\xfd7zXZ\x00",         # xz
    b"Rar!\x1a\x07\x00",     # RAR4
    b"Rar!\x1a\x07\x01",     # RAR5
    b"\x28\xb5\x2f\xfd",     # zstd
    b"MSCF",                 # cab
)
_SNIFF_BYTES = 265  # enough to reach the tar `ustar` marker at offset 257

# OOXML (Office Open XML) members that are executable — a Word/Excel/PowerPoint
# document never legitimately ships a script or native binary inside its zip.
_SCRIPT_MEMBER_EXTS = (".sh", ".bash", ".zsh", ".ksh", ".py", ".pyw", ".rb",
                       ".pl", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".command",
                       ".scpt", ".js", ".mjs", ".cjs", ".vbs", ".vbe", ".jse",
                       ".wsf", ".exe", ".dll", ".so", ".dylib", ".com", ".msi",
                       ".scr", ".app", ".deb", ".rpm", ".pkg", ".jar")


def _archive_kind(name):
    low = name.lower()
    for ext in _TAR_EXTS:  # check compound .tar.* before single exts
        if low.endswith(ext):
            return "tar"
    _, ext = os.path.splitext(low)
    if ext in _ZIP_EXTS:
        return "zip"
    if ext in _TAR_EXTS:
        return "tar"
    if ext in _UNSUPPORTED_EXTS:
        return "unsupported"
    return None


def _sniff_archive_kind(file_path):
    """Content-based archive detection by leading-byte magic. Catches an archive
    whose extension is forged or dropped. Returns the same vocabulary as
    _archive_kind ('zip'/'tar'/'unsupported') or None. gzip/bzip2 streams route
    to 'tar' because tarfile auto-detects their compression."""
    try:
        with open(file_path, "rb") as f:
            head = f.read(_SNIFF_BYTES)
    except OSError:
        return None
    if head.startswith(_ZIP_MAGIC):
        return "zip"
    if head.startswith((b"\x1f\x8b", b"BZh")):  # gzip / bzip2 stream
        return "tar"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    for magic in _UNSUPPORTED_MAGIC:
        if head.startswith(magic):
            return "unsupported"
    # Leading magic can be hidden behind a stub (self-extracting / polyglot zip):
    # zipfile reads the end-of-central-directory at EOF, so such a file opens
    # fine yet has no PK at offset 0. is_zipfile locates the EOCD, catching it.
    try:
        if zipfile.is_zipfile(file_path):
            return "zip"
    except OSError:
        pass
    return None


def _is_ooxml(names):
    """An OOXML container has the content-types manifest plus a recognised office
    payload root. This is the structural signature, not the file extension."""
    return "[Content_Types].xml" in names and any(
        n.startswith(("word/", "xl/", "ppt/", "visio/")) for n in names)


def _is_script_member(name, data):
    """A member is a script if its name carries a script extension or its bytes
    start with a shebang. Detection is structural — payload content is irrelevant
    (a benign-looking `echo` is still an executable that should never be here)."""
    if name.lower().endswith(_SCRIPT_MEMBER_EXTS):
        return True
    return data is not None and data[:2] == b"#!"


def _office_exec_finding(label, vpath, member_name, reason):
    """A HIGH structural finding for an executable smuggled in an Office document.
    Shared by the name-based (pre-read) and shebang-based (post-read) checks."""
    return _finding(
        "high", "Executable script smuggled in Office document",
        f"{vpath} {reason} inside an OOXML document structure; Office files never "
        f"legitimately contain executable scripts.",
        label, "executable-in-office-doc", member_name)


def _finding(severity, title, desc, file, category, snippet=""):
    return core.Finding(
        scanner=SCANNER_NAME, severity=severity, title=title, description=desc,
        file=file, line=0, snippet=snippet, category=category,
    )


def _max_sev(findings):
    for sev in ("critical", "high", "medium", "low"):
        if any(f.severity == sev for f in findings):
            return sev
    return "low"


def _emit_inner(label, inner, findings):
    """Emit the archive-indirection summary plus the member findings, if any.
    Shared by _scan_zip and _scan_tar (identical emit block)."""
    if not inner:
        return
    findings.append(_finding(_max_sev(inner), "Payload hidden inside archive",
                             f"{label} contains {len(inner)} finding(s) in its members "
                             f"(archive indirection — opaque to source scanners).",
                             label, "archive-indirection"))
    findings.extend(inner)


def _over_budget(state):
    return state["files"] >= MAX_TOTAL_FILES or (time.monotonic() - state["t0"]) > TOTAL_BUDGET_SEC


def _scan_member_text(data, vpath):
    """Run the four in-process detectors over a decoded member (bounded to
    MEMBER_SCAN_BYTES so one large member cannot overrun the budget). Returns
    inner findings carrying vpath."""
    window = data[:MEMBER_SCAN_BYTES]
    # Binary members (embedded fonts, images, compiled blobs) are not source code;
    # decoding them as text and running SAST produces garbage matches. Detect
    # binary by the RATIO of non-text bytes, NOT a single null — a lone null is
    # trivially prepended by an attacker to blind every text detector, so the
    # sentinel-byte test is unsafe. A real font/image is densely non-text; a
    # script with a stray null is overwhelmingly printable and still scanned.
    # Structural/nested-archive checks already ran in the caller.
    if window:
        nontext = sum(1 for b in window if b < 9 or (13 < b < 32))
        if nontext / len(window) > 0.30:
            return []
    text = window.decode("utf-8", errors="replace")
    out = []
    ext = os.path.splitext(vpath)[1].lower()
    if ext in scan_sast._PACK_EXTENSIONS:
        out.extend(scan_sast.scan_text(text, vpath, ext=ext))
    else:
        # Untrusted member name: don't let a missing/forged extension dodge the
        # SAST pack. Sniff as the common code languages and dedup.
        seen = set()
        for sniff in _SNIFF_EXTS:
            for f in scan_sast.scan_text(text, vpath, ext=sniff):
                key = (f.rule_id, f.line, f.title)
                if key not in seen:
                    seen.add(key)
                    out.append(f)
    out.extend(core.scan_text_trifecta(text, vpath))
    out.extend(scan_secrets.scan_text(text, vpath))
    out.extend(scan_skill_threats.scan_content(text, vpath))
    return out


def _stream_read(fh, claimed_size, compress_size, state):
    """Read a member fileobj in chunks under the budget, MEASURING bytes (never
    trusting the header). Returns (data_or_None, status). status in
    {ok, bomb, cap, unreadable}. compress_size of 0 disables the ratio guard
    (tar members carry no per-member compressed size)."""
    if compress_size and claimed_size and (claimed_size / compress_size) > RATIO_LIMIT:
        return None, "bomb"
    chunks = []
    total = 0
    try:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            state["bytes"] += len(chunk)
            if state["bytes"] > MAX_TOTAL_UNCOMPRESSED:
                return None, "cap"
            if total > MAX_ENTRY_BYTES:
                if compress_size and (total / compress_size) > RATIO_LIMIT:
                    return None, "bomb"
                return None, "cap"
            chunks.append(chunk)
    except _MEMBER_READ_ERRORS:
        return None, "unreadable"
    return b"".join(chunks), "ok"


def _zip_source(source):
    """zipfile arg: a path (top-level, read from disk, never loaded whole) or
    bounded in-memory bytes (nested)."""
    return source if isinstance(source, str) else io.BytesIO(source)


def _scan_zip(source, label, depth, state, findings):
    try:
        zf = zipfile.ZipFile(_zip_source(source))
    except (zipfile.BadZipFile, OSError):
        findings.append(_finding("low", "Unreadable archive",
                                 f"{label} has a zip extension but is not a valid zip.",
                                 label, "opaque-archive"))
        return
    inner = []
    entries = 0
    try:
        with zf:
            try:
                infos = zf.infolist()
            except (zipfile.BadZipFile, OSError):
                findings.append(_finding("low", "Unreadable archive",
                                         f"{label} zip index is corrupt.", label, "opaque-archive"))
                return
            is_ooxml = _is_ooxml([i.filename for i in infos])
            for info in infos:
                if _over_budget(state):
                    state["incomplete"] = True
                    break
                if info.is_dir():
                    continue
                entries += 1
                if entries > MAX_ENTRIES_PER_ARCHIVE:
                    state["incomplete"] = True
                    break
                state["files"] += 1
                vpath = f"{label} -> {info.filename}"
                # Structural anomaly: a script inside an Office document. Flag on
                # the name alone (HIGH) so a member too large to read, or one with
                # a benign body, is still caught.
                if is_ooxml and info.filename.lower().endswith(_SCRIPT_MEMBER_EXTS):
                    inner.append(_office_exec_finding(
                        label, vpath, info.filename, "is a script member"))
                try:
                    fh = zf.open(info)
                except _MEMBER_READ_ERRORS:
                    findings.append(_finding("low", "Opaque archive member",
                                             f"Could not read {vpath} (encrypted or corrupt).",
                                             label, "opaque-archive", info.filename))
                    continue
                with fh:
                    data_m, status = _stream_read(fh, info.file_size, info.compress_size, state)
                # Shebang-based detection for script members whose extension is
                # forged (caught only once: name-based check above is extension-only).
                if (is_ooxml and status == "ok"
                        and not info.filename.lower().endswith(_SCRIPT_MEMBER_EXTS)
                        and _is_script_member(info.filename, data_m)):
                    inner.append(_office_exec_finding(
                        label, vpath, info.filename, "carries a shebang"))
                if status == "bomb":
                    findings.append(_finding("high", "Zip bomb member aborted",
                                             f"{vpath} decompresses past the safety ratio; aborted.",
                                             label, "zip-bomb", info.filename))
                    state["incomplete"] = True
                    break
                if status != "ok" or data_m is None:
                    if status == "cap":
                        state["incomplete"] = True
                    continue
                _dispatch_member(data_m, info.filename, vpath, depth, state, inner)
    finally:
        _emit_inner(label, inner, findings)


def _scan_tar(source, label, depth, state, findings):
    try:
        tf = tarfile.open(name=source) if isinstance(source, str) \
            else tarfile.open(fileobj=io.BytesIO(source))
    except (tarfile.TarError, OSError):
        findings.append(_finding("low", "Unreadable archive",
                                 f"{label} has a tar extension but is not a valid tar.",
                                 label, "opaque-archive"))
        return
    inner = []
    entries = 0
    try:
        with tf:
            # Lazy iteration: a .tgz that expands to gigabytes is bounded by the
            # entry/time caps below, NOT fully expanded by getmembers().
            tar_iter = iter(tf)
            while True:
                try:
                    member = next(tar_iter)
                except StopIteration:
                    break
                except (tarfile.TarError, OSError):
                    findings.append(_finding("low", "Unreadable archive",
                                             f"{label} tar index is corrupt.", label, "opaque-archive"))
                    break
                if _over_budget(state):
                    state["incomplete"] = True
                    break
                if not member.isfile():
                    if member.issym() or member.islnk():
                        findings.append(_finding("high", "Unsafe tar link member refused",
                                                 f"{label} contains a {'sym' if member.issym() else 'hard'}link "
                                                 f"member ({member.name}) that can point outside the archive; refused.",
                                                 label, "path-traversal", member.name))
                    elif member.ischr() or member.isblk() or member.isfifo():
                        findings.append(_finding("high", "Unsafe tar device member refused",
                                                 f"{label} contains a device/FIFO member ({member.name}); refused.",
                                                 label, "path-traversal", member.name))
                    continue
                entries += 1
                if entries > MAX_ENTRIES_PER_ARCHIVE:
                    state["incomplete"] = True
                    break
                state["files"] += 1
                vpath = f"{label} -> {member.name}"
                try:
                    fh = tf.extractfile(member)
                except (tarfile.TarError, OSError):
                    fh = None
                if fh is None:
                    continue
                with fh:
                    # compress_size=0: tar members carry no per-member compressed
                    # size, so the ratio guard is disabled and absolute caps apply.
                    data_m, status = _stream_read(fh, member.size, 0, state)
                if status != "ok" or data_m is None:
                    if status == "cap":
                        state["incomplete"] = True
                    continue
                _dispatch_member(data_m, member.name, vpath, depth, state, inner)
    finally:
        _emit_inner(label, inner, findings)


def _dispatch_member(data, member_name, vpath, depth, state, inner):
    """Scan a member; recurse into nested archives up to MAX_DEPTH."""
    kind = _archive_kind(member_name)
    if kind in ("zip", "tar"):
        if depth >= MAX_DEPTH:
            inner.append(_finding("low", "Nested archive past depth limit",
                                  f"{vpath} is a nested archive beyond depth {MAX_DEPTH}; not opened.",
                                  vpath, "archive-scan-incomplete"))
            return
        nested = []
        if kind == "zip":
            _scan_zip(data, vpath, depth + 1, state, nested)
        else:
            _scan_tar(data, vpath, depth + 1, state, nested)
        inner.extend(nested)
        return
    if kind == "unsupported":
        inner.append(_finding("low", "Unsupported nested archive type",
                              f"{vpath} is an archive format this scanner cannot open.",
                              vpath, "unsupported-archive-type"))
        return
    inner.extend(_scan_member_text(data, vpath))


def scan_repo(repo_path, ignore_patterns=None):
    all_findings = []
    state = {"files": 0, "bytes": 0, "t0": time.monotonic(), "incomplete": False}
    archives = 0
    for file_path, rel_path in core.walk_aux(
        repo_path, ignore_patterns=ignore_patterns, apply_size_cap=False
    ):
        kind = _archive_kind(os.path.basename(file_path))
        if kind is None:
            # Extension said "not an archive" — sniff CONTENT before trusting it.
            # An archive renamed to dodge extension gating is caught here.
            kind = _sniff_archive_kind(file_path)
        if kind is None:
            continue
        if archives >= MAX_ARCHIVES:
            all_findings.append(_finding("medium", "Archive scan incomplete (archive-count budget)",
                                         "Reached the maximum number of archives to scan; "
                                         "remaining archives not inspected.",
                                         rel_path, "archive-scan-incomplete"))
            break
        archives += 1

        if kind == "unsupported":
            all_findings.append(_finding("low", "Unsupported archive type",
                                         f"{rel_path} is an archive format this scanner cannot open "
                                         f"(.7z/.xz/.zst/.rar/.cab). Contents not inspected.",
                                         rel_path, "unsupported-archive-type"))
            continue

        # Fail loud per-archive (R12): if the cumulative budget is already spent,
        # name THIS archive as uninspected rather than emitting one generic note
        # that hides which archive a fan-out decoy starved out.
        if _over_budget(state):
            all_findings.append(_finding("medium", "Archive not scanned (budget exhausted)",
                                         f"{rel_path} was reached after the cumulative file/time budget "
                                         f"was spent (often by an earlier fan-out archive); not inspected.",
                                         rel_path, "archive-scan-incomplete"))
            continue

        # Reset per-archive byte budget (cumulative file count persists). Each
        # archive is isolated: a malformed one can never crash the whole scan.
        state["bytes"] = 0
        try:
            if kind == "zip":
                _scan_zip(file_path, rel_path, 0, state, all_findings)
            else:
                _scan_tar(file_path, rel_path, 0, state, all_findings)
        except Exception as exc:  # noqa: BLE001 - last-resort isolation per archive
            all_findings.append(_finding("low", "Archive could not be scanned",
                                         f"{rel_path} raised an unexpected error during scan "
                                         f"({type(exc).__name__}); skipped.",
                                         rel_path, "opaque-archive"))

    if state["incomplete"]:
        all_findings.append(_finding("low", "Archive scan incomplete",
                                     "One or more archives hit a safety cap (entry count, size, "
                                     "ratio, time, or depth); some members were not fully inspected.",
                                     repo_path, "archive-scan-incomplete"))
    return all_findings


def main():
    args = core.parse_common_args(sys.argv, "Archive Indirection Scanner")
    repo_path = args.repo_path
    core.emit_status(args.format, f"[*] Scanning archives in {repo_path}...")
    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = scan_repo(repo_path, ignore_patterns)
    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
