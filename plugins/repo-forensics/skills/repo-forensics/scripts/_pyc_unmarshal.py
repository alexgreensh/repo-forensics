#!/usr/bin/env python3
"""_pyc_unmarshal.py — isolated subprocess: parse and inspect a .pyc.

This runs as a DISPOSABLE CHILD of scan_bytecode.py. It parses the bounded
marshal stream in Python instead of passing attacker-controlled code objects
to CPython's native deserializer. Resource limits and a deny-default OS
sandbox remain in place. Unknown or malformed data fails closed, and the
parent reports the bytecode as unanalyzable.

Usage:  _pyc_unmarshal.py <pyc_path> <header_len>
Output: a text blob (NAME/CONST/OP lines) on stdout; exit 0 on success,
        non-zero on any failure. Bounded: memory, CPU, recursion depth,
        code-object count, output size.

The child reads names, string constants, and import opcodes. It never
constructs, executes, or evaluates a code object.
"""

import dis
from collections.abc import Mapping
import ctypes
import ctypes.util
import importlib.util
import sys

try:
    import resource
except ImportError:  # non-POSIX
    resource = None

MEM_CAP_BYTES = 512 * 1024 * 1024    # 512 MB address space ceiling
CPU_CAP_SEC = 10                     # CPU-seconds ceiling
MAX_CODE_OBJECTS = 5000              # bound nested-code fan-out
MAX_DEPTH = 50                       # bound nesting depth
MAX_OUTPUT_CHARS = 4 * 1024 * 1024   # 4 MB blob cap
MAX_INPUT_BYTES = 5 * 1024 * 1024
MAX_PARSED_OBJECTS = MAX_INPUT_BYTES  # Every parsed object consumes at least one byte.
SANDBOX_UNAVAILABLE = 5
ANALYSIS_LIMIT = 6
MAGIC_MISMATCH = 7


class AnalysisLimitExceeded(ValueError):
    """Partial disassembly must never be reported as complete."""


class _BoundedLines(list):
    def __init__(self):
        super().__init__()
        self.chars = 0

    def append(self, line):
        size = self.chars + len(line) + bool(self)
        if size > MAX_OUTPUT_CHARS:
            raise AnalysisLimitExceeded("bytecode output limit exceeded")
        super().append(line)
        self.chars = size


def _apply_sandbox():
    """Deny host capabilities before parsing untrusted marshal data.

    No files need opening after this point. Linux needs libseccomp; other
    unsupported systems skip disassembly instead of parsing without isolation.
    Resource limits alone cannot contain a native deserializer exploit.
    """
    if sys.platform == "darwin":
        system = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        system.sandbox_init.argtypes = [ctypes.c_char_p, ctypes.c_uint64,
                                       ctypes.POINTER(ctypes.c_char_p)]
        system.sandbox_init.restype = ctypes.c_int
        error = ctypes.c_char_p()
        return system.sandbox_init(b"(version 1)(deny default)", 0,
                                   ctypes.byref(error)) == 0
    if sys.platform != "linux":
        return False
    library = ctypes.util.find_library("seccomp")
    if not library:
        return False
    seccomp = ctypes.CDLL(library, use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                       ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.restype = None
    # Unknown syscalls return EPERM. The child keeps only stdin/out/err, so
    # read/write cannot reach host files through an inherited descriptor.
    context = seccomp.seccomp_init(0x00050001)  # SCMP_ACT_ERRNO(EPERM)
    if not context:
        return False
    try:
        for name in (
            "read", "write", "close", "fstat", "fstat64", "lseek",
            "mmap", "mmap2", "mprotect", "munmap", "mremap", "brk", "madvise",
            "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigreturn",
            "sigaltstack", "futex", "futex_time64", "clock_gettime",
            "clock_gettime64", "gettimeofday", "getpid", "gettid", "getrandom",
            "exit", "exit_group",
        ):
            number = seccomp.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number >= 0 and seccomp.seccomp_rule_add(context, 0x7FFF0000,
                                                       number, 0) != 0:
                return False
        return seccomp.seccomp_load(context) == 0
    finally:
        seccomp.seccomp_release(context)


def _apply_limits():
    """Best-effort CPU + memory ceilings. Silently no-op where unsupported.

    RLIMIT_AS is the strongest address-space cap but its hard limit is
    RLIM_INFINITY on macOS, where lowering it raises and is skipped; RLIMIT_DATA
    is tried as an additional heap lever there. The parent's subprocess timeout
    is the guaranteed backstop regardless of which rlimits the OS honours."""
    if resource is None:
        return
    for res_name, cap in (("RLIMIT_AS", MEM_CAP_BYTES), ("RLIMIT_DATA", MEM_CAP_BYTES),
                          ("RLIMIT_CPU", CPU_CAP_SEC)):
        res = getattr(resource, res_name, None)
        if res is None:
            continue
        try:
            _soft, hard = resource.getrlimit(res)
            if hard == resource.RLIM_INFINITY:
                new_hard = cap
            else:
                new_hard = min(cap, hard)
            resource.setrlimit(res, (min(cap, new_hard), new_hard))
        except (ValueError, OSError):
            pass


def _esc(value):
    """Escape a name/const so it stays on ONE output line and cannot be confused
    with the NAME/CONST/OP line protocol. Without this, a multi-line string
    constant would be truncated at its first newline (hiding a marker after it)
    and an attacker could forge fake `NAME`/`OP IMPORT_NAME` lines inside a
    constant. Backslash first, then the line/return chars."""
    return (str(value).replace("\\", "\\\\")
            .replace("\n", "\\n").replace("\r", "\\r"))


_PENDING = object()
_NULL = object()


class _Sequence:
    __slots__ = ("kind", "items")

    def __init__(self, kind):
        self.kind = kind
        self.items = []

    def __iter__(self):
        return iter(self.items)

    def __len__(self):
        return len(self.items)

    def __getitem__(self, index):
        return self.items[index]


class _DecodedCode:
    __slots__ = ("co_code", "co_consts", "co_names")

    def __init__(self, bytecode, consts, names):
        if (not isinstance(bytecode, bytes) or not isinstance(consts, _Sequence)
                or consts.kind not in "()"):
            raise ValueError("malformed code object")
        if not isinstance(names, _Sequence) or names.kind not in "()":
            raise ValueError("malformed code names")
        self.co_code = bytecode
        self.co_consts = consts
        self.co_names = names


class _Reader:
    """Bounded subset of CPython's marshal format, with no object construction.

    The two code layouts are from CPython 3.8-3.10 and 3.11-3.14. The caller
    requires the input magic to match this interpreter, so its opcode table and
    code layout agree with the file. Container references can be cyclic;
    references to incomplete code objects are rejected.
    """

    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.refs = []
        self.objects = 0

    def take(self, n):
        if n < 0 or n > len(self.data) - self.pos:
            raise ValueError("truncated marshal stream")
        value = self.data[self.pos:self.pos + n]
        self.pos += n
        return value

    def byte(self):
        return self.take(1)[0]

    def int32(self):
        return int.from_bytes(self.take(4), "little", signed=True)

    def count(self):
        n = self.int32()
        if n < 0 or n > len(self.data) - self.pos:
            raise ValueError("invalid marshal object count")
        return n

    def length(self):
        n = self.int32()
        if n < 0 or n > len(self.data) - self.pos:
            raise ValueError("invalid marshal data length")
        return n

    def sequence(self, n, depth, kind, index):
        value = _Sequence(kind)
        if index is not None:
            self.refs[index] = value
        for _ in range(n):
            item = self.read(depth + 1)
            if item is _NULL:
                raise ValueError("null in marshal sequence")
            value.items.append(item)
        return value

    def code(self, depth):
        if not (3, 8) <= sys.version_info[:2] <= (3, 15):
            raise ValueError("unsupported bytecode version")
        # CPython writes fixed-width integers before the object fields.
        for _ in range(5 if sys.version_info >= (3, 11) else 6):
            self.int32()
        bytecode = self.read(depth + 1)
        consts = self.read(depth + 1)
        names = self.read(depth + 1)
        if sys.version_info >= (3, 11):
            for _ in range(5):  # locals names/kinds, filename, name, qualname
                self.read(depth + 1)
            self.int32()  # first line
            self.read(depth + 1)  # line table
            self.read(depth + 1)  # exception table
        else:
            for _ in range(5):  # varnames, freevars, cellvars, filename, name
                self.read(depth + 1)
            self.int32()  # first line
            self.read(depth + 1)  # line table
        return _DecodedCode(bytecode, consts, names)

    def read(self, depth=0):
        self.objects += 1
        if depth > MAX_DEPTH or self.objects > MAX_PARSED_OBJECTS:
            raise AnalysisLimitExceeded("marshal traversal limit exceeded")
        tag = self.byte()
        flag, kind = bool(tag & 0x80), chr(tag & 0x7f)
        if kind == "r":
            index = self.int32()
            if index < 0 or index >= len(self.refs) or self.refs[index] is _PENDING:
                raise ValueError("invalid marshal reference")
            # CPython ignores FLAG_REF on a reference; it does not add a slot.
            return self.refs[index]
        # CPython does not register singleton tags in the reference table.
        index = len(self.refs) if flag and kind not in "0NFTS." else None
        if index is not None:
            self.refs.append(_PENDING)
        if kind == "0":
            value = _NULL
        elif kind in "NFTS.":
            value = None
        elif kind == "i":
            value = self.int32()
        elif kind == "I":
            self.take(8)
            value = None
        elif kind == "l":
            digits = abs(self.int32())
            if digits > (len(self.data) - self.pos) // 2:
                raise ValueError("invalid integer digit count")
            self.take(digits * 2)
            value = None
        elif kind in "gy":
            self.take(8 if kind == "g" else 16)
            value = None
        elif kind in "fx":
            for _ in range(1 if kind == "f" else 2):
                self.take(self.byte())
            value = None
        elif kind == "s":
            value = self.take(self.length())
        elif kind in "utaAzZ":
            n = self.byte() if kind in "zZ" else self.length()
            encoding = "latin-1" if kind in "aAzZ" else "utf-8"
            value = self.take(n).decode(encoding, "surrogatepass")
        elif kind in "()[<>":
            n = self.byte() if kind == ")" else self.count()
            value = self.sequence(n, depth, kind, index)
        elif kind == "{":
            if index is not None:
                self.refs[index] = None
            while True:
                key = self.read(depth + 1)
                if key is _NULL:
                    break
                self.read(depth + 1)
            value = None
        elif kind == ":":
            value = self.sequence(3, depth, kind, index)
        elif kind == "c":
            value = self.code(depth)
        else:
            raise ValueError("unknown marshal type")
        if index is not None:
            self.refs[index] = value
        return value


def _instructions(code):
    if len(code.co_code) % 2:
        raise ValueError("odd-length wordcode")
    extended = 0
    caches = getattr(dis, "_inline_cache_entries", None)
    # 3.15 ships the table as a frozendict: treat any mapping like a dict.
    if caches is not None and not isinstance(caches, (list, dict)) and isinstance(caches, Mapping):
        caches = dict(caches)
    if sys.version_info >= (3, 11) and (not isinstance(caches, (list, dict)) or not caches):
        raise AnalysisLimitExceeded("inline cache table unavailable")
    offset = 0
    while offset < len(code.co_code):
        op, arg = code.co_code[offset:offset + 2]
        arg |= extended
        name = dis.opname[op]
        if name == "EXTENDED_ARG":
            if arg > 0xffffff:
                raise AnalysisLimitExceeded("opcode argument limit exceeded")
            extended = arg << 8
        else:
            extended = 0
        if name == "IMPORT_NAME":
            if sys.version_info >= (3, 15):
                arg >>= 2  # low two bits carry the lazy-import flags (PEP 810)
            if arg >= len(code.co_names):
                raise ValueError("invalid import name index")
            target = code.co_names[arg]
            yield name, target if isinstance(target, str) else None
        else:
            # The parent consumes only import argvals; co_names and co_consts
            # are emitted separately for every opcode and string constant.
            yield name, None
        if isinstance(caches, list):
            if op >= len(caches):
                raise AnalysisLimitExceeded("inline cache table incomplete")
            cache_count = caches[op]
        elif isinstance(caches, dict):
            # Current CPython's dictionary lists only opcodes with caches.
            cache_count = caches.get(name, 0)
        else:
            cache_count = 0
        if not isinstance(cache_count, int) or cache_count < 0:
            raise AnalysisLimitExceeded("invalid inline cache count")
        offset += 2 * (1 + cache_count)
    if offset != len(code.co_code):
        raise ValueError("truncated inline cache")


def _walk_code(code, out, seen, depth):
    """Recursively collect names, string constants, and opcodes. dis does NOT
    recurse into nested code objects, so we walk co_consts ourselves — an
    os.system inside a function body lives in a nested CodeType."""
    if id(code) in seen:
        return
    if depth > MAX_DEPTH or len(seen) >= MAX_CODE_OBJECTS:
        raise AnalysisLimitExceeded("bytecode traversal limit exceeded")
    seen.add(id(code))

    for name in code.co_names:  # attrs, globals, imports
        if isinstance(name, str):
            out.append("NAME " + _esc(name))
    for opname, argval in _instructions(code):
        arg = (" " + _esc(argval)) if isinstance(argval, str) else ""
        out.append("OP " + opname + arg)
    seen_containers = set()

    def walk_const(const, const_depth):
        if const_depth > MAX_DEPTH:
            raise AnalysisLimitExceeded("bytecode traversal limit exceeded")
        if isinstance(const, str):
            out.append("CONST " + _esc(const))
        elif isinstance(const, _DecodedCode):
            _walk_code(const, out, seen, const_depth)
        elif isinstance(const, _Sequence):
            if id(const) in seen_containers:
                return
            if len(seen_containers) >= MAX_CODE_OBJECTS:
                raise AnalysisLimitExceeded("bytecode traversal limit exceeded")
            seen_containers.add(id(const))
            for item in const:
                walk_const(item, const_depth + 1)

    for const in code.co_consts:
        walk_const(const, depth + 1)


def main():
    _apply_limits()
    if len(sys.argv) != 3:
        sys.exit(2)
    pyc_path = sys.argv[1]
    try:
        header_len = int(sys.argv[2])
    except ValueError:
        sys.exit(2)

    with open(pyc_path, "rb") as f:
        magic = f.read(4)
        f.seek(header_len)
        raw = f.read(MAX_INPUT_BYTES + 1)
    if magic != importlib.util.MAGIC_NUMBER:
        sys.exit(MAGIC_MISMATCH)
    if len(raw) > MAX_INPUT_BYTES:
        sys.exit(ANALYSIS_LIMIT)

    try:
        sandboxed = _apply_sandbox()
    except (OSError, AttributeError):
        sandboxed = False
    if not sandboxed:
        sys.exit(SANDBOX_UNAVAILABLE)

    # Parse only after the OS has removed the child's host capabilities.
    code = _Reader(raw).read()
    if not isinstance(code, _DecodedCode):
        sys.exit(3)

    out = _BoundedLines()
    _walk_code(code, out, set(), 0)
    blob = "\n".join(out)
    # Write via the byte buffer with surrogatepass: a string constant carrying a
    # lone surrogate (e.g. "\ud800", which marshal round-trips fine) would crash
    # a plain text-mode stdout.write with UnicodeEncodeError, downgrading the
    # whole .pyc to "unanalyzable" and dropping any real payload beside it.
    sys.stdout.buffer.write(blob.encode("utf-8", "surrogatepass"))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except AnalysisLimitExceeded:
        sys.exit(ANALYSIS_LIMIT)
    except BaseException:
        # Any malformed or unsupported stream is an unanalyzable finding in the
        # parent. No traceback noise and no partial output.
        sys.exit(4)
