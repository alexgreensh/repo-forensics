#!/usr/bin/env python3
"""_pyc_unmarshal.py — isolated subprocess: unmarshal + disassemble a .pyc.

This runs as a DISPOSABLE CHILD of scan_bytecode.py. marshal.loads is
documented by CPython as unsafe against erroneous or maliciously constructed
data and can abort the interpreter at the C level (SIGSEGV/SIGABRT) — a crash a
parent try/except cannot catch. By doing the unmarshal here, in a throwaway
process under CPU + address-space rlimits and a deny-default OS sandbox, a
hostile .pyc cannot access host files, network, or spawn processes. The parent
maps any non-zero/negative exit to an "unanalyzable bytecode" finding and the
scan continues. This is the U2 user-safety property
(KTD6): never let attacker-controlled bytecode crash or hang the real scan.

Usage:  _pyc_unmarshal.py <pyc_path> <header_len>
Output: a text blob (NAME/CONST/OP lines) on stdout; exit 0 on success,
        non-zero on any failure. Bounded: memory, CPU, recursion depth,
        code-object count, output size.

The child only ever DISASSEMBLES the code object (dis). It never exec()s,
eval()s, or otherwise runs it.
"""

import dis
import ctypes
import ctypes.util
import marshal
import sys
import types

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
SANDBOX_UNAVAILABLE = 5
ANALYSIS_LIMIT = 6


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


def _walk_code(code, out, seen, depth):
    """Recursively collect names, string constants, and opcodes. dis does NOT
    recurse into nested code objects, so we walk co_consts ourselves — an
    os.system inside a function body lives in a nested CodeType."""
    if id(code) in seen:
        return
    if depth > MAX_DEPTH or len(seen) >= MAX_CODE_OBJECTS:
        raise AnalysisLimitExceeded("bytecode traversal limit exceeded")
    seen.add(id(code))

    for name in getattr(code, "co_names", ()):  # attrs, globals, imports
        out.append("NAME " + _esc(name))
    for const in getattr(code, "co_consts", ()):
        if isinstance(const, str):
            out.append("CONST " + _esc(const))
    for instr in dis.get_instructions(code):
        arg = (" " + _esc(instr.argval)) if isinstance(instr.argval, str) else ""
        out.append("OP " + instr.opname + arg)
    for const in getattr(code, "co_consts", ()):
        if isinstance(const, types.CodeType):
            _walk_code(const, out, seen, depth + 1)


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
        f.seek(header_len)
        raw = f.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        sys.exit(ANALYSIS_LIMIT)

    try:
        sandboxed = _apply_sandbox()
    except (OSError, AttributeError):
        sandboxed = False
    if not sandboxed:
        sys.exit(SANDBOX_UNAVAILABLE)

    # Parse only after the OS has removed the child's host capabilities.
    code = marshal.loads(raw)
    if not isinstance(code, types.CodeType):
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
        # Any failure (EOFError/ValueError/MemoryError from a corrupt or hostile
        # marshal stream, recursion errors, etc.) is a non-zero exit the parent
        # reads as "unanalyzable". No traceback noise, no partial output.
        sys.exit(4)
