#!/usr/bin/env python3
"""_pyc_unmarshal.py — isolated subprocess: unmarshal + disassemble a .pyc.

This runs as a DISPOSABLE CHILD of scan_bytecode.py. marshal.loads is
documented by CPython as unsafe against erroneous or maliciously constructed
data and can abort the interpreter at the C level (SIGSEGV/SIGABRT) — a crash a
parent try/except cannot catch. By doing the unmarshal here, in a throwaway
process under CPU + address-space rlimits, a hostile .pyc can only ever kill
THIS process. The parent maps any non-zero/negative exit to an "unanalyzable
bytecode" finding and the scan continues. This is the U2 user-safety property
(KTD6): never let attacker-controlled bytecode crash or hang the real scan.

Usage:  _pyc_unmarshal.py <pyc_path> <header_len>
Output: a text blob (NAME/CONST/OP lines) on stdout; exit 0 on success,
        non-zero on any failure. Bounded: memory, CPU, recursion depth,
        code-object count, output size.

The child only ever DISASSEMBLES the code object (dis). It never exec()s,
eval()s, or otherwise runs it.
"""

import dis
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
    if depth > MAX_DEPTH or len(seen) >= MAX_CODE_OBJECTS:
        return
    if id(code) in seen:
        return
    seen.add(id(code))

    for name in getattr(code, "co_names", ()):  # attrs, globals, imports
        out.append("NAME " + _esc(name))
    for const in getattr(code, "co_consts", ()):
        if isinstance(const, str):
            out.append("CONST " + _esc(const))
    try:
        for instr in dis.get_instructions(code):
            arg = (" " + _esc(instr.argval)) if isinstance(instr.argval, str) else ""
            out.append("OP " + instr.opname + arg)
    except (ValueError, TypeError):
        pass
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
        raw = f.read()

    # The unsafe step. If it crashes the interpreter, this process dies and the
    # parent records "unanalyzable" — the scan is unharmed.
    code = marshal.loads(raw)
    if not isinstance(code, types.CodeType):
        sys.exit(3)

    out = []
    _walk_code(code, out, set(), 0)
    blob = "\n".join(out)
    if len(blob) > MAX_OUTPUT_CHARS:
        blob = blob[:MAX_OUTPUT_CHARS]
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
    except BaseException:
        # Any failure (EOFError/ValueError/MemoryError from a corrupt or hostile
        # marshal stream, recursion errors, etc.) is a non-zero exit the parent
        # reads as "unanalyzable". No traceback noise, no partial output.
        sys.exit(4)
