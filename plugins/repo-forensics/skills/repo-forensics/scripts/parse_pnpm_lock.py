#!/usr/bin/env python3
"""parse_pnpm_lock.py - pnpm-lock.yaml transitive dependency parser.

Addresses Marc Gadsdon's issue #5 suggestion #4: pnpm-lock.yaml currently only
gets URL scanning via scan_lockfile(). There's no parse_pnpm_lock() equivalent,
so pnpm projects get NO IOC checks, NO typosquatting checks, and NO compromised
version checks on actual packages.

Supports lockfileVersion 6.x and 9.x (the two formats in active use as of
2026-04-05). v5 and older are legacy; v10 does not exist yet. When the file
format cannot be identified, the parser returns an empty dict rather than
guessing.

This is a regex-based parser against a restricted YAML subset, not a full
YAML parser. The design trade-off is explicit: we stay zero-dependency (no
PyYAML) and we only need the `packages:` section. For anything more complex
than name@version extraction, the scanner should fall back to generic URL
scanning in scan_lockfile().

Created 2026-04-05 as part of PR#A (version-pinned IOC upgrade).
"""

import re
import sys


# Matches package keys inside the `packages:` section. Examples of what it
# catches (v6 and v9 formats):
#   /chalk@5.6.1:                                        -> ('chalk', '5.6.1')
#   /@nx/devkit@20.9.0:                                  -> ('@nx/devkit', '20.9.0')
#   chalk@5.6.1:                                         -> ('chalk', '5.6.1')
#   '@nx/devkit@20.9.0':                                 -> ('@nx/devkit', '20.9.0')
#   '@ctrl/tinycolor@4.1.1(peer@4.5.6)':                 -> ('@ctrl/tinycolor', '4.1.1')
#   'react@18.2.0(react-dom@18.2.0)':                    -> ('react', '18.2.0')
#   'chalk@5.6.1(foo@1.0.0)(bar@2.0.0)':                 -> ('chalk', '5.6.1')  [chained]
#   '@babel/runtime@7.22.15(foo@1.0.0(bar@2.0.0))':      -> ('@babel/runtime', '7.22.15')  [nested]
#
# NOTE (2026-04-05 review fix): the previous `(?:\([^)]*\))?` pattern only
# matched a single flat peer-dep group — it silently dropped chalk@5.6.1 if
# the key was `'chalk@5.6.1(foo@1.0.0)(bar@2.0.0)'` because the second `(`
# was never consumed. Real pnpm v9 monorepos emit chained and nested peer
# suffixes constantly. Changed to `(?:\(.*\))?` which greedily consumes
# everything to the last `)` on the line. Greedy `.*` is safe here because
# it's anchored by the `:\s*$` line-end terminator — backtracking is linear
# in the length of the single line.
_PACKAGE_KEY_RE = re.compile(
    r"^\s+"                           # must be indented (inside packages:)
    r"['\"]?"                         # optional leading quote
    r"/?"                             # optional leading slash (v6 style)
    r"(?P<name>@[\w.-]+/[\w.-]+|[\w.-]+)"  # package name (scoped or bare)
    r"@"
    r"(?P<version>[\w][\w.\-+]*)"     # version (must start with alnum)
    r"(?:\(.*\))?"                    # optional peer-dep suffix (chained or nested)
    r"['\"]?"
    r":\s*$"
)

_LOCKFILE_VERSION_RE = re.compile(
    r"^lockfileVersion:\s*['\"]?([\d.]+)['\"]?\s*$",
    re.MULTILINE,
)

# Hard limits to prevent DoS via adversarial lockfiles
_MAX_LOCKFILE_BYTES = 50 * 1024 * 1024   # 50MB (pnpm lockfiles can be large)
_MAX_PACKAGES = 200_000                   # generous upper bound


def detect_lockfile_version(content):
    """Return the lockfile version string (e.g. '6.0', '9.0') or None."""
    m = _LOCKFILE_VERSION_RE.search(content)
    if not m:
        return None
    return m.group(1)


def is_supported_version(version):
    """Return True if we can parse this lockfile version."""
    if not version:
        return False
    try:
        major = int(version.split('.')[0])
    except (ValueError, IndexError):
        return False
    return major in (6, 9)


def parse_pnpm_lock(filepath):
    """Parse a pnpm-lock.yaml file and extract all package@version pairs.

    Returns a dict mapping package name -> version string. Only the `packages:`
    section is scanned. Peer-dep suffixes like '(peer@4.5.6)' are stripped.
    Package names are preserved as-typed (including @scope/name form).

    On any error (missing file, unsupported version, corrupt content), returns
    an empty dict rather than raising. Errors are logged to stderr for debug.
    """
    try:
        import os
        size = os.path.getsize(filepath)
        if size > _MAX_LOCKFILE_BYTES:
            print(
                f"[!] pnpm lockfile too large ({size} bytes, max "
                f"{_MAX_LOCKFILE_BYTES}): {filepath}",
                file=sys.stderr,
            )
            return {}
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Could not read pnpm lockfile {filepath}: {e}", file=sys.stderr)
        return {}

    version = detect_lockfile_version(content)
    if not is_supported_version(version):
        print(
            f"[!] Unsupported pnpm lockfile version {version!r} in {filepath} "
            f"(supported: 6.x, 9.x)",
            file=sys.stderr,
        )
        return {}

    # Find the `packages:` section and extract keys until the indentation
    # level goes back to top-level.
    result = {}
    in_packages = False
    packages_indent = None
    line_count = 0

    for raw_line in content.split('\n'):
        line_count += 1
        if len(result) > _MAX_PACKAGES:
            print(
                f"[!] pnpm lockfile exceeds max packages ({_MAX_PACKAGES}): "
                f"{filepath}",
                file=sys.stderr,
            )
            break

        # Entering the packages: block
        if not in_packages:
            if raw_line.rstrip() == 'packages:':
                in_packages = True
                packages_indent = None
            continue

        # Blank lines don't end the block
        if not raw_line.strip():
            continue

        # Skip comment lines entirely — they must NOT influence
        # packages_indent, or an attacker plants a comment at indent 6
        # and all real package entries at indent 2 get silently dropped.
        # (Security review A3, 2026-04-05.)
        stripped_test = raw_line.lstrip()
        if stripped_test.startswith('#'):
            continue

        # Leading whitespace tells us if we're still inside packages:
        stripped = stripped_test
        indent = len(raw_line) - len(stripped)

        if packages_indent is None:
            # First non-blank, non-comment line inside packages: sets the
            # expected indent. pnpm uses 2 spaces typically. Reject
            # implausible indents (> 8 spaces) to catch adversarial files.
            if indent > 8:
                print(
                    f"[!] Rejecting pnpm lockfile with implausible "
                    f"packages_indent={indent}: {filepath}",
                    file=sys.stderr,
                )
                return {}
            packages_indent = indent

        # If we see a line at indent 0 after entering, we've left the block
        # (e.g. `snapshots:` section in v9)
        if indent == 0 and stripped:
            break

        # Only match package key lines at the expected depth. Nested metadata
        # (resolution, dependencies, engines) lives at deeper indent.
        if indent != packages_indent:
            continue

        m = _PACKAGE_KEY_RE.match(raw_line)
        if m:
            name = m.group('name')
            version_str = m.group('version')
            if name and version_str:
                # Preserve first occurrence if a package appears multiple times
                # with different versions (pnpm aliasing).
                if name not in result:
                    result[name] = version_str

    return result


def main():
    """CLI: python3 parse_pnpm_lock.py <lockfile>"""
    if len(sys.argv) != 2:
        print("Usage: parse_pnpm_lock.py <pnpm-lock.yaml>", file=sys.stderr)
        sys.exit(2)
    result = parse_pnpm_lock(sys.argv[1])
    import json
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
