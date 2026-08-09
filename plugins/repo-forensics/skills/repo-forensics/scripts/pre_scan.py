#!/usr/bin/env python3
"""
pre_scan.py - PreToolUse hook handler for repo-forensics v2.
Lightweight pre-execution gate that blocks known-malicious packages and
pipe-to-shell patterns BEFORE the command runs.

Runs as a Claude Code PreToolUse hook. Reads JSON from stdin, outputs JSON
to stdout. Fast path (<10ms for non-matching commands). IOC-only — no
subprocess calls, no full scans (those run post-execution in auto_scan.py).

Design constraints (all critical for safety):
  - MUST NOT call subprocess or spawn any child process (avoids recursive
    hook triggers and keeps latency under 200ms even on IOC matches)
  - MUST NOT block commands when IOC database is unavailable (graceful
    degradation — approve on error, never silently block legitimate work)
  - MUST output valid JSON to stdout in all code paths (empty {} = approve)
  - MUST exit 0 for approve, exit 2 for block (Claude Code convention)

Created by Alex Greenshpun
"""

import json
import os
import re
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

# --- Pattern Detection ---
# NOTE: These patterns are intentionally duplicated from auto_scan.py.
# pre_scan.py MUST remain standalone (no imports from auto_scan, no subprocess)
# to guarantee <10ms latency and zero recursion risk. If you update patterns
# here, update auto_scan.py too (and vice versa).

# Optional package-manager flags between the tool name and its subcommand
# (`pnpm -r add x`, `pnpm --filter web add x`, `uv --project /p add x`). Each
# unit is one -flag (first char after the dash(es) is a non-dash, so dash runs
# fail fast — no ReDoS) plus an optional value token that must NOT be a
# subcommand keyword. Kept identical in auto_scan.py — update both.
_PM_FLAGS = (
    r'(?:-{1,2}[^-\s]\S*'
    r'(?:\s+(?!(?:install|i|add|update|sync|pip|tool|remove|run)\b)[^-\s]\S*)?'
    r'\s+)*'
)

INSTALL_PATTERNS = [
    # uv/pnpm must precede pip/npm: the patterns are unanchored, so
    # 'uv pip install x' / 'pnpm install x' substring-match the pip/npm entries.
    # _PM_FLAGS covers flags between the tool and subcommand (monorepo forms).
    (re.compile(r'uv\s+' + _PM_FLAGS + r'(?:add|pip\s+install|tool\s+install)\s+(.+)'), 'uv_install'),
    (re.compile(r'pip3?\s+install\s+(.+)'), 'pip_install'),
    (re.compile(r'pnpm\s+' + _PM_FLAGS + r'(?:install|i|add|update)\s+(.+)'), 'pnpm_install'),
    (re.compile(r'bun\s+' + _PM_FLAGS + r'(?:install|i|add|update)\s+(.+)'), 'bun_install'),
    (re.compile(r'npm\s+(?:install|i)\s+(.+)'), 'npm_install'),
    (re.compile(r'npm\s+update\s+(.+)'), 'npm_install'),
    (re.compile(r'yarn\s+add\s+(.+)'), 'yarn_add'),
    (re.compile(r'gem\s+(?:install|update)\s+(.+)'), 'gem_install'),
    (re.compile(r'cargo\s+install\s+(.+)'), 'cargo_install'),
    (re.compile(r'go\s+(?:get|install)\s+(.+)'), 'go_install'),
    (re.compile(r'brew\s+(?:install|upgrade)\s+(.+)'), 'brew_install'),
    (re.compile(r'openclaw\s+(?:skills|plugins)\s+(?:install|update)\s+(.+)'), 'openclaw_install'),
    (re.compile(r'clawhub\s+(?:install|publish)\s+(.+)'), 'openclaw_install'),
]

_DOWNLOADERS = r'(?:curl|wget|aria2c|http|Invoke-WebRequest)'
_SHELLS = r'(?:sudo\s+)?(?:/[\w/.-]*/)?(?:bash|zsh|dash|ksh|csh|tcsh|fish|pwsh|sh)(?!\w)'
_BASE64_PIPE = r'base64\s+(?:-d|--decode)\s*\|'

PIPE_TO_SHELL = re.compile(
    r'(?:'
    r'(?:' + _DOWNLOADERS + r')\s+[^|]*\|\s*(?:' + _BASE64_PIPE + r'\s*)?(?:' + _SHELLS + r'|iex)'
    r'|' + _BASE64_PIPE + r'\s*(?:' + _SHELLS + r'|iex)'
    r'|(?:' + _DOWNLOADERS + r')\s+[^>]*>\s*/tmp/[^\s;]+\s*(?:;|&&?)\s*(?:' + _SHELLS + r')\s+/tmp/'
    r')',
    re.IGNORECASE,
)

# Strip ONLY the flag token itself, never a following "value" — otherwise a
# boolean flag swallows the next package (`npm install foo --save-exact keyv@6.0.0`
# hid keyv). A real value-flag's argument (a URL, a path) is left as a token, but
# it harmlessly matches no IOC. Every non-flag token must reach the IOC checks.
INSTALL_FLAGS = re.compile(r'\s+--?[a-zA-Z][\w-]*')


def parse_hook_input():
    """Read and parse PreToolUse JSON from stdin."""
    try:
        raw = sys.stdin.read(1_048_576)  # 1MB max
        if not raw.strip():
            return None
        return json.loads(raw)
    except (json.JSONDecodeError, IOError):
        return None


def extract_command(data):
    """Extract the bash command from hook payload."""
    if not data:
        return None
    if data.get('tool_name', '') != 'Bash':
        return None
    tool_input = data.get('tool_input', {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except json.JSONDecodeError:
            return None
    return tool_input.get('command', '')


def detect_install_command(command):
    """Match command against install patterns.
    Returns (pattern_type, match_obj) or (None, None)."""
    if not command:
        return None, None
    if PIPE_TO_SHELL.search(command):
        return 'pipe_to_shell', None
    for pattern, ptype in INSTALL_PATTERNS:
        m = pattern.search(command)
        if m:
            return ptype, m
    return None, None


def extract_package_names(pattern_type, match):
    """Extract package names from install command match."""
    if not match:
        return []
    if pattern_type not in ('pip_install', 'npm_install', 'yarn_add', 'gem_install',
                            'cargo_install', 'go_install', 'brew_install', 'openclaw_install',
                            'uv_install', 'bun_install', 'pnpm_install'):
        return []
    raw = match.group(1)
    cleaned = INSTALL_FLAGS.sub('', raw).strip()
    names = [n.strip() for n in cleaned.split() if n.strip() and not n.startswith('-')]
    if pattern_type in ('pip_install', 'uv_install'):
        names = [re.split(r'[>=<!\[\];@]', n)[0] for n in names]
    return names


# npm-family installers pin versions as `name@version`, which the pip/uv strip
# in extract_package_names() deliberately leaves untouched. These are the
# pattern types whose tokens get the split treatment below.
NPM_FAMILY_INSTALLS = ('npm_install', 'yarn_add', 'pnpm_install', 'bun_install')


def split_npm_name_version(token):
    """Split an npm-family install token into (base_name, version).

    The version separator `@` collides with the leading `@` of a scoped name,
    so split on the LAST `@` and only when it is not that scope marker:
      keyv@6.0.0        -> ('keyv', '6.0.0')
      @scope/pkg@1.2.3  -> ('@scope/pkg', '1.2.3')
      @scope/pkg        -> ('@scope/pkg', None)
      keyv              -> ('keyv', None)

    Also resolves the install forms that used to smuggle a malicious package
    past the name/version checks:
      npm alias   local@npm:keyv@6.0.0        -> ('keyv', '6.0.0')
      tarball URL https://reg/keyv/-/keyv-6.0.0.tgz -> ('keyv', '6.0.0')
      git URL     git+https://gh/x/keyv.git   -> ('keyv', None)
    """
    # npm alias: <localname>@npm:<realname>@<version> — resolve to the REAL pkg.
    alias = re.search(r'@npm:(.+)$', token)
    if alias:
        token = alias.group(1)  # realname[@version]

    # URL / git / tarball forms: extract the package name (and version if a
    # tarball encodes one). check_ioc_packages compares whole tokens, so a URL
    # never matches a name — pull the name out so the IOC checks see it.
    if re.match(r'(?i)^(https?://|git\+|git://|ssh://|file:)', token):
        # scoped tarball: .../@scope/name/-/name-1.2.3.tgz -> ('@scope/name', '1.2.3')
        scoped = re.search(
            r'/(@[^/@\s]+/[^/@\s]+)/-/[^/@\s]+-(\d+\.\d+\.\d+[^/\s]*)\.(?:tgz|tar\.gz)$', token)
        if scoped:
            return scoped.group(1), scoped.group(2)
        # unscoped tarball: .../<name>-<version>.tgz
        tgz = re.search(r'/([^/@\s]+)-(\d+\.\d+\.\d+[^/\s]*)\.(?:tgz|tar\.gz)$', token)
        if tgz:
            return tgz.group(1), tgz.group(2)
        # git repo: .../<name>(.git)
        git = re.search(r'/([^/@\s]+?)(?:\.git)?(?:#.*)?$', token)
        if git:
            return git.group(1), None
        return token, None

    idx = token.rfind('@')
    if idx <= 0:
        return token, None
    version = token[idx + 1:]
    return token[:idx], (version or None)


def _semver_tuple(v):
    """Best-effort (major, minor, patch) from a version string. Non-numeric
    trailing segments (prerelease/build) are ignored for comparison."""
    nums = []
    for part in re.split(r'[.\-+]', v.strip()):
        if part.isdigit():
            nums.append(int(part))
        else:
            break
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def _spec_could_match(spec, concrete):
    """Could the npm version SPEC (^1.2.0, ~1.2, >=1.0.0, 1.x, 1.2.3, =1.2.3)
    resolve to the concrete COMPROMISED version? The offline gate cannot query
    the registry, so this is deliberately CONSERVATIVE: it returns True whenever
    a range could include the compromised version (better to over-block one
    package than wave a worm through), but False for a clean exact version and
    for dist-tags like `latest`/`next`, which point at the maintainer's current
    — now-fixed — release and must stay installable.
    """
    spec = (spec or '').strip()
    if not spec:
        return False
    if spec.startswith('='):
        spec = spec[1:].strip()
    # A leading `v` on a numeric version (v6.0.0, =v6.0.0) is a VERSION, not a
    # dist-tag — strip it before the dist-tag test below, or `keyv@v6.0.0` (which
    # npm installs as exactly 6.0.0) would be waved through as if it were `latest`.
    spec = re.sub(r'^v(?=\d)', '', spec)
    # dist-tag / non-semver (latest, next, a branch) -> resolves to fixed release
    if re.match(r'^[A-Za-z]', spec):
        return False
    c = _semver_tuple(concrete)
    low = spec.lower().replace('*', 'x')
    # x-ranges: 6.x, 6.*, 6, 6.0.x
    if 'x' in low or re.match(r'^\d+(?:\.\d+)?$', spec):
        parts = low.split('.')
        for i, part in enumerate(parts):
            if part in ('x', ''):
                break
            if not part.isdigit() or (i < len(c) and int(part) != c[i]):
                return False
        return True
    m = re.match(r'^(\^|~|>=|<=|>|<)?\s*v?(\d+(?:\.\d+){0,2}[^\s]*)$', spec)
    if not m:
        return True  # unparseable range -> conservative block
    op = m.group(1) or '='
    t = _semver_tuple(m.group(2))
    if op == '=':
        return c == t
    if op == '^':  # >= t, < next-major (special-cased for 0.x per npm semantics)
        if t[0] > 0:
            return c >= t and c[0] == t[0]
        if t[1] > 0:
            return c >= t and c[0] == 0 and c[1] == t[1]
        return c == t
    if op == '~':  # >= t, < next-minor
        return c >= t and c[0] == t[0] and c[1] == t[1]
    if op == '>=':
        return c >= t
    if op == '>':
        return c > t
    if op == '<=':
        return c <= t
    if op == '<':
        return c < t
    return True


def check_ioc_pinned_versions(pattern_type, package_names, iocs=None):
    """Check npm-family `name@version` tokens against the IOC database.

    Complements check_ioc_packages(), which compares whole tokens against the
    name sets: a pinned token like `rimarf@1.0.0` matches no name, so it used
    to be approved while bare `rimarf` was blocked. Blocks when either the base
    name is a known-malicious package, or the exact pinned version appears in
    the shipped compromised_versions map. Returns a list of description strings.

    `iocs` may be passed pre-loaded so main() loads the IOC set once instead of
    each checker paying the disk+verify cost (the npm path calls both). When
    None, loads on its own (standalone/test use). Fail-open on load failure.
    """
    if pattern_type not in NPM_FAMILY_INSTALLS:
        return []
    if iocs is None:
        try:
            import ioc_manager
            iocs = ioc_manager.get_iocs()
        except (ImportError, AttributeError, KeyError, TypeError):
            return []

    all_malicious = iocs.get('malicious_npm', set()) | iocs.get('malicious_pypi', set())
    compromised_versions = iocs.get('compromised_versions', {})

    blocked = []
    for pkg in package_names:
        base, version = split_npm_name_version(pkg)
        base_lower = base.lower()
        # Check the RESOLVED base name first — for alias (foo@npm:rimarf) and git/URL
        # forms the base is malicious even with no pinned version, and the raw token
        # (which check_ioc_packages compares) never equals the resolved base. Must
        # run before the version-less skip below or these smuggle forms escape.
        if base_lower in all_malicious:
            label = f"{base}@{version}" if version is not None else base
            blocked.append(f"{label} (known-malicious package, any version)")
            continue
        if version is None:
            continue  # bare in-registry names are covered by check_ioc_packages()
        pkg_bad = compromised_versions.get(base_lower, {})
        if not pkg_bad:
            continue
        # exact pin
        if version in pkg_bad:
            blocked.append(f"{base}@{version} (compromised version, campaign: {pkg_bad[version]})")
            continue
        # range / x-range / comparator spec that could resolve to a compromised
        # version (e.g. keyv@^6.0.0 resolving to the bad 6.0.0). Conservative.
        for bad_ver, campaign in pkg_bad.items():
            if _spec_could_match(version, bad_ver):
                blocked.append(
                    f"{base}@{version} (version range may resolve to compromised "
                    f"{bad_ver}, campaign: {campaign})"
                )
                break
    return blocked


def check_ioc_packages(package_names, iocs=None):
    """Check package names against IOC database. Returns list of malicious names.

    Fail-open: if ioc_manager cannot be loaded at all, returns [] (approve).
    When the remote-feed cache is stale or absent, approves but emits a WARNING
    to stderr so the operator knows threat intelligence is degraded.

    `iocs` may be passed pre-loaded so main() loads the IOC set once (the npm
    path runs both checkers); when None it loads on its own.
    """
    if iocs is None:
        try:
            import ioc_manager
            iocs = ioc_manager.get_iocs()
        except (ImportError, AttributeError, KeyError, TypeError):
            return []

    # Warn when operating without a fresh remote IOC feed. We still approve
    # (fail-open) to avoid blocking legitimate work, but the degraded flag
    # tells the operator to run `ioc_manager.py --update` to refresh.
    if iocs.get('_ioc_degraded'):
        print(
            "[repo-forensics] WARNING: IOC database unavailable, operating without "
            "threat intelligence. Remote feed cache is absent or stale. Run "
            "`python3 ioc_manager.py --update` to refresh. Only hardcoded IOCs "
            "are active; recently-discovered malicious packages may not be detected.",
            file=sys.stderr,
        )

    malicious_npm = iocs.get('malicious_npm', set())
    malicious_pypi = iocs.get('malicious_pypi', set())
    all_malicious = malicious_npm | malicious_pypi

    blocked = []
    for pkg in package_names:
        if pkg.lower() in all_malicious:
            blocked.append(pkg)
    return blocked


def output_block(reason):
    """Output JSON that tells the agent to block the command.

    Claude Code reads the JSON decision on stdout; Kimi Code blocks on exit
    code 2 and surfaces stderr as the reason. Emit both so either host shows
    the operator why the command was blocked."""
    result = {
        "decision": "block",
        "reason": reason
    }
    print(json.dumps(result))
    print(reason, file=sys.stderr)
    sys.exit(2)


def output_approve():
    """Output empty JSON — command proceeds normally."""
    print('{}')
    sys.exit(0)


def main():
    data = parse_hook_input()
    command = extract_command(data)

    if not command:
        output_approve()
        return

    # Detect install/update pattern (also catches pipe-to-shell)
    pattern_type, match = detect_install_command(command)

    # Pipe-to-shell: instant block
    if pattern_type == 'pipe_to_shell':
        output_block(
            "[repo-forensics] BLOCKED: Command pipes remote content directly "
            "to shell execution. This bypasses all package manager security "
            "checks and can execute arbitrary code."
        )
        return

    if not pattern_type:
        output_approve()
        return

    # Extract package names and check IOC
    package_names = extract_package_names(pattern_type, match)
    if not package_names:
        output_approve()
        return

    # Load the IOC set ONCE and pass it to both checkers. The npm-family path
    # runs both check_ioc_packages() and check_ioc_pinned_versions(); without
    # sharing, get_iocs() (disk read + Ed25519 verify + set rebuild) ran twice.
    shared_iocs = None
    try:
        import ioc_manager
        shared_iocs = ioc_manager.get_iocs()
    except Exception:
        # Any failure loading IOCs must fail OPEN cleanly (the checkers re-load and
        # also fail open). Catch broadly so an unexpected error never crashes the
        # hook without emitting the approve JSON the PreToolUse contract requires.
        shared_iocs = None

    blocked_packages = check_ioc_packages(package_names, iocs=shared_iocs)
    if blocked_packages:
        pkg_list = ', '.join(blocked_packages)
        output_block(
            f"[repo-forensics] BLOCKED: Known malicious package(s) detected: "
            f"{pkg_list}. These packages match the IOC database and should NOT "
            f"be installed. Remove them from the command and try again."
        )
        return

    # Version-pinned npm-family tokens (`name@version`) never match the name
    # sets above, so re-check them by base name and exact pinned version.
    blocked_pinned = check_ioc_pinned_versions(pattern_type, package_names, iocs=shared_iocs)
    if blocked_pinned:
        pkg_list = ', '.join(blocked_pinned)
        output_block(
            f"[repo-forensics] BLOCKED: Known malicious package(s) detected: "
            f"{pkg_list}. These packages match the IOC database and should NOT "
            f"be installed. Remove them from the command and try again."
        )
        return

    # No IOC matches — approve
    output_approve()


if __name__ == '__main__':
    main()
