#!/usr/bin/env python3
"""
auto_scan.py - post-execution hook handler for repo-forensics v2.
Detects install/clone commands in shell tool calls and auto-triggers security scans.

Runs as a Claude Code / Codex / OpenClaw PostToolUse hook and as a Cursor
afterShellExecution hook (`--adapter cursor`). Reads JSON from stdin, writes its
report to stdout. Fast path (<10ms for non-matching commands).

OBSERVE-ONLY on every adapter. This is where the deep 28-scanner audit runs, so
it deliberately never gates execution — the blocking decision belongs to
pre_scan.py, which is the only thing fast enough to sit in front of the agent's
inner loop (PRD v3 R2).

Created by Alex Greenshpun
"""

import json
import os
import re
import sys
# subprocess and concurrent.futures are lazy-imported in run_scanner/run_targeted_scan
# to keep the no-match fast path under 10ms

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

import hook_adapter  # noqa: E402  (leaf module, stdlib-only)

# --- Install/Clone Pattern Detection ---

# Optional package-manager flags that can sit between the tool name and its
# subcommand, e.g. `pnpm -r add x`, `pnpm --filter web add x`,
# `uv --project /p add x`. Each unit is one -flag (whose first char after the
# leading dash(es) is a non-dash — this makes dash runs fail fast and avoids
# ReDoS) plus an OPTIONAL value token that must NOT itself be a subcommand
# keyword (the lookahead stops a flag value from swallowing `add`/`install`).
# Kept identical in pre_scan.py — update both.
_PM_FLAGS = (
    r'(?:-{1,2}[^-\s]\S*'
    r'(?:\s+(?!(?:install|i|add|update|sync|pip|tool|remove|run)\b)[^-\s]\S*)?'
    r'\s+)*'
)

INSTALL_PATTERNS = [
    # git clone
    (re.compile(r'git\s+clone\s+(?:--[^\s]+\s+)*(?:https?://|git@)([^\s]+)(?:\s+([^\s]+))?'), 'git_clone'),
    # git pull (update — scans CWD after pull)
    (re.compile(r'git\s+pull(?:\s|$)'), 'git_pull'),
    # uv add / uv pip install / uv tool install — must precede pip: patterns are
    # unanchored, so 'uv pip install x' substring-matches the pip entry.
    # _PM_FLAGS allows global options before the subcommand (`uv --project p add x`).
    (re.compile(r'uv\s+' + _PM_FLAGS + r'(?:add|pip\s+install|tool\s+install)\s+(.+)'), 'uv_install'),
    # uv sync (lockfile install — scans CWD after sync, like git_pull)
    (re.compile(r'uv\s+sync(?:\s|$)'), 'uv_sync'),
    # pip install (with package names) — also catches --upgrade
    (re.compile(r'pip3?\s+install\s+(.+)'), 'pip_install'),
    # pnpm install/add/update — must precede npm: 'pnpm install x'
    # substring-matches the npm entry. _PM_FLAGS covers monorepo/workspace
    # forms: `pnpm -r add x`, `pnpm --filter web add x`.
    (re.compile(r'pnpm\s+' + _PM_FLAGS + r'(?:install|i|add|update)\s+(.+)'), 'pnpm_install'),
    # bun install/add/update
    (re.compile(r'bun\s+' + _PM_FLAGS + r'(?:install|i|add|update)\s+(.+)'), 'bun_install'),
    # npm install (with package names)
    (re.compile(r'npm\s+(?:install|i)\s+(.+)'), 'npm_install'),
    # npm update (missed update commands)
    (re.compile(r'npm\s+update\s+(.+)'), 'npm_install'),
    # Bare lockfile installs (no package args) — scan CWD like uv_sync/git_pull.
    # MUST come after the with-args npm/pnpm/bun entries above so
    # 'pnpm install express' still classifies as pnpm_install. Anchored to
    # end-of-command (optionally trailing flags) so it only fires for the
    # arg-less form: `npm install`, `npm ci`, `pnpm install --frozen-lockfile`,
    # `bun install`, and `cd app && pnpm install`.
    (re.compile(r'(?:npm|pnpm|bun)\s+(?:ci|install|i)(?:\s+--?\S+)*\s*$'), 'lockfile_install'),
    (re.compile(r'yarn(?:\s+install)?(?:\s+--?\S+)*\s*$'), 'lockfile_install'),
    # yarn add
    (re.compile(r'yarn\s+add\s+(.+)'), 'yarn_add'),
    # gem install
    (re.compile(r'gem\s+install\s+(.+)'), 'gem_install'),
    # gem update
    (re.compile(r'gem\s+update\s+(.+)'), 'gem_install'),
    # cargo install
    (re.compile(r'cargo\s+install\s+(.+)'), 'cargo_install'),
    # go get/install
    (re.compile(r'go\s+(?:get|install)\s+(.+)'), 'go_install'),
    # brew install
    (re.compile(r'brew\s+install\s+(.+)'), 'brew_install'),
    # brew upgrade
    (re.compile(r'brew\s+upgrade\s+(.+)'), 'brew_install'),
    # openclaw skills/plugins install or update
    (re.compile(r'openclaw\s+(?:skills|plugins)\s+(?:install|update)\s+(.+)'), 'openclaw_install'),
    # clawhub install
    (re.compile(r'clawhub\s+(?:install|publish)\s+(.+)'), 'openclaw_install'),
    # claude plugins install/update/add (CLI variants: `claude plugins install`,
    # `claude plugins:install`, `claude /plugins install`, `claude plugins enable`)
    (re.compile(r'claude\s+/?plugins[:\s]+(?:install|update|add|enable)\s+(.+)'), 'claude_plugin_install'),
]

# Pipe-to-shell patterns (instant CRITICAL)
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
    """Read and parse PostToolUse JSON from stdin."""
    try:
        raw = sys.stdin.read(1_048_576)  # 1MB max to prevent memory exhaustion
        if not raw.strip():
            return None
        data = json.loads(raw)
        return data
    except (json.JSONDecodeError, IOError):
        return None


def extract_command(data):
    """Extract the bash command from hook payload."""
    if not data:
        return None
    tool_name = data.get('tool_name', '')
    if tool_name != 'Bash':
        return None
    tool_input = data.get('tool_input', {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except json.JSONDecodeError:
            return None
    return tool_input.get('command', '')


# --- Inert quote carriers ---------------------------------------------------
# A pipe-to-shell pattern inside a quoted argument to a command that never
# executes its arguments is someone WRITING ABOUT the attack, not performing
# it — a `git commit -m` whose message warns against downloader-to-shell
# pipelines, a `grep` searching the docs for them, an `echo` telling the reader
# not to. Blocking those is the false positive that gets a blocking hook
# uninstalled, and it fires on this repo's own commit messages, which discuss
# pipe-to-shell constantly. (These examples are deliberately paraphrased rather
# than written out: pre_scan.py and auto_scan.py are the blocking gate and stay
# OUT of .forensicsignore, so a literal payload here would be a finding the
# scanner reports against itself — see tests/test_cursor_wiring.py.)
#
# This is the command-string analogue of the evidence model forensics_core
# already applies to files (a README that DESCRIBES an attack is not the
# attack). The suppression is deliberately narrow, because the obvious wide
# version — "ignore anything inside quotes" — is a bypass, not a fix: a
# downloader-to-shell pipeline handed to `sh -c` as a quoted argument is both
# quoted AND executed. So two conditions must BOTH hold: the command starts
# with a known inert carrier, and the residue left after deleting every quoted
# span contains no shell execution of its own. An `echo` whose quoted argument
# is itself piped onward to a shell keeps that residual pipe and still blocks.
# Kept identical in pre_scan.py — update both.
# Only commands whose job is to RECORD or SEARCH FOR text, never to produce a
# stream someone would plausibly pipe onward. `cat`, `jq` and friends are
# deliberately absent: their output being piped to a shell is a normal thing to
# do, so they do not belong on a list whose whole premise is "this argument is
# inert prose". (The residual-exec check below would catch a piped `cat` too,
# but a suppression list should not lean on a second layer to stay safe.)
_INERT_CARRIERS = re.compile(
    r'^\s*(?:'
    r'echo|printf|grep|egrep|fgrep|rg|ag|ack'
    r'|git\s+(?:commit|tag|notes|stash\s+save|config)'
    r'|gh\s+(?:issue|pr|release)\s+[a-z-]+'
    r')\b',
    re.IGNORECASE,
)

# Quoted spans: single- or double-quoted, non-greedy, no cross-line matching.
_QUOTED_SPAN = re.compile(r"'[^']*'|\"[^\"]*\"")

# Residual shell execution after quoted spans are removed. Any of these means
# the command really does hand something to a shell, so no suppression.
_RESIDUAL_EXEC = re.compile(
    r'\|\s*(?:' + _SHELLS + r'|iex)'
    r'|(?:^|[\s;&|(])(?:eval|exec|source)\b'
    r'|\B-c(?:\s|$)'
    r'|(?:^|[\s;&|(])' + _SHELLS + r'\s+-c',
    re.IGNORECASE,
)


def is_inert_quote_carrier(command):
    """True when every pipe-to-shell signal in *command* sits inside a quoted
    argument to a command that does not execute its arguments."""
    if not command or not _INERT_CARRIERS.match(command):
        return False
    residue = _QUOTED_SPAN.sub(' ', command)
    if _RESIDUAL_EXEC.search(residue):
        return False
    # The signal must be gone once the quotes are removed. If it survives, it
    # was never inside a quoted argument in the first place — an inert carrier
    # followed by `;` and then a real downloader-to-shell pipeline.
    return not PIPE_TO_SHELL.search(residue)


def detect_install_command(command):
    """Match command against install/clone patterns.
    Returns (pattern_type, match_obj) or (None, None)."""
    if not command:
        return None, None

    # Check pipe-to-shell first (instant CRITICAL)
    if PIPE_TO_SHELL.search(command) and not is_inert_quote_carrier(command):
        return 'pipe_to_shell', None

    for pattern, ptype in INSTALL_PATTERNS:
        m = pattern.search(command)
        if m:
            return ptype, m

    return None, None


def extract_package_names(pattern_type, match):
    """Extract package names from install command match."""
    if pattern_type in ('pip_install', 'npm_install', 'yarn_add', 'gem_install',
                        'cargo_install', 'go_install', 'brew_install', 'openclaw_install',
                        'claude_plugin_install', 'uv_install', 'bun_install', 'pnpm_install'):
        raw = match.group(1)
        # Strip flags
        cleaned = INSTALL_FLAGS.sub('', raw).strip()
        # Split on whitespace, filter empties and flags
        names = [n.strip() for n in cleaned.split() if n.strip() and not n.startswith('-')]
        # Strip version specifiers for pip; .strip() handles `pkg @ url` form
        # which leaves trailing whitespace after the @ split.
        if pattern_type in ('pip_install', 'uv_install'):
            names = [re.split(r'[>=<!\[\];@]', n)[0].strip() for n in names]
            names = [n for n in names if n]
        return names
    return []


def _is_safe_scan_path(resolved_path):
    """Ensure resolved path is within CWD to prevent scanning sensitive directories."""
    from pathlib import PurePath
    cwd = os.getcwd()
    try:
        # PurePath.is_relative_to handles all edge cases (cwd='/', symlinks, etc.)
        p = PurePath(resolved_path)
        return (p.is_relative_to(cwd)
                or p.is_relative_to('/tmp')
                or p.is_relative_to('/private/tmp'))
    except (TypeError, ValueError):
        return False


def extract_clone_target(match):
    """Extract directory path from git clone command."""
    if not match:
        return None
    url = match.group(1)
    explicit_dir = match.group(2) if match.lastindex >= 2 else None

    if explicit_dir:
        resolved = os.path.realpath(explicit_dir)
    else:
        # Derive directory from URL
        repo_name = url.rstrip('/').split('/')[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        resolved = os.path.realpath(repo_name)

    # Path containment: refuse to scan outside CWD or /tmp
    if not _is_safe_scan_path(resolved):
        return None
    return resolved


# npm-family installers pin versions as `name@version`, which the pip/uv strip
# in extract_package_names() deliberately leaves untouched. These are the
# pattern types whose tokens get the split treatment below.
# Kept in sync with pre_scan.py — duplicated rather than imported so each hook
# script stays standalone-loadable.
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
        # tarball: .../<name>-<version>.tgz  (name may be scoped .../@scope/name/-/name-1.2.3.tgz)
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


def check_ioc_pinned_versions(pattern_type, package_names):
    """Check npm-family `name@version` tokens against the IOC database.

    Complements check_ioc_packages(), which compares whole tokens against the
    name sets: a pinned token like `rimarf@1.0.0` matches no name, so the
    install used to sail through while bare `rimarf` was flagged. Flags when
    either the base name is a known-malicious package, or the exact pinned
    version appears in the shipped compromised_versions map.

    Fail-open on IOC-load failure, same contract as check_ioc_packages().
    """
    if pattern_type not in NPM_FAMILY_INSTALLS:
        return []
    try:
        import ioc_manager
        iocs = ioc_manager.get_iocs()
    except (ImportError, AttributeError, KeyError, TypeError):
        return []

    all_malicious = iocs.get('malicious_npm', set()) | iocs.get('malicious_pypi', set())
    compromised_versions = iocs.get('compromised_versions', {})

    findings = []
    for pkg in package_names:
        base, version = split_npm_name_version(pkg)
        if version is None:
            continue  # bare names are already covered by check_ioc_packages()
        base_lower = base.lower()
        if base_lower in all_malicious:
            findings.append({
                'scanner': 'auto_scan',
                'severity': 'critical',
                'title': f"Known Malicious Package: '{base}@{version}'",
                'description': f"Package '{base}' matches IOC database at any version. DO NOT INSTALL.",
                'file': 'N/A',
                'line': 0,
                'snippet': f"'{base}' is a known malicious package (IOC match)",
                'category': 'known-ioc'
            })
            continue
        pkg_bad = compromised_versions.get(base_lower, {})
        if not pkg_bad:
            continue
        # exact pin
        if version in pkg_bad:
            findings.append({
                'scanner': 'auto_scan',
                'severity': 'critical',
                'title': f"Compromised Package Version: '{base}@{version}'",
                'description': (
                    f"Version {version} of '{base}' was published in supply-chain "
                    f"campaign '{pkg_bad[version]}'. DO NOT INSTALL this version."
                ),
                'file': 'N/A',
                'line': 0,
                'snippet': f"'{base}@{version}' is a known-compromised release ({pkg_bad[version]})",
                'category': 'known-ioc'
            })
            continue
        # range / x-range / comparator spec that could resolve to a compromised
        # version (e.g. keyv@^6.0.0 resolving to the bad 6.0.0). Conservative.
        for bad_ver, campaign in pkg_bad.items():
            if _spec_could_match(version, bad_ver):
                findings.append({
                    'scanner': 'auto_scan',
                    'severity': 'critical',
                    'title': f"Compromised Package Version: '{base}@{version}'",
                    'description': (
                        f"Version range '{version}' of '{base}' may resolve to "
                        f"compromised {bad_ver}, published in supply-chain campaign "
                        f"'{campaign}'. DO NOT INSTALL this version."
                    ),
                    'file': 'N/A',
                    'line': 0,
                    'snippet': f"'{base}@{version}' may resolve to compromised {bad_ver} ({campaign})",
                    'category': 'known-ioc'
                })
                break

    return findings


def check_ioc_packages(package_names):
    """Check package names against IOC database. Returns findings list."""
    try:
        import ioc_manager
        iocs = ioc_manager.get_iocs()
    except ImportError:
        return []

    findings = []
    malicious_npm = iocs.get('malicious_npm', set())
    malicious_pypi = iocs.get('malicious_pypi', set())
    all_malicious = malicious_npm | malicious_pypi

    for pkg in package_names:
        pkg_lower = pkg.lower()
        if pkg_lower in all_malicious:
            findings.append({
                'scanner': 'auto_scan',
                'severity': 'critical',
                'title': f"Known Malicious Package: '{pkg}'",
                'description': f"Package '{pkg}' matches IOC database. DO NOT INSTALL.",
                'file': 'N/A',
                'line': 0,
                'snippet': f"'{pkg}' is a known malicious package (IOC match)",
                'category': 'known-ioc'
            })

        # Also check for liteLLM specifically
        if pkg_lower == 'litellm':
            findings.append({
                'scanner': 'auto_scan',
                'severity': 'critical',
                'title': f"Supply Chain Risk: '{pkg}' (liteLLM)",
                'description': "liteLLM had a malicious .pth file injection in v1.82.8 (March 2026). "
                               "Verify version is not compromised before installing.",
                'file': 'N/A',
                'line': 0,
                'snippet': "liteLLM PyPI supply chain attack: .pth file auto-exfiltrates credentials",
                'category': 'supply-chain'
            })

    return findings


def _scan_incomplete_finding(scanner_script, reason):
    """Build a LOUD synthetic finding for a scanner that failed to complete.

    A scanner that times out, is killed by a signal (SIGKILL/OOM), exits with
    an error code, or emits unparseable JSON used to return [] silently here —
    meaning the user got a CLEAN verdict with NO indication the scan was
    incomplete. That is a detection bypass: an attacker who pushes any scanner
    past the 15s wall-clock (or OOMs it) thereby SUPPRESSES all of that
    scanner's findings without a trace. Fail LOUD instead: emit a high-severity
    finding so the verdict flips and the gap is visible. (Closes the
    "SIGKILL -> silent zero" class; torture 2026-06-17.)
    """
    name = scanner_script[:-3] if scanner_script.endswith('.py') else scanner_script
    return [{
        'scanner': name,
        'severity': 'high',
        'title': 'Scanner did not complete — results may be incomplete',
        'description': (
            f"{name} {reason}; its findings are MISSING from this report. "
            f"A repo can trigger this (e.g. by making the scanner overrun its "
            f"time budget or exhaust memory) to suppress detection, so treat a "
            f"clean verdict from this scan as UNTRUSTWORTHY for {name}'s surface. "
            f"Re-run the scanner in isolation to obtain complete results."
        ),
        'file': '',
        'line': 0,
        'snippet': '',
        'category': 'scan-incomplete',
    }]


def run_scanner(scanner_script, repo_path):
    """Run a single scanner and return parsed findings.

    On any failure mode that would otherwise yield a SILENT empty result
    (timeout, signal-kill, scanner error, unparseable JSON on non-empty stdout,
    or a NON-zero exit with empty stdout — the uncaught-exception crash door),
    returns a LOUD synthetic 'scan-incomplete' finding instead of [] so the
    incompleteness surfaces in the verdict. A clean [] is returned when rc==0
    with empty stdout, or whenever stdout parses to valid JSON (including an
    empty list) at rc<=2 — a scanner may exit non-zero while still emitting its
    findings JSON, and that output is trusted. The crash door is specifically a
    NON-zero exit with EMPTY or unparseable stdout, which now fails loud.
    """
    import subprocess
    script_path = os.path.join(SCRIPTS_DIR, scanner_script)
    if not os.path.exists(script_path):
        return []

    try:
        result = subprocess.run(
            [sys.executable, script_path, repo_path, '--format', 'json'],
            capture_output=True, text=True, timeout=15,
            cwd=SCRIPTS_DIR
        )
    except subprocess.TimeoutExpired:
        return _scan_incomplete_finding(
            scanner_script, "TIMED OUT (exceeded the 15s wall-clock budget)")
    except OSError as e:
        return _scan_incomplete_finding(
            scanner_script, f"could not be launched (OSError: {e})")

    rc = result.returncode
    # Killed by a signal: subprocess returncode is negative (e.g. -9 = SIGKILL,
    # the classic OOM / wall-clock kill). This is the core silent-zero vector.
    if rc < 0:
        return _scan_incomplete_finding(
            scanner_script,
            f"was KILLED by signal {-rc} (e.g. SIGKILL/OOM or wall-clock kill)")
    # Scanner errored out (rc > 2 is outside the success/findings-present band).
    if rc > 2:
        return _scan_incomplete_finding(
            scanner_script, f"exited with error code {rc}")

    out = result.stdout.strip()
    if not out:
        # ONLY rc==0 with empty stdout is a legitimate "ran clean, found
        # nothing" result. A NON-zero rc with EMPTY stdout means the scanner
        # did NOT produce results — the classic uncaught-exception crash exits
        # rc==1 (or 2) and writes its traceback to STDERR, leaving stdout empty.
        # Treating that as "[] = benign" silently suppresses the whole scanner:
        # the same silent-zero detection-bypass class as the timeout/SIGKILL
        # doors, just via the crash door. Fail LOUD instead. (P1, CE review
        # 2026-06-17.)
        if rc == 0:
            return []
        return _scan_incomplete_finding(
            scanner_script,
            f"exited non-zero (rc {rc}) with no output — likely crashed")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return _scan_incomplete_finding(
            scanner_script, "produced UNPARSEABLE JSON output")


def run_targeted_scan(repo_path):
    """Run 19 targeted scanners in parallel on a cloned/installed repo."""
    if not os.path.isdir(repo_path):
        return []

    targeted_scanners = [
        'scan_dependencies.py',
        'scan_secrets.py',
        'scan_lifecycle.py',
        'scan_skill_threats.py',
        'scan_manifest_drift.py',
        'scan_runtime_dynamism.py',
        'scan_agent_skills.py',
        'scan_sast.py',
        'scan_mcp_security.py',
        'scan_infra.py',
        'scan_entrypoint.py',
        'scan_oversize.py',
        'scan_splitstream.py',
        'scan_provenance.py',
        'scan_archive.py',
        'scan_bytecode.py',
        'scan_dead_anchors.py',
        'scan_yara.py',
        'scan_git_config.py',
    ]

    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_findings = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(run_scanner, s, repo_path): s
            for s in targeted_scanners
        }
        for future in as_completed(futures):
            try:
                findings = future.result()
                if isinstance(findings, list):
                    all_findings.extend(findings)
            except Exception as e:
                print(f"[!] Scanner {futures[future]} failed: {e}", file=sys.stderr)

    # Raw-content correlation fallbacks (Lethal Trifecta + registry hijack), run
    # before correlate() so the hook path has the same raw-content feed as the
    # full-scan build_report path. Without these the PostToolUse hook gives a
    # false-clean on registry-hijack and trifecta payloads at install time — the
    # exact moment interception matters most.
    try:
        import forensics_core as core
        all_findings.extend(f.to_dict() for f in core.detect_trifecta_raw(repo_path))
        all_findings.extend(f.to_dict() for f in core.detect_registry_hijack_raw(repo_path))
    except (ImportError, OSError, AttributeError) as e:
        print(f"[!] Raw-content scan failed: {e}", file=sys.stderr)

    # Run correlation engine on collected findings to detect compound threats.
    # Uses the shared findings_from_dicts helper to stay in sync with
    # aggregate_json.run_correlation_pass (PR-F1, 2026-04-05).
    try:
        import forensics_core as core
        finding_objs = core.findings_from_dicts(all_findings)
        if finding_objs:
            correlated = core.correlate(finding_objs, repo_path=repo_path)
            all_findings.extend(cf.to_dict() for cf in correlated)
    except (ImportError, AttributeError, KeyError, TypeError, ValueError) as e:
        print(f"[!] Correlation failed: {e}", file=sys.stderr)

    return [f for f in all_findings if f.get("scanner") != "trifecta_raw"]


def build_pipe_to_shell_warning(command):
    """Build CRITICAL warning for pipe-to-shell commands."""
    return [{
        'scanner': 'auto_scan',
        'severity': 'critical',
        'title': 'Pipe-to-Shell Execution Detected',
        'description': (
            'Command pipes remote content directly to shell execution. '
            'This bypasses all package manager security checks and can execute '
            'arbitrary code. NEVER pipe untrusted URLs to shell.'
        ),
        'file': 'N/A',
        'line': 0,
        'snippet': command[:200] if command else '',
        'category': 'pipe-to-shell'
    }]


def format_output(findings, command='', pattern_type='', scanned_target=''):
    """Format scan results as plain text so Claude Code surfaces it to the model.

    Always produces output when a scan ran (even if clean) so the model knows
    the security check happened. Returns empty string only when no scan was
    triggered (non-matching command).
    """
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

    if not findings:
        if scanned_target:
            return f"[repo-forensics] auto-scan complete: {scanned_target} — no issues found."
        return ''

    findings.sort(key=lambda f: severity_order.get(f.get('severity', 'low'), 3))

    critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
    high_count = sum(1 for f in findings if f.get('severity') == 'high')

    lines = []
    lines.append(f"[repo-forensics] auto-scan: {len(findings)} finding(s)")
    if pattern_type:
        lines.append(f"Triggered by: {pattern_type} command")

    # Sanitize the scanner-authored title/description (defense in depth) and do
    # NOT echo the raw `snippet` here. The snippet is the attacker-controlled
    # payload; the only place it appears is inside the injection-safe
    # adjudication block below, behind the `> SNIPPET: ` prefix. Echoing it
    # unprefixed in this summary list would reintroduce the exact prompt-injection
    # surface U8 closes ("no unprefixed attacker text anywhere in the output").
    try:
        import adjudication as _adj
        _clean = _adj.sanitize_snippet
    except ImportError:
        # B4 fix: inline fallback must cover \r, U+2028/2029, BIDI, C1 range,
        # and collapse all whitespace/line-separator chars to a single space.
        # Kept self-contained since the import failed.
        import re as _re
        _FALLBACK_CTRL_RE = _re.compile(
            r"[\x00-\x1f\x7f\x80-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\u2060-\u2064\ufeff]"
        )

        def _clean(text, max_len=160):
            if not isinstance(text, str):
                return ""
            cleaned = _FALLBACK_CTRL_RE.sub("", text or "")
            cleaned = _re.sub(r"\s+", " ", cleaned).strip()
            return cleaned[:max_len]

    for f in findings[:15]:
        sev = f.get('severity', 'low').upper()
        title = _clean(f.get('title', 'Unknown'), max_len=160)
        desc = _clean(f.get('description', ''), max_len=300)
        lines.append(f"[{sev}] {title}: {desc}")

    if len(findings) > 15:
        lines.append(f"... and {len(findings) - 15} more findings. Run full scan for details.")

    if critical_count > 0:
        lines.append(f"VERDICT: {critical_count} CRITICAL finding(s). Do not proceed without review.")
    elif high_count > 0:
        lines.append(f"VERDICT: {high_count} HIGH finding(s). Review before proceeding.")

    # Adjudication block (U8): WARN-tier findings get an injection-safe block
    # the host agent reads as tool output. auto_scan does not run aggregate_json,
    # so needs_adjudication is not pre-set; the helper falls back to the WARN
    # confidence band and excludes correlation-synthesized findings itself.
    try:
        import adjudication
        block = adjudication.build_adjudication_block(findings)
        if block:
            lines.append(block)
    except ImportError:
        pass

    return '\n'.join(lines)


def emit_report(adapter, text):
    """Write the post-execution report in *adapter*'s output shape.

    Claude/Codex/OpenClaw surface plain text from a PostToolUse hook, which is
    what has always been printed here. Cursor parses hook stdout as JSON, so the
    same report is carried in the canonical verdict triple with an `allow`
    permission — the event is observe-only, so there is no other verdict it
    could carry.
    """
    if not text:
        if adapter == hook_adapter.ADAPTER_CURSOR:
            hook_adapter.emit_verdict(adapter, hook_adapter.ALLOW)
        return
    if adapter == hook_adapter.ADAPTER_CURSOR:
        hook_adapter.emit_verdict(adapter, hook_adapter.ALLOW,
                                  user_message=text, agent_message=text)
        return
    print(text)


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    adapter, adapter_error = hook_adapter.normalize_adapter(
        hook_adapter.adapter_from_argv(argv))
    if adapter_error:
        print(f"[repo-forensics] WARNING: {adapter_error}; falling back to "
              f"'{hook_adapter.ADAPTER_CLAUDE}'", file=sys.stderr)

    # Parse hook input through the shared adapter so the Cursor envelope reaches
    # the SAME detection code as the Claude one. Drift is not fatal here: this
    # hook cannot block, so an unreadable envelope means "nothing to scan",
    # never "deny" (that policy belongs to pre_scan.py).
    request = hook_adapter.parse_request(adapter, hook_adapter.read_stdin())
    if request.drift:
        print(f"[repo-forensics] WARNING: post-execution audit skipped: "
              f"{request.drift}", file=sys.stderr)
        emit_report(adapter, "")
        sys.exit(0)
    command = request.command

    if not command:
        emit_report(adapter, "")
        sys.exit(0)

    # Detect install/clone pattern
    pattern_type, match = detect_install_command(command)

    if not pattern_type:
        emit_report(adapter, "")
        sys.exit(0)

    # Pipe-to-shell: instant CRITICAL, no scan needed
    if pattern_type == 'pipe_to_shell':
        findings = build_pipe_to_shell_warning(command)
        output = format_output(findings, command, pattern_type, scanned_target='pipe-to-shell')
        emit_report(adapter, output)
        sys.exit(0)

    all_findings = []
    scanned_target = ''

    # For package install commands: check IOC list
    package_names = []
    if pattern_type != 'git_clone':
        package_names = extract_package_names(pattern_type, match)
        if package_names:
            scanned_target = ', '.join(package_names)
            ioc_findings = check_ioc_packages(package_names)
            all_findings.extend(ioc_findings)
            # Version-pinned npm-family tokens (`name@version`) never match the
            # name sets above, so re-check them by base name and exact version.
            all_findings.extend(check_ioc_pinned_versions(pattern_type, package_names))

    # For git clone: scan the cloned directory
    if pattern_type == 'git_clone':
        clone_dir = extract_clone_target(match)
        if clone_dir and os.path.isdir(clone_dir):
            scanned_target = clone_dir
            scan_findings = run_targeted_scan(clone_dir)
            all_findings.extend(scan_findings)

    # For git pull / uv sync / bare lockfile install: scan CWD (repo or its
    # deps were updated in place from the lockfile — no package args to target).
    # A with-args install that extracted zero packages is also a lockfile
    # install: its args were all flags (`pnpm install --frozen-lockfile`,
    # `npm install --production`) — deps still changed, so scan CWD.
    _lockfile_like = pattern_type in ('git_pull', 'uv_sync', 'lockfile_install') or (
        pattern_type in ('pip_install', 'npm_install', 'uv_install',
                         'bun_install', 'pnpm_install') and not package_names)
    if _lockfile_like:
        cwd = os.getcwd()
        if os.path.isdir(cwd) and _is_safe_scan_path(cwd):
            scanned_target = cwd
            scan_findings = run_targeted_scan(cwd)
            all_findings.extend(scan_findings)

    # For pip/npm-style install with a local path: scan it (with path containment)
    if pattern_type in ('pip_install', 'npm_install', 'uv_install', 'bun_install',
                        'pnpm_install'):
        for pkg in package_names:
            pkg_path = os.path.realpath(pkg)
            if os.path.isdir(pkg_path) and _is_safe_scan_path(pkg_path):
                scanned_target = pkg_path
                scan_findings = run_targeted_scan(pkg_path)
                all_findings.extend(scan_findings)

    output = format_output(all_findings, command, pattern_type, scanned_target)
    emit_report(adapter, output)
    sys.exit(0)


if __name__ == '__main__':
    main()
