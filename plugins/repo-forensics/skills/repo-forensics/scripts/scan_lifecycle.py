#!/usr/bin/env python3
"""
scan_lifecycle.py - Lifecycle Script Scanner (v2: rewritten from JS to Python)
Detects malicious NPM hooks and Python setup.py/pyproject.toml cmdclass overrides.
No Bun dependency, all pure Python.

Created by Alex Greenshpun
"""

import os
import re
import sys
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "lifecycle"

# CLI commands commonly targeted by Command-Jacking (Checkmarx, October 2024).
# Shared across npm bin, setup.py console_scripts, and pyproject.toml [project.scripts].
SHADOWED_COMMANDS = {
    'aws', 'docker', 'git', 'kubectl', 'terraform', 'pip', 'pip3',
    'npm', 'npx', 'node', 'python', 'python3', 'curl', 'wget',
    'ssh', 'scp', 'rsync', 'ls', 'cat', 'touch', 'mkdir', 'rm',
    'cp', 'mv', 'chmod', 'chown', 'sudo', 'su', 'gcloud', 'az',
    'heroku', 'vercel', 'netlify', 'gh', 'brew', 'apt', 'yum',
    'bun', 'bunx', 'deno', 'pnpm', 'yarn',
}

DANGEROUS_NPM_HOOKS = ['preinstall', 'postinstall', 'install', 'prepare', 'prepublish', 'postpublish']
SUSPICIOUS_COMMANDS = [
    (re.compile(r'\bcurl\b'), "curl command"),
    (re.compile(r'\bwget\b'), "wget command"),
    (re.compile(r'\bbash\s+-i\b'), "interactive bash"),
    (re.compile(r'/dev/tcp'), "/dev/tcp network"),
    (re.compile(r'\bbase64\s+-d\b.*\|\s*(sh|bash)'), "base64 decode piped to shell"),
    (re.compile(r'\bbase64\b.*\bsh\b'), "base64 with shell execution"),
    (re.compile(r'\bnc\s'), "netcat"),
    (re.compile(r'\bpython\b.*-c'), "python inline execution"),
    (re.compile(r'\bnode\b.*-e'), "node inline execution"),
    (re.compile(r'\beval\b'), "eval command"),
    (re.compile(r'\bbunx?\b'), "bun/bunx execution (Bun runtime stager pattern)"),
    (re.compile(r'oven-sh/bun|bun-v\d+\.\d+'), "Bun runtime download (TeamPCP stager pattern, April 2026)"),
    (re.compile(r'>\s*/dev/null.*2>&1'), "output suppression"),
]

# Paste service / dead-drop URLs in install hooks.
# StegaBin/Shai-Hulud (2025-2026) staged payloads on public paste services to evade
# static analysis; buildrunner-dev (Feb 2026) used image hosting for RGB steganography.
PASTE_SERVICE_PATTERNS = [
    (re.compile(r'(?i)\b(pastebin\.com|hastebin\.com|dpaste\.(org|com)|paste\.ee|ghostbin\.co|rentry\.co|ix\.io|sprunge\.us)\b'), "Paste service URL (dead-drop C2 staging pattern, StegaBin/Shai-Hulud 2025-2026)"),
    (re.compile(r'(?i)\braw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/'), "Raw GitHub file fetch (potential dead-drop payload source)"),
    (re.compile(r'(?i)\bgist\.githubusercontent\.com\b'), "GitHub Gist fetch (potential dead-drop payload)"),
    (re.compile(r'(?i)\b(webhook\.site|requestbin\.com|pipedream\.net)\b'), "Webhook/request-bin service (data exfiltration endpoint)"),
    (re.compile(r'(?i)\b(i\.ibb\.co|imgbb\.com|cloudinary\.com/[^/]+/image)\b'), "Image hosting service in install context (RGB pixel steganography vector, buildrunner-dev Feb 2026)"),
]

# Agent config directory write patterns.
# Malicious packages that write to AI agent config dirs persist across uninstall
# because ~/.claude/, ~/.cursor/, etc. are not cleaned up with npm/pip uninstall.
AGENT_CONFIG_DIR_PATTERNS = [
    (re.compile(r'(?i)(~|\$HOME|\$\{HOME\})/\.claude(/|["\']|$|\s|;|&)'), "Write to ~/.claude/ (Claude Code config injection, persists after uninstall)"),
    (re.compile(r'(?i)(~|\$HOME|\$\{HOME\})/\.cursor(/|["\']|$|\s|;|&)'), "Write to ~/.cursor/ (Cursor config injection)"),
    (re.compile(r'(?i)(~|\$HOME|\$\{HOME\})/\.continue(/|["\']|$|\s|;|&)'), "Write to ~/.continue/ (Continue config injection)"),
    (re.compile(r'(?i)(~|\$HOME|\$\{HOME\})/\.windsurf(/|["\']|$|\s|;|&)'), "Write to ~/.windsurf/ (Windsurf config injection)"),
    (re.compile(r'(?i)(~|\$HOME|\$\{HOME\})/\.codeium(/|["\']|$|\s|;|&)'), "Write to ~/.codeium/ (Codeium config injection)"),
    (re.compile(r'(?i)mkdir\s+.*\.(claude|cursor|continue|windsurf)(/|$|\s|;|&)'), "Directory creation in AI agent config path"),
]

# Anti-forensics patterns: self-destructing installers (Axios supply chain, March 2026)
ANTI_FORENSICS_PATTERNS = [
    (re.compile(r'(?i)\brm\s+([-rf\s]*)(setup\.js|install\.js|postinstall\.js|preinstall\.js)'), "Self-deleting installer script"),
    (re.compile(r'(?i)fs\.unlinkSync\s*\(\s*__filename\s*\)'), "Script deletes itself after execution (fs.unlinkSync(__filename))"),
    (re.compile(r'(?i)fs\.unlink(Sync)?\s*\(\s*(path\.)?(resolve|join)\s*\(.*?(setup|install|postinstall)'), "Script deletes installer file after execution"),
    (re.compile(r'(?i)fs\.writeFileSync\s*\(\s*.*?package\.json'), "Script overwrites package.json (post-execution cleanup)"),
    (re.compile(r'(?i)(fs\.rename|fs\.copyFile)(Sync)?\s*\(.*?package\.json'), "Script replaces package.json (anti-forensics)"),
    (re.compile(r'(?i)child_process.*\brm\s'), "child_process used to remove files (anti-forensics)"),
]

INSTALL_SCRIPT_IOC_PATTERNS = [
    (re.compile(r'(?i)\baab\.sportsontheweb\.net\b'), "vpmdhaj OpenSearch typosquat C2 domain (Microsoft, May 2026)"),
    (re.compile(r'(?i)\bX-Supply\b'), "vpmdhaj install-time HTTP beacon header X-Supply: 1"),
    (re.compile(r'(?i)__DAEMONIZED\s*=?\s*["\']?1'), "detached payload marker __DAEMONIZED=1"),
    (re.compile(r'(?i)\b(payload\.bin|opensearch_init\.js|ai_init\.js)\b'), "known stage-2 payload filename"),
    (re.compile(r'\b169\.254\.169\.254\b|\b169\.254\.170\.2\b'), "cloud metadata endpoint access from install script"),
    (re.compile(r'(?i)github\.com/oven-sh/bun/releases/download'), "Bun runtime download used as npm malware loader"),
    (re.compile(r'(?i)/-/npm/v1/tokens|/-/whoami'), "npm token validation/enumeration endpoint"),
    (re.compile(r'(?i)sts:GetCallerIdentity|AssumeRole|secretsmanager:(ListSecrets|GetSecretValue)'), "cloud credential enumeration API name"),
    (re.compile(r'(?i)/proc/(?:self|[0-9]+)/mem|process\.memory|runner.*memory'), "CI runner process-memory scraping marker"),
    (re.compile(r'(?i)bypass_2fa'), "npm 2FA-bypass token abuse marker"),
    (re.compile(r'(?i)Miasma:\s*The\s*Spreading\s*Blight'), "Miasma campaign repository marker"),
]

# "Shai-Hulud: The Second Coming" (November 24, 2025 fake-Bun npm wave) and its
# December 28, 2025 "Golden Path" rename. Every filename and marker string below
# is taken verbatim from the Cobenian/shai-hulud-detect reference detector and its
# CHANGELOG (2.7.0 / 2.8.0 entries) -- no invented IOCs.
#   check_bun_attack_files()        -> setup_bun.js, bun_installer.js,
#                                      bun_environment.js, environment_source.js
#   check_new_workflow_patterns()   -> actionsSecrets.json
#   check_preinstall_bun_patterns() -> "preinstall": "node setup_bun.js"
#   check_second_coming_repos()     -> "Sha1-Hulud: The Second Coming"
#   check_github_actions_runner()   -> SHA1HULUD runner name
SECOND_COMING_PATTERNS = [
    (re.compile(r'(?i)"preinstall"\s*:\s*"node\s+(?:\./)?(setup_bun\.js|bun_installer\.js)"'),
     'fake-Bun preinstall dropper hook ("preinstall": "node setup_bun.js")'),
    (re.compile(r'(?i)\bactionsSecrets\.json\b'),
     "actionsSecrets.json double-Base64 secrets-exfiltration staging file"),
    (re.compile(r'(?i)\b(Sha1|Shai)-Hulud:\s{0,4}The\s{0,4}Second\s{0,4}Coming\b'),
     "Second Coming GitHub dead-drop repository description marker"),
    (re.compile(r'SHA1HULUD'),
     "SHA1HULUD self-hosted GitHub Actions runner marker (Second Coming persistence)"),
    # "Golden Path Variant Detection ... Detection for obfuscated exfiltration JSON
    # files: `3nvir0nm3nt.json`, `cl0vd.json`, `c9nt3nts.json`, `pigS3cr3ts.json`"
    # -- Cobenian/shai-hulud-detect CHANGELOG 3.1.0 (December 2025 Golden Path).
    (re.compile(r'(?i)\b(3nvir0nm3nt|cl0vd|c9nt3nts|pigS3cr3ts)\.json\b'),
     "Golden Path obfuscated secrets-exfiltration staging filename "
     "(3nvir0nm3nt.json / cl0vd.json / c9nt3nts.json / pigS3cr3ts.json)"),
    # formatter_<digits>.yml is the Second Coming injected-workflow name. Scoped to a
    # .github/workflows/ path on the same line so it fires on the dropper
    # (`cp payload .github/workflows/formatter_123.yml`) but NOT on a bare, benign
    # date/PR-numbered `formatter_20260806.yml` reference elsewhere. The on-disk
    # artifact is also caught path-scoped in scan_post_incident.py.
    (re.compile(r'(?i)\.github[/\\]workflows[/\\][^\n]{0,40}formatter_\d{4,20}\.ya?ml\b'),
     "Second Coming injected GitHub Actions workflow (.github/workflows/formatter_<digits>.yml)"),
]

# Bare dropper/payload FILENAMES from the Second Coming / Golden Path waves. A file
# named setup_bun.js or bun_environment.js is a real IOC, but the name alone also
# appears in legitimate Bun projects and in docs/blog posts about the attack, so a
# standalone filename match is a MEDIUM weak-signal hint, not a CRITICAL detection.
# The strong signals (preinstall dropper hook, exfil staging files, repo marker) stay
# critical in SECOND_COMING_PATTERNS above.
WEAK_BUN_FILENAME_HINTS = [
    (re.compile(r'(?i)\b(?:\./)?(setup_bun|bun_installer)\.js\b'),
     "Second Coming fake-Bun runtime installer filename (setup_bun.js / bun_installer.js)"),
    (re.compile(r'(?i)\b(?:\./)?(bun_environment|environment_source)\.js\b'),
     "Second Coming / Golden Path credential-harvest payload filename "
     "(bun_environment.js / environment_source.js)"),
]

# GitHub dead-drop repository description / beacon markers used across the
# Shai-Hulud family. Every literal is taken verbatim from the
# Cobenian/shai-hulud-detect reference detector:
#   check_malicious_repo_descriptions() -> "Goldox-T3chs: Only Happy Girl",
#       "Miasma - The Spreading Blight", "Hades - The End for the Damned",
#       "Shai-Hulud: Here We Go Again"
#   check_mini_shai_hulud_indicators() IOC 3 -> "A Mini Shai-Hulud has Appeared",
#       "niagA oG eW ereH :duluH-iahS", "siridar-ghola-567",
#       "tleilaxu-ornithopter-43"
# The worm stamps these on the public repos it creates under the victim's own
# GitHub account, so a copy inside a package is either the worm itself or a
# staged copy of it.
SHAI_HULUD_REPO_MARKERS = [
    (re.compile(r'(?i)\bA\s{0,4}Mini\s{0,4}Shai-Hulud\s{0,4}has\s{0,4}Appeared\b'),
     'Mini Shai-Hulud exfil-repo description marker '
     '("A Mini Shai-Hulud has Appeared", May 2026 TanStack wave)'),
    (re.compile(r'niagA oG eW ereH :duluH-iahS'),
     'Mini Shai-Hulud exfil-repo beacon, character-reversed '
     '("niagA oG eW ereH :duluH-iahS", May 2026 AntV/atool wave)'),
    (re.compile(r'(?i)\bShai-Hulud:\s{0,4}Here\s{0,4}We\s{0,4}Go\s{0,4}Again\b'),
     'Shai-Hulud dead-drop repository description marker '
     '("Shai-Hulud: Here We Go Again")'),
    (re.compile(r'(?i)\bGoldox-T3chs:\s{0,4}Only\s{0,4}Happy\s{0,4}Girl\b'),
     'Golden Path dead-drop repository description marker '
     '("Goldox-T3chs: Only Happy Girl", December 2025)'),
    (re.compile(r'(?i)\bHades\s{0,3}-\s{0,3}The\s{0,4}End\s{0,4}for\s{0,4}the\s{0,4}Damned\b'),
     'Hades/Miasma PyPI-branch dead-drop repository description marker '
     '("Hades - The End for the Damned")'),
    (re.compile(r'(?i)\bMiasma\s{0,3}-\s{0,3}The\s{0,4}Spreading\s{0,4}Blight\b'),
     'Miasma dead-drop repository description marker, hyphen form '
     '("Miasma - The Spreading Blight")'),
    (re.compile(r'(?i)\b(siridar-ghola-567|tleilaxu-ornithopter-43)\b'),
     'Mini Shai-Hulud attacker exfil repository name '
     '(siridar-ghola-567 / tleilaxu-ornithopter-43)'),
]

# Mini Shai-Hulud (April-May 2026 TanStack / AntV / atool waves) dropper
# filenames and the install-hook delivery vectors that launch them.
# Ported verbatim from check_mini_shai_hulud_indicators():
#   IOC 1 -> router_init.js, tanstack_runner.js
#   IOC 7 -> "github:tanstack/router#79ac49ee",
#            "github:antvis/G2#<1916faa365|7cb42f5756|dc3d62a218>",
#            "bun run tanstack_runner.js", '"preinstall": "bun run index.js"',
#            "@tanstack/setup"
MINI_SHAI_HULUD_PATTERNS = [
    (re.compile(r'(?i)\b(router_init|tanstack_runner)\.js\b'),
     "Mini Shai-Hulud payload filename (router_init.js / tanstack_runner.js)"),
    (re.compile(r'(?i)"(preinstall|prepare)"\s{0,4}:\s{0,4}"bun\s{1,4}run\s{1,4}(index|tanstack_runner)\.js"'),
     'Mini Shai-Hulud Bun dropper hook '
     '("preinstall": "bun run index.js" / "bun run tanstack_runner.js")'),
    (re.compile(r'(?i)\bgithub:tanstack/router#79ac49ee'),
     "Mini Shai-Hulud malicious optionalDependencies orphan-commit ref "
     "(github:tanstack/router#79ac49ee)"),
    (re.compile(r'(?i)\bgithub:antvis/G2#(1916faa365|7cb42f5756|dc3d62a218)'),
     "Mini Shai-Hulud malicious optionalDependencies orphan-commit ref "
     "(github:antvis/G2#...)"),
    (re.compile(r'@tanstack/setup\b'),
     "Reference to the attacker-created fake @tanstack/setup package "
     "(Mini Shai-Hulud, May 2026)"),
]

# Wipe-threat token description strings. The family plants these as the
# description of the GitHub PAT its dead-man's switch monitors, so that the
# standard incident-response action (revoke the token) is what fires the wipe.
# Sources: check_mini_shai_hulud_indicators() IOC 2
# ("IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner") and the
# CHANGELOG token-nuke markers for the Miasma / Hades / LeoPlatform waves
# ("IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner",
#  "IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully",
#  "RevokeAndItGoesKaboom").
WIPE_THREAT_MARKERS = [
    (re.compile(r'(?i)\bIfYou(Revoke|Invalidate|Yank)ThisTokenItWill(Wipe|Nuke)'
                r'TheComputerOfTheOwner(Fully)?\b'),
     "wipe-threat token description string (revoking the token triggers the wipe)"),
    (re.compile(r'(?i)\bRevokeAndItGoesKaboom\b'),
     "wipe-threat marker (RevokeAndItGoesKaboom)"),
]

# Dead-man's-switch daemon artefacts referenced from inside a package. Both Mini
# Shai-Hulud waves install a polling service that wipes the host when its
# monitored token is revoked (check_mini_shai_hulud_indicators() IOC 8:
# gh-token-monitor.{sh,service}, com.user.gh-token-monitor.plist,
# kitty-monitor.{sh,service}, com.user.kitty-monitor.plist,
# ~/.local/share/kitty/cat.py).
DEADMAN_SERVICE_PATTERNS = [
    (re.compile(r'(?i)\b(gh-token-monitor|kitty-monitor)\.(sh|service)\b'),
     "Mini Shai-Hulud dead-man's-switch daemon script or systemd unit "
     "(gh-token-monitor / kitty-monitor)"),
    (re.compile(r'(?i)\bcom\.user\.(gh-token-monitor|kitty-monitor)\.plist\b'),
     "Mini Shai-Hulud dead-man's-switch macOS LaunchAgent plist"),
    (re.compile(r'(?i)/kitty/cat\.py\b'),
     "Mini Shai-Hulud dead-man's-switch payload path "
     "(~/.local/share/kitty/cat.py)"),
]

# Secure-erase / overwrite wiper stages. Ported from check_destructive_patterns()
# shai_hulud_wiper_regex, which upstream describes as "SPECIFIC signatures from
# actual malware (Koi Security disclosure)":
#   Bun.spawnSync.{1,50}(cmd.exe|bash).{1,100}(del /F|shred|cipher /W)
#   shred.{1,30}-[nuvz].{1,50}($HOME|~/)
#   cipher[[:space:]]*/W:.{0,30}USERPROFILE
#   del[[:space:]]*/F[[:space:]]*/Q[[:space:]]*/S.{1,30}USERPROFILE
#   find.{1,30}$HOME.{1,50}shred
#   rd[[:space:]]*/S[[:space:]]*/Q.{1,30}USERPROFILE
# These complement DEADMAN_DESTRUCT_PATTERNS (rm/del/Remove-Item/find family):
# the wiper variants overwrite rather than unlink, so an rm-only rule misses them.
DEADMAN_WIPER_PATTERNS = [
    (re.compile(r'(?i)\bshred\s{1,4}-[nuvz]{1,4}\b[^\n]{0,50}(\$HOME|\$\{HOME\}|~/|/home/)'),
     "secure-erase (shred) of files under the home directory"),
    (re.compile(r'(?i)\bfind\s{1,4}(\$HOME|\$\{HOME\}|~)[^\n]{0,60}\bshred\b'),
     "find-driven mass shred under the home directory"),
    (re.compile(r'(?i)(\$HOME|\$\{HOME\}|~/|/home/)[^\n]{0,80}\bxargs\s{1,4}shred\b'),
     "piped mass shred (xargs shred) of files under the home directory"),
    (re.compile(r'(?i)\bcipher\s{0,4}/W:[^\n]{0,30}USERPROFILE'),
     "Windows free-space overwrite of the user profile (cipher /W:)"),
    (re.compile(r'(?i)\bdel\s{0,4}/F\s{0,4}/Q\s{0,4}/S\b[^\n]{0,30}USERPROFILE'),
     "Windows recursive force-delete of the user profile (del /F /Q /S)"),
    (re.compile(r'(?i)\brd\s{0,4}/S\s{0,4}/Q\b[^\n]{0,30}USERPROFILE'),
     "Windows recursive directory removal of the user profile (rd /S /Q)"),
    (re.compile(r'(?i)\bBun\.spawnSync\b[^\n]{0,60}(cmd\.exe|bash)[^\n]{0,100}'
                r'(del\s{1,4}/F|shred|cipher\s{1,4}/W)'),
     "Bun.spawnSync shelling out to a wiper command "
     "(Shai-Hulud 2.0 wiper, Koi Security disclosure)"),
]

# TruffleHog download + execution. The Second Coming payload pulls the TruffleHog
# binary at install time and runs it over the filesystem to harvest GitHub PATs,
# npm tokens, and cloud credentials before exfiltration.
# Ported from check_trufflehog_activity() HIGH-risk patterns (bounded to stay ReDoS-safe).
# Strong, context-independent harvest signals: TruffleHog actually invoked against
# the filesystem or targeting tokens. These fire everywhere (critical).
TRUFFLEHOG_HARVEST_PATTERNS = [
    (re.compile(r'(?i)\btrufflehog\b[^\n]{0,120}\b(filesystem|--?results|--?json|--?no-update)\b'),
     "TruffleHog invoked against the filesystem (credential harvest)"),
    (re.compile(r'(?i)\btrufflehog\b[^\n]{0,120}\b(NPM_TOKEN|GITHUB_TOKEN|AWS_(ACCESS|SECRET)[A-Z_]{0,20}|env)\b'),
     "TruffleHog credential-scanning pattern targeting tokens/environment"),
]

# Bare TruffleHog binary DOWNLOAD. Suspicious inside a package install/runtime
# script (packages have no business fetching a secret scanner), but it is ALSO
# the canonical benign CI idiom (curl .../trufflehog.tar.gz | tar xz). So this is
# fired at critical ONLY when the file is NOT a CI workflow (see _is_ci_workflow).
TRUFFLEHOG_DOWNLOAD_PATTERN = re.compile(
    r'(?i)\b(curl|wget|download|bunExecutable)\b[^\n]{0,120}trufflehog'
)


def _is_ci_workflow(rel_path):
    """True for GitHub Actions / CI workflow files, where installing TruffleHog
    (a legitimate secret scanner) is expected rather than an IOC."""
    p = (rel_path or '').replace('\\', '/').lower()
    return '.github/workflows/' in p or '.gitlab-ci' in p or '/.circleci/' in p

# Dead-man's switch / self-destruct fallback: the install hook recursively deletes
# the victim's home directory when credential theft or authentication fails.
# Ported from check_destructive_patterns() basic_destructive_regex, which is scoped
# to $HOME / ~ / /home/ targets only (upstream removed context-free globs to kill FPs).
DEADMAN_DESTRUCT_PATTERNS = [
    (re.compile(r'(?i)\brm\s+(?:-[a-z]{1,4}|--recursive|--force|--no-preserve-root)'
                r'(?:\s+(?:-[a-z]{1,4}|--recursive|--force|--no-preserve-root))*\s+["\']?'
                r'(\$HOME|\$\{HOME\}|~|/home/(?:\$\{?\w+\}?|\w+)?)'
                r'/?["\']?(?![\w./])'),
     "recursive delete of the home directory (rm -rf $HOME / rm -rf ~)"),
    (re.compile(r'(?i)\bdel\s+/s\s+/q\s+(%USERPROFILE%|\$HOME)'),
     "recursive delete of the Windows user profile (del /s /q %USERPROFILE%)"),
    (re.compile(r'(?i)\bRemove-Item\s+-Recurse\b[^\n]{0,60}(\$HOME|\$env:USERPROFILE|~(?![a-zA-Z0-9_/]))'),
     "PowerShell recursive delete of the home directory"),
    (re.compile(r'(?i)\bfind\s+(\$HOME|\$\{HOME\}|~(?![a-zA-Z0-9_/])|/home/)[^\n]{0,100}(-delete\b|-exec\s+rm\b)'),
     "find-based mass delete under the home directory"),
]

# Conditional destruction: destroy-on-auth-failure wording that upstream matches in
# shell contexts (check_destructive_patterns shell_conditional_regex).
DEADMAN_CONDITIONAL_PATTERNS = [
    (re.compile(r'(?i)\bif\b[^\n]{0,80}\bcredential\w{0,6}\b[^\n]{0,80}\b(fail|error)\w{0,4}\b[^\n]{0,60}'
                r'\brm\b[^\n]{0,50}(\$HOME/?(?![\w./])|~/?(?![\w./])|/home/\w+/?(?![\w./])'
                r'|\.npmrc|\.ssh|\.aws|\.netrc|\.git-credentials|keychain|credentials?)'),
     "destroy-on-credential-failure conditional targeting the home dir / credential store"),
    (re.compile(r'(?i)\bif\b[^\n]{0,80}\btoken\b[^\n]{0,60}\bnot\s+found\b[^\n]{0,60}\b(delete|rm)\b'),
     "destroy-on-missing-token conditional"),
    (re.compile(r'(?i)\bif\b[^\n]{0,80}\bgithub\b[^\n]{0,60}\bauth\w{0,6}\b[^\n]{0,60}\bfail\w{0,4}\b[^\n]{0,40}\brm\b'),
     "destroy-on-GitHub-auth-failure conditional"),
    (re.compile(r'(?i)\bcatch\b[^\n]{0,60}\brm\s+-[a-z]{1,4}\b'),
     "recursive delete inside an error handler (destructive fallback)"),
]

# JS form of the same dead-man's switch: resolve the home directory, then remove it
# recursively. Reported only when BOTH halves are present in one file, matching the
# combined-signal convention used by forensics_core's destructive-fallback rule.
HOMEDIR_REFERENCE = re.compile(
    r'(?i)\b(os\.homedir\s*\(\s*\)'
    r'|require\(\s*["\']os["\']\s*\)\s*\.\s*homedir'
    r'|process\.env\.(HOME|USERPROFILE)\b)'
)
# Only a delete whose FIRST argument IS the home directory itself (not a subpath
# under it). rmSync(os.homedir(), {recursive:true}) is the dead-man's switch;
# rmSync(path.join(home,'.cache'), {recursive:true}) is benign cache cleanup and
# must NOT fire. The home ref must be the whole first arg (optionally a trailing
# slash), immediately followed by the arg separator/close — never a path.join or
# a "+ '/sub'" concatenation.
RECURSIVE_DELETE = re.compile(
    r'(?i)\b(fs\.promises\.rm|fs\.rmSync|fs\.rm|fs\.rmdirSync|rmSync|rmdirSync|rimraf\.sync|rimraf)\s*\(\s*'
    r'(os\.homedir\s*\(\s*\)|process\.env\.(?:HOME|USERPROFILE)'
    r'|home|homedir|homeDir|homeDirectory|homePath|userHome|userDir|HOME)'
    r'\s*/?\s*[,)]'
    # [\s\S] (not [^\n]) so prettier-formatted multiline options still match;
    # accept the truthy shorthands recursive:!0 / recursive:1 too.
    r'[\s\S]{0,120}recursive\s*:\s*(?:true|!0|1)\b'
)

# File types worth running the Second Coming content signatures over. Manifests,
# JS/TS entrypoints, workflow YAML, and install shell scripts cover every observed
# delivery surface for this campaign.
SECOND_COMING_SCAN_EXTS = (
    '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.json',
    '.yml', '.yaml', '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd', '.py',
)

RELAY_PATTERN = re.compile(
    r'^(node|python|python3|sh|bash|bun|deno)\s+[\w./-]+\.(js|mjs|cjs|py|sh)$'
)

KNOWN_SAFE_HOOKS = re.compile(
    r'^('
    r'husky(\s+(install|init))?|'
    r'is-ci\s*\|\|\s*husky\s+(install|init)|'
    r'patch-package|'
    r'prisma\s+generate|'
    r'prisma\s+migrate\s+deploy|'
    r'tsc(\s+(-b|--build|--noEmit))?|'
    r'esbuild\b[^|;&]*|'
    r'(node-gyp\s+)?rebuild|'
    r'electron-builder\s+install-app-deps|'
    r'rimraf\s+\S+|'
    r'ngcc(\s+[^\s|;&]+)*|'
    r'opencollective\s+postinstall|'
    r'playwright\s+install(\s+[^\s|;&]+)*|'
    r'husky(\s+(install|init))?\s*&&\s*npm\s+run\s+(build|compile|prepare)|'
    r'npm\s+run\s+(build|compile|prepare)|'
    r'npx\s+browserslist@latest\s+--update-db|'
    r'lefthook\s+install|'
    r'simple-git-hooks'
    r')$'
)


def scan_package_json(file_path, rel_path):
    """Check NPM lifecycle scripts for suspicious commands."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        scripts = data.get('scripts', {})
        for hook in DANGEROUS_NPM_HOOKS:
            if hook in scripts:
                cmd = scripts[hook]
                cmd = cmd[:10000]

                # Check for suspicious commands
                found_suspicious = False
                for pattern, desc in SUSPICIOUS_COMMANDS:
                    if pattern.search(cmd):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"NPM Hook: Suspicious '{hook}'",
                            description=f"Hook contains {desc}",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="lifecycle-hook"
                        ))
                        found_suspicious = True
                        break

                if not found_suspicious:
                    # Check for filename relay pattern: node/python/sh/bash <file>
                    # This is THE standard supply chain attack entry point.
                    # Even legitimate uses warrant HIGH because the external
                    # script can contain anything. Review the referenced file.
                    if RELAY_PATTERN.match(cmd.strip()):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="high",
                            title=f"NPM Hook: '{hook}' Runs External Script",
                            description="Lifecycle hook executes external file (standard supply chain attack pattern)",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="lifecycle-hook"
                        ))
                    elif KNOWN_SAFE_HOOKS.match(cmd.strip()):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="low",
                            title=f"NPM Hook: '{hook}' (Known Safe Pattern)",
                            description="Lifecycle hook uses recognized build tooling command",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="lifecycle-hook"
                        ))
                    else:
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="medium",
                            title=f"NPM Hook: '{hook}' Present",
                            description="Lifecycle hook exists (common malware vector)",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="lifecycle-hook"
                        ))

                # Check for paste service / dead-drop URLs
                for pattern, desc in PASTE_SERVICE_PATTERNS:
                    if pattern.search(cmd):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"NPM Hook: Paste Service URL in '{hook}'",
                            description=f"Lifecycle hook references {desc}",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="lifecycle-hook"
                        ))
                        break

                # Check for agent config directory writes
                for pattern, desc in AGENT_CONFIG_DIR_PATTERNS:
                    if pattern.search(cmd):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"NPM Hook: Agent Config Dir Write in '{hook}'",
                            description=f"Lifecycle hook writes to AI agent config directory: {desc}",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="lifecycle-hook"
                        ))
                        break

                # Check for anti-forensics patterns
                for pattern, desc in ANTI_FORENSICS_PATTERNS:
                    if pattern.search(cmd):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"Anti-Forensics in '{hook}' Hook",
                            description=f"Lifecycle hook contains self-destructing pattern: {desc} (Axios supply chain attack pattern, March 2026)",
                            file=rel_path, line=0,
                            snippet=f"{hook}: {cmd[:120]}",
                            category="anti-forensics"
                        ))
                        break

        # Check bin field for command-jacking (Checkmarx, October 2024)
        bin_field = data.get('bin', {})
        if isinstance(bin_field, str):
            bin_field = {data.get('name', ''): bin_field}
        if isinstance(bin_field, dict):
            for cmd_name in bin_field:
                if cmd_name.lower() in SHADOWED_COMMANDS:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Command-Jacking: bin '{cmd_name}' Shadows System Command",
                        description=f"Package registers bin entry '{cmd_name}' which shadows a common CLI tool. After install, running '{cmd_name}' executes this package's code instead of the real tool (Checkmarx Command-Jacking, October 2024)",
                        file=rel_path, line=0,
                        snippet=f"bin.{cmd_name}: {str(bin_field[cmd_name])[:80]}",
                        category="command-jacking"
                    ))

    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_js_anti_forensics(file_path, rel_path):
    """Detect anti-forensics and campaign IOC patterns in lifecycle JS files.

    Patterns include: self-deleting scripts (fs.unlinkSync(__filename)),
    package.json overwrite after execution, and version mismatch indicators.
    Source: Axios supply chain compromise, March 31, 2026.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        lines = content.split('\n')
        for i, line in enumerate(lines):
            line = core.clip_line(line)
            for pattern, desc in ANTI_FORENSICS_PATTERNS:
                if pattern.search(line):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Anti-Forensics Pattern: {desc}",
                        description="Script contains self-destructing or evidence-cleanup pattern (supply chain attack indicator)",
                        file=rel_path, line=i + 1,
                        snippet=line.strip()[:120],
                        category="anti-forensics"
                    ))

            for pattern, desc in INSTALL_SCRIPT_IOC_PATTERNS:
                if pattern.search(line):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Install Script IOC: {desc}",
                        description=(
                            "Lifecycle script contains a high-confidence supply "
                            "chain IOC or behavior observed in active 2026 npm "
                            "credential-stealing campaigns."
                        ),
                        file=rel_path, line=i + 1,
                        snippet=line.strip()[:120],
                        category="install-script-ioc"
                    ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_js_install_iocs(file_path, rel_path):
    """Detect high-confidence install-script IOCs in generic JS entrypoints."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        for i, line in enumerate(content.split('\n')):
            line = core.clip_line(line)
            for pattern, desc in INSTALL_SCRIPT_IOC_PATTERNS:
                if pattern.search(line):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Install Script IOC: {desc}",
                        description=(
                            "JavaScript entrypoint contains a high-confidence "
                            "supply chain IOC or behavior observed in active "
                            "2026 npm credential-stealing campaigns."
                        ),
                        file=rel_path, line=i + 1,
                        snippet=line.strip()[:120],
                        category="install-script-ioc"
                    ))
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_setup_py(file_path, rel_path):
    """Check Python setup.py for cmdclass overrides (arbitrary code on pip install)."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check for cmdclass override
        if re.search(r'cmdclass\s*=\s*\{', content):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="setup.py: cmdclass Override",
                description="Custom cmdclass can execute arbitrary code during pip install",
                file=rel_path, line=0,
                snippet="cmdclass override detected",
                category="lifecycle-hook"
            ))

        # Check for subprocess/os.system in setup.py
        for suspicious in ['subprocess', 'os.system', 'os.popen', 'urllib', 'requests.', 'socket.']:
            if suspicious in content:
                line_no = 0
                for i, line in enumerate(content.split('\n')):
                    if suspicious in line:
                        line_no = i + 1
                        break
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"setup.py: Suspicious Import ({suspicious})",
                    description="setup.py contains network/execution code that runs during installation",
                    file=rel_path, line=line_no,
                    snippet=content.split('\n')[line_no - 1].strip()[:120] if line_no > 0 else suspicious,
                    category="lifecycle-hook"
                ))

        # Check for Command-Jacking via console_scripts entry points
        entry_points_match = re.search(r"entry_points\s*=\s*\{[^}]*'console_scripts'\s*:\s*\[(.*?)\]", content, re.DOTALL)
        if entry_points_match:
            scripts_text = entry_points_match.group(1)
            for ep_match in re.finditer(r"['\"](\w+)\s*=", scripts_text):
                cmd_name = ep_match.group(1)
                if cmd_name.lower() in SHADOWED_COMMANDS:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Command-Jacking: console_scripts '{cmd_name}' Shadows System Command",
                        description=f"Package registers console_scripts entry '{cmd_name}' which shadows a common CLI tool (Checkmarx Command-Jacking, October 2024)",
                        file=rel_path, line=0,
                        snippet=f"console_scripts: {cmd_name}",
                        category="command-jacking"
                    ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_pyproject_toml(file_path, rel_path):
    """Check pyproject.toml for cmdclass overrides."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if '[tool.setuptools.cmdclass]' in content or 'cmdclass' in content.lower():
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="pyproject.toml: cmdclass Override",
                description="Custom cmdclass can execute arbitrary code during pip install",
                file=rel_path, line=0,
                snippet="cmdclass override in pyproject.toml",
                category="lifecycle-hook"
            ))

        # Check for Command-Jacking via [project.scripts]
        in_scripts = False
        for i, line in enumerate(content.split('\n')):
            stripped = line.strip()
            if stripped in ('[project.scripts]', '[project.entry-points.console_scripts]'):
                in_scripts = True
                continue
            if in_scripts:
                if stripped.startswith('['):
                    in_scripts = False
                    continue
                ep_match = re.match(r'(\w+)\s*=', stripped)
                if ep_match:
                    cmd_name = ep_match.group(1)
                    if cmd_name.lower() in SHADOWED_COMMANDS:
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"Command-Jacking: [project.scripts] '{cmd_name}' Shadows System Command",
                            description=f"Package registers script entry '{cmd_name}' which shadows a common CLI tool (Checkmarx Command-Jacking, October 2024)",
                            file=rel_path, line=i + 1,
                            snippet=stripped[:120],
                            category="command-jacking"
                        ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


# --- .pth File Injection Detection (liteLLM-style attack, March 2026) ---

# Known malicious .pth filenames - lazy loaded from ioc_manager
_KNOWN_MALICIOUS_PTH = None

_FALLBACK_MALICIOUS_PTH = {
    'litellm_init.pth', 'litellm-init.pth', 'litellm.pth',
    'llm_init.pth', 'init_hook.pth', 'startup.pth',
}


def _get_known_malicious_pth():
    """Lazy-load known malicious .pth filenames from ioc_manager."""
    global _KNOWN_MALICIOUS_PTH
    if _KNOWN_MALICIOUS_PTH is None:
        try:
            import ioc_manager as _ioc
            _KNOWN_MALICIOUS_PTH = _ioc.get_iocs().get('malicious_pth_files', _FALLBACK_MALICIOUS_PTH)
        except (ImportError, OSError, json.JSONDecodeError, ValueError) as e:
            print(f"[!] IOC loading failed, using fallback: {e}", file=sys.stderr)
            _KNOWN_MALICIOUS_PTH = _FALLBACK_MALICIOUS_PTH
    return _KNOWN_MALICIOUS_PTH

PTH_EXEC_PATTERNS = [
    (re.compile(r'\bexec\s*\('), "exec() call"),
    (re.compile(r'\beval\s*\('), "eval() call"),
    (re.compile(r'\bcompile\s*\('), "compile() call"),
    (re.compile(r'\b__import__\s*\('), "__import__() call"),
    (re.compile(r'\bos\.system\s*\('), "os.system() call"),
    (re.compile(r'\bsubprocess'), "subprocess usage"),
]


def scan_pth_files(file_path, rel_path):
    """Detect malicious .pth files (Python startup injection vector).

    .pth files in site-packages execute import statements on Python startup.
    The liteLLM attack (March 2026) used this to auto-exfiltrate all credentials
    on `pip install` without any user action.
    """
    findings = []
    basename = os.path.basename(file_path)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return findings

    lines = content.strip().split('\n')

    # Check for known malicious filenames (CRITICAL)
    if basename.lower() in _get_known_malicious_pth():
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title=f"Known Malicious .pth Filename: {basename}",
            description="Filename matches known supply chain attack IOC (liteLLM-style .pth injection)",
            file=rel_path, line=0,
            snippet=f"Known IOC: {basename}",
            category="pth-injection"
        ))

    # Check for base64 content (CRITICAL)
    # Pre-filter with simple 'in' check to avoid ReDoS on long alphanumeric lines
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    for i, line in enumerate(lines):
        # Truncate rather than skip: a `continue` here let a payload hide behind
        # 10k characters of padding on the same line.
        stripped = core.clip_line(line.strip())
        # Skip filesystem paths (legitimate .pth content)
        if stripped.startswith('/') or stripped.startswith('.') or 'site-packages' in stripped:
            continue
        # Require at least one +, /, or = to distinguish from plain alphanumeric
        if not any(c in stripped for c in ('+', '/', '=')):
            continue
        if base64_pattern.search(stripped):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=".pth File: Base64 Content",
                description=".pth file contains base64-encoded data (obfuscated payload, liteLLM attack pattern)",
                file=rel_path, line=i + 1,
                snippet=line.strip()[:120],
                category="pth-injection"
            ))
            break  # One finding per file for base64

    # Check for exec/eval/compile (CRITICAL)
    for i, line in enumerate(lines):
        for pattern, desc in PTH_EXEC_PATTERNS:
            if pattern.search(line):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f".pth File: {desc}",
                    description=f".pth file contains {desc}. Executes on Python startup without user action.",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="pth-injection"
                ))
                break  # One finding per line

    # Check for import statements (MEDIUM - legitimate but worth flagging)
    import_pattern = re.compile(r'^import\s+\S+')
    for i, line in enumerate(lines):
        if import_pattern.match(line.strip()):
            # Only flag if no exec/eval already found (to avoid noise)
            if not any(f.category == "pth-injection" and f.severity == "critical" for f in findings):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title=".pth File: Import Statement",
                    description=".pth file with import statement runs code on Python startup",
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="pth-injection"
                ))
                break  # One import finding is enough

    # If .pth file exists but has no suspicious content, still note it (LOW)
    if not findings:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title=f".pth File Present: {basename}",
            description=".pth files execute on Python startup. Verify this is intentional.",
            file=rel_path, line=0,
            snippet=content[:120].replace('\n', ' '),
            category="pth-injection"
        ))

    return findings


def scan_claude_settings(file_path, rel_path):
    """Detect malicious Claude Code hook injection in .claude/settings.json.

    Mini Shai-Hulud (TeamPCP Wave 6, April 2026) injects SessionStart hooks
    that execute dropper scripts on every Claude Code session start.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        hooks = data.get('hooks', {})
        for event_name, event_hooks in hooks.items():
            if not isinstance(event_hooks, list):
                continue
            for hook_entry in event_hooks:
                if not isinstance(hook_entry, dict):
                    continue
                # Support both nested format ({matcher, hooks: [{command}]})
                # and flat format ({command, type}) used in Claude Code docs
                if 'hooks' in hook_entry:
                    hook_list = hook_entry.get('hooks', [])
                elif 'command' in hook_entry:
                    hook_list = [hook_entry]
                else:
                    continue
                for hook in hook_list:
                    if not isinstance(hook, dict):
                        continue
                    cmd = hook.get('command', '')
                    if not cmd:
                        continue
                    for pattern, desc in SUSPICIOUS_COMMANDS:
                        if pattern.search(cmd):
                            findings.append(core.Finding(
                                scanner=SCANNER_NAME, severity="critical",
                                title=f"Claude Code Hook Injection: {event_name}",
                                description=f"Claude Code {event_name} hook contains {desc}. "
                                    "Mini Shai-Hulud injects SessionStart hooks to re-execute "
                                    "dropper on every session (TeamPCP Wave 6, April 2026)",
                                file=rel_path, line=0,
                                snippet=f"{event_name}: {cmd[:120]}",
                                category="ai-tool-persistence"
                            ))
                            break
                    if re.search(r'setup\.mjs|execution\.js|config\.mjs', cmd):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title="Claude Code Hook: Shai-Hulud Dropper",
                            description="Claude Code hook executes known TeamPCP dropper filename",
                            file=rel_path, line=0,
                            snippet=f"{event_name}: {cmd[:120]}",
                            category="ai-tool-persistence"
                        ))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, TypeError, AttributeError):
        pass
    return findings


def scan_vscode_tasks(file_path, rel_path):
    """Detect malicious VS Code tasks with folderOpen auto-run.

    Mini Shai-Hulud injects tasks.json with runOptions.runOn: folderOpen
    to execute dropper when a developer opens the project in VS Code.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        for task in data.get('tasks', []):
            run_options = task.get('runOptions', {})
            if run_options.get('runOn') == 'folderOpen':
                cmd = task.get('command', '')
                label = task.get('label', '')
                has_suspicious = any(p.search(cmd) for p, _ in SUSPICIOUS_COMMANDS)
                if has_suspicious or re.search(r'setup\.mjs|execution\.js|config\.mjs', cmd):
                    severity = "critical"
                else:
                    severity = "medium"
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity=severity,
                    title="VS Code Task: Auto-Execute on Folder Open",
                    description=f"Task '{label}' runs automatically when project is opened. "
                        "Mini Shai-Hulud uses this as a persistence vector (TeamPCP Wave 6)",
                    file=rel_path, line=0,
                    snippet=f"runOn: folderOpen, command: {cmd[:100]}",
                    category="ai-tool-persistence"
                ))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, TypeError, AttributeError):
        pass
    return findings


def scan_second_coming_indicators(file_path, rel_path):
    """Detect "Shai-Hulud: The Second Coming" behavioral signatures.

    Covers the November 2025 fake-Bun npm wave and its December 2025 "Golden Path"
    rename: dropper/exfil artifact references, the fake-Bun preinstall hook, the
    GitHub dead-drop repository description marker, the SHA1HULUD self-hosted
    runner marker, TruffleHog download-and-execute credential harvesting, and the
    dead-man's switch that wipes $HOME when credential theft fails.

    Artifact names and marker strings are taken verbatim from the
    Cobenian/shai-hulud-detect reference detector; nothing here is inferred.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        for i, line in enumerate(content.split('\n')):
            line = core.clip_line(line)

            for pattern, desc in SECOND_COMING_PATTERNS:
                if pattern.search(line):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Shai-Hulud Second Coming: {desc}",
                        description=(
                            "File references a confirmed 'Shai-Hulud: The Second "
                            "Coming' artifact (November 2025 fake-Bun npm wave, "
                            "1,100+ packages; December 2025 'Golden Path' rename). "
                            "The campaign installs a fake Bun runtime, harvests "
                            "credentials, and exfiltrates them to attacker-created "
                            "GitHub repositories."
                        ),
                        file=rel_path, line=i + 1,
                        snippet=line.strip()[:120],
                        category="install-script-ioc"
                    ))

            for pattern, desc in WEAK_BUN_FILENAME_HINTS:
                if pattern.search(line):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="medium",
                        title=f"Shai-Hulud Second Coming (weak filename hint): {desc}",
                        description=(
                            "File references a Second Coming / Golden Path dropper "
                            "filename. The name alone is a weak signal (it also appears "
                            "in legitimate Bun projects and in write-ups about the "
                            "attack); corroborate with a preinstall hook, exfil staging "
                            "file, or the repo marker before treating as an infection."
                        ),
                        file=rel_path, line=i + 1,
                        snippet=line.strip()[:120],
                        category="install-script-ioc"
                    ))

            for pattern, desc in TRUFFLEHOG_HARVEST_PATTERNS:
                if pattern.search(line):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"TruffleHog Credential Harvest: {desc}",
                        description=(
                            "Install/runtime script downloads or invokes TruffleHog "
                            "to sweep the filesystem for secrets. This is the "
                            "credential-harvesting stage of Shai-Hulud 'The Second "
                            "Coming', used to collect GitHub PATs, npm tokens, and "
                            "cloud keys before exfiltration."
                        ),
                        file=rel_path, line=i + 1,
                        snippet=line.strip()[:120],
                        category="install-script-ioc"
                    ))
                    break

            # Bare TruffleHog download: an IOC in a package install/runtime script,
            # but the normal way CI installs the scanner — suppress in CI workflows.
            if not _is_ci_workflow(rel_path) and TRUFFLEHOG_DOWNLOAD_PATTERN.search(line):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="TruffleHog Credential Harvest: binary download in an install/runtime script",
                    description=(
                        "A package install or runtime script downloads the TruffleHog "
                        "binary. Legitimate packages do not fetch a secret scanner at "
                        "install time; this is the credential-harvest stage of "
                        "Shai-Hulud 'The Second Coming'. (Suppressed in CI workflow "
                        "files, where installing TruffleHog is expected.)"
                    ),
                    file=rel_path, line=i + 1,
                    snippet=line.strip()[:120],
                    category="install-script-ioc"
                ))

            for pattern, desc in DEADMAN_DESTRUCT_PATTERNS:
                if pattern.search(line):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Dead-Man's Switch: {desc}",
                        description=(
                            "Script recursively deletes the user's home directory. "
                            "Shai-Hulud 'The Second Coming' fires this destructive "
                            "fallback from its install hook when credential theft or "
                            "GitHub authentication fails. Treat the host as "
                            "destructive-capable and do NOT rotate the monitored "
                            "token before neutralising the script."
                        ),
                        file=rel_path, line=i + 1,
                        snippet=line.strip()[:120],
                        category="destructive-fallback"
                    ))
                    break

            for pattern, desc in DEADMAN_CONDITIONAL_PATTERNS:
                if pattern.search(line):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Dead-Man's Switch: {desc}",
                        description=(
                            "Script deletes files on an authentication or credential "
                            "failure path. Shai-Hulud 'The Second Coming' uses this "
                            "destroy-on-failure fallback so a machine that cannot be "
                            "robbed is wiped instead."
                        ),
                        file=rel_path, line=i + 1,
                        snippet=line.strip()[:120],
                        category="destructive-fallback"
                    ))
                    break

        # File-level combined signal: home-directory resolution + recursive delete.
        # Neither half is conclusive alone; together they are the JS dead-man's switch.
        delete_match = RECURSIVE_DELETE.search(content)
        if delete_match and HOMEDIR_REFERENCE.search(content):
            line_no = content.count('\n', 0, delete_match.start()) + 1
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title="Dead-Man's Switch: Home Directory Resolved and Recursively Deleted",
                description=(
                    "File resolves the home directory (os.homedir() / process.env.HOME) "
                    "AND performs a recursive delete (rmSync/fs.rm with recursive: true). "
                    "Combined, this is the JavaScript form of the Shai-Hulud 'The Second "
                    "Coming' self-destruct that wipes the host when credential "
                    "exfiltration fails."
                ),
                file=rel_path, line=line_no,
                snippet=delete_match.group(0).strip()[:120],
                category="destructive-fallback"
            ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_shai_hulud_family_indicators(file_path, rel_path):
    """Detect Shai-Hulud FAMILY signatures outside the Second Coming wave.

    Sibling of scan_second_coming_indicators(), covering the behaviours the
    November-2025 wave does not carry:

      * GitHub dead-drop repository description / beacon markers used by the
        v1 worm's successors (SHAI_HULUD_REPO_MARKERS).
      * Mini Shai-Hulud (April-May 2026 TanStack / AntV / atool) dropper
        filenames and Bun install-hook delivery (MINI_SHAI_HULUD_PATTERNS).
      * Wipe-threat token description strings (WIPE_THREAT_MARKERS) and
        dead-man's-switch daemon artefacts (DEADMAN_SERVICE_PATTERNS).
      * Secure-erase wiper stages that overwrite rather than unlink
        (DEADMAN_WIPER_PATTERNS).

    Every literal is quoted from the Cobenian/shai-hulud-detect reference
    detector or its CHANGELOG; see each pattern list for the source function.
    """
    findings = []

    ioc_groups = (
        (SHAI_HULUD_REPO_MARKERS, "install-script-ioc",
         "Shai-Hulud Dead-Drop Marker",
         "File contains a GitHub repository description or beacon string that "
         "the Shai-Hulud worm family stamps on the public repositories it "
         "creates under the victim's own account to exfiltrate stolen "
         "credentials. Treat every credential reachable from this machine as "
         "compromised."),
        (MINI_SHAI_HULUD_PATTERNS, "install-script-ioc",
         "Mini Shai-Hulud IOC",
         "File references a confirmed Mini Shai-Hulud artifact (April-May 2026 "
         "TanStack / AntV / atool npm waves). The campaign delivers an "
         "obfuscated Bun payload through a preinstall/prepare hook or a "
         "malicious optionalDependencies orphan-commit reference, then steals "
         "cloud, npm, GitHub and SSH credentials."),
        (WIPE_THREAT_MARKERS, "destructive-fallback",
         "Dead-Man's Switch",
         "File contains the wipe-threat string the worm plants as the "
         "description of the GitHub token its dead-man's switch monitors. "
         "Revoking that token is what FIRES the wipe. Stop and remove the "
         "monitoring service BEFORE rotating any credential."),
        (DEADMAN_SERVICE_PATTERNS, "destructive-fallback",
         "Dead-Man's Switch",
         "File references the Mini Shai-Hulud dead-man's-switch daemon "
         "(gh-token-monitor / kitty-monitor). The daemon polls GitHub and wipes "
         "the host when its monitored token is revoked. Stop and remove the "
         "service BEFORE rotating any credential."),
        (DEADMAN_WIPER_PATTERNS, "destructive-fallback",
         "Dead-Man's Switch",
         "File contains a secure-erase wiper stage (shred / cipher /W / "
         "del /F /Q /S / rd /S /Q) targeting the user's home directory or "
         "profile. This is the Shai-Hulud destructive fallback that runs when "
         "credential theft fails: it overwrites rather than unlinks, so an "
         "rm-based rule alone does not see it."),
    )

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        for i, line in enumerate(content.split('\n')):
            line = core.clip_line(line)
            for patterns, category, title_prefix, description in ioc_groups:
                for pattern, desc in patterns:
                    if pattern.search(line):
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"{title_prefix}: {desc}",
                            description=description,
                            file=rel_path, line=i + 1,
                            snippet=line.strip()[:120],
                            category=category
                        ))
                        break  # one finding per group per line

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Lifecycle Script Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning lifecycle scripts in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True, skip_lockfiles=True):
        basename = os.path.basename(file_path)

        # Shai-Hulud "The Second Coming" signatures run alongside (not instead of)
        # the per-filename dispatch below, because the campaign's markers appear in
        # manifests, JS entrypoints, workflow YAML, and install shell scripts alike.
        if basename == 'package.json' or file_path.endswith(SECOND_COMING_SCAN_EXTS):
            all_findings.extend(scan_second_coming_indicators(file_path, rel_path))
            # Remaining Shai-Hulud family waves (v1 successors, Mini waves,
            # copycats) share the same delivery surfaces, so they run over the
            # same file set.
            all_findings.extend(scan_shai_hulud_family_indicators(file_path, rel_path))

        if basename == 'package.json':
            all_findings.extend(scan_package_json(file_path, rel_path))
        elif basename == 'setup.py':
            all_findings.extend(scan_setup_py(file_path, rel_path))
        elif basename == 'pyproject.toml':
            all_findings.extend(scan_pyproject_toml(file_path, rel_path))
        elif basename.endswith('.pth'):
            all_findings.extend(scan_pth_files(file_path, rel_path))
        elif basename in ('setup.js', 'install.js', 'postinstall.js', 'preinstall.js',
                          'setup.mjs', 'config.mjs', 'opensearch_init.js', 'ai_init.js'):
            all_findings.extend(scan_js_anti_forensics(file_path, rel_path))
        elif basename == 'index.js':
            all_findings.extend(scan_js_install_iocs(file_path, rel_path))
        elif basename == 'binding.gyp':
            all_findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="binding.gyp: Implicit Native Build",
                description="binding.gyp triggers node-gyp rebuild on install without explicit install script (native code execution)",
                file=rel_path, line=0,
                snippet="binding.gyp present (implicit install-time execution)",
                category="lifecycle-hook"
            ))
        elif basename == 'settings.json' and (os.sep + '.claude' + os.sep) in (os.sep + rel_path):
            all_findings.extend(scan_claude_settings(file_path, rel_path))
        elif basename == 'tasks.json' and (os.sep + '.vscode' + os.sep) in (os.sep + rel_path):
            all_findings.extend(scan_vscode_tasks(file_path, rel_path))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
