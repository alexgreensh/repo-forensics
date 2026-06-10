"""Shared constants for repo-forensics scanners (rules-as-data, U4).

Single source of truth for the verb/filename LISTS used across multiple
scanners. As of v2.10 the underlying lists live in a JSON rule pack
(data/rulepacks/shared.json) loaded via rule_loader; the composed regexes
(EXFIL_VERBS_RE, AUTO_EXEC_PATHS_RE, WRITE_VERBS_RE, REF_VERBS_RE) are rebuilt
here from those lists at import time. The *construction* of the composed
regexes is algorithm and stays in code; only the lists are data.

KTD-14 dependency law: this module may import rule_loader because
`forensics_core.py` never imports `_shared_patterns` (verified), so rule_loader
is never pulled into forensics_core's import graph. If the pack cannot be
loaded (corrupted/tampered install), we fall back to the historical lists so
the cross-scanner composed regexes never silently vanish — a corrupted install
is independently surfaced as a critical finding by the scanners that consume a
pack directly (scan_skill_threats / scan_mcp_security) and by the integrity
scanner.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rule_loader

# Historical fallbacks (only used if shared.json fails to load). Kept minimal
# and explicitly labelled so they are never mistaken for the source of truth.
_FALLBACK_EXFIL_VERBS = (
    'send', 'post', 'upload', 'forward', 'transmit', 'exfiltrate',
    'share', 'submit', 'deliver', 'write', 'pipe',
    'push', 'beacon', 'relay', 'report', 'notify',
    'dispatch', 'leak', 'siphon', 'extract', 'ship', 'stream',
    'overwrite', 'replace', 'inject',
)
_FALLBACK_AUTO_EXEC = {
    'heartbeat.md', 'claude.md', 'agents.md', 'settings.json',
    'soul.md', 'routine.md', 'boot.md', 'bootstrap.md',
    'identity.md', 'user.md', '.mcp.json', 'mcp.json',
}
_FALLBACK_SEED_FILES = {
    'SKILL.md', 'SOUL.md', 'HEARTBEAT.md', 'ROUTINE.md',
    'AGENTS.md', 'BOOT.md', 'BOOTSTRAP.md',
    'CLAUDE.md', 'IDENTITY.md', 'USER.md',
}
_FALLBACK_GIT_UPDATABLE = {
    'changelog.md', 'readme.md', 'updates.md', 'release_notes.md',
    'release-notes.md', 'news.md',
    'changes.md', 'history.md', 'whatsnew.md', 'migration.md',
    'upgrade.md', 'patch-notes.md', 'versions.md',
}
_FALLBACK_SKILL_CONFIG = {
    'skill.md', 'soul.md', 'routine.md', 'heartbeat.md', 'agents.md',
    'claude.md', 'boot.md', 'bootstrap.md', 'identity.md', 'user.md',
    'readme.md', 'instructions.md', 'rules.md', 'workflow.md',
    'setup.md', 'config.md', 'guide.md', 'procedures.md',
    'runbook.md', 'playbook.md',
}


def _values_for(pack, rule_id, fallback):
    """Return the (raw, pre-normalization) values list for a keyword rule id, or
    the fallback when the pack/rule is unavailable. The loader NFKC-lowercases
    keyword values; these lists are already lowercase except SEED_FILES, so we
    re-derive the original-case sets from the fallback shape where casing matters
    (SEED_FILES). For lowercase lists the pack values are authoritative."""
    if pack is None:
        return fallback
    for r in pack.all_rules:
        if r.id == rule_id and r.type == "keyword":
            return r.values
    return fallback


_PACK = rule_loader.load_pack("shared")

# EXFIL_VERBS: lowercase verb tuple. Pack keyword values are lowercased already.
EXFIL_VERBS = tuple(_values_for(_PACK, "SH-EV-001", _FALLBACK_EXFIL_VERBS))

# Composed regex (construction stays in code, rebuilt from the pack list).
EXFIL_VERBS_RE = r'(?:' + '|'.join(EXFIL_VERBS) + ')'

# AUTO_EXEC_FILENAMES: filename set. The pack stores them lowercase; the set is
# used for case-insensitive comparison downstream, so lowercase is fine.
AUTO_EXEC_FILENAMES = set(_values_for(_PACK, "SH-AE-001", _FALLBACK_AUTO_EXEC))


def _to_regex_entry(fn):
    name, ext = fn.rsplit('.', 1) if '.' in fn else (fn, '')
    escaped = fn.replace('.', r'\.')
    if ext == 'md':
        return name.upper() + r'\.' + ext
    return escaped


AUTO_EXEC_PATHS_RE = r'(?:' + '|'.join(
    _to_regex_entry(fn) for fn in sorted(AUTO_EXEC_FILENAMES)
) + r'|\.claude/|commands/|hooks\.json)'

# SEED_FILES casing matters (uppercased .md names). The loader lowercases
# keyword values, so we keep the original-case fallback as the source for the
# in-memory set while the pack remains the audit/feed surface. The fallback and
# pack are kept in lock-step by the parity gate.
SEED_FILES = set(_FALLBACK_SEED_FILES)

GIT_UPDATABLE = set(_values_for(_PACK, "SH-GU-001", _FALLBACK_GIT_UPDATABLE))

SKILL_CONFIG_FILES = set(_values_for(_PACK, "SH-SC-001", _FALLBACK_SKILL_CONFIG))

WRITE_VERBS_RE = r'(?:add|append|write|modify|update|edit|create|insert|put|place|include|overwrite|replace|set|change|patch|inject|prepend)'

REF_VERBS_RE = r'(?:read|follow|run|execute|apply|check|consult|open|include|see|refer\s+to|load|import|source|parse|process)'

REF_FILE_EXTS_RE = r'(?:md|txt|ya?ml|json|toml)'
