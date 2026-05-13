"""Shared constants for repo-forensics scanners.

Single source of truth for pattern sets used across multiple scanners,
preventing drift where the same concept has different coverage.
"""

EXFIL_VERBS = (
    'send', 'post', 'upload', 'forward', 'transmit', 'exfiltrate',
    'share', 'submit', 'deliver', 'write', 'pipe',
    'push', 'beacon', 'relay', 'report', 'notify',
    'dispatch', 'leak', 'siphon', 'extract', 'ship', 'stream',
    'overwrite', 'replace', 'inject',
)

EXFIL_VERBS_RE = r'(?:' + '|'.join(EXFIL_VERBS) + ')'

AUTO_EXEC_FILENAMES = {
    'heartbeat.md', 'claude.md', 'agents.md', 'settings.json',
    'soul.md', 'routine.md', 'boot.md', 'bootstrap.md',
    'identity.md', 'user.md', '.mcp.json', 'mcp.json',
}

def _to_regex_entry(fn):
    name, ext = fn.rsplit('.', 1) if '.' in fn else (fn, '')
    escaped = fn.replace('.', r'\.')
    if ext == 'md':
        return name.upper() + r'\.' + ext
    return escaped

AUTO_EXEC_PATHS_RE = r'(?:' + '|'.join(
    _to_regex_entry(fn) for fn in sorted(AUTO_EXEC_FILENAMES)
) + r'|\.claude/|commands/|hooks\.json)'

SEED_FILES = {
    'SKILL.md', 'SOUL.md', 'HEARTBEAT.md', 'ROUTINE.md',
    'AGENTS.md', 'BOOT.md', 'BOOTSTRAP.md',
    'CLAUDE.md', 'IDENTITY.md', 'USER.md',
}

GIT_UPDATABLE = {
    'changelog.md', 'readme.md', 'updates.md', 'release_notes.md',
    'release-notes.md', 'news.md',
    'changes.md', 'history.md', 'whatsnew.md', 'migration.md',
    'upgrade.md', 'patch-notes.md', 'versions.md',
}

SKILL_CONFIG_FILES = {
    'skill.md', 'soul.md', 'routine.md', 'heartbeat.md', 'agents.md',
    'claude.md', 'boot.md', 'bootstrap.md', 'identity.md', 'user.md',
    'readme.md', 'instructions.md', 'rules.md', 'workflow.md',
    'setup.md', 'config.md', 'guide.md', 'procedures.md',
    'runbook.md', 'playbook.md',
}

WRITE_VERBS_RE = r'(?:add|append|write|modify|update|edit|create|insert|put|place|include|overwrite|replace|set|change|patch|inject|prepend)'

REF_VERBS_RE = r'(?:read|follow|run|execute|apply|check|consult|open|include|see|refer\s+to|load|import|source|parse|process)'

REF_FILE_EXTS_RE = r'(?:md|txt|ya?ml|json|toml)'
