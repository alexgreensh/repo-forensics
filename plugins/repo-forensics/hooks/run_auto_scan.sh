#!/usr/bin/env bash
# Wrapper for PostToolUse auto-scan that fails loud if the target script
# is missing instead of silently dying.
#
# Caught by torture-room security-sentinel Finding 6.
#
# Without this wrapper, if the canonical skills/repo-forensics/scripts/
# auto_scan.py path is missing for any reason — plugin install corruption,
# partial file restore after a tamper attempt, botched rename, tarball
# extraction failure, or a future layout refactor that breaks the hook
# path — the agent hook runner would silently swallow the "file not
# found" failure and the user would have zero indication that their
# security hook is no longer firing. For a security tool, silent failure
# IS the worst failure mode.
#
# This wrapper:
#   1. Checks that auto_scan.py exists at the expected canonical path
#   2. If missing: prints a clear warning and exits 0 so the hook chain is not broken for the
#      user's Bash command — graceful degradation over blocking every
#      command
#   3. If present: exec into python3 on auto_scan.py with argv forwarding
#      preserved (the hook receives stdin from the agent hook runner)

set -u

SCRIPT="${CLAUDE_PLUGIN_ROOT}/skills/repo-forensics/scripts/auto_scan.py"
LAUNCHER="${CLAUDE_PLUGIN_ROOT}/hooks/python-launcher.sh"

if [ ! -f "$SCRIPT" ]; then
    echo "[repo-forensics] WARNING: auto_scan.py not found at: $SCRIPT"
    echo "[repo-forensics] Plugin install may be corrupt, or the skill layout may have changed."
    echo "[repo-forensics] Auto-scan hook disabled for this command. Update or reinstall repo-forensics."
    # exit 0 so we don't break the user's Bash command chain. Hook is
    # PostToolUse — its failure should not retroactively fail the command.
    exit 0
fi

if [ -f "$LAUNCHER" ]; then
    exec "${BASH:-/bin/bash}" "$LAUNCHER" "$SCRIPT"
fi

exec python3 "$SCRIPT"
