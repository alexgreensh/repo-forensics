#!/bin/bash
# repo-forensics - SessionStart First-Run Auto-Update Nudge
#
# Marketplace installs can go stale. This hook prints a one-time platform-aware
# message telling users how to keep repo-forensics current so they get new IOCs,
# detection rules, and critical security patches.
#
# For a security scanner specifically, stale installs are especially dangerous:
# users running repo-forensics against known supply chain attacks need the IOC
# list that was current at the time of the attack, not six weeks ago.
#
# Conditions (all must be true for the nudge to fire):
#   - running from a plugin cache (marketplace install, not a dev checkout)
#   - flag file absent (one-shot per user)
#   - REPO_FORENSICS_NUDGE environment variable not set to 0 (kill switch)
#
# Copyright (C) 2026 Alex Greenshpun
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

SCRIPT_DIR="$(dirname "$0")"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CODEX_ROOT="${CODEX_HOME:-${HOME}/.codex}"
if [ -d "$CODEX_ROOT" ]; then
    CODEX_ROOT="$(cd "$CODEX_ROOT" && pwd)"
fi
CLAUDE_ROOT="${HOME}/.claude"
if [ -d "$CLAUDE_ROOT" ]; then
    CLAUDE_ROOT="$(cd "$CLAUDE_ROOT" && pwd)"
fi

PLATFORM="generic"
STATE_ROOT="${HOME}/.repo-forensics"
if [[ "$PLUGIN_ROOT" == "$CODEX_ROOT/"* || "$PLUGIN_ROOT" == *"/.codex/"* ]]; then
    PLATFORM="codex"
    STATE_ROOT="${CODEX_ROOT}/repo-forensics"
elif [[ "$PLUGIN_ROOT" == "$CLAUDE_ROOT/"* || "$PLUGIN_ROOT" == *"/.claude/"* ]]; then
    PLATFORM="claude"
    STATE_ROOT="${CLAUDE_ROOT}/repo-forensics"
fi
NUDGE_FLAG="${STATE_ROOT}/.marketplace-nudge-shown"

# Kill switch
if [ "${REPO_FORENSICS_NUDGE:-1}" = "0" ]; then
    exit 0
fi

# Only fire for marketplace/cache installs. Dev-symlink or script-install users
# have their own update paths and do not need this hint.
if [[ "$PLUGIN_ROOT" != *"/plugins/cache/"* ]]; then
    exit 0
fi

# One-shot: if we've already shown the nudge, stay silent.
if [ -f "$NUDGE_FLAG" ]; then
    exit 0
fi

if [ "$PLATFORM" = "claude" ]; then
    cat <<'NUDGE'

  [repo-forensics] First-run tip: enable auto-update for this marketplace
  so you get new IOCs, detection rules, and critical security patches
  automatically. For a security scanner, stale installs are especially
  dangerous. In Claude Code:

      /plugin  ->  Marketplaces  ->  select your repo-forensics marketplace
               ->  Enable auto-update

  Third-party marketplaces ship with auto-update off by default in Claude
  Code. This is not our choice. Opt out of this hint permanently with
  REPO_FORENSICS_NUDGE=0. This message will not show again.

NUDGE
elif [ "$PLATFORM" = "codex" ]; then
    cat <<'NUDGE'

  [repo-forensics] First-run tip: keep your Codex marketplace snapshot fresh
  so you get new IOCs, detection rules, and critical security patches.

      codex plugin marketplace upgrade

  If repo-forensics was already installed from that marketplace, reinstall it
  after refreshing the snapshot. Opt out of this hint permanently with
  REPO_FORENSICS_NUDGE=0. This message will not show again.

NUDGE
else
    cat <<'NUDGE'

  [repo-forensics] First-run tip: keep your plugin source fresh so you get
  new IOCs, detection rules, and critical security patches. Update or
  reinstall repo-forensics from your agent's plugin marketplace when a new
  version is available. Opt out of this hint permanently with
  REPO_FORENSICS_NUDGE=0. This message will not show again.

NUDGE
fi

mkdir -p "$(dirname "$NUDGE_FLAG")" 2>/dev/null
touch "$NUDGE_FLAG" 2>/dev/null
exit 0
