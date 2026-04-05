#!/bin/bash
# repo-forensics - SessionStart First-Run Auto-Update Nudge
#
# Claude Code ships third-party marketplaces with auto-update OFF by default,
# and plugin authors cannot change that default. This hook prints a one-time
# message telling marketplace-installed users how to enable auto-update so they
# get new IOCs, detection rules, and critical security patches automatically.
#
# For a security scanner specifically, stale installs are especially dangerous:
# users running repo-forensics against known supply chain attacks need the IOC
# list that was current at the time of the attack, not six weeks ago.
#
# Conditions (all must be true for the nudge to fire):
#   - running from /plugins/cache/ (marketplace install, not a dev checkout)
#   - flag file absent (one-shot per user)
#   - REPO_FORENSICS_NUDGE environment variable not set to 0 (kill switch)
#
# Copyright (C) 2026 Alex Greenshpun
# SPDX-License-Identifier: AGPL-3.0-only

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NUDGE_FLAG="${HOME}/.claude/repo-forensics/.autoupdate-nudge-shown"

# Kill switch
if [ "${REPO_FORENSICS_NUDGE:-1}" = "0" ]; then
    exit 0
fi

# Only fire for marketplace installs. Dev-symlink or script-install users
# have their own update paths and don't need this hint.
if [[ "$PLUGIN_ROOT" != *"/plugins/cache/"* ]]; then
    exit 0
fi

# One-shot: if we've already shown the nudge, stay silent.
if [ -f "$NUDGE_FLAG" ]; then
    exit 0
fi

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

mkdir -p "$(dirname "$NUDGE_FLAG")" 2>/dev/null
touch "$NUDGE_FLAG" 2>/dev/null
exit 0
