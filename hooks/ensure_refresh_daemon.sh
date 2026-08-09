#!/usr/bin/env bash
# SessionStart adapter for the cross-platform refresh controller.

set -u
CALLER_PATH="${PATH:-}"
# Trusted command roots for this wrapper's own utilities (dirname, cd, pwd):
# FHS + NixOS system profiles (root-owned) + per-user Nix/XDG profile dirs
# (same trust as Homebrew). NixOS has no /usr/bin or /bin coreutils.
PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:/run/current-system/sw/bin:/run/wrappers/bin:/nix/var/nix/profiles/default/bin"
if [ -n "${HOME:-}" ]; then
    PATH="$PATH:$HOME/.nix-profile/bin:$HOME/.local/bin:$HOME/.local/state/nix/profile/bin"
fi
_rf_profile_user="${USER:-}"
if [ -z "$_rf_profile_user" ] && [ -n "${HOME:-}" ]; then
    _rf_profile_user="${HOME##*/}"
fi
if [ -n "$_rf_profile_user" ]; then
    PATH="$PATH:/etc/profiles/per-user/$_rf_profile_user/bin"
fi
unset _rf_profile_user
export PATH

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)" || exit 0
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-${KIMI_PLUGIN_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}}"
CONTROLLER="$PLUGIN_ROOT/skills/repo-forensics/scripts/refresh_controller.py"
LAUNCHER="$PLUGIN_ROOT/hooks/python-launcher.sh"

[ -f "$CONTROLLER" ] || exit 0
[ -f "$LAUNCHER" ] || exit 0

# Preserve caller PATH only for the interpreter launcher: it independently
# allowlists every Python location, including standard Windows installs. The
# wrapper's own utilities above resolve exclusively through trusted paths.
# Repair is detached so a slow/broken scheduler API cannot block SessionStart.
PATH="${CALLER_PATH:+$CALLER_PATH:}$PATH" \
    "${BASH:-$(command -v bash || echo /bin/bash)}" "$LAUNCHER" "$CONTROLLER" ensure \
    </dev/null >/dev/null 2>&1 &
exit 0
