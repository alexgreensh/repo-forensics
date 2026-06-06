#!/usr/bin/env bash
# install_refresh_daemon.sh — Install the repo-forensics threat DB refresh daemon.
#
# Why: SessionStart hook used to do up to 20s of network I/O refreshing IOC + KEV
# caches. This daemon moves that work to a daily background launchd job so the
# hook stays under 1 second.
#
# Safe to run multiple times — bootout previous instance, install new plist.
# Set REPO_FORENSICS_DISABLE_REFRESH=1 in env to disable without uninstalling.
#
# Uninstall: bash hooks/uninstall_refresh_daemon.sh
#
# macOS only (uses launchctl). On other platforms this script will refuse.

set -euo pipefail

if [ "$(uname)" != "Darwin" ]; then
    echo "[install] ERROR: macOS only (uses launchctl)" >&2
    exit 1
fi

LABEL="com.alexgreenshpun.repo-forensics-refresh"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
CACHE_DIR="$HOME/.cache/repo-forensics"

# 1) Resolve python3, prefer system locations (stable across Homebrew upgrades).
#    Avoids supply-chain risk of a python in user-writable bin directories
#    being baked into a persistent launchd job.
PYTHON_BIN=""
for candidate in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if [ -x "$candidate" ]; then
        PYTHON_BIN="$candidate"
        break
    fi
done
if [ -z "$PYTHON_BIN" ]; then
    echo "[install] ERROR: python3 not found in /usr/bin, /opt/homebrew/bin, /usr/local/bin" >&2
    exit 1
fi

# 2) Find the newest installed scripts dir under the plugin cache
PLUGIN_ROOT="$HOME/.claude/plugins/cache"
SCRIPT_PATH=""
if [ -d "$PLUGIN_ROOT" ]; then
    # Use mtime not version-sort so this matches the Python resolver's selection.
    while IFS= read -r -d '' f; do
        SCRIPT_PATH="$f"
    done < <(find "$PLUGIN_ROOT" -maxdepth 6 -type f \
        -path "*/repo-forensics/*/skills/repo-forensics/scripts/refresh_threat_dbs.py" \
        -print0 2>/dev/null | xargs -0 stat -f '%m %N' 2>/dev/null \
        | sort -n | awk '{$1=""; sub(/^ /, ""); print}' | tr '\n' '\0')
fi

# Fallback: relative to this script (source-repo dogfood)
if [ -z "$SCRIPT_PATH" ]; then
    SCRIPT_DIR="$(dirname "$0")"
    HERE="$(cd "$SCRIPT_DIR" && pwd)"
    CANDIDATE="$HERE/../skills/repo-forensics/scripts/refresh_threat_dbs.py"
    if [ -f "$CANDIDATE" ]; then
        CANDIDATE_DIR="$(dirname "$CANDIDATE")"
        CANDIDATE_BASE="$(basename "$CANDIDATE")"
        SCRIPT_PATH="$(cd "$CANDIDATE_DIR" && pwd)/$CANDIDATE_BASE"
    fi
fi

if [ -z "$SCRIPT_PATH" ] || [ ! -f "$SCRIPT_PATH" ]; then
    echo "[install] ERROR: refresh_threat_dbs.py not found" >&2
    echo "[install] Searched: $PLUGIN_ROOT (newest by mtime)" >&2
    exit 1
fi

# 3) Reject paths containing characters that could inject into XML or plist parsing.
#    Defense-in-depth even though we still XML-escape below.
for value in "$PYTHON_BIN" "$SCRIPT_PATH" "$CACHE_DIR" "$PLIST_PATH" "$LABEL"; do
    case "$value" in
        *$'\n'*|*$'\r'*|*$'\t'*|*'<'*|*'>'*|*'&'*|*'"'*|*"'"*)
            echo "[install] ERROR: path or label contains forbidden character: $value" >&2
            exit 1
            ;;
    esac
done

# 4) XML-escape any interpolated values for the plist heredoc. Paranoid even after
#    rejection above — if Apple's path conventions change to allow `<` etc.
xml_escape() {
    printf '%s' "$1" \
        | sed -e 's/&/\&amp;/g' \
              -e 's/</\&lt;/g' \
              -e 's/>/\&gt;/g' \
              -e 's/"/\&quot;/g' \
              -e "s/'/\\&apos;/g"
}
ESC_LABEL="$(xml_escape "$LABEL")"
ESC_PYTHON_BIN="$(xml_escape "$PYTHON_BIN")"
ESC_SCRIPT_PATH="$(xml_escape "$SCRIPT_PATH")"
ESC_CACHE_DIR="$(xml_escape "$CACHE_DIR")"

# 5) Bootout previous instance if loaded (idempotent)
launchctl bootout "gui/$UID" "$PLIST_PATH" 2>/dev/null || true

# 6) Render plist (using already-XML-escaped values; heredoc is "quoted" to suppress
#    further bash expansion on the body).
mkdir -p "$HOME/Library/LaunchAgents"
mkdir -p "$CACHE_DIR"
chmod 0700 "$CACHE_DIR" 2>/dev/null || true

# Use a temp file + atomic rename so a failed write never leaves a half-written plist.
TMP_PLIST="$(mktemp "${PLIST_PATH}.tmp.XXXXXX")"
trap 'rm -f "$TMP_PLIST"' EXIT

cat > "$TMP_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${ESC_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${ESC_PYTHON_BIN}</string>
        <string>${ESC_SCRIPT_PATH}</string>
    </array>
    <key>StartInterval</key>
    <integer>86400</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>ThrottleInterval</key>
    <integer>300</integer>
    <key>AbandonProcessGroup</key>
    <false/>
    <key>ExitTimeOut</key>
    <integer>90</integer>
    <key>Nice</key>
    <integer>10</integer>
    <key>LowPriorityIO</key>
    <true/>
    <key>LowPriorityBackgroundIO</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>${ESC_CACHE_DIR}/launchd-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${ESC_CACHE_DIR}/launchd-stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
PLIST

# 7) Validate before installing
if ! plutil -lint "$TMP_PLIST" >/dev/null; then
    echo "[install] ERROR: rendered plist failed plutil -lint" >&2
    exit 1
fi

mv "$TMP_PLIST" "$PLIST_PATH"
trap - EXIT

# 8) Bootstrap (allow non-zero in case bootout was racy and the prior reference
#    is being torn down asynchronously; warn loudly rather than abort hard).
if ! launchctl bootstrap "gui/$UID" "$PLIST_PATH" 2>/tmp/repo-forensics-bootstrap.err; then
    echo "[install] WARN: launchctl bootstrap returned non-zero. Will retry once after 2s." >&2
    cat /tmp/repo-forensics-bootstrap.err >&2 || true
    sleep 2
    if ! launchctl bootstrap "gui/$UID" "$PLIST_PATH" 2>>/tmp/repo-forensics-bootstrap.err; then
        echo "[install] ERROR: bootstrap failed twice. Plist is on disk; load manually with:" >&2
        echo "    launchctl bootstrap gui/\$UID $PLIST_PATH" >&2
        exit 1
    fi
fi

echo "[install] OK: ${LABEL} loaded"
echo "[install] Python:  $PYTHON_BIN"
echo "[install] Script:  $SCRIPT_PATH"
echo "[install] Logs:    $CACHE_DIR/refresh.log"
echo "[install] Disable: REPO_FORENSICS_DISABLE_REFRESH=1 (env), or run uninstall_refresh_daemon.sh"
