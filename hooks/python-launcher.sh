#!/usr/bin/env bash
# Locate a usable Python 3 interpreter and exec it with the given arguments.
# Hook environments may have a stripped PATH, especially under Codex and
# GUI-launched agent apps. Keep this launcher dependency-free and conservative.

set -eu

_SAFE_PREFIXES="/usr/bin /usr/local/bin /opt/homebrew/bin /opt/homebrew/opt"

_is_safe_prefix() {
    local IFS=$' \t\n'
    local binpath="$1" prefix
    for prefix in $_SAFE_PREFIXES; do
        case "$binpath" in
            "$prefix"/*) return 0 ;;
        esac
    done
    case "$binpath" in
        /[a-zA-Z]/Program\ Files/Python[23]*) return 0 ;;
        /[a-zA-Z]/Program\ Files\ \(x86\)/Python[23]*) return 0 ;;
        /[a-zA-Z]/Python3[0-9]*) return 0 ;;
        /[a-zA-Z]/Users/*/AppData/Local/Programs/Python/*) return 0 ;;
        /[a-zA-Z]/Users/*/AppData/Local/Microsoft/WindowsApps/*) return 0 ;;
    esac
    return 1
}

find_interpreter() {
    local name="$1"
    local IFS=:
    local dir binpath ext
    for dir in ${PATH:-}; do
        [ -n "$dir" ] || dir="."
        for ext in "" ".exe"; do
            binpath="${dir}/${name}${ext}"
            [ -x "$binpath" ] || continue
            [ -s "$binpath" ] || continue
            _is_safe_prefix "$binpath" || continue
            case "$binpath" in
                */WindowsApps/*|*/windowsapps/*)
                    if command -v timeout >/dev/null 2>&1; then
                        timeout 2s "$binpath" --version >/dev/null 2>&1 || continue
                    else
                        "$binpath" --version >/dev/null 2>&1 || continue
                    fi
                    ;;
            esac
            printf "%s\n" "$binpath"
            return 0
        done
    done
    return 1
}

# Run "<binpath> --version" with a hard ~2s time bound and echo its combined
# output. A hung or hostile binary must never block the hook — and therefore
# every Bash command — forever. Portable pure-bash watchdog (no dependency on
# coreutils `timeout`, absent on stock macOS):
#   * output goes to a temp file, never the caller's capturing pipe, so an
#     orphaned grandchild can't hold that pipe open past the deadline;
#   * the deadline uses SIGKILL, which bash cannot defer while it waits on a
#     foreground child (SIGTERM to a shell wrapper would be deferred until its
#     child exits — the exact way an interpreter could stall the probe).
_bounded_version() {
    local binpath="$1" tmpf rc
    tmpf=$(mktemp 2>/dev/null) || tmpf="${TMPDIR:-/tmp}/rf-probe.$$"
    "$binpath" --version >"$tmpf" 2>&1 &
    local cmd_pid=$!
    ( sleep 2; kill -KILL "$cmd_pid" 2>/dev/null ) </dev/null >/dev/null 2>&1 &
    local killer_pid=$!
    wait "$cmd_pid" 2>/dev/null
    rc=$?
    kill -KILL "$killer_pid" 2>/dev/null
    wait "$killer_pid" 2>/dev/null
    printf '%s' "$(<"$tmpf")"
    rm -f "$tmpf" 2>/dev/null
    return "$rc"
}

# Probe a candidate interpreter conservatively before trusting it: it must be a
# non-empty executable file that answers to --version AND identifies itself as
# Python 3. Exit-zero alone is not enough — the bundled-runtime fallback below
# searches user-writable dirs outside the _is_safe_prefix whitelist, so we
# require the version banner to match before ever exec'ing it as the interpreter.
# (This is a best-effort identity gate, not a boundary against a determined
# planter, but it keeps an accidental or generic exit-0 binary from standing in
# for the Python that runs the scan.)
_probe_interpreter() {
    local binpath="$1" ver=""
    [ -n "$binpath" ] || return 1
    [ -f "$binpath" ] || return 1
    [ -x "$binpath" ] || return 1
    [ -s "$binpath" ] || return 1
    ver=$(_bounded_version "$binpath") || return 1
    case "$ver" in
        *"Python 3"*) return 0 ;;
    esac
    return 1
}

# Locate the Python that Codex Desktop (and similar GUI agents) bundle inside
# their runtime cache. These interpreters are not on PATH and sit under the
# user's own cache directory, e.g. under Git Bash on Windows:
#   /c/Users/<user>/.cache/codex-runtimes/<runtime>/dependencies/python/python.exe
# We derive the search roots from HOME / XDG_CACHE_HOME rather than hardcoding
# any one user's path, and probe each candidate before exec. CODEX_RUNTIME_PYTHON
# is an explicit user override (setting it is the opt-in); it still must pass the
# same Python-3 probe.
find_codex_runtime_python() {
    if [ -n "${CODEX_RUNTIME_PYTHON:-}" ] && _probe_interpreter "${CODEX_RUNTIME_PYTHON}"; then
        printf '%s\n' "${CODEX_RUNTIME_PYTHON}"
        return 0
    fi
    # Use an array, not a space-joined string: cache roots legitimately contain
    # spaces on Windows (e.g. C:\Users\First Last), and word-splitting a joined
    # string would shatter those paths and silently find nothing.
    local -a roots=()
    local base
    for base in "${XDG_CACHE_HOME:-}" "${HOME:+${HOME}/.cache}" "${LOCALAPPDATA:-}"; do
        [ -n "$base" ] || continue
        roots+=("${base}/codex-runtimes")
    done
    local root candidate
    for root in ${roots[@]+"${roots[@]}"}; do
        [ -d "$root" ] || continue
        for candidate in \
            "$root"/*/dependencies/python/python.exe \
            "$root"/*/dependencies/python/python3.exe \
            "$root"/*/dependencies/python/python \
            "$root"/*/dependencies/python/python3 \
            "$root"/*/dependencies/python/bin/python3 \
            "$root"/*/dependencies/python/bin/python; do
            _probe_interpreter "$candidate" || continue
            printf '%s\n' "$candidate"
            return 0
        done
    done
    return 1
}

if py3=$(find_interpreter "python3"); then
    exec "$py3" "$@"
fi

if py=$(find_interpreter "python"); then
    exec "$py" "$@"
fi

if pyl=$(find_interpreter "py"); then
    exec "$pyl" -3 "$@"
fi

for direct in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
    if [ -x "$direct" ] && [ -s "$direct" ]; then
        exec "$direct" "$@"
    fi
done

# Last resort: agent-bundled runtime pythons (Codex Desktop et al.) that never
# appear on PATH. Prefer real system interpreters above; only fall back here.
if codexpy=$(find_codex_runtime_python); then
    exec "$codexpy" "$@"
fi

echo "repo-forensics: no usable Python 3 interpreter found" >&2
echo "  tried: python3, python, py -3, direct paths, codex runtime" >&2
exit 127
