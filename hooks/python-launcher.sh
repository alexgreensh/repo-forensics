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

echo "repo-forensics: no usable Python 3 interpreter found" >&2
echo "  tried: python3, python, py -3, direct paths" >&2
exit 127
