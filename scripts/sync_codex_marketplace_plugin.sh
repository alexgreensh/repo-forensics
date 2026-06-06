#!/usr/bin/env bash
# Mirror the root repo-forensics plugin into the nested Codex marketplace shape.
#
# Codex marketplace sources discover plugins under ./plugins/<name> with their
# own .codex-plugin/plugin.json. A root-level .codex-plugin is useful for direct
# plugin-cache installs, but it is not enough for `codex plugin marketplace add`.
# Keep root content canonical and regenerate this mirror before release.

set -euo pipefail

if [ -z "${BASH_VERSION:-}" ]; then
    echo "ERROR: run with bash, not sh." >&2
    exit 2
fi

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIRNAME="$(dirname "$SCRIPT_PATH")"
SCRIPT_DIR="$(cd "$SCRIPT_DIRNAME" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

for marker in ".codex-plugin/plugin.json" ".claude-plugin/plugin.json" "skills/repo-forensics/SKILL.md" "skills/forensify/SKILL.md" "hooks/hooks.json"; do
    if [ ! -e "${REPO_ROOT}/${marker}" ]; then
        echo "ERROR: REPO_ROOT looks wrong (missing ${marker}): ${REPO_ROOT}" >&2
        echo "Refusing to run destructive sync." >&2
        exit 3
    fi
done

NESTED="${REPO_ROOT}/plugins/repo-forensics"
STAGE="${REPO_ROOT}/plugins/.repo-forensics.stage.$$"

cleanup_stage() { rm -rf "${STAGE}" 2>/dev/null || true; }
trap cleanup_stage EXIT

rm -rf "${STAGE}"
mkdir -p "${STAGE}"

cp -R "${REPO_ROOT}/skills" "${STAGE}/skills"
cp -R "${REPO_ROOT}/hooks" "${STAGE}/hooks"
cp -R "${REPO_ROOT}/.codex-plugin" "${STAGE}/.codex-plugin"
cp -R "${REPO_ROOT}/.claude-plugin" "${STAGE}/.claude-plugin"

find "${STAGE}" \( \
    -name '__pycache__' -o \
    -name '.pytest_cache' -o \
    -name '.ruff_cache' -o \
    -name '.DS_Store' -o \
    -name '*.pyc' -o \
    -name '*.pyo' \
  \) -exec rm -rf {} + 2>/dev/null || true

# Tests are release-time verification material, not runtime plugin payload.
find "${STAGE}/skills" -type d -name tests -prune -exec rm -rf {} + 2>/dev/null || true

# Keep local scratch/reference files out of the marketplace payload. The source
# checkout can contain untracked research notes; the installed plugin should
# only contain tracked repo-forensics skill files covered by checksums.json.
if git -C "${REPO_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    KEEP_FILE="${STAGE}/.repo-forensics.tracked-files"
    git -C "${REPO_ROOT}" ls-files -- "skills/repo-forensics" \
        | sed 's#^skills/repo-forensics/##' \
        | sort > "${KEEP_FILE}"

    while IFS= read -r -d '' staged_file; do
        rel="${staged_file#${STAGE}/skills/repo-forensics/}"
        if ! grep -Fxq "$rel" "${KEEP_FILE}"; then
            rm -f "$staged_file"
        fi
    done < <(find "${STAGE}/skills/repo-forensics" -type f -print0)

    rm -f "${KEEP_FILE}"
    find "${STAGE}/skills/repo-forensics" -type d -empty -delete 2>/dev/null || true
fi

# Preserve the legacy root skill entrypoint expected by checksums.json.
ln -s "skills/repo-forensics" "${STAGE}/skill"

[ -f "${STAGE}/.codex-plugin/plugin.json" ] || { echo "ERROR: nested Codex manifest missing" >&2; exit 4; }
[ -f "${STAGE}/hooks/hooks.json" ] || { echo "ERROR: nested hooks.json missing" >&2; exit 4; }
[ -f "${STAGE}/hooks/first-run-nudge.sh" ] || { echo "ERROR: nested first-run-nudge.sh missing" >&2; exit 4; }
[ -f "${STAGE}/skills/repo-forensics/scripts/run_forensics.sh" ] || { echo "ERROR: nested repo-forensics runner missing" >&2; exit 4; }
[ -f "${STAGE}/skills/forensify/SKILL.md" ] || { echo "ERROR: nested forensify skill missing" >&2; exit 4; }

rm -rf "${NESTED}"
mkdir -p "$(dirname "${NESTED}")"
mv "${STAGE}" "${NESTED}"

echo "Synced Codex marketplace plugin -> plugins/repo-forensics"
echo "  skills:      $(find "${NESTED}/skills" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ') dirs"
echo "  hooks:       present"
echo "  plugin.json: $(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "${NESTED}/.codex-plugin/plugin.json" | head -1)"
