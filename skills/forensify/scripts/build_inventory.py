#!/usr/bin/env python3
"""
build_inventory.py - Cross-agent inventory layer for forensify (v0.1)

Enumerates what a user has installed across AI-agent ecosystems (Claude Code,
Codex, OpenClaw, NanoClaw) and emits a structured JSON inventory. Zero-LLM,
deterministic, read-only.

This is the foundation layer for forensify. It runs before any domain
sub-agent and produces the canonical "what exists on this machine" report
that every downstream component reasons against.

Key invariants (enforced at runtime):
  - Stdlib-only. Zero external dependencies. Preserves repo-forensics'
    zero-dependency promise.
  - NFKC normalization on every string that enters inventory output.
  - Bidirectional override characters rejected outright.
  - Credential files: shape and stat inspection only. Values are never
    read into inventory output.
  - Symlinks are realpath-resolved before hashing, and the symlink target
    is recorded in the inventory when the target lies outside the stack
    root.
  - Walk depth is bounded by the config-level walk_depth_cap invariant.

This skeleton commit lands config loading, normalization helpers, env var
expansion, and ecosystem detection. Surface walkers and credential shape
inspection land in subsequent commits.

Usage:
  python3 build_inventory.py                    # auto-detect all ecosystems, emit inventory JSON to stdout
  python3 build_inventory.py --target ~/.claude # enumerate a single explicit path
  python3 build_inventory.py --list-ecosystems  # print which ecosystems are installed and exit
"""
from __future__ import annotations

import argparse
import glob as glob_module
import json
import os
import re
import stat
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Maximum file size for config/credential file reads (1MB). Defense against
# maliciously large files or symlinks to /dev/zero.
_MAX_CONFIG_READ_BYTES = 1_048_576

# ---------------------------------------------------------------------------
# Schema invariants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = 1
BIDI_OVERRIDE_CODEPOINTS = frozenset(
    [
        0x202A,  # LRE
        0x202B,  # RLE
        0x202C,  # PDF
        0x202D,  # LRO
        0x202E,  # RLO
        0x2066,  # LRI
        0x2067,  # RLI
        0x2068,  # FSI
        0x2069,  # PDI
    ]
)


class BidiOverrideRejected(ValueError):
    """Raised when a string contains a bidirectional override character."""


class SchemaMismatch(ValueError):
    """Raised when ecosystem_roots.json declares an unsupported schema_version."""


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def reject_bidi(s: str) -> str:
    """
    Raise BidiOverrideRejected if the string contains any bidi-override
    codepoint. Returns the string unchanged on success. This is the first
    gate every string passes through before entering inventory output.
    """
    for ch in s:
        if ord(ch) in BIDI_OVERRIDE_CODEPOINTS:
            raise BidiOverrideRejected(
                "bidirectional override codepoint detected: U+%04X" % ord(ch)
            )
    return s


def normalize_text(s: str) -> str:
    """
    NFKC-normalize a string and reject bidi overrides. Used for any path,
    filename, or identifier that will appear in inventory output. Catches
    Unicode confusable attacks that substitute non-breaking space or
    full-width Latin characters for ASCII equivalents.
    """
    return reject_bidi(unicodedata.normalize("NFKC", s))


def expand_env_vars(path: str, env: Optional[Dict[str, str]] = None) -> str:
    """
    Expand environment variable references of the form ${NAME} or ${NAME:-default}
    in a path string, then expand a leading ~ to the user's home directory.
    Passes the result through normalize_text before returning.

    Only ${NAME} and ${NAME:-default} forms are supported. $NAME without
    braces is intentionally not expanded to avoid surprises with paths
    containing dollar signs.
    """
    if env is None:
        env = dict(os.environ)

    out_parts: List[str] = []
    i = 0
    while i < len(path):
        if path[i] == "$" and i + 1 < len(path) and path[i + 1] == "{":
            end = path.find("}", i + 2)
            if end == -1:
                out_parts.append(path[i])
                i += 1
                continue
            var_spec = path[i + 2 : end]
            if ":-" in var_spec:
                name, default = var_spec.split(":-", 1)
            else:
                name, default = var_spec, ""
            out_parts.append(env.get(name, default))
            i = end + 1
        else:
            out_parts.append(path[i])
            i += 1

    expanded = "".join(out_parts)

    # Expand leading ~ against the passed env dict's HOME (or the real HOME if
    # not supplied). Honoring env["HOME"] is required for test isolation —
    # os.path.expanduser reads the real process $HOME and cannot be swapped.
    if expanded.startswith("~"):
        home = env.get("HOME") or os.path.expanduser("~")
        if expanded == "~":
            expanded = home
        elif expanded.startswith("~/"):
            expanded = home + expanded[1:]
        # Intentionally do not handle ~otheruser syntax — out of scope for
        # inventory detection and a source of surprise on multi-user systems.

    return normalize_text(expanded)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def default_config_path() -> Path:
    """Return the canonical location of ecosystem_roots.json next to this file."""
    return Path(__file__).resolve().parent.parent / "config" / "ecosystem_roots.json"


def load_ecosystem_roots(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load and validate ecosystem_roots.json. Enforces schema_version check,
    normalizes top-level string fields through the bidi gate, and returns
    the parsed config dict.

    Raises:
        FileNotFoundError: if the config file does not exist
        json.JSONDecodeError: if the file is not valid JSON
        SchemaMismatch: if the schema_version is not supported
        BidiOverrideRejected: if any string in the config contains a
            bidi override (defense against a malicious config edit)
    """
    if config_path is None:
        config_path = default_config_path()

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    schema_version = config.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise SchemaMismatch(
            "unsupported schema_version: expected %d, got %r"
            % (SCHEMA_VERSION, schema_version)
        )

    # Shallow bidi sweep over string leaves so a poisoned config fails loud
    # before anything reaches inventory output.
    _walk_strings_and_normalize(config)

    return config


def _walk_strings_and_normalize(obj: Any) -> None:
    """
    Recursively walk a parsed JSON structure and reject any string containing
    bidi overrides. Mutates strings in place via NFKC is NOT done here — the
    config file is treated as already-normalized by the author. This is a
    defensive gate, not a cleanup pass.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                reject_bidi(k)
            _walk_strings_and_normalize(v)
    elif isinstance(obj, list):
        for item in obj:
            _walk_strings_and_normalize(item)
    elif isinstance(obj, str):
        reject_bidi(obj)


# ---------------------------------------------------------------------------
# Ecosystem detection
# ---------------------------------------------------------------------------


def _resolve_env_for_ecosystem(
    eco_config: Dict[str, Any], env: Dict[str, str]
) -> Dict[str, str]:
    """
    Build the effective environment dict for an ecosystem by merging the
    user's real env with the defaults declared in ecosystem_roots.json
    under detection.env_overrides.

    Example: Codex declares env_overrides with CODEX_HOME defaulting to
    ~/.codex. If the user has CODEX_HOME set, it wins. If not, the default
    is injected into the env dict so subsequent expand_env_vars calls
    resolve ${CODEX_HOME} correctly.
    """
    effective = dict(env)
    detection = eco_config.get("detection", {})
    for override in detection.get("env_overrides", []):
        if not isinstance(override, dict):
            continue
        name = override.get("name")
        default = override.get("default")
        if name and name not in effective and default is not None:
            effective[name] = expand_env_vars(default, env)
    return effective


def _check_signal_exists(path: str) -> bool:
    """
    Return True if the given path exists on disk. Follows symlinks.
    Safe against non-existent parents, permission errors, and bad encodings.
    """
    try:
        return os.path.exists(path)
    except (OSError, ValueError):
        return False


def _detect_git_repo_signature(
    detection: Dict[str, Any],
    env: Dict[str, str],
) -> Optional[str]:
    """
    Locate a git-cloned agent install (NanoClaw) by walking:
      1. env var override (NANOCLAW_DIR)
      2. common clone paths with glob expansion
      3. signature file verification on each candidate

    Returns the first confirmed install path, or None.
    Walk depth is bounded by detection.walk_depth_cap (default 3).
    """
    walk_cap = int(detection.get("walk_depth_cap", 3))
    sig_files = detection.get("signature_files_all") or []
    sig_content = detection.get("signature_content_any") or []

    def _is_valid_install(candidate: str) -> bool:
        """Check if candidate contains ALL signature files and at least one
        content match in package.json."""
        for sf in sig_files:
            target = os.path.join(candidate, sf)
            if not os.path.exists(target):
                return False
        # Content check: at least one pattern must match in package.json
        if sig_content:
            pkg = os.path.join(candidate, "package.json")
            try:
                with open(pkg, "r", encoding="utf-8") as f:
                    content = f.read(4096)  # first 4KB is enough
            except OSError:
                return False
            if not any(re.search(pat, content) for pat in sig_content):
                return False
        return True

    # 1. Env var override
    for override in detection.get("env_overrides", []):
        if not isinstance(override, dict):
            continue
        var_name = override.get("name")
        if var_name and var_name in env:
            candidate = expand_env_vars(env[var_name], env)
            if os.path.isdir(candidate) and _is_valid_install(candidate):
                return candidate

    # 2. Common paths with bounded glob
    for path_tpl in detection.get("common_paths", []):
        if not isinstance(path_tpl, str):
            continue
        expanded = expand_env_vars(path_tpl, env)
        # If the template contains wildcards, glob; otherwise check directly
        if "*" in expanded or "?" in expanded:
            try:
                candidates = glob_module.glob(expanded)
            except (OSError, ValueError):
                candidates = []
            for c in candidates[:10]:  # cap candidates to avoid runaway
                if os.path.isdir(c) and _is_valid_install(c):
                    return normalize_text(c)
        else:
            if os.path.isdir(expanded) and _is_valid_install(expanded):
                return normalize_text(expanded)

    return None


def detect_ecosystems(
    config: Dict[str, Any],
    env: Optional[Dict[str, str]] = None,
    target_override: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Walk every ecosystem declared in config and report which ones are
    installed on this machine.

    If target_override is supplied, only the ecosystem whose declared roots
    best match the override path is returned. This supports the
    `forensify --target /path/to/nanoclaw-clone` flow.

    Returns a list of ecosystem records, each carrying:
      - key: the ecosystem identifier (claude_code, codex, openclaw, nanoclaw)
      - display_name
      - detected: True if any required_signals_any path exists
      - resolved_roots: list of paths with env vars expanded
      - matched_signals: list of paths that confirmed detection
      - effective_env: subset of env needed for further path resolution
    """
    if env is None:
        env = dict(os.environ)

    results: List[Dict[str, Any]] = []

    for eco_key, eco_config in config.get("ecosystems", {}).items():
        effective_env = _resolve_env_for_ecosystem(eco_config, env)
        detection = eco_config.get("detection", {})
        kind = detection.get("kind", "unknown")

        resolved_roots: List[str] = []
        for root_template in detection.get("roots", []):
            if isinstance(root_template, str):
                resolved_roots.append(expand_env_vars(root_template, effective_env))

        matched_signals: List[str] = []
        for sig_template in detection.get("required_signals_any", []):
            if not isinstance(sig_template, str):
                continue
            resolved = expand_env_vars(sig_template, effective_env)
            if _check_signal_exists(resolved):
                matched_signals.append(resolved)

        # Signature-based detection (NanoClaw): walk env var, common paths,
        # and signature files to locate git-cloned installs.
        if kind == "git_repo_signature":
            found_root = _detect_git_repo_signature(detection, effective_env)
            if found_root:
                resolved_roots.append(found_root)
                matched_signals.append(found_root)

        detected = len(matched_signals) > 0

        # When a --target is supplied, only return the ecosystem whose
        # resolved roots contain the target. Exact-prefix match on realpath.
        if target_override is not None:
            target_real = os.path.realpath(target_override)
            root_matches_target = any(
                _path_contains(root, target_real) for root in resolved_roots
            )
            if not root_matches_target:
                continue

        results.append(
            {
                "key": normalize_text(eco_key),
                "display_name": normalize_text(
                    eco_config.get("display_name", eco_key)
                ),
                "vendor": normalize_text(eco_config.get("vendor", "")),
                "detection_kind": kind,
                "detected": detected,
                "resolved_roots": resolved_roots,
                "matched_signals": matched_signals,
            }
        )

    return results


def _path_contains(parent: str, candidate: str) -> bool:
    """Return True if candidate is the same as parent or is nested under it."""
    try:
        parent_real = os.path.realpath(parent)
        return (
            candidate == parent_real
            or candidate.startswith(parent_real.rstrip(os.sep) + os.sep)
        )
    except (OSError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Path primitives
# ---------------------------------------------------------------------------


def _safe_stat(path: str) -> Optional[os.stat_result]:
    """
    stat(path) with exception swallowing. Returns None if the file is gone,
    unreadable, or stat fails for any reason. Callers must handle None.
    """
    try:
        return os.stat(path, follow_symlinks=True)
    except (OSError, ValueError):
        return None


def _safe_lstat(path: str) -> Optional[os.stat_result]:
    """lstat without following symlinks. Used to detect symlink targets."""
    try:
        return os.lstat(path)
    except (OSError, ValueError):
        return None


def _iso_mtime(st: os.stat_result) -> str:
    """Convert a stat_result's mtime to an ISO-8601 UTC timestamp."""
    return datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(
        timespec="seconds"
    )


def _path_depth_under(path: str, root: str) -> int:
    """
    Return how many path segments `path` sits below `root`. A file directly
    inside root returns 1. Used to enforce walk_depth_cap.
    """
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return -1
    if rel == "." or rel.startswith(".."):
        return 0
    return rel.count(os.sep) + 1


def safe_resolve_glob(
    template: str,
    env: Dict[str, str],
    walk_depth_cap: int = 8,
) -> List[str]:
    """
    Expand a glob template (with env var and ~ substitution) and return the
    list of matching paths. Results are NFKC-normalized, deduplicated, sorted
    for stable output, and filtered to stay inside the walk_depth_cap from
    the nearest concrete ancestor.

    Templates may contain `*` (single segment), `**` (recursive), and `?`.
    Uses glob.glob(recursive=True) from the stdlib — no external dependency.

    The walk_depth_cap enforcement is defense-in-depth: even if a user points
    --target at `/` or a symlink cycle exists under their home, the glob
    will not return paths more than `walk_depth_cap` segments deep beneath
    the first wildcard-free prefix of the template.
    """
    expanded = expand_env_vars(template, env)

    # Find the non-wildcard prefix so we can enforce walk_depth_cap against it.
    first_wildcard = len(expanded)
    for marker in ("*", "?", "["):
        idx = expanded.find(marker)
        if idx != -1 and idx < first_wildcard:
            first_wildcard = idx
    prefix = expanded[:first_wildcard]
    # Round prefix back to the nearest path separator so we do not split a
    # directory name in half when a wildcard sits mid-segment.
    if os.sep in prefix:
        prefix = prefix.rsplit(os.sep, 1)[0]

    try:
        raw_matches = glob_module.glob(expanded, recursive=True)
    except (OSError, ValueError):
        return []

    out: List[str] = []
    seen = set()
    for match in raw_matches:
        try:
            normalized = normalize_text(match)
        except BidiOverrideRejected:
            # A bidi-override filename on disk is itself a finding — skip it
            # from the clean inventory and rely on the shadow surface layer
            # (landing in a later commit) to report it.
            continue
        if normalized in seen:
            continue
        seen.add(normalized)

        # Walk depth cap enforcement
        if prefix:
            depth = _path_depth_under(normalized, prefix)
            if depth > walk_depth_cap:
                continue

        out.append(normalized)

    out.sort()
    return out


def _file_record(path: str, root_for_relative: Optional[str] = None) -> Dict[str, Any]:
    """
    Build a uniform inventory record for a single file path.

    Returns:
        dict with normalized path, relative_path (if root given), size_bytes,
        last_modified_iso, is_symlink, symlink_target (realpath if symlinked
        outside root, else null), file_mode_octal.

    Returns a minimal record with `_error` set if stat fails.
    """
    normalized = normalize_text(path)
    st = _safe_stat(normalized)
    if st is None:
        return {"path": normalized, "_error": "stat_failed"}

    lst = _safe_lstat(normalized)
    is_symlink = bool(lst and stat.S_ISLNK(lst.st_mode))
    symlink_target: Optional[str] = None
    if is_symlink:
        try:
            target = os.path.realpath(normalized)
            symlink_target = normalize_text(target)
        except (OSError, ValueError):
            symlink_target = None

    record: Dict[str, Any] = {
        "path": normalized,
        "size_bytes": st.st_size,
        "last_modified_iso": _iso_mtime(st),
        "is_symlink": is_symlink,
        "file_mode_octal": "0o%o" % (st.st_mode & 0o777),
    }

    if root_for_relative:
        try:
            rel = os.path.relpath(normalized, normalize_text(root_for_relative))
            record["relative_path"] = normalize_text(rel)
        except ValueError:
            pass

    if symlink_target:
        record["symlink_target"] = symlink_target

    return record


# ---------------------------------------------------------------------------
# Surface walkers
# ---------------------------------------------------------------------------


def _collect_glob_templates(
    surface_config: Dict[str, Any],
) -> List[Tuple[str, Optional[int]]]:
    """
    Extract glob templates from a surface config dict, handling both
    `globs` (flat list) and `precedence_chain` (ordered list with implicit
    precedence rank). Returns a list of (template, precedence_rank) tuples
    where precedence_rank is None for flat globs and 0..N-1 for chain entries.
    """
    out: List[Tuple[str, Optional[int]]] = []
    for tpl in surface_config.get("globs", []) or []:
        if isinstance(tpl, str):
            out.append((tpl, None))
    for idx, tpl in enumerate(surface_config.get("precedence_chain", []) or []):
        if isinstance(tpl, str):
            out.append((tpl, idx))
    return out


def _resolve_workspace_path(
    eco_config: Dict[str, Any], env: Dict[str, str]
) -> Optional[str]:
    """
    Resolve OpenClaw's workspace path honoring the profile env var and the
    openclaw.json config override. For other ecosystems (no `workspace`
    block), returns None.

    This is called by walkers that need to substitute ${workspace} into
    glob templates.
    """
    ws = eco_config.get("workspace")
    if not ws:
        return None

    default_path = ws.get("default_path", "")
    profile_env_name = ws.get("profile_env")

    # Profile suffix handling: if OPENCLAW_PROFILE is set and not "default",
    # the workspace becomes workspace-<profile>. Matches docs.openclaw.ai
    # and openclawplaybook.ai documentation.
    if profile_env_name and profile_env_name in env:
        profile_value = env[profile_env_name]
        if profile_value and profile_value != "default":
            default_path = default_path + "-" + profile_value

    # openclaw.json override: if present AND has the override key, it wins.
    # This is a best-effort read — we fail open if the file does not parse
    # so walker behavior matches detection behavior for corrupted configs.
    override_path = ws.get("config_override_path")
    override_key = ws.get("config_override_key")
    if override_path and override_key:
        try:
            with open(expand_env_vars(override_path, env), "r", encoding="utf-8") as f:
                oc_config = json.load(f)
            val = _get_dotted(oc_config, override_key)
            if isinstance(val, str) and val:
                default_path = val
        except (OSError, json.JSONDecodeError, ValueError):
            pass

    return expand_env_vars(default_path, env) if default_path else None


def _get_dotted(obj: Any, key: str) -> Any:
    """Safely read a dotted key path from a nested dict. Returns None on miss."""
    parts = key.split(".")
    cur = obj
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
        if cur is None:
            return None
    return cur


def walk_skills_surface(
    eco_key: str,
    eco_config: Dict[str, Any],
    env: Dict[str, str],
    walk_depth_cap: int = 8,
) -> List[Dict[str, Any]]:
    """
    Enumerate every skill under a detected ecosystem.

    For Claude Code and Codex: walks `surfaces.skills.globs`.
    For OpenClaw: walks `surfaces.skills.precedence_chain` and decorates
      each record with `precedence_rank` (lower = higher precedence).
    For NanoClaw: walks all three skill subcategories (operational,
      container, utility) if the ecosystem was detected via signature scan.
      Signature detection lands in a later commit; until then this returns
      an empty list for NanoClaw.

    Each record:
      path, size_bytes, last_modified_iso, is_symlink, symlink_target,
      file_mode_octal, relative_path (when a root is known),
      skill_name (parent directory name for SKILL.md files),
      precedence_rank (OpenClaw only).
    """
    surfaces = eco_config.get("surfaces", {})
    records: List[Dict[str, Any]] = []

    # Resolve ${workspace} for OpenClaw before expanding templates
    workspace_env = dict(env)
    workspace_path = _resolve_workspace_path(eco_config, env)
    if workspace_path:
        workspace_env["workspace"] = workspace_path

    skills_cfg = surfaces.get("skills") or {}

    for template, precedence_rank in _collect_glob_templates(skills_cfg):
        matches = safe_resolve_glob(template, workspace_env, walk_depth_cap)
        for match in matches:
            # For SKILL.md templates, derive skill_name from parent directory
            record = _file_record(match)
            parent = os.path.basename(os.path.dirname(match))
            if parent:
                record["skill_name"] = normalize_text(parent)
            if precedence_rank is not None:
                record["precedence_rank"] = precedence_rank
                record["precedence_source"] = template
            records.append(record)

    # NanoClaw uses a different schema layout — separate keys per skill type
    # rather than a flat skills/globs block. Walk them if present.
    for alt_key in ("operational_skills", "container_skills", "utility_skills"):
        alt_cfg = surfaces.get(alt_key)
        if not alt_cfg:
            continue
        for template in alt_cfg.get("globs", []) or []:
            if not isinstance(template, str):
                continue
            matches = safe_resolve_glob(template, workspace_env, walk_depth_cap)
            for match in matches:
                record = _file_record(match)
                parent = os.path.basename(os.path.dirname(match))
                if parent:
                    record["skill_name"] = normalize_text(parent)
                record["skill_subtype"] = alt_key
                records.append(record)

    return records


def _walk_generic_files(
    surface_config: Dict[str, Any],
    env: Dict[str, str],
    walk_depth_cap: int = 8,
) -> List[Dict[str, Any]]:
    """
    Walk any surface config that declares `files` and/or `globs` and return
    file records for every match. Generic walker used by commands, agents,
    memory, plugins, and other glob-based surfaces.
    """
    records: List[Dict[str, Any]] = []
    seen = set()

    for f_tpl in surface_config.get("files", []) or []:
        if not isinstance(f_tpl, str):
            continue
        resolved = expand_env_vars(f_tpl, env)
        if os.path.exists(resolved) and resolved not in seen:
            seen.add(resolved)
            records.append(_file_record(resolved))

    for tpl in surface_config.get("globs", []) or []:
        if not isinstance(tpl, str):
            continue
        for match in safe_resolve_glob(tpl, env, walk_depth_cap):
            if match not in seen:
                seen.add(match)
                records.append(_file_record(match))

    for tpl in surface_config.get("precedence_chain", []) or []:
        if not isinstance(tpl, str):
            continue
        for match in safe_resolve_glob(tpl, env, walk_depth_cap):
            if match not in seen:
                seen.add(match)
                records.append(_file_record(match))

    # walk_dirs: recursively walk directories and record every file
    for d_tpl in surface_config.get("walk_dirs", []) or []:
        if not isinstance(d_tpl, str):
            continue
        resolved_dir = expand_env_vars(d_tpl, env)
        if not os.path.isdir(resolved_dir):
            continue
        for dirpath, _dirnames, filenames in os.walk(resolved_dir):
            if _path_depth_under(dirpath, resolved_dir) > walk_depth_cap:
                continue
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                try:
                    normalized = normalize_text(full)
                except BidiOverrideRejected:
                    continue
                if normalized not in seen:
                    seen.add(normalized)
                    records.append(_file_record(normalized))

    return records


def walk_commands_agents_memory(
    eco_key: str,
    eco_config: Dict[str, Any],
    env: Dict[str, str],
    walk_depth_cap: int = 8,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Walk commands, agents, and memory surfaces for an ecosystem.
    Returns a dict with keys: commands, agents, memory, brain_files.
    """
    surfaces = eco_config.get("surfaces", {})
    workspace_env = dict(env)
    workspace_path = _resolve_workspace_path(eco_config, env)
    if workspace_path:
        workspace_env["workspace"] = workspace_path

    result: Dict[str, List[Dict[str, Any]]] = {}

    for surface_name in ("commands", "agents"):
        cfg = surfaces.get(surface_name) or {}
        result[surface_name] = _walk_generic_files(cfg, workspace_env, walk_depth_cap)

    # Memory: combine memory_files and brain_files from multiple config keys
    mem_records: List[Dict[str, Any]] = []
    seen_mem = set()

    for mem_key in ("commands_and_memory", "memory"):
        cfg = surfaces.get(mem_key) or {}
        for sub_key in ("memory_files", "files", "globs"):
            sub = cfg.get(sub_key)
            if not sub:
                continue
            if isinstance(sub, list):
                for tpl in sub:
                    if not isinstance(tpl, str):
                        continue
                    resolved = expand_env_vars(tpl, workspace_env)
                    # Could be a glob or a direct file
                    matches = safe_resolve_glob(
                        resolved if "*" in resolved or "?" in resolved else resolved,
                        workspace_env,
                        walk_depth_cap,
                    )
                    if not matches and os.path.exists(resolved):
                        matches = [resolved]
                    for m in matches:
                        if m not in seen_mem:
                            seen_mem.add(m)
                            mem_records.append(_file_record(m))

    result["memory"] = mem_records

    # Brain files (OpenClaw workspace context files)
    brain_cfg = surfaces.get("brain_files") or {}
    result["brain_files"] = _walk_generic_files(brain_cfg, workspace_env, walk_depth_cap)

    return result


def walk_hooks_surface(
    eco_key: str,
    eco_config: Dict[str, Any],
    env: Dict[str, str],
    walk_depth_cap: int = 8,
) -> List[Dict[str, Any]]:
    """
    Walk hooks surface. For Claude Code, walks both the hooks directory
    (with realpath resolution for symlinks) and settings.json + plugin
    hooks.json files. For Codex, extracts approval_policy and sandbox_mode
    from config.toml via regex.
    """
    surfaces = eco_config.get("surfaces", {})
    hooks_cfg = surfaces.get("hooks") or {}
    records = _walk_generic_files(hooks_cfg, env, walk_depth_cap)

    # Enrich Codex hook records with policy extraction from TOML
    if hooks_cfg.get("parse_as") == "toml":
        extract_keys = hooks_cfg.get("extract_keys") or []
        for rec in records:
            if rec.get("_error"):
                continue
            path = rec.get("path", "")
            if path.endswith(".toml") and os.path.isfile(path):
                policies = _extract_toml_keys(path, extract_keys)
                if policies:
                    rec["extracted_policies"] = policies

    return records


def _extract_toml_keys(path: str, keys: List[str]) -> Dict[str, str]:
    """
    Regex-based extraction of specific keys from a TOML file.
    This is NOT a full TOML parser — it handles simple `key = "value"` and
    `key = value` lines only. Used for Codex config.toml policy extraction
    without adding a tomllib dependency.
    """
    result: Dict[str, str] = {}
    st = _safe_stat(path)
    if st and st.st_size > _MAX_CONFIG_READ_BYTES:
        return result
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return result

    for key in keys:
        # Match: key = "value" or key = value (unquoted)
        pattern = r'^\s*' + re.escape(key) + r'\s*=\s*"?([^"\n]+)"?'
        match = re.search(pattern, content, re.MULTILINE)
        if match:
            result[key] = match.group(1).strip().strip('"')

    return result


def walk_mcp_surface(
    eco_key: str,
    eco_config: Dict[str, Any],
    env: Dict[str, str],
    walk_depth_cap: int = 8,
) -> List[Dict[str, Any]]:
    """
    Walk MCP server configurations. For JSON config files (Claude Code
    ~/.claude.json, plugin .mcp.json), counts MCP server entries. For TOML
    (Codex config.toml), counts [mcp_servers.*] section headers via regex.
    """
    surfaces = eco_config.get("surfaces", {})
    mcp_cfg = surfaces.get("mcp") or {}
    records = _walk_generic_files(mcp_cfg, env, walk_depth_cap)

    for rec in records:
        if rec.get("_error"):
            continue
        path = rec.get("path", "")
        if path.endswith(".json") and os.path.isfile(path):
            rec["mcp_server_count"] = _count_json_mcp_servers(path)
        elif path.endswith(".toml") and os.path.isfile(path):
            rec["mcp_server_count"] = _count_toml_mcp_servers(path)

    return records


def _count_json_mcp_servers(path: str) -> int:
    """Count MCP server entries in a JSON config (Claude Code format)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return 0
    # Claude Code: top-level mcpServers dict
    servers = data.get("mcpServers") or data.get("mcp_servers") or {}
    if isinstance(servers, dict):
        return len(servers)
    return 0


def _count_toml_mcp_servers(path: str) -> int:
    """Count [mcp_servers.*] section headers in a TOML file via regex."""
    st = _safe_stat(path)
    if st and st.st_size > _MAX_CONFIG_READ_BYTES:
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return 0
    return len(re.findall(r'^\s*\[mcp_servers\.\w+\]', content, re.MULTILINE))


def walk_plugins_surface(
    eco_key: str,
    eco_config: Dict[str, Any],
    env: Dict[str, str],
    walk_depth_cap: int = 8,
) -> List[Dict[str, Any]]:
    """Walk plugin manifests and registry files."""
    surfaces = eco_config.get("surfaces", {})
    plugins_cfg = surfaces.get("plugins") or {}
    return _walk_generic_files(plugins_cfg, env, walk_depth_cap)


def walk_settings_surface(
    eco_config: Dict[str, Any],
    env: Dict[str, str],
    walk_depth_cap: int = 8,
) -> List[Dict[str, Any]]:
    """Walk settings/config files."""
    surfaces = eco_config.get("surfaces", {})
    settings_cfg = surfaces.get("settings") or {}
    return _walk_generic_files(settings_cfg, env, walk_depth_cap)


def walk_credentials_surface(
    eco_key: str,
    eco_config: Dict[str, Any],
    env: Dict[str, str],
    walk_depth_cap: int = 8,
) -> List[Dict[str, Any]]:
    """
    Walk credential files with structured metadata extraction.
    NEVER reads credential values — stat and JSON-shape inspection only.
    """
    surfaces = eco_config.get("surfaces", {})
    cred_cfg = surfaces.get("credentials") or {}
    records = _walk_generic_files(cred_cfg, env, walk_depth_cap)

    schema_mode = cred_cfg.get("schema_inspection", "stat_only")

    for rec in records:
        if rec.get("_error"):
            continue
        path = rec.get("path", "")
        st = _safe_stat(path)
        if st is None:
            continue

        # Permission analysis
        mode = st.st_mode & 0o777
        rec["is_world_readable"] = bool(mode & stat.S_IROTH)
        rec["is_group_readable"] = bool(mode & stat.S_IRGRP)
        rec["owner_uid_matches_current"] = st.st_uid == os.getuid()

        if schema_mode == "shape_only" and path.endswith(".json"):
            rec.update(_inspect_json_shape(path))
        elif schema_mode == "line_count_only":
            rec["line_count_non_comment"] = _count_non_comment_lines(path)

    return records


def _inspect_json_shape(path: str) -> Dict[str, Any]:
    """
    Read a JSON credential file and extract ONLY structural metadata.
    Top-level key names, value types, and string lengths. NEVER captures
    actual secret values — this is the shape_only policy.

    Defense-in-depth: file size capped at _MAX_CONFIG_READ_BYTES. After
    shape extraction, the parsed dict is explicitly cleared so credential
    values do not persist in process memory longer than necessary.
    """
    # Metadata keys safe to extract as values (non-secret by design)
    _SAFE_METADATA_KEYS = frozenset({"auth_mode", "last_refresh"})

    result: Dict[str, Any] = {}

    # Size guard: credential files should be small
    st = _safe_stat(path)
    if st and st.st_size > _MAX_CONFIG_READ_BYTES:
        result["_shape_error"] = "file_too_large"
        return result

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        result["_shape_error"] = "parse_failed"
        return result

    if not isinstance(data, dict):
        return result

    shape: Dict[str, str] = {}
    for k, v in data.items():
        if isinstance(v, dict):
            shape[k] = "dict(%d keys)" % len(v)
        elif isinstance(v, list):
            shape[k] = "list(%d items)" % len(v)
        elif isinstance(v, str):
            shape[k] = "str(len=%d)" % len(v)
        elif v is None:
            shape[k] = "null"
        else:
            shape[k] = type(v).__name__
    result["json_shape"] = shape

    # Codex-specific enrichment: auth_mode and staleness
    auth_mode = data.get("auth_mode")
    if isinstance(auth_mode, str):
        result["auth_mode"] = auth_mode
        risk_weights = {"apikey": "high", "chatgpt": "medium"}
        result["auth_mode_risk_weight"] = risk_weights.get(auth_mode, "low")

    last_refresh = data.get("last_refresh")
    if isinstance(last_refresh, str):
        result["token_last_refresh_iso"] = last_refresh
        try:
            lr = datetime.fromisoformat(last_refresh.replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - lr).days
            result["staleness_days"] = max(0, days)
        except (ValueError, TypeError):
            pass

    # Defense-in-depth: clear credential values from process memory.
    # Only _SAFE_METADATA_KEYS survive; everything else is wiped.
    data.clear()

    return result


def _count_non_comment_lines(path: str) -> int:
    """Count non-empty, non-comment lines in a file (for .env files)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return sum(
                1
                for line in f
                if line.strip() and not line.strip().startswith("#")
            )
    except OSError:
        return 0


def walk_shadow_surfaces(
    eco_key: str,
    eco_config: Dict[str, Any],
    env: Dict[str, str],
    walk_depth_cap: int = 8,
) -> List[Dict[str, Any]]:
    """
    Enumerate shadow surfaces (backups, caches, session DBs, file history).
    Reports existence and stat metadata only — does not read contents.
    Default scans skip this walker; opt-in via --include-shadows.
    """
    shadow_cfg = eco_config.get("shadow_surfaces") or {}
    records: List[Dict[str, Any]] = []
    seen = set()

    for tpl in shadow_cfg.get("globs", []) or []:
        if not isinstance(tpl, str):
            continue
        for match in safe_resolve_glob(tpl, env, walk_depth_cap):
            if match not in seen:
                seen.add(match)
                st = _safe_stat(match)
                rec = {"path": normalize_text(match)}
                if st:
                    rec["size_bytes"] = st.st_size
                    rec["last_modified_iso"] = _iso_mtime(st)
                    rec["is_dir"] = stat.S_ISDIR(st.st_mode)
                records.append(rec)

    for tpl in shadow_cfg.get("walk_dirs", []) or []:
        if not isinstance(tpl, str):
            continue
        resolved = expand_env_vars(tpl, env)
        if os.path.isdir(resolved) and resolved not in seen:
            seen.add(resolved)
            st = _safe_stat(resolved)
            rec = {"path": normalize_text(resolved), "is_dir": True}
            if st:
                rec["last_modified_iso"] = _iso_mtime(st)
            records.append(rec)

    return records


def evaluate_cross_tool_iocs(
    config: Dict[str, Any],
    detected_ecosystems: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Evaluate cross-tool IOC rules against the set of detected ecosystems.
    Returns a list of triggered IOC records. Deterministic, no LLM.
    """
    detected_keys = {e["key"] for e in detected_ecosystems if e["detected"]}
    triggered: List[Dict[str, Any]] = []

    for ioc in config.get("cross_tool_iocs", []):
        conditions = ioc.get("trigger_conditions", [])
        all_met = True
        for cond in conditions:
            if not isinstance(cond, dict):
                all_met = False
                break
            for key, required_val in cond.items():
                # key format: eco_name_installed (e.g. codex_installed)
                eco_name = key.replace("_installed", "")
                if required_val is True and eco_name not in detected_keys:
                    all_met = False
                elif required_val is False and eco_name in detected_keys:
                    all_met = False
        if all_met:
            triggered.append({
                "id": ioc.get("id"),
                "title": ioc.get("title"),
                "severity": ioc.get("severity"),
                "affected_file": ioc.get("affected_file"),
                "reference": ioc.get("reference"),
            })

    return triggered


def find_cross_ecosystem_agents_md(
    detected_ecosystems: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Surface AGENTS.md files found across multiple ecosystems for
    cross-ecosystem coordination risk analysis.
    """
    agents_md_records: List[Dict[str, Any]] = []
    for eco in detected_ecosystems:
        if not eco["detected"]:
            continue
        surfaces = eco.get("surfaces", {})
        for surface_name in ("memory", "brain_files"):
            for rec in surfaces.get(surface_name, []):
                path = rec.get("path", "")
                if os.path.basename(path) == "AGENTS.md":
                    agents_md_records.append({
                        "ecosystem": eco["key"],
                        "path": path,
                        "size_bytes": rec.get("size_bytes", 0),
                    })
    return agents_md_records


# ---------------------------------------------------------------------------
# Inventory assembly
# ---------------------------------------------------------------------------


def build_inventory(
    config: Optional[Dict[str, Any]] = None,
    env: Optional[Dict[str, str]] = None,
    target_override: Optional[str] = None,
    include_shadows: bool = False,
) -> Dict[str, Any]:
    """
    Build a structured inventory of the user's AI-agent stack.
    Walks all six surface domains for each detected ecosystem.
    """
    if config is None:
        config = load_ecosystem_roots()
    if env is None:
        env = dict(os.environ)

    detected = detect_ecosystems(config, env=env, target_override=target_override)
    walk_cap = int(config.get("invariants", {}).get("walk_depth_cap", 8))

    shadow_all: Dict[str, List[Dict[str, Any]]] = {}

    for eco_record in detected:
        if not eco_record["detected"]:
            eco_record["surfaces"] = {}
            continue
        eco_key = eco_record["key"]
        eco_config = config["ecosystems"][eco_key]
        eco_env = _resolve_env_for_ecosystem(eco_config, env)

        # Inject workspace for OpenClaw templates
        workspace_path = _resolve_workspace_path(eco_config, eco_env)
        if workspace_path:
            eco_env["workspace"] = workspace_path

        # Inject root for NanoClaw (git_repo_signature): resolved_roots[0]
        # is the detected install directory, used by ${root} templates
        if eco_record.get("detection_kind") == "git_repo_signature":
            if eco_record["resolved_roots"]:
                eco_env["root"] = eco_record["resolved_roots"][0]

        surfaces: Dict[str, Any] = {}
        surfaces["skills"] = walk_skills_surface(
            eco_key, eco_config, eco_env, walk_depth_cap=walk_cap
        )
        cam = walk_commands_agents_memory(
            eco_key, eco_config, eco_env, walk_depth_cap=walk_cap
        )
        surfaces["commands"] = cam.get("commands", [])
        surfaces["agents"] = cam.get("agents", [])
        surfaces["memory"] = cam.get("memory", [])
        surfaces["brain_files"] = cam.get("brain_files", [])
        surfaces["hooks"] = walk_hooks_surface(
            eco_key, eco_config, eco_env, walk_depth_cap=walk_cap
        )
        surfaces["mcp"] = walk_mcp_surface(
            eco_key, eco_config, eco_env, walk_depth_cap=walk_cap
        )
        surfaces["plugins"] = walk_plugins_surface(
            eco_key, eco_config, eco_env, walk_depth_cap=walk_cap
        )
        surfaces["settings"] = walk_settings_surface(
            eco_config, eco_env, walk_depth_cap=walk_cap
        )
        surfaces["credentials"] = walk_credentials_surface(
            eco_key, eco_config, eco_env, walk_depth_cap=walk_cap
        )
        eco_record["surfaces"] = surfaces

        if include_shadows:
            shadow_all[eco_key] = walk_shadow_surfaces(
                eco_key, eco_config, eco_env, walk_depth_cap=walk_cap
            )

    # Cross-ecosystem analysis
    iocs = evaluate_cross_tool_iocs(config, detected)
    agents_md = find_cross_ecosystem_agents_md(detected)

    return {
        "schema_version": SCHEMA_VERSION,
        "forensify_version": config.get("version", "unknown"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "invariants": config.get("invariants", {}),
        "ecosystems": detected,
        "shadow_surfaces": shadow_all,
        "cross_ecosystem": {
            "agents_md": agents_md,
            "iocs": iocs,
        },
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_inventory",
        description="Cross-agent inventory layer for forensify. Enumerates "
        "installed AI-agent ecosystems and emits structured JSON.",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=None,
        help="Explicit stack root to audit. Narrows detection to the "
        "ecosystem whose resolved roots contain this path.",
    )
    parser.add_argument(
        "--list-ecosystems",
        action="store_true",
        help="Print which ecosystems are installed and exit. Minimal output, "
        "suitable for shell scripting.",
    )
    parser.add_argument(
        "--include-shadows",
        action="store_true",
        help="Include shadow surfaces (backups, caches, session DBs) in "
        "the inventory. Off by default to preserve signal-to-noise.",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to a non-default ecosystem_roots.json (testing hook).",
    )
    args = parser.parse_args(argv)

    config_path = Path(args.config) if args.config else None
    config = load_ecosystem_roots(config_path)
    inventory = build_inventory(
        config=config,
        target_override=args.target,
        include_shadows=args.include_shadows,
    )

    if args.list_ecosystems:
        for eco in inventory["ecosystems"]:
            state = "installed" if eco["detected"] else "not_installed"
            sys.stdout.write("%s\t%s\n" % (eco["key"], state))
        return 0

    json.dump(inventory, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
