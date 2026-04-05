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
import stat
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

        # Signature-based detection (NanoClaw) is a separate code path that
        # will land in a subsequent commit alongside the NanoClaw walker.
        # For now, git_repo_signature ecosystems report detected=False unless
        # an env var override points at a real directory.
        if kind == "git_repo_signature":
            env_var_names = [
                o.get("name")
                for o in detection.get("env_overrides", [])
                if isinstance(o, dict) and o.get("role") == "primary_path_override"
            ]
            for var_name in env_var_names:
                if var_name and var_name in env:
                    candidate = expand_env_vars(env[var_name], effective_env)
                    if os.path.isdir(candidate):
                        resolved_roots.append(candidate)
                        matched_signals.append(candidate)
                        break

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


# ---------------------------------------------------------------------------
# Inventory assembly (skeleton — walkers land in later commits)
# ---------------------------------------------------------------------------


def build_inventory(
    config: Optional[Dict[str, Any]] = None,
    env: Optional[Dict[str, str]] = None,
    target_override: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a structured inventory of the user's AI-agent stack.

    For each detected ecosystem, walkers populate the `surfaces` subtree
    with structured records (currently: skills). Additional surface walkers
    land in subsequent commits.
    """
    if config is None:
        config = load_ecosystem_roots()
    if env is None:
        env = dict(os.environ)

    detected = detect_ecosystems(config, env=env, target_override=target_override)
    walk_cap = int(config.get("invariants", {}).get("walk_depth_cap", 8))

    # Walk every surface domain for each detected ecosystem
    for eco_record in detected:
        if not eco_record["detected"]:
            eco_record["surfaces"] = {}
            continue
        eco_key = eco_record["key"]
        eco_config = config["ecosystems"][eco_key]
        eco_env = _resolve_env_for_ecosystem(eco_config, env)

        surfaces: Dict[str, Any] = {}
        surfaces["skills"] = walk_skills_surface(
            eco_key, eco_config, eco_env, walk_depth_cap=walk_cap
        )
        eco_record["surfaces"] = surfaces

    return {
        "schema_version": SCHEMA_VERSION,
        "forensify_version": config.get("version", "unknown"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "invariants": config.get("invariants", {}),
        "ecosystems": detected,
        "shadow_surfaces": {},  # populated by walker layer
        "cross_ecosystem": {
            "agents_md": [],
            "iocs": [],
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
        "--config",
        type=str,
        default=None,
        help="Path to a non-default ecosystem_roots.json (testing hook).",
    )
    args = parser.parse_args(argv)

    config_path = Path(args.config) if args.config else None
    config = load_ecosystem_roots(config_path)
    inventory = build_inventory(config=config, target_override=args.target)

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
