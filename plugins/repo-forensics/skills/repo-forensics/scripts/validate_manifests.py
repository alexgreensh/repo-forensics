#!/usr/bin/env python3
"""Validate plugin and marketplace manifests before they are shipped."""

import argparse
import json
import re
import sys
from pathlib import Path


NAME_RE = re.compile(r"^[a-z0-9-]+$")
RESERVED_PREFIXES = ("claude-", "anthropic-")

# Markdown frontmatter keys that are documented as scalar strings. A raw value
# that begins with an unquoted ``[`` or ``{`` is a YAML flow collection, which
# either parses as the wrong type or, when two flow sequences sit on one line
# (issue #35), is a hard YAML ParserError that makes loaders drop the skill.
FRONTMATTER_SCALAR_KEYS = (
    "name",
    "description",
    "argument-hint",
    "allowed-tools",
    "user-invocable",
)
FRONTMATTER_STRING_KEYS = ("name", "description", "argument-hint", "allowed-tools")
_FRONTMATTER_KEY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$")

# Legitimate frontmatter never nests flow collections anywhere near this deep.
# Beyond it the value is unbalanced or hostile: PyYAML's pure-Python loader
# dies with RecursionError (not YAMLError), so the depth is bounded here in
# the dependency-free pass instead of relying on the parser to complain.
FRONTMATTER_MAX_FLOW_DEPTH = 100

# Vendored trees, VCS internals and tool caches. Build output directories are
# intentionally absent: they can contain shipped skills.
EXCLUDED_DIR_PARTS = frozenset((
    "node_modules", ".git", "__pycache__", ".pytest_cache", ".ruff_cache",
    ".venv", "venv",
))

try:
    import yaml as _yaml
except ImportError:
    _yaml = None


def discover_manifests(root):
    """Return every supported manifest location under *root*."""
    paths = [
        root / ".claude-plugin/plugin.json",
        root / ".claude-plugin/marketplace.json",
        root / ".codex-plugin/plugin.json",
        root / "openclaw/openclaw.plugin.json",
    ]
    for plugin in (root / "plugins").glob("*") if (root / "plugins").is_dir() else ():
        paths.extend((
            plugin / ".claude-plugin/plugin.json",
            plugin / ".claude-plugin/marketplace.json",
            plugin / ".codex-plugin/plugin.json",
        ))
    return sorted(path for path in paths if path.is_file())


def _is_excluded(path, root):
    """True when *path* lives under a directory this gate does not validate.

    Test fixtures and scan corpora hold sample skills that are malformed on
    purpose, so they are out of scope; only shipped skills are validated.
    """
    parts = path.relative_to(root).parts
    if EXCLUDED_DIR_PARTS.intersection(parts):
        return True
    for index in range(len(parts) - 1):
        if parts[index] == "tests" and parts[index + 1] in ("fixtures", "corpus"):
            return True
    return False


def discover_skill_markdown(root):
    """Return every ``SKILL.md`` and command markdown file under *root*.

    Command markdown is any ``*.md`` file beneath a ``commands`` directory.
    Files without YAML frontmatter are filtered out by the caller, and test
    fixtures / corpora are skipped (see :func:`_is_excluded`).
    """
    root = Path(root)
    paths = set()
    # An unreadable directory anywhere under root must not abort the gate with a
    # PermissionError traceback.
    try:
        paths.update(root.rglob("SKILL.md"))
        for commands_dir in root.rglob("commands"):
            if commands_dir.is_dir():
                paths.update(commands_dir.rglob("*.md"))
    except OSError:
        pass
    return sorted(
        path for path in paths
        if path.is_file() and not _is_excluded(path, root)
    )


def _extract_frontmatter(text):
    """Return the raw frontmatter block (between the opening and closing ``---``).

    Returns ``None`` when *text* does not start with a frontmatter fence.
    """
    lines = text.lstrip("﻿").splitlines()
    if not lines or lines[0].rstrip() != "---":
        return None
    for index in range(1, len(lines)):
        # The closing fence must sit at column 0, so that an indented ``---``
        # inside a block scalar (such as a ``description: |`` containing a
        # markdown horizontal rule) does not end the block early.
        if lines[index].rstrip() == "---":
            return "\n".join(lines[1:index])
    return None


def _flow_depth(value):
    """Return the deepest flow-collection nesting in *value*.

    Counts ``[``/``{`` openers against ``]``/``}`` closers, ignoring quoting;
    for a sanity bound that approximation is fine.
    """
    depth = deepest = 0
    for char in value:
        if char in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "]}":
            depth = max(0, depth - 1)
    return deepest


def _structural_frontmatter_check(violations, relative, block):
    """Flag scalar keys whose raw value begins with an unquoted flow collection.

    Works with zero third-party dependencies. Catches issue #35
    (``argument-hint: [a] [b]``) which is a hard YAML ParserError, and also
    catches single flow collections (``argument-hint: [single]``) that parse
    as a list instead of the documented string type. Flow collections nested
    deeper than ``FRONTMATTER_MAX_FLOW_DEPTH`` are flagged on any key, since
    they kill the real parser with RecursionError rather than a YAMLError.
    """
    for line in block.splitlines():
        match = _FRONTMATTER_KEY_RE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        if value and value[0] in "[{" \
                and _flow_depth(value) > FRONTMATTER_MAX_FLOW_DEPTH:
            _failure(
                violations, relative, "frontmatter",
                "flow collection nested deeper than {} levels; unbalanced or "
                "hostile nesting crashes strict YAML loaders".format(
                    FRONTMATTER_MAX_FLOW_DEPTH),
            )
            continue
        if key not in FRONTMATTER_SCALAR_KEYS or not value:
            continue
        if value[0] in "[{":
            _failure(
                violations, relative, key,
                "value begins with unquoted '{}': YAML flow collection on a "
                "documented string key; quote the value".format(value[0]),
            )


def _validate_frontmatter(violations, relative, text):
    """Validate the YAML frontmatter of a single markdown file."""
    block = _extract_frontmatter(text)
    if block is None:
        return
    _structural_frontmatter_check(violations, relative, block)
    if _yaml is None:
        return
    try:
        data = _yaml.safe_load(block)
    except (_yaml.YAMLError, RecursionError) as exc:
        # Deeply nested flow collections raise RecursionError rather than
        # YAMLError, so both are reported as a parse violation.
        _failure(violations, relative, "frontmatter", "YAML parse error: {}".format(
            type(exc).__name__ if isinstance(exc, RecursionError) else exc))
        return
    if not isinstance(data, dict):
        _failure(violations, relative, "frontmatter", "must be a YAML mapping")
        return
    for key in FRONTMATTER_STRING_KEYS:
        if key in data and not isinstance(data[key], str):
            _failure(
                violations, relative, key,
                "must be a string, got {}".format(type(data[key]).__name__),
            )


def _failure(violations, path, field, message):
    violations.append({"file": str(path), "field": field, "message": message})


def _check_name(violations, path, field, value):
    if not isinstance(value, str) or not NAME_RE.fullmatch(value):
        _failure(violations, path, field, "must be kebab-case ([a-z0-9-]+)")
    elif value.startswith(RESERVED_PREFIXES):
        _failure(violations, path, field, "must not start with claude- or anthropic-")


def _check_author(violations, path, field, value):
    if not isinstance(value, dict) or not isinstance(value.get("name"), str):
        _failure(violations, path, field, "must be an object with a string name")


def validate_manifests(root):
    """Return all manifest violations beneath *root* without raising on bad JSON."""
    root = Path(root).resolve()
    canonical_path = root / ".claude-plugin/plugin.json"
    violations = []
    manifests = discover_manifests(root)
    parsed = {}

    for path in manifests:
        relative = path.relative_to(root)
        try:
            with path.open(encoding="utf-8") as handle:
                parsed[path] = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            _failure(violations, relative, "JSON", "invalid JSON: {}".format(exc))

    canonical = parsed.get(canonical_path)
    canonical_version = canonical.get("version") if isinstance(canonical, dict) else None
    if canonical_version is None:
        _failure(violations, canonical_path.relative_to(root), "version", "canonical version is missing")

    for path, data in parsed.items():
        relative = path.relative_to(root)
        if not isinstance(data, dict):
            _failure(violations, relative, "manifest", "must be a JSON object")
            continue
        marketplace = path.name == "marketplace.json"

        if marketplace:
            _check_name(violations, relative, "name", data.get("name"))
            if "owner" in data and not isinstance(data["owner"], dict):
                _failure(violations, relative, "owner", "must be an object")
            metadata = data.get("metadata", {})
            if isinstance(metadata, dict) and "version" in metadata:
                _check_version(violations, relative, "metadata.version", metadata["version"], canonical_version)
            plugins = data.get("plugins", [])
            if not isinstance(plugins, list):
                _failure(violations, relative, "plugins", "must be a list")
                continue
            for index, plugin in enumerate(plugins):
                prefix = "plugins[{}]".format(index)
                if not isinstance(plugin, dict):
                    _failure(violations, relative, prefix, "must be an object")
                    continue
                _check_name(violations, relative, prefix + ".name", plugin.get("name"))
                if "author" in plugin:
                    _check_author(violations, relative, prefix + ".author", plugin["author"])
                if "version" in plugin:
                    _check_version(violations, relative, prefix + ".version", plugin["version"], canonical_version)
        elif path.name == "openclaw.plugin.json":
            # OpenClaw is a separate ecosystem: `id` is the kebab identifier and
            # `name` is a human-readable display string (spaces/caps allowed).
            # Do not impose Claude Code's name rules on it.
            if "id" in data:
                _check_name(violations, relative, "id", data["id"])
            if "author" in data:
                _check_author(violations, relative, "author", data["author"])
            if "version" in data:
                _check_version(violations, relative, "version", data["version"], canonical_version)
        else:
            _check_name(violations, relative, "name", data.get("name"))
            if "author" in data:
                _check_author(violations, relative, "author", data["author"])
            if "version" in data:
                _check_version(violations, relative, "version", data["version"], canonical_version)

    for path in discover_skill_markdown(root):
        relative = path.relative_to(root)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            # UnicodeDecodeError is a ValueError, not an OSError: a non-UTF-8
            # SKILL.md must be reported as a violation, never crash the gate.
            _failure(violations, relative, "SKILL.md", "could not read: {}".format(exc))
            continue
        _validate_frontmatter(violations, relative, text)

    return manifests, violations


def _check_version(violations, path, field, value, canonical_version):
    if canonical_version is not None and value != canonical_version:
        _failure(
            violations, path, field,
            "version {} does not match canonical version {}".format(value, canonical_version),
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--require-yaml", action="store_true",
        help="fail instead of falling back to the weaker structural-only "
             "frontmatter check when PyYAML is unavailable (use in CI)",
    )
    args = parser.parse_args(argv)

    # Without PyYAML the frontmatter check covers only the structural pass.
    # --require-yaml fails closed; otherwise the reduced scope is reported.
    degraded = _yaml is None
    if degraded and args.require_yaml:
        print("ERROR: PyYAML is required for full frontmatter validation "
              "(--require-yaml was passed); install pyyaml", file=sys.stderr)
        return 2
    if degraded:
        print("WARNING: PyYAML not installed - frontmatter checks limited to "
              "the structural pass (no YAML parse or type validation)",
              file=sys.stderr)

    manifests, violations = validate_manifests(args.root)

    if args.as_json:
        print(json.dumps({"valid": not violations, "manifests": len(manifests),
                          "violations": violations, "yaml_available": not degraded}, indent=2))
    elif violations:
        for violation in violations:
            print("ERROR: {file}: {field}: {message}".format(**violation))
    else:
        print("OK: {} manifests valid".format(len(manifests)))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
