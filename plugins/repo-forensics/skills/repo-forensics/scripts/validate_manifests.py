#!/usr/bin/env python3
"""Validate plugin and marketplace manifests before they are shipped."""

import argparse
import json
import re
import sys
from pathlib import Path


NAME_RE = re.compile(r"^[a-z0-9-]+$")
RESERVED_PREFIXES = ("claude-", "anthropic-")


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
    args = parser.parse_args(argv)
    manifests, violations = validate_manifests(args.root)

    if args.as_json:
        print(json.dumps({"valid": not violations, "manifests": len(manifests), "violations": violations}, indent=2))
    elif violations:
        for violation in violations:
            print("ERROR: {file}: {field}: {message}".format(**violation))
    else:
        print("OK: {} manifests valid".format(len(manifests)))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
