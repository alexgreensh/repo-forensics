#!/usr/bin/env python3
"""
scan_devcontainer.py - Devcontainer Security Scanner
Audits devcontainer.json for host secret exposure, container escape vectors,
and supply chain risks via lifecycle commands.

Uses json.load() for structured analysis (not regex on raw text).

Created by Alex Greenshpun
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "devcontainer"

TARGET_FILENAMES = {"devcontainer.json", ".devcontainer.json"}

SECRET_PATHS = {".npmrc", ".ssh", ".aws", ".env", ".gnupg", ".config/gcloud", ".azure", ".kube"}

SECRET_ENV_KEYWORDS = re.compile(
    r'(?i)(API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY|AUTH|CREDENTIAL|ACCESS_KEY)', re.IGNORECASE
)

LIFECYCLE_COMMANDS = [
    "initializeCommand", "onCreateCommand", "updateContentCommand",
    "postCreateCommand", "postStartCommand", "postAttachCommand",
]


def _commands_to_strings(value):
    """Normalize a devcontainer command field to a list of strings.
    Handles string, list, and dict forms per the devcontainer spec."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [" ".join(str(s) for s in value)]
    if isinstance(value, dict):
        result = []
        for v in value.values():
            result.extend(_commands_to_strings(v))
        return result
    return []


def _has_secret_path(text):
    """Check if a string references a known host secret path."""
    for sp in SECRET_PATHS:
        if sp in text:
            return sp
    return None


def scan_devcontainer(file_path, rel_path):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
        return findings

    if not isinstance(data, dict):
        return findings

    # --- Mounts: host secret exposure ---
    for mount in data.get("mounts", []):
        mount_str = mount if isinstance(mount, str) else json.dumps(mount)
        secret = _has_secret_path(mount_str)
        if secret:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title="Devcontainer: Host Secret Mount",
                description=f"Mounts host path containing '{secret}' into container",
                file=rel_path, line=0, snippet=mount_str[:120],
                category="host-secret-exposure"
            ))
        if "/var/run/docker.sock" in mount_str:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title="Devcontainer: Docker Socket Mount",
                description="Docker socket mounted into container (container escape vector)",
                file=rel_path, line=0, snippet=mount_str[:120],
                category="container-escape"
            ))

    # --- runArgs ---
    run_args = data.get("runArgs", [])
    if isinstance(run_args, list):
        run_args_str = " ".join(str(a) for a in run_args)

        if "--privileged" in run_args_str:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title="Devcontainer: Privileged Container",
                description="Container runs in privileged mode (full host access)",
                file=rel_path, line=0, snippet="--privileged in runArgs",
                category="container-escape"
            ))

        if re.search(r'--cap-add[=\s]*SYS_ADMIN', run_args_str):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Devcontainer: SYS_ADMIN Capability",
                description="SYS_ADMIN capability grants near-full host access",
                file=rel_path, line=0, snippet="--cap-add SYS_ADMIN in runArgs",
                category="container-escape"
            ))

        for i, arg in enumerate(run_args):
            arg_str = str(arg)
            if arg_str in ("-v", "--volume") and i + 1 < len(run_args):
                vol = str(run_args[i + 1])
                secret = _has_secret_path(vol)
                if secret:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title="Devcontainer: runArgs Host Volume Mount",
                        description=f"Volume mount references host secret path '{secret}'",
                        file=rel_path, line=0, snippet=vol[:120],
                        category="host-secret-exposure"
                    ))
            if arg_str == "-e" and i + 1 < len(run_args):
                env_val = str(run_args[i + 1])
                if SECRET_ENV_KEYWORDS.search(env_val.split("=")[0] if "=" in env_val else env_val):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title="Devcontainer: Secret in runArgs Env Var",
                        description="Secret environment variable passed via runArgs",
                        file=rel_path, line=0, snippet=env_val[:120],
                        category="secret-in-config"
                    ))

    # --- remoteEnv / containerEnv: localEnv interpolation ---
    for env_field in ("remoteEnv", "containerEnv"):
        env_map = data.get(env_field, {})
        if not isinstance(env_map, dict):
            continue
        for key, val in env_map.items():
            if isinstance(val, str) and "${localEnv:" in val:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Devcontainer: {env_field} Pulls Host Secret",
                    description=f"'{key}' interpolates host env via ${{localEnv:}}. Lifecycle commands can exfiltrate this.",
                    file=rel_path, line=0, snippet=f"{key}={val}"[:120],
                    category="host-secret-exposure"
                ))

    # --- Lifecycle commands ---
    for cmd_name in LIFECYCLE_COMMANDS:
        raw = data.get(cmd_name)
        if raw is None:
            continue
        commands = _commands_to_strings(raw)
        for cmd in commands:
            secret = _has_secret_path(cmd)
            if secret:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"Devcontainer: {cmd_name} Accesses Host Secrets",
                    description=f"Lifecycle command references host secret path '{secret}'",
                    file=rel_path, line=0, snippet=cmd[:120],
                    category="host-secret-exposure"
                ))

            if re.search(r'\b(curl|wget)\s+', cmd):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Devcontainer: Remote Fetch in {cmd_name}",
                    description="Lifecycle command fetches remote content at container creation",
                    file=rel_path, line=0, snippet=cmd[:120],
                    category="remote-code-execution"
                ))

    # --- Features: untrusted OCI artifacts ---
    features = data.get("features", {})
    if isinstance(features, dict):
        trusted_prefixes = ("ghcr.io/devcontainers/", "mcr.microsoft.com/")
        for feature_ref in features:
            if not any(feature_ref.startswith(p) for p in trusted_prefixes):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="Devcontainer: Untrusted Feature",
                    description=f"Feature '{feature_ref}' is not from a trusted registry. Features run install scripts as root.",
                    file=rel_path, line=0, snippet=feature_ref[:120],
                    category="untrusted-source"
                ))

    return findings


def main():
    args = core.parse_common_args(sys.argv, "Devcontainer Security Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning devcontainers in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        basename = os.path.basename(file_path)
        if basename in TARGET_FILENAMES:
            all_findings.extend(scan_devcontainer(file_path, rel_path))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
