#!/usr/bin/env python3
"""
scan_infra.py - Infrastructure Security Scanner (v2)
Audits Dockerfiles, Kubernetes manifests, CI/CD workflows.
Added: unpinned GitHub Actions detection, secrets in run blocks.

Created by Alex Greenshpun
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "infra"


def scan_dockerfile(file_path, rel_path):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        has_user = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("USER "):
                has_user = True
                if "root" in stripped.lower() and "nonroot" not in stripped.lower():
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="medium",
                        title="Docker: Running as ROOT",
                        description="Container explicitly runs as root user",
                        file=rel_path, line=i+1, snippet=stripped[:120],
                        category="container-config"
                    ))

            if stripped.startswith("ADD ") and "http" in stripped:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="Docker: ADD with Remote URL",
                    description="Using ADD with remote URL (use COPY + curl/wget instead for verification)",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="container-config"
                ))

            if re.search(r'(?i)(password|secret|token|key)\s*=', stripped) and "ENV" in stripped:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Docker: Secret in ENV",
                    description="Potential secret hardcoded in environment variable",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="secret-in-config"
                ))

        if not has_user:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="low",
                title="Docker: No USER Instruction",
                description="No USER instruction found (defaults to root)",
                file=rel_path, line=0, snippet="Missing USER directive",
                category="container-config"
            ))
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_kubernetes(file_path, rel_path):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.split('\n')

        for i, line in enumerate(lines):
            if "privileged: true" in line:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="K8s: Privileged Container",
                    description="Container running in privileged mode (container breakout risk)",
                    file=rel_path, line=i+1, snippet=line.strip()[:120],
                    category="container-config"
                ))
            if "hostPath:" in line:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="K8s: hostPath Mount",
                    description="hostPath volume mount detected (container breakout risk)",
                    file=rel_path, line=i+1, snippet=line.strip()[:120],
                    category="container-config"
                ))
            if "hostNetwork: true" in line:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="K8s: Host Network",
                    description="Container using host network namespace",
                    file=rel_path, line=i+1, snippet=line.strip()[:120],
                    category="container-config"
                ))
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_github_actions(file_path, rel_path):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            stripped = line.strip()

            if "pull_request_target" in stripped:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="GHA: pull_request_target Trigger",
                    description="pull_request_target runs with write permissions on forked PRs (script injection risk)",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))

            # Unpinned third-party actions (not pinned to SHA)
            m = re.match(r'\s*-?\s*uses:\s*([^@\s]+)@(.+)', stripped)
            if m:
                action = m.group(1)
                ref = m.group(2).strip()
                # Official actions are lower risk, but third-party unpinned is high
                is_official = action.startswith('actions/') or action.startswith('github/')
                is_sha_pinned = bool(re.match(r'^[a-f0-9]{40}', ref))

                if not is_sha_pinned and not is_official:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title=f"GHA: Unpinned Third-Party Action",
                        description=f"Action '{action}@{ref}' not pinned to commit SHA (supply chain risk)",
                        file=rel_path, line=i+1, snippet=stripped[:120],
                        category="ci-cd"
                    ))
                elif not is_sha_pinned and is_official:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="medium",
                        title=f"GHA: Unpinned Official Action",
                        description=f"Action '{action}@{ref}' not pinned to commit SHA (official action compromise is a real vector)",
                        file=rel_path, line=i+1, snippet=stripped[:120],
                        category="ci-cd"
                    ))

            # Dangerous permissions
            if re.search(r'contents\s*:\s*write', stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="GHA: contents: write Permission",
                    description="Workflow has write access to repository contents (can push code, create releases)",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))
            if re.search(r'permissions\s*:\s*write-all', stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="GHA: write-all Permissions",
                    description="Workflow has full write permissions to all scopes",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))

            # Self-hosted runners
            if re.search(r'runs-on\s*:\s*self-hosted', stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="GHA: Self-Hosted Runner",
                    description="Workflow runs on self-hosted runner (persistent environment, credential exposure risk)",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))

            if '${{ secrets.' in stripped and ('run:' in stripped or 'run: |' in stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="GHA: Secret in Run Block",
                    description="Secret directly interpolated in shell command (log exposure risk)",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))

            # GHA expression injection: attacker-controlled inputs in run blocks
            if '${{ github.event.' in stripped and ('run:' in stripped or 'run: |' in stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="GHA: Expression Injection Risk",
                    description="github.event.* is attacker-controlled in PRs and can inject shell commands",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))

            # Strip shell comments before checking npm install
            cmd_part = re.sub(r'#.*$', '', stripped)
            if re.search(r'\brun\s*:\s*(?:.+\s)?npm\s+(?:install|i)(?=\s|$)', cmd_part):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="GHA: npm install in Workflow",
                    description="Workflow uses npm install instead of npm ci (non-deterministic install, weaker lockfile enforcement)",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))

        # Multi-line run block check
        content = ''.join(lines)
        for m in re.finditer(r'run:\s*\|\n((?:\s+.*\n)+)', content):
            block = m.group(1)
            line_no = content[:m.start()].count('\n') + 1
            if '${{ secrets.' in block:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="GHA: Secret in Multi-line Run Block",
                    description="Secret interpolated in multi-line shell script",
                    file=rel_path, line=line_no, snippet=block.strip()[:120],
                    category="ci-cd"
                ))
            # Check for expression injection in multi-line blocks (attacker-controlled inputs)
            for expr in ('${{ github.event.', '${{ github.event_path', '${{ inputs.'):
                if expr in block:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title="GHA: Expression Injection in Multi-line Run Block",
                        description=f"Attacker-controlled expression '{expr}...' in shell script (expression injection risk)",
                        file=rel_path, line=line_no, snippet=block.strip()[:120],
                        category="ci-cd"
                    ))
                    break
            # Check non-comment lines for npm install
            block_code = "\n".join(
                ln for ln in block.splitlines() if not ln.strip().startswith("#")
            )
            if re.search(r'\bnpm\s+(?:install|i)(?=\s|$)', block_code):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="GHA: npm install in Multi-line Run Block",
                    description="Workflow uses npm install instead of npm ci in a multi-line script (non-deterministic install, weaker lockfile enforcement)",
                    file=rel_path, line=line_no, snippet=block.strip()[:120],
                    category="ci-cd"
                ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_npmrc(file_path, rel_path):
    """Scan .npmrc for security-relevant configuration."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        lines = content.split('\n')

        has_ignore_scripts = False
        has_allow_git_none = False
        has_min_release_age = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith(';'):
                continue

            if re.match(r'ignore-scripts\s*=\s*true', stripped):
                has_ignore_scripts = True
            if re.match(r'allow-git\s*=\s*none', stripped, re.IGNORECASE):
                has_allow_git_none = True
            min_release_match = re.match(r'min-release-age\s*=\s*(\d+)', stripped, re.IGNORECASE)
            if min_release_match and int(min_release_match.group(1)) >= 3:
                has_min_release_age = True

            if re.match(r'strict-ssl\s*=\s*false', stripped, re.IGNORECASE):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=".npmrc: SSL Verification Disabled",
                    description="strict-ssl=false allows MITM attacks on registry connections",
                    file=rel_path, line=i + 1, snippet=stripped[:120],
                    category="npmrc-config"
                ))

            if re.match(r'package-lock\s*=\s*false', stripped, re.IGNORECASE):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=".npmrc: Lockfile Generation Disabled",
                    description="package-lock=false prevents lockfile creation (no dependency pinning)",
                    file=rel_path, line=i + 1, snippet=stripped[:120],
                    category="npmrc-config"
                ))

            # git= override pointing to non-system paths (PackageGate bypass)
            git_match = re.match(r'git\s*=\s*(.+)', stripped)
            if git_match:
                git_path = git_match.group(1).strip()
                system_git_paths = ('/usr/bin/git', '/usr/local/bin/git', '/opt/homebrew/bin/git', 'git')
                if git_path not in system_git_paths:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=".npmrc: Custom git Binary Override",
                        description=f"git= points to non-system path (PackageGate .npmrc injection bypass vector)",
                        file=rel_path, line=i + 1, snippet=stripped[:120],
                        category="npmrc-config"
                    ))

        if not has_ignore_scripts:
            # Check if project has lifecycle hooks (elevate severity if so)
            pkg_json = os.path.join(os.path.dirname(file_path), 'package.json')
            has_hooks = False
            if os.path.exists(pkg_json):
                try:
                    with open(pkg_json, 'r') as pf:
                        pkg_data = json.load(pf)
                    scripts = pkg_data.get('scripts', {})
                    hook_names = {'preinstall', 'postinstall', 'install', 'prepare', 'prepublish'}
                    has_hooks = bool(hook_names & set(scripts.keys()))
                except (json.JSONDecodeError, OSError):
                    pass

            sev = "high" if has_hooks else "medium"
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity=sev,
                title=".npmrc: Missing ignore-scripts",
                description="ignore-scripts=true not set (install scripts will execute)",
                file=rel_path, line=0, snippet="ignore-scripts not found",
                category="npmrc-config"
            ))

        if not has_allow_git_none:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="medium",
                title=".npmrc: Missing allow-git=none",
                description="allow-git=none not set (npm 11+; git dependencies can bypass ignore-scripts protections)",
                file=rel_path, line=0, snippet="allow-git=none not found",
                category="npmrc-config"
            ))

        if not has_min_release_age:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="low",
                title=".npmrc: Missing min-release-age",
                description="min-release-age>=3 not set (npm 11+; newly published packages are installed without cooldown)",
                file=rel_path, line=0, snippet="min-release-age>=3 not found",
                category="npmrc-config"
            ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_pnpm_workspace(file_path, rel_path):
    """Scan pnpm-workspace.yaml for security-relevant configuration."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        for i, line in enumerate(content.split('\n')):
            if re.search(r'dangerouslyAllowAllBuilds\s*:\s*true', line):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="pnpm: dangerouslyAllowAllBuilds Enabled",
                    description="All package build scripts allowed to run (bypasses pnpm safety)",
                    file=rel_path, line=i + 1, snippet=line.strip()[:120],
                    category="pnpm-config"
                ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def scan_claude_config(file_path, rel_path):
    """Scan .claude/settings.json and claude_desktop_config.json for dangerous patterns.
    Covers CVE-2025-59536 (hooks RCE) and CVE-2026-21852 (ANTHROPIC_BASE_URL override).
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # CVE-2025-59536: hooks section with shell execution → RCE before trust dialog
        hooks_patterns = [
            (re.compile(r'(?i)"hooks"\s*:'), "hooks section present in Claude Code settings"),
            (re.compile(r'(?i)"(PreToolUse|PostToolUse|UserPromptSubmit|Stop|SessionStart|SessionEnd)"\s*:'), "Claude Code hook event handler"),
            (re.compile(r'(?i)"command"\s*:\s*"[^"]{0,300}(curl|wget|bash|sh|python|node|exec|eval|base64)[^"]{0,300}"'), "Shell/download command in Claude Code hook (CVE-2025-59536 RCE vector)"),
        ]
        for pattern, title in hooks_patterns:
            for m in re.finditer(pattern, content):
                line_no = content[:m.start()].count('\n') + 1
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"Claude Config: {title}",
                    description="Hooks execute before trust dialog — attacker-planted hooks achieve RCE (CVE-2025-59536, CVSS 8.7)",
                    file=rel_path, line=line_no,
                    snippet=content[m.start():m.start()+120].replace('\n', ' '),
                    category="claude-code-rce"
                ))
                break  # One finding per pattern

        # CVE-2026-21852: ANTHROPIC_BASE_URL override → API key exfiltration
        if re.search(r'(?i)ANTHROPIC_BASE_URL', content):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title="Claude Config: ANTHROPIC_BASE_URL Override",
                description="ANTHROPIC_BASE_URL set in config — routes API calls through attacker proxy (CVE-2026-21852, CVSS 7.5)",
                file=rel_path, line=0,
                snippet="ANTHROPIC_BASE_URL override detected",
                category="claude-code-rce"
            ))

        # enableAllProjectMcpServers: consent bypass
        if re.search(r'(?i)enableAllProjectMcpServers\s*["\']?\s*:\s*true', content):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title="Claude Config: enableAllProjectMcpServers: true",
                description="Auto-approves all MCP servers in project — bypasses per-server consent dialog (supply chain attack amplifier)",
                file=rel_path, line=0,
                snippet="enableAllProjectMcpServers: true",
                category="mcp-config-risk"
            ))

        # CVE-2026-33068 (CVSS 7.7): Workspace trust bypass via bypassPermissions
        bypass_match = re.search(r'(?i)(bypassPermissions|"permission[_-]?mode"\s*:\s*"bypass")', content)
        if bypass_match:
            line_no = content[:bypass_match.start()].count('\n') + 1
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title="Claude Config: Workspace Trust Bypass (CVE-2026-33068)",
                description="bypassPermissions or elevated permission mode set in settings.json — bypasses workspace trust boundary (CVE-2026-33068, CVSS 7.7). Attacker-planted config can auto-approve dangerous tool calls.",
                file=rel_path, line=line_no,
                snippet=content[bypass_match.start():bypass_match.start()+120].replace('\n', ' '),
                category="claude-code-rce"
            ))

        # Claude Code source map leak (informational)
        if re.search(r'(?i)(sourceMap|source[_-]?map)\s*["\']?\s*:\s*true', content):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="low",
                title="Claude Config: Source Map Exposure",
                description="Source maps enabled in Claude Code config — may leak internal code structure to attackers (informational)",
                file=rel_path, line=0,
                snippet="sourceMap enabled",
                category="info-disclosure"
            ))

    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Infrastructure Security Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning Infrastructure in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        basename = os.path.basename(file_path)

        if basename == "Dockerfile" or basename.endswith(".dockerfile"):
            all_findings.extend(scan_dockerfile(file_path, rel_path))

        if basename == '.npmrc':
            all_findings.extend(scan_npmrc(file_path, rel_path))

        if basename == 'pnpm-workspace.yaml':
            all_findings.extend(scan_pnpm_workspace(file_path, rel_path))
        elif basename.endswith((".yaml", ".yml")):
            if ".github/workflows" in file_path:
                all_findings.extend(scan_github_actions(file_path, rel_path))
            else:
                # Only scan as Kubernetes if file has K8s markers
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        yaml_content = f.read()
                    if any(marker in yaml_content for marker in ('apiVersion:', 'kind:', 'metadata:')):
                        all_findings.extend(scan_kubernetes(file_path, rel_path))
                except (OSError, UnicodeDecodeError):
                    pass

        # Claude Code / MCP config files (CVE-2025-59536, CVE-2026-21852)
        if basename in ('claude_desktop_config.json', '.mcp.json') or \
           (basename == 'settings.json' and '.claude' in file_path):
            all_findings.extend(scan_claude_config(file_path, rel_path))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
