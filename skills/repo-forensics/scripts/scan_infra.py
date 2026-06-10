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
# npm recommends >= 3 days to allow malware detection before install (npm 11+)
MIN_RELEASE_AGE_DAYS = 3

# Megalodon (May 2026): base64 decode-then-pipe-to-shell patterns.
# The dangerous signal is base64 -d outputting INTO a pipe to a shell interpreter,
# or the heredoc variant. Broad base64 presence is intentionally NOT flagged to
# avoid false positives on GCP service account keys, Docker registry tokens, and
# K8s CA certs that appear frequently in legitimate CI workflows.
#
# Dangerous examples:
#   base64 -d | bash          (direct decode to shell)
#   base64 --decode | sh      (--decode variant)
#   base64 -d <<< "$PAYLOAD" | python3  (heredoc input variant)
# NOT flagged:
#   DECODED=$(echo $KEY | base64 --decode)  (captured in variable, not exec'd)
#   base64 -w0 < file.json > out.b64        (encode-only, no decode pipe)
_B64_EXEC_RE = re.compile(
    r'base64\s+(?:-d|--decode)\s*\|'    # base64 -d | ... (output piped to shell)
    r'|base64\s+(?:-d|--decode)\s*<<<'  # base64 -d <<< "..." heredoc variant
    r'|base64\s+(?:-d|--decode)\s*>'    # base64 -d > /tmp/x (redirect-then-exec)
)

# Known compromised GitHub Actions (2025-2026 supply chain attacks)
COMPROMISED_ACTIONS = {
    "tj-actions/changed-files": "CVE-2025-30066: Secret exfiltration via CI logs (March 2025)",
    "tj-actions/eslint-changed-files": "Compromised in same campaign as tj-actions/changed-files (March 2025)",
    "reviewdog/action-setup": "Compromised March 2025 (tj-actions/changed-files chain)",
    "reviewdog/action-shellcheck": "Compromised March 2025 (tj-actions/changed-files chain)",
    "reviewdog/action-composite-template": "Compromised March 2025 (tj-actions/changed-files chain)",
    "reviewdog/action-staticcheck": "Compromised March 2025 (tj-actions/changed-files chain)",
    "reviewdog/action-ast-grep": "Compromised March 2025 (tj-actions/changed-files chain)",
    "reviewdog/action-typos": "Compromised March 2025 (tj-actions/changed-files chain)",
    "aquasecurity/trivy-action": "TeamPCP: 75 of 76 tags compromised (March 2026)",
    "aquasecurity/setup-trivy": "TeamPCP: 7 tags compromised (March 2026)",
    "checkmarx/kics-github-action": "TeamPCP: All tags pre-v2.1.20 compromised (March-April 2026)",
    "checkmarx/ast-github-action": "TeamPCP: v2.3.28 and v2.3.35 compromised (March-April 2026)",
}

AGENTIC_CI_ACTION_RE = re.compile(
    r'(?i)(anthropics?/claude-code(?:-base)?-action|'
    r'anthropic-ai/claude-code(?:-base)?-action|'
    r'claude-code(?:-base)?-action|openai/codex(?:-action)?)'
)

UNTRUSTED_AGENTIC_TRIGGER_RE = re.compile(
    r'(?im)(^\s*(pull_request|pull_request_target|issues|issue_comment|discussion)\s*:'
    r'|^\s*["\']?on["\']?\s*:\s*["\']?(pull_request|pull_request_target|issues|issue_comment|discussion)["\']?\s*$'
    r'|^\s*["\']?on["\']?\s*:\s*\[[^\]]*(pull_request|pull_request_target|issues|issue_comment|discussion)[^\]]*\])'
)

AGENTIC_SENSITIVE_TOOLS_RE = re.compile(
    r'(?is)\ballowed_tools\b\s*:\s*(?:[|>]\s*)?.{0,800}'
    r'\b(Read|Bash|WebFetch|WebSearch|mcp__github|github_comment|create_pull_request)\b'
)

AGENTIC_EXTERNAL_CHANNEL_RE = re.compile(
    r'(?is)\b(WebFetch|curl|wget|mcp__github|github_comment|create_pull_request)\b'
    r'|show_full_output\s*:\s*true'
)

PROC_SECRET_PATH_RE = re.compile(
    r'/proc/(?:self|[0-9]+)/environ|/proc/(?:self|[0-9]+)/mem',
    re.IGNORECASE,
)


def _strip_shell_comment(line):
    """Strip shell comments, respecting single and double quotes.

    Naive '#.*$' fails on URLs (curl https://x.com/setup#v2 && npm install)
    and quoted strings (echo "this # not a comment" && npm install).
    """
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == '#' and not in_single and not in_double:
            if i == 0 or line[i - 1] in (' ', '\t'):
                return line[:i]
    return line


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

            if stripped.startswith("ARG ") and re.search(r'(?i)(secret|password|token|key|api_key|credential|private)', stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="Docker: Secret in ARG Directive",
                    description="ARG values are permanently visible in docker history. Use BuildKit secrets or multi-stage builds.",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="secret-in-config"
                ))

            if re.search(r'(?:COPY|ADD)\s+.*\.env\b(?!\.example|\.template|\.sample)', stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Docker: .env File Copied into Image",
                    description=".env file copied into Docker image layer. Visible even if deleted later. Use multi-stage builds.",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="secret-in-image"
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

            # Mini Shai-Hulud: discussion-triggered C2 workflow (TeamPCP Wave 6)
            if re.match(r'discussion\s*:', stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="GHA: Discussion-Triggered Workflow",
                    description="Workflow triggers on discussion events. Mini Shai-Hulud uses discussion.yaml as a C2 channel "
                        "with expression injection via discussion body (TeamPCP Wave 6)",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))

            # Unpinned third-party actions (not pinned to SHA)
            m = re.match(r'\s*-?\s*uses:\s*([^@\s]+)@(.+)', stripped)
            if m:
                action = m.group(1)
                ref = m.group(2).strip()
                action_lower = action.lower()

                # Check against known compromised actions
                if action_lower in COMPROMISED_ACTIONS:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"GHA: Known Compromised Action: {action}",
                        description=f"This action was compromised in a supply chain attack. {COMPROMISED_ACTIONS[action_lower]}",
                        file=rel_path, line=i+1, snippet=stripped[:120],
                        category="compromised-action"
                    ))

                # Existing unpinned action checks...
                is_official = action_lower.startswith('actions/') or action_lower.startswith('github/')
                is_sha_pinned = bool(re.match(r'^[a-f0-9]{40}', ref))

                if not is_sha_pinned and not is_official:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title="GHA: Unpinned Third-Party Action",
                        description=f"Action '{action}@{ref}' not pinned to commit SHA (supply chain risk)",
                        file=rel_path, line=i+1, snippet=stripped[:120],
                        category="ci-cd"
                    ))
                elif not is_sha_pinned and is_official:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="medium",
                        title="GHA: Unpinned Official Action",
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

            # secrets: inherit passes ALL caller secrets to reusable workflow
            if re.match(r'\s*secrets\s*:\s*inherit\s*$', stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="GHA: secrets: inherit Passes All Secrets",
                    description="secrets: inherit passes ALL caller secrets to the reusable workflow and any third-party actions it uses. Prefer explicit secret forwarding.",
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
            _injection_exprs = (
                '${{ github.event.', '${{ github.head_ref',
                '${{ github.event_path', '${{ inputs.',
                '${{ github.event.discussion.body',
                '${{ github.event.discussion.title',
                '${{ github.event.comment.body',
            )
            for _expr in _injection_exprs:
                if _expr in stripped and ('run:' in stripped or 'run: |' in stripped):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title="GHA: Expression Injection Risk",
                        description=f"Attacker-controlled expression '{_expr}...' in run block can inject shell commands",
                        file=rel_path, line=i+1, snippet=stripped[:120],
                        category="ci-cd"
                    ))
                    break

            # Mini Shai-Hulud: OIDC token exchange in workflow (TeamPCP Wave 6)
            if re.search(r'ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL|oidc/token/exchange', stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="GHA: OIDC Token Exchange",
                    description="Workflow accesses OIDC token exchange endpoints. Mini Shai-Hulud abused this to mint npm publish tokens (TeamPCP Wave 6)",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-token-abuse"
                ))

            if re.search(r'\brun\s*:\s*(?:.+\s)?npm\s+(?:install|i)(?=\s|$)', _strip_shell_comment(stripped)):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="GHA: npm install in Workflow",
                    description="Workflow uses npm install instead of npm ci (non-deterministic install, weaker lockfile enforcement)",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))

            # Auto-commit legitimization loop: git push in workflow with [skip ci]
            if re.search(r'git\s+push', stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="GHA: Auto-Push to Repository",
                    description="Workflow pushes commits directly. Combined with auto-generated content, "
                        "this creates a legitimization loop where tampered files get fresh checksums/lockfiles",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-integrity"
                ))

            # Megalodon campaign (May 2026): base64 decode-and-execute.
            # Pattern defined at module level as _B64_EXEC_RE.
            if _B64_EXEC_RE.search(stripped):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="GHA: Base64 Decode-and-Execute in Workflow (Megalodon pattern)",
                    description="Workflow decodes base64 content and pipes to a shell interpreter. "
                        "This matches the Megalodon supply chain campaign (May 2026) which used "
                        "this exact pattern to execute obfuscated payloads inside CI runners.",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))

            # Deprecated workflow commands (log injection vectors)
            if '::set-output' in stripped or '::save-state' in stripped:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="GHA: Deprecated Workflow Command",
                    description="Deprecated ::set-output or ::save-state enables log command injection. "
                        "Use $GITHUB_OUTPUT / $GITHUB_STATE instead (deprecated since Nov 2022)",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="ci-cd"
                ))

        content = ''.join(lines)

        if PROC_SECRET_PATH_RE.search(content):
            line_no = content[:PROC_SECRET_PATH_RE.search(content).start()].count('\n') + 1
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title="GHA: /proc Secret Exposure Path",
                description=(
                    "Workflow references /proc/self/environ or /proc/*/mem. "
                    "Microsoft's June 2026 Claude Code GitHub Action research "
                    "showed these paths can expose CI secrets when read by an "
                    "agent tool."
                ),
                file=rel_path, line=line_no,
                snippet=content.splitlines()[line_no - 1].strip()[:120],
                category="agentic-ci"
            ))

        has_agentic_action = bool(AGENTIC_CI_ACTION_RE.search(content))
        has_untrusted_trigger = bool(UNTRUSTED_AGENTIC_TRIGGER_RE.search(content))
        has_secret_context = '${{ secrets.' in content or re.search(r'(?im)^\s*secrets\s*:\s*inherit\s*$', content)
        has_sensitive_tools = bool(AGENTIC_SENSITIVE_TOOLS_RE.search(content))
        has_external_channel = bool(AGENTIC_EXTERNAL_CHANNEL_RE.search(content))
        if has_agentic_action and has_untrusted_trigger and has_secret_context and has_sensitive_tools:
            action_match = AGENTIC_CI_ACTION_RE.search(content)
            line_no = content[:action_match.start()].count('\n') + 1 if action_match else 0
            severity = "critical" if has_external_channel else "high"
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity=severity,
                title="GHA: Agentic CI Secret Exposure Risk",
                description=(
                    "AI workflow processes untrusted GitHub content while secrets "
                    "and sensitive agent tools are available. This violates the "
                    "agentic CI separation model highlighted by Microsoft's June "
                    "2026 Claude Code GitHub Action case."
                ),
                file=rel_path, line=line_no,
                snippet="agent action + untrusted trigger + secrets + sensitive tools",
                category="agentic-ci"
            ))

        # Multi-line run block check
        secret_lines = {f.line for f in findings if 'Secret' in f.title}
        for m in re.finditer(r'run:\s*[|>]-?\s*\n((?:\s+.*\n)+)', content):
            block = m.group(1)
            line_no = content[:m.start()].count('\n') + 1
            if '${{ secrets.' in block:
                if line_no not in secret_lines:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title="GHA: Secret in Multi-line Run Block",
                        description="Secret interpolated in multi-line shell script",
                        file=rel_path, line=line_no, snippet=block.strip()[:120],
                        category="ci-cd"
                    ))
            # Check for expression injection in multi-line blocks (attacker-controlled inputs)
            for expr in ('${{ github.event.', '${{ github.head_ref', '${{ github.event_path', '${{ inputs.'):
                if expr in block:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="high",
                        title="GHA: Expression Injection in Multi-line Run Block",
                        description=f"Attacker-controlled expression '{expr}...' in shell script (expression injection risk)",
                        file=rel_path, line=line_no, snippet=block.strip()[:120],
                        category="ci-cd"
                    ))
                    break
            # Megalodon: base64 decode-and-execute in multi-line run blocks
            # Skip if the per-line loop already caught this (avoid double-firing)
            b64_already = any(f.line == line_no and "Megalodon" in f.title for f in findings)
            if not b64_already and _B64_EXEC_RE.search(block):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="GHA: Base64 Decode-and-Execute in Workflow (Megalodon pattern)",
                    description="Multi-line run block decodes base64 content and pipes to a shell interpreter. "
                        "This matches the Megalodon supply chain campaign (May 2026) which used "
                        "this exact pattern to execute obfuscated payloads inside CI runners.",
                    file=rel_path, line=line_no, snippet=block.strip()[:120],
                    category="ci-cd"
                ))

            # Strip comments (quote-aware) from each line before checking npm install
            block_code = "\n".join(
                _strip_shell_comment(ln) for ln in block.splitlines()
                if not ln.strip().startswith("#")
            )
            if re.search(r'\bnpm\s+(?:install|i)(?=\s|$)', block_code):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="GHA: npm install in Multi-line Run Block",
                    description="Workflow uses npm install instead of npm ci in a multi-line script (non-deterministic install, weaker lockfile enforcement)",
                    file=rel_path, line=line_no, snippet=block.strip()[:120],
                    category="ci-cd"
                ))

        # Item 7: Zombie workflow detection - workflow_dispatch only + write permissions
        has_workflow_dispatch = False
        has_other_trigger = False
        has_write_perm = False
        for line in lines:
            stripped_l = line.strip()
            if re.match(r'workflow_dispatch\s*:', stripped_l) or stripped_l == 'workflow_dispatch':
                has_workflow_dispatch = True
            # Check for other triggers (push, pull_request, schedule, etc.)
            for trigger in ('push', 'pull_request', 'pull_request_target', 'schedule',
                            'release', 'issues', 'issue_comment', 'watch', 'fork',
                            'create', 'delete', 'deployment', 'repository_dispatch'):
                if re.match(rf'{trigger}\s*:', stripped_l) or stripped_l == trigger:
                    has_other_trigger = True
                    break
            # Check for write permissions
            if re.search(r'(contents|packages|actions|security-events|deployments|pages)\s*:\s*write', stripped_l):
                has_write_perm = True
            if re.search(r'permissions\s*:\s*write-all', stripped_l):
                has_write_perm = True

        if has_workflow_dispatch and not has_other_trigger and has_write_perm:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="medium",
                title="GHA: Zombie Workflow (dispatch-only with write permissions)",
                description="Workflow has only workflow_dispatch trigger but retains write permissions. "
                    "Dormant workflows with elevated permissions can be manually triggered by anyone with repo access.",
                file=rel_path, line=0, snippet="workflow_dispatch-only + write permissions",
                category="ci-cd"
            ))

        # Item 8: GHA cache poisoning - actions/cache without content hash in key
        for i, line in enumerate(lines):
            stripped_l = line.strip()
            m_cache = re.search(r'uses:\s*actions/cache@', stripped_l)
            if m_cache:
                # Look ahead for the key: field within next few lines
                cache_line_idx = i
                key_content = ""
                for look_line in lines[cache_line_idx:min(cache_line_idx + 10, len(lines))]:
                    key_match = re.search(r'key\s*:\s*(.+)', look_line)
                    if key_match:
                        key_content = key_match.group(1).strip()
                        break
                if key_content:
                    has_hash = 'hashFiles' in key_content or 'hash' in key_content.lower()
                    if not has_hash:
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="medium",
                            title="GHA: Cache Key Without Content Hash",
                            description="Cache key without content hash (hashFiles) allows cache poisoning via stale injection. "
                                "Use hashFiles('**/lockfile') in cache key to ensure integrity.",
                            file=rel_path, line=cache_line_idx + 1, snippet=key_content[:120],
                            category="ci-cd"
                        ))
                        break  # One finding per workflow is sufficient

        # pull_request_target + actions/cache save = cache poisoning via forked PR
        non_comment = [ln for ln in lines if not ln.lstrip().startswith('#')]
        has_prt = any("pull_request_target" in line for line in non_comment)
        has_cache_save = any(
            re.search(r'uses:\s*actions/cache(?:/save)?@', line) for line in non_comment
        )
        if has_prt and has_cache_save:
            cache_key_info = ""
            for line in non_comment:
                key_match = re.search(r'key\s*:\s*(.+)', line)
                if key_match:
                    cache_key_info = key_match.group(1).strip()[:80]
                    break
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title="GHA: pull_request_target + Cache Write (Cache Poisoning)",
                description=(
                    "Workflow uses pull_request_target trigger with actions/cache. "
                    "Forked PRs run with repo write permissions and can poison the cache "
                    "with malicious content. Subsequent builds on the default branch consume "
                    "the poisoned cache (TanStack postmortem, May 2026)."
                ),
                file=rel_path, line=0,
                snippet=f"pull_request_target + actions/cache (key: {cache_key_info})" if cache_key_info else "pull_request_target + actions/cache",
                category="cache-poisoning"
            ))

        # TanStack attack vector: pull_request_target + id-token: write.
        # Forked PRs get write permissions AND can mint OIDC tokens for npm publish.
        has_id_token_write = any(
            re.search(r'id-token\s*:\s*write', line) for line in non_comment
        )
        if has_prt and has_id_token_write:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title="GHA: pull_request_target + id-token: write (TanStack Attack Vector)",
                description=(
                    "Workflow combines pull_request_target trigger with id-token: write permission. "
                    "Forked PRs can mint OIDC tokens exchangeable for npm publish tokens. "
                    "This exact combination was exploited in the TanStack supply chain attack "
                    "(CVE-2026-45321, TeamPCP Wave 7, May 2026)"
                ),
                file=rel_path, line=0,
                snippet="pull_request_target + id-token: write",
                category="ci-token-abuse"
            ))

        if has_id_token_write and not has_prt:
            for i, line in enumerate(lines):
                if re.search(r'id-token\s*:\s*write', line):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="medium",
                        title="GHA: id-token: write Permission",
                        description="Workflow can request OIDC tokens (used for npm provenance, cloud auth). Verify this is intentional.",
                        file=rel_path, line=i + 1, snippet=line.strip()[:120],
                        category="ci-cd"
                    ))
                    break

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
            if min_release_match and int(min_release_match.group(1)) >= MIN_RELEASE_AGE_DAYS:
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
                        description="git= points to non-system path (PackageGate .npmrc injection bypass vector)",
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


def scan_sandbox_profile(file_path, rel_path):
    """Detect overly permissive sandbox policies (.sb seatbelt, seccomp, apparmor)."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if file_path.endswith('.sb'):
            if '(allow default)' in content:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="Sandbox: allow-default Policy (Inverted)",
                    description="macOS Seatbelt profile uses (allow default) with selective denies. "
                        "Sub-agents can read all host files (SSH keys, AWS creds, keychains). "
                        "Invert to (deny default) with explicit allows",
                    file=rel_path, line=1, snippet="(allow default)",
                    category="sandbox-policy"
                ))

        if file_path.endswith('.json') and 'seccomp' in rel_path.lower():
            if '"SCMP_ACT_ALLOW"' in content and '"defaultAction"' in content:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="Sandbox: Seccomp Default Allow",
                    description="Seccomp profile defaults to ALLOW. All syscalls permitted unless explicitly denied. "
                        "Use SCMP_ACT_ERRNO or SCMP_ACT_KILL as default",
                    file=rel_path, line=1, snippet='defaultAction: SCMP_ACT_ALLOW',
                    category="sandbox-policy"
                ))
    except (OSError, UnicodeDecodeError):
        pass
    return findings


def scan_shell_script(file_path, rel_path):
    """Detect supply-chain and integrity issues in shell scripts."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        has_curl_pipe = False
        has_checksum_verify = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue

            # Pipe-to-shell without integrity check
            if re.search(r'curl\s.*\|\s*(ba)?sh|wget\s.*\|\s*(ba)?sh', stripped):
                has_curl_pipe = True
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Shell: Pipe-to-Shell Install",
                    description="Downloads and executes remote code in one pipeline without integrity verification. "
                        "Add checksum verification between download and execution",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="supply-chain"
                ))

            # git pull without pinning (auto-update pattern)
            if re.search(r'git\s+pull\b', stripped) and 'ff-only' in stripped:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="Shell: Unpinned Git Pull (Auto-Update)",
                    description="git pull --ff-only without commit SHA verification. "
                        "If the remote is compromised, arbitrary code is pulled automatically",
                    file=rel_path, line=i+1, snippet=stripped[:120],
                    category="supply-chain"
                ))

            # Track if checksum verification exists anywhere in the script
            if re.search(r'sha256sum|shasum|gpg\s+--verify|cosign\s+verify', stripped):
                has_checksum_verify = True

        # If there's a curl|bash but also checksum verification, downgrade the finding
        if has_curl_pipe and has_checksum_verify:
            for f in findings:
                if 'Pipe-to-Shell' in f.title:
                    f.severity = "low"

    except (OSError, UnicodeDecodeError):
        pass
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

        # Sandbox profiles (macOS Seatbelt, seccomp)
        if basename.endswith('.sb') or ('seccomp' in rel_path.lower() and basename.endswith('.json')):
            all_findings.extend(scan_sandbox_profile(file_path, rel_path))

        # Shell scripts (supply-chain patterns)
        if basename.endswith('.sh') or basename == 'Makefile':
            all_findings.extend(scan_shell_script(file_path, rel_path))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
