#!/usr/bin/env python3
"""
scan_secrets.py - Secret Scanner (v2: 40+ patterns with severity)
Detects hardcoded API keys, tokens, certificates, private keys,
database credentials, and generic secret assignments.

Created by Alex Greenshpun
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "secrets"

ENV_FILE_VARIANTS = {
    '.env', '.env.local', '.env.production', '.env.staging',
    '.env.development', '.env.test', '.env.docker', '.env.container',
}
ENV_FILE_SAFE = {'.env.example', '.env.template', '.env.sample'}

# Severity: critical = private keys, high = API keys, medium = generic assignments
PATTERNS = [
    # --- Critical: Private Keys ---
    {"name": "Private Key (RSA/PEM/EC/DSA/OPENSSH)", "severity": "critical",
     "regex": re.compile(r'-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----')},

    # --- High: Cloud Provider Keys ---
    {"name": "AWS Access Key ID", "severity": "high",
     "regex": re.compile(r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}')},
    {"name": "AWS Secret Access Key", "severity": "high",
     "regex": re.compile(r'(?i)aws[^\'"\n]{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]')},
    {"name": "Google API Key", "severity": "high",
     "regex": re.compile(r'AIza[0-9A-Za-z\\-_]{35}')},
    {"name": "Google OAuth Client Secret", "severity": "high",
     "regex": re.compile(r'(?i)client_secret[^\'"\n]{0,5}[\'"][a-zA-Z0-9_-]{24}[\'"]')},
    {"name": "Azure Connection String", "severity": "high",
     "regex": re.compile(r'(?i)(DefaultEndpointsProtocol|AccountKey|SharedAccessSignature)=[^\s;]+')},
    {"name": "Azure AD Client Secret", "severity": "high",
     "regex": re.compile(r'(?i)azure[^\'"\n]{0,20}(client_secret|secret)[^\'"\n]{0,5}[\'"][a-zA-Z0-9~._-]{34,}[\'"]')},

    # --- High: AI Provider Keys ---
    {"name": "OpenAI API Key", "severity": "high",
     "regex": re.compile(r'sk-[a-zA-Z0-9]{20,}')},
    {"name": "Anthropic API Key", "severity": "high",
     "regex": re.compile(r'sk-ant-[a-zA-Z0-9]{20,}')},

    # --- High: Payment & Communication ---
    {"name": "Stripe API Key", "severity": "high",
     "regex": re.compile(r'(sk_live_|pk_live_|rk_live_)[0-9a-zA-Z]{24,}')},
    {"name": "Slack Token", "severity": "high",
     "regex": re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})')},
    {"name": "Slack Webhook URL", "severity": "high",
     "regex": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+')},
    {"name": "Twilio Account SID", "severity": "high",
     "regex": re.compile(r'AC[0-9a-f]{32}')},
    {"name": "Twilio Auth Token", "severity": "high",
     "regex": re.compile(r'(?i)twilio[^\'"\n]{0,20}(auth_token|token)[^\'"\n]{0,5}[\'"][0-9a-f]{32}[\'"]')},
    {"name": "SendGrid API Key", "severity": "high",
     "regex": re.compile(r'SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}')},
    {"name": "Mailgun API Key", "severity": "high",
     "regex": re.compile(r'key-[0-9a-zA-Z]{32}')},

    # --- High: Version Control & CI ---
    {"name": "GitHub Personal Access Token", "severity": "high",
     "regex": re.compile(r'ghp_[0-9a-zA-Z]{36}')},
    {"name": "GitHub OAuth Access Token", "severity": "high",
     "regex": re.compile(r'gho_[0-9a-zA-Z]{36}')},
    {"name": "GitHub App Token", "severity": "high",
     "regex": re.compile(r'(ghu|ghs)_[0-9a-zA-Z]{36}')},
    {"name": "GitLab Token", "severity": "high",
     "regex": re.compile(r'glpat-[0-9a-zA-Z_-]{20}')},

    # --- High: Infrastructure ---
    {"name": "Cloudflare API Token", "severity": "high",
     "regex": re.compile(r'(?i)cloudflare[^\'"\n]{0,20}[\'"][a-zA-Z0-9_-]{40}[\'"]')},
    {"name": "DigitalOcean Token", "severity": "high",
     "regex": re.compile(r'dop_v1_[a-f0-9]{64}')},
    {"name": "Heroku API Key", "severity": "high",
     "regex": re.compile(r'(?i)heroku[^\'"\n]{0,20}[\'"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\'"]')},
    {"name": "Firebase API Key", "severity": "high",
     "regex": re.compile(r'(?i)firebase.{0,20}AIza[0-9A-Za-z-_]{35}')},
    {"name": "NPM Token", "severity": "high",
     "regex": re.compile(r'npm_[a-zA-Z0-9]{36}')},
    {"name": "PyPI Token", "severity": "high",
     "regex": re.compile(r'pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}')},

    # --- High: Database ---
    {"name": "PostgreSQL Connection URI", "severity": "high",
     "regex": re.compile(r'postgres(ql)?://[^/\s]+:[^/\s]+@[^/\s]+')},
    {"name": "MySQL Connection URI", "severity": "high",
     "regex": re.compile(r'mysql://[^/\s]+:[^/\s]+@[^/\s]+')},
    {"name": "MongoDB Connection URI", "severity": "high",
     "regex": re.compile(r'mongodb(\+srv)?://[^/\s]+:[^/\s]+@[^/\s]+')},
    {"name": "Redis Connection URI", "severity": "high",
     "regex": re.compile(r'redis://[^/\s]+:[^/\s]+@[^/\s]+')},

    # --- High: Secret Manager Tokens ---
    {"name": "1Password Connect Token (OP_CONNECT_TOKEN)", "severity": "critical",
     "regex": re.compile(r'OP_CONNECT_TOKEN\s*=\s*[\'"]?[a-zA-Z0-9_\-]{20,}')},
    {"name": "1Password Service Account Token", "severity": "critical",
     "regex": re.compile(r'ops_[a-zA-Z0-9+/=_\-]{50,}')},
    {"name": "HashiCorp Vault Token", "severity": "critical",
     "regex": re.compile(r'hvs\.[a-zA-Z0-9_\-]{24,}')},

    # --- High: Framework Exposed Secrets (browser bundle leaks) ---
    {"name": "Framework Exposed Secret: NEXT_PUBLIC_", "severity": "high",
     "regex": re.compile(r'NEXT_PUBLIC_[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD|API_KEY|PRIVATE|AUTH)[A-Z_]*\s*=\s*[\'"][^\'"]{8,}[\'"]')},
    {"name": "Framework Exposed Secret: REACT_APP_", "severity": "high",
     "regex": re.compile(r'REACT_APP_[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD|API_KEY|PRIVATE|AUTH)[A-Z_]*\s*=\s*[\'"][^\'"]{8,}[\'"]')},
    {"name": "Framework Exposed Secret: VITE_", "severity": "high",
     "regex": re.compile(r'VITE_[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD|API_KEY|PRIVATE|AUTH)[A-Z_]*\s*=\s*[\'"][^\'"]{8,}[\'"]')},
    {"name": "Framework Exposed Secret: EXPO_PUBLIC_", "severity": "high",
     "regex": re.compile(r'EXPO_PUBLIC_[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD|API_KEY|PRIVATE|AUTH)[A-Z_]*\s*=\s*[\'"][^\'"]{8,}[\'"]')},
    {"name": "Framework Exposed Secret: GATSBY_", "severity": "high",
     "regex": re.compile(r'GATSBY_[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD|API_KEY|PRIVATE|AUTH)[A-Z_]*\s*=\s*[\'"][^\'"]{8,}[\'"]')},
    {"name": "Framework Exposed Secret: NX_PUBLIC_", "severity": "high",
     "regex": re.compile(r'NX_PUBLIC_[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD|API_KEY|PRIVATE|AUTH)[A-Z_]*\s*=\s*[\'"][^\'"]{8,}[\'"]')},

    # --- High: Auth Tokens ---
    {"name": "JWT Token", "severity": "high",
     "regex": re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')},
    {"name": "Bearer Token", "severity": "high",
     "regex": re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}')},

    # --- Medium: Generic Assignments ---
    {"name": "Generic Secret Assignment", "severity": "medium",
     "regex": re.compile(r'(?i)(api_key|apikey|secret|token|password|auth_token|access_key|private_key)[^\'"\n=]{0,20}=\s*[\'"][0-9a-zA-Z\-_/+]{16,}[\'"]')},
    {"name": "URI with Embedded Password", "severity": "medium",
     "regex": re.compile(r'(?i)[a-z]+://[^/\s:]+:[^/\s@]+@[^/\s]+')},
    {"name": "Generic Password in Config", "severity": "medium",
     "regex": re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]')},

    # --- Low: Potential but noisy ---
    {"name": "Hardcoded IP Address", "severity": "low",
     "regex": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')},
]


def scan_file(file_path, rel_path):
    findings = []

    basename = os.path.basename(file_path)
    if basename in ENV_FILE_VARIANTS and basename not in ENV_FILE_SAFE:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="high",
            title=f"Unencrypted {basename} File in Repository",
            description=f"{basename} likely contains plaintext secrets and should be in .gitignore",
            file=rel_path, line=0,
            snippet=f"{basename} found in repo (should never be committed)",
            category="secret-storage"
        ))

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            # Skip mega-lines to prevent O(n^2) regex backtracking
            if len(line) > core.MAX_LINE_LENGTH:
                continue

            for pattern in PATTERNS:
                match = pattern['regex'].search(line)
                if match:
                    snippet = match.group(0)
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."

                    findings.append(core.Finding(
                        scanner=SCANNER_NAME,
                        severity=pattern['severity'],
                        title=pattern['name'],
                        description=f"Potential hardcoded secret detected",
                        file=rel_path,
                        line=i + 1,
                        snippet=snippet,
                        category="secret"
                    ))
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Secret Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning for secrets in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    if ignore_patterns:
        core.emit_status(args.format, f"[*] Loaded {len(ignore_patterns)} custom ignore patterns from .forensicsignore")

    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
