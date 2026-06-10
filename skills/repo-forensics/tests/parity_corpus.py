"""Shared parity corpus builder for the pack-extraction parity gate (U3+).

The parity gate proves that a scanner driven by a JSON rule pack produces
byte-identical findings (on the parity key) to the scanner that used to carry
hardcoded constants. To exercise that, it needs a corpus that triggers every
rule. Synthetic fixtures alone under-cover the long tail, so the corpus is
assembled from two deterministic sources:

  1. Every shipped rule pack's embedded `examples` (match + no_match), written
     into a file whose extension matches the rule's gate (so extension-gated
     SAST rules actually fire). This guarantees per-rule coverage that tracks
     the packs automatically as U4/U5 add more.
  2. The conftest fixture bodies that historically exercised these scanners
     (real-world-shaped multi-line inputs), so the parity check also covers
     line-numbering and multi-pattern-per-file interactions.

The builder is pure-stdlib and writes only inside the directory it is given.
U4/U5 extend the PACK_EXTS map and (optionally) FIXTURE_FILES; the parity
harness itself stays generic.
"""

import os

# Pack name -> the file extension its example files should be written under.
# secrets is extension-agnostic (scans every text file) so its examples go into
# a neutral .txt file; sast rules are per-extension so each rule's examples are
# written under that rule's own gated extension (see build_corpus).
PACK_EXTS = {
    "secrets": ".txt",
    "sast": None,  # per-rule extension comes from rule.extensions
    # U4 packs. skill_threats and mcp_security regex rules are mostly
    # extension-agnostic at the rule level (the scanner gates by ext at the
    # call site), so their example files land in extensions the scanner
    # actually scans. We write skill_threats examples into a code-and-text mix
    # via .md (broadest skill_threats gate) and mcp_security into .py (its
    # primary code gate). shared keyword examples go into .md.
    "skill_threats": ".md",
    "mcp_security": ".py",
    "shared": ".md",
    # U5 packs. runtime_dynamism gates on code extensions; .py exercises both its
    # regex tables and (incidentally) the AST visitor, but the AST path is code
    # and out of the pack's scope — the parity key still matches because the
    # golden was captured from the same scan_file over the same corpus.
    "runtime_dynamism": ".py",
}


# Conftest-style fixture bodies that historically drove these two scanners.
# Kept verbatim so the parity gate covers real multi-line inputs, not just the
# one-liner examples. (Filename -> content.)
FIXTURE_FILES = {
    "config_secrets.py": (
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        "OPENAI_KEY = 'sk-proj-1234567890abcdef'\n"
        "STRIPE_KEY = 'sk_live_abcdef1234567890'\n"
        "DB_URL = 'postgresql://user:p@ssword@localhost/db'\n"
    ),
    "framework_env.local": (
        "NEXT_PUBLIC_SECRET_KEY='sk-live-abc123def456ghi789jkl012'\n"
        "REACT_APP_API_SECRET='supersecretapikey12345678'\n"
        "VITE_AUTH_TOKEN='vt_live_abcdefghijklmnop'\n"
        "EXPO_PUBLIC_PRIVATE_KEY='expo_pk_1234567890abcdef'\n"
        "GATSBY_SECRET_KEY='gatsby_sk_abcdefghijklmno'\n"
        "NX_PUBLIC_API_KEY='nx_key_1234567890abcdef'\n"
        "NEXT_PUBLIC_ANALYTICS_ID='UA-12345'\n"
    ),
    "onepassword.sh": (
        "export OP_CONNECT_TOKEN=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9abcdefghij\n"
        "export OP_CONNECT_HOST=https://connect.1password.internal\n"
    ),
    "sql_injection.py": (
        "import sqlite3\n"
        "def query(user_input):\n"
        "    cursor.execute('SELECT * FROM users WHERE name=' + user_input)\n"
        "    cursor.execute(f'INSERT INTO data VALUES({user_input})')\n"
    ),
    "obfuscation.py": (
        "import base64, codecs\n"
        "exec(base64.b64decode('cHJpbnQoImhlbGxvIik='))\n"
        "getattr(__import__('os'), 'system')('whoami')\n"
    ),
    "clean_main.py": (
        "def hello():\n"
        "    print('Hello, world!')\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    hello()\n"
    ),
    "clean_readme.md": "# Clean Project\nThis is a safe project.\n",
}


def _load_pack(name):
    """Load a shipped pack via the real loader (install-dir resolution)."""
    import rule_loader
    return rule_loader.load_pack(name)


# Per-pack filename prefix. mcp_security gates many categories behind
# is_mcp_related() (basename contains mcp/server/tool/handler), so its example
# files need an mcp-flavored name to actually exercise those rules. skill_threats
# rules are gated only by extension, so a plain rule-id name is enough.
PACK_FNAME_PREFIX = {
    "mcp_security": "mcp_",
}


def build_corpus(root, pack_names=("secrets", "sast", "skill_threats",
                                   "mcp_security", "shared",
                                   "runtime_dynamism")):
    """Materialize the parity corpus under `root`.

    Returns the list of relative file paths written. Idempotent for a fresh
    `root`. Each rule's examples land in a file named for the rule id so the
    corpus is self-documenting and collisions are impossible.
    """
    written = []

    # 1. Pack example files.
    for pack_name in pack_names:
        pack = _load_pack(pack_name)
        if pack is None:
            continue
        default_ext = PACK_EXTS.get(pack_name, ".txt")
        prefix = PACK_FNAME_PREFIX.get(pack_name, "")
        for rule in pack.all_rules:
            # Pick the extension this rule is actually gated to (first one),
            # else the pack default. Extension-agnostic regex rules use default.
            if rule.extensions:
                ext = rule.extensions[0]
            else:
                ext = default_ext or ".txt"
            lines = []
            lines.extend(rule.examples.get("match", []))
            lines.extend(rule.examples.get("no_match", []))
            if not lines:
                continue
            fname = f"{prefix}{rule.id}{ext}"
            path = os.path.join(root, fname)
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            written.append(fname)

    # 2. Fixture bodies.
    for fname, content in FIXTURE_FILES.items():
        path = os.path.join(root, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        written.append(fname)

    return written
