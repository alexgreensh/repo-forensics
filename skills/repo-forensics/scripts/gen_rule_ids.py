#!/usr/bin/env python3
"""
gen_rule_ids.py - Dev helper: mint canonical rule ids for the extraction work.

The U3/U4/U5 extraction units move ~500 hardcoded patterns into JSON rule packs.
Those run in parallel, so they need a single collision-free id namespace agreed
up front. This script reads the existing scanner source with `ast` (no imports,
no execution of scanner code), finds the module-level pattern TABLES (lists /
dicts whose names look like `*_PATTERNS`, `*_KEYWORDS`, `HOMOGLYPHS`, etc.),
counts the entries in each, and emits a canonical

    <SCANNER>-<CATEGORY>-<NNN>

id map to a committed CSV. Extractors (U3-U5) assign ids straight from this CSV,
so two parallel branches never collide and the parity harness can assert every
pack-driven finding carries a non-empty rule_id.

Pure stdlib, dependency-free, side-effect-free (it never imports the scanners —
it parses them as text via ast, so a hostile pattern table can't run).

Usage:
    python3 gen_rule_ids.py                 # writes data/rule_ids.csv
    python3 gen_rule_ids.py --out path.csv  # custom output
    python3 gen_rule_ids.py --print         # stdout only, no file write

CSV columns:
    rule_id, scanner, category, source_file, table_name, index, severity_hint

`index` is the 0-based position of the entry inside its source table, so an
extractor can map "the 3rd item of PROMPT_INJECTION_PATTERNS" to its id
deterministically.
"""

import os
import sys
import ast
import csv

_SCRIPTS_DIR = os.path.dirname(os.path.realpath(__file__))
_DATA_DIR = os.path.normpath(os.path.join(_SCRIPTS_DIR, "..", "data"))
_DEFAULT_OUT = os.path.join(_DATA_DIR, "rule_ids.csv")

# Per-scanner file -> abbreviation used in rule ids. Mirrors the
# <SCANNER> half of the id convention (e.g. ST = skill_threats).
_SCANNER_ABBREV = {
    "scan_secrets.py": "SC",
    "scan_sast.py": "SA",
    "scan_skill_threats.py": "ST",
    "scan_mcp_security.py": "MC",
    "scan_agent_skills.py": "AS",
    "scan_runtime_dynamism.py": "RD",
    "scan_infra.py": "IN",
    "scan_lifecycle.py": "LC",
    "scan_dependencies.py": "DP",
    "scan_devcontainer.py": "DC",
    "_shared_patterns.py": "SH",
    # dead_anchors authors all its rule ids directly in
    # data/rulepacks/dead_anchors.json (no module-level *_PATTERNS tables to
    # scrape), so this abbrev emits ZERO rows in rule_ids.csv — registration for
    # completeness only. Expected, not a bug.
    "scan_dead_anchors.py": "DA",
}

# Table-name fragment -> CATEGORY abbreviation. First matching fragment wins.
# Extend as extraction proceeds; unknown tables fall back to "GEN".
_CATEGORY_RULES = [
    ("PROMPT_INJECTION", "PI"),
    ("INJECTION", "PI"),
    ("HOMOGLYPH", "HG"),
    ("EXFIL", "EX"),
    ("CREDENTIAL", "CR"),
    ("PERSISTENCE", "PE"),
    ("SCOPE", "SP"),
    ("STEALTH", "ST"),
    ("CLICKFIX", "CF"),
    ("PREREQUISITE", "PR"),
    ("TOOL_INJECTION", "TI"),
    ("SUB_AGENT", "SA"),
    ("AUTHORITY", "AU"),
    ("SAFETY_THEATER", "ST"),
    ("TRUST_ESCALATION", "TE"),
    ("UPDATE_CHANNEL", "UC"),
    ("RAT_BINARY", "RB"),
    ("MALICIOUS_AUTHOR", "MA"),
    ("SAST", "SAST"),
    ("PATTERNS", "GEN"),
    ("KEYWORDS", "KW"),
]

# Table names to ignore: IOC fallbacks (live-fed, not rules-as-data) and
# anything that is clearly not a behavioral-pattern table.
_SKIP_FRAGMENTS = ("_FALLBACK_", "_IPS", "_DOMAINS", "MAP")

# Table-name suffixes / shapes we treat as pattern tables.
_TABLE_SUFFIXES = ("_PATTERNS", "_KEYWORDS", "_PATHS")
_TABLE_EXACT = {"HOMOGLYPHS"}


def _category_for(table_name):
    for frag, abbrev in _CATEGORY_RULES:
        if frag in table_name:
            return abbrev
    return "GEN"


def _is_pattern_table(name):
    if any(skip in name for skip in _SKIP_FRAGMENTS):
        return False
    if name in _TABLE_EXACT:
        return True
    return any(name.endswith(suf) for suf in _TABLE_SUFFIXES)


def _count_entries(node):
    """Return the number of top-level entries in a List/Tuple/Dict/Set literal,
    or None if the value is not a simple collection literal."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return len(node.elts)
    if isinstance(node, ast.Dict):
        return len(node.keys)
    return None


def _severity_hint(node, index):
    """Best-effort severity extraction from a dict-shaped entry, else ''."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return ""
    if index >= len(node.elts):
        return ""
    elt = node.elts[index]
    if isinstance(elt, ast.Dict):
        for k, v in zip(elt.keys, elt.values):
            if isinstance(k, ast.Constant) and k.value == "severity" \
                    and isinstance(v, ast.Constant) and isinstance(v.value, str):
                return v.value
    return ""


def collect_tables(scripts_dir=None):
    """Parse every known scanner and yield (scanner_file, table_name, node).

    Reads source as text and parses with ast — never imports/executes it.
    """
    scripts_dir = scripts_dir or _SCRIPTS_DIR
    for fname in sorted(_SCANNER_ABBREV):
        path = os.path.join(scripts_dir, fname)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        try:
            tree = ast.parse(src, filename=path)
        except SyntaxError:
            print(f"[gen_rule_ids] skip (parse error): {fname}", file=sys.stderr)
            continue
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if not _is_pattern_table(target.id):
                    continue
                yield fname, target.id, node.value


def build_id_map(scripts_dir=None):
    """Build the full list of rule-id rows.

    Returns list[dict] with keys: rule_id, scanner, category, source_file,
    table_name, index, severity_hint. Sequence numbers (<NNN>) are assigned
    per (scanner, category) in stable file+table+index order.
    """
    rows = []
    seq = {}  # (scanner_abbrev, category) -> next int
    for fname, table_name, node in collect_tables(scripts_dir):
        count = _count_entries(node)
        if not count:
            continue
        scanner = _SCANNER_ABBREV[fname]
        category = _category_for(table_name)
        for i in range(count):
            key = (scanner, category)
            n = seq.get(key, 0) + 1
            seq[key] = n
            rule_id = f"{scanner}-{category}-{n:03d}"
            rows.append({
                "rule_id": rule_id,
                "scanner": scanner,
                "category": category,
                "source_file": fname,
                "table_name": table_name,
                "index": i,
                "severity_hint": _severity_hint(node, i),
            })
    return rows


_FIELDS = ["rule_id", "scanner", "category", "source_file",
           "table_name", "index", "severity_hint"]


def write_csv(rows, out_path):
    """Write rows to CSV at out_path (creates parent dir if needed)."""
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    out = _DEFAULT_OUT
    print_only = False
    i = 0
    while i < len(argv):
        if argv[i] == "--out" and i + 1 < len(argv):
            out = argv[i + 1]
            i += 2
        elif argv[i] == "--print":
            print_only = True
            i += 1
        else:
            print(f"[gen_rule_ids] unknown arg: {argv[i]}", file=sys.stderr)
            return 2
    rows = build_id_map()
    if print_only:
        w = csv.DictWriter(sys.stdout, fieldnames=_FIELDS)
        w.writeheader()
        w.writerows(rows)
    else:
        write_csv(rows, out)
        print(f"[gen_rule_ids] wrote {len(rows)} rule ids -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
