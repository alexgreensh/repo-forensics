#!/usr/bin/env python3
"""
sync_badges.py - keep the README badges and diagram counts honest, automatically.

The README "scanners" and "tests" badges, the prose counts, and the numbers
embedded in the hero/pipeline diagrams used to be hand-maintained and drifted on
every release (v2.11.0 shipped with "20 scanners / 1,551 tests" still showing).
This script computes the real numbers from the source of truth and writes them
everywhere they appear, so a stale count is impossible.

Sources of truth:
  - scanners: number of `scan_*.py` files that declare a `SCANNER_NAME` (the
    canonical scanner marker).
  - tests:    pytest collected-test count.
  - version:  the root .claude-plugin/plugin.json `version`.

Outputs (idempotent — running twice changes nothing):
  - .github/badges/metrics.json  (read live by the README's dynamic shields)
  - README.md prose counts + the "The N Scanners" heading / "Show all N" summary
  - diagrams/hero.svg, scan-verdict.svg, attack-flow.svg scanner counts

Run locally any time, and from CI on every push (see .github/workflows/sync-badges.yml).
Pure standard library; no third-party deps (the repo's zero-dependency promise).

Usage:  python3 scripts/sync_badges.py [--check]
        --check exits non-zero if anything is out of date (for CI verification).
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "repo-forensics")
SCRIPTS = os.path.join(SKILL, "scripts")
METRICS = os.path.join(ROOT, ".github", "badges", "metrics.json")


def count_scanners():
    n = 0
    for fn in os.listdir(SCRIPTS):
        if fn.startswith("scan_") and fn.endswith(".py"):
            with open(os.path.join(SCRIPTS, fn), encoding="utf-8") as f:
                if re.search(r"^SCANNER_NAME\s*=", f.read(), re.M):
                    n += 1
    return n


def count_tests():
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
        cwd=SKILL, capture_output=True, text=True,
    ).stdout
    m = re.search(r"(\d+)\s+tests? collected", out)
    if m:
        return int(m.group(1))
    # Fallback: count "::" test-node lines.
    return sum(1 for line in out.splitlines() if "::" in line)


def read_version():
    with open(os.path.join(ROOT, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
        return json.load(f).get("version", "0.0.0")


def _grp(n):
    """Group an int with thousands commas: 1631 -> '1,631'."""
    return f"{n:,}"


def update_readme(text, scanners, tests):
    s = _grp(scanners)  # scanners rarely cross 1000 but be consistent
    t = _grp(tests)
    subs = [
        # static badges (in case the dynamic endpoint is ever reverted)
        (r"(badge/scanners-)\d+(-)", rf"\g<1>{scanners}\g<2>"),
        (r'(alt="N?)\d+( Scanners")', rf"\g<1>{scanners}\g<2>"),
        (r"(badge/tests-)[0-9%C,]+(-)", rf"\g<1>{t.replace(',', '%2C')}\g<2>"),
        (r'(alt=")[\d,]+( Tests")', rf"\g<1>{t}\g<2>"),
        # prose + headings
        (r"(## The )\d+( Scanners)", rf"\g<1>{scanners}\g<2>"),
        (r"(Show all )\d+( scanners)", rf"\g<1>{scanners}\g<2>"),
        (r"\b\d+(-scanner attack surface)", rf"{scanners}\g<1>"),
        (r"(input to )\d+( scanners)", rf"\g<1>{scanners}\g<2>"),
        (r"\b\d+( scanners, runtime behavior)", rf"{scanners}\g<1>"),
        (r"\b\d+( scanners run in parallel)", rf"{scanners}\g<1>"),
        (r"(repo-forensics:\*\* )\d+( scanners)", rf"\g<1>{scanners}\g<2>"),
        (r"[\d,]+( tests across 40)", rf"{t}\g<1>"),
        (r"(All )[\d,]+( tests use synthetic)", rf"\g<1>{t}\g<2>"),
        (r"\*\*[\d,]+( pytest tests)\*\*", rf"**{t}\g<1>**"),
    ]
    for pat, rep in subs:
        text = re.sub(pat, rep, text)
    return text


def update_svgs(scanners):
    changed = []
    targets = {
        "hero.svg": [(r"\b\d+( scanners)", rf"{scanners}\g<1>")],
        "scan-verdict.svg": [(r"(Running all )\d+( scanners)", rf"\g<1>{scanners}\g<2>")],
        "attack-flow.svg": [(r"(across all )\d+( scanners)", rf"\g<1>{scanners}\g<2>")],
    }
    for fn, pats in targets.items():
        path = os.path.join(ROOT, "diagrams", fn)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            orig = f.read()
        new = orig
        for pat, rep in pats:
            new = re.sub(pat, rep, new)
        if new != orig:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new)
            changed.append(fn)
    return changed


def main():
    check = "--check" in sys.argv
    scanners, tests, version = count_scanners(), count_tests(), read_version()
    # Flat keys so the README's shields.io dynamic/json badges can query
    # $.scanners / $.tests / $.version directly.
    metrics = {
        "scanners": str(scanners),
        "tests": _grp(tests),
        "version": version,
    }
    dirty = []

    os.makedirs(os.path.dirname(METRICS), exist_ok=True)
    new_metrics = json.dumps(metrics, indent=2) + "\n"
    old_metrics = open(METRICS, encoding="utf-8").read() if os.path.exists(METRICS) else ""
    if new_metrics != old_metrics:
        dirty.append(".github/badges/metrics.json")
        if not check:
            open(METRICS, "w", encoding="utf-8").write(new_metrics)

    readme_path = os.path.join(ROOT, "README.md")
    old_readme = open(readme_path, encoding="utf-8").read()
    new_readme = update_readme(old_readme, scanners, tests)
    if new_readme != old_readme:
        dirty.append("README.md")
        if not check:
            open(readme_path, "w", encoding="utf-8").write(new_readme)

    if check:
        # In check mode SVGs are reported but not written.
        for fn in ("hero.svg", "scan-verdict.svg", "attack-flow.svg"):
            path = os.path.join(ROOT, "diagrams", fn)
            if os.path.exists(path) and re.search(r"\b\d+ scanners", open(path, encoding="utf-8").read()):
                cur = re.search(r"(\d+) scanners", open(path, encoding="utf-8").read())
                if cur and cur.group(1) != str(scanners):
                    dirty.append(f"diagrams/{fn}")
    else:
        dirty += [f"diagrams/{c}" for c in update_svgs(scanners)]

    print(f"scanners={scanners} tests={_grp(tests)} version={version}")
    if dirty:
        print(("OUT OF DATE: " if check else "updated: ") + ", ".join(sorted(set(dirty))))
        if check:
            sys.exit(1)
    else:
        print("all badge surfaces current")


if __name__ == "__main__":
    main()
