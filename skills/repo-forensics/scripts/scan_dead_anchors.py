#!/usr/bin/env python3
"""
scan_dead_anchors.py - Dead-Anchor / Repojacking Scanner (Skilljacking gap).

Extracts every external anchor a skill/repo points at (GitHub owner/repo, prose
package-install target, bare domain, free-tier cloud subdomain) and checks
whether that anchor is currently CLAIMABLE BY AN ATTACKER — the structural gap
AIR's Skilljacking research says "tripped nothing at all" in every existing
scanner, because the file content never changes; only the world behind the
anchor does.

Three-tier signal partition (mirrors scan_provenance.py exactly, renamed):
  CONFIRMED-CLAIMABLE (CC)  -> emits a Finding (severity per the DA table).
  LIVE-AND-OWNED      (LO)  -> SILENT (the normal state of the world).
  COULDN'T-CHECK      (NC)  -> SILENT (rate-limited / offline / over-budget).

Never-hard-fail: every failure degrades to silence. Never raises, never a false
CRITICAL, never a non-zero exit from an internal error. `--offline` degrades
every anchor to NC instantly (sub-second, zero sockets).

Anchor extraction (dead_anchors_extract) and claimability probes
(dead_anchors_probe) do the work; this module is the 3-tier classifier + Finding
emitter, plus DA-09 (free-tier suffix) and DA-10 (GitHub-owner trust) bundled in
at zero extra network cost.

Zero non-stdlib deps: stdlib + forensics_core / vuln_feed / rule_loader only.

Created by Alex Greenshpun
"""

import os
import sys
import json

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import forensics_core as core
import dead_anchors_extract as extract
import dead_anchors_probe as probe

SCANNER_NAME = "dead_anchors"

_PACK_PATH = os.path.normpath(
    os.path.join(_SCRIPTS_DIR, "..", "data", "rulepacks", "dead_anchors.json")
)


def _load_fingerprints():
    """Read the provider fingerprint map straight from the pack file (structured
    data no rule_loader type models). Tolerant: any error => empty map."""
    try:
        with open(_PACK_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}  # a valid-JSON but non-dict pack (e.g. a list) is not a crash
        fp = data.get("fingerprints")
        if isinstance(fp, dict):
            return {k: v for k, v in fp.items() if not k.startswith("_")}
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    return {}


def _snippet(anchor):
    raw = (anchor.raw or "").strip()
    return raw[:120]


def scan_repo(repo_path, ignore_patterns=None, offline=False):
    """Extract anchors, probe claimability, emit a Finding only on CC.

    ignore_patterns is accepted for uniform registration but unused (this is an
    anchor-level check, not a per-file walk). One shared probe context per call
    holds the deadline / budget / breaker / cache — all local, never module
    globals (spec §10 no-shared-state)."""
    findings = []
    del ignore_patterns  # accepted for registration uniformity, unused

    try:
        anchors = extract.extract_anchors(repo_path)
    except Exception:
        return findings  # never-hard-fail: extraction problem => nothing to probe
    if not anchors:
        return findings

    # ProbeContext construction (cache-dir resolution) and pack loading sit
    # between the two already-guarded blocks; wrap them too so no environmental
    # or malformed-pack failure can escape as a non-zero exit (error-soundness
    # F1, python-redos F4).
    try:
        ctx = probe.ProbeContext(offline=offline)
        fingerprints = _load_fingerprints()
    except Exception:
        return findings

    owner_verdicts = {}   # owner -> (verdict, meta)  memo (dedup owner probes)
    emitted_da01 = set()  # owners already reported claimable
    probed = 0
    skipped = 0

    for a in anchors:
        try:
            emitted, ok = _handle_anchor(
                a, ctx, fingerprints, findings, owner_verdicts, emitted_da01)
        except Exception:
            # A single anchor blowing up must never sink the scan.
            skipped += 1
            continue
        if ok:
            probed += 1
        else:
            skipped += 1

    # Optional operator-only summary (text format only; NEVER a Finding, never
    # counted toward severity/exit-code). See KTD-4.
    scan_repo._last_summary = (probed, skipped, len(anchors))
    return findings


scan_repo._last_summary = (0, 0, 0)


def _handle_anchor(a, ctx, fingerprints, findings, owner_verdicts, emitted_da01):
    """Probe one anchor and append any Finding. Returns (emitted, checked) where
    `checked` is False when the verdict was NC (couldn't-check / skipped)."""
    if a.type == "github":
        return _handle_github(a, ctx, findings, owner_verdicts, emitted_da01)
    if a.type == "package":
        verdict, _meta = (
            probe.probe_npm(a.target.split(":", 1)[1], ctx)
            if a.ecosystem == "npm" else
            probe.probe_pypi(a.target.split(":", 1)[1], ctx)
        )
        if verdict == "CC":
            name = a.target.split(":", 1)[1]
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=f"Phantom / claimable {a.ecosystem} package: {name}",
                description=(
                    f"A prose install command references the {a.ecosystem} "
                    f"package '{name}', but the registry returns 404 — it was "
                    "never published or has been removed, so an attacker can "
                    "register that exact name and every follower of this skill "
                    "installs their code (phantom-package / dependency-confusion)."
                ),
                file=a.file, line=a.line, snippet=_snippet(a),
                category="dead-anchor", rule_id="", confidence=0.90,
            ))
            return True, True
        return False, verdict != "NC"
    if a.type == "domain":
        verdict, extra = probe.probe_domain_rdap(a.target, ctx)
        if verdict == "CC":
            is_target = bool(a.fetch_context)
            findings.append(core.Finding(
                scanner=SCANNER_NAME,
                severity="critical" if is_target else "high",
                title=f"Unregistered / expired domain anchor: {a.target}",
                description=(
                    f"The domain '{a.target}' referenced here is not registered "
                    "(RDAP 404) — it is expired or was never registered, so an "
                    "attacker can register it and control whatever this skill "
                    + ("fetches/installs from it."
                       if is_target else "links to it.")
                ),
                file=a.file, line=a.line, snippet=_snippet(a),
                category="dead-anchor", rule_id="", confidence=0.85,
            ))
            return True, True
        return False, verdict != "NC"
    if a.type == "cloud":
        verdict, extra = probe.probe_cloud_subdomain(
            a.target, a.suffix, ctx, fingerprints=fingerprints)
        if verdict == "CC":
            reason = (extra or {}).get("reason")
            if reason == "nxdomain":
                conf = 0.90
                how = "no longer resolves (NXDOMAIN)"
            else:
                conf = float((extra or {}).get("confidence", 0.80))
                how = "returns a provider 'deleted app' page"
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=f"Dangling cloud subdomain: {a.target}",
                description=(
                    f"'{a.target}' is on the free-tier host '{a.suffix}' and "
                    f"{how}: the app/project was deleted, so the slug is "
                    "reclaimable — an attacker re-deploys under the same URL "
                    "the skill points at. Free-tier suffixes are trivially "
                    "re-registrable (DA-09)."
                ),
                file=a.file, line=a.line, snippet=_snippet(a),
                category="dead-anchor", rule_id="", confidence=conf,
            ))
            return True, True
        return False, verdict != "NC"
    return False, False


def _handle_github(a, ctx, findings, owner_verdicts, emitted_da01):
    owner, repo = a.owner, a.repo
    # GitHub identity is case-insensitive: memoize the owner verdict and the
    # emitted-finding set on the lowercased owner so case variants dedup to one
    # probe and one CRITICAL (code-review F3).
    okey = (owner or "").lower()
    if okey in owner_verdicts:
        overdict, ometa = owner_verdicts[okey]
    else:
        overdict, ometa = probe.probe_github_user(owner, ctx)
        owner_verdicts[okey] = (overdict, ometa)

    if overdict == "CC":
        # DA-01: the whole owner/org is re-registerable. One finding per owner.
        if okey not in emitted_da01:
            emitted_da01.add(okey)
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=f"Claimable GitHub owner: {owner}",
                description=(
                    f"The GitHub user/org '{owner}' referenced here returns 404 "
                    "(api.github.com/users) — deleted or renamed, so the "
                    "username is re-registerable. An attacker who claims it "
                    f"controls every '{owner}/*' repo this skill points at "
                    "(repojacking)."
                ),
                file=a.file, line=a.line, snippet=_snippet(a),
                category="dead-anchor", rule_id="", confidence=0.90,
            ))
            return True, True
        return False, True

    if overdict == "LO":
        # DA-02: owner lives, but the specific repo may be gone (weaker signal).
        rverdict, _rmeta = probe.probe_github_repo(owner, repo, ctx)
        if rverdict == "CC":
            desc = (
                f"The repo '{owner}/{repo}' returns 404 while the owner "
                f"'{owner}' is live — renamed, deleted, or made private. If it "
                "was renamed/deleted the name can be re-created under the same "
                "owner and mis-point followers of this skill (weaker signal: "
                "could also be a legitimately private/moved repo)."
            )
            trust = _owner_trust_note(ometa)
            if trust:
                desc += " " + trust
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="medium",
                title=f"Claimable GitHub repo under live owner: {owner}/{repo}",
                description=desc,
                file=a.file, line=a.line, snippet=_snippet(a),
                category="dead-anchor", rule_id="", confidence=0.55,
            ))
            return True, True
        return False, rverdict != "NC"

    return False, False  # owner NC => couldn't check


def _owner_trust_note(meta):
    """DA-10: enrich (never a standalone finding) when the live owner looks
    low-trust: recent account + few repos + empty bio."""
    if not isinstance(meta, dict):
        return ""
    created = meta.get("created_at")
    repos = meta.get("public_repos")
    bio = meta.get("bio")
    signals = []
    ts = probe._parse_iso8601(created) if created else None
    if ts is not None:
        import time as _t
        age_days = (_t.time() - ts) / 86400.0
        if age_days < 365:
            signals.append(f"account < 1yr old (~{int(age_days)}d)")
    if isinstance(repos, int) and not isinstance(repos, bool) and repos <= 2:
        signals.append(f"only {repos} public repos")
    if bio in (None, "", False):
        signals.append("empty bio")
    if len(signals) >= 2:
        return "Owner trust signals: " + ", ".join(signals) + "."
    return ""


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="repo-forensics: dead_anchors (repojacking / phantom "
                    "package / expired domain / dangling cloud subdomain)")
    parser.add_argument("repo_path", help="Path to repository to scan")
    parser.add_argument("--format", choices=["text", "json", "summary"],
                        default="text", help="Output format (default: text)")
    parser.add_argument("--offline", action="store_true",
                        help="No network: every anchor degrades to couldn't-check "
                             "(silent), zero sockets opened")
    args = parser.parse_args(sys.argv[1:])
    repo_path = os.path.abspath(args.repo_path)

    core.emit_status(args.format,
                     f"[*] Checking external anchor claimability for {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = scan_repo(repo_path, ignore_patterns, offline=args.offline)
    core.output_findings(all_findings, args.format, SCANNER_NAME)

    if args.format == "text":
        probed, skipped, total = scan_repo._last_summary
        if total:
            note = f"[i] dead_anchors: {total} anchors, {probed} checked"
            if skipped:
                note += f", {skipped} skipped (rate-limited/offline/over-budget)"
            print(note, file=sys.stderr)


if __name__ == "__main__":
    main()
