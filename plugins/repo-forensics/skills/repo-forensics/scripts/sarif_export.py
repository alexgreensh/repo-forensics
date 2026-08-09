#!/usr/bin/env python3
"""sarif_export.py - SARIF 2.1.0 converter for repo-forensics reports.

Converts the aggregated report dict produced by aggregate_json.build_report()
into a SARIF 2.1.0 document (GitHub code-scanning compatible). Additive and
pure-stdlib: the text/json/summary paths never import this module.
aggregate_json imports it lazily inside the --sarif branch only, so the
rule_loader dependency (used to build the rule-descriptor index) stays out of
the text/json paths and honors the KTD-14 leaf rule (rule_loader is a leaf;
this module is the only aggregator-side importer of it, and rule_loader never
imports this module).

Mapping spec: see design doc §1.2-1.4.
"""

import hashlib
import json
import os
import re
import urllib.parse
from pathlib import Path

# Resolved from the plugin manifests at import time so the SARIF tool version
# can never drift from the release version again (it went stale at 2.15.0 and
# 2.16.0 while hardcoded). The manifests sit three levels above this file in
# both the source checkout and installed plugin layouts. The literal fallback
# keeps standalone use (skill copied without manifests) working; it is pinned
# to .claude-plugin/plugin.json by test_sarif_export.
def _resolve_tool_version():
    root = Path(__file__).resolve().parents[3]
    for rel in (".claude-plugin/plugin.json", ".kimi-plugin/plugin.json",
                ".codex-plugin/plugin.json"):
        manifest = root / rel
        try:
            if manifest.is_file():
                version = json.loads(manifest.read_text(encoding="utf-8"))["version"]
                if version:
                    return version
        except (OSError, ValueError, KeyError):
            continue
    return "2.16.0"


TOOL_VERSION = _resolve_tool_version()

TOOL_NAME = "repo-forensics"
INFORMATION_URI = "https://github.com/alexgreensh/repo-forensics"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

# severity -> SARIF level (forensics_core.py:20 vocabulary + info/unknown).
# critical/high -> error, medium -> warning, low/info/unknown -> note.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Confidence -> GitHub precision (mirrors VERDICT_BLOCK_MIN/WARN_MIN in
# aggregate_json.py:28-30).
def _precision(confidence):
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        c = 0.0
    if c >= 0.92:
        return "high"
    if c >= 0.60:
        return "medium"
    return "low"


def _category_slug(category):
    slug = re.sub(r"[^a-z0-9]+", "-", (category or "general").lower()).strip("-")
    return slug or "general"


def _normalize_uri(file_path):
    r"""Normalize a relative path into a SARIF artifactLocation.uri.

    SARIF uris are relative to the SRCROOT uriBaseId: never absolute, never
    scheme-prefixed, and never containing a `..` segment that could escape
    SRCROOT.

    Platform handling (path-traversal & literal-backslash hardening):
      - Windows (os.sep == '\\'): the native separator is converted to `/`
        (SARIF requires forward slashes). Other backslashes are NOT treated
        as separators; they are percent-encoded as literal data (%5C).
      - POSIX (os.sep == '/'): a backslash is a literal filename character,
        never a separator. It is percent-encoded as %5C. Only the real `/`
        is kept as a path separator. (Previously the code rewrote `\`->`/`
        unconditionally, which on POSIX turned a literal backslash in a
        filename into a phantom directory separator and let `..\..\x`
        become a `..` traversal that escaped SRCROOT.)

    All URI-unsafe characters are percent-encoded per RFC 3986
    (urllib.parse.quote with safe='/') so spaces become %20, literal
    backslashes become %5C, etc., while real `/` separators are preserved.

    Traversal guard: after normalization, leading `../` segments are
    stripped and any remaining `..` segment forces a fallback to the bare
    basename. A leading `/` or scheme is also stripped. A location that
    cannot be safely expressed relative to SRCROOT falls back to the bare
    basename, never a `..` path."""
    if not isinstance(file_path, str):
        file_path = ""
    if not file_path:
        return ""
    path = file_path
    # Strip a leading scheme (defensive — never emit absolute URIs).
    if "://" in path:
        path = path.split("://", 1)[-1]
    # Windows: convert the native separator to `/`. POSIX: leave backslashes
    # as literal data (percent-encoded below as %5C, never a separator).
    if os.sep == "\\":
        path = path.replace("\\", "/")
    # Percent-encode URI-unsafe characters per RFC 3986; keep real `/`.
    norm = urllib.parse.quote(path, safe="/")
    # Strip a leading slash (absolute path) — URIs are repo-relative.
    norm = norm.lstrip("/")
    # Traversal guard: strip leading `../` segments so a repo-relative URI
    # can never climb out of SRCROOT.
    while norm.startswith("../"):
        norm = norm[3:]
    # If any `..` segment remains anywhere (e.g. `a/../../b`), fall back to
    # the bare basename so the URI stays within SRCROOT.
    segments = norm.split("/")
    if any(seg == ".." for seg in segments):
        base = segments[-1]
        norm = base if base and base != ".." else ""
    return norm


def _build_rule_index():
    """Build {rule_id: CompiledRule} across the seven shipped packs plus the
    YARA manifest's rule_meta. Lazy rule_loader import (leaf rule). Returns
    (pack_index, yara_index) where pack_index maps rule.id -> (rule, pack_name,
    pack_version) and yara_index maps YR-* id -> rule_meta dict."""
    pack_index = {}
    try:
        import rule_loader
    except ImportError:
        return pack_index, {}
    for name in ("secrets", "sast", "skill_threats", "mcp_security",
                 "runtime_dynamism", "dead_anchors", "shared"):
        try:
            pack = rule_loader.load_pack(name)
        except Exception:
            pack = None
        if pack is None:
            continue
        for rule in pack.all_rules:
            if rule.id:
                pack_index[rule.id] = (rule, pack.name, pack.pack_version)

    yara_index = {}
    try:
        manifest_path = os.path.normpath(os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "..", "data", "yara",
            "manifest.json"))
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = __import__("json").load(handle)
        rule_meta = manifest.get("rule_meta", {}) if isinstance(manifest, dict) else {}
        if isinstance(rule_meta, dict):
            for rule_name, meta in rule_meta.items():
                if isinstance(meta, dict) and meta.get("id"):
                    yara_index[meta["id"]] = meta
    except (OSError, ValueError, KeyError):
        pass
    return pack_index, yara_index


def _synthesize_rule_id(scanner, category):
    """Synthesized descriptor id for findings with no pack rule_id.
    rf/<scanner>/<category-slug>; correlation -> rf/correlation/<slug>;
    meta -> rf/meta/<slug>. Category strings are code constants, so these ids
    are stable across runs even when titles are reworded."""
    return "rf/{}/{}".format(scanner or "general", _category_slug(category))


def _rule_descriptor(rule_id, finding, pack_index, yara_index):
    """Build one reportingDescriptor entry for `rule_id` using the first-seen
    `finding` for synthesized descriptors."""
    pack_entry = pack_index.get(rule_id)
    yara_meta = yara_index.get(rule_id)

    if pack_entry is not None:
        rule, pack_name, pack_version = pack_entry
        props = {
            "category": rule.category,
            "confidence": rule.confidence,
            "pack": pack_name,
            "packVersion": pack_version,
            "precision": _precision(rule.confidence),
            "tags": [rule.category] if rule.category else [],
        }
        threat = {}
        if rule.attacker or rule.boundary or rule.asset:
            threat = {
                "attacker": rule.attacker or "",
                "boundary": rule.boundary or "",
                "asset": rule.asset or "",
            }
        if threat:
            props["threatModel"] = threat
        desc = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": rule.title or rule_id},
            "fullDescription": {"text": rule.explanation or rule.title or rule_id},
            "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL.get(rule.severity, "note")},
            "properties": props,
        }
        return desc

    if yara_meta is not None:
        props = {
            "category": yara_meta.get("category", ""),
            "confidence": yara_meta.get("confidence", 0.0),
            "pack": "yara",
            "packVersion": 1,
            "precision": _precision(yara_meta.get("confidence", 0.0)),
            "tags": [yara_meta.get("category", "")] if yara_meta.get("category") else [],
        }
        threat = {}
        for key in ("attacker", "boundary", "asset"):
            if yara_meta.get(key):
                threat[key] = yara_meta[key]
        if threat:
            props["threatModel"] = threat
        desc = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": yara_meta.get("title", rule_id)},
            "fullDescription": {"text": yara_meta.get("explanation", yara_meta.get("title", rule_id))},
            "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL.get(yara_meta.get("severity", "low"), "note")},
            "properties": props,
        }
        return desc

    # Synthesized descriptor for non-pack / empty rule_id findings.
    scanner = finding.get("scanner", "")
    category = finding.get("category", "")
    syn_id = rule_id if rule_id else _synthesize_rule_id(scanner, category)
    title = finding.get("title", "") or syn_id
    description = finding.get("description", "") or title
    confidence = finding.get("confidence", 0.0)
    props = {
        "category": category,
        "confidence": confidence,
        "precision": _precision(confidence),
        "synthesized": True,
        "tags": [category] if category else [],
    }
    threat = {}
    for key in ("attacker", "boundary", "asset"):
        if finding.get(key):
            threat[key] = finding[key]
    if threat:
        props["threatModel"] = threat
    desc = {
        "id": syn_id,
        "name": syn_id,
        "shortDescription": {"text": title},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL.get(finding.get("severity", "low"), "note")},
        "properties": props,
    }
    return desc


def _result_rule_id(finding):
    """The ruleId for a result. Pack rule_id when non-empty; else synthesized
    rf/<scanner>/<category-slug> (correlation/meta get their own namespace)."""
    rule_id = finding.get("rule_id", "") or ""
    if rule_id:
        return rule_id
    scanner = finding.get("scanner", "")
    category = finding.get("category", "")
    return _synthesize_rule_id(scanner, category)


def _build_result(finding, occurrence_index):
    """Build one SARIF result object from a finding dict."""
    rule_id = _result_rule_id(finding)
    severity = finding.get("severity", "low") or "low"
    level = _SEVERITY_TO_LEVEL.get(severity, "note")

    title = finding.get("title", "") or ""
    description = finding.get("description", "") or ""
    message_text = "{} — {}".format(title, description) if description else title

    file_path = finding.get("file", "") or ""
    uri = _normalize_uri(file_path)

    physical = {"artifactLocation": {"uri": uri, "uriBaseId": "SRCROOT"}}
    line = finding.get("line", 0) or 0
    try:
        line = int(line)
    except (TypeError, ValueError):
        line = 0
    snippet = finding.get("snippet", "") or ""
    if line > 0:
        region = {"startLine": line}
        if snippet:
            region["snippet"] = {"text": snippet}
        physical["region"] = region
    elif snippet:
        # No region: stash snippet in properties so the evidence is not lost.
        pass

    result = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message_text},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {
            "repoForensics/findingId": finding.get("finding_id", "") or "",
            "repoForensics/stableLocationV1": _stable_location(
                rule_id, finding, occurrence_index),
        },
        "properties": {
            "scanner": finding.get("scanner", "") or "",
            "category": finding.get("category", "") or "",
            "confidence": finding.get("confidence", 0.0),
        },
    }

    if line > 0 and snippet:
        # already in region.snippet
        pass
    elif snippet:
        result["properties"]["snippet"] = snippet

    ev_class = finding.get("evidence_class", "") or ""
    if ev_class:
        result["properties"]["evidenceClass"] = ev_class
    orig_sev = finding.get("original_severity", "") or ""
    if orig_sev:
        result["properties"]["originalSeverity"] = orig_sev
    freshness = finding.get("freshness_status", "") or ""
    if freshness:
        result["properties"]["freshnessStatus"] = freshness
    if finding.get("needs_adjudication"):
        result["properties"]["needsAdjudication"] = True

    return result


def _stable_location(rule_id, finding, occurrence_index):
    """sha1(ruleId ␟ scanner ␟ file ␟ category ␟ occurrenceIndex)[:16].
    Survives snippet rotation; the ordinal disambiguates multiple occurrences
    of the same rule in one file so GitHub does not collapse distinct
    findings."""
    parts = [
        rule_id,
        finding.get("scanner", "") or "",
        finding.get("file", "") or "",
        finding.get("category", "") or "",
        str(occurrence_index),
    ]
    fingerprint = "\x1f".join(parts)
    return hashlib.sha1(fingerprint.encode("utf-8", "replace")).hexdigest()[:16]


def _attach_suppression(result):
    result["suppressions"] = [{
        "kind": "external",
        "justification": "Suppressed via .forensicsignore rule directive",
    }]


def report_to_sarif(report):
    """Convert an aggregate_json.build_report() dict into a SARIF 2.1.0 dict."""
    pack_index, yara_index = _build_rule_index()

    active = report.get("findings", []) or []
    suppressed = report.get("suppressed", []) or []

    # Occurrence index: 0-based ordinal of the finding among all findings
    # sharing (ruleId, file), ordered by (line, snippet). Computed across
    # active+suppressed together so indices are stable regardless of
    # suppression state.
    all_for_index = list(active) + list(suppressed)
    occ_counter = {}
    occ_map = {}
    # Group by (ruleId, file) then assign ordinal by (line, snippet) order.
    groups = {}
    for finding in all_for_index:
        rid = _result_rule_id(finding)
        key = (rid, finding.get("file", "") or "")
        groups.setdefault(key, []).append(finding)
    for key, group in groups.items():
        group.sort(key=lambda f: (
            int(f.get("line", 0) or 0),
            (f.get("snippet", "") or "")[:80],
        ))
        for idx, finding in enumerate(group):
            occ_map[id(finding)] = idx

    results = []
    descriptor_ids = set()
    descriptor_order = []

    for finding in active:
        occ = occ_map.get(id(finding), 0)
        result = _build_result(finding, occ)
        results.append(result)
        rid = result["ruleId"]
        if rid not in descriptor_ids:
            descriptor_ids.add(rid)
            descriptor_order.append((rid, finding))

    for finding in suppressed:
        occ = occ_map.get(id(finding), 0)
        result = _build_result(finding, occ)
        _attach_suppression(result)
        results.append(result)
        rid = result["ruleId"]
        if rid not in descriptor_ids:
            descriptor_ids.add(rid)
            descriptor_order.append((rid, finding))

    rules = []
    for rid, finding in descriptor_order:
        rules.append(_rule_descriptor(rid, finding, pack_index, yara_index))
    # Dedup by id (defensive) and sort by id for deterministic output.
    seen = set()
    deduped = []
    for desc in rules:
        if desc["id"] in seen:
            continue
        seen.add(desc["id"])
        deduped.append(desc)
    deduped.sort(key=lambda d: d["id"])

    target = report.get("target", "") or ""
    srcroot_uri = "file://{}/".format(target.rstrip("/")) if target else "file://./"

    run = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "semanticVersion": TOOL_VERSION,
                "informationUri": INFORMATION_URI,
                "rules": deduped,
            }
        },
        "originalUriBaseIds": {
            "SRCROOT": {"uri": srcroot_uri}
        },
        "results": results,
        "properties": {
            "mode": report.get("mode", "") or "",
            "exitCode": report.get("exit_code", 99),
            "summary": report.get("summary", {}),
            "coreVerdictTier": (report.get("core_verdict") or {}).get("tier", ""),
        },
    }

    sarif = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }
    return sarif
