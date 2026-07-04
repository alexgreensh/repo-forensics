#!/usr/bin/env python3
"""
dead_anchors_extract.py - Anchor extraction for the dead-anchor / repojacking
scanner (U1).

Given a repo path, pulls every EXTERNAL anchor a skill/repo points at, with ZERO
network calls:
  - GitHub owner/repo (URL form DA-GH-001, `github:` shorthand DA-GH-002),
    reserved-word owners (DA-RW-001) filtered out.
  - Prose package-install targets (DA-PK-001); pip->PyPI, npm/yarn/pnpm->npm;
    gem/cargo/bundle are extracted but tagged ecosystem=None (no P0 probe).
  - Bare domains (DA-DM-001) reduced to eTLD+1 via the vendored multi-part-TLD
    list (DA-TLD-001); safe-domain allowlist (DA-SD-001) skipped.
  - Free-tier cloud subdomains (DA-CL-001 suffix membership).

Everything data-driven lives in data/rulepacks/dead_anchors.json (feed-updatable,
read-only at scan time). Anchors are DE-DUPLICATED before return so N references
to the same target cost exactly one probe downstream (loop-safety, spec §10).

Never raises on a scan target: a missing/invalid pack => "nothing to probe this
run" (empty list), a malformed seed file => skipped, never a crash.

Created by Alex Greenshpun
"""

import os
import re
import sys
import stat
from collections import namedtuple

_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import rule_loader

try:
    from _shared_patterns import SEED_FILES as _SEED_FILES
except Exception:  # pragma: no cover - fallback if shared pack unavailable
    _SEED_FILES = {
        'SKILL.md', 'SOUL.md', 'HEARTBEAT.md', 'ROUTINE.md', 'AGENTS.md',
        'BOOT.md', 'BOOTSTRAP.md', 'CLAUDE.md', 'IDENTITY.md', 'USER.md',
    }

# Additional non-seed manifest files worth scanning for anchors.
_EXTRA_FILES = {".mcp.json", "mcp.json", "README.md", "readme.md"}

# Directories we never descend into (heavy / vendored / vcs).
_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
}

# Bounds (loop-safety / lightweight): never read an unbounded tree.
_MAX_FILES = 200
_MAX_FILE_BYTES = 1_000_000
# Hard cap on distinct extracted anchors so a maximally-adversarial (but
# within-file-count/size-bound) repo cannot drive extraction / the downstream
# dispatch loop into multi-minute / multi-GB territory (python-redos F3).
_MAX_ANCHORS = 5000


def normalize_npm_name(name):
    """npm package identity is case-insensitive and lowercase; an @scope is kept
    but lowercased too. Used for BOTH the existence probe and the dedup key so
    'npm install React' and 'react' resolve to one live package, not a phantom."""
    return (name or "").strip().lower()


def normalize_pypi_name(name):
    """PEP 503 canonical form: lowercase and collapse any run of -, _ or . to a
    single -. 'My_Package', 'my-package', 'my.package' are one distribution."""
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()

# Verbs near a domain that promote DA-04 from HIGH to CRITICAL (the domain is an
# active fetch/install target, not a passing mention). Best-effort, per spec §2.
_FETCH_VERB_RE = re.compile(
    r"(?i)\b(curl|wget|fetch|download|source|install|clone|git\s+clone|pip\s+install|"
    r"npm\s+install|require|import\s+from)\b"
)

# One immutable anchor record. `raw` is the original reference (for the snippet);
# `target` is the normalized probe key; `is_free_tier` flags DA-09.
Anchor = namedtuple(
    "Anchor",
    ["type", "target", "owner", "repo", "ecosystem", "suffix",
     "is_free_tier", "file", "line", "raw", "fetch_context"],
)


def _rule_by_id(pack, rule_id):
    if pack is None:
        return None
    try:
        rules = pack.all_rules
    except Exception:
        return None
    for r in rules:
        if getattr(r, "id", None) == rule_id:
            return r
    return None


def _keyword_values(rule):
    """Values of a keyword rule, or an empty set for anything else. A pack that
    has been tampered/corrupted so this id is authored as a NON-keyword type
    (rule.values is then None) must degrade to 'no data', never crash on
    set(None) (python-redos F2 / error-soundness never-hard-fail)."""
    if rule is None or getattr(rule, "type", None) != "keyword":
        return set()
    vals = getattr(rule, "values", None)
    if not vals:
        return set()
    try:
        return set(vals)
    except TypeError:
        return set()


class _Extractor:
    """Compiled pack view. Built once per scan; holds the four extraction
    regexes and the four static lists. A missing pack degrades to a no-op
    extractor (every extract_* returns nothing) rather than crashing."""

    def __init__(self, pack=None, base_dir=None):
        if pack is None:
            try:
                pack = rule_loader.load_pack("dead_anchors", base_dir=base_dir)
            except Exception:
                pack = None
        self.pack = pack
        gh = _rule_by_id(pack, "DA-GH-001")
        sh = _rule_by_id(pack, "DA-GH-002")
        pk = _rule_by_id(pack, "DA-PK-001")
        dm = _rule_by_id(pack, "DA-DM-001")
        self.re_gh = getattr(gh, "regex", None) if gh else None
        self.re_sh = getattr(sh, "regex", None) if sh else None
        self.re_pk = getattr(pk, "regex", None) if pk else None
        self.re_dm = getattr(dm, "regex", None) if dm else None
        cl = _rule_by_id(pack, "DA-CL-001")
        rw = _rule_by_id(pack, "DA-RW-001")
        sd = _rule_by_id(pack, "DA-SD-001")
        tld = _rule_by_id(pack, "DA-TLD-001")
        # rule.values are NFKC-lowercased tuples; domains/suffixes are already
        # lowercase so this is lossless. _keyword_values tolerates a tampered
        # pack that authors any of these ids as a non-keyword type.
        self.cloud_suffixes = _keyword_values(cl)
        self.reserved_words = _keyword_values(rw)
        self.safe_domains = _keyword_values(sd)
        self.multi_tlds = _keyword_values(tld)

    # -- individual extractors (operate on one line of text) ------------------

    def _github_from(self, regex, line, ecosystem_hint):
        out = []
        if regex is None:
            return out
        for m in regex.finditer(line):
            owner, repo = m.group(1), m.group(2)
            if not owner or not repo:
                continue
            if owner.lower() in self.reserved_words:
                continue
            # Trailing punctuation cleanup (e.g. "repo)." in prose).
            repo = repo.rstrip(".")
            if not repo:
                continue
            out.append((owner, repo, m.group(0)))
        return out

    def _packages_from(self, line):
        out = []
        if self.re_pk is None:
            return out
        for m in self.re_pk.finditer(line):
            verb = m.group(0).split()[0].lower()
            raw_name = m.group(1)
            name = _strip_pkg_version(raw_name)
            if not name:
                continue
            if verb.startswith("pip"):
                eco = "PyPI"
            elif verb in ("npm", "yarn", "pnpm"):
                eco = "npm"
            else:
                eco = None  # gem/cargo/bundle: extracted, not probed in P0
            out.append((name, eco, m.group(0)))
        return out

    def _domains_from(self, line):
        """Yield (kind, payload, raw) where kind is 'cloud' or 'domain'."""
        out = []
        if self.re_dm is None:
            return out
        for m in self.re_dm.finditer(line):
            host = m.group(1).lower().rstrip(".")
            if not host or "." not in host:
                continue
            suffix = self._cloud_suffix_for(host)
            if suffix is not None:
                if host == suffix:
                    continue  # bare platform domain, not our subdomain to claim
                out.append(("cloud", (host, suffix), m.group(0)))
                continue
            reg = self._registrable(host)
            if not reg or reg in self.safe_domains:
                continue
            out.append(("domain", reg, m.group(0)))
        return out

    def _cloud_suffix_for(self, host):
        for suf in self.cloud_suffixes:
            if host == suf or host.endswith("." + suf):
                return suf
        return None

    def _registrable(self, host):
        labels = host.split(".")
        if len(labels) < 2:
            return None
        # Longest matching multi-part TLD wins.
        for n in (3, 2):
            if len(labels) > n:
                candidate = ".".join(labels[-n:])
                if candidate in self.multi_tlds:
                    return ".".join(labels[-(n + 1):])
        return ".".join(labels[-2:])


def _strip_pkg_version(raw):
    """Strip version specifiers/flags from a captured package token, preserving
    an npm scope (@scope/name)."""
    name = raw.strip().strip(",;)")
    if not name:
        return ""
    # pip-style specifiers.
    for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "["):
        idx = name.find(sep)
        if idx > 0:
            name = name[:idx]
    # npm @version, keeping a leading scope @.
    if name.startswith("@"):
        parts = name[1:].split("@", 1)
        name = "@" + parts[0]
    else:
        name = name.split("@", 1)[0]
    return name.rstrip("/.")


def _iter_seed_files(repo_path):
    """Yield (abs_path, rel_path) for seed / manifest files, bounded.

    Non-regular files (FIFOs, sockets, device nodes) are skipped BEFORE they are
    ever handed to a reader: a FIFO named 'SKILL.md' shipped in a malicious repo
    would otherwise block open()/read() forever and hang the whole scan
    (python-redos F1). os.stat follows a symlink to its target, so a symlink
    pointing at a FIFO/device is caught here too; only a real regular file (of
    the target) passes."""
    seeds_lower = {s.lower() for s in _SEED_FILES} | {e.lower() for e in _EXTRA_FILES}
    count = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if fn.lower() in seeds_lower:
                abs_path = os.path.join(root, fn)
                try:
                    st = os.stat(abs_path)  # follows symlink to its final target
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue  # FIFO / socket / device / dir -> never open
                if st.st_size > _MAX_FILE_BYTES:
                    continue  # size cap enforced BEFORE any read
                rel = os.path.relpath(abs_path, repo_path)
                yield abs_path, rel
                count += 1
                if count >= _MAX_FILES:
                    return


def _read_regular_file(abs_path):
    """Open a seed file defensively and return its text, or None to skip it.

    Belt-and-suspenders over _iter_seed_files: O_NONBLOCK guarantees the open()
    itself can never block on a FIFO/device even under a TOCTOU swap after the
    stat, and an fstat on the fd we actually hold re-confirms it is a regular
    file and re-checks the size cap on that exact fd."""
    try:
        fd = os.open(abs_path, os.O_RDONLY | _O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_FILE_BYTES:
            os.close(fd)
            return None
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, ValueError):
        try:
            os.close(fd)
        except OSError:
            pass
        return None


def extract_anchors(repo_path, pack=None, base_dir=None):
    """Extract the deduped list of Anchor records from a repo. Zero network.

    De-dup key is (type, target) so N references to the same anchor => 1 probe.
    The FIRST occurrence's file/line/raw is kept for the finding location.
    """
    try:
        ex = _Extractor(pack=pack, base_dir=base_dir)
    except Exception:
        return []  # tampered/malformed pack: nothing to probe this run (no crash)
    if not (ex.re_gh or ex.re_sh or ex.re_pk or ex.re_dm):
        return []  # pack unavailable: nothing to probe this run

    seen = {}  # normalized (type, key) -> Anchor (first wins)

    def _add(anchor):
        # Dedup on the NORMALIZED identity so case/separator variants of the same
        # real anchor collapse to one probe + one finding. The original casing is
        # preserved on the stored Anchor for display.
        if anchor.type == "github":
            key = ("github", "%s/%s" % ((anchor.owner or "").lower(),
                                        (anchor.repo or "").lower()))
        elif anchor.type == "package":
            eco, _, nm = anchor.target.partition(":")
            if eco == "npm":
                nm = normalize_npm_name(nm)
            elif eco == "PyPI":
                nm = normalize_pypi_name(nm)
            key = ("package", "%s:%s" % (eco, nm))
        else:
            key = (anchor.type, anchor.target)
        if key not in seen:
            seen[key] = anchor

    for abs_path, rel in _iter_seed_files(repo_path):
        if len(seen) >= _MAX_ANCHORS:
            break
        text = _read_regular_file(abs_path)
        if text is None:
            continue
        lines = text.splitlines(keepends=True)
        for lineno, line in enumerate(lines, 1):
            if len(seen) >= _MAX_ANCHORS:
                break
            if len(line) > 8000:
                line = line[:8000]
            fetch_ctx = bool(_FETCH_VERB_RE.search(line))
            # GitHub URL + shorthand.
            for owner, repo, raw in ex._github_from(ex.re_gh, line, None):
                _add(Anchor("github", f"{owner}/{repo}", owner, repo, None,
                            None, False, rel, lineno, raw, fetch_ctx))
            for owner, repo, raw in ex._github_from(ex.re_sh, line, None):
                _add(Anchor("github", f"{owner}/{repo}", owner, repo, None,
                            None, False, rel, lineno, raw, fetch_ctx))
            # Packages.
            for name, eco, raw in ex._packages_from(line):
                if eco is None:
                    continue  # gem/cargo/bundle not probed in P0
                _add(Anchor("package", f"{eco}:{name}", None, None, eco,
                            None, False, rel, lineno, raw, fetch_ctx))
            # Domains + cloud subdomains.
            for kind, payload, raw in ex._domains_from(line):
                if kind == "cloud":
                    host, suffix = payload
                    _add(Anchor("cloud", host, None, None, None, suffix,
                                True, rel, lineno, raw, fetch_ctx))
                else:
                    _add(Anchor("domain", payload, None, None, None, None,
                                False, rel, lineno, raw, fetch_ctx))

    return list(seen.values())
