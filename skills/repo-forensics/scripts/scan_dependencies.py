#!/usr/bin/env python3
"""
scan_dependencies.py - Dependency Scanner (v3: NPM + Python + Go + transitive, 500+ packages)
Detects typosquatting, untrusted registries, version anomalies, and transitive supply chain attacks.

Created by Alex Greenshpun
"""

import sys
import os
import json
import difflib
import re
import unicodedata
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "dependencies"

# Top 200 NPM packages
POPULAR_NPM = [
    "react", "react-dom", "lodash", "underscore", "express", "moment", "axios", "chalk", "commander",
    "debug", "fs-extra", "bluebird", "async", "request", "prop-types", "classnames", "uuid", "mkdirp",
    "body-parser", "glob", "minimist", "colors", "inquirer", "yeoman-generator", "through2", "cheerio",
    "shelljs", "rimraf", "yargs", "cookie-parser", "jsonwebtoken", "mongoose", "sequelize",
    "vue", "angular", "rxjs", "tslib", "zone-js", "core-js", "webpack", "babel-core", "typescript",
    "tailwindcss", "postcss", "autoprefixer", "eslint", "prettier", "vite", "next", "nuxt",
    "dotenv", "cors", "morgan", "helmet", "passport", "bcrypt", "nodemon", "concurrently",
    "cross-env", "webpack-cli", "babel-loader", "css-loader", "style-loader", "file-loader",
    "url-loader", "html-webpack-plugin", "mini-css-extract-plugin", "terser-webpack-plugin",
    "jest", "mocha", "chai", "sinon", "supertest", "nyc", "istanbul", "karma",
    "socket-io", "redis", "pg", "mysql2", "mongodb", "knex", "prisma", "typeorm",
    "graphql", "apollo-server", "apollo-client", "relay-runtime",
    "react-router", "react-router-dom", "react-redux", "redux", "redux-thunk", "redux-saga",
    "mobx", "zustand", "recoil", "immer", "ramda", "date-fns", "dayjs", "luxon",
    "formik", "yup", "zod", "ajv", "joi", "validator",
    "winston", "bunyan", "pino", "loglevel", "log4js",
    "aws-sdk", "firebase", "stripe", "twilio", "sendgrid",
    "sharp", "jimp", "canvas", "puppeteer", "playwright", "cypress",
    "electron", "tauri", "capacitor", "ionic", "react-native", "expo",
    "d3", "chart-js", "three", "p5", "fabric", "konva", "pixi-js",
    "material-ui", "ant-design", "chakra-ui", "headlessui", "radix-ui",
    "storybook", "docusaurus", "gatsby", "astro", "remix", "svelte", "sveltekit",
    "fastify", "koa", "hapi", "nest", "adonis",
    "esbuild", "rollup", "parcel", "swc", "turbopack",
    "lerna", "nx", "turborepo", "changesets", "semantic-release",
    "husky", "lint-staged", "commitlint", "conventional-changelog",
    "nodemailer", "bull", "agenda", "cron", "node-cron",
    "multer", "busboy", "formidable", "express-fileupload",
    "compression", "serve-static", "http-proxy-middleware",
    "i18next", "intl", "globalize", "polyglot",
    "nanoid", "cuid", "shortid", "ulid",
    "cheerio", "jsdom", "node-fetch", "got", "superagent", "ky",
    "ora", "listr", "progress", "cli-progress", "boxen", "figlet",
    "execa", "zx", "shelljs", "cross-spawn",
    "semver", "compare-versions", "node-semver",
    "yaml", "toml", "ini", "properties-parser",
    "gray-matter", "front-matter", "markdown-it", "marked", "remark", "rehype",
]

# Top 200 PyPI packages
POPULAR_PYPI = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "sqlalchemy", "celery",
    "boto3", "botocore", "pillow", "scipy", "matplotlib", "scikit-learn", "tensorflow",
    "pytorch", "torch", "transformers", "beautifulsoup4", "lxml", "scrapy",
    "pytest", "unittest2", "nose", "tox", "coverage", "hypothesis",
    "click", "typer", "argparse", "fire", "docopt",
    "pydantic", "attrs", "dataclasses", "marshmallow",
    "aiohttp", "httpx", "urllib3", "certifi", "chardet",
    "cryptography", "pycryptodome", "paramiko", "fabric",
    "redis", "pymongo", "psycopg2", "mysql-connector-python",
    "gunicorn", "uvicorn", "waitress", "twisted", "tornado",
    "jinja2", "mako", "chameleon",
    "setuptools", "pip", "wheel", "twine", "build",
    "black", "flake8", "mypy", "pylint", "isort", "autopep8", "yapf",
    "python-dotenv", "decouple", "environs",
    "pyyaml", "toml", "tomli", "configparser",
    "jsonschema", "simplejson", "orjson", "ujson",
    "arrow", "pendulum", "python-dateutil", "pytz",
    "rich", "colorama", "termcolor", "tqdm", "alive-progress",
    "loguru", "structlog", "python-json-logger",
    "jwt", "pyjwt", "oauthlib", "authlib",
    "stripe", "twilio", "sendgrid",
    "opencv-python", "imageio", "scikit-image",
    "networkx", "igraph", "graph-tool",
    "sympy", "mpmath", "statsmodels",
    "selenium", "playwright", "pyppeteer",
    "docker", "kubernetes", "ansible",
    "grpcio", "protobuf", "thrift",
    "graphene", "strawberry-graphql", "ariadne",
    "alembic", "migrate", "peewee", "tortoise-orm",
    "sentry-sdk", "newrelic", "datadog",
    "openai", "anthropic", "langchain", "llama-index",
    "streamlit", "gradio", "dash", "panel",
    "sphinx", "mkdocs", "pdoc",
    "regex", "more-itertools", "toolz", "funcy",
    "tenacity", "retrying", "backoff",
    "apscheduler", "schedule", "rq",
    "watchdog", "inotify", "pyinotify",
    "psutil", "py-cpuinfo", "gputil",
    "pexpect", "ptyprocess", "subprocess32",
    "pygments", "asttokens", "astunparse",
]

# Top 100 Go modules (short names for import path matching)
POPULAR_GO = [
    "gin", "echo", "fiber", "chi", "mux", "gorilla", "httprouter",
    "gorm", "sqlx", "pgx", "go-redis", "mongo-driver",
    "cobra", "viper", "pflag", "urfave-cli",
    "zap", "logrus", "zerolog",
    "testify", "gomock", "gocheck",
    "grpc", "protobuf", "twirp",
    "jwt", "oauth2", "casbin",
    "aws-sdk-go", "azure-sdk-for-go", "google-cloud-go",
    "docker", "kubernetes", "helm", "terraform",
    "prometheus", "opentelemetry", "jaeger",
    "uuid", "ulid", "xid",
    "validator", "ozzo-validation",
    "go-kit", "micro",
    "fx", "wire", "dig",
    "colly", "goquery", "rod",
    "ginkgo", "gomega", "goconvey",
    "afero", "embed",
    "graphql", "gqlgen", "graphql-go",
]

TRUSTED_REGISTRIES = [
    "registry.npmjs.org", "registry.yarnpkg.com", "codeload.github.com",
    "github.com", "cdn.jsdelivr.net", "pnpm.io",
    "pypi.org", "files.pythonhosted.org",
    "proxy.golang.org", "sum.golang.org",
]

# Funding/sponsorship domains that appear in lockfile metadata (not registries)
KNOWN_BENIGN_DOMAINS = [
    "opencollective.com", "tidelift.com", "paulmillr.com",
    "feross.org", "patreon.com", "buymeacoffee.com",
    "eslint.org", "ko-fi.com", "paypal.me",
]


# IOC packages - lazy loaded from ioc_manager (single source of truth)
_SANDWORM_KNOWN_IOC_PACKAGES = None

_FALLBACK_IOC_PACKAGES = {
    "rimarf", "yarsg", "suport-color", "naniod", "opencraw",
    "claud-code", "cloude-code", "cloude", "mcp-cliient", "mcp-serever",
    "anthropic-sdk-node", "claude-code-cli", "clawclient",
    "anthopic", "antrhopic", "claudes", "mcp-python-sdk",
    # Axios supply chain RAT dropper (March 31, 2026)
    "plain-crypto-js",
    # Companion malware packages (March 2026)
    "@shadanai/openclaw", "@qqbrowser/openclaw-qbot",
}


def _get_ioc_packages():
    """Lazy-load IOC packages from ioc_manager."""
    global _SANDWORM_KNOWN_IOC_PACKAGES
    if _SANDWORM_KNOWN_IOC_PACKAGES is None:
        try:
            import ioc_manager as _ioc
            _iocs = _ioc.get_iocs()
            _SANDWORM_KNOWN_IOC_PACKAGES = {p.lower() for p in (_iocs.get('malicious_npm', set()) | _iocs.get('malicious_pypi', set()))}
        except (ImportError, OSError, json.JSONDecodeError, ValueError) as e:
            print(f"[!] IOC loading failed, using fallback: {e}", file=sys.stderr)
            _SANDWORM_KNOWN_IOC_PACKAGES = _FALLBACK_IOC_PACKAGES
    return _SANDWORM_KNOWN_IOC_PACKAGES


def _apply_l33t(name):
    """Normalize l33t substitutions for typosquatting comparison.
    Maps: 0->o, 1->l, 3->e, @->a (common character swaps in malicious packages).
    """
    return name.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('@', 'a')


# Match version strings in a tolerant-but-parseable way. Captures:
#   1. major (required)
#   2. minor (optional)
#   3. patch (optional)
#   4. suffix (optional pre-release/build metadata starting with - or +)
_VERSION_RE = re.compile(
    r'^\s*[vV]?'
    r'[~^>=<!]*\s*'
    r'(\d+)(?:\.(\d+))?(?:\.(\d+))?'
    r'([-+][0-9A-Za-z.\-+]*)?'
    r'\s*$'
)


def normalize_version(version, strict_pin=False):
    """Canonicalize a version string for IOC comparison.

    Returns a normalized string (e.g. '5.6.1') or None if the input cannot
    be parsed as a version. The goal is to make bypass attempts like 'v5.6.1',
    '5.06.1', '  5.6.1  ', '^5.6.1', NFC-unnormalized unicode, and leading
    zeros all map to the same key as '5.6.1' so they get caught by the IOC
    set lookup.

    Args:
        version: string version to normalize.
        strict_pin: when True (used by package.json callers), rejects ANY
            range operator — `^`, `~`, `>=`, `<=` — because those are range
            constraints that may or may not resolve to the IOC version.
            `<=5.6.1` and `~5.6.1` both INCLUDE 5.6.1 in their range but do
            NOT pin it, so matching the chalk@5.6.1 IOC on a package.json
            that writes `"chalk": "<=5.6.1"` is a false positive. (Code
            review CRC-F1, 2026-04-05.) Lockfile resolved versions never
            contain operators and call with strict_pin=False (default).

    Strips:
      - Leading/trailing whitespace
      - 'v' or 'V' prefix (npm tag aliases, GitHub release style)
      - Range hint operators: ^ ~ (approximately equal) — when strict_pin=False
      - Leading zeros in each numeric segment ('5.06.1' -> '5.6.1')
      - Build metadata ('+sha.abc123'). Per SemVer 2.0.0 §10 build metadata
        MUST be ignored when determining version precedence, so
        `5.6.1+mirror.hash` must normalize to `5.6.1` and match the chalk
        IOC. (Security review SS-F3, 2026-04-05.)

    Preserves:
      - Pre-release metadata ('-beta.0', '-rc.1', '-next.0')

    Rejects (returns None):
      - None, non-string types
      - Empty string
      - Non-version strings ('latest', 'main', git refs)
      - Strings with embedded control characters
      - Exclusion operators (<, >, !, !=). These definitively EXCLUDE the
        target version — e.g. '<5.6.1' means 'anything less than 5.6.1'.
        (Security review B1, 2026-04-05.)
      - Inclusion range operators (>=, <=, ^, ~) WHEN strict_pin=True.
    """
    if not isinstance(version, str) or not version:
        return None
    # Defensive: reject strings with control chars (prevents log-injection
    # via version field and YAML/JSON parser quirks)
    if any(ord(c) < 0x20 and c not in '\t' for c in version):
        return None
    # NFC normalize to collapse homoglyph-style unicode variants
    version = unicodedata.normalize('NFC', version)
    # Reject exclusion operators that definitively EXCLUDE the target version
    # (security review B1, 2026-04-05):
    #   <5.6.1   means "anything below 5.6.1"  — excludes 5.6.1
    #   >5.6.1   means "anything above 5.6.1"  — excludes 5.6.1
    #   !5.6.1   means "not 5.6.1"             — excludes 5.6.1
    #   !=5.6.1  means "not equal to 5.6.1"    — excludes 5.6.1
    # Inclusion operators like >=5.6.1, <=5.6.1, ^5.6.1, ~5.6.1 all include
    # 5.6.1 and are legitimately normalized.
    stripped = version.strip()
    if stripped.startswith(('!=', '!')):
        return None
    # `<` or `>` followed by anything OTHER than `=` is an exclusion operator
    if stripped.startswith('<') and not stripped.startswith('<='):
        return None
    if stripped.startswith('>') and not stripped.startswith('>='):
        return None
    # In strict-pin mode (package.json manifest callers), reject ANY range
    # operator. These are NOT pins — they're constraints that the lockfile
    # resolves to some specific version, which may or may not be the IOC.
    # Flagging them as critical IOC hits is a false positive. (CRC-F1.)
    if strict_pin:
        if stripped.startswith(('<=', '>=', '^', '~')):
            return None
    m = _VERSION_RE.match(version)
    if not m:
        return None
    major, minor, patch, suffix = m.groups()
    parts = [str(int(major))]
    if minor is not None:
        parts.append(str(int(minor)))
    if patch is not None:
        parts.append(str(int(patch)))
    normalized = '.'.join(parts)
    # Preserve pre-release ('-beta.0') but drop build metadata ('+sha.abc')
    # per SemVer §10. `-beta.0+build.1` keeps `-beta.0`, drops `+build.1`.
    if suffix:
        plus_idx = suffix.find('+')
        if plus_idx >= 0:
            suffix = suffix[:plus_idx]
        if suffix:
            normalized += suffix
    return normalized


def check_typosquatting(dependencies, popular_list):
    # Pre-compute lowercase mapping for O(1) lookup instead of O(n) per dep
    popular_lower_map = {p.lower(): p for p in popular_list}
    popular_lower_set = set(popular_lower_map.keys())
    suspicious = []
    for dep in dependencies:
        dep_lower = dep.lower()
        dep_l33t = _apply_l33t(dep_lower)

        if dep_lower in popular_lower_set:
            continue

        # Check raw similarity (pre-filter by length to avoid O(n*m) SequenceMatcher on large lockfiles)
        for pop_lower, popular in popular_lower_map.items():
            if abs(len(dep_lower) - len(pop_lower)) > max(3, int(len(pop_lower) * 0.15)):
                continue  # Length difference too large for >0.85 similarity
            ratio = difflib.SequenceMatcher(None, dep_lower, pop_lower).ratio()
            if ratio > 0.85 and dep_lower != pop_lower:
                suspicious.append((dep, popular, ratio))
                break
            # Check l33t-normalized similarity
            if dep_l33t != dep_lower:
                ratio_l33t = difflib.SequenceMatcher(None, dep_l33t, pop_lower).ratio()
                if ratio_l33t > 0.85 and dep_l33t != pop_lower:
                    suspicious.append((dep, popular, ratio_l33t))
                    break

    return suspicious


def check_version_anomaly(version_str):
    """Detect dependency confusion signatures like v99.x.x"""
    m = re.match(r'[~^>=<]*(\d+)', version_str)
    if m:
        major = int(m.group(1))
        if major >= 90:
            return True
    return False


def check_known_ioc_packages(dependencies, rel_path):
    """Flag packages matching SANDWORM_MODE campaign known-IOC list (critical)."""
    findings = []
    for dep in dependencies:
        if dep.lower() in _get_ioc_packages():
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=f"Known Malicious Package: '{dep}'",
                description="Package matches SANDWORM_MODE campaign IOC list (source: Socket Research, Snyk ToxicSkills 2026)",
                file=rel_path, line=0, snippet=f"'{dep}' is a known malicious package",
                category="known-ioc"
            ))
    return findings


# Compromised versions of legitimate packages (supply chain hijack, not typosquatting).
#
# DESIGN NOTE (2026-04-05): This in-module dict is the LEGACY baseline that
# ships with the scanner for offline/air-gapped use. It is DISJOINT from the
# larger ioc_manager-loaded database (skills/repo-forensics/data/compromised_versions.json)
# which carries Marc Gadsdon's 127 IOCs with campaign attribution. The two
# sources are union-merged by _get_compromised_versions_db() below. When
# adding new IOCs, prefer the JSON file (richer metadata, reviewable in git
# history, easier to update). Only touch this dict if you need a detection
# that must work even when the JSON file is missing/corrupt.
COMPROMISED_PACKAGE_VERSIONS = {
    # Axios supply chain compromise (March 31, 2026)
    "axios": {"1.14.1", "0.30.4"},
    # plain-crypto-js RAT dropper (March 31, 2026)
    "plain-crypto-js": {"4.2.1"},
    # Companion malware packages (March 2026)
    "@shadanai/openclaw": {"2026.3.28-2", "2026.3.28-3", "2026.3.31-1", "2026.3.31-2"},
    "@qqbrowser/openclaw-qbot": {"0.0.130"},
    # liteLLM supply chain attack (March 24, 2026)
    "litellm": {"1.82.7", "1.82.8"},
}

# Suspicious npm scopes (systematic MCP server forking campaigns)
SUSPICIOUS_NPM_SCOPES = {
    "@iflow-mcp",   # Systematic MCP server forking campaign (March 2026)
}


def _get_compromised_versions_db():
    """Return the live compromised-versions database.

    Merges the in-module COMPROMISED_PACKAGE_VERSIONS fallback (kept for
    offline/air-gapped use) with the richer ioc_manager dataset loaded from
    skills/repo-forensics/data/compromised_versions.json. When ioc_manager provides campaign
    attribution, the fallback dict's bare version strings are replaced by
    {version: campaign_id} maps for better reporting; when it does not, we
    synthesize 'local-fallback' as the campaign id so the downstream code
    path stays uniform.

    Returns: dict mapping package_name_lower -> {normalized_version: campaign_id}
    """
    # Seed from in-module fallback (always available)
    db = {}
    for pkg, versions in COMPROMISED_PACKAGE_VERSIONS.items():
        pkg_lower = pkg.lower()
        db[pkg_lower] = {}
        for v in versions:
            normalized = normalize_version(v) or v
            db[pkg_lower][normalized] = "local-fallback"

    # Merge ioc_manager data (JSON file ships with the tool + optional OSV)
    try:
        import ioc_manager as _ioc
        ioc_data = _ioc.get_iocs()
        remote_cv = ioc_data.get('compromised_versions', {})
        for pkg_lower, version_map in remote_cv.items():
            if pkg_lower not in db:
                db[pkg_lower] = {}
            for version, campaign_id in version_map.items():
                # Normalize the DB-side key so lookups match regardless of
                # how the IOC was typed into the JSON file.
                normalized = normalize_version(version) or version
                db[pkg_lower][normalized] = campaign_id
    except (ImportError, OSError, json.JSONDecodeError, ValueError, KeyError) as e:
        print(f"[!] Compromised-version IOC load failed, using fallback: {e}",
              file=sys.stderr)

    return db


# Lazy-loaded cache of the merged DB. Populated on first call and cleared
# by tests that need a fresh load.
_COMPROMISED_VERSIONS_DB = None


def _compromised_versions_db():
    global _COMPROMISED_VERSIONS_DB
    if _COMPROMISED_VERSIONS_DB is None:
        _COMPROMISED_VERSIONS_DB = _get_compromised_versions_db()
    return _COMPROMISED_VERSIONS_DB


def check_compromised_versions(all_deps_with_versions, rel_path, db=None, strict_pin=False):
    """Flag specific compromised versions of legitimate packages.

    Matches against the merged IOC database (in-module fallback + shipped
    JSON via ioc_manager + optional OSV feed). Uses normalize_version() on
    the dependency-side version string to defeat prefix/leading-zero/v-prefix
    bypass attempts.

    Args:
        all_deps_with_versions: dict of {package_name: version_string}
        rel_path: file path for the finding (for attribution)
        db: optional pre-loaded database (for testing); defaults to the
            lazy-loaded module cache.
        strict_pin: pass True when the caller is scanning a manifest (like
            package.json) whose version strings are RANGE CONSTRAINTS, not
            resolved versions. With strict_pin=True, normalize_version rejects
            operators like `<=`, `>=`, `^`, `~` to avoid false-positive IOC
            matches on ranges that merely include the compromised version.
            Lockfile callers pass strict_pin=False (default). Code review
            CRC-F1, 2026-04-05.
    """
    if db is None:
        db = _compromised_versions_db()
    findings = []
    for pkg, version in all_deps_with_versions.items():
        pkg_lower = pkg.lower()
        if pkg_lower not in db:
            continue
        normalized = normalize_version(version, strict_pin=strict_pin)
        if normalized is None:
            # Unparseable version — skip silently rather than flag or crash
            continue
        if normalized in db[pkg_lower]:
            campaign_id = db[pkg_lower][normalized]
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=f"Compromised Package Version: {pkg}@{normalized}",
                description=(
                    f"Version {normalized} of '{pkg}' is known compromised "
                    f"(supply chain attack IOC, campaign: {campaign_id})"
                ),
                file=rel_path, line=0,
                snippet=f"{pkg}@{normalized} (known compromised, {campaign_id})",
                category="supply-chain"
            ))
    return findings


def check_suspicious_scopes(dependencies, rel_path):
    """Flag packages from suspicious npm scopes (systematic forking campaigns)."""
    findings = []
    for dep in dependencies:
        for scope in SUSPICIOUS_NPM_SCOPES:
            if dep.lower().startswith(scope + "/"):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Suspicious Scope Package: '{dep}'",
                    description=f"Package from '{scope}' scope (systematic MCP server forking campaign, March 2026)",
                    file=rel_path, line=0,
                    snippet=f"'{dep}' from suspicious scope '{scope}'",
                    category="suspicious-scope"
                ))
    return findings


_OVERRIDES_MAX_DEPTH = 32  # real npm/yarn/pnpm overrides never nest beyond ~3


def _flatten_overrides(overrides_map, result=None, _depth=0, _seen=None):
    """Recursively flatten npm `overrides` / yarn `resolutions` nested maps.

    npm overrides can be nested: {"foo": {".": "1.0.0", "bar": "2.0.0"}} means
    override foo to 1.0.0 AND override foo's transitive bar to 2.0.0. Yarn
    resolutions use **/package syntax. This flattener extracts all
    package@version pairs regardless of nesting depth.

    Depth-guarded against adversarial package.json with thousands of nested
    levels (security review SS-F1, 2026-04-05). A RecursionError here aborts
    the entire scanner walk and silently suppresses chalk@5.6.1 detection.
    """
    if result is None:
        result = {}
    if _seen is None:
        _seen = set()
    if _depth > _OVERRIDES_MAX_DEPTH:
        return result
    if not isinstance(overrides_map, dict):
        return result
    # Cycle guard: Python dicts from json.load cannot be cyclic, but raw dicts
    # from test harnesses or future YAML anchor loaders could be.
    obj_id = id(overrides_map)
    if obj_id in _seen:
        return result
    _seen.add(obj_id)
    for key, value in overrides_map.items():
        if isinstance(value, str):
            # Leaf: package name -> version string
            # Strip yarn resolution glob prefix (**/) and leading/trailing slashes
            pkg_name = key.replace('**/', '').strip('/')
            if pkg_name and pkg_name != '.':
                result[pkg_name] = value
        elif isinstance(value, dict):
            # Nested: {'.': '1.0.0', 'bar': '2.0.0'}
            if '.' in value and isinstance(value['.'], str):
                pkg_name = key.replace('**/', '').strip('/')
                if pkg_name:
                    result[pkg_name] = value['.']
            _flatten_overrides(value, result, _depth=_depth + 1, _seen=_seen)
    return result


def scan_package_json(filepath, rel_path):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        all_deps = {}
        for key in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
            all_deps.update(data.get(key, {}))

        # Parse npm `overrides`, yarn `resolutions`, and pnpm `pnpm.overrides`.
        # These override the resolved version of a transitive dep and are a
        # real bypass vector: a single-field PR can inject chalk@5.6.1 as an
        # override without changing any top-level dependency.
        override_deps = {}
        override_deps.update(_flatten_overrides(data.get('overrides', {})))
        override_deps.update(_flatten_overrides(data.get('resolutions', {})))
        pnpm_section = data.get('pnpm', {})
        if isinstance(pnpm_section, dict):
            override_deps.update(_flatten_overrides(pnpm_section.get('overrides', {})))

        # pnpm catalog: (pnpm-workspace.yaml has catalogs, package.json can
        # reference them; we scan declared catalogs in package.json too)
        catalogs = data.get('catalog', {})
        if isinstance(catalogs, dict):
            for pkg, ver in catalogs.items():
                if isinstance(ver, str):
                    override_deps[pkg] = ver

        # Merge overrides into all_deps for the downstream checks, but also
        # flag them as override-sourced for attribution
        if override_deps:
            for pkg, ver in override_deps.items():
                if pkg not in all_deps:
                    all_deps[pkg] = ver
            # Run compromised-version check specifically on overrides so the
            # finding snippet can call out the override vector
            override_findings = check_compromised_versions(override_deps, rel_path, strict_pin=True)
            for f in override_findings:
                f.description = f.description + " [via overrides/resolutions/catalog]"
                f.category = "supply-chain-override"
            findings.extend(override_findings)

        # Flag .pnpmfile.cjs as an install-time rewriting vector (advisory only)
        pkg_dir = os.path.dirname(filepath)
        pnpmfile = os.path.join(pkg_dir, '.pnpmfile.cjs')
        if os.path.exists(pnpmfile):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="medium",
                title=".pnpmfile.cjs present",
                description=(
                    ".pnpmfile.cjs can rewrite dependency specs at install "
                    "time. Review for malicious rewrites (e.g. redirecting "
                    "chalk to a compromised version)."
                ),
                file=os.path.relpath(pnpmfile, os.path.dirname(filepath)) or ".pnpmfile.cjs",
                line=0,
                snippet=".pnpmfile.cjs install-time hook",
                category="install-time-rewriter"
            ))

        dep_names = list(all_deps.keys())

        # Missing lockfile detection
        if all_deps:
            pkg_dir = os.path.dirname(filepath)
            lockfile_names = ('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock')
            has_lockfile = any(os.path.exists(os.path.join(pkg_dir, lf)) for lf in lockfile_names)
            # Monorepo check: look up 2 parent directories
            if not has_lockfile:
                parent = os.path.dirname(pkg_dir)
                for _ in range(2):
                    if any(os.path.exists(os.path.join(parent, lf)) for lf in lockfile_names):
                        has_lockfile = True
                        break
                    parent = os.path.dirname(parent)
            if not has_lockfile:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Missing Lockfile",
                    description="No lockfile found (package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lockb). Dependencies resolve to latest in range on every install.",
                    file=rel_path, line=0,
                    snippet=f"{len(all_deps)} dependencies without lockfile",
                    category="missing-lockfile"
                ))

        # Git/HTTP/file dependency flagging
        for pkg, ver in all_deps.items():
            if not isinstance(ver, str):
                continue
            if ver.startswith(('git+', 'git://', 'github:')):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Git Dependency: {pkg}",
                    description="Git dependency bypasses registry integrity checks (PackageGate .npmrc injection vector)",
                    file=rel_path, line=0, snippet=f"{pkg}: {ver[:120]}",
                    category="git-dependency"
                ))
            elif ver.startswith('http://'):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title=f"HTTP Dependency: {pkg}",
                    description="Dependency fetched over unencrypted HTTP (MITM attack vector)",
                    file=rel_path, line=0, snippet=f"{pkg}: {ver[:120]}",
                    category="insecure-protocol"
                ))
            elif ver.startswith('file:'):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title=f"Local File Dependency: {pkg}",
                    description="Dependency references local filesystem path",
                    file=rel_path, line=0, snippet=f"{pkg}: {ver[:120]}",
                    category="local-dependency"
                ))

        # Known IOC check (critical, before typosquatting)
        findings.extend(check_known_ioc_packages(dep_names, rel_path))

        # Compromised versions of legitimate packages. strict_pin=True rejects
        # range constraints like `<=5.6.1`, `~5.6.1` which would otherwise
        # false-positive. Lockfile scanners pass strict_pin=False because
        # their values are already resolved. (CRC-F1, 2026-04-05.)
        findings.extend(check_compromised_versions(all_deps, rel_path, strict_pin=True))

        # Suspicious npm scopes (forking campaigns)
        findings.extend(check_suspicious_scopes(dep_names, rel_path))

        # Typosquatting
        typos = check_typosquatting(dep_names, POPULAR_NPM)
        for suspect, target, score in typos:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"Typosquat Risk: '{suspect}' ~ '{target}'",
                description=f"Package name similarity {score:.0%} to popular package",
                file=rel_path, line=0, snippet=f"'{suspect}' might be typosquatting '{target}'",
                category="typosquatting"
            ))

        # Version anomaly
        for pkg, ver in all_deps.items():
            if isinstance(ver, str) and check_version_anomaly(ver):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Version Anomaly: {pkg}@{ver}",
                    description="Abnormally high major version (dependency confusion indicator)",
                    file=rel_path, line=0, snippet=f"{pkg}: {ver}",
                    category="dependency-confusion"
                ))

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="Package manifest parse error",
            description=f"Could not fully parse package.json: {e}",
            file=rel_path, line=0, snippet=str(e)[:120],
            category="parse-error"
        ))
    except (RecursionError, MemoryError) as e:
        # Adversarial package.json with pathologically nested overrides or
        # huge arrays can exhaust the interpreter. Without this handler a
        # single malicious file aborts the entire scanner walk loop and every
        # subsequent IOC / compromised-version check silently fails. The
        # depth guard in _flatten_overrides already protects the normal path;
        # this is the belt-and-suspenders catch for any future recursive
        # helper that slips through. (Security review SS-F1, 2026-04-05.)
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="high",
            title="Adversarial package.json structure",
            description=f"Refused to parse hostile package.json: {type(e).__name__}",
            file=rel_path, line=0, snippet=str(e)[:120],
            category="parser-dos"
        ))
    except OSError as e:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="Package manifest read error",
            description=f"Could not read package.json: {e}",
            file=rel_path, line=0, snippet=str(e)[:120],
            category="parse-error"
        ))
    return findings


def scan_python_deps(filepath, rel_path):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        deps = []
        basename = os.path.basename(filepath)
        # Check for companion lockfiles (suppress unbounded-range warnings if locked)
        lock_dir = os.path.dirname(filepath)
        py_lockfiles = ('requirements.lock', 'requirements-lock.txt', 'Pipfile.lock', 'poetry.lock')
        has_py_lockfile = any(os.path.exists(os.path.join(lock_dir, lf)) for lf in py_lockfiles)

        if basename in ('requirements.txt', 'requirements-dev.txt', 'requirements-test.txt', 'constraints.txt'):
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    pkg = re.split(r'[>=<!\[\];~]', line)[0].strip()
                    if pkg:
                        deps.append(pkg)
                    # Check version
                    ver_m = re.search(r'[>=<]=?(\d+)', line)
                    if ver_m and int(ver_m.group(1)) >= 90:
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="high",
                            title=f"Version Anomaly: {pkg}",
                            description="Abnormally high version in requirements",
                            file=rel_path, line=0, snippet=line[:120],
                            category="dependency-confusion"
                        ))

                    # Unbounded range detection (only if no lockfile)
                    if not has_py_lockfile and pkg:
                        # Bare package name with no version constraint
                        if pkg and line.strip() == pkg:
                            findings.append(core.Finding(
                                scanner=SCANNER_NAME, severity="high",
                                title=f"No Version Constraint: {pkg}",
                                description="Package has no version constraint (installs latest on every install)",
                                file=rel_path, line=0, snippet=line[:120],
                                category="no-version-constraint"
                            ))
                        # >= without upper bound
                        elif '>=' in line and '<' not in line and '~=' not in line and '==' not in line:
                            findings.append(core.Finding(
                                scanner=SCANNER_NAME, severity="medium",
                                title=f"Unbounded Version Range: {pkg}",
                                description=">=X.Y.Z with no upper bound allows arbitrary future versions",
                                file=rel_path, line=0, snippet=line[:120],
                                category="unbounded-range"
                            ))

        elif basename in ('pyproject.toml', 'Pipfile'):
            for m in re.finditer(r'["\']([a-zA-Z0-9_-]+)["\']', content):
                deps.append(m.group(1))

        # Known IOC check first
        findings.extend(check_known_ioc_packages(deps, rel_path))

        typos = check_typosquatting(deps, POPULAR_PYPI)
        for suspect, target, score in typos:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"Typosquat Risk: '{suspect}' ~ '{target}'",
                description=f"Package name similarity {score:.0%} to popular PyPI package",
                file=rel_path, line=0, snippet=f"'{suspect}' might be typosquatting '{target}'",
                category="typosquatting"
            ))

    except (UnicodeDecodeError, OSError) as e:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="Requirements file read error",
            description=f"Could not fully parse requirements: {e}",
            file=rel_path, line=0, snippet=str(e)[:120],
            category="parse-error"
        ))
    return findings


def scan_lockfile(filepath, rel_path):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        urls = re.findall(r'https?://[^\s"\'}]+', content)
        suspicious = set()

        for url in urls:
            # Check hostname only to prevent path-based bypass (e.g., evil.com/registry.npmjs.org/)
            hostname = urlparse(url).hostname or ''
            is_trusted = any(hostname == t or hostname.endswith('.' + t) for t in TRUSTED_REGISTRIES)
            is_benign = any(hostname == d or hostname.endswith('.' + d) for d in KNOWN_BENIGN_DOMAINS)
            if not is_trusted and not is_benign and "schema.org" not in hostname:
                suspicious.add(url)

        # Flag git+ and git:// resolved URLs in lockfiles (separate regex since https? doesn't match these)
        git_urls = re.findall(r'(?:git\+https?://|git://)[^\s"\'}]+', content)
        for url in git_urls:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title="Lockfile: Git-Resolved Dependency",
                description="Lockfile resolves dependency via git (bypasses registry integrity)",
                file=rel_path, line=0, snippet=url[:120],
                category="git-dependency"
            ))

        # Flag http:// resolved URLs (MITM risk)
        for url in urls:
            if url.startswith('http://'):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="Lockfile: HTTP-Resolved Dependency",
                    description="Lockfile resolves dependency over unencrypted HTTP (MITM risk)",
                    file=rel_path, line=0, snippet=url[:120],
                    category="insecure-protocol"
                ))

        if suspicious:
            for url in list(suspicious)[:5]:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="critical",
                    title="Untrusted Registry URL",
                    description="Lockfile resolves to non-standard registry (supply chain risk)",
                    file=rel_path, line=0, snippet=url[:120],
                    category="untrusted-registry"
                ))

    except (UnicodeDecodeError, OSError) as e:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="Lockfile read error",
            description=f"Could not read lockfile: {e}",
            file=rel_path, line=0, snippet=str(e)[:120],
            category="parse-error"
        ))
    return findings


# --- Transitive Dependency Scanning ---
# Parses lockfiles to extract ALL package names (not just top-level)
# and checks them against the IOC list for supply chain attacks.

def parse_package_lock_json(filepath, rel_path):
    """Parse package-lock.json (v1, v2, v3) to extract all transitive dependencies."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        all_packages = set()
        lockfile_version = data.get('lockfileVersion', 1)

        # v2/v3 format: "packages" key with flattened node_modules paths
        if 'packages' in data and lockfile_version >= 2:
            for pkg_path, pkg_info in data.get('packages', {}).items():
                if pkg_path == '':
                    continue  # Skip root package
                # Extract package name from path (e.g., "node_modules/foo" -> "foo")
                parts = pkg_path.split('node_modules/')
                if parts:
                    name = parts[-1]
                    if name:
                        all_packages.add(name)

                # Integrity hash verification (v2/v3 only)
                # Skip workspace links and root package
                if pkg_info.get('link'):
                    continue
                if 'integrity' not in pkg_info and pkg_path:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="medium",
                        title=f"Missing Integrity Hash: {name if parts else pkg_path}",
                        description="Package in lockfile has no integrity hash (tampered lockfile indicator)",
                        file=rel_path, line=0,
                        snippet=f"{pkg_path}: no integrity field",
                        category="missing-integrity"
                    ))

        # v1 format: "dependencies" key with nested structure
        if 'dependencies' in data:
            _collect_npm_deps_recursive(data['dependencies'], all_packages)

        # Check ALL transitive deps against IOC list
        if all_packages:
            findings.extend(check_known_ioc_packages(list(all_packages), rel_path))

            # Suspicious npm scopes in transitive deps
            findings.extend(check_suspicious_scopes(list(all_packages), rel_path))

            # Build pkg -> version map and feed it through check_compromised_versions
            # so transitive deps use the same merged IOC database (ioc_manager JSON
            # + in-module fallback) and normalize_version() bypass defenses as every
            # other code path. Without this, chalk@5.6.1 in a package-lock.json
            # transitive dep would silently not flag — the #1 blocker caught in
            # the 2026-04-05 code review.
            pkg_versions = {}
            for pkg in all_packages:
                info = _find_package_info(data, pkg)
                version = info.get('version', '') if info else ''
                if version:
                    pkg_versions[pkg] = version
            if pkg_versions:
                findings.extend(check_compromised_versions(pkg_versions, rel_path))

            # Typosquatting check on transitive deps too
            typos = check_typosquatting(list(all_packages), POPULAR_NPM)
            for suspect, target, score in typos:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Transitive Typosquat Risk: '{suspect}' ~ '{target}'",
                    description=f"Transitive dependency name similarity {score:.0%} to popular package",
                    file=rel_path, line=0,
                    snippet=f"'{suspect}' (transitive) might be typosquatting '{target}'",
                    category="typosquatting"
                ))

    except (json.JSONDecodeError, KeyError, TypeError, OSError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def _collect_npm_deps_recursive(deps_dict, all_packages, depth=0):
    """Recursively collect package names from v1 package-lock.json dependencies."""
    if depth > 20 or len(all_packages) > 50000:  # Prevent infinite recursion and memory exhaustion
        return
    for name, info in deps_dict.items():
        all_packages.add(name)
        if isinstance(info, dict) and 'dependencies' in info:
            _collect_npm_deps_recursive(info['dependencies'], all_packages, depth + 1)


def _find_package_info(data, package_name):
    """Find package info in package-lock.json (works with v1 and v2/v3)."""
    # v2/v3: check packages
    packages = data.get('packages', {})
    for pkg_path, info in packages.items():
        if pkg_path.endswith(f'node_modules/{package_name}'):
            return info
    # v1: check dependencies
    deps = data.get('dependencies', {})
    if package_name in deps:
        return deps[package_name]
    return None


def parse_yarn_lock(filepath, rel_path):
    """Parse yarn.lock to extract all package names."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        all_packages = set()
        # yarn.lock format: "package@version:" or "package@^version, package@~version:"
        for match in re.finditer(r'^"?(@?[^@\s"]+)@', content, re.MULTILINE):
            name = match.group(1)
            if name and not name.startswith('#'):
                all_packages.add(name)

        if all_packages:
            findings.extend(check_known_ioc_packages(list(all_packages), rel_path))
            findings.extend(check_suspicious_scopes(list(all_packages), rel_path))

            # Extract RESOLVED versions by parsing yarn.lock as blocks. Each
            # block starts with a header line like `"chalk@^5.6.0":` (which
            # contains the CONSTRAINT, not the resolved version) followed by
            # a `version "x.y.z"` line with the RESOLVED version.
            #
            # Regex-only parsing (the old approach) extracted the constraint
            # because the header regex matched first. Result: chalk@^5.6.0
            # resolving to 5.6.1 during the Sep 2025 compromise window was
            # NOT detected because the scanner saw "5.6.0" not "5.6.1".
            # Security review A2 (2026-04-05).
            pkg_versions = {}
            current_header_names = []
            for line in content.split('\n'):
                stripped = line.rstrip()
                if not stripped or stripped.startswith('#'):
                    continue
                # Header lines are at column 0 and end with `:`
                if not stripped[0].isspace() and stripped.endswith(':'):
                    header = stripped[:-1].strip('"')
                    # Multiple names separated by ", " share the resolved version
                    current_header_names = []
                    for entry in header.split(', '):
                        entry = entry.strip().strip('"')
                        # Extract bare package name (strip @version constraint)
                        # Scoped: @scope/name@^1.0.0 -> @scope/name
                        if entry.startswith('@'):
                            # second @ separates scope/name from version
                            second_at = entry.find('@', 1)
                            name = entry[:second_at] if second_at > 0 else entry
                        else:
                            at = entry.find('@')
                            name = entry[:at] if at > 0 else entry
                        if name:
                            current_header_names.append(name)
                # Indented `version "x.y.z"` line carries the resolved version
                elif current_header_names and stripped.lstrip().startswith('version'):
                    m = re.search(r'version\s+"([^"]+)"', stripped)
                    if m:
                        resolved = m.group(1)
                        for name in current_header_names:
                            pkg_versions[name] = resolved
                        current_header_names = []
            if pkg_versions:
                findings.extend(check_compromised_versions(pkg_versions, rel_path))

            typos = check_typosquatting(list(all_packages), POPULAR_NPM)
            for suspect, target, score in typos:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Transitive Typosquat Risk: '{suspect}' ~ '{target}'",
                    description=f"Transitive dependency (yarn.lock) similarity {score:.0%}",
                    file=rel_path, line=0,
                    snippet=f"'{suspect}' (transitive) might be typosquatting '{target}'",
                    category="typosquatting"
                ))

    except (UnicodeDecodeError, OSError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def parse_poetry_lock(filepath, rel_path):
    """Parse poetry.lock to extract all package names."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        all_packages = set()
        pkg_versions = {}
        # poetry.lock format: [[package]]\nname = "package-name"\nversion = "x.y.z"
        for match in re.finditer(
            r'^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"',
            content, re.MULTILINE
        ):
            name, version = match.group(1), match.group(2)
            all_packages.add(name)
            pkg_versions[name] = version
        # Also catch packages without version on next line
        for match in re.finditer(r'^\s*name\s*=\s*"([^"]+)"', content, re.MULTILINE):
            all_packages.add(match.group(1))

        if all_packages:
            findings.extend(check_known_ioc_packages(list(all_packages), rel_path))

            # Check all packages against known compromised versions
            if pkg_versions:
                findings.extend(check_compromised_versions(pkg_versions, rel_path))

            typos = check_typosquatting(list(all_packages), POPULAR_PYPI)
            for suspect, target, score in typos:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Transitive Typosquat Risk: '{suspect}' ~ '{target}'",
                    description=f"Transitive dependency (poetry.lock) similarity {score:.0%}",
                    file=rel_path, line=0,
                    snippet=f"'{suspect}' (transitive) might be typosquatting '{target}'",
                    category="typosquatting"
                ))

    except (UnicodeDecodeError, OSError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


def parse_pnpm_lock_file(filepath, rel_path):
    """Parse pnpm-lock.yaml (v6+v9) and check packages against IOC lists.

    This closes the gap flagged in Marc Gadsdon's issue #5 suggestion #4:
    pnpm lockfiles previously got only URL-level scanning via scan_lockfile,
    so version-pinned IOCs (chalk@5.6.1, @nx/devkit@20.9.0, etc) inside
    pnpm transitive deps were never checked.
    """
    findings = []
    try:
        import parse_pnpm_lock as _pnpm
        deps = _pnpm.parse_pnpm_lock(filepath)
    except ImportError as e:
        print(f"[!] parse_pnpm_lock unavailable: {e}", file=sys.stderr)
        return findings
    except (OSError, ValueError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
        return findings

    if not deps:
        return findings

    # All the standard checks
    findings.extend(check_known_ioc_packages(list(deps.keys()), rel_path))
    findings.extend(check_suspicious_scopes(list(deps.keys()), rel_path))
    findings.extend(check_compromised_versions(deps, rel_path))

    # Typosquatting on the package names
    typos = check_typosquatting(list(deps.keys()), POPULAR_NPM)
    for suspect, target, score in typos:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="high",
            title=f"Transitive Typosquat Risk: '{suspect}' ~ '{target}'",
            description=f"Transitive dependency (pnpm-lock.yaml) similarity {score:.0%}",
            file=rel_path, line=0,
            snippet=f"'{suspect}' (transitive) might be typosquatting '{target}'",
            category="typosquatting"
        ))

    return findings


def parse_pipfile_lock(filepath, rel_path):
    """Parse Pipfile.lock to extract all package names."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        all_packages = set()
        pkg_versions = {}
        for section in ('default', 'develop'):
            for pkg_name, pkg_info in data.get(section, {}).items():
                all_packages.add(pkg_name)
                version = pkg_info.get('version', '').lstrip('=')
                if version:
                    pkg_versions[pkg_name] = version

        if all_packages:
            # Check all packages against known compromised versions
            if pkg_versions:
                findings.extend(check_compromised_versions(pkg_versions, rel_path))
            findings.extend(check_known_ioc_packages(list(all_packages), rel_path))
            typos = check_typosquatting(list(all_packages), POPULAR_PYPI)
            for suspect, target, score in typos:
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title=f"Transitive Typosquat Risk: '{suspect}' ~ '{target}'",
                    description=f"Transitive dependency (Pipfile.lock) similarity {score:.0%}",
                    file=rel_path, line=0,
                    snippet=f"'{suspect}' (transitive) might be typosquatting '{target}'",
                    category="typosquatting"
                ))

    except (json.JSONDecodeError, KeyError, TypeError, OSError) as e:
        print(f"[!] Skipped {rel_path}: {e}", file=sys.stderr)
    return findings


# --- User-supplied package list (--package-list) ---

# Hard limits for user-supplied package list files. These are defense-in-
# depth: users should only ever load their own lists, but a malicious repo
# can plant a .package-list file in hopes an automation blindly loads it.

_PACKAGE_LIST_MAX_BYTES = 256 * 1024  # 256KB
_PACKAGE_LIST_MAX_WILDCARDS = 100
_PACKAGE_LIST_MAX_ENTRIES = 10_000

# Strict package entry regex. Enforces:
#   - Optional leading @scope/
#   - Package name: letters, digits, dot, dash, underscore
#   - Optional @version suffix (or @* wildcard for entirely-malicious)
_PACKAGE_ENTRY_RE = re.compile(
    r"^(?P<name>@[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+|[a-zA-Z0-9_.-]+)"
    r"(?:@(?P<version>\*|[A-Za-z0-9_.\-+]+))?$"
)


def load_package_list(path, scanned_repo_path=None):
    """Load a user-supplied package list with strict path and content hardening.

    Format: one `package@version` (or `package@*` wildcard) per line. Lines
    starting with `#` are comments, blank lines are skipped.

    Hardening (all P0 per 2026-04-05 security review):
      - Requires absolute path
      - Rejects symlinks (os.lstat S_ISLNK)
      - Rejects if the realpath is inside the scanned repo (plantable file)
      - Rejects if the file is not owned by the current user (UNIX only)
      - 256KB file size cap
      - Strict regex parser (rejects shell metacharacters, path separators)
      - Wildcard entry cap: 100 max (DoS prevention)
      - Entry cap: 10,000 max
      - NFC unicode normalization
      - Missing file is a hard error (raises), never silently proceeds

    Returns (version_pinned, entirely_malicious) tuple suitable for merging
    into the IOC database:
      - version_pinned: dict[str, dict[str, str]] keyed by lower-cased package
        name -> {version: "user-list-file"}
      - entirely_malicious: set[str] of lower-cased package names

    Raises:
      ValueError: for any hardening violation or parse error.
    """
    import stat as _stat

    if not isinstance(path, str) or not path:
        raise ValueError("--package-list path must be a non-empty string")
    if not os.path.isabs(path):
        raise ValueError(
            f"--package-list path must be absolute, got {path!r}. "
            f"Use an absolute path like /path/to/iocs.txt"
        )

    # Reject symlinks at the top-level (os.lstat to NOT follow)
    try:
        lstat_result = os.lstat(path)
    except OSError as e:
        raise ValueError(f"--package-list file not found or unreadable: {e}")

    if _stat.S_ISLNK(lstat_result.st_mode):
        raise ValueError(
            f"--package-list refuses symlinks (got {path!r}). "
            f"Use the real path directly."
        )

    # Resolve real path to check repo containment + size
    real_path = os.path.realpath(path)

    # If we know the scanned repo, reject lists planted inside it
    if scanned_repo_path:
        scanned_real = os.path.realpath(scanned_repo_path)
        try:
            # commonpath raises if paths are on different drives (Windows)
            common = os.path.commonpath([real_path, scanned_real])
        except ValueError:
            common = None  # different drives; not inside repo by definition
        if common == scanned_real:
            raise ValueError(
                f"--package-list refuses files inside the scanned repo "
                f"(planted-file attack defense). Got {path!r} inside "
                f"{scanned_repo_path!r}."
            )

    # Ownership check (best-effort; skip on non-POSIX)
    try:
        current_uid = os.getuid()
        if lstat_result.st_uid != current_uid:
            raise ValueError(
                f"--package-list refuses files not owned by the current "
                f"user (expected uid {current_uid}, got {lstat_result.st_uid}). "
                f"Likely a planted file."
            )
    except AttributeError:
        pass  # Windows: no uid concept

    # Size cap
    if lstat_result.st_size > _PACKAGE_LIST_MAX_BYTES:
        raise ValueError(
            f"--package-list file too large "
            f"({lstat_result.st_size} bytes, max {_PACKAGE_LIST_MAX_BYTES})"
        )

    # Read and parse. Use O_NOFOLLOW to prevent TOCTOU attacks: between the
    # lstat above and this open, an attacker could symlink the path to a
    # different file. O_NOFOLLOW refuses the open if the path is (now) a
    # symlink, and we verify the opened file's inode matches the lstat
    # result so the underlying file hasn't been swapped. Security review
    # B on load_package_list TOCTOU (2026-04-05).
    try:
        nofollow = getattr(os, 'O_NOFOLLOW', 0)  # 0 on Windows
        fd = os.open(real_path, os.O_RDONLY | nofollow)
    except OSError as e:
        raise ValueError(f"--package-list could not open {path!r}: {e}")
    try:
        fstat_result = os.fstat(fd)
        if (
            fstat_result.st_dev != lstat_result.st_dev
            or fstat_result.st_ino != lstat_result.st_ino
        ):
            raise ValueError(
                f"--package-list file changed between lstat and open "
                f"(possible TOCTOU attack): {path!r}"
            )
        try:
            with os.fdopen(fd, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError as e:
            raise ValueError(f"--package-list could not decode {path!r}: {e}")
    except BaseException:
        # fdopen takes ownership; only close manually on pre-fdopen error
        try:
            os.close(fd)
        except OSError:
            pass
        raise

    version_pinned = {}
    entirely_malicious = set()
    wildcard_count = 0
    entry_count = 0

    for line_no, raw_line in enumerate(content.split('\n'), start=1):
        line = unicodedata.normalize('NFC', raw_line.strip())
        if not line or line.startswith('#'):
            continue
        entry_count += 1
        if entry_count > _PACKAGE_LIST_MAX_ENTRIES:
            raise ValueError(
                f"--package-list has too many entries "
                f"(max {_PACKAGE_LIST_MAX_ENTRIES})"
            )

        m = _PACKAGE_ENTRY_RE.match(line)
        if not m:
            raise ValueError(
                f"--package-list line {line_no}: invalid entry {line!r}. "
                f"Expected 'package@version' or 'package@*' format."
            )

        name = m.group('name').lower()
        version = m.group('version')

        if version is None or version == '*':
            wildcard_count += 1
            if wildcard_count > _PACKAGE_LIST_MAX_WILDCARDS:
                raise ValueError(
                    f"--package-list has too many wildcard entries "
                    f"(max {_PACKAGE_LIST_MAX_WILDCARDS})"
                )
            entirely_malicious.add(name)
        else:
            # Normalize the version so lookups match the scanner's normalized form
            normalized = normalize_version(version) or version
            if name not in version_pinned:
                version_pinned[name] = {}
            version_pinned[name][normalized] = "user-list-file"

    return version_pinned, entirely_malicious


def _merge_user_package_list_into_db(path, repo_path):
    """Load a user-supplied package list and merge into the runtime IOC db.

    Called from main() when --package-list is passed. Mutates the module-level
    _COMPROMISED_VERSIONS_DB and the _FALLBACK_IOC_PACKAGES set so subsequent
    calls to check_compromised_versions / check_known_ioc_packages see the
    user's entries.
    """
    global _COMPROMISED_VERSIONS_DB, _SANDWORM_KNOWN_IOC_PACKAGES

    version_pinned, entirely_malicious = load_package_list(path, scanned_repo_path=repo_path)

    # Force the lazy-loaded db and ioc-packages set to populate, then extend
    db = _compromised_versions_db()
    for pkg, versions in version_pinned.items():
        if pkg not in db:
            db[pkg] = {}
        db[pkg].update(versions)

    if entirely_malicious:
        # Mutate the cached ioc packages set so check_known_ioc_packages sees it
        current = _get_ioc_packages()
        _SANDWORM_KNOWN_IOC_PACKAGES = current | entirely_malicious

    core.emit_status(
        "text",
        f"[*] Loaded {sum(len(v) for v in version_pinned.values())} version-pinned + "
        f"{len(entirely_malicious)} wildcard IOCs from {path}"
    )


def main():
    # Follow the same pattern as scan_integrity.py: when a scanner needs
    # extra CLI flags beyond those in core.parse_common_args, build a local
    # argparse.ArgumentParser in main() with all flags (repo_path, --format,
    # and scanner-specific). That makes --help list every flag and avoids
    # hand-rolled argv pre-filtering.
    import argparse
    parser = argparse.ArgumentParser(description="repo-forensics: Dependency Scanner")
    parser.add_argument('repo_path', help="Path to repository to scan")
    parser.add_argument('--format', choices=['text', 'json', 'summary'],
                        default='text', help="Output format (default: text)")
    parser.add_argument('--package-list', default=None, metavar='FILE',
                        help=("Absolute path to a user-supplied IOC file "
                              "(one 'package@version' or 'package@*' per "
                              "line, # comments allowed). File must be "
                              "outside the scanned repo, owned by current "
                              "user, not a symlink, and under 256KB."))
    args = parser.parse_args()
    args.repo_path = os.path.abspath(args.repo_path)
    repo_path = args.repo_path

    # Apply --package-list before any scanning so the IOC db reflects user entries
    if args.package_list:
        try:
            _merge_user_package_list_into_db(args.package_list, repo_path)
        except ValueError as e:
            print(f"[!] --package-list rejected: {e}", file=sys.stderr)
            sys.exit(2)

    core.emit_status(args.format, f"[*] Scanning dependencies in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True, skip_lockfiles=False):
        basename = os.path.basename(file_path)

        if basename == 'package.json':
            all_findings.extend(scan_package_json(file_path, rel_path))
        elif basename == 'package-lock.json':
            all_findings.extend(scan_lockfile(file_path, rel_path))
            all_findings.extend(parse_package_lock_json(file_path, rel_path))
        elif basename == 'yarn.lock':
            all_findings.extend(scan_lockfile(file_path, rel_path))
            all_findings.extend(parse_yarn_lock(file_path, rel_path))
        elif basename == 'pnpm-lock.yaml':
            all_findings.extend(scan_lockfile(file_path, rel_path))
            all_findings.extend(parse_pnpm_lock_file(file_path, rel_path))
        elif basename == 'poetry.lock':
            all_findings.extend(parse_poetry_lock(file_path, rel_path))
        elif basename == 'Pipfile.lock':
            all_findings.extend(parse_pipfile_lock(file_path, rel_path))
        elif basename in ('requirements.txt', 'requirements-dev.txt', 'requirements-test.txt',
                          'constraints.txt', 'pyproject.toml', 'Pipfile'):
            all_findings.extend(scan_python_deps(file_path, rel_path))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
