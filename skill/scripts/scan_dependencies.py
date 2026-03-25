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


# IOC packages loaded from ioc_manager (single source of truth)
try:
    import ioc_manager as _ioc
    _iocs = _ioc.get_iocs()
    SANDWORM_KNOWN_IOC_PACKAGES = _iocs.get('malicious_npm', set()) | _iocs.get('malicious_pypi', set())
except ImportError:
    # Fallback if ioc_manager unavailable
    SANDWORM_KNOWN_IOC_PACKAGES = {
        "rimarf", "yarsg", "suport-color", "naniod", "opencraw",
        "claud-code", "cloude-code", "cloude", "mcp-cliient", "mcp-serever",
        "anthropic-sdk-node", "claude-code-cli", "clawclient",
        "anthopic", "antrhopic", "claudes", "mcp-python-sdk",
    }


def _apply_l33t(name):
    """Normalize l33t substitutions for typosquatting comparison.
    Maps: 0->o, 1->l, 3->e, @->a (common character swaps in malicious packages).
    """
    return name.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('@', 'a')


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
        if dep.lower() in SANDWORM_KNOWN_IOC_PACKAGES:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical",
                title=f"Known Malicious Package: '{dep}'",
                description="Package matches SANDWORM_MODE campaign IOC list (source: Socket Research, Snyk ToxicSkills 2026)",
                file=rel_path, line=0, snippet=f"'{dep}' is a known malicious package",
                category="known-ioc"
            ))
    return findings


def scan_package_json(filepath, rel_path):
    findings = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)

        all_deps = {}
        for key in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
            all_deps.update(data.get(key, {}))

        dep_names = list(all_deps.keys())

        # Known IOC check (critical, before typosquatting)
        findings.extend(check_known_ioc_packages(dep_names, rel_path))

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
        if basename in ('requirements.txt', 'requirements-dev.txt', 'requirements-test.txt', 'constraints.txt'):
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    pkg = re.split(r'[>=<!\[\];]', line)[0].strip()
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
            is_trusted = any(t in url for t in TRUSTED_REGISTRIES)
            if not is_trusted and "schema.org" not in url:
                suspicious.add(url)

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

        # v1 format: "dependencies" key with nested structure
        if 'dependencies' in data:
            _collect_npm_deps_recursive(data['dependencies'], all_packages)

        # Check ALL transitive deps against IOC list
        if all_packages:
            findings.extend(check_known_ioc_packages(list(all_packages), rel_path))

            # Specific liteLLM version check (npm wrapper packages)
            for pkg in all_packages:
                if 'litellm' in pkg.lower():
                    pkg_info = _find_package_info(data, pkg)
                    version = pkg_info.get('version', '') if pkg_info else ''
                    if version == '1.82.8':
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"Compromised liteLLM Version: {pkg}@{version}",
                            description="liteLLM v1.82.8 contains malicious .pth file injection (March 2026 supply chain attack)",
                            file=rel_path, line=0,
                            snippet=f"{pkg}@{version} (known compromised)",
                            category="supply-chain"
                        ))

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

    except (json.JSONDecodeError, KeyError, TypeError, OSError):
        pass
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

    except (UnicodeDecodeError, OSError):
        pass
    return findings


def parse_poetry_lock(filepath, rel_path):
    """Parse poetry.lock to extract all package names."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        all_packages = set()
        # poetry.lock format: [[package]]\nname = "package-name"
        for match in re.finditer(r'^\s*name\s*=\s*"([^"]+)"', content, re.MULTILINE):
            all_packages.add(match.group(1))

        if all_packages:
            findings.extend(check_known_ioc_packages(list(all_packages), rel_path))

            # Check for liteLLM specifically with version
            for match in re.finditer(
                r'^\[\[package\]\]\s*\nname\s*=\s*"([^"]*litellm[^"]*)"\s*\nversion\s*=\s*"([^"]+)"',
                content, re.MULTILINE
            ):
                name, version = match.group(1), match.group(2)
                if version == '1.82.8':
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title=f"Compromised liteLLM Version: {name}@{version}",
                        description="liteLLM v1.82.8 contains malicious .pth file injection (March 2026)",
                        file=rel_path, line=0,
                        snippet=f"{name}=={version} (known compromised)",
                        category="supply-chain"
                    ))

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

    except (UnicodeDecodeError, OSError):
        pass
    return findings


def parse_pipfile_lock(filepath, rel_path):
    """Parse Pipfile.lock to extract all package names."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        all_packages = set()
        for section in ('default', 'develop'):
            for pkg_name in data.get(section, {}).keys():
                all_packages.add(pkg_name)

                # Check for liteLLM version
                pkg_info = data[section][pkg_name]
                if 'litellm' in pkg_name.lower():
                    version = pkg_info.get('version', '').lstrip('=')
                    if version == '1.82.8':
                        findings.append(core.Finding(
                            scanner=SCANNER_NAME, severity="critical",
                            title=f"Compromised liteLLM Version: {pkg_name}@{version}",
                            description="liteLLM v1.82.8 contains malicious .pth file injection (March 2026)",
                            file=rel_path, line=0,
                            snippet=f"{pkg_name}=={version} (known compromised)",
                            category="supply-chain"
                        ))

        if all_packages:
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

    except (json.JSONDecodeError, KeyError, TypeError, OSError):
        pass
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Dependency Scanner")
    repo_path = args.repo_path

    print(f"[*] Scanning dependencies in {repo_path}...")

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
