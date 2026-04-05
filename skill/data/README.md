# skill/data/

Static IOC data shipped with the repo-forensics skill. Files here are loaded
at runtime by `ioc_manager.py`. They are NOT fetched from external sources
at scan time and they MUST NOT be loaded from paths outside this directory.

## What lives here

- `compromised_versions.json` — version-pinned and entirely-malicious package
  IOCs organized by supply-chain campaign. See the file's top-level
  `description` and `schema_version` fields. Loaded by
  `ioc_manager._load_compromised_versions_file()`.

## Schema versioning

Every file here must declare a `schema_version` field at the top level.
Loaders gate on the major version — e.g. `ioc_manager` accepts `1.x` and
rejects `2.x` with a warning. Bump the major version when making a
backwards-incompatible change to the structure.

## Provenance

Entries are sourced from public vendor research (Socket, Snyk, Check Point,
JFrog, ReversingLabs, CISA, OWASP). Each campaign in `compromised_versions.json`
carries a `reference` URL pointing to the original disclosure.

## Review discipline

This directory is `git`-tracked. Changes are reviewed line-by-line like any
other source file. Do not drop large untrusted datasets here; they belong
in the remote IOC feed (`iocs/latest.json` on GitHub) which has its own
update channel.
