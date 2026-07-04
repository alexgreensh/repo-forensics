# Dead-anchor benign fixture (live-and-owned references)

This file exists to verify `scan_dead_anchors.py` stays SILENT on anchors that
are live and owned. Every reference below points at a stable, real target whose
lifecycle is owner-controlled (avoids third-party CI flakiness). Under the
dead_anchors LO branch (registry/API 200, registered domain) it must produce
ZERO findings.

## Stable GitHub references

Project source lives at github.com/alexgreensh/repo-forensics and can also be
referenced as github:alexgreensh/repo-forensics for the shorthand install form.

## Live package references

Install the JavaScript helper with `npm install lodash` and the Python HTTP
client with `pip install requests`. Both are long-lived, widely used packages.

## Live documentation domains

See the docs at https://docs.python.org/3/library/os.html and the registry at
https://pypi.org/project/requests for details. These are safe-allowlisted and
are never probed.
