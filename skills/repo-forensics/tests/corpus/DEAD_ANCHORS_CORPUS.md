# Dead-Anchor Test Corpus — status & TODO

Fixtures backing `scan_dead_anchors.py`. All unit/integration tests monkeypatch
the network (vuln_feed's `urllib.request.urlopen` chokepoint + `socket.gethostbyname`);
NO test in `tests/test_dead_anchors_*.py` ever performs a real HTTP request or
DNS lookup.

## Committed benign fixtures (in `benign/`)

- `dead_anchors_live_refs.md` — live GitHub owner/repo + `github:` shorthand,
  live npm (`lodash`) / PyPI (`requests`) install commands, safe-allowlisted docs
  domains. Asserted to produce ZERO findings under the LO branch
  (`test_scan_dead_anchors.py::test_benign_corpus_all_lo_zero_findings`, network
  mocked to 200/registered). Budgeted at zero for the per-file committed-corpus
  gate too (see `budgets.json`).

## Positive (teeth) coverage

Lives in `tests/test_scan_dead_anchors.py` and `tests/test_dead_anchors_probe.py`
(canned 404 / NXDOMAIN / provider-fingerprint bodies per anchor type → correct
CRITICAL/HIGH/MEDIUM finding). Negative coverage: canned 200/registered → zero
findings; canned 403/429/5xx/timeout → zero findings + no crash (never-hard-fail).

## TODO — external datasets (MANUAL, security-gated — do NOT automate)

These are deliberately NOT wired into CI yet. Each requires a manual, blocking
`repo-forensics`-first security review before any external bytes enter this
corpus (Alex's standing external-code rule applied to the test data itself).

1. **SkillSieve** (`github.com/xiaohou521/skillsieve`, 49,592 skills + 400
   labeled). Before copying ANY labeled skill folder into `tests/corpus/`: clone
   into an isolated temp dir, run a full `repo-forensics` scan on the clone,
   review findings, and only then extract reviewed folders. Do NOT clone/fetch
   from a test or CI path.

2. **ToxicSkills 8 live-malicious IOC URLs** (Snyk, e.g. `clawhub.ai/zaycv/clawhud`).
   These belong in `ioc_manager.py`'s SIGNED remote IOC feed (a feed-authoring
   step publishing to the `iocs/latest.json` the manager pulls — NOT a direct
   edit to any file under `scripts/`/`data/`). Once fed, add a negative-control
   test asserting `scan_dead_anchors` does not double-fire or conflict with
   `ioc_manager`'s existing IOC flag on the same anchor (IOC-badness ≠
   claimability; distinguishable by `scanner` field + `category`).
