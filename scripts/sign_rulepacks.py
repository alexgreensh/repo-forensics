#!/usr/bin/env python3
"""
sign_rulepacks.py - DEV-ONLY publisher: build + sign the rule-pack bundle and
sign the IOC feed.

NEVER shipped or loaded by the skill at scan time.

What it does:
  1. Builds iocs/rulepacks.json by bundling every pack under
     skills/repo-forensics/data/rulepacks/ into one envelope:
        {schema_version, generated, bundle_version, packs: {name: {pack_version, rules}}}
  2. Signs the EXACT raw bytes of iocs/rulepacks.json -> iocs/rulepacks.json.sig
  3. Signs the EXACT raw bytes of iocs/latest.json     -> iocs/latest.json.sig

Signatures are detached, raw 64-byte Ed25519 over the file's literal bytes (no
parse-and-reserialize). The verify side re-reads those exact bytes.

Usage:
    python3 scripts/sign_rulepacks.py --seed-hex <PRIVATE_SEED_HEX> \\
        [--pub-hex <PUBLIC_KEY_HEX>] [--bundle-version N]

The private seed is supplied at sign time (kept offline); it is never stored in
the repo. --pub-hex (optional) cross-checks the seed matches the pinned pubkey.
"""

import argparse
import glob
import json
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "scripts"))
import _ed25519_sign  # noqa: E402  (dev-only sibling)

_RULEPACK_DIR = os.path.join(
    _REPO_ROOT, "skills", "repo-forensics", "data", "rulepacks"
)
_IOCS_DIR = os.path.join(_REPO_ROOT, "iocs")
_BUNDLE_PATH = os.path.join(_IOCS_DIR, "rulepacks.json")
_LATEST_PATH = os.path.join(_IOCS_DIR, "latest.json")

# Bundle envelope schema; major version is gated on the verify side.
BUNDLE_SCHEMA_VERSION = "1.0"


def _published_pack_payload(pack):
    """Fields whose change requires a new published pack version."""
    return {"schema_version": pack.get("schema_version", "1.0"),
            "rules": pack.get("rules", [])}


def build_bundle(bundle_version, generated=None, previous_bundle=None):
    """Build a bundle whose publication versions beat installed versions.

    A publication is justified by actual rule-content change somewhere in the
    bundle. Once justified, every carried pack advances above both its shipped
    and previously published version so every entry is overlay-capable. This
    prevents a mixed bundle from silently leaving equal-version packs inert.
    """
    if previous_bundle is None:
        try:
            with open(_BUNDLE_PATH, "r", encoding="utf-8") as f:
                previous_bundle = json.load(f)
        except (OSError, ValueError):
            previous_bundle = {}
    prior_packs = previous_bundle.get("packs", {}) if isinstance(previous_bundle, dict) else {}
    sources = {}
    for path in sorted(glob.glob(os.path.join(_RULEPACK_DIR, "*.json"))):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        name = data.get("pack") or os.path.splitext(os.path.basename(path))[0]
        sources[name] = data
    changed = any(
        name not in prior_packs
        or _published_pack_payload(prior_packs[name]) != _published_pack_payload(data)
        for name, data in sources.items()
    )
    packs = {}
    for name, data in sources.items():
        shipped_version = data.get("pack_version", 1)
        prior = prior_packs.get(name, {}) if isinstance(prior_packs, dict) else {}
        prior_version = prior.get("pack_version", 0) if isinstance(prior, dict) else 0
        publish_version = (max(shipped_version, prior_version) + 1
                           if changed else prior_version)
        packs[name] = {"pack_version": publish_version,
                       **_published_pack_payload(data)}
    import datetime
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "generated": generated or datetime.date.today().isoformat(),
        "bundle_version": bundle_version,
        "packs": packs,
    }


def _write_and_sign(path, raw_bytes, priv, pub):
    """Write raw_bytes to path, then write path + '.sig' (detached signature)."""
    with open(path, "wb") as f:
        f.write(raw_bytes)
    sig = _ed25519_sign.sign(raw_bytes, priv, pub)
    with open(path + ".sig", "wb") as f:
        f.write(sig)


def main():
    ap = argparse.ArgumentParser(description="Build + sign feeds (dev-only).")
    key = ap.add_mutually_exclusive_group()
    key.add_argument("--seed-hex", help="Private seed hex (legacy; prefer --seed-file).")
    key.add_argument("--seed-file", help="Path to offline 32-byte or hex seed file.")
    ap.add_argument("--build-only", action="store_true",
                    help="Build unsigned bundle; maintainer signs in a later step.")
    ap.add_argument("--pub-hex", default=None, help="Expected public key hex (cross-check).")
    ap.add_argument("--bundle-version", type=int, default=None,
                    help="Bundle envelope version (default: prior + 1).")
    ap.add_argument("--allow-unchanged", action="store_true",
                    help="Permit re-signing a bundle with no pack-content changes.")
    args = ap.parse_args()

    if not args.build_only and not (args.seed_hex or args.seed_file):
        ap.error("--seed-file (preferred) or --seed-hex is required unless --build-only is used")
    if args.seed_file:
        seed_raw = open(os.path.expanduser(args.seed_file), "rb").read().strip()
        try:
            priv = bytes.fromhex(seed_raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            priv = seed_raw
    else:
        priv = bytes.fromhex(args.seed_hex) if args.seed_hex else None
    if priv is not None and len(priv) != 32:
        ap.error("feed signing seed must be exactly 32 bytes (raw or 64 hex characters)")
    pub = _ed25519_sign.keypair(priv)[1] if priv else None
    if args.pub_hex and (pub is None or pub.hex() != args.pub_hex.lower()):
        print(f"[!] seed-derived pubkey {pub.hex()} != --pub-hex {args.pub_hex}",
              file=sys.stderr)
        return 1

    os.makedirs(_IOCS_DIR, exist_ok=True)

    # 1+2. Build + sign the rule-pack bundle over its exact serialized bytes.
    try:
        with open(_BUNDLE_PATH, "r", encoding="utf-8") as f:
            previous = json.load(f)
    except (OSError, ValueError):
        previous = {}
    prior_version = previous.get("bundle_version", 0) if isinstance(previous, dict) else 0
    bundle = build_bundle(args.bundle_version or prior_version + 1,
                          previous_bundle=previous)
    changed = [name for name, pack in bundle["packs"].items()
               if ((previous.get("packs", {}) if isinstance(previous, dict) else {})
                   .get(name)) != pack]
    if not changed and not args.allow_unchanged:
        print("[!] no rule-pack content changed; refusing a hollow freshness bump",
              file=sys.stderr)
        return 2
    bundle_bytes = json.dumps(bundle, indent=2, sort_keys=True).encode("utf-8")
    if args.build_only:
        with open(_BUNDLE_PATH, "wb") as f:
            f.write(bundle_bytes)
        print(f"[+] wrote unsigned {_BUNDLE_PATH} ({len(bundle_bytes)} bytes; "
              f"{len(bundle['packs'])} packs)")
        return 0
    _write_and_sign(_BUNDLE_PATH, bundle_bytes, priv, pub)
    print(f"[+] wrote {_BUNDLE_PATH} ({len(bundle_bytes)} bytes) + .sig "
          f"({len(bundle['packs'])} packs)")

    # 3. Sign the IOC feed over its EXACT on-disk bytes (no reserialize).
    if os.path.isfile(_LATEST_PATH):
        with open(_LATEST_PATH, "rb") as f:
            latest_bytes = f.read()
        sig = _ed25519_sign.sign(latest_bytes, priv, pub)
        with open(_LATEST_PATH + ".sig", "wb") as f:
            f.write(sig)
        print(f"[+] signed {_LATEST_PATH} ({len(latest_bytes)} bytes) -> .sig")
    else:
        print(f"[!] {_LATEST_PATH} missing; skipped IOC signing", file=sys.stderr)

    print(f"[i] pubkey: {pub.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
