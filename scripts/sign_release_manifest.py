#!/usr/bin/env python3
"""Sign the exact repo-forensics checksum manifest for stable payload promotion.

The private seed stays outside the repository. The verifier pins only the
public key. Run after verify_install.py --generate and before packaging.
"""

import argparse
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "skills" / "repo-forensics" / "checksums.json"
DEFAULT_KEY = Path.home() / ".config" / "repo-forensics" / "release-signing-seed"
EXPECTED_PUBLIC_KEY = "c86f717c5f3293da397435cde3d8ab49cddba2165eddbd47c6fb62aad3e9526a"


def _signer():
    path = ROOT / "scripts" / "_ed25519_sign.py"
    spec = importlib.util.spec_from_file_location("repo_forensics_release_signer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description="Sign repo-forensics checksums.json")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--key-file", default=str(DEFAULT_KEY))
    args = parser.parse_args()
    manifest = Path(args.manifest)
    key_file = Path(args.key_file)
    seed = bytes.fromhex(key_file.read_text(encoding="utf-8").strip())
    signer = _signer()
    _private, public = signer.keypair(seed)
    if public.hex() != EXPECTED_PUBLIC_KEY:
        raise SystemExit("release signing key does not match pinned public key")
    signature = signer.sign(manifest.read_bytes(), seed, public)
    output = manifest.with_name(manifest.name + ".sig")
    output.write_bytes(signature)
    output.chmod(0o644)
    print(f"signed {manifest} -> {output}")


if __name__ == "__main__":
    main()
