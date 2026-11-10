"""
make_manifest.py -- the release key and the signed update manifest (plan 5.6; agent.py #36).

    python packaging/make_manifest.py new-key KEYFILE
        Once. Writes a new Ed25519 release key to KEYFILE (keep it OUT of the repo, e.g.
        %USERPROFILE%\\.haltline\\release.key) and prints HALTLINE_UPDATE_PUBKEY for build.ps1.

    python packaging/make_manifest.py sign KEYFILE INSTALLER URL [OUTDIR]
        Writes OUTDIR/latest.json and latest.json.sig (OUTDIR defaults to build/). Upload both
        next to each other at HALTLINE_UPDATE_URL, and the installer at URL.
"""
import base64
import hashlib
import json
import os
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def pub_b64(key):
    return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def new_key(path):
    if os.path.exists(path):
        sys.exit(f"{path} exists; refusing to overwrite a release key")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    with open(path, "w", encoding="ascii") as f:
        f.write(base64.b64encode(seed).decode())
    print(f"HALTLINE_UPDATE_PUBKEY={pub_b64(key)}")


def sign(keyfile, installer, url, outdir="build"):
    if not url.startswith("https://"):
        sys.exit("the installer URL must be https://")
    with open(keyfile, encoding="ascii") as f:
        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(f.read().strip()))
    version = re.search(r"(\d+\.\d+\.\d+)", os.path.basename(installer))
    if not version:
        sys.exit("installer name must contain its version, e.g. Haltline-Setup-0.2.0.exe")
    with open(installer, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    raw = json.dumps({"version": version.group(1), "installer": url, "sha256": sha}, indent=1).encode()
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "latest.json"), "wb") as f:
        f.write(raw)
    with open(os.path.join(outdir, "latest.json.sig"), "w", encoding="ascii") as f:
        f.write(base64.b64encode(key.sign(raw)).decode())
    print(f"signed {version.group(1)} ({sha[:12]}...) with {pub_b64(key)}")


if __name__ == "__main__":
    if sys.argv[1:2] == ["new-key"] and len(sys.argv) == 3:
        new_key(sys.argv[2])
    elif sys.argv[1:2] == ["sign"] and len(sys.argv) in (5, 6):
        sign(*sys.argv[2:])
    else:
        sys.exit(__doc__)
