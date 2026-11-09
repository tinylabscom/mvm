#!/usr/bin/env python3
"""PR-only synthetic base input; never an image-set release or launch credential."""

import gzip
import hashlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

ISSUER = "https://token.actions.githubusercontent.com"


def create(root: Path) -> None:
    root.mkdir()
    body = io.BytesIO()
    with tarfile.open(fileobj=body, mode="w") as archive:
        marker = tarfile.TarInfo("etc/mvm/base-image-contract")
        marker.mode, marker.size = 0o444, 2
        archive.addfile(marker, io.BytesIO(b"1\n"))
        worker = tarfile.TarInfo("home/mvm-worker")
        worker.type = tarfile.DIRTYPE
        worker.uid = worker.gid = 901
        archive.addfile(worker)
    payload = gzip.compress(body.getvalue(), mtime=0)
    (root / "rootfs.tar.gz").write_bytes(payload)
    (root / "base.json").write_text(json.dumps({
        "schema": "mvm.synthetic-composition-base/v1",
        "arch": "x86_64",
        "archive_sha256": hashlib.sha256(payload).hexdigest(),
        "archive_size": len(payload),
    }, sort_keys=True, separators=(",", ":")))


def verify(root: Path, identity: str) -> None:
    manifest = root / "base.json"
    archive = root / "rootfs.tar.gz"
    bundle = root / "base.bundle"
    if manifest.stat().st_size > 4096 or not 0 < archive.stat().st_size <= 2 * 1024**3:
        raise ValueError("synthetic base metadata or archive exceeds its bound")
    subprocess.run([
        "cosign", "verify-blob", "--bundle", str(bundle),
        "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER,
        str(manifest),
    ], check=True)
    value = json.loads(manifest.read_bytes())
    if set(value) != {"schema", "arch", "archive_sha256", "archive_size"} or (
        value["schema"], value["arch"], value["archive_size"]
    ) != ("mvm.synthetic-composition-base/v1", "x86_64", archive.stat().st_size):
        raise ValueError("synthetic base descriptor is not the expected closed shape")
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != value["archive_sha256"]:
        raise ValueError("synthetic base archive differs from its signed descriptor")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "create":
        create(Path(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "verify":
        verify(Path(sys.argv[2]), sys.argv[3])
    else:
        raise SystemExit("usage: test-composable-base-input.py create DIR | verify DIR OIDC_IDENTITY")
