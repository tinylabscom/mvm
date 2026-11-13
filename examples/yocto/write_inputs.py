"""Record the exact representative Yocto archive and layer bytes for pack import."""

import argparse
import hashlib
import json
import stat
from pathlib import Path

POKY_REVISION = "72983ac391008ebceb45edc7a8f0f6d5f4fe715c"


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_layer(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"layer contains a non-regular file: {path}")
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        digest.update((metadata.st_mode & 0o777).to_bytes(2, "little"))
        digest.update(metadata.st_size.to_bytes(8, "little"))
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def inputs(archive: Path, layer: Path) -> dict:
    if not archive.is_file() or not layer.is_dir():
        raise ValueError("the Yocto archive and meta-mvm layer must exist")
    return {
        "schema_version": 1,
        "target": "aarch64-linux",
        "machine": "qemuarm64",
        "layers": {"poky": POKY_REVISION, "meta-mvm": digest_layer(layer)},
        "rootfs_archive_sha256": digest_file(archive),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("layer", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    record = inputs(args.archive, args.layer)
    with args.out.open("x", encoding="utf-8") as output:
        json.dump(record, output, sort_keys=True, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
