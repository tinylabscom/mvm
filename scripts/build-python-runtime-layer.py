#!/usr/bin/env python3
"""Repack digest-pinned, static CPython for one Linux guest architecture.

This is an unsigned producer, not a pack publisher. The registry signer must
bind the resulting tar's exact size and SHA-256 to its own signed descriptor.
"""

import argparse
import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile

SOURCE_BASE = "https://github.com/astral-sh/python-build-standalone/releases/download/20261026/"
SOURCES = {
    "x86_64": (
        SOURCE_BASE + "cpython-3.13.18%2B20261026-x86_64-unknown-linux-musl-lto%2Bstatic-full.tar.zst",
        "e0bb0840e127aa95dbb1212202a29cde715711ae6826132e548f5eb04a958533",
        62,
    ),
    "aarch64": (
        SOURCE_BASE + "cpython-3.13.18%2B20261026-aarch64-unknown-linux-musl-lto%2Bstatic-full.tar.zst",
        "9968a4b1fc3db172ba3b3ab36235fa76fab91c3ec83204f269adca756c87261d",
        183,
    ),
}
SOURCE_SIZE_LIMIT = 80 * 1024 * 1024
TREE_SIZE_LIMIT = 256 * 1024 * 1024
STDLIB = "python/install/lib/python3.13/"
SKIP = frozenset({"test", "site-packages", "ensurepip", "idlelib", "turtledemo", "tkinter"})
REQUIRED = frozenset({
    "usr/bin/python3",
    "usr/lib/python3.13/encodings/__init__.py",
    "usr/lib/python3.13/importlib/__init__.py",
})


def snapshot(source: Path, expected: str, output: Path) -> None:
    """Read a regular, non-symlink source once into a private, digest-checked file."""
    fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as original, output.open("wb") as held:
        info = os.fstat(original.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= SOURCE_SIZE_LIMIT:
            raise ValueError("Python source must be a bounded regular file")
        digest = hashlib.sha256()
        for chunk in iter(lambda: original.read(1024 * 1024), b""):
            digest.update(chunk)
            held.write(chunk)
        if held.tell() != info.st_size or digest.hexdigest() != expected:
            raise ValueError("Python source bytes differ from the pinned digest")


def selected_files(source: io.BufferedReader, arch: str) -> list[tuple[str, int, bytes]]:
    """Select runtime-only files without extracting upstream paths to the host."""
    process = subprocess.Popen(
        ["zstd", "-dc"], stdin=source, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    if process.stdout is None:
        raise OSError("Python source decompressor has no output stream")
    files = {}
    size = 0
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                if member.name == "python/install/bin/python3.13":
                    path = "usr/bin/python3"
                elif member.name.startswith(STDLIB):
                    relative = member.name[len(STDLIB):]
                    if relative.split("/")[0] in SKIP or relative.startswith("config-"):
                        continue
                    path = "usr/lib/python3.13/" + relative
                else:
                    continue
                if (not path or any(part in ("", ".", "..") for part in path.split("/"))
                        or path in files or not member.isfile() or member.mode & 0o6000):
                    raise ValueError("unsafe or duplicate Python runtime entry")
                if member.size > 64 * 1024 * 1024 or size + member.size > TREE_SIZE_LIMIT:
                    raise ValueError("Python runtime exceeds its unpacked size limit")
                content = archive.extractfile(member)
                if content is None:
                    raise ValueError("missing Python runtime bytes")
                data = content.read(member.size + 1)
                if len(data) != member.size:
                    raise ValueError("truncated Python runtime file")
                size += len(data)
                files[path] = (0o755 if member.mode & 0o111 else 0o644, data)
        if process.wait() != 0:
            raise ValueError("Python source decompression failed")
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    if not REQUIRED.issubset(files):
        raise ValueError("Python runtime is missing its executable or standard library")
    binary = files["usr/bin/python3"][1]
    if (len(binary) < 20 or binary[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(binary[18:20], "little") != SOURCES[arch][2]):
        raise ValueError("Python runtime ELF architecture differs from the pinned source")
    return [(path, *files[path]) for path in sorted(files)]


def write_layer(entries: list[tuple[str, int, bytes]], output: Path) -> str:
    """Canonical plain tar accepted by the runtime-layer composer."""
    digest = hashlib.sha256()
    with output.open("wb") as target:
        with tarfile.open(fileobj=target, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for path, mode, data in entries:
                member = tarfile.TarInfo(path)
                member.mode = mode
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    with output.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(source: Path, destination: Path, expected: str, arch: str = "x86_64") -> tuple[str, int]:
    """Refuse an existing destination and publish only a complete checked layer."""
    if arch not in SOURCES:
        raise ValueError("unsupported Python runtime architecture")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Python layer destination already exists")
    with tempfile.TemporaryDirectory(prefix="mvm-python-input-") as private:
        held = Path(private) / "source.tar.zst"
        snapshot(source, expected, held)
        with held.open("rb") as source_file:
            entries = selected_files(source_file, arch)
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".python-layer-", delete=False) as tmp:
            staged = Path(tmp.name)
        try:
            digest = write_layer(entries, staged)
            size = staged.stat().st_size
            if not 0 < size <= 2 * 1024 * 1024 * 1024:
                raise ValueError("Python layer exceeds its signed descriptor size limit")
            os.link(staged, destination)  # never overwrite a concurrent writer
        finally:
            staged.unlink(missing_ok=True)
    return digest, size


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=SOURCES, help="Linux guest architecture")
    parser.add_argument("source", type=Path, help="pinned upstream tar.zst")
    parser.add_argument("destination", type=Path, help="new, unsigned layer.tar")
    args = parser.parse_args()
    source_url, source_sha256, _ = SOURCES[args.arch]
    sha256, size = build(args.source, args.destination, source_sha256, args.arch)
    print(f"arch={args.arch} archive_sha256={sha256} archive_size={size} source_sha256={source_sha256} source_url={source_url}")
