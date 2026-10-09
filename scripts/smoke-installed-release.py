#!/usr/bin/env python3
"""Exercise an installed CLI/hostlib and its preserved guest-runtime payload."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.request


def runtime_digest(archive: Path) -> str:
    checksum = Path(str(archive) + ".sha256").read_text().split()
    sha256 = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha256.update(chunk)
    digest = sha256.hexdigest()
    if checksum != [digest, archive.name]:
        raise RuntimeError("installed guest archive differs from its release checksum")
    if not Path(str(archive) + ".bundle").read_bytes():
        raise RuntimeError("installed guest archive signature bundle is empty")
    return digest


def fetch_verified_runtime(cli: Path, version: str) -> str:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version):
        raise RuntimeError("invalid release version")
    name = f"mvm-guest-bins-v{version}.tar.gz"
    base = f"https://github.com/tinylabscom/mvm/releases/download/v{version}"
    # Do not mutate a package-manager-owned prefix or pretend this exercises
    # the lazy cache or a guest boot. The installed binary verifies real
    # fetched release bytes with its embedded trust root.
    with tempfile.TemporaryDirectory(prefix="mvm-runtime-smoke-") as temporary:
        root = Path(temporary)
        for suffix in ("", ".sha256", ".bundle", ".sha256.bundle"):
            request = urllib.request.Request(
                f"{base}/{name}{suffix}", headers={"User-Agent": "mvm-release-smoke"}
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                with (root / (name + suffix)).open("wb") as target:
                    shutil.copyfileobj(response, target)
        archive = root / name
        digest = runtime_digest(archive)
        env = dict(os.environ, HOME=str(root / "home"), MVM_HOME=str(root / "home" / ".mvm"))
        (root / "home").mkdir()
        for key in ("MVM_SKIP_COSIGN_VERIFY", "MVM_SKIP_VERIFY", "MVM_SKIP_HASH_VERIFY"):
            env.pop(key, None)
        for artifact in (archive, Path(str(archive) + ".sha256")):
            subprocess.run(
                [cli, "env", "verify-release", artifact, "--tag", f"v{version}"],
                check=True, env=env,
            )
        return digest


def smoke(prefix: Path, version: str, *, runtime_fetch: bool = False) -> None:
    cli = (prefix / "bin" / "mvmctl").resolve(strict=True)
    reported = subprocess.check_output([cli, "--version"], text=True).strip()
    if reported != f"mvmctl {version}":
        raise RuntimeError(f"installed version mismatch: {reported}")
    subprocess.run([cli, "--help"], check=True, stdout=subprocess.DEVNULL)
    extension = "dylib" if platform.system() == "Darwin" else "so"
    library_path = cli.parent / f"libmvm_hostlib.{extension}"
    library = ctypes.CDLL(str(library_path))
    library.mvm_hostlib_abi_version.argtypes = []
    library.mvm_hostlib_abi_version.restype = ctypes.c_uint32
    abi = library.mvm_hostlib_abi_version()
    if abi >> 16 != 1:
        raise RuntimeError(f"incompatible installed hostlib ABI: {abi:#x}")
    name = f"mvm-guest-bins-v{version}.tar.gz"
    directories = [cli.parent / "guest-runtime"]
    if cli.parent.name == "bin":
        directories.append(cli.parent.parent / "lib" / "mvmctl" / "guest-runtime")
    archive = directories[0] / name
    for directory in directories:
        candidate = directory / name
        components = [Path(str(candidate) + suffix) for suffix in ("", ".sha256", ".bundle")]
        if any(path.exists() or path.is_symlink() for path in components):
            archive = candidate
            break
    digest = fetch_verified_runtime(cli, version) if runtime_fetch else runtime_digest(archive)
    # Cryptographic verification runs at recipe acquisition and guest-runtime
    # admission; this witness exercises the package manager's installed bytes.
    print(json.dumps({"cli": str(cli), "version": version, "library": str(library_path),
                      "abi": abi, "guest_runtime_sha256": digest,
                      "guest_runtime_source": "fetched-and-authenticated" if runtime_fetch else "package",
                      "guest_boot_witnessed": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prefix", type=Path)
    parser.add_argument("version")
    parser.add_argument("--runtime-fetch", action="store_true",
                        help="fetch the exact runtime and authenticate it using the installed CLI")
    args = parser.parse_args()
    smoke(args.prefix, args.version, runtime_fetch=args.runtime_fetch)
