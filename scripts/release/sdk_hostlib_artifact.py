#!/usr/bin/env python3
"""Bind SDK host-library transfers to immutable same-run artifacts; never load code."""

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "sdk_runtime_transport", ROOT / "scripts/runtime-proof-candidate.py")
TRANSPORT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TRANSPORT
SPEC.loader.exec_module(TRANSPORT)

LIBRARY = "libmvm_hostlib.dylib"
PLATFORM = "darwin-arm64"
MAX_BYTES = 256 * 1024 * 1024


def channel(value):
    if value not in ("npm", "pypi"):
        raise ValueError("SDK channel must be npm or pypi")
    return value


def positive(value):
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise ValueError("expected a positive numeric workflow ID or attempt")
    return int(value)


def source_context(env):
    repository = env.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid workflow repository")
    sha = env.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid workflow source SHA")
    source = TRANSPORT.TagSource(
        positive(env.get("GITHUB_REPOSITORY_ID", "")),
        positive(env.get("GITHUB_RUN_ID", "")),
        positive(env.get("GITHUB_RUN_ATTEMPT", "")), sha, "")
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if head != sha:
        raise ValueError("checkout HEAD does not match GITHUB_SHA")
    return repository, source


def library_hash(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_BYTES:
        raise ValueError("host library must be a bounded regular file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(payload):
    expected = {payload / PLATFORM, payload / PLATFORM / LIBRARY}
    if payload.is_symlink() or set(payload.rglob("*")) != expected:
        raise ValueError("host library payload has unexpected members")
    if (payload / PLATFORM).is_symlink():
        raise ValueError("host library platform directory must not be a symlink")
    return library_hash(payload / PLATFORM / LIBRARY)


def fetch(args, env):
    selected = channel(args.channel)
    repository, source = source_context(env)
    attempt = positive(args.producer_attempt)
    if attempt > source.run_attempt:
        raise ValueError("producer attempt is newer than this workflow attempt")
    expected_hash = TRANSPORT.sha256(args.library_sha256)
    # The unsigned upload is flat; the final SDK artifact restores its platform directory.
    with tempfile.TemporaryDirectory(prefix="mvm-sdk-hostlib-") as temporary:
        destination = Path(temporary) / "library"
        TRANSPORT.retrieve_artifact(source, TRANSPORT.ArtifactTransfer(
            positive(args.artifact_id), args.artifact_digest,
            f"unsigned-{selected}-hostlib-{attempt}", (LIBRARY,),
            destination, MAX_BYTES,
        ), repository=repository)
        if library_hash(destination / LIBRARY) != expected_hash:
            raise ValueError("raw host library SHA-256 mismatch")
        args.payload.mkdir(mode=0o700, parents=False, exist_ok=False)
        shutil.move(str(destination), str(args.payload / PLATFORM))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate-channel", "inventory", "fetch"))
    parser.add_argument("--channel", required=True)
    parser.add_argument("--payload", type=Path, default=Path("hostlib-out"))
    parser.add_argument("--artifact-id", default="")
    parser.add_argument("--artifact-digest", default="")
    parser.add_argument("--library-sha256", default="")
    parser.add_argument("--producer-attempt", default="")
    args = parser.parse_args()
    try:
        channel(args.channel)
        if args.command == "inventory":
            _, source = source_context(os.environ)
            digest = inventory(args.payload)
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write(f"library-sha256={digest}\nrun-attempt={source.run_attempt}\n")
        elif args.command == "fetch":
            fetch(args, os.environ)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"SDK host library transfer failed: {error}\n")


if __name__ == "__main__":
    main()
