#!/usr/bin/env python3
"""Write and validate the signed-archive manifest for mvm-hvf-run-owner."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

SCHEMA_VERSION = 1
COMPONENT = "mvm-hvf-run-owner"
BOOTSTRAP_PROTOCOL_VERSION = 1
FIELDS = {
    "schema_version",
    "component",
    "sha256",
    "version",
    "target",
    "source_commit",
    "bootstrap_protocol_version",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate(value, binary=None, target=None, version=None, source_commit=None):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("owner component manifest fields differ")
    if value["schema_version"] != SCHEMA_VERSION:
        raise ValueError("owner component schema differs")
    if value["component"] != COMPONENT:
        raise ValueError("owner component name differs")
    if value["bootstrap_protocol_version"] != BOOTSTRAP_PROTOCOL_VERSION:
        raise ValueError("owner bootstrap protocol differs")
    if not isinstance(value["version"], str) or not value["version"]:
        raise ValueError("owner component version is invalid")
    if not isinstance(value["target"], str) or not value["target"]:
        raise ValueError("owner component target is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]):
        raise ValueError("owner source commit is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", value["sha256"]):
        raise ValueError("owner component digest is invalid")
    if binary is not None and digest(binary) != value["sha256"]:
        raise ValueError("owner component bytes differ")
    for actual, expected, label in (
        (value["target"], target, "target"),
        (value["version"], version, "version"),
        (value["source_commit"], source_commit, "source commit"),
    ):
        if expected is not None and actual != expected:
            raise ValueError(f"owner component {label} differs")
    return value


def write(binary, output, version, target, source_commit):
    if binary.resolve() == output.resolve():
        raise ValueError("owner manifest cannot overwrite its binary")
    value = validate({
        "schema_version": SCHEMA_VERSION,
        "component": COMPONENT,
        "sha256": digest(binary),
        "version": version,
        "target": target,
        "source_commit": source_commit,
        "bootstrap_protocol_version": BOOTSTRAP_PROTOCOL_VERSION,
    }, binary, target, version, source_commit)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        directory = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    try:
        write(args.binary, args.output, args.version, args.target, args.source_commit)
    except (OSError, ValueError) as error:
        parser.exit(1, f"owner component manifest failed: {error}\n")


if __name__ == "__main__":
    main()
