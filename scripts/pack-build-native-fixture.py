#!/usr/bin/env python3
"""Author the native witness with the real, checkout-local Python SDK."""
import argparse
from pathlib import Path

from mvm.packs import pack

HELLO = "pack-build-native-sdk-witness\n"


def author(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=False)
    source = directory / "source"
    source.mkdir()
    (source / "hello.txt").write_text(HELLO, encoding="utf-8")
    spec = directory / "pack.json"
    (
        pack("witness/native-hello", "1.0.0")
        .target("x86_64-linux")
        .source("source")
        .package("busybox", scope="runtime")
        .copy("hello.txt", "/app/hello.txt")
        .entrypoint("cat", "/app/hello.txt")
        .resources(cpu_cores=1, memory_mib=256)
        .write(spec)
    )
    return spec


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(author(parser.parse_args().directory))
