"""Refuse a representative Yocto image with unrequested runtime packages."""

import argparse
import struct
import tarfile
from pathlib import Path

EXPECTED_PACKAGES = {"mvm-hello"}
ENTRYPOINT = "srv/app/hello"


def check_static_pie(program: bytes) -> None:
    if (len(program) < 64 or program[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<HH", program, 16) != (3, 183)):
        raise ValueError("Yocto entrypoint must be an aarch64 static PIE")
    phoff = struct.unpack_from("<Q", program, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", program, 54)
    if phentsize < 56 or phnum > 128 or phoff + phentsize * phnum > len(program):
        raise ValueError("Yocto entrypoint has invalid ELF program headers")
    for index in range(phnum):
        kind, _, offset, _, _, size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", program, phoff + index * phentsize
        )
        if kind == 3:  # PT_INTERP
            raise ValueError("Yocto entrypoint must not need a dynamic loader")
        if kind == 2:  # PT_DYNAMIC
            if offset + size > len(program) or size % 16:
                raise ValueError("Yocto entrypoint has an invalid dynamic section")
            for at in range(offset, offset + size, 16):
                tag = struct.unpack_from("<Q", program, at)[0]
                if tag in (1, 0x6FFFFEF5):  # DT_NEEDED, DT_GNU_HASH
                    raise ValueError("Yocto entrypoint must not need a runtime linker")


def check(manifest: Path, archive: Path) -> tuple[int, int]:
    installed = {
        line.split()[0]
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    if installed != EXPECTED_PACKAGES:
        raise ValueError(f"unexpected guest packages: {sorted(installed - EXPECTED_PACKAGES)}; "
                         f"missing: {sorted(EXPECTED_PACKAGES - installed)}")

    with tarfile.open(archive, "r:gz") as rootfs:
        files = [member for member in rootfs if member.isfile()]
        entrypoints = [member for member in files if member.name.removeprefix("./") == ENTRYPOINT]
        if len(entrypoints) != 1 or not entrypoints[0].mode & 0o111:
            raise ValueError("Yocto archive has no executable /srv/app/hello")
        if entrypoints[0].size > 16 * 1024 * 1024:
            raise ValueError("Yocto sample entrypoint is unexpectedly large")
        check_static_pie(rootfs.extractfile(entrypoints[0]).read())
    return archive.stat().st_size, sum(member.size for member in files)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    compressed, file_bytes = check(args.manifest, args.archive)
    print(f"guest packages: {', '.join(sorted(EXPECTED_PACKAGES))}")
    print(f"rootfs archive: {compressed} bytes; regular file contents: {file_bytes} bytes")


if __name__ == "__main__":
    main()
