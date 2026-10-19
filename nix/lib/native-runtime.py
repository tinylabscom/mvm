"""Plan and install application-layer GNU runtime aliases; never copy ELF bytes."""

import argparse
import os
from pathlib import Path
import re
import struct


GNU = {
    "aarch64-linux": ("ld-linux-aarch64.so.1", 183, "lib"),
    "x86_64-linux": ("ld-linux-x86-64.so.2", 62, "lib64"),
}


def closure_target(source, roots):
    """Follow each symlink hop only within declared store outputs."""
    def start(path):
        owner = next((root for root in roots if path.is_relative_to(root)), None)
        if owner is None:
            raise ValueError(f"library escapes selected closure: {source}")
        return owner, list(path.relative_to(owner).parts)

    current, pending = start(source)
    hops = 0
    while pending:
        part = pending.pop(0)
        candidate = current.parent if part == ".." else current / part
        if not any(candidate.is_relative_to(root) for root in roots):
            raise ValueError(f"library escapes selected closure: {source}")
        candidate.lstat()
        if candidate.is_symlink():
            hops += 1
            if hops > 40:
                raise ValueError(f"excessive library symlink chain: {source}")
            link = Path(os.readlink(candidate))
            if link.is_absolute():
                current, parts = start(link)
            else:
                parts = list(link.parts)
            pending = parts + pending
        else:
            current = candidate
            if pending and not current.is_dir():
                raise NotADirectoryError(current)
    return current


def dynamic_names(path, machine):
    """Read ELF64 little-endian dynamic names without loading or executing ELF."""
    data = path.read_bytes()
    if (len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01"
            or struct.unpack_from("<H", data, 16)[0] != 3
            or struct.unpack_from("<H", data, 18)[0] != machine
            or struct.unpack_from("<I", data, 20)[0] != 1
            or struct.unpack_from("<H", data, 52)[0] != 64):
        raise ValueError(f"incompatible ELF library: {path}")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 54)
    if (entsize != 56 or not 0 < count < 65535 or phoff < 64
            or phoff + count * entsize > len(data)):
        raise ValueError(f"invalid ELF program headers: {path}")
    segments = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * entsize)
                for i in range(count)]
    tags = []
    dynamics = 0
    for kind, _, offset, vaddr, _, size, memsz, align in segments:
        # PT_NULL is unused; ELF leaves every other field in that entry undefined.
        if kind == 0:
            continue
        if (offset + size > len(data) or vaddr + memsz > 2**64
                or (kind in (1, 2) and size > memsz)
                or (align not in (0, 1) and
                    (align & (align - 1) or vaddr % align != offset % align))):
            raise ValueError(f"invalid ELF segment: {path}")
        if kind == 2:
            dynamics += 1
            if dynamics != 1 or not size or size % 16:
                raise ValueError(f"invalid ELF dynamic segment: {path}")
            for pos in range(offset, offset + size, 16):
                tag, value = struct.unpack_from("<qQ", data, pos)
                if tag == 0:
                    break
                tags.append((tag, value))
            else:
                raise ValueError(f"unterminated ELF dynamic segment: {path}")
            if not any(k == 1 and o <= offset and offset + size <= o + f
                       and a + offset - o == vaddr
                       for k, _, o, a, _, f, _, _ in segments):
                raise ValueError(f"unmapped ELF dynamic segment: {path}")
    if not dynamics:
        raise ValueError(f"missing ELF dynamic segment: {path}")
    for tag in (5, 10):
        if len({value for key, value in tags if key == tag}) > 1:
            raise ValueError(f"conflicting ELF string table tags: {path}")
    strings = dict(tags)
    names = [(tag, value) for tag, value in tags if tag in (1, 14)]
    if not any(tag == 14 for tag, _ in names):
        raise ValueError(f"missing ELF SONAME: {path}")
    address, size = strings.get(5), strings.get(10)
    table = None
    mappings = 0
    for kind, _, offset, vaddr, _, filesz, memsz, _ in segments:
        if (kind == 1 and address is not None and size
                and vaddr < address + size and address < vaddr + memsz):
            mappings += 1
            if not (vaddr <= address and address + size <= vaddr + filesz):
                raise ValueError(f"invalid ELF string table mapping: {path}")
            table = data[offset + address - vaddr:offset + address - vaddr + size]
    if table is None or mappings != 1:
        raise ValueError(f"invalid ELF string table: {path}")
    soname, needed = None, []
    for tag, offset in names:
        end = table.find(b"\0", offset)
        if end < 0:
            raise ValueError(f"invalid ELF dynamic name: {path}")
        name = table[offset:end].decode("ascii")
        if not name or "/" in name or name in (".", ".."):
            raise ValueError(f"non-basename ELF dynamic name: {path}")
        if tag == 14:
            if soname is not None and soname != name:
                raise ValueError(f"ambiguous ELF SONAME: {path}")
            soname = name
        else:
            needed.append(name)
    return soname, needed


def plan(system, roots):
    """Pure filesystem inspection: return guest-relative aliases to closure files."""
    if system not in GNU:
        raise ValueError(f"unsupported GNU runtime system: {system}")
    loader, machine, loader_dir = GNU[system]
    roots = tuple(sorted({Path(p).resolve(strict=True) for p in roots}))
    aliases, sonames, dependencies = {}, {}, set()
    for root in roots:
        directory = root / "lib"
        if not directory.exists():
            continue
        if directory.resolve() != directory:
            raise ValueError(f"symlinked library directory: {directory}")
        for source in sorted(directory.glob("*.so*")):
            target = closure_target(source, roots)
            if not target.is_file():
                raise ValueError(f"library is not a file: {source}")
            with target.open("rb") as stream:
                header = stream.read(20)
            # Only ELF shared objects are aliases. Linker scripts (.so) stay
            # in the store; versioned runtime names may never be scripts.
            if header[:4] != b"\x7fELF":
                script = target.read_bytes() if target.stat().st_size <= 65536 else b""
                if (".so." in source.name or not script
                        or not script.isascii() or b"\0" in script
                        or re.search(rb"\b(?:GROUP|INPUT)\s*\(", script) is None):
                    raise ValueError(f"non-ELF runtime library: {source}")
                continue
            soname, needed = dynamic_names(target, machine)
            dependencies.update(needed)
            if soname is not None:
                if soname in sonames and sonames[soname] != target:
                    raise ValueError(f"ambiguous runtime SONAME: {soname}")
                sonames[soname] = target
            name = f"lib/{source.name}"
            if name in aliases and aliases[name] != target:
                raise ValueError(f"ambiguous runtime library: {name}")
            aliases[name] = target
    # SONAME may differ from the package file's versioned basename.
    for soname, target in sonames.items():
        name = f"lib/{soname}"
        if name in aliases and aliases[name] != target:
            raise ValueError(f"ambiguous runtime library: {name}")
        aliases[name] = target
    missing = sorted(name for name in dependencies if f"lib/{name}" not in aliases)
    if missing:
        raise ValueError(f"missing runtime libraries: {', '.join(missing)}")
    if f"lib/{loader}" not in aliases:
        raise ValueError(f"missing GNU interpreter: {loader}")
    aliases[f"{loader_dir}/{loader}"] = aliases[f"lib/{loader}"]
    return dict(sorted(aliases.items()))


def install(root, aliases):
    """Refuse pre-existing destinations rather than overwrite application files."""
    root = Path(root).resolve(strict=True)
    # Preflight every destination before creating anything.
    for name in aliases:
        destination = root / name
        if destination.parent.exists() and destination.parent.resolve() != destination.parent:
            raise ValueError(f"alias parent is a symlink: {destination.parent}")
        if os.path.lexists(destination):
            raise ValueError(f"runtime alias collision: {destination}")
    for name, target in aliases.items():
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", required=True)
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    install(args.root, plan(args.system, args.closure.read_text().splitlines()))
