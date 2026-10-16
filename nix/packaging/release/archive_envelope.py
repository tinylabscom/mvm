#!/usr/bin/env python3
"""Safe CLI release envelope extraction into a caller-owned private directory."""

from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile


def extract_package(archive, destination, envelope):
    """Validate every member before writing; never interpret archive links."""
    with tarfile.open(archive, "r:gz") as package:
        members = package.getmembers()
        seen = set()
        paths = {PurePosixPath(member.name) for member in members}
        payload = []
        for member in members:
            path = PurePosixPath(member.name)
            # BSD tar emits AppleDouble companions of files and directories.
            # Discard only regular companions of actual in-envelope members.
            companion = (path.with_name(path.name[2:])
                         if path.name.startswith("._") and len(path.name) > 2
                         else None)
            metadata = (member.isfile() and companion in paths
                        and companion.parts[0] == envelope)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or (path.parts[0] != envelope and not metadata)
                    or not (member.isdir() or member.isfile()) or path in seen
                    or (path.name.startswith("._") and not metadata)):
                raise ValueError("unsafe or duplicate archive member: " + member.name)
            seen.add(path)
            if not metadata:
                payload.append(member)
        for member in payload:
            path = Path(destination).joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(member) as source, path.open("xb") as output:
                    shutil.copyfileobj(source, output)
                path.chmod(member.mode & 0o777)


if __name__ == "__main__":
    try:
        extract_package(*sys.argv[1:])
    except (OSError, ValueError, tarfile.TarError) as error:
        print("archive envelope validation failed: " + str(error), file=sys.stderr)
        sys.exit(1)
