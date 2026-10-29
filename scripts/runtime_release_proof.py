"""Fixed-identity runtime proof verification; never signs or publishes."""
import hashlib
from pathlib import Path
import re
import subprocess

REPOSITORY = "tinylabscom/mvm"
ISSUER = "https://token.actions.githubusercontent.com"


def runtime_names(version):
    if not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?",
        version,
    ):
        raise ValueError("invalid runtime version")
    if "-" in version:
        identifiers = version.split("-", 1)[1].split(".")
        if any(part.isdigit() and len(part) > 1 and part.startswith("0")
               for part in identifiers):
            raise ValueError("noncanonical numeric prerelease identifier")
    archive = f"mvm-guest-bins-v{version}.tar.gz"
    checksum = archive + ".sha256"
    return archive, checksum, archive + ".bundle", checksum + ".bundle"


def checksum_record(text, filename):
    matches = []
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if match and match[2] == filename:
            matches.append(match[1])
    if len(matches) != 1:
        raise ValueError(f"expected exactly one checksum record for {filename}")
    return matches[0]


def verify_blob(version, directory, asset, *, source_sha=None):
    runtime_names(version)
    command = [
        "cosign", "verify-blob",
        "--bundle", str(directory / (asset + ".bundle")),
        "--certificate-identity",
        f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/v{version}",
        "--certificate-oidc-issuer", ISSUER,
    ]
    if source_sha is not None:
        if not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
            raise ValueError("expected certificate source SHA must be a commit")
        command += [
            "--certificate-github-workflow-sha", source_sha,
            "--certificate-github-workflow-trigger", "push",
            "--certificate-github-workflow-ref", f"refs/tags/v{version}",
            "--certificate-github-workflow-repository", REPOSITORY,
        ]
    command.append(str(directory / asset))
    subprocess.run(command, check=True)


def verify_quartet(version, directory, *, source_sha=None):
    directory = Path(directory)
    archive, checksum, archive_bundle, checksum_bundle = runtime_names(version)
    names = (archive, checksum, archive_bundle, checksum_bundle)
    for name in names:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"runtime proof is missing an ordinary file: {name}")
    verify_blob(version, directory, archive, source_sha=source_sha)
    verify_blob(version, directory, checksum, source_sha=source_sha)
    hashes = {}
    for name in names:
        with (directory / name).open("rb") as source:
            hashes[name] = hashlib.file_digest(source, "sha256").hexdigest()
    if checksum_record((directory / checksum).read_text(), archive) != hashes[archive]:
        raise ValueError("runtime checksum does not match archive")
    return hashes
