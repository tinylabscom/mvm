#!/usr/bin/env python3
"""Render binary package recipes only from an authenticated release asset set."""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess


HERE = Path(__file__).resolve().parent
REPO = "https://github.com/tinylabscom/mvm"
HOSTS = ("x86_64", "aarch64")
HOST_BINS = (
    "mvmctl", "mvm-host-agent", "mvm-signer-helper", "mvm-network-endpoint",
    "mvm-broker", "mvm-audit-signer", "mvm-gpu-endpoint",
)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checksums(path):
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](\S+)", line)
        if not match or match[2] in result:
            raise ValueError(f"malformed or duplicate checksum in {path}")
        result[match[2]] = match[1].lower()
    return result


def verify(path, version):
    # Same exact release-workflow identity as the installer; no regexp, identity
    # override, unsigned mode, or trust in a sibling checksum alone.
    for required in (path, Path(str(path) + ".bundle")):
        if not required.is_file():
            raise FileNotFoundError(f"required signed release asset missing: {required}")
    subprocess.run([
        "cosign", "verify-blob", "--bundle", str(path) + ".bundle",
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
        "--certificate-identity",
        f"{REPO}/.github/workflows/release.yml@refs/tags/v{version}",
        str(path),
    ], check=True)


def render(version, assets, out):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("version must be a stable release number without v")
    guest = f"mvm-guest-bins-v{version}.tar.gz"
    hosts = [f"mvmctl-{arch}-unknown-linux-gnu.tar.gz" for arch in HOSTS]
    manifest = assets / "checksums-sha256.txt"
    verify(manifest, version)
    pins = checksums(manifest)
    for name in [*hosts, guest]:
        path = assets / name
        if pins.get(name) != digest(path):
            raise ValueError(f"signed manifest digest mismatch or missing entry: {name}")
        verify(path, version)
    if checksums(assets / (guest + ".sha256")) != {guest: pins[guest]}:
        raise ValueError("guest archive checksum disagrees with signed manifest")
    values = {
        "VERSION": version,
        "HOST_BINS": " ".join(HOST_BINS),
        "SHA_X86_64": pins[hosts[0]],
        "SHA_AARCH64": pins[hosts[1]],
        "SHA_GUEST": pins[guest],
        "SHA_GUEST_CHECKSUM": digest(assets / (guest + ".sha256")),
        "SHA_GUEST_BUNDLE": digest(assets / (guest + ".bundle")),
    }
    recipes = [
        (HERE / "PKGBUILD.tmpl", "PKGBUILD"),
        (HERE.parent / "nixpkgs/package.nix.tmpl", "package.nix"),
    ]
    rendered = []
    for template, name in recipes:
        text = template.read_text()
        for key, value in values.items():
            text = text.replace(f"@@{key}@@", value)
        if "@@" in text:
            raise ValueError(f"unresolved template token in {template}")
        rendered.append((name, text))
    # No output is created until every asset has passed authentication.
    out.mkdir(parents=True, exist_ok=True)
    for name, text in rendered:
        (out / name).write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--assets-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    render(args.version, args.assets_dir, args.out_dir)


if __name__ == "__main__":
    main()
