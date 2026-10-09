#!/usr/bin/env python3
"""SDK metadata and signed CLI-runtime gate; no publication side effects."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "tinylabscom/mvm"


def fetch_json(url):
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def validate_metadata(root, event, tag, dry_run):
    sdk = root / "crates/mvm-sdk/sdks"
    release = tomllib.loads((sdk / "release.toml").read_text())
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    hostlib = tomllib.loads((root / "crates/mvm-hostlib/Cargo.toml").read_text())
    python = tomllib.loads((sdk / "python/pyproject.toml").read_text())["project"]
    npm = json.loads((sdk / "typescript/package.json").read_text())
    for key in ("version", "runtime_version"):
        if not re.fullmatch(r"\d+\.\d+\.\d+", release[key]):
            raise ValueError(f"invalid {key}")
    if hostlib["package"]["version"] != {"workspace": True}:
        raise ValueError("hostlib must inherit workspace version")
    if release["runtime_version"] != workspace["workspace"]["package"]["version"]:
        raise ValueError("runtime_version must equal the compiled hostlib workspace version")
    if release["cli_binary_names"] != ["mvmctl"]:
        raise ValueError("CLI binary names must be ['mvmctl']")
    for key, package in (("python", python), ("typescript", npm)):
        if package["version"] != release["version"] or package["name"] != release[key]["name"]:
            raise ValueError(f"{key} package metadata differs from SDK release manifest")
    if event == "release":
        if tag != release["tag_prefix"] + release["version"]:
            raise ValueError("release tag differs from SDK manifest")
    elif not dry_run:
        raise ValueError("non-release invocation must remain dry-run")
    return release


def checksum_record(text, filename):
    matches = []
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if match and match[2] == filename:
            matches.append(match[1])
    if len(matches) != 1:
        raise ValueError(f"expected exactly one checksum record for {filename}")
    return matches[0]


def verify_runtime(version, directory):
    tag = f"v{version}"
    archive = f"mvm-guest-bins-{tag}.tar.gz"
    manifest = "checksums-sha256.txt"
    assets = [archive, archive + ".sha256", manifest]
    for asset in assets:
        for filename in (asset, asset + ".bundle"):
            url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{filename}"
            with urllib.request.urlopen(url, timeout=120) as response:
                with (directory / filename).open("wb") as output:
                    shutil.copyfileobj(response, output)
        subprocess.run([
            "cosign", "verify-blob", "--bundle", str(directory / (asset + ".bundle")),
            "--certificate-identity",
            f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}",
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            str(directory / asset),
        ], check=True)
    with (directory / archive).open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    for record in (archive + ".sha256", manifest):
        if checksum_record((directory / record).read_text(), archive) != digest:
            raise ValueError(f"{record} does not match runtime archive")
    subprocess.run([
        "gh", "attestation", "verify", str(directory / archive),
        "--repo", REPOSITORY, "--signer-workflow", f"{REPOSITORY}/.github/workflows/release.yml",
        "--source-ref", f"refs/tags/{tag}",
    ], check=True)
    return digest


def registry_state(release, fetch=fetch_json):
    """Existing versions are resumable, never an instruction to bump.

    Only a registry's HTTP 404 means absent; transport/auth/parser failures
    propagate. Installed-package verification is still mandatory on reruns.
    """
    version = release["version"]
    names = [release["typescript"]["name"]]
    names += [f"{names[0]}-{key}" for key in (
        "darwin-arm64", "linux-x64-gnu", "linux-arm64-gnu",
        "linux-x64-musl", "linux-arm64-musl",
    )]
    urls = [("pypi", f"https://pypi.org/pypi/{release['python']['name']}/{version}/json")]
    urls += [(name, f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='')}/{version}")
             for name in names]
    return {name: "present; resume/verify" if fetch(url) is not None else "absent"
            for name, url in urls}


def main():
    dry_run = os.environ.get("SDK_DRY_RUN", "true") == "true"
    release = validate_metadata(Path.cwd(), os.environ["SDK_EVENT_NAME"],
                                os.environ.get("SDK_RELEASE_TAG", ""), dry_run)
    if dry_run:
        print("Local build rehearsal only: no published runtime required; NOT release acceptance.")
    else:
        print(json.dumps(registry_state(release), indent=2))
        with tempfile.TemporaryDirectory(prefix="sdk-runtime-") as directory:
            digest = verify_runtime(release["runtime_version"], Path(directory))
        print(f"Verified signed CLI runtime {release['runtime_version']}: sha256:{digest}")


if __name__ == "__main__":
    main()
