#!/usr/bin/env python3
"""Inspect final package bytes; not boot or notarization authority."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import sys
import tempfile
import tarfile
import zipfile

import sign_macos
import owner_component_manifest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "nix/packaging/release"))
from archive_envelope import extract_package


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def extract_zip(archive, destination):
    """Bound allocation and normalize paths before any member is written."""
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        if len(members) > 10000 or sum(m.file_size for m in members) > 2**30:
            raise ValueError("ZIP exceeds inspection limits")
        seen = set()
        for member in members:
            path = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (not path.parts or path.is_absolute() or ".." in path.parts
                    or "\\" in member.filename or ":" in member.filename
                    or path in seen or stat.S_ISLNK(mode)
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise ValueError("unsafe or duplicate ZIP member")
            seen.add(path)
        for member in members:
            path = destination.joinpath(*PurePosixPath(member.filename).parts)
            if member.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with package.open(member) as source, path.open("xb") as output:
                    shutil.copyfileobj(source, output)


def entries(report):
    result = {}
    for entry in report["files"]:
        path = PurePosixPath(entry["path"])
        if (not path.parts or path.is_absolute() or ".." in path.parts
                or "\\" in entry["path"] or ":" in entry["path"]
                or str(path) in result):
            raise ValueError("invalid signing report inventory")
        digest = entry["sha256"]
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise ValueError("invalid signing report hash")
        result[str(path)] = entry
    if not result:
        raise ValueError("empty signing report inventory")
    return result


def verify_relocatable(path):
    inspection = (sign_macos.run("otool", "-L", path) + "\n" +
                  sign_macos.run("otool", "-l", path))
    if any(marker in inspection for marker in
           ("/opt/homebrew", "/usr/local", "mvm-libkrun-tier")):
        raise ValueError(f"non-relocatable path in packaged Mach-O: {path}")


def verify_owner_hardening(path):
    details = sign_macos.run_diagnostic("codesign", "-d", "--verbose=4", path)
    if "(runtime)" not in details:
        raise ValueError("owner executable lacks hardened runtime")
    libraries = sign_macos.run("otool", "-L", path).splitlines()[1:]
    dependencies = [line.strip().split(" ", 1)[0] for line in libraries if line.strip()]
    if not dependencies or any(
            not dependency.startswith(("/usr/lib/", "/System/Library/"))
            for dependency in dependencies):
        raise ValueError("owner executable links a non-system library")
    load_commands = sign_macos.run("otool", "-l", path)
    if "LC_RPATH" in load_commands:
        raise ValueError("owner executable carries an rpath")


def verify(archive, producer, notary, report, envelope=None,
           require_cli_inventory=False, require_owner_inventory=False,
           owner_version=None, owner_target=None, owner_source_commit=None,
           sdk_layout=False):
    if report.resolve() in {p.resolve() for p in (archive, producer, notary) if p is not None}:
        raise ValueError("inspection report must not overwrite its inputs")
    report.unlink(missing_ok=True)
    if platform.system() != "Darwin":
        raise ValueError("final package inspection requires macOS")
    original = json.loads(producer.read_text())
    if original.get("status") != "ProducerAdhocVerified" or original.get("notarized") is not False:
        raise ValueError("invalid producer status")
    baseline = entries(original)
    source = producer
    expected = baseline
    if notary is not None:
        final = json.loads(notary.read_text())
        if final.get("status") == "Accepted":
            if not final.get("id") or not final.get("team_id"):
                raise ValueError("Accepted report lacks notary identity")
            expected = entries(final)
            if set(expected) != set(baseline):
                raise ValueError("final signing inventory changed")
            source = notary
        elif (final.get("status") != "Unconfigured"
              or any(key in final for key in ("files", "id", "team_id"))
              or final.get("notarized", False) is not False):
            raise ValueError("unknown or failed notarization status")
    package_hash = sha256(archive)
    with tempfile.TemporaryDirectory(prefix="mvm-final-package-") as temporary:
        root = Path(temporary)
        if zipfile.is_zipfile(archive):
            if envelope is not None:
                raise ValueError("ZIP must not specify TAR envelope")
            extract_zip(archive, root)
            payload = root
        else:
            if not envelope:
                raise ValueError("TAR requires an explicit envelope")
            extract_package(archive, root, envelope)
            payload = root / envelope
        if require_cli_inventory or require_owner_inventory:
            owner_component = payload / "mvm-hvf-run-owner"
            if not owner_component.is_file():
                raise ValueError("missing owner executable")
            owner_manifest_path = payload / "owner-component.json"
            if not owner_manifest_path.is_file():
                raise ValueError("missing owner component manifest")
            if None in (owner_version, owner_target, owner_source_commit):
                raise ValueError("owner package identity expectation is incomplete")
            owner_manifest = owner_component_manifest.validate(
                json.loads(owner_manifest_path.read_text()),
                owner_component,
                owner_target,
                owner_version,
                owner_source_commit,
            )
        else:
            owner_manifest = None
            owner_component = None
        code = sign_macos.targets(payload)
        if require_cli_inventory:
            missing = sign_macos.REQUIRED_CLI_BINARIES - {
                path.name for path, kind in code if kind == 2}
            if missing:
                raise ValueError("missing required CLI inventory")
        if owner_component is not None:
            verify_owner_hardening(owner_component)
        remaining = set(expected)
        actual = []
        for path, kind in code:
            if require_cli_inventory:
                verify_relocatable(path)
            keys = sign_macos.ROLES.get(path.name, []) if kind == 2 else []
            role = path.name if keys else "code"
            relative = str(path.relative_to(payload))
            candidates = [p for p in remaining if
                          (p == relative or (sdk_layout and
                           PurePosixPath(p).name == path.name))]
            if len(candidates) != 1:
                raise ValueError("ambiguous, extra or missing package inventory")
            matched = candidates[0]
            producer_entry = baseline[matched]
            if (producer_entry.get("role") != role
                    or producer_entry.get("required_entitlements") != keys):
                raise ValueError("signing report role policy mismatch")
            digest = sha256(path)
            if expected[matched]["sha256"] != digest:
                raise ValueError("final member hash mismatch")
            sign_macos.run("codesign", "--verify", "--strict", "--all-architectures", path)
            sign_macos.verify_entitlements(path, keys)
            remaining.remove(matched)
            actual.append({"path": relative, "signing_path": matched,
                           "sha256": digest, "role": role,
                           "required_entitlements": keys})
        if remaining:
            raise ValueError("missing package inventory")
    if sha256(archive) != package_hash:
        raise ValueError("package changed during inspection")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({
        "status": "FinalPackageVerified", "authority": "package-inspection-only",
        "package": str(archive), "package_sha256": package_hash,
        "report_source": str(source), "report_source_sha256": sha256(source),
        "owner_component": owner_manifest,
        "files": actual,
    }, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "producer-report", "report"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--notary-report", type=Path)
    parser.add_argument("--envelope")
    parser.add_argument("--require-cli-inventory", action="store_true")
    parser.add_argument("--require-owner-inventory", action="store_true")
    parser.add_argument("--owner-version")
    parser.add_argument("--owner-target")
    parser.add_argument("--owner-source-commit")
    parser.add_argument("--sdk-layout", action="store_true")
    args = parser.parse_args()
    try:
        verify(args.archive, args.producer_report, args.notary_report, args.report,
               args.envelope, args.require_cli_inventory, args.require_owner_inventory,
               args.owner_version, args.owner_target, args.owner_source_commit,
               args.sdk_layout)
    except (ValueError, RuntimeError, OSError, KeyError, TypeError,
            zipfile.BadZipFile, tarfile.TarError) as error:
        parser.exit(1, f"final macOS package inspection failed: {error}\n")


if __name__ == "__main__":
    main()
