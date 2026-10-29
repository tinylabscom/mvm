#!/usr/bin/env python3
"""Sign and notarize a staged macOS payload before any distribution packaging."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import secrets
import struct
import subprocess
import tempfile


CREDENTIALS = (
    "APPLE_DEVELOPER_ID_P12_BASE64",
    "APPLE_DEVELOPER_ID_P12_PASSWORD",
    "APPLE_DEVELOPER_ID_IDENTITY",
    "APPLE_TEAM_ID",
    "APPLE_ID",
    "APPLE_APP_SPECIFIC_PASSWORD",
)
THIN = {b"\xfe\xed\xfa\xce": ">", b"\xce\xfa\xed\xfe": "<",
        b"\xfe\xed\xfa\xcf": ">", b"\xcf\xfa\xed\xfe": "<"}
FAT = {b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
       b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True)}
ROLES = {
    "mvmctl": ["com.apple.security.virtualization"],
    "mvm-hvf-supervisor": ["com.apple.security.hypervisor"],
    "mvm-libkrun-supervisor": ["com.apple.security.hypervisor"],
    # Retain the historical spelling when inspecting older staging layouts.
    "mvm-krun-supervisor": ["com.apple.security.hypervisor"],
}
# codesign treats a requirement argument without '=' as a filename.
DEVELOPER_ID_REQUIREMENT = (
    '=anchor apple generic and '
    'certificate leaf[field.1.2.840.113635.100.6.1.13] exists and '
    'certificate leaf[subject.OU] = "{team}"'
)


def run(*args):
    # Never log argument vectors: security/notarytool receive credentials.
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{args[0]} {args[1]} failed (exit {result.returncode})")
    return result.stdout


def macho_type(path):
    """Read thin/single-slice FAT headers, including extensionless helpers.

    Multi-slice FAT is outside the ARM-only producer scope: default-slice
    entitlement readback cannot establish the entitlement policy for every slice.
    """
    with path.open("rb") as stream:
        header = stream.read(16)
        magic = header[:4]
        if magic in THIN:
            return struct.unpack(THIN[magic] + "I", header[12:16])[0]
        if magic not in FAT:
            return None
        endian, wide = FAT[magic]
        count = struct.unpack(endian + "I", header[4:8])[0]
        if not 0 < count <= 64:
            raise RuntimeError(f"invalid universal Mach-O: {path}")
        if count > 1:
            raise RuntimeError(f"multi-slice FAT Mach-O is not supported: {path}")
        types = set()
        for index in range(count):
            stream.seek(8 + index * (32 if wide else 20) + 8)
            offset = struct.unpack(endian + ("Q" if wide else "I"),
                                   stream.read(8 if wide else 4))[0]
            stream.seek(offset)
            thin = stream.read(16)
            if thin[:4] not in THIN:
                raise RuntimeError(f"invalid universal Mach-O slice: {path}")
            types.add(struct.unpack(THIN[thin[:4]] + "I", thin[12:16])[0])
        if len(types) != 1:
            raise RuntimeError(f"mixed universal Mach-O types: {path}")
        return types.pop()


def targets(payload):
    found = []
    for path in sorted(payload.rglob("*")):
        if path.is_symlink():
            if not path.resolve().is_relative_to(payload):
                raise RuntimeError(f"payload symlink escapes staging: {path}")
            continue
        if not path.is_file():
            continue
        kind = macho_type(path)
        if kind is not None:
            if kind not in (2, 6, 8):  # MH_EXECUTE, MH_DYLIB, MH_BUNDLE
                raise RuntimeError(f"unsupported shipped Mach-O type {kind}: {path}")
            if path.name in ROLES and kind != 2:
                raise RuntimeError(f"runtime role must be MH_EXECUTE: {path}")
            found.append((path, kind))
        elif path.suffix in (".dylib", ".so") or path.name in ROLES:
            raise RuntimeError(f"expected Mach-O: {path}")
    if not found:
        raise RuntimeError("payload contains no Mach-O code")
    return found


def verify_entitlements(path, keys):
    """Check the signed bytes, never the input entitlement template."""
    embedded = run("codesign", "-d", "--entitlements", "-", "--xml", path)
    actual = plistlib.loads(embedded.encode()) if embedded.strip() else {}
    if not isinstance(actual, dict) or set(actual) != set(keys) or not all(
            actual[key] is True for key in keys):
        raise RuntimeError(f"required runtime entitlement missing or unexpected: {path}")


def producer_sign(payload, report, require_cli_inventory=False):
    """Mandatory credential-free gate for new producer staging bytes only."""
    report.unlink(missing_ok=True)
    payload = payload.resolve(strict=True)
    if not payload.is_dir():
        raise RuntimeError("--payload must be a staging directory")
    if report.resolve().is_relative_to(payload):
        raise RuntimeError("--report must be outside the payload")
    if platform.system() != "Darwin":
        raise RuntimeError("producer signing requires macOS")
    code = targets(payload)
    if require_cli_inventory:
        names = {path.name for path, kind in code if kind == 2}
        missing = {"mvmctl", "mvm-hvf-supervisor", "mvm-libkrun-supervisor"} - names
        if missing:
            raise RuntimeError("missing required CLI inventory: " + ", ".join(sorted(missing)))
    entries = []
    with tempfile.TemporaryDirectory(prefix="mvm-producer-sign-") as tmp:
        for path, kind in sorted(code, key=lambda item: item[1] == 2):
            keys = ROLES.get(path.name, []) if kind == 2 else []
            args = ["codesign", "--force", "--sign", "-", "--timestamp=none"]
            if keys:
                entitlements = Path(tmp) / "entitlements.plist"
                entitlements.write_bytes(plistlib.dumps(dict.fromkeys(keys, True)))
                args += ["--entitlements", entitlements]
            run(*args, path)
            run("codesign", "--verify", "--strict", "--all-architectures", path)
            verify_entitlements(path, keys)
            entries.append({
                "path": str(path.relative_to(payload)),
                "role": path.name if keys else "code",
                "required_entitlements": keys,
                "verification": "strict-all-architectures",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            })
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({
        "status": "ProducerAdhocVerified", "notarized": False, "files": entries,
    }, indent=2) + "\n")


def unconfigured(report):
    """Record that this run shipped without Developer ID signing.

    Only a run with no Apple credential at all is skipped. A partial set is a
    misconfiguration and still fails in `sign`, so a typo in one secret name
    cannot quietly downgrade a release that was meant to be notarized.
    """
    if any(os.environ.get(name) for name in CREDENTIALS):
        return False
    report.unlink(missing_ok=True)
    report.parent.mkdir(parents=True, exist_ok=True)
    message = ("no Apple signing credentials are configured; the macOS payload "
               "keeps its ad-hoc signature and is not notarized")
    report.write_text(json.dumps({"status": "Unconfigured", "reason": message},
                                 indent=2) + "\n")
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::warning::{message}")
    else:
        print(f"warning: {message}")
    return True


def sign(payload, report):
    payload = payload.resolve(strict=True)
    if not payload.is_dir():
        raise RuntimeError("--payload must be a staging directory")
    if report.resolve().is_relative_to(payload):
        raise RuntimeError("--report must be outside the payload")
    # A failed rerun must not leave a previous Accepted report as this run's evidence.
    report.unlink(missing_ok=True)
    missing = [name for name in CREDENTIALS if not os.environ.get(name)]
    if missing:
        raise RuntimeError("missing Apple signing credentials: " + ", ".join(missing))
    if platform.system() != "Darwin":
        raise RuntimeError("Developer ID signing requires macOS")
    team = os.environ["APPLE_TEAM_ID"]
    identity = os.environ["APPLE_DEVELOPER_ID_IDENTITY"]
    if not (team.isalnum() and len(team) == 10 and
            identity.startswith("Developer ID Application: ") and
            identity.endswith(f"({team})")):
        raise RuntimeError("Developer ID Application identity must match APPLE_TEAM_ID")
    code = targets(payload)
    requirement = DEVELOPER_ID_REQUIREMENT.format(team=team)
    with tempfile.TemporaryDirectory(prefix="mvm-notary-") as tmp:
        root = Path(tmp)
        keychain = root / "release.keychain-db"
        p12 = root / "identity.p12"
        encoded = "".join(os.environ[CREDENTIALS[0]].split())
        p12.write_bytes(base64.b64decode(encoded, validate=True))
        p12.chmod(0o600)
        password = secrets.token_urlsafe(32)
        created = False
        try:
            run("security", "create-keychain", "-p", password, keychain)
            created = True
            run("security", "set-keychain-settings", "-lut", "21600", keychain)
            run("security", "unlock-keychain", "-p", password, keychain)
            run("security", "import", p12, "-k", keychain, "-P",
                os.environ[CREDENTIALS[1]], "-T", "/usr/bin/codesign")
            p12.unlink()
            run("security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:",
                "-s", "-k", password, keychain)
            # Sign dylibs first; no --deep, ad-hoc identity, or entitlement on a dylib.
            for path, kind in sorted(code, key=lambda item: item[1] == 2):
                args = ["codesign", "--force", "--sign", identity, "--keychain",
                        keychain, "--timestamp", "--options", "runtime"]
                keys = ROLES.get(path.name, []) if kind == 2 else []
                if keys:
                    entitlements = root / "entitlements.plist"
                    entitlements.write_bytes(plistlib.dumps(dict.fromkeys(keys, True)))
                    args += ["--entitlements", entitlements]
                run(*args, path)
                run("codesign", "--verify", "--strict", "--all-architectures",
                    "-R", requirement, path)
                verify_entitlements(path, keys)
            archive = root / "submission.zip"
            run("ditto", "-c", "-k", "--keepParent", payload, archive)
            result = json.loads(run(
                "xcrun", "notarytool", "submit", archive, "--apple-id",
                os.environ["APPLE_ID"], "--team-id", team, "--password",
                os.environ["APPLE_APP_SPECIFIC_PASSWORD"], "--wait", "--timeout",
                "30m", "--output-format", "json"))
            if result.get("status") != "Accepted" or not result.get("id"):
                raise RuntimeError(f"notarization not Accepted: {result.get('status')}")
            entries = []
            for path, _ in code:
                run("codesign", "--verify", "--strict", "--all-architectures",
                    "--check-notarization", "-R", requirement, path)
                entries.append({"path": str(path.relative_to(payload)),
                                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
            # Standalone Mach-O, ZIP, tar, wheels and npm archives cannot be stapled.
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(json.dumps({"status": "Accepted", "id": result["id"],
                                          "team_id": team, "files": entries}, indent=2) + "\n")
        finally:
            if created:
                run("security", "delete-keychain", keychain)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--producer-adhoc", action="store_true",
                        help="sign and verify new staged Mach-O without Apple credentials")
    parser.add_argument("--require-cli-inventory", action="store_true",
                        help="require mvmctl plus the HVF and libkrun supervisors")
    parser.add_argument(
        "--skip-unconfigured", action="store_true",
        help="exit 0 with an Unconfigured report when no Apple credential is set")
    args = parser.parse_args()
    try:
        if args.producer_adhoc:
            if args.skip_unconfigured:
                raise RuntimeError("--producer-adhoc cannot skip signing")
            producer_sign(args.payload, args.report, args.require_cli_inventory)
            return
        if args.require_cli_inventory:
            raise RuntimeError("--require-cli-inventory requires --producer-adhoc")
        if args.skip_unconfigured and unconfigured(args.report):
            return
        sign(args.payload, args.report)
    except (RuntimeError, ValueError, OSError, struct.error) as error:
        parser.exit(1, f"macOS release signing failed: {error}\n")


if __name__ == "__main__":
    main()
