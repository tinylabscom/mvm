#!/usr/bin/env python3
"""Public Claude acquisition prerequisite witness; never launches or reads credentials."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid


spec = importlib.util.spec_from_file_location(
    "oci_witness", Path(__file__).with_name("check-oci-bundle-smoke.py"))
witness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(witness)
Blocked = witness.Blocked
require = witness.require
REFERENCE = "agent/claude@2.0.0"


def sha256(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
            "expected a lowercase SHA-256 digest")
    return value


def private_directory(path):
    require(path.is_absolute() and path == path.resolve(),
            "consumer paths must be absolute and contain no symlinks")
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "consumer directory must be owned by this user with mode 0700")


def consumer_environment(home, mvm_home):
    private_directory(home)
    private_directory(mvm_home)
    require(home != Path.home().resolve(), "refusing the operator's ordinary HOME")
    require(mvm_home.is_relative_to(home) and mvm_home != home,
            "MVM_HOME must be inside the isolated HOME")
    # Never traverse prepared identity, binding or trust stores.
    for relative in ("bundles", "cache/registry-packs", "registry/packs.lock.toml",
                     "audit", "sessions", "vms"):
        path = mvm_home / relative
        require(not path.exists() and not path.is_symlink(),
                f"consumer application/runtime state is not pristine: {relative}")
    config = home / ".config"
    require(not config.exists() and not config.is_symlink(),
            "ambient consumer configuration present")
    return {
        "HOME": str(home), "MVM_HOME": str(mvm_home),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
    }


def released_cli(path, expected):
    sha256(expected)
    require(path.is_absolute() and path == path.resolve(),
            "CLI must be an absolute path without symlinks")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and os.access(path, os.X_OK),
            "released CLI must be an executable regular file")
    require(not info.st_mode & 0o222, "released CLI must have no write permission bits")
    require(witness.digest(path) == expected, "released CLI digest mismatch")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def assert_application(info, expected):
    require(isinstance(info, dict), "pack verify did not return an object")
    for field, value in {
        "kind": "application", "reference": REFERENCE, "guest_arch": "aarch64",
        "manifest_sha256": expected.descriptor_sha256,
        "verification_scope": "descriptor_and_bundle_archive",
    }.items():
        require(info.get(field) == value, f"verified application mismatch: {field}")
    bundle = info.get("bundle")
    require(isinstance(bundle, dict), "verified bundle metadata missing")
    for field, value in {
        "archive_sha256": expected.archive_sha256,
        "archive_size": expected.archive_size, "key_id": expected.key_id,
    }.items():
        require(bundle.get(field) == value, f"verified bundle mismatch: {field}")
    require(bool(info.get("signer_identity")) and bool(info.get("signer_issuer")),
            "publisher identity missing")


def assert_caller_metadata(record, installation, public_key_sha256):
    require(isinstance(record, dict) and record.get("version") == 1,
            "unsupported caller identity metadata")
    require(str(uuid.UUID(installation)) == installation
            and uuid.UUID(installation).int != 0,
            "caller installation assertion must be a nonzero canonical UUID")
    require(record.get("installation") == installation, "caller installation mismatch")
    state = record.get("state")
    require(isinstance(state, dict) and state.get("kind") == "enrolled",
            "caller enrollment is missing or pending; retain recovery state")
    key = state.get("public_key")
    require(isinstance(key, list) and len(key) == 32
            and all(type(byte) is int and 0 <= byte <= 255 for byte in key),
            "invalid caller public pin")
    require(hashlib.sha256(bytes(key)).hexdigest() == sha256(public_key_sha256),
            "caller public pin mismatch")
    return {"installation": installation, "public_key_sha256": public_key_sha256,
            "scope": "public_metadata_only_not_native_executable_acl"}


def assert_binding_metadata(output, expected_name):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+", expected_name), "invalid binding name assertion")
    rows = [line.split("\t") for line in output.splitlines() if line.strip()]
    # The ordinary application route selects exactly one provider-bound slot.
    eligible = [row for row in rows if "provider=anthropic" in row[1:]]
    require(len(eligible) == 1 and eligible[0][0] == expected_name,
            "requires exactly one expected Anthropic provider binding")
    require(eligible[0][1:] == [
        "type=bearer", "hosts=api.anthropic.com", "provider=anthropic"],
        "Anthropic binding metadata has unexpected auth, destinations or approval")
    return {"name": expected_name, "provider": "anthropic",
            "host": "api.anthropic.com", "scope": "metadata_only_not_secret_reveal"}


def readiness(args, runner, env, report):
    caller = runner.run("caller-metadata",
                        [args.cli, "env", "caller-identity", "show"], env)
    report["caller_metadata"] = assert_caller_metadata(
        json.loads(caller["stdout"]), args.caller_installation,
        args.caller_public_key_sha256)
    bindings = runner.run("binding-metadata", [args.cli, "secret", "ls"], env)
    report["binding_metadata"] = assert_binding_metadata(
        bindings["stdout"], args.binding_name)


def preflight(args, runner, report):
    require(os.environ.get("MVM_TEST_CLAUDE_DEMO") == "1",
            "requires explicit MVM_TEST_CLAUDE_DEMO=1")
    require(args.endpoint == "api.anthropic.com:443", "unexpected allowed endpoint")
    require(args.archive_size > 0, "archive size must be positive")
    require(bool(args.key_id), "bundle key assertion missing")
    require(re.fullmatch(r"[0-9a-f]{40}", args.release_commit),
            "release commit must be a full Git SHA")
    for value in (args.descriptor_sha256, args.archive_sha256):
        sha256(value)
    env = consumer_environment(args.home, args.mvm_home)
    identity = released_cli(args.cli, args.cli_sha256)
    if getattr(args, "check_readiness", False):
        require(args.caller_installation and args.caller_public_key_sha256
                and args.binding_name, "readiness requires caller and binding assertions")
        readiness(args, runner, env, report)
    version = runner.run("version", [args.cli, "--version"], env)
    require(version["stdout"].strip() == args.version, "released CLI version mismatch")
    search = runner.run("search", [args.cli, "search", "agent/claude"], env)
    require(any(re.search(r"\bagent/claude\b", line)
                and re.search(r"(?<![\d.])2\.0\.0(?![\d.])", line)
                for line in search["stdout"].splitlines()),
            "public search did not name agent/claude version 2.0.0")
    runner.run("pull", [args.cli, "pull", "agent/claude"], env)
    verified = runner.run("verify", [args.cli, "pack", "verify", REFERENCE, "--json"], env)
    info = json.loads(verified["stdout"])
    assert_application(info, args)
    archive = args.mvm_home / "bundles" / f"{args.archive_sha256}.mvmpkg"
    require(archive == archive.resolve() and archive.is_file(),
            "installed archive missing or symlinked")
    require(archive.stat().st_size == args.archive_size, "measured archive size mismatch")
    measured = witness.digest(archive)
    require(measured == args.archive_sha256, "measured archive digest mismatch")
    require(released_cli(args.cli, args.cli_sha256) == identity,
            "CLI identity changed during preflight")
    report.update(status="preflight_passed", verified_application=info,
                  measured_archive_size=archive.stat().st_size,
                  measured_archive_sha256=measured,
                  release_commit_assertion=args.release_commit,
                  endpoint_assertion=args.endpoint)
    return env


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "home", "mvm-home"):
        result.add_argument("--" + name, type=Path, required=True)
    for name in ("cli-sha256", "version", "release-commit", "descriptor-sha256",
                 "archive-sha256", "key-id", "endpoint"):
        result.add_argument("--" + name, required=True)
    result.add_argument("--archive-size", required=True, type=int)
    result.add_argument("--check-readiness", action="store_true",
                        help="also check canonical caller and binding public metadata")
    for name in ("caller-installation", "caller-public-key-sha256", "binding-name"):
        result.add_argument("--" + name)
    return result


def main():
    args = parser().parse_args()
    os.umask(0o077)
    evidence = Path(tempfile.mkdtemp(prefix="mvm-claude-preflight-", dir="/tmp"))
    report = {
        "status": "blocked", "commands": [], "demo_acceptance": False,
        "model_request_attempted": False, "guest_boot_witnessed": False,
        "custody_verified": False, "credential_cleanup_attempted": False,
    }
    try:
        preflight(args, witness.Runner(evidence, report), report)
    except (Exception, KeyboardInterrupt) as error:
        # External parser errors can quote input; do not include their text.
        report["blocker"] = str(error) if isinstance(error, Blocked) else type(error).__name__
    finally:
        (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "evidence": str(evidence)}))
    return 0 if report["status"] == "preflight_passed" else 1


if __name__ == "__main__":
    sys.exit(main())
