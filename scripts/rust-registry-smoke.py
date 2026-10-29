#!/usr/bin/env python3
"""Registry consumer witness; requires authenticated released native code.

This is install/load evidence only: no VM or guest boot is exercised.
The release verifier is the sole cryptographic verifier. There is no fallback.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile


_envelope_spec = importlib.util.spec_from_file_location(
    "release_archive_envelope",
    Path(__file__).resolve().parent.parent
    / "nix/packaging/release/archive_envelope.py")
_envelope = importlib.util.module_from_spec(_envelope_spec)
_envelope_spec.loader.exec_module(_envelope)


PLATFORMS = {
    "aarch64-apple-darwin": ("Darwin", "arm64"),
    "x86_64-unknown-linux-gnu": ("Linux", "x86_64"),
    "aarch64-unknown-linux-gnu": ("Linux", "aarch64"),
}
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"

RUST_SOURCE = r'''
use runmvm_client::{DiscoveryOptions, Hostlib};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = DiscoveryOptions::from_env();
    if options.hostlib_path.is_none() {
        return Err("MVM_HOSTLIB_PATH is required".into());
    }
    let resolved = options.resolve()?;
    // SAFETY: the harness authenticated the exact release archive with the
    // release workflow's tag identity, preserves its matching helper set,
    // and controls this private directory and the loader environment.
    // The operator trusts this native code and its dependencies to implement
    // ABI 1.7, including memory ownership, thread safety and no FFI unwinding.
    // Authentication is provenance, not a sandbox or proof of ABI safety.
    let host = unsafe { Hostlib::load(&resolved) }?;
    let abi = host.abi_version();
    if abi >> 16 != 1 || abi & 0xffff < 7 {
        return Err("released hostlib does not implement ABI 1.7".into());
    }
    let reply = host.call_json_bytes("manifest.list", Some(b"{}"))?;
    println!("{{\"library\":{:?},\"abi\":{},\"method\":\"manifest.list\",\"reply\":{}}}",
        resolved.to_str().ok_or("non-UTF8 library path")?, abi,
        std::str::from_utf8(&reply)?);
    Ok(())
}
'''


def release_version(tag):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", tag):
        raise ValueError("expected a versioned release tag")
    return tag[1:]


def check_platform(target):
    if target not in PLATFORMS or PLATFORMS[target] != (
        platform.system(), platform.machine()
    ):
        raise ValueError("release target does not match this native host")
    if platform.system() == "Linux" and platform.libc_ver()[0] != "glibc":
        raise ValueError("released Linux CLI requires GNU libc")


def check_cargo_config_isolation(project, cargo_home):
    """Reject Cargo's config search paths without opening configuration payloads."""
    project = Path(project).resolve()
    directories = [directory / ".cargo" for directory in (project, *project.parents)]
    directories.append(Path(cargo_home).resolve())
    for directory in directories:
        for name in ("config", "config.toml"):
            candidate = directory / name
            try:
                candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                raise ValueError("cannot establish Cargo configuration isolation") from None
            # Source replacement can retain crates.io metadata identity, so
            # metadata alone cannot prove that registry resolution was isolated.
            raise ValueError("Cargo configuration isolation requires no config files")


def check_metadata(metadata, project, version, checkout):
    project = project.resolve()
    checkout = checkout.resolve()
    root = metadata["resolve"]["root"]
    packages = metadata["packages"]
    consumer = next(p for p in packages if p["id"] == root)
    if Path(consumer["manifest_path"]).resolve() != project / "Cargo.toml":
        raise ValueError("consumer is not the fresh external project")
    dependencies = consumer["dependencies"]
    if len(dependencies) != 1 or (
        dependencies[0]["name"] != "runmvm-client"
        or dependencies[0]["req"] != f"={version}"
        or dependencies[0]["source"] != REGISTRY
        or dependencies[0].get("path") is not None
    ):
        raise ValueError("consumer must depend only on exact registry runmvm-client")
    facade = []
    for package in packages:
        manifest = Path(package["manifest_path"]).resolve()
        if manifest.is_relative_to(checkout):
            raise ValueError("checkout source leakage")
        if package["id"] == root:
            continue
        if package["source"] != REGISTRY:
            raise ValueError("non-crates.io dependency source")
        if package["name"].startswith("mvm-") and package["name"] != "mvm-contract":
            raise ValueError("internal mvm dependency leaked into consumer")
        if package["name"] == "runmvm-client":
            facade.append(package)
    if len(facade) != 1 or facade[0]["version"] != version:
        raise ValueError("exact registry facade not resolved")
    return {"name": facade[0]["name"], "version": version,
            "source": facade[0]["source"], "manifest": facade[0]["manifest_path"]}


def extract_release(archive, destination, target):
    expected = f"mvmctl-{target}"
    _envelope.extract_package(archive, destination, expected)
    prefix = (destination / expected).resolve(strict=True)
    helpers = ["mvmctl", "mvm-network-endpoint"]
    if target == "aarch64-apple-darwin":
        helpers.append("mvm-hvf-supervisor")
    for helper in helpers:
        if not (prefix / helper).is_file() or not os.access(prefix / helper, os.X_OK):
            raise ValueError(f"missing released helper: {helper}")
    library = prefix / ("libmvm_hostlib.dylib" if "darwin" in target
                        else "libmvm_hostlib.so")
    return prefix, library.resolve(strict=True)


def witness(stdout, library):
    result = json.loads(stdout)
    if (result.get("library") != str(library) or
            not isinstance(result.get("abi"), int) or
            result["abi"] >> 16 != 1 or result["abi"] & 0xffff < 7 or
            result.get("method") != "manifest.list" or
            result.get("reply") != []):
        raise ValueError("invalid native manifest.list witness for empty home")
    return result


def smoke(args):
    version = release_version(args.tag)
    check_platform(args.target)
    checkout = Path(__file__).resolve().parent.parent
    assets = args.assets_dir.resolve(strict=True)
    repository = args.repository
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid release repository")
    args.evidence.mkdir(parents=True, exist_ok=True)
    commands = []
    with tempfile.TemporaryDirectory(prefix="mvm-rust-registry-") as temporary:
        work = Path(temporary).resolve()
        if work.is_relative_to(checkout):
            raise ValueError("consumer must be outside checkout")
        home = work / "home"
        home.mkdir()
        env = {key: value for key, value in os.environ.items()
               if key in ("PATH", "SYSTEMROOT", "TMPDIR", "RUSTUP_HOME")}
        if "RUSTUP_HOME" not in env:
            env["RUSTUP_HOME"] = str(Path.home() / ".rustup")
        env.update(HOME=str(home), CARGO_HOME=str(work / "cargo"),
                   CARGO_TARGET_DIR=str(work / "target"), MVM_HOME=str(home / ".mvm"),
                   COSIGN_IDENTITY=f"https://github.com/{repository}/.github/workflows/release.yml@refs/tags/{args.tag}",
                   COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com")

        def run(argv, cwd=work):
            if argv[0] == "cargo":
                check_cargo_config_isolation(cwd, env["CARGO_HOME"])
            commands.append([str(arg) for arg in argv])
            result = subprocess.run(argv, cwd=cwd, env=env, check=False,
                                    text=True, capture_output=True, timeout=900)
            with (args.evidence / "commands.log").open("a") as log:
                log.write(json.dumps(commands[-1]) + "\n" + result.stdout + result.stderr)
            result.check_returncode()
            return result.stdout

        # No native code from the archive is loaded before this gate passes.
        run(["bash", checkout / "nix/packaging/release/verify-release-assets.sh",
             "--assets-dir", assets, "--cosign", "--expect-version", version])
        archive = assets / f"mvmctl-{args.target}.tar.gz"
        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        prefix, library = extract_release(archive, work / "release", args.target)
        if run([prefix / "mvmctl", "--version"]).strip() != f"mvmctl {version}":
            raise ValueError("released CLI version mismatch")
        env["MVM_HOSTLIB_PATH"] = str(library)
        project = work / "consumer"
        (project / "src").mkdir(parents=True)
        (project / "Cargo.toml").write_text(
            '[package]\nname = "registry-witness"\nversion = "0.0.0"\nedition = "2021"\n'
            f'[dependencies]\nrunmvm-client = "={version}"\n')
        (project / "src/main.rs").write_text(RUST_SOURCE)
        (args.evidence / "Cargo.toml").write_bytes((project / "Cargo.toml").read_bytes())
        (args.evidence / "main.rs").write_text(RUST_SOURCE)
        run(["cargo", "generate-lockfile"], project)
        metadata_stdout = run(["cargo", "metadata", "--format-version", "1", "--locked"], project)
        origin = check_metadata(json.loads(metadata_stdout), project, version, checkout)
        (args.evidence / "metadata.json").write_text(metadata_stdout)
        (args.evidence / "Cargo.lock").write_bytes((project / "Cargo.lock").read_bytes())
        run(["cargo", "build", "--locked"], project)
        stdout = run(["cargo", "run", "--locked", "--quiet"], project)
        native = witness(stdout, library)
        evidence = {"tag": args.tag, "version": version, "platform": args.target,
                    "archive": archive.name, "archive_sha256": archive_hash,
                    "identity": env["COSIGN_IDENTITY"], "registry_facade": origin,
                    "native": native, "stdout": stdout, "argv": commands,
                    "guest_boot_witnessed": False, "vm_boot_witnessed": False}
        (args.evidence / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps(evidence))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--target", required=True, choices=PLATFORMS)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--assets-dir", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    smoke(parser.parse_args())
