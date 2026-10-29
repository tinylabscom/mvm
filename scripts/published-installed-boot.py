#!/usr/bin/env python3
"""Release-only installed boot witness; standalone smokes remain diagnostic.

The smoke boots the CLI's current signed image pin, not a staged schema-3
candidate. Linux ARM boot is unverified: no ARM Linux KVM runner is available.
Only this workflow's successful two-lane aggregate is promotion evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile

LANES = {
    "x86_64-unknown-linux-gnu": ("x86_64", "firecracker", "Linux", "x86_64"),
    "aarch64-apple-darwin": ("aarch64", "hvf", "Darwin", "arm64"),
}
WORKFLOW = ".github/workflows/release.yml"
BOOT_CHECKS = [{"name": name, "result": "success"} for name in
               ("cold", "cache-reuse", "sdk-sidecar", "egress")]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return stream_sha(stream)


def stream_sha(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def identity(tag):
    e = os.environ
    require(re.fullmatch(r"v[0-9][A-Za-z0-9.+-]*", tag), "invalid tag")
    require(e["GITHUB_EVENT_NAME"] == "push", "only tag pushes are authoritative")
    require(e["GITHUB_REF"] == f"refs/tags/{tag}", "tag/ref mismatch")
    require(re.fullmatch(r"[0-9a-f]{40}", e["GITHUB_SHA"]), "invalid commit")
    require(e["GITHUB_WORKFLOW_REF"] ==
            f'{e["GITHUB_REPOSITORY"]}/{WORKFLOW}@refs/tags/{tag}',
            "not the release workflow")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]*", e[key]), "invalid run identity")
    return {
        "schema_version": 1,
        "cli": {"tag": tag, "commit": e["GITHUB_SHA"]},
        "workflow": {
            "repository": e["GITHUB_REPOSITORY"], "path": WORKFLOW,
            "run_id": e["GITHUB_RUN_ID"], "run_attempt": e["GITHUB_RUN_ATTEMPT"],
            "event": e["GITHUB_EVENT_NAME"], "ref": e["GITHUB_REF"],
        },
    }


def authenticate(directory, tag, targets):
    """Authenticate each exact archive through manifest, blob and provenance."""
    directory.mkdir(parents=True, exist_ok=True)
    repo = os.environ["GITHUB_REPOSITORY"]
    names = [f"mvmctl-{target}.tar.gz" for target in targets]
    names.append(f"mvm-guest-bins-{tag}.tar.gz")
    manifest = "checksums-sha256.txt"
    for name in [manifest, *names]:
        for suffix in ("", ".bundle"):
            run("gh", "release", "download", tag, "--repo", repo,
                "--pattern", name + suffix, "--dir", str(directory), "--clobber")
        run("cosign", "verify-blob", "--bundle", str(directory / (name + ".bundle")),
            "--certificate-identity", f"https://github.com/{repo}/{WORKFLOW}@refs/tags/{tag}",
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            str(directory / name))
    sums = {}
    for line in (directory / manifest).read_text().splitlines():
        match = re.fullmatch(r"([a-f0-9]{64}) [ *]([^/\\]+)", line)
        require(match, "invalid checksum manifest")
        digest, name = match.groups()
        require(name not in sums, "duplicate checksum entry")
        sums[name] = digest
    assets = []
    for name in names:
        require(sha(directory / name) == sums.get(name), f"checksum mismatch: {name}")
        run("gh", "attestation", "verify", str(directory / name), "--repo", repo,
            "--signer-workflow", f"{repo}/{WORKFLOW}",
            "--source-ref", f"refs/tags/{tag}", "--source-digest", os.environ["GITHUB_SHA"])
        assets.append({"name": name, "sha256": sums[name]})
    return sorted(assets, key=lambda asset: asset["name"])


def payload_hashes(archive, target):
    result = {}
    prefix = f"mvmctl-{target}/"
    with tarfile.open(archive) as tar:
        for member in tar:
            if member.isdir() and member.name == prefix.rstrip("/"):
                continue
            require(member.name.startswith(prefix), "unexpected archive root")
            relative = member.name[len(prefix):]
            require(not relative.startswith("/") and ".." not in Path(relative).parts,
                    "unsafe archive member")
            if member.isdir():
                continue
            require(member.isfile(), "non-regular archive payload")
            require(relative not in result, "duplicate archive member")
            with tar.extractfile(member) as stream:
                result[relative] = stream_sha(stream)
    require("mvmctl" in result, "missing CLI payload")
    return result


def installed_hashes(home, archives, target, tag):
    executable = (home / ".local/bin/mvmctl").resolve(strict=True)
    base = executable.parent
    require(base.is_relative_to(home.resolve()), "CLI escaped throwaway HOME")
    expected = payload_hashes(archives / f"mvmctl-{target}.tar.gz", target)
    require(executable.name == "mvmctl" and sha(executable) == expected["mvmctl"],
            "installed entrypoint mismatch")
    runtime = f"guest-runtime/mvm-guest-bins-{tag}.tar.gz"
    expected[runtime] = sha(archives / f"mvm-guest-bins-{tag}.tar.gz")
    for name, digest in expected.items():
        path = base / name
        require(path.resolve(strict=True).is_relative_to(base), "installed payload escaped")
        require(sha(path) == digest, f"installed bytes mismatch: {name}")
    return [{"path": name, "sha256": digest} for name, digest in sorted(expected.items())]


def smoke_home(state_file, owned_root):
    home = Path(state_file.read_text().rstrip("\n"))
    require(home.name == "home" and home.parent.parent == owned_root,
            "invalid smoke HOME")
    require(home.resolve(strict=True) == home, "unsafe smoke HOME")
    require(re.fullmatch(r"s\.[A-Za-z0-9]{3}", home.parent.name), "invalid smoke root")
    return home


def boot_checks(directory):
    checks = [json.loads(line) for line in
              (directory / "boot-results.jsonl").read_text().splitlines()]
    require(checks == BOOT_CHECKS, "missing or invalid four-boot outcomes")
    return checks


def lane(args):
    report = identity(args.tag)
    arch, backend, system, machine = LANES[args.target]
    require((platform.system(), platform.machine()) == (system, machine), "wrong runner")
    args.out.mkdir(parents=True, exist_ok=False)
    assets_dir = args.out / "authenticated"
    assets = authenticate(assets_dir, args.tag, [args.target])
    # No archive shortcut or inherited runtime overrides can enter this witness.
    env = {k: v for k, v in os.environ.items() if not k.startswith("MVM_")}
    state_file = args.out / "smoke-home.txt"
    env.update(MVM_SMOKE_KEEP="1", MVM_SMOKE_OUT=str(args.out / "smoke"),
               MVM_SMOKE_STATE_FILE=str(state_file))
    transcript = args.out / "smoke/transcript.log"
    # Deletion authority comes only from this wrapper-created root, NEVER the
    # state file. A corrupted state cannot nominate another smoke for cleanup.
    # w.<8 random chars>/s.<3 random chars> is as short as the standalone
    # mvm-fresh.<6 random chars> root, preserving macOS Unix-socket headroom.
    with tempfile.TemporaryDirectory(prefix="w.", dir="/tmp") as scratch:
        owned_root = Path(scratch).resolve()
        env["MVM_SMOKE_TEMP_PARENT"] = str(owned_root)
        run("sh", "scripts/smoke-fresh-install.sh", args.tag, env=env)
        home = smoke_home(state_file, owned_root)
        installed = installed_hashes(home, assets_dir, args.target, args.tag)
        checks = boot_checks(transcript.parent)
    text = transcript.read_text()
    require("\nPASS: " in text and "\nFAIL:" not in text, "smoke did not pass")
    report.update(assets=assets, boots=[{
        "host_target": args.target, "guest_arch": arch, "backend": backend,
        "result": "success", "installed": installed, "checks": checks,
        "transcript": {"path": "smoke/transcript.log", "sha256": sha(transcript)},
    }])
    (args.out / "lane.json").write_text(json.dumps(report, indent=2) + "\n")


def aggregate(args):
    report = identity(args.tag)
    assets = authenticate(args.assets, args.tag, list(LANES))
    boots = []
    files = sorted(args.lanes.glob("*/lane.json"))
    require(len(files) == 2, "exactly two lane reports required")
    for path in files:
        record = json.loads(path.read_text())
        for key, value in report.items():
            require(record.get(key) == value, f"lane identity mismatch: {key}")
        require(len(record["boots"]) == 1, "one boot per lane required")
        boot = record["boots"][0]
        target = boot["host_target"]
        require(target in LANES and target not in [b["host_target"] for b in boots],
                "unexpected or duplicate lane")
        arch, backend, _, _ = LANES[target]
        require((boot["guest_arch"], boot["backend"], boot["result"]) ==
                (arch, backend, "success"), "invalid boot result")
        require(boot["checks"] == boot_checks(path.parent / "smoke"),
                "four-boot outcomes mismatch")
        expected_assets = [a for a in assets if a["name"] in
                           (f"mvmctl-{target}.tar.gz", f"mvm-guest-bins-{args.tag}.tar.gz")]
        require(record["assets"] == expected_assets, "lane asset mismatch")
        hashes = payload_hashes(args.assets / f"mvmctl-{target}.tar.gz", target)
        hashes[f"guest-runtime/mvm-guest-bins-{args.tag}.tar.gz"] = next(
            a["sha256"] for a in assets if a["name"] == f"mvm-guest-bins-{args.tag}.tar.gz")
        require(boot["installed"] == [{"path": n, "sha256": h} for n, h in sorted(hashes.items())],
                "installed payload evidence mismatch")
        require(boot["transcript"]["path"] == "smoke/transcript.log", "unsafe transcript path")
        require(sha(path.parent / "smoke/transcript.log") == boot["transcript"]["sha256"],
                "transcript tampered")
        transcript = (path.parent / "smoke/transcript.log").read_text()
        require("\nPASS: " in transcript and "\nFAIL:" not in transcript,
                "missing successful smoke verdict")
        boot["transcript"]["path"] = f"{path.parent.name}/smoke/transcript.log"
        boots.append(boot)
    report.update(assets=assets, boots=sorted(boots, key=lambda b: b["host_target"]),
                  runtime_evidence="Installed archive bytes verified; guest runtime bytes are not measured.",
                  unverified=[{"host_target": "aarch64-unknown-linux-gnu",
                               "reason": "No ARM Linux KVM runner is available."}])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("lane", "aggregate"):
        sub = commands.add_parser(name)
        sub.add_argument("--tag", required=True)
        sub.add_argument("--out", type=Path, required=True)
        if name == "lane":
            sub.add_argument("--target", choices=LANES, required=True)
        else:
            sub.add_argument("--lanes", type=Path, required=True)
            sub.add_argument("--assets", type=Path, required=True)
    args = parser.parse_args()
    (lane if args.command == "lane" else aggregate)(args)


if __name__ == "__main__":
    main()
