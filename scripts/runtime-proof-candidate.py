#!/usr/bin/env python3
"""Fail-closed same-run runtime transport. Does not sign, publish or boot."""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import tomllib
import urllib.error
import urllib.request
from typing import Callable
import zipfile

from runtime_release_proof import (
    REPOSITORY, checksum_record, runtime_names, verify_quartet,
)

MAX_TRANSFER_BYTES = 256 * 1024 * 1024
MAX_RELEASE_TRANSFER_BYTES = 1024 * 1024 * 1024
RELEASE_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
)
UPLOAD_CONTEXT = "runtime-upload-context.json"
UPLOAD_PRODUCERS = {
    "unsigned": ("mvm-guest-bins", "guest-bins"),
    "checked": ("mvm-runtime-proof-input", "runtime-proof-input-check"),
    "signed": ("mvm-runtime-proof-candidate", "runtime-proof-candidate"),
}


@dataclass(frozen=True)
class TagSource:
    repository_id: int
    run_id: int
    run_attempt: int
    sha: str
    version: str


@dataclass(frozen=True)
class ArtifactTransfer:
    artifact_id: int
    digest: str
    name: str
    members: tuple[str, ...] | Callable[[Path], tuple[str, ...]]
    destination: Path
    max_bytes: int = MAX_TRANSFER_BYTES


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _rest_open(endpoint):
    # Same GitHub API endpoint `gh api` calls, for runners without the gh CLI.
    # The token goes only to api.github.com; a redirect target (signed blob
    # URL) is fetched without it.
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("no gh CLI and no GH_TOKEN for the GitHub REST API")
    request = urllib.request.Request(f"https://api.github.com/{endpoint}", headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        return urllib.request.build_opener(_NoRedirect).open(request, timeout=60)
    except urllib.error.HTTPError as error:
        location = error.headers.get("Location")
        if error.code in (301, 302, 303, 307, 308) and location and location.startswith("https://"):
            return urllib.request.urlopen(location, timeout=60)
        raise


def gh_json(endpoint):
    if shutil.which("gh") is None:
        with _rest_open(endpoint) as response:
            return json.loads(response.read())
    return json.loads(subprocess.check_output(
        ["gh", "api", "--hostname", "github.com", endpoint], text=True, timeout=60
    ))


def tag_source(env, version):
    runtime_names(version)
    ref = f"refs/tags/v{version}"
    if (
        env.get("GITHUB_REPOSITORY") != REPOSITORY
        or env.get("GITHUB_EVENT_NAME") != "push"
        or env.get("GITHUB_REF_TYPE") != "tag"
        or env.get("GITHUB_REF") != ref
        or env.get("GITHUB_WORKFLOW_REF") != f"{REPOSITORY}/.github/workflows/release.yml@{ref}"
        or not re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", ""))
    ):
        raise ValueError("runtime candidate requires the real version-matched release tag push")
    for name in ["GITHUB_REPOSITORY_ID", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]:
        if not re.fullmatch(r"[1-9][0-9]*", env.get(name, "")):
            raise ValueError(f"invalid actual workflow context: {name}")
    return TagSource(int(env["GITHUB_REPOSITORY_ID"]), int(env["GITHUB_RUN_ID"]),
                     int(env["GITHUB_RUN_ATTEMPT"]), env["GITHUB_SHA"], version)


def artifact_name(source, kind):
    base = UPLOAD_PRODUCERS[kind][0]
    return f"{base}-attempt-{source.run_attempt}"


def payload_names(version, kind):
    names = runtime_names(version)
    if kind == "unsigned":
        return names[:2] + ("mvmctl",)
    if kind == "checked":
        return names[:2]
    if kind == "signed":
        return names
    raise ValueError("unknown runtime transport kind")


def sha256(value):
    if not isinstance(value, str):
        raise ValueError("artifact transport digest must be a string")
    value = value.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("artifact transport digest is missing or malformed")
    return value


def validate_artifact(metadata, source, expected, *, max_bytes=None):
    limit = MAX_TRANSFER_BYTES if max_bytes is None else max_bytes
    artifact_id, digest, name = expected
    run = metadata.get("workflow_run", {})
    if (
        metadata.get("id") != artifact_id
        or metadata.get("name") != name
        or metadata.get("expired") is not False
        or sha256(metadata.get("digest", "")) != sha256(digest)
        or run.get("id") != source.run_id
        or run.get("repository_id") != source.repository_id
        or run.get("head_repository_id") != source.repository_id
        or run.get("head_sha") != source.sha
    ):
        raise ValueError("artifact ID/digest/repository/run/source does not match this release")
    size = metadata.get("size_in_bytes")
    if type(size) is not int or not 0 < size <= limit:
        raise ValueError("runtime artifact exceeds the bounded transfer size")


def extract_exact(archive, destination, names, *, max_bytes=None):
    limit = MAX_TRANSFER_BYTES if max_bytes is None else max_bytes
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        if sorted(entry.filename for entry in entries) != sorted(names):
            raise ValueError("runtime artifact has missing, duplicate or unexpected members")
        total = 0
        for entry in entries:
            mode = entry.external_attr >> 16
            total += entry.file_size
            if (
                entry.is_dir()
                or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                or entry.flag_bits & 1
                or total > limit
            ):
                raise ValueError("runtime artifact has nonregular/encrypted/oversized members")
        # A fresh directory is mandatory; never overlay an unsigned or signed
        # download or follow an existing destination symlink.
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        for entry in entries:
            descriptor = os.open(destination / entry.filename,
                                 os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with zipped.open(entry) as reader, os.fdopen(descriptor, "wb") as output:
                copied = 0
                while block := reader.read(1024 * 1024):
                    copied += len(block)
                    if copied > entry.file_size:
                        raise ValueError("artifact member exceeds its declared bound")
                    output.write(block)
                if copied != entry.file_size:
                    raise ValueError("artifact member is truncated")


def payload_hashes(version, directory, kind):
    names = runtime_names(version)
    expected = payload_names(version, kind)
    for name in expected:
        path = directory / name
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("runtime directory contains a nonregular input")
    if kind == "signed":
        return verify_quartet(version, directory)
    hashes = {}
    for name in expected:
        with (directory / name).open("rb") as stream:
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    if checksum_record((directory / names[1]).read_text(), names[0]) != hashes[names[0]]:
        raise ValueError("unsigned archive/checksum mismatch")
    return hashes


def producer_job(kind):
    return UPLOAD_PRODUCERS[kind][1]


def upload_record(env, version, kind, hashes):
    # This record is workflow-owned transport provenance, not a signature or
    # runtime admission capability. It is carried INSIDE the pinned artifact.
    for name in ["GITHUB_REPOSITORY_ID", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]:
        if not re.fullmatch(r"[1-9][0-9]*", env.get(name, "")):
            raise ValueError(f"missing producer workflow context: {name}")
    if env.get("GITHUB_JOB") != producer_job(kind):
        raise ValueError("upload context must be emitted by the actual producer job")
    if not re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", "")):
        raise ValueError("producer source SHA is missing")
    keys = ["GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_REF",
            "GITHUB_REF_TYPE", "GITHUB_WORKFLOW_REF"]
    if any(not env.get(key) for key in keys):
        raise ValueError("producer workflow/ref context is missing")
    if kind != "unsigned":
        tag_source(env, version)
    return {
        "schema_version": 1, "kind": kind, "version": version,
        "repository": env["GITHUB_REPOSITORY"],
        "repository_id": int(env["GITHUB_REPOSITORY_ID"]),
        "run_id": int(env["GITHUB_RUN_ID"]),
        "run_attempt": int(env["GITHUB_RUN_ATTEMPT"]),
        "source_sha": env["GITHUB_SHA"],
        "event": env["GITHUB_EVENT_NAME"], "ref": env["GITHUB_REF"],
        "ref_type": env["GITHUB_REF_TYPE"], "workflow_ref": env["GITHUB_WORKFLOW_REF"],
        "producer_job": env["GITHUB_JOB"], "files": hashes,
    }


def validate_upload_record(record, source, kind, hashes):
    expected = upload_record({
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(source.repository_id),
        "GITHUB_RUN_ID": str(source.run_id),
        "GITHUB_RUN_ATTEMPT": str(source.run_attempt),
        "GITHUB_SHA": source.sha, "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": f"refs/tags/v{source.version}", "GITHUB_REF_TYPE": "tag",
        "GITHUB_WORKFLOW_REF":
            f"{REPOSITORY}/.github/workflows/release.yml@refs/tags/v{source.version}",
        "GITHUB_JOB": producer_job(kind),
    }, source.version, kind, hashes)
    # JSON comparison is type-strict (Python otherwise equates True and 1).
    if json.dumps(record, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("upload context differs from this attempt/source/producer or payload")


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate upload context key")
        result[key] = value
    return result


def verify_directory(source, directory, kind):
    expected = list(payload_names(source.version, kind)) + [UPLOAD_CONTEXT]
    if directory.is_symlink() or sorted(p.name for p in directory.iterdir()) != sorted(expected):
        raise ValueError("runtime directory lacks the exact payload and upload context")
    context = directory / UPLOAD_CONTEXT
    if not stat.S_ISREG(context.lstat().st_mode) or context.stat().st_size > 16 * 1024:
        raise ValueError("upload context must be a bounded ordinary file")
    record = json.loads(context.read_text(), object_pairs_hook=no_duplicate_keys)
    hashes = (verify_quartet(source.version, directory, source_sha=source.sha)
              if kind == "signed" else payload_hashes(source.version, directory, kind))
    validate_upload_record(record, source, kind, hashes)
    return hashes


def emit_upload_context(root, directory, kind):
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    expected = payload_names(version, kind)
    if directory.is_symlink() or sorted(p.name for p in directory.iterdir()) != sorted(expected):
        raise ValueError("producer output must be exact and have no prewritten context")
    hashes = (verify_quartet(version, directory, source_sha=tag_source(os.environ, version).sha)
              if kind == "signed" else payload_hashes(version, directory, kind))
    record = upload_record(os.environ, version, kind, hashes)
    # Never overwrite context planted by a build step or an earlier attempt.
    descriptor = os.open(directory / UPLOAD_CONTEXT,
                         os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(record, output, sort_keys=True)
        output.write("\n")
    return record


def validate_unsigned_runtime(source, directory):
    if (
        os.environ.get("GITHUB_JOB") != producer_job("checked")
        or "ACTIONS_ID_TOKEN_REQUEST_TOKEN" in os.environ
        or "ACTIONS_ID_TOKEN_REQUEST_URL" in os.environ
    ):
        raise ValueError("canonical reader may run only in the unprivileged input-check job")
    before = verify_directory(source, directory, "unsigned")
    # Only the same-source, hash-bound tool in this exact producer artifact
    # may read the archive. Never discover a validator on PATH or expose the
    # signing job's GitHub/OIDC environment to it. Environment clearing is
    # hygiene, not a process/filesystem sandbox: the job has NO OIDC permission.
    tool = (directory / "mvmctl").resolve()
    archive = (directory / runtime_names(source.version)[0]).resolve()
    tool.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix="mvm-runtime-reader-") as temporary:
        home = str(Path(temporary).resolve())
        result = subprocess.run(
            [str(tool), "dev", "guest-bins", "--check-release-archive", str(archive)],
            cwd=home,
            env={"HOME": home, "MVM_HOME": home, "TMPDIR": home, "PATH": "/usr/bin:/bin"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=60,
        )
    if len(result.stdout) > 4 * 1024 * 1024:
        raise ValueError("canonical runtime reader output exceeds its bound")
    manifest = json.loads(result.stdout, object_pairs_hook=no_duplicate_keys)
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != source.version
        or manifest.get("source") != {"commit": source.sha, "worktree": {"state": "clean"}}
    ):
        raise ValueError("canonical runtime reader reports a different version or source")
    if verify_directory(source, directory, "unsigned") != before:
        raise ValueError("runtime input or canonical reader changed during validation")
    return manifest


def copy_exact_subjects(directory, destination, expected, *, max_bytes=None):
    """Append exact bytes to a caller-owned directory, never overwrite."""
    # The bound is per subject: the name set is a fixed inventory, so the
    # aggregate stays bounded, while a staged debug build legitimately sums
    # past one subject's limit.
    limit = MAX_TRANSFER_BYTES if max_bytes is None else max_bytes
    for name, expected_digest in expected.items():
        total = 0
        with (directory / name).open("rb") as reader:
            descriptor = os.open(destination / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "wb") as output:
                while block := reader.read(1024 * 1024):
                    total += len(block)
                    if total > limit:
                        raise ValueError("runtime subject copy exceeds size bound")
                    output.write(block)
                    digest.update(block)
        if digest.hexdigest() != expected_digest:
            raise ValueError("runtime subject changed while copying")


def prepare_checked_input(source, directory, destination, root):
    validate_unsigned_runtime(source, directory)
    before = verify_directory(source, directory, "unsigned")
    expected = {name: before[name] for name in payload_names(source.version, "checked")}
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    copy_exact_subjects(directory, destination, expected)
    emit_upload_context(root, destination, "checked")
    return verify_directory(source, destination, "checked")


def signing_inputs(source, original, checked):
    if os.environ.get("GITHUB_JOB") != producer_job("signed"):
        raise ValueError("candidate staging requires the fixed signing job")
    original_hashes = verify_directory(source, original, "unsigned")
    checked_hashes = verify_directory(source, checked, "checked")
    expected = {name: original_hashes[name]
                for name in payload_names(source.version, "checked")}
    if checked_hashes != expected:
        raise ValueError("checked archive/checksum differ from the original producer")
    return expected


def stage_signing_input(source, original, checked, destination):
    expected = signing_inputs(source, original, checked)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    copy_exact_subjects(checked, destination, expected)
    return expected


def seal_candidate(source, original, checked, directory, root):
    expected = signing_inputs(source, original, checked)
    if directory.is_symlink() or sorted(p.name for p in directory.iterdir()) != sorted(runtime_names(source.version)):
        raise ValueError("candidate must contain the exact quartet before sealing")
    hashes = verify_quartet(source.version, directory, source_sha=source.sha)
    if any(hashes[name] != digest for name, digest in expected.items()):
        raise ValueError("candidate signing changed the original archive/checksum")
    emit_upload_context(root, directory, "signed")
    return verify_directory(source, directory, "signed")


def current_source(root):
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    source = tag_source(os.environ, version)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    tag = gh_json(f"repos/{REPOSITORY}/commits/v{version}")
    attempt = gh_json(
        f"repos/{REPOSITORY}/actions/runs/{source.run_id}/attempts/{source.run_attempt}"
    )
    tracked = subprocess.check_output(["git", "show", "HEAD:Cargo.toml"], cwd=root)
    if (
        head != source.sha or tag.get("sha") != source.sha
        or tracked != (root / "Cargo.toml").read_bytes()
        or attempt.get("id") != source.run_id
        or attempt.get("run_attempt") != source.run_attempt
        or attempt.get("head_sha") != source.sha
        or attempt.get("path") != ".github/workflows/release.yml"
        or attempt.get("event") != "push"
    ):
        raise ValueError("checkout, original Cargo version and actual tag commit must agree")
    return source


def _gh_download(endpoint):
    if shutil.which("gh") is None:
        return _rest_open(endpoint + "/zip"), None
    process = subprocess.Popen(
        ["gh", "api", "--hostname", "github.com", endpoint + "/zip"], stdout=subprocess.PIPE
    )
    return process.stdout, process


def download_archive(endpoint, archive, *, max_bytes=None):
    limit = MAX_TRANSFER_BYTES if max_bytes is None else max_bytes
    stream, process = _gh_download(endpoint)
    try:
        total = 0
        with archive.open("xb") as output:
            while block := stream.read(1024 * 1024):
                total += len(block)
                if total > limit:
                    raise ValueError("downloaded runtime artifact exceeds size bound")
                output.write(block)
        if process is not None and process.wait() != 0:
            raise ValueError("runtime artifact download failed")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        stream.close()


def retrieve_artifact(source, transfer):
    if type(transfer.artifact_id) is not int or transfer.artifact_id <= 0:
        raise ValueError("artifact ID must be an actual positive numeric upload ID")
    endpoint = f"repos/{REPOSITORY}/actions/artifacts/{transfer.artifact_id}"
    digest = sha256(transfer.digest)
    metadata = gh_json(endpoint)
    validate_artifact(metadata, source, (transfer.artifact_id, digest, transfer.name),
                      max_bytes=transfer.max_bytes)
    with tempfile.TemporaryDirectory(prefix="mvm-runtime-transfer-") as temporary:
        archive = Path(temporary) / "artifact.zip"
        download_archive(endpoint, archive, max_bytes=transfer.max_bytes)
        with archive.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != digest:
            raise ValueError("actual artifact ZIP digest mismatch")
        names = transfer.members(archive) if callable(transfer.members) else transfer.members
        extract_exact(archive, transfer.destination, names, max_bytes=transfer.max_bytes)
    return tuple(names)


def fetch(args, source):
    if not re.fullmatch(r"[1-9][0-9]*", args.artifact_id):
        raise ValueError("artifact ID must be the actual numeric upload ID")
    retrieve_artifact(source, ArtifactTransfer(
        int(args.artifact_id), args.artifact_digest, artifact_name(source, args.kind),
        payload_names(source.version, args.kind) + (UPLOAD_CONTEXT,), args.out_dir,
    ))
    return verify_directory(source, args.out_dir, args.kind)


def checksum_pairs(directory, names):
    subjects = [name for name in names if not name.endswith(".sha256")]
    if set(names) != set(subjects) | {name + ".sha256" for name in subjects}:
        raise ValueError("release payload lacks exact archive/checksum pairs")
    hashes = {}
    for subject in subjects:
        with (directory / subject).open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        text = (directory / (subject + ".sha256")).read_text()
        if len(text.splitlines()) != 1 or checksum_record(text, subject) != digest:
            raise ValueError("release sidecar is not the exact subject checksum")
        hashes[subject] = digest
        hashes[subject + ".sha256"] = hashlib.sha256(text.encode()).hexdigest()
    return hashes


def package_members(version, archive):
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
    packages = [name for name in names if name.endswith((".deb", ".rpm"))]
    expected_arches = set()
    for name in packages:
        deb = re.fullmatch(r"mvmctl_" + re.escape(version) + r"-1_(amd64|arm64)\.deb", name)
        rpm = re.fullmatch(r"mvmctl-" + re.escape(version)
                           + r"-[A-Za-z0-9._+~]+\.(x86_64|aarch64)\.rpm", name)
        if deb:
            expected_arches.add(("deb", deb[1]))
        elif rpm:
            expected_arches.add(("rpm", rpm[1]))
        else:
            raise ValueError("unexpected package name/version/architecture")
    if len(packages) != 4 or expected_arches != {
        ("deb", "amd64"), ("deb", "arm64"), ("rpm", "x86_64"), ("rpm", "aarch64")
    }:
        raise ValueError("release requires both package formats on both architectures")
    expected = tuple(packages + [name + ".sha256" for name in packages])
    if sorted(names) != sorted(expected):
        raise ValueError("packages artifact has duplicate, missing or extra members")
    return expected


def candidate_pins(source, env):
    labels = ["ARCHIVE_SHA256", "CHECKSUM_SHA256", "ARCHIVE_BUNDLE_SHA256",
              "CHECKSUM_BUNDLE_SHA256"]
    return {name: sha256(env.get("RUNTIME_" + label, ""))
            for name, label in zip(runtime_names(source.version), labels)}


def verify_collected_candidate(source, directory, pins):
    hashes = verify_quartet(source.version, directory, source_sha=source.sha)
    if hashes != pins:
        raise ValueError("release quartet differs from the original candidate outputs")
    return hashes


def collect_release(source, args):
    if os.environ.get("GITHUB_JOB") != "release":
        raise ValueError("release collection requires the fixed publishing job")
    pins = candidate_pins(source, os.environ)
    listed = gh_json(f"repos/{REPOSITORY}/actions/runs/{source.run_id}/artifacts?per_page=100")
    artifacts = listed.get("artifacts", [])
    if (type(listed.get("total_count")) is not int
            or listed["total_count"] != len(artifacts) or len(artifacts) > 100):
        raise ValueError("release artifact listing is incomplete or exceeds its bound")
    selected_names = [f"mvmctl-{target}-attempt-{source.run_attempt}"
                      for target in RELEASE_TARGETS]
    selected_names.append(f"distro-packages-attempt-{source.run_attempt}")
    selected = {}
    for name in selected_names:
        matches = [artifact for artifact in artifacts if artifact.get("name") == name]
        if len(matches) != 1:
            raise ValueError(f"missing or ambiguous current-attempt release artifact: {name}")
        selected[name] = matches[0]
    # The publishing directory itself must also be fresh. Files from unrelated
    # artifacts, earlier attempts, validator tools and transport records never
    # enter this directory.
    args.out_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="mvm-release-inputs-") as temporary:
        temporary = Path(temporary)
        for index, (name, metadata) in enumerate(selected.items()):
            target = temporary / str(index)
            if name.startswith("mvmctl-"):
                release_target = name.removeprefix("mvmctl-").removesuffix(
                    f"-attempt-{source.run_attempt}"
                )
                archive = f"mvmctl-{release_target}.tar.gz"
                members = (archive, archive + ".sha256")
            else:
                members = lambda path: package_members(source.version, path)
            names = retrieve_artifact(source, ArtifactTransfer(
                metadata["id"], metadata.get("digest", ""), name, members, target,
                MAX_RELEASE_TRANSFER_BYTES,
            ))
            hashes = checksum_pairs(target, names)
            copy_exact_subjects(target, args.out_dir, hashes, max_bytes=MAX_RELEASE_TRANSFER_BYTES)
        if not re.fullmatch(r"[1-9][0-9]*", args.candidate_id):
            raise ValueError("candidate ID is missing")
        candidate = temporary / "candidate"
        retrieve_artifact(source, ArtifactTransfer(
            int(args.candidate_id), args.candidate_digest, artifact_name(source, "signed"),
            runtime_names(source.version) + (UPLOAD_CONTEXT,), candidate,
        ))
        if verify_directory(source, candidate, "signed") != pins:
            raise ValueError("downloaded candidate differs from the checked output pins")
        # Only the four retained files, never the validator or CI context.
        copy_exact_subjects(candidate, args.out_dir, pins)
    return verify_collected_candidate(source, args.out_dir, pins)


def stage_producer(source, candidate, cli, destination, root):
    pins = candidate_pins(source, os.environ)
    if verify_directory(source, candidate, "signed") != pins:
        raise ValueError("producer candidate differs from the pinned quartet")
    cli = cli.resolve(strict=True)
    if cli.name != "mvmctl":
        raise ValueError("producer staging requires the exact prebuilt mvmctl executable")
    original = cli.parent
    locations = [original / "guest-runtime"]
    if original.name == "bin":
        locations.append(original.parent / "lib/mvmctl/guest-runtime")
    for location in locations:
        for name in runtime_names(source.version):
            if (location / name).exists() or (location / name).is_symlink():
                raise ValueError("consumer executable prefix already contains candidate runtime inputs")
    # The Cargo bin declarations are the source inventory for native host
    # helpers. Copy only code, never user configuration, signing keys or caches.
    hostd = tomllib.loads((root / "crates/mvm-hostd/Cargo.toml").read_text())
    names = {"mvmctl", "mvm-gpu-endpoint", "libmvm_hostlib.so", "libmvm_hostlib.dylib"}
    names.update(item["name"] for item in hostd.get("bin", []))
    hashes = {}
    modes = {}
    for name in sorted(names):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", name):
            raise ValueError("invalid code inventory basename")
        if name not in {"mvmctl", "libmvm_hostlib.so", "libmvm_hostlib.dylib"} \
                and not name.startswith("mvm-"):
            raise ValueError("host helper inventory contains a non-mvm binary")
        path = original / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("prebuilt producer code must be ordinary files")
        if name.startswith("mvm") and not info.st_mode & 0o111:
            raise ValueError("prebuilt producer binary is not executable")
        with path.open("rb") as stream:
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
        modes[name] = info.st_mode & 0o777
    if "mvmctl" not in hashes:
        raise ValueError("prebuilt producer CLI is missing")
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Do NOT hardlink: signing a staged macOS helper must never mutate the
    # consumer's original executable inode.
    copy_exact_subjects(original, destination, hashes, max_bytes=MAX_RELEASE_TRANSFER_BYTES)
    for name, mode in modes.items():
        (destination / name).chmod(mode)
    runtime = destination / "guest-runtime"
    runtime.mkdir(mode=0o700)
    copy_exact_subjects(candidate, runtime, pins)
    verify_collected_candidate(source, runtime, pins)
    for name, expected in hashes.items():
        with (original / name).open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                raise ValueError("consumer code changed while staging producer inputs")
    return {"producer_cli": str(destination / "mvmctl"), "code": hashes, "runtime": pins}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("guard")
    emit = commands.add_parser("emit-upload-context")
    emit.add_argument("--kind", choices=["unsigned"], required=True)
    emit.add_argument("--directory", type=Path, required=True)
    validate = commands.add_parser("validate-input")
    validate.add_argument("--directory", type=Path, required=True)
    prepare = commands.add_parser("prepare-checked")
    prepare.add_argument("--directory", type=Path, required=True)
    prepare.add_argument("--out-dir", type=Path, required=True)
    for operation in ["stage-signing", "seal-candidate"]:
        staging = commands.add_parser(operation)
        staging.add_argument("--original-dir", type=Path, required=True)
        staging.add_argument("--checked-dir", type=Path, required=True)
        staging.add_argument("--directory", type=Path, required=True)
    collect = commands.add_parser("collect-release")
    collect.add_argument("--candidate-id", required=True)
    collect.add_argument("--candidate-digest", required=True)
    collect.add_argument("--out-dir", type=Path, required=True)
    verify = commands.add_parser("verify-collected")
    verify.add_argument("--directory", type=Path, required=True)
    producer = commands.add_parser("stage-producer")
    producer.add_argument("--candidate-dir", type=Path, required=True)
    producer.add_argument("--cli", type=Path, required=True)
    producer.add_argument("--out-dir", type=Path, required=True)
    transfer = commands.add_parser("fetch")
    transfer.add_argument("--kind", choices=list(UPLOAD_PRODUCERS), required=True)
    transfer.add_argument("--artifact-id", required=True)
    transfer.add_argument("--artifact-digest", required=True)
    transfer.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "emit-upload-context":
        print(json.dumps(emit_upload_context(args.root, args.directory, args.kind), sort_keys=True))
        return
    source = current_source(args.root)
    result = {"source_sha": source.sha, "run_attempt": source.run_attempt, "version": source.version}
    if args.command == "fetch":
        result["files"] = fetch(args, source)
    elif args.command == "validate-input":
        result["manifest"] = validate_unsigned_runtime(source, args.directory)
    elif args.command == "prepare-checked":
        result["files"] = prepare_checked_input(source, args.directory, args.out_dir, args.root)
    elif args.command == "stage-signing":
        result["files"] = stage_signing_input(
            source, args.original_dir, args.checked_dir, args.directory
        )
    elif args.command == "seal-candidate":
        result["files"] = seal_candidate(
            source, args.original_dir, args.checked_dir, args.directory, args.root
        )
        if path := os.environ.get("GITHUB_OUTPUT"):
            with open(path, "a") as outputs:
                for label, name in zip(
                    ["archive_sha256", "checksum_sha256", "archive_bundle_sha256",
                     "checksum_bundle_sha256"], runtime_names(source.version)
                ):
                    outputs.write(f"{label}={result['files'][name]}\n")
    elif args.command == "collect-release":
        result["files"] = collect_release(source, args)
    elif args.command == "verify-collected":
        result["files"] = verify_collected_candidate(
            source, args.directory, candidate_pins(source, os.environ)
        )
    elif args.command == "stage-producer":
        result["staging"] = stage_producer(
            source, args.candidate_dir, args.cli, args.out_dir, args.root
        )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
