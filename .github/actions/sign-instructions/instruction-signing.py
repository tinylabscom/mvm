#!/usr/bin/env python3
"""Transfer only source-bound instruction requests between isolated jobs."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
CONTEXT_KEYS = (
    "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_WORKFLOW_REF",
    "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
)


def context():
    values = {key: os.environ[key] for key in CONTEXT_KEYS}
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != values["GITHUB_SHA"]:
        raise ValueError("checkout does not match the workflow source revision")
    return values


def relative_path(name):
    path = PurePosixPath(name)
    if (not path.parts or path.is_absolute() or str(path) != name
            or any(part in (".", "..", ".git") for part in path.parts)
            or any(char in name for char in "\x00\r\n\\")
            or name.endswith(".sigstore.json")):
        raise ValueError(f"invalid instruction path: {name!r}")
    return path


def source_blob(name):
    relative_path(name)
    # Read the commit, not the producer's working tree or index. A symlink,
    # submodule, tree, or pathspec expanding to another name is not a file.
    entry = subprocess.check_output([
        "git", "--literal-pathspecs", "ls-tree", "-z", "HEAD", "--", name,
    ])
    fields, actual = entry.removesuffix(b"\0").split(b"\t", 1)
    mode, kind, oid = fields.split()
    if (actual != name.encode() or mode not in (b"100644", b"100755")
            or kind != b"blob"):
        raise ValueError(f"not a tracked regular file: {name}")
    size = int(subprocess.check_output(["git", "cat-file", "-s", oid]))
    if size > MAX_FILE:
        raise ValueError(f"instruction exceeds size limit: {name}")
    return subprocess.check_output(["git", "cat-file", "blob", oid])


def bounded_read(path, limit):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular transfer file: {path}")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"transfer exceeds size limit: {path}")
    return data


def discover(cli):
    output = subprocess.check_output(
        [cli, "trust", "instructions", "sign", "--dry-run", "."], text=True
    )
    root = Path.cwd().resolve()
    names = []
    for line in output.splitlines():
        path = Path(line)
        if not path.is_absolute():
            path = root / path
        # Normalize the CLI's "./" spelling, but do not resolve symlinks.
        name = path.relative_to(root).as_posix()
        relative_path(name)
        names.append(name)
    if not names or len(names) > 4096 or len(names) != len(set(names)):
        raise ValueError("instruction list is empty, duplicated, or oversized")
    return sorted(names)


def read_request(path):
    data = json.loads(bounded_read(path, 1024 * 1024))
    if set(data) != {"context", "files"} or data["context"] != context():
        raise ValueError("request belongs to another source, workflow, run, or attempt")
    files = data["files"]
    if not isinstance(files, dict) or not 0 < len(files) <= 4096:
        raise ValueError("invalid instruction file set")
    blobs = {}
    total = 0
    for name, digest in files.items():
        blob = source_blob(name)
        total += len(blob)
        if total > MAX_TOTAL or hashlib.sha256(blob).hexdigest() != digest:
            raise ValueError("instruction content does not match the source commit")
        blobs[name] = blob
    return blobs


def prepare(cli, output):
    files = {}
    total = 0
    for name in discover(cli):
        blob = source_blob(name)
        total += len(blob)
        if total > MAX_TOTAL:
            raise ValueError("instruction set exceeds size limit")
        files[name] = hashlib.sha256(blob).hexdigest()
    data = json.dumps({"context": context(), "files": files}, sort_keys=True)
    if len(data.encode()) > 1024 * 1024:
        raise ValueError("request exceeds size limit")
    output.mkdir()
    (output / "request.json").write_text(data)


def sign(request, output):
    blobs = read_request(request)  # Validate the entire request before signing.
    output.mkdir()
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "instruction"
        for name, blob in blobs.items():
            source.write_bytes(blob)
            bundle = output / (name + ".sigstore.json")
            bundle.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run([
                "cosign", "sign-blob", "--yes", "--new-bundle-format",
                "--bundle", str(bundle), str(source),
            ], check=True)


def verify(cli, request, candidate, output):
    blobs = read_request(request)
    if sorted(blobs) != discover(cli):
        raise ValueError("request does not cover the complete instruction policy")
    expected = {name + ".sigstore.json" for name in blobs}
    actual = set()
    for path in candidate.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in candidate bundle tree")
        if path.is_file():
            actual.add(path.relative_to(candidate).as_posix())
    if actual != expected:
        raise ValueError("candidate bundle set differs from the request")
    bundles = {}
    total = 0
    for name in expected:
        data = bounded_read(candidate / name, MAX_FILE)
        total += len(data)
        if total > MAX_TOTAL:
            raise ValueError("candidate bundle set exceeds size limit")
        bundles[name] = data
    # A dependency build may have changed the verifier job's checkout.
    # Refuse that state instead of verifying against producer-modified bytes.
    for name, blob in blobs.items():
        path = Path(name)
        if path.resolve() != Path.cwd().resolve() / name:
            raise ValueError("instruction path traverses a symlink")
        if bounded_read(path, MAX_FILE) != blob:
            raise ValueError("working instruction differs from source commit")
        sidecar = Path(name + ".sigstore.json")
        if sidecar.is_symlink():
            raise ValueError("instruction sidecar is a symlink")
        sidecar.write_bytes(bundles[name + ".sigstore.json"])
    ctx = context()
    prefix = ctx["GITHUB_REPOSITORY"] + "/"
    workflow_ref = ctx["GITHUB_WORKFLOW_REF"]
    suffix = "@" + ctx["GITHUB_REF"]
    if not workflow_ref.startswith(prefix) or not workflow_ref.endswith(suffix):
        raise ValueError("invalid caller workflow identity")
    workflow = workflow_ref[len(prefix):-len(suffix)]
    # JSON strings are valid TOML basic strings for these GitHub identifiers.
    policy = 'enforcement = "deny"\n[[publishers]]\nkind = "keyless"\n'
    for key, value in {
        "name": "sign-instructions",
        "issuer": "https://token.actions.githubusercontent.com",
        "repository": ctx["GITHUB_REPOSITORY"],
        "workflow": workflow,
        "ref": ctx["GITHUB_REF"],
    }.items():
        policy += f"{key} = {json.dumps(value)}\n"
    with tempfile.TemporaryDirectory() as directory:
        policy_path = Path(directory) / "policy.toml"
        policy_path.write_text(policy)
        subprocess.run([
            cli, "trust", "instructions", "verify", ".", "--policy", str(policy_path),
        ], check=True)
    output.mkdir()
    # Publish the received bytes, not files potentially rewritten by the verifier.
    for name, data in bundles.items():
        dest = output / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)


if __name__ == "__main__":
    phase = sys.argv[1]
    root = Path(os.environ["MVM_SIGN_STATE"])
    if phase == "prepare":
        prepare(os.environ["MVM_SIGN_MVMCTL"], root / "request")
    elif phase == "sign":
        sign(root / "request/request.json", root / "candidate")
    elif phase == "verify":
        verify(os.environ["MVM_SIGN_MVMCTL"], root / "request/request.json",
               root / "candidate", root / "verified")
    else:
        raise ValueError("phase must be prepare, sign, or verify")
