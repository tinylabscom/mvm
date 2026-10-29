#!/usr/bin/env python3
"""Publish immutable, commit-addressed helper pairs. Never touches legacy assets."""

import argparse
import json
import pathlib
import re
import subprocess


TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
)


def api(repo, endpoint, payload=None):
    command = ["gh", "api", "--include", f"repos/{repo}/{endpoint}"]
    if payload is not None:
        command += ["--method", "POST", "--input", "-"]
    result = subprocess.run(
        command, input=json.dumps(payload) if payload is not None else None,
        text=True, capture_output=True, check=False,
    )
    # gh emits response headers even for HTTP failures. Transport/auth CLI
    # failures without a response must never be interpreted as absence.
    match = re.match(r"HTTP/\S+ (\d+)[^\n]*\n", result.stdout)
    if not match:
        raise RuntimeError("GitHub API returned no HTTP response")
    status = int(match[1])
    if status == 404:
        return None
    if result.returncode or not 200 <= status < 300:
        raise RuntimeError(f"GitHub API failed: HTTP {status}")
    return json.loads(re.split(r"\r?\n\r?\n", result.stdout, maxsplit=1)[1])


def tag_commit(repo, tag):
    ref = api(repo, f"git/ref/tags/{tag}")
    if ref is None:
        return None
    obj = ref["object"]
    for _ in range(16):
        if obj["type"] == "commit":
            return obj["sha"]
        if obj["type"] != "tag":
            raise RuntimeError("helper tag does not resolve to a commit")
        obj = api(repo, f"git/tags/{obj['sha']}")["object"]
    raise RuntimeError("helper tag nesting exceeds limit")


def publish(repo, commit, directory):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source commit must be a full lowercase SHA")
    tag = f"source-builds-{commit}"
    names = [
        f"mvm-host-helpers-{commit}-{target}.tar.gz{suffix}"
        for target in TARGETS for suffix in ("", ".bundle")
    ]
    if any(not (directory / name).is_file() for name in names):
        raise ValueError("publication requires all three archive/signature pairs")
    resolved = tag_commit(repo, tag)
    if resolved is not None and resolved != commit:
        raise RuntimeError("existing helper tag points to a different commit")
    release = api(repo, f"releases/tags/{tag}")
    if release is None:
        # A simultaneous creator may win; re-read and validate, never clobber.
        try:
            api(repo, "releases", {
                "tag_name": tag, "target_commitish": commit,
                "name": f"Source helpers {commit}", "prerelease": True,
                "make_latest": "false",
                "body": "Signed host helpers for this exact source commit.",
            })
        except RuntimeError:
            if api(repo, f"releases/tags/{tag}") is None:
                raise
        release = api(repo, f"releases/tags/{tag}")
    if tag_commit(repo, tag) != commit:
        raise RuntimeError("published helper tag does not match source commit")
    if not release["prerelease"] or release["draft"]:
        raise RuntimeError("existing helper release must be a published prerelease")
    assets = {asset["name"] for asset in release["assets"]}
    if assets - set(names):
        raise RuntimeError("unexpected assets in helper release")
    for archive, bundle in zip(names[::2], names[1::2]):
        present = (archive in assets, bundle in assets)
        if any(present) and not all(present):
            raise RuntimeError(
                f"partial helper pair in {tag}: {archive} / {bundle}; "
                "operator repair requires original matching bytes; "
                "do not blindly regenerate, clobber or delete assets"
            )
    for archive, bundle in zip(names[::2], names[1::2]):
        if archive in assets:
            continue
        # No --clobber: a concurrent upload cannot overwrite published bytes.
        subprocess.run(
            ["gh", "release", "upload", tag, str(directory / archive),
             str(directory / bundle), "--repo", repo], check=True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--directory", type=pathlib.Path, default=pathlib.Path("dist"))
    args = parser.parse_args()
    publish(args.repo, args.commit, args.directory)
