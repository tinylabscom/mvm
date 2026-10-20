#!/usr/bin/env python3
"""Validate historical source against the trusted workflow's immutable commit."""

import argparse
import re
import subprocess


def resolve(source, workflow):
    for commit in (source, workflow):
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("source and workflow commits must be full lowercase SHAs")
    actual = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{source}^{{commit}}"], text=True,
    ).strip()
    if actual != source:
        raise ValueError("source must name the exact commit, not a tag object")
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", source, workflow], check=True,
    )
    return source


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--workflow", required=True)
    args = parser.parse_args()
    print(resolve(args.source, args.workflow))
