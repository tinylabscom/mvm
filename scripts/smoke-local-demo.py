#!/usr/bin/env python3
"""Contributor smoke for a prepared cached image, in builder or permitted HVF host.

No image preparation or leak repair is performed. Python is not a demo dependency.
"""

import argparse
import json
import re
import subprocess
import sys
import time
import uuid


class SmokeError(Exception):
    """Smoke assertion or infrastructure failure."""


def invoke(runner, command, timeout):
    try:
        return runner(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SmokeError(f"{command[1:3]} failed: {exc}") from exc


def inventory(runner, binary):
    result = invoke(
        runner, [binary, "machine", "ps", "--all", "--show-expired", "--json"], 30
    )
    if result.returncode:
        raise SmokeError(f"inventory failed ({result.returncode}): {result.stderr}")
    try:
        records = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise SmokeError("inventory returned invalid JSON") from exc
    if not isinstance(records, list) or any(
        not isinstance(record, dict)
        or not isinstance(record.get("name"), str)
        or not record["name"]
        for record in records
    ):
        raise SmokeError("inventory must be an array of records with nonempty names")
    return {record["name"] for record in records}


def smoke(image, binary="mvmctl", runner=subprocess.run, output=print):
    # Only a pin-shape guard: OCI parsing and cache authority belong to mvmctl.
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image):
        raise SmokeError("--image requires a digest-pinned OCI reference")
    inspected = invoke(runner, [binary, "image", "inspect", image, "--digest-ref"], 30)
    if inspected.returncode:
        raise SmokeError(f"cached image inspection failed: {inspected.stderr}")
    if inspected.stdout.strip() != image:
        raise SmokeError("cached image digest reference drifted from --image")
    for expected in (0, 7):
        name = f"local-demo-smoke-{uuid.uuid4().hex}"
        marker = f"guest-{uuid.uuid4().hex}"
        if name in inventory(runner, binary):
            raise SmokeError(f"generated name already exists: {name}")
        script = f"printf '%s\\n' '{marker}'; /bin/uname -s"
        if expected:
            script += "; exit 7"
        command = [
            binary, "machine", "run", "--name", name, "--profile", "dev",
            "--cpus", "1", "--memory", "256M", "--timeout", "120",
            "--image", image, "--", "/bin/sh", "-c", script,
        ]
        started = time.monotonic()
        errors = []
        try:
            result = invoke(runner, command, 180)
            if result.returncode != expected:
                errors.append(
                    f"{name}: expected exit {expected}, got {result.returncode}: "
                    f"{result.stderr}"
                )
            lines = result.stdout.splitlines()
            if marker not in lines or "Linux" not in lines:
                errors.append(f"{name}: missing guest marker or Linux uname output")
        except SmokeError as exc:
            errors.append(str(exc))
        # Check teardown even when the CLI failed or timed out; never stop other VMs.
        try:
            if name in inventory(runner, binary):
                errors.append(f"own machine leaked (including stopped records): {name}")
        except SmokeError as exc:
            errors.append(f"{name}: teardown verification failed: {exc}")
        elapsed = time.monotonic() - started
        if errors:
            raise SmokeError("; ".join(errors))
        output(
            f"{name}: guest exit {expected}, output verified, identity absent; "
            f"whole run+teardown cold elapsed {elapsed:.3f}s (not startup benchmark)"
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="prepared cached OCI digest reference")
    parser.add_argument("--mvmctl", default="mvmctl", help="existing CLI executable")
    args = parser.parse_args(argv)
    try:
        smoke(args.image, args.mvmctl)
    except SmokeError as exc:
        print(f"local demo smoke FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
