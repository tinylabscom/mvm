"""Live SDK prompt checkpoint and restore witness.

Run only in an isolated, prepared MVM_HOME with MVMCTL and MVM_HOSTLIB_PATH
pointing at binaries built from the same revision. The builder must have KVM
and the prerequisites needed to run examples/agent-prompt.
"""

from __future__ import annotations

import base64
import os
import secrets
import subprocess
import sys

import mvm
from mvm import checkpoint


def main() -> int:
    if not os.environ.get("MVM_HOME") or not os.environ.get("MVM_HOSTLIB_PATH"):
        raise RuntimeError("MVM_HOME and MVM_HOSTLIB_PATH must be explicitly set")
    ctl = os.environ["MVMCTL"]
    suffix = secrets.token_hex(5)
    parent = f"sdk-witness-{suffix}"
    child = f"sdk-child-{suffix}"
    names = (parent, child)

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run([ctl, *args], text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError(
                f"command {args!r} failed ({result.returncode}):\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
        return result

    try:
        run("machine", "run", "--flake", "examples/agent-prompt", "--name", parent, "-d")
        answer = mvm.Machine(parent).prompt("first", checkpoint=True)
        assert answer["delivered"] is True, answer
        assert answer["exit_code"] == 0, answer
        assert base64.b64decode(answer["stdout_b64"]).decode().find("turn 1: first") >= 0, answer
        assert answer["checkpoint_failed"] is False, answer
        checkpoint_id = answer["checkpoint_id"]
        assert isinstance(checkpoint_id, str) and checkpoint_id, answer
        checkpoint.verify_lineage(checkpoint_id)
        run("machine", "restore", checkpoint_id, "--as", child)
        restored = mvm.Machine(child).prompt("second")
        assert restored["delivered"] is True, restored
        assert restored["exit_code"] == 0, restored
        assert base64.b64decode(restored["stdout_b64"]).decode().find("turn 2: second") >= 0, restored
        print("PASS: SDK prompt checkpoint lineage verified and exact checkpoint fork restored")
        return 0
    finally:
        failures = []
        for name in reversed(names):
            for action in ("stop", "rm"):
                result = subprocess.run(
                    [ctl, "machine", action, name, "--yes"],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if result.returncode and f'machine "{name}" does not exist' not in result.stderr:
                    failures.append(f"{action} {name}: {result.stderr.strip()}")
        if failures:
            print("cleanup failures: " + "; ".join(failures), file=sys.stderr)
            raise RuntimeError("could not verify witness machine cleanup")


if __name__ == "__main__":
    raise SystemExit(main())
