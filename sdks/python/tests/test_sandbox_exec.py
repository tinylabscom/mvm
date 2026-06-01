"""Plan 120 §Task 5 — one-shot exec on a dev-tier live sandbox.

Live-mode SDK is dev-tier (SandboxDevOnly guards prod). exec() is a
one-shot convenience over commands.start: run argv, collect stdout +
exit. Gated on MVM_E2E_SMOKE=1 because it boots a real VM.
"""

from __future__ import annotations

import os

import pytest

from mvm import Sandbox


@pytest.mark.skipif(
    os.environ.get("MVM_E2E_SMOKE") != "1",
    reason="needs libkrun + builder VM; set MVM_E2E_SMOKE=1 to run",
)
def test_sandbox_exec_returns_stdout() -> None:
    sb = Sandbox.create(image="python:slim")
    try:
        r = sb.exec("python", "-c", "print(2 + 2)")
        assert r.exit_code == 0
        assert r.stdout.strip() == "4"
    finally:
        sb.kill()
