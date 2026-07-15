"""Tests for ADR-0014 Phase 2 multi-function apps.

Repeated `@mvm.func(name="X", ...)` against the same workload
extends the existing app's `entrypoints` list. App-level config
must only appear on the FIRST decoration.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

import mvm

FAKE_MVM = (
    Path(__file__).parent / "fixtures" / "fake-mvm"
).resolve()


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch) -> None:
    mvm.reset()
    monkeypatch.setenv("MVM_MVM_BIN", str(FAKE_MVM))
    yield
    mvm.reset()


def test_repeated_decoration_extends_entrypoints() -> None:
    @mvm.func(name="math-svc", module="math")
    async def add(a: int, b: int) -> int:
        return a + b

    @mvm.func(name="math-svc", module="math")
    async def mul(a: int, b: int) -> int:
        return a * b

    payload = json.loads(mvm.emit_json())
    eps = payload["apps"][0]["entrypoints"]
    assert len(eps) == 2
    assert eps[0]["function"] == "add"
    assert eps[0]["primary"] is True
    assert eps[1]["function"] == "mul"
    assert eps[1]["primary"] is False
    # Single workload + single app — multi-function shape.
    assert len(payload["apps"]) == 1
    assert payload["id"] == "math-svc"


def test_explicit_primary_override() -> None:
    @mvm.func(name="math-svc", module="math", primary=False)
    async def add(a: int, b: int) -> int:
        return a + b

    @mvm.func(name="math-svc", module="math", primary=True)
    async def mul(a: int, b: int) -> int:
        return a * b

    payload = json.loads(mvm.emit_json())
    eps = payload["apps"][0]["entrypoints"]
    assert eps[0]["primary"] is False
    assert eps[1]["primary"] is True


def test_subsequent_decoration_rejects_app_level_kwargs() -> None:
    @mvm.func(name="math-svc", module="math")
    async def add(a: int, b: int) -> int:
        return a + b

    with pytest.raises(ValueError, match="image"):

        @mvm.func(
            name="math-svc",
            module="math",
            image=mvm.nix_packages(["python312", "ffmpeg"]),
        )
        async def mul(a: int, b: int) -> int:
            return a * b


def test_first_decoration_carries_app_level_config() -> None:
    @mvm.func(
        name="math-svc",
        module="math",
        image=mvm.nix_packages(["python312", "ffmpeg"]),
    )
    async def add(a: int, b: int) -> int:
        return a + b

    @mvm.func(name="math-svc", module="math")
    async def mul(a: int, b: int) -> int:
        return a * b

    payload = json.loads(mvm.emit_json())
    assert payload["apps"][0]["image"]["packages"] == ["python312", "ffmpeg"]
    assert len(payload["apps"][0]["entrypoints"]) == 2


@pytest.mark.skip(
    reason="cross-process test needs `mvmctl validate` (not yet wired in "
    "mvm; the validator itself is exercised by the 39 Rust tests in "
    "crates/mvm-ir/tests/validate.rs)"
)
def test_validator_rejects_no_primary_in_long_form() -> None:
    """The long form `mv.app(entrypoints=[...])` doesn't auto-mark
    primary. A multi-function app with zero primaries must be
    rejected by the validator (E_NO_PRIMARY_ENTRYPOINT)."""
    mvm.workload(id="math-svc")

    @mvm.app(
        name="math-svc",
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        dependencies=mvm.no_deps(),
        entrypoints=[
            mvm.entrypoint_function(module="math", function="add"),
            mvm.entrypoint_function(module="math", function="mul"),
        ],
    )
    def _():
        pass

    # Round-trip through `mvm validate` to exercise the host
    # validator. Use a subprocess for true integration.
    import subprocess
    import sys

    ir = mvm.emit_json()
    cargo_root = Path(__file__).parent.parent.parent.parent.parent
    bin_path = cargo_root / "target" / "debug" / "mvm"
    proc = subprocess.run(
        [str(bin_path), "validate", "/dev/stdin"],
        input=ir,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, f"expected validate to fail; got {proc.stdout}"
    out = json.loads(proc.stdout)
    codes = [e["code"] for e in out["errors"]]
    assert "E_NO_PRIMARY_ENTRYPOINT" in codes


@pytest.mark.skip(
    reason="cross-process test needs `mvmctl validate` (not yet wired in "
    "mvm; the validator itself is exercised by the 39 Rust tests in "
    "crates/mvm-ir/tests/validate.rs)"
)
def test_validator_rejects_multiple_primaries() -> None:
    mvm.workload(id="math-svc")

    @mvm.app(
        name="math-svc",
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        dependencies=mvm.no_deps(),
        entrypoints=[
            mvm.entrypoint_function(module="math", function="add", primary=True),
            mvm.entrypoint_function(module="math", function="mul", primary=True),
        ],
    )
    def _():
        pass

    import subprocess

    ir = mvm.emit_json()
    cargo_root = Path(__file__).parent.parent.parent.parent.parent
    bin_path = cargo_root / "target" / "debug" / "mvm"
    proc = subprocess.run(
        [str(bin_path), "validate", "/dev/stdin"],
        input=ir,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    codes = [e["code"] for e in out["errors"]]
    assert "E_MULTIPLE_PRIMARY_ENTRYPOINTS" in codes


@pytest.mark.skip(
    reason="cross-process test needs `mvmctl validate` (not yet wired in "
    "mvm; the validator itself is exercised by the 39 Rust tests in "
    "crates/mvm-ir/tests/validate.rs)"
)
def test_validator_rejects_duplicate_module_function_pair() -> None:
    mvm.workload(id="math-svc")

    @mvm.app(
        name="math-svc",
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        dependencies=mvm.no_deps(),
        entrypoints=[
            mvm.entrypoint_function(module="math", function="add", primary=True),
            mvm.entrypoint_function(module="math", function="add"),  # duplicate
        ],
    )
    def _():
        pass

    import subprocess

    ir = mvm.emit_json()
    cargo_root = Path(__file__).parent.parent.parent.parent.parent
    bin_path = cargo_root / "target" / "debug" / "mvm"
    proc = subprocess.run(
        [str(bin_path), "validate", "/dev/stdin"],
        input=ir,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    codes = [e["code"] for e in out["errors"]]
    assert "E_DUPLICATE_ENTRYPOINT_FUNCTION" in codes


def test_app_rejects_both_entrypoint_and_entrypoints() -> None:
    mvm.workload(id="x")
    with pytest.raises(ValueError, match="not both"):

        @mvm.app(
            name="x",
            source=mvm.local_path("."),
            image=mvm.nix_packages(["python312"]),
            resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
            entrypoint=mvm.entrypoint(command=["true"]),
            entrypoints=[mvm.entrypoint(command=["true"])],
        )
        def _():
            pass


def test_app_rejects_neither_entrypoint_nor_entrypoints() -> None:
    mvm.workload(id="x")
    with pytest.raises(ValueError, match="required"):

        @mvm.app(
            name="x",
            source=mvm.local_path("."),
            image=mvm.nix_packages(["python312"]),
            resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        )
        def _():
            pass


def test_dispatch_to_specific_function_via_remote_function(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Each `RemoteFunction` returned from a multi-function decoration
    dispatches against its own function name once the wrapper supports
    `--fn` (W11). Today the SDK passes `--fn=<wrapped-fn-name>` via
    the WorkloadRef path — direct `RemoteFunction` calls don't pass
    `--fn` (single-function wrappers use the static wrapper.json
    binding). Test that each handle still dispatches correctly to
    the same workload."""
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")

    @mvm.func(name="math-svc", module="math")
    async def add(a: int, b: int) -> int:
        return a + b

    @mvm.func(name="math-svc", module="math")
    async def mul(a: int, b: int) -> int:
        return a * b

    asyncio.run(add(2, 3))
    asyncio.run(mul(4, 5))

    text = record.read_text()
    invoke_blocks = [b for b in text.split("\n--\n") if "subcommand=invoke" in b]
    assert len(invoke_blocks) == 2
    for block in invoke_blocks:
        assert "workload=math-svc" in block
