"""Tests for ADR-0014 Phase 2 multi-function apps.

Repeated `@mvm.func(name="X", ...)` against the same workload
extends the existing app's `entrypoints` list. App-level config
must only appear on the FIRST decoration.
"""

from __future__ import annotations

import asyncio
import json

import pytest

import mvm


@pytest.fixture(autouse=True)
def _clean_state() -> None:
    mvm.reset()
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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each `RemoteFunction` returned from a multi-function decoration
    dispatches to its own body while both stay bound to the one workload."""
    monkeypatch.setenv("MVM_NO_VM", "1")

    @mvm.func(name="math-svc", module="math")
    async def add(a: int, b: int) -> int:
        return a + b

    @mvm.func(name="math-svc", module="math")
    async def mul(a: int, b: int) -> int:
        return a * b

    assert asyncio.run(add(2, 3)) == 5
    assert asyncio.run(mul(4, 5)) == 20
    assert add.workload_id == mul.workload_id == "math-svc"
