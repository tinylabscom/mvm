"""ADR-0010 §2 Layer-3 emit-context guard.

When `mvm emit` invokes the SDK as a subprocess, it sets
`MVM_EMITTING=1`. The runtime SDK refuses Layer-3 calls
(``await f(...)``, ``f.sync(...)``, ``mv.session(...)``) under this
flag, raising :class:`mvm.EmittingContextError`. This catches
build-time recursion (an entry module trying to call into a VM that
doesn't exist yet because we're still constructing the artifact for
it).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import mvm

FAKE_MVM = (
    Path(__file__).parent / "fixtures" / "fake-mvm"
).resolve()


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch) -> None:
    mvm.reset()
    # Point at the fake-mvm shim so that, in the absence of the guard,
    # the call would otherwise succeed — proving the guard, not a
    # transport failure, is what raises.
    monkeypatch.setenv("MVM_MVM_BIN", str(FAKE_MVM))
    yield
    mvm.reset()


def _build_adder() -> mvm.RemoteFunction:
    mvm.workload(id="adder")

    @mvm.app(
        name="adder",
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        entrypoint=mvm.entrypoint_function(
            language="python", module="adder", function="add"
        ),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        dependencies=mvm.no_deps(),
    )
    def add(a: int, b: int) -> int:
        return a + b

    assert isinstance(add, mvm.RemoteFunction)
    return add


def test_async_call_raises_under_emitting_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    add = _build_adder()
    monkeypatch.setenv("MVM_EMITTING", "1")
    with pytest.raises(mvm.EmittingContextError) as exc:
        asyncio.run(add(2, 3))
    assert "RemoteFunction" in str(exc.value)
    assert "ADR-0010" in str(exc.value)


def test_sync_call_raises_under_emitting_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    add = _build_adder()
    monkeypatch.setenv("MVM_EMITTING", "1")
    with pytest.raises(mvm.EmittingContextError) as exc:
        add.sync(2, 3)
    assert "RemoteFunction" in str(exc.value)
    assert "ADR-0010" in str(exc.value)


def test_session_raises_under_emitting_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MVM_EMITTING", "1")
    with pytest.raises(mvm.EmittingContextError):
        with mvm.session("adder"):
            pytest.fail("session body should not execute under MVM_EMITTING=1")


def test_local_call_unaffected_by_emitting_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    add = _build_adder()
    monkeypatch.setenv("MVM_EMITTING", "1")
    # f.local(...) is the in-process body; emit subprocess loads user
    # modules and reads their registrations, so this must stay reachable.
    assert add.local(4, 5) == 9


def test_async_call_works_when_flag_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    add = _build_adder()
    monkeypatch.delenv("MVM_EMITTING", raising=False)
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")
    assert asyncio.run(add(2, 3)) == 5


def test_sync_call_works_when_flag_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    add = _build_adder()
    monkeypatch.delenv("MVM_EMITTING", raising=False)
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")
    assert add.sync(2, 3) == 5


def test_emitting_context_error_is_runtime_error() -> None:
    # Inheritance contract for callers using broad `except RuntimeError:`.
    assert issubclass(mvm.EmittingContextError, RuntimeError)
