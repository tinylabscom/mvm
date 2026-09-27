"""The function-dispatch surface: ``await f(...)``, ``f.sync(...)``, ``f.local``.

Under ``MVM_NO_VM=1`` a call runs in this process through the workload's
wire format, so these tests assert what that round trip preserves, refuses
and reports. Without it the call must refuse with a transport error — and
must do so without touching the host library or starting anything.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import warnings
from pathlib import Path

import pytest

import mvm


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch):
    mvm.reset()
    monkeypatch.setenv("MVM_NO_VM", "1")
    for name in ("MVM_STRICT_SECRETS", "MVM_MAX_PAYLOAD_BYTES", "MVM_MAX_OUTPUT_BYTES"):
        monkeypatch.delenv(name, raising=False)
    yield
    mvm.reset()


def _build(fn, format: str = "json", name: str = "adder") -> mvm.RemoteFunction:
    mvm.workload(id=name)
    decorated = mvm.app(
        name=name,
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        entrypoint=mvm.entrypoint_function(
            language="python", module="adder", function="add", format=format
        ),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
    )(fn)
    assert isinstance(decorated, mvm.RemoteFunction)
    return decorated


def _add(a, b=0):
    return a + b


def test_app_with_function_entrypoint_returns_remote_function() -> None:
    add = _build(_add)
    assert add.workload_id == "adder"
    assert add.format == "json"


def test_app_with_command_entrypoint_returns_callable_unchanged() -> None:
    mvm.workload(id="hello")

    @mvm.app(
        name="hello",
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        entrypoint=mvm.entrypoint(command=["python", "-m", "hello"]),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
    )
    def hello() -> str:
        return "local"

    assert hello() == "local"
    assert not isinstance(hello, mvm.RemoteFunction)


def test_local_call_passes_through() -> None:
    assert _build(_add).local(4, 5) == 9


# ── MVM_NO_VM=1: in-process dispatch ─────────────────────────────────


def test_sync_dispatch_runs_the_function_locally() -> None:
    add = _build(_add)
    assert add.sync(2, 3) == 5
    assert add.sync(1, b=2) == 3


def test_async_dispatch_runs_the_function_locally() -> None:
    assert asyncio.run(_build(_add)(2, 3)) == 5


def test_an_async_body_is_awaited_on_both_paths() -> None:
    async def add(a, b):
        await asyncio.sleep(0)
        return a + b

    remote = _build(add)
    assert asyncio.run(remote(2, 3)) == 5
    assert remote.sync(2, 3) == 5


def test_sync_dispatch_of_an_async_body_works_inside_a_running_loop() -> None:
    async def add(a, b):
        await asyncio.sleep(0)
        return a + b

    remote = _build(add)

    async def caller() -> int:
        return remote.sync(4, 5)

    assert asyncio.run(caller()) == 9


def test_arguments_cross_the_wire_format_not_by_reference() -> None:
    seen = {}

    def capture(values, *, options):
        seen["values"], seen["options"] = values, options
        return {"n": len(values)}

    remote = _build(capture)
    original = (1, 2)
    assert remote.sync(original, options={"k": (3,)}) == {"n": 2}
    # A tuple becomes a list and a nested tuple too, exactly as a guest
    # would receive them; nothing is shared with the caller's objects.
    assert seen == {"values": [1, 2], "options": {"k": [3]}}


def test_msgpack_round_trips_bytes() -> None:
    pytest.importorskip("msgpack")
    remote = _build(lambda data: data + b"!", format="msgpack")
    assert remote.sync(b"hi") == b"hi!"


def test_a_value_the_format_cannot_carry_is_refused() -> None:
    remote = _build(lambda: object())
    with pytest.raises(mvm.MvmTransportError, match="cannot be encoded as json"):
        remote.sync()


def test_a_non_finite_result_is_refused_like_a_guest_result() -> None:
    remote = _build(lambda: {"x": float("nan")})
    with pytest.raises(mvm.MvmTransportError, match="non-finite"):
        remote.sync()


def test_a_non_finite_argument_is_refused_like_the_guest_runner_does() -> None:
    remote = _build(_add)
    with pytest.raises(mvm.MvmTransportError, match="non-finite JSON constant in arguments"):
        remote.sync(float("inf"))


def test_an_over_deep_result_is_refused() -> None:
    def deep():
        value: list = [1]
        for _ in range(100):
            value = [value]
        return value

    with pytest.raises(mvm.MvmTransportError, match="nesting depth"):
        _build(deep).sync()


def test_the_output_cap_applies_to_the_encoded_result(monkeypatch) -> None:
    monkeypatch.setenv("MVM_MAX_OUTPUT_BYTES", "64")
    with pytest.raises(mvm.MvmTransportError, match="output cap"):
        _build(lambda: "x" * 1024).sync()


def test_the_functions_own_exception_propagates_unchanged() -> None:
    class Boom(ValueError):
        pass

    def fail(a):
        raise Boom(f"negative input {a}")

    remote = _build(fail)
    with pytest.raises(Boom, match="negative input -1"):
        remote.sync(-1)
    with pytest.raises(Boom):
        asyncio.run(remote(-1))


def test_a_module_under_test_dispatches_by_its_own_definition(tmp_path: Path) -> None:
    """A function defined in a real module runs through the same path as one
    defined in a test body."""
    (tmp_path / "adder_mod.py").write_text("def add(a, b):\n    return a + b\n")
    sys.path.insert(0, str(tmp_path))
    try:
        module = importlib.import_module("adder_mod")
        remote = mvm.func(name="adder")(module.add)
        assert remote.sync(2, 3) == 5
        assert asyncio.run(remote(2, 3)) == 5
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("adder_mod", None)


# ── checks that run before any dispatch ──────────────────────────────


def test_payload_cap_raises_on_both_paths(monkeypatch) -> None:
    monkeypatch.setenv("MVM_MAX_PAYLOAD_BYTES", "32")
    calls = []
    remote = _build(lambda s: calls.append(s))
    with pytest.raises(mvm.PayloadTooLarge, match="MVM_MAX_PAYLOAD_BYTES"):
        remote.sync("x" * 1024)
    with pytest.raises(mvm.PayloadTooLarge):
        asyncio.run(remote("y" * 1024))
    assert calls == []


def test_secret_kwarg_warns_by_default() -> None:
    remote = _build(lambda **kw: len(kw))
    with pytest.warns(mvm.SecretInArgWarning, match="api_key"):
        assert remote.sync(api_key="sk-deadbeef") == 1


def test_secret_kwarg_raises_in_strict_mode(monkeypatch) -> None:
    monkeypatch.setenv("MVM_STRICT_SECRETS", "1")
    calls = []
    remote = _build(lambda **kw: calls.append(kw))
    with pytest.raises(mvm.SecretInArgError, match="api_key"):
        remote.sync(api_key="sk-deadbeef")
    assert calls == []


def test_innocent_kwarg_does_not_warn() -> None:
    remote = _build(lambda **kw: len(kw))
    with warnings.catch_warnings():
        warnings.simplefilter("error", mvm.SecretInArgWarning)
        assert remote.sync(name="hello", count=3) == 2


def test_a_malformed_workload_id_is_refused() -> None:
    remote = _build(_add)
    # Bypass the IR validator the way hand-built IR could.
    remote._workload_id = "-flag-injection"  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="workload_id"):
        remote.sync(2, 3)


def test_format_must_be_json_or_msgpack() -> None:
    with pytest.raises(ValueError, match="format"):
        mvm.RemoteFunction(_add, workload_id="x", format="yaml")


def test_msgpack_path_raises_clearly_when_dependency_missing(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "msgpack", None)
    with pytest.raises(mvm.MsgpackUnavailable):
        _build(_add, format="msgpack").sync(1, 2)


# ── without MVM_NO_VM: refused, and nothing is reached for ───────────


@pytest.fixture
def no_library(monkeypatch):
    """Fail the test if dispatch reaches for the host library at all."""
    from mvm import _hostlib

    def refuse(method, _request):
        raise AssertionError(f"dispatch reached the host library: {method}")

    monkeypatch.setattr(_hostlib, "_invoke", refuse)
    monkeypatch.delenv("MVM_NO_VM", raising=False)


def test_without_no_vm_a_call_is_refused_with_the_way_out(no_library) -> None:
    calls = []
    remote = _build(lambda a, b: calls.append((a, b)))
    with pytest.raises(mvm.MvmTransportError, match="MVM_NO_VM=1") as raised:
        remote.sync(2, 3)
    assert "not available through the in-process host library" in str(raised.value)
    with pytest.raises(mvm.MvmTransportError, match="MVM_NO_VM=1"):
        asyncio.run(remote(2, 3))
    assert calls == []


def test_without_no_vm_the_pre_dispatch_checks_still_run_first(no_library, monkeypatch) -> None:
    monkeypatch.setenv("MVM_MAX_PAYLOAD_BYTES", "32")
    with pytest.raises(mvm.PayloadTooLarge):
        _build(_add).sync("x" * 1024)


def test_a_workload_ref_call_is_always_refused(no_library, monkeypatch) -> None:
    math = mvm.workload_ref("math-svc")
    with pytest.raises(mvm.MvmTransportError, match=r"WorkloadRef\('math-svc'\)\.add"):
        math.add.sync(1, 2)
    with pytest.raises(mvm.MvmTransportError):
        asyncio.run(math.add(1, 2))

    # Under MVM_NO_VM=1 there is still no local body to run: the callee's
    # function lives in the callee's microVM.
    monkeypatch.setenv("MVM_NO_VM", "1")
    with pytest.raises(mvm.NoVmIntrospectionError, match="no local function"):
        math.add.sync(1, 2)
    assert issubclass(mvm.NoVmIntrospectionError, mvm.MvmTransportError)


def test_workload_ref_validates_and_describes_itself() -> None:
    ref = mvm.workload_ref("math-svc", format="msgpack")
    assert ref.id == "math-svc"
    assert repr(ref) == "WorkloadRef('math-svc', format='msgpack')"
    assert "math-svc.add" in repr(ref.add)
    with pytest.raises(AttributeError):
        ref._private
    with pytest.raises(ValueError):
        mvm.workload_ref("Bad_Id")
    with pytest.raises(ValueError, match="format"):
        mvm.workload_ref("ok", format="yaml")
