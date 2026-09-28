"""The function-dispatch surface: ``await f(...)``, ``f.sync(...)``, ``f.local``.

Under ``MVM_NO_VM=1`` a call runs in this process through the workload's
wire format, so these tests assert what that round trip preserves, refuses
and reports. Without it the call goes to the host library, driven here by
the recorded stand-in, so the tests assert the exact request each call
sends and how each reply is turned into a result or an error.
"""

from __future__ import annotations

import asyncio
import base64
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


# ── without MVM_NO_VM: dispatched through the host library ───────────


@pytest.fixture
def on_host(hostlib, monkeypatch):
    """A host process with no MVM_NO_VM: calls go to the (recorded) library."""
    monkeypatch.delenv("MVM_NO_VM", raising=False)
    return hostlib


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _reply(exit_code: int = 0, stdout: bytes = b"", stderr: bytes = b"", **extra) -> dict:
    return {
        "exit_code": exit_code,
        "stdout_b64": _b64(stdout),
        "stderr_b64": _b64(stderr),
        "output_truncated": False,
        **extra,
    }


def test_a_call_is_dispatched_into_the_workload_and_decoded(on_host) -> None:
    ran = []
    remote = _build(lambda a, b: ran.append((a, b)))
    on_host.reply("entrypoint.call", _reply(stdout=b"5"))
    assert remote.sync(2, 3) == 5
    assert on_host.request("entrypoint.call") == {
        "workload": "adder",
        "payload_b64": _b64(b"[[2,3],{}]"),
    }
    assert ran == [], "the local body never runs for a host call"


def test_an_awaited_call_is_dispatched_the_same_way(on_host) -> None:
    on_host.reply("entrypoint.call", _reply(stdout=b'{"sum":7}'))
    assert asyncio.run(_build(_add)(3, b=4)) == {"sum": 7}
    assert on_host.request("entrypoint.call")["payload_b64"] == _b64(b'[[3],{"b":4}]')


def test_a_raised_exception_comes_back_as_remote_error(on_host) -> None:
    on_host.reply(
        "entrypoint.call",
        _reply(
            exit_code=1,
            stderr=b"MVM_ENVELOPE: {...}\n",
            error={"kind": "ValueError", "error_id": "0123456789abcdef", "message": "bad"},
        ),
    )
    with pytest.raises(mvm.RemoteError) as raised:
        _build(_add).sync(1, 2)
    assert (raised.value.kind, raised.value.error_id, raised.value.message) == (
        "ValueError",
        "0123456789abcdef",
        "bad",
    )


def test_a_failure_without_an_envelope_is_a_transport_error_with_the_stderr_tail(on_host) -> None:
    on_host.reply("entrypoint.call", _reply(exit_code=3, stderr=b"x" * 5000 + b"segfault"))
    with pytest.raises(mvm.MvmTransportError, match="status 3") as raised:
        _build(_add).sync(1, 2)
    assert "segfault" in str(raised.value)
    assert "x" * 2100 not in str(raised.value), "only the tail is quoted"


def test_an_agent_ended_call_says_why(on_host) -> None:
    on_host.reply(
        "entrypoint.call",
        _reply(exit_code=124, agent_error={"kind": "Timeout", "message": "exceeded 30s"}),
    )
    with pytest.raises(mvm.MvmTransportError, match="Timeout: exceeded 30s"):
        _build(_add).sync(1, 2)


def test_a_result_is_decoded_with_the_same_hardening(on_host) -> None:
    remote = _build(_add)
    on_host.reply("entrypoint.call", _reply(stdout=b"NaN"))
    with pytest.raises(mvm.MvmTransportError, match="non-finite"):
        remote.sync(1, 2)
    on_host.reply("entrypoint.call", _reply(stdout=b'{"a":1,"a":2}'))
    with pytest.raises(mvm.MvmTransportError, match="duplicate key"):
        remote.sync(1, 2)


def test_the_output_cap_applies_to_a_host_result(on_host, monkeypatch) -> None:
    remote = _build(_add)
    monkeypatch.setenv("MVM_MAX_OUTPUT_BYTES", "4")
    on_host.reply("entrypoint.call", _reply(stdout=b"123456"))
    with pytest.raises(mvm.MvmTransportError, match="output cap"):
        remote.sync(1, 2)
    monkeypatch.delenv("MVM_MAX_OUTPUT_BYTES")
    on_host.reply("entrypoint.call", _reply(stdout=b"1", output_truncated=True))
    with pytest.raises(mvm.MvmTransportError, match="output cap"):
        remote.sync(1, 2)


def test_a_reply_without_an_exit_status_is_refused(on_host) -> None:
    on_host.reply("entrypoint.call", {"stdout_b64": ""})
    with pytest.raises(mvm.MvmTransportError, match="no exit status"):
        _build(_add).sync(1, 2)


def test_a_library_refusal_reaches_the_caller_typed(on_host) -> None:
    on_host.fail("entrypoint.call", "INVALID_SPEC", "no built image named \"adder\"")
    with pytest.raises(mvm.HostLibraryError, match="no built image"):
        _build(_add).sync(1, 2)


def test_without_no_vm_the_pre_dispatch_checks_still_run_first(on_host, monkeypatch) -> None:
    monkeypatch.setenv("MVM_MAX_PAYLOAD_BYTES", "32")
    with pytest.raises(mvm.PayloadTooLarge):
        _build(_add).sync("x" * 1024)
    assert on_host.calls == [], "an oversized call never reaches the library"


def test_a_workload_ref_call_is_dispatched_to_its_workload(on_host, monkeypatch) -> None:
    math = mvm.workload_ref("math-svc")
    on_host.reply("entrypoint.call", _reply(stdout=b"3"))
    assert math.add.sync(1, 2) == 3
    on_host.reply("entrypoint.call", _reply(stdout=b"4"))
    assert asyncio.run(math.add(2, 2)) == 4
    assert [r["workload"] for r in on_host.requests("entrypoint.call")] == ["math-svc"] * 2

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
