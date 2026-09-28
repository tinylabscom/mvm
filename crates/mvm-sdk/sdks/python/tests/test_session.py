"""`mvm.session(...)`: a local scope under ``MVM_NO_VM=1``, a microVM on the
host otherwise."""

from __future__ import annotations

import asyncio
import base64
import re
import threading

import pytest

import mvm
from mvm import _hostlib


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch):
    mvm.reset()
    monkeypatch.setenv("MVM_NO_VM", "1")
    monkeypatch.delenv("MVM_EMITTING", raising=False)

    def refuse(method, _request):
        raise AssertionError(f"a session reached the host library: {method}")

    # A local scope has nothing to ask the library; the host-session tests
    # below replace this with the recorder.
    monkeypatch.setattr(_hostlib, "_invoke", refuse)
    yield
    mvm.reset()


def _build_adder() -> mvm.RemoteFunction:
    return mvm.func(name="adder")(lambda a, b: a + b)


def test_a_session_is_a_local_scope_with_a_local_id() -> None:
    assert mvm.current_session_id() is None
    with mvm.session("adder") as sess:
        assert re.fullmatch(r"local-[0-9a-f]{16}", sess.id)
        assert str(sess) == sess.id
        assert sess.workload_id == "adder"
        assert mvm.current_session_id() == sess.id
    assert mvm.current_session_id() is None


def test_each_session_gets_its_own_id() -> None:
    assert mvm.session("adder").id != mvm.session("adder").id


def test_async_with_binds_the_id_and_calls_dispatch_inside() -> None:
    add = _build_adder()

    async def body() -> tuple[str | None, int]:
        async with mvm.session("adder") as sess:
            assert mvm.current_session_id() == sess.id
            return mvm.current_session_id(), await add(2, 3)

    sid, total = asyncio.run(body())
    assert sid is not None and total == 5
    assert mvm.current_session_id() is None


def test_sync_calls_dispatch_inside_a_session() -> None:
    add = _build_adder()
    with mvm.session("adder"):
        assert add.sync(4, 5) == 9


def test_a_body_exception_propagates_and_ends_the_scope() -> None:
    with pytest.raises(RuntimeError, match="boom"):
        with mvm.session("adder") as sess:
            raise RuntimeError("boom")
    assert mvm.current_session_id() is None
    assert asyncio.run(sess.info())["active"] is False


def test_the_session_id_does_not_leak_into_other_threads() -> None:
    seen: list[str | None] = []
    with mvm.session("adder"):
        thread = threading.Thread(target=lambda: seen.append(mvm.current_session_id()))
        thread.start()
        thread.join()
    assert seen == [None]


def test_invoke_dispatches_within_the_session_and_guards_the_workload() -> None:
    add = _build_adder()
    sess = mvm.session("adder")
    assert asyncio.run(sess.invoke(add, 2, 3)) == 5

    mvm.reset()
    other = mvm.func(name="other")(lambda: None)
    with pytest.raises(ValueError, match="cannot invoke RemoteFunction"):
        asyncio.run(sess.invoke(other))


def test_lifecycle_methods_act_locally() -> None:
    sess = mvm.session("adder")

    asyncio.run(sess.set_timeout(30))
    info = asyncio.run(sess.info())
    assert info == {
        "id": sess.id,
        "workload_id": "adder",
        "active": True,
        "idle_timeout_secs": 30.0,
        "local": True,
    }

    asyncio.run(sess.kill())
    assert asyncio.run(sess.info())["active"] is False

    with pytest.raises(ValueError, match="non-negative"):
        asyncio.run(sess.set_timeout(-1))


@pytest.mark.parametrize("workload_id", ["", "Bad_Id", "-flag"])
def test_a_bad_workload_id_is_refused(workload_id) -> None:
    with pytest.raises(ValueError):
        mvm.session(workload_id)


def test_a_session_handle_refuses_a_malformed_id() -> None:
    with pytest.raises(ValueError, match="session_id"):
        mvm.Session("adder", "Not Valid")


# ── without MVM_NO_VM: a microVM on the host, through the library ────

SID = "abcdefghijklmnopqrstuvwx"


def _call_reply(stdout: bytes) -> dict:
    return {
        "exit_code": 0,
        "stdout_b64": base64.b64encode(stdout).decode(),
        "stderr_b64": "",
        "output_truncated": False,
    }


@pytest.fixture
def on_host(hostlib, monkeypatch):
    monkeypatch.delenv("MVM_NO_VM")
    hostlib.reply("session.start", {"session_id": SID, "vm_name": "session-vm"})
    return hostlib


def test_a_host_session_boots_on_entry_calls_into_it_and_stops_on_exit(on_host) -> None:
    add = _build_adder()
    on_host.reply("session.call", _call_reply(b"5"))
    on_host.reply("session.stop", {})
    sess = mvm.session("adder")
    assert sess.id is None, "the host mints the id when the VM boots"
    assert on_host.calls == [], "nothing boots until the session is entered"
    with sess:
        assert sess.id == SID
        assert mvm.current_session_id() == SID
        assert add.sync(2, 3) == 5
    assert mvm.current_session_id() is None
    assert on_host.methods == ["session.start", "session.call", "session.stop"]
    assert on_host.request("session.start") == {"workload": "adder"}
    assert on_host.request("session.call") == {
        "session_id": SID,
        "payload_b64": base64.b64encode(b"[[2,3],{}]").decode(),
    }
    assert on_host.request("session.stop") == {"session_id": SID}


def test_an_async_host_session_dispatches_awaited_calls_into_it(on_host) -> None:
    add = _build_adder()
    on_host.reply("session.call", _call_reply(b"9"))
    on_host.reply("session.stop", {})

    async def body() -> int:
        async with mvm.session("adder", idle_timeout_secs=60) as sess:
            assert mvm.current_session_id() == sess.id == SID
            return await add(4, 5)

    assert asyncio.run(body()) == 9
    assert on_host.request("session.start") == {"workload": "adder", "idle_timeout_secs": 60}
    assert on_host.methods[-1] == "session.stop"


def test_a_call_to_another_workload_inside_a_session_runs_on_its_own(on_host) -> None:
    mvm.reset()
    other = mvm.func(name="other")(lambda: None)
    on_host.reply("entrypoint.call", _call_reply(b"null"))
    on_host.reply("session.stop", {})
    with mvm.session("adder"):
        assert other.sync() is None
    assert on_host.request("entrypoint.call")["workload"] == "other"
    assert "session.call" not in on_host.methods


def test_a_body_exception_still_stops_the_host_session(on_host) -> None:
    on_host.reply("session.stop", {})
    with pytest.raises(RuntimeError, match="boom"):
        with mvm.session("adder"):
            raise RuntimeError("boom")
    assert on_host.methods == ["session.start", "session.stop"]


def test_a_stop_failure_never_masks_the_body_exception(on_host) -> None:
    on_host.fail("session.stop", "BACKEND_ERROR", "teardown failed")
    with pytest.raises(RuntimeError, match="boom"):
        with mvm.session("adder"):
            raise RuntimeError("boom")
    on_host.fail("session.stop", "BACKEND_ERROR", "teardown failed")
    on_host.reply("session.start", {"session_id": SID, "vm_name": "session-vm"})
    with pytest.raises(mvm.HostLibraryError, match="teardown failed"):
        with mvm.session("adder"):
            pass


def test_a_start_without_a_usable_id_is_refused_before_the_body(on_host) -> None:
    on_host._queued["session.start"].clear()
    on_host.reply("session.start", {"session_id": "NOT-BASE32", "vm_name": "x"})
    with pytest.raises(mvm.MvmTransportError, match="no usable session id"):
        with mvm.session("adder"):
            pytest.fail("the session body must not run")
    assert mvm.current_session_id() is None


def test_host_session_lifecycle_methods_reach_the_host(on_host) -> None:
    on_host.reply(
        "session.info",
        {"session_id": SID, "state": "running", "idle_timeout_secs": 300, "invoke_count": 0},
    )
    on_host.reply("session.stop", {})
    sess = mvm.session("adder")
    with pytest.raises(mvm.MvmTransportError, match="enter it"):
        asyncio.run(sess.invoke(_build_adder(), 1, 2))
    with sess:
        info = asyncio.run(sess.info())
        assert info["id"] == SID and info["active"] is True and info["local"] is False
        assert info["idle_timeout_secs"] == 300
        with pytest.raises(mvm.MvmTransportError, match="fixed when its microVM boots"):
            asyncio.run(sess.set_timeout(10))
        asyncio.run(sess.kill())
    assert on_host.methods.count("session.stop") == 1, "a killed session is not stopped twice"


def test_a_bad_idle_timeout_is_refused(on_host) -> None:
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValueError, match="idle_timeout_secs"):
            mvm.session("adder", idle_timeout_secs=bad)
    assert on_host.calls == []
