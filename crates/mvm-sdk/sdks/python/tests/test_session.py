"""`mvm.session(...)`: a local scope under ``MVM_NO_VM=1``, refused otherwise."""

from __future__ import annotations

import asyncio
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

    # No session path may touch the library: there is no session surface in
    # it, and a local scope has nothing to ask.
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


def test_without_no_vm_opening_a_session_is_refused(monkeypatch) -> None:
    monkeypatch.delenv("MVM_NO_VM")
    with pytest.raises(mvm.MvmTransportError, match="MVM_NO_VM=1"):
        with mvm.session("adder"):
            pytest.fail("the session body must not run")
    assert mvm.current_session_id() is None
