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

def test_unknown_session_release_uses_original_context_close_and_checked_free(monkeypatch):
    import ctypes
    import json

    monkeypatch.setenv("MVM_NO_VM", "0")
    methods = []
    def transport(method, _request):
        methods.append(method)
        return 6, json.dumps({
            "code": "REJECTED", "message": "local fixture", "retryable": False
        }).encode()
    monkeypatch.setattr(_hostlib, "_invoke", transport)
    with pytest.raises(_hostlib.OwnedContextFailure) as caught:
        with mvm.session("fixture"):
            pytest.fail("a refused start must not run its body")
    owner = caught.value.session
    context = caught.value.recovery
    primary = caught.value.primary_error
    calls = []
    class Library:
        close_ok = False
        free_ok = False
        def mvm_hostlib_context_close(self, _pointer, out):
            calls.append("close")
            out._obj.len = 0
            return 0 if self.close_ok else 5
        def mvm_hostlib_context_checked_free(self, pointer):
            calls.append("free")
            if not self.free_ok:
                return 5
            pointer._obj.value = None
            return 0
        def mvm_hostlib_free(self, _out):
            pass
    # Actual SDK receiver and C outcome adapter, not a native allocation/proof.
    library = Library()
    context._pointer = ctypes.c_void_p(123)
    context._library = library
    for close_ok in [False, True]:
        library.close_ok = close_ok
        with pytest.raises(_hostlib.OwnedContextFailure) as retry:
            owner.retry_stop()
        assert retry.value.primary_error is primary
        assert retry.value.session is owner
        assert retry.value.recovery is context
        assert owner._start_phase == "unknown"
        assert not context._freed
        assert context._pointer.value == 123
        assert "local fixture" not in str(retry.value)
    assert len(owner._cleanup_errors) == 2
    history = list(owner._cleanup_errors)
    library.free_ok = True
    owner.retry_stop()
    assert owner._start_phase == "finished" and owner._stop_phase == "closed"
    assert not owner._active and context._pointer.value is None
    assert owner._start_error is primary
    assert owner._cleanup_errors == history
    finished_calls = list(calls)
    owner.retry_stop()
    assert calls == finished_calls
    assert methods == ["session.start"]

def test_actual_session_retains_body_and_cleanup_errors_and_retries_cleanup_only(monkeypatch):
    monkeypatch.setenv("MVM_NO_VM", "0")
    primary = ValueError("body fixture")
    cleanup = RuntimeError("close fixture")
    calls = []
    class NoChildContext:
        fail_close = True
        def _reserve_session_start(self):
            pass  # No C allocation or native resource exists in this adapter.
        def call(self, method, _request):
            calls.append(method)
            if method == "session.start":
                return {"session_id": "abcdefghijklmnopqrstuvwx", "vm_name": "fixture"}
            return {}
        def close(self):
            calls.append("close")
            if self.fail_close:
                raise cleanup
        def free(self):
            calls.append("free")
    context = NoChildContext()
    monkeypatch.setattr(_hostlib, "NativeContext", lambda: context)
    handle = mvm.session("fixture")
    with pytest.raises(_hostlib.OwnedContextFailure) as caught:
        with handle:
            raise primary
    assert caught.value.primary_error is primary
    assert caught.value.cleanup_error is cleanup
    assert caught.value.recovery is context
    assert caught.value.session is handle
    assert handle._active
    context.fail_close = False
    handle.retry_stop()
    assert not handle._active
    assert calls.count("session.stop") == 1
    assert calls.count("close") == 2


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


def test_a_stop_failure_retains_body_and_stop_errors_in_the_owned_context(
    on_host, monkeypatch
) -> None:
    # Host sessions now use the caller-owned context even for ordinary calls.
    # This recorder exercises that consumer without a library or native child.
    original_call = _hostlib.NativeContext.call
    stop_errors = []

    def record_stop_error(context, method, request):
        try:
            return original_call(context, method, request)
        except mvm.HostLibraryError as error:
            if method == "session.stop":
                stop_errors.append(error)
            raise

    monkeypatch.setattr(_hostlib.NativeContext, "call", record_stop_error)
    on_host.fail("session.stop", "BACKEND_ERROR", "teardown failed")
    primary = RuntimeError("body fixture must not be rendered")
    session = mvm.session("adder")
    with pytest.raises(_hostlib.OwnedContextFailure) as caught:
        with session:
            raise primary
    assert caught.value.primary_error is primary
    assert caught.value.cleanup_error is stop_errors[0]
    assert caught.value.recovery is session._context
    assert caught.value.session is session
    assert session._active
    assert str(primary) not in str(caught.value)
    assert str(stop_errors[0]) not in str(caught.value)
    on_host.fail("session.stop", "BACKEND_ERROR", "teardown failed")
    on_host.reply("session.start", {"session_id": SID, "vm_name": "session-vm"})
    other = mvm.session("adder")
    with pytest.raises(_hostlib.OwnedContextFailure) as no_body:
        with other:
            pass
    assert no_body.value.primary_error is None
    assert no_body.value.cleanup_error is stop_errors[1]
    assert no_body.value.recovery is other._context
    assert no_body.value.session is other
    assert other._active


def test_explicit_failed_retry_retains_original_body_all_errors_and_same_owner(
    on_host, monkeypatch
) -> None:
    on_host.fail("session.stop", "BACKEND_ERROR", "first fixture stop")
    on_host.fail("session.stop", "BACKEND_ERROR", "second fixture stop")
    on_host.reply("session.stop", {})
    primary = ValueError("body fixture must stay private")
    errors = []
    original_call = _hostlib.NativeContext.call

    def observe(context, method, request):
        try:
            return original_call(context, method, request)
        except BaseException as error:
            errors.append(error)
            raise

    monkeypatch.setattr(_hostlib.NativeContext, "call", observe)
    with pytest.raises(_hostlib.OwnedContextFailure) as first:
        with mvm.session("adder"):
            raise primary
    with pytest.raises(_hostlib.OwnedContextFailure) as second:
        first.value.session.retry_stop()
    owner = second.value.session
    assert second.value.primary_error is primary
    assert second.value.cleanup_error is errors[1]
    assert owner is first.value.session
    assert second.value.recovery is first.value.recovery is owner._context
    assert owner._primary_error is primary
    assert len(owner._cleanup_errors) == 2
    assert owner._cleanup_errors[0] is errors[0]
    assert owner._cleanup_errors[1] is errors[1]
    assert owner._active
    assert "body fixture" not in str(second.value)
    assert "fixture stop" not in str(second.value)
    owner.retry_stop()
    owner.retry_stop()
    assert not owner._active
    assert on_host.methods == ["session.start", "session.stop", "session.stop", "session.stop"]
    assert owner._primary_error is primary
    assert owner._cleanup_errors == errors


def test_cleanup_error_budget_refuses_retry_before_transport_without_discard(on_host):
    from mvm import _session

    for _ in range(_session._MAX_CLEANUP_FAILURES):
        on_host.fail("session.stop", "BACKEND_ERROR", "bounded fixture")
    owner = mvm.session("adder")
    owner.__enter__()
    for _ in range(_session._MAX_CLEANUP_FAILURES):
        with pytest.raises(_hostlib.OwnedContextFailure) as failed:
            owner.retry_stop()
        assert failed.value.session is owner
        assert failed.value.recovery is owner._context
    originals = list(owner._cleanup_errors)
    before = list(on_host.calls)
    with pytest.raises(_hostlib.OwnedContextFailure) as exhausted:
        owner.retry_stop()
    assert exhausted.value.session is owner
    assert exhausted.value.recovery is owner._context
    assert on_host.calls == before
    assert len(owner._cleanup_errors) == _session._MAX_CLEANUP_FAILURES
    assert all(a is b for a, b in zip(owner._cleanup_errors, originals))
    assert owner._active
    owner._reset_contextvar()
    # Original no-child recorder state stays held. No terminal proof is minted.


@pytest.mark.parametrize("reply", [
    {}, {"session_id": None}, {"session_id": 7},
    {"session_id": "NOT-BASE32"}, {"session_id": SID + "\n"},
])
def test_a_start_without_a_usable_id_retains_its_original_receiver(
    on_host, monkeypatch, reply
) -> None:
    on_host._queued["session.start"].clear()
    on_host.reply("session.start", reply)
    original_call = _hostlib.NativeContext.call
    protocol_errors = []

    def observe(context, method, request):
        try:
            return original_call(context, method, request)
        except BaseException as error:
            protocol_errors.append(error)
            raise

    monkeypatch.setattr(_hostlib.NativeContext, "call", observe)
    with pytest.raises(_hostlib.OwnedContextFailure) as caught:
        with mvm.session("adder"):
            pytest.fail("the session body must not run")
    owner = caught.value.session
    context = caught.value.recovery
    assert owner._context is context
    assert caught.value.primary_error is protocol_errors[0]
    assert owner._start_error is protocol_errors[0]
    assert owner.id is None
    assert not owner._active  # Not an assertion that an unknown launch stopped.
    for cleanup in [owner.retry_stop, context.retry_stop, context.close, context.free]:
        with pytest.raises(mvm.MvmTransportError):
            cleanup()
    with pytest.raises(_hostlib.OwnedContextFailure) as repeated:
        owner.__enter__()
    assert repeated.value.primary_error is protocol_errors[0]
    assert repeated.value.session is owner
    assert repeated.value.recovery is context
    assert on_host.methods == ["session.start"]
    assert mvm.current_session_id() is None


@pytest.mark.parametrize("malformed", [False, True])
def test_cancelled_anonymous_async_start_retains_the_real_worker_and_receiver(
    on_host, monkeypatch, malformed
) -> None:
    entered = threading.Event()
    release = threading.Event()
    starts = []
    if malformed:
        on_host._queued["session.start"].clear()
        on_host.reply("session.start", {"private_marker": "must-not-render"})
    on_host.reply("session.stop", {})

    def blocked_inprocess_transport(method, request):
        if method == "session.start":
            starts.append(method)
            entered.set()
            assert release.wait(5), "test must release its no-child worker"
        return on_host(method, request)

    monkeypatch.setattr(_hostlib, "_invoke", blocked_inprocess_transport)

    async def scenario():
        async def anonymous():
            async with mvm.session("adder"):
                pytest.fail("cancelled start cannot enter the body")

        entering = asyncio.create_task(anonymous())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            entering.cancel()
            with pytest.raises(asyncio.CancelledError) as cancelled:
                await entering
            failure = cancelled.value
            owner = failure.session
            context = failure.recovery
            worker = failure.worker
            assert owner._context is context
            assert owner._start_task is worker
            assert failure.primary_error is failure.__cause__
            assert owner._start_cancellations[0] is failure.primary_error
            assert not worker.done()
            for cleanup in [owner.retry_stop, context.close, context.free]:
                with pytest.raises(mvm.MvmTransportError):
                    cleanup()
            with pytest.raises(_hostlib.OwnedContextFailure):
                await owner.__aenter__()
            waiter = asyncio.create_task(owner.wait_started())
            await asyncio.sleep(0)  # Yield until this waiter is on the held task.
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError) as cancelled_wait:
                await waiter
            assert cancelled_wait.value.session is owner
            assert cancelled_wait.value.recovery is context
            assert cancelled_wait.value.worker is worker
            assert cancelled_wait.value.primary_error is cancelled_wait.value.__cause__
            assert not worker.cancelled()
            assert len(starts) == 1
            release.set()
            if malformed:
                with pytest.raises(_hostlib.OwnedContextFailure) as worker_error:
                    await owner.wait_started()
                assert worker_error.value.primary_error is owner._start_error
                assert owner._start_error is context._session_error
                with pytest.raises(_hostlib.OwnedContextFailure):
                    owner.retry_stop()
                with pytest.raises(mvm.MvmTransportError):
                    context.free()
                assert owner.id is None
                assert "must-not-render" not in str(worker_error.value)
            else:
                await owner.wait_started()
                await owner.wait_started()
                assert owner._active
                owner.retry_stop()
                assert not owner._active
                assert on_host.methods == ["session.start", "session.stop"]
            assert worker.done()
            assert len(starts) == 1
            assert owner._start_cancellations[0] is failure.primary_error
        finally:
            release.set()

    asyncio.run(scenario())


@pytest.mark.parametrize("worker_fails", [False, True])
def test_cancelled_anonymous_async_cleanup_keeps_cancel_worker_and_all_retries(
    on_host, monkeypatch, worker_fails
) -> None:
    entered = threading.Event()
    release = threading.Event()
    primary = ValueError("private body fixture")
    if worker_fails:
        on_host.fail("session.stop", "BACKEND_ERROR", "private stop fixture")
    else:
        on_host.reply("session.stop", {})
    on_host.reply("session.stop", {})
    original_call = _hostlib.NativeContext.call
    stop_errors = []

    def observe(context, method, request):
        try:
            return original_call(context, method, request)
        except BaseException as error:
            if method == "session.stop":
                stop_errors.append(error)
            raise

    def blocked_transport(method, request):
        if method == "session.stop" and not entered.is_set():
            entered.set()
            assert release.wait(5), "test must release its no-child cleanup worker"
        return on_host(method, request)

    monkeypatch.setattr(_hostlib, "_invoke", blocked_transport)
    monkeypatch.setattr(_hostlib.NativeContext, "call", observe)

    async def scenario():
        async def anonymous():
            async with mvm.session("adder"):
                raise primary

        exiting = asyncio.create_task(anonymous())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            exiting.cancel()
            with pytest.raises(asyncio.CancelledError) as cancelled:
                await exiting
            first = cancelled.value
            owner, context, worker = first.session, first.recovery, first.worker
            original_cancel = first.cleanup_error
            assert first.primary_error is primary
            assert original_cancel is first.__cause__
            assert owner._cleanup_task is worker
            assert owner._context is context
            assert owner._cleanup_cancellations[0] is original_cancel
            assert owner._primary_error is primary
            assert not worker.done()
            before = list(on_host.calls)
            with pytest.raises(_hostlib.OwnedContextFailure) as busy:
                first.session.retry_stop()
            assert busy.value.session is owner
            assert busy.value.recovery is context
            assert busy.value.worker is worker
            assert busy.value.primary_error is primary
            assert any(error is original_cancel for error in busy.value.cancellation_errors)
            assert on_host.calls == before
            waiter = asyncio.create_task(busy.value.session.wait_cleanup())
            await asyncio.sleep(0)
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError) as cancelled_wait:
                await waiter
            second_cancel = cancelled_wait.value.cleanup_error
            assert cancelled_wait.value.session is owner
            assert cancelled_wait.value.worker is worker
            assert cancelled_wait.value.primary_error is primary
            assert second_cancel is cancelled_wait.value.__cause__
            assert owner._cleanup_cancellations == [original_cancel, second_cancel]
            assert not worker.cancelled()
            release.set()
            if worker_fails:
                with pytest.raises(_hostlib.OwnedContextFailure) as failed:
                    await cancelled_wait.value.session.wait_cleanup()
                assert failed.value.session is owner
                assert failed.value.recovery is context
                assert failed.value.worker is worker
                assert failed.value.primary_error is primary
                assert failed.value.cleanup_error is stop_errors[0]
                assert any(error is original_cancel for error in failed.value.cancellation_errors)
                assert any(error is second_cancel for error in failed.value.cancellation_errors)
                assert owner._active
                failed.value.session.retry_stop()
            else:
                await owner.wait_cleanup()
            assert worker.done()
            owner.retry_stop()
            assert not owner._active
            assert owner._primary_error is primary
            assert any(error is original_cancel for error in owner._cleanup_errors)
            assert any(error is second_cancel for error in owner._cleanup_errors)
            assert owner._error_reserved == 0
            assert len(on_host.requests("session.stop")) == (2 if worker_fails else 1)
            assert "private body" not in str(first)
            assert "private stop" not in str(first)
        finally:
            release.set()

    asyncio.run(scenario())


def test_cleanup_cancellation_capacity_is_reserved_before_wait_and_worker_race(
    on_host, monkeypatch
) -> None:
    from mvm import _session

    entered = threading.Event()
    release = threading.Event()
    on_host.fail("session.stop", "BACKEND_ERROR", "no-child fixture")

    def blocked_transport(method, request):
        if method == "session.stop":
            entered.set()
            assert release.wait(5)
        return on_host(method, request)

    monkeypatch.setattr(_hostlib, "_invoke", blocked_transport)

    async def scenario():
        async def anonymous():
            async with mvm.session("adder"):
                pass

        exiting = asyncio.create_task(anonymous())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            exiting.cancel()
            with pytest.raises(asyncio.CancelledError) as first:
                await exiting
            owner = first.value.session
            original = first.value.cleanup_error
            # One original cancellation, one reserved worker outcome. Fill
            # only the remaining slots with real pending wait operations.
            waiters = [
                asyncio.create_task(owner.wait_cleanup())
                for _ in range(_session._MAX_CLEANUP_FAILURES - 2)
            ]
            await asyncio.sleep(0)
            assert len(owner._cleanup_errors) + owner._error_reserved == _session._MAX_CLEANUP_FAILURES
            before = list(on_host.calls)
            with pytest.raises(_hostlib.OwnedContextFailure) as full:
                await owner.wait_cleanup()
            assert full.value.session is owner
            assert any(error is original for error in full.value.cancellation_errors)
            assert on_host.calls == before
            for waiter in waiters:
                waiter.cancel()
            for waiter in waiters:
                with pytest.raises(asyncio.CancelledError) as cancelled:
                    await waiter
                assert cancelled.value.session is owner
                assert any(error is original for error in cancelled.value.cancellation_errors)
            release.set()
            # Observe actual no-child worker completion without taking a new
            # public wait slot, then exercise the public completed-task path.
            completed = asyncio.Event()
            owner._cleanup_task.add_done_callback(lambda _task: completed.set())
            await asyncio.wait_for(completed.wait(), 5)
            with pytest.raises(_hostlib.OwnedContextFailure):
                await owner.wait_cleanup()
            assert len(owner._cleanup_errors) == _session._MAX_CLEANUP_FAILURES
            assert owner._error_reserved == 0
            originals = tuple(owner._cleanup_errors)
            before = list(on_host.calls)
            with pytest.raises(_hostlib.OwnedContextFailure) as refused:
                owner.retry_stop()
            assert refused.value.session is owner
            assert any(error is original for error in refused.value.cancellation_errors)
            assert on_host.calls == before
            assert all(a is b for a, b in zip(owner._cleanup_errors, originals))
            assert owner._active
        finally:
            release.set()

    asyncio.run(scenario())


def test_async_cleanup_refuses_before_task_when_two_error_slots_are_unavailable(on_host):
    from mvm import _session

    for _ in range(_session._MAX_CLEANUP_FAILURES - 1):
        on_host.fail("session.stop", "BACKEND_ERROR", "no-child fixture")
    on_host.reply("session.stop", {})
    async def scenario():
        owner = mvm.session("adder")
        await owner.__aenter__()
        for _ in range(_session._MAX_CLEANUP_FAILURES - 1):
            with pytest.raises(_hostlib.OwnedContextFailure):
                owner.retry_stop()
        before = list(on_host.calls)
        with pytest.raises(_hostlib.OwnedContextFailure) as full:
            await owner.__aexit__(None, None, None)
        assert full.value.session is owner
        assert on_host.calls == before
        assert owner._cleanup_task is None
        assert owner._error_reserved == 0
        owner.retry_stop()  # One synchronous outcome slot remains; no new worker.
        owner.retry_stop()
        assert not owner._active
        assert mvm.current_session_id() is None

    asyncio.run(scenario())


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
