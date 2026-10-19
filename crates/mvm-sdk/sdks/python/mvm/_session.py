"""Sessions for function-entrypoint workloads.

A session is the explicit boundary inside which calls to one workload share
state: on a microVM, a warm VM reused across ``await f(...)`` calls instead
of one cold boot per call. Both async and sync forms are supported::

    async with mv.session("adder") as sess:
        await add(2, 3)
        await add(4, 5)

    with mv.session("adder") as sess:
        add.sync(2, 3)
        add.sync(4, 5)

Where a session lives follows from where calls run (see ``mvm._remote``):

- ``MVM_NO_VM=1``: calls run in this process, so a session is a local scope.
  It has an id of the form ``local-<hex>``, :func:`current_session_id`
  reports it inside the body, and there is no VM behind it; its methods act
  locally.
- Otherwise: entering the session boots the workload's microVM through the
  host library (``session.start``), every call to that workload inside the
  body is dispatched into it (``session.call``), and leaving the session stops
  it (``session.stop``). The VM is admitted and audited exactly as
  ``mvmctl machine session start`` admits one. A warm VM is not a warm
  interpreter: each call still runs the function's wrapper afresh.
"""

from __future__ import annotations

import asyncio
import contextvars
import secrets
import threading
from typing import TYPE_CHECKING, Any

from mvm import _hostlib
from mvm._errors.types import MvmTransportError
from mvm._hostabi.methods import SESSION_INFO, SESSION_START, SESSION_STOP
from mvm._remote import (
    _check_emitting_context,
    _check_id,
    _no_vm,
)

if TYPE_CHECKING:
    from mvm._remote import RemoteFunction

__all__ = ["Session", "session", "current_session_id"]

_MAX_CLEANUP_FAILURES = 16

_active_session: contextvars.ContextVar["Session | None"] = contextvars.ContextVar(
    "mvm_session", default=None
)


def current_session_id() -> str | None:
    """Return the session id active in the current context, or ``None``."""
    active = _active_session.get()
    return active.id if active is not None else None


def _host_session_for(workload_id: str) -> str | None:
    """The host session a call to ``workload_id`` goes into, if one is open
    in this context. A call to another workload inside a session runs in a
    VM of its own."""
    active = _active_session.get()
    if (
        active is None
        or not active._host_backed
        or not active._active
        or active._id is None
        or active.workload_id != workload_id
    ):
        return None
    return active._id


def _host_context_for(workload_id: str) -> _hostlib.NativeContext | None:
    active = _active_session.get()
    if _host_session_for(workload_id) is None or active is None:
        return None
    return active._context


class _SessionStartCancelled(asyncio.CancelledError):
    """Cancellation retains its original exception and in-flight receiver."""

    def __init__(self, cancellation: asyncio.CancelledError, session: "Session"):
        super().__init__("session start wait cancelled; original worker and context retained")
        self.primary_error = cancellation
        self.session = session
        self.recovery = session._context
        self.worker = session._start_task


class _SessionCleanupCancelled(asyncio.CancelledError):
    """The waiter cancelled, not the original cleanup operation."""

    def __init__(self, cancellation: asyncio.CancelledError, session: "Session"):
        super().__init__("session cleanup wait cancelled; original worker and context retained")
        primary = session._cleanup_primary()
        self.primary_error = primary if primary is not None else cancellation
        self.cleanup_error = cancellation
        self.session = session
        self.recovery = session._context
        self.worker = session._cleanup_task


class Session:
    """Typed handle for a session.

    Use as a context manager — ``async with`` when you're already in async
    code; ``with`` for synchronous callers that pair with
    :meth:`RemoteFunction.sync`. ``str(sess)`` returns the session id so
    logs stay readable.

    Within the ``with`` body, :func:`current_session_id` returns this
    session's id; the binding is a context variable, so it does not leak into
    other threads or tasks.

    Cross-workload guard: :meth:`invoke` raises if the supplied
    ``RemoteFunction``'s ``workload_id`` doesn't match the session's.
    """

    __slots__ = (
        "_workload_id",
        "_id",
        "_token",
        "_active",
        "_timeout",
        "_host_backed",
        "_vm_name",
        "_context",
        "_stop_phase",
        "_start_phase",
        "_start_error",
        "_start_task",
        "_start_cancellations",
        "_primary_error",
        "_cleanup_errors",
        "_cleanup_lock",
        "_cleanup_task",
        "_cleanup_cancellations",
        "_history_lock",
        "_error_reserved",
    )

    def __init__(self, workload_id: str, session_id: str):
        _check_id("session_id", session_id)
        self._workload_id = workload_id
        self._id: str | None = session_id
        self._token: contextvars.Token[Session | None] | None = None
        self._active = True
        self._timeout: float | None = None
        self._host_backed = False
        self._vm_name: str | None = None
        self._context: _hostlib.NativeContext | None = None
        self._stop_phase = "running"
        self._start_phase = "active"
        self._start_error: BaseException | None = None
        self._start_task: asyncio.Task[None] | None = None
        self._start_cancellations: list[asyncio.CancelledError] = []
        self._primary_error: BaseException | None = None
        self._cleanup_errors: list[BaseException] = []
        self._cleanup_lock = threading.Lock()
        self._cleanup_task: asyncio.Task[None] | None = None
        self._cleanup_cancellations: list[asyncio.CancelledError] = []
        self._history_lock = threading.Lock()
        self._error_reserved = 0

    @classmethod
    def _on_host(cls, workload_id: str, idle_timeout_secs: int | None) -> "Session":
        """A session whose microVM boots when it is entered."""
        handle = cls.__new__(cls)
        handle._workload_id = workload_id
        handle._id = None
        handle._token = None
        handle._active = False
        handle._timeout = None if idle_timeout_secs is None else float(idle_timeout_secs)
        handle._host_backed = True
        handle._vm_name = None
        handle._context = None
        handle._stop_phase = "running"
        handle._start_phase = "new"
        handle._start_error = None
        handle._start_task = None
        handle._start_cancellations = []
        handle._primary_error = None
        handle._cleanup_errors = []
        handle._cleanup_lock = threading.Lock()
        handle._cleanup_task = None
        handle._cleanup_cancellations = []
        handle._history_lock = threading.Lock()
        handle._error_reserved = 0
        return handle

    @property
    def id(self) -> str | None:
        """The session identifier. ``None`` for a host session that has not
        been entered yet: the host mints the id when it boots the VM."""
        return self._id

    @property
    def workload_id(self) -> str:
        """The workload this session is bound to."""
        return self._workload_id

    def __str__(self) -> str:
        return self._id or ""

    def __repr__(self) -> str:
        return f"Session(workload_id={self._workload_id!r}, id={self._id!r})"

    # --- host lifecycle --------------------------------------------------

    def _retained_failure(self, primary: BaseException | None, reason: str) -> BaseException:
        error = MvmTransportError(reason)
        if self._context is None:
            return self._decorate_failure(error)
        failure = _hostlib.OwnedContextFailure(primary, error, self._context)
        return self._decorate_failure(failure)

    def _decorate_failure(
        self, failure: BaseException, worker: asyncio.Task[None] | None = None
    ) -> BaseException:
        failure.session = self
        failure.recovery = self._context
        failure.worker = worker if worker is not None else self._cleanup_task or self._start_task
        with self._history_lock:
            failure.cancellation_errors = tuple(
                self._start_cancellations + self._cleanup_cancellations
            )
            failure.cleanup_errors = tuple(self._cleanup_errors)
        return failure

    def _reserve_error_slots(self, count: int) -> bool:
        # Only bounded bookkeeping is locked, never FFI, await or user code.
        with self._history_lock:
            if len(self._cleanup_errors) + self._error_reserved + count > _MAX_CLEANUP_FAILURES:
                return False
            self._error_reserved += count
            return True

    def _finish_error_slot(
        self, error: BaseException | None, cancelled_phase: str | None = None
    ) -> None:
        with self._history_lock:
            assert self._error_reserved > 0
            self._error_reserved -= 1
            if error is not None:
                self._cleanup_errors.append(error)
                if isinstance(error, asyncio.CancelledError):
                    if cancelled_phase == "start":
                        self._start_cancellations.append(error)
                    elif cancelled_phase == "cleanup":
                        self._cleanup_cancellations.append(error)

    def _prepare_start(self) -> None:
        if self._start_phase == "new":
            self._context = _hostlib.NativeContext()
            self._context._reserve_session_start()
            self._start_phase = "prepared"
        elif self._start_phase not in ("prepared", "active"):
            raise self._retained_failure(self._start_error, "original session start cannot be repeated")

    def _start(self) -> None:
        if not self._host_backed:
            return
        self._prepare_start()
        if self._start_phase == "active":
            return
        self._start_phase = "starting"
        request: dict[str, Any] = {"workload": self._workload_id}
        if self._timeout is not None:
            request["idle_timeout_secs"] = int(self._timeout)
        assert self._context is not None
        try:
            reply = self._context.call(SESSION_START, request)
            session_id = _hostlib._session_id_from_reply(reply)
        except BaseException as error:
            self._start_error = error
            self._start_phase = "unknown"
            raise self._retained_failure(error, "original session start remains unconfirmed") from None
        self._id = session_id
        self._vm_name = reply.get("vm_name")
        self._active = True
        self._start_phase = "active"

    def _cleanup_primary(self) -> BaseException | None:
        with self._history_lock:
            if self._primary_error is not None:
                return self._primary_error
            if self._start_error is not None:
                return self._start_error
            if self._start_cancellations:
                return self._start_cancellations[0]
            return self._cleanup_cancellations[0] if self._cleanup_cancellations else None

    def _stop(self) -> None:
        if self._cleanup_task is not None and not self._cleanup_task.done():
            raise self._retained_failure(
                self._cleanup_primary(), "original cleanup worker is still pending"
            )
        if not self._host_backed or self._stop_phase == "closed":
            self._active = False
            return
        if not self._reserve_error_slots(1):
            raise self._retained_failure(
                self._cleanup_primary(),
                "cleanup error retention budget exhausted; no further operation dispatched",
            )
        self._stop_reserved()

    def _stop_reserved(self) -> None:
        """Consume one reserved outcome slot for this original operation."""
        if not self._cleanup_lock.acquire(blocking=False):
            self._finish_error_slot(None)
            raise self._retained_failure(self._cleanup_primary(), "original cleanup is busy")
        try:
            try:
                self._stop_original()
            except BaseException as error:
                self._finish_error_slot(error)
                if (
                    isinstance(error, _hostlib.OwnedContextFailure)
                    and getattr(error, "session", None) is self
                ):
                    raise self._decorate_failure(error)
                assert self._context is not None
                failure = _hostlib.OwnedContextFailure(
                    self._cleanup_primary(), error, self._context
                )
                raise self._decorate_failure(failure) from None
            else:
                self._finish_error_slot(None)
        finally:
            self._cleanup_lock.release()

    def _stop_original(self) -> None:
        if (
            self._host_backed
            and self._start_phase == "unknown"
            and (self._start_task is None or self._start_task.done())
        ):
            if self._context is None:
                raise MvmTransportError("session has no original owning context")
            # Unknown is not proof. Only the original C close can establish
            # a known pre-dispatch failure; it refuses ambiguous starts.
            self._context.close()
            self._context.free()
            self._stop_phase = "closed"
            self._start_phase = "finished"
            self._active = False
            return
        if self._host_backed and (
            self._start_phase in ("prepared", "starting", "unknown")
            or (self._start_task is not None and not self._start_task.done())
        ):
            primary = self._start_error
            if primary is None and self._start_cancellations:
                primary = self._start_cancellations[0]
            raise self._retained_failure(primary, "original session start is not ready for cleanup")
        if self._host_backed and self._active and self._id is not None:
            if self._context is None:
                raise MvmTransportError("session has no original owning context")
            if self._stop_phase == "running":
                self._context.call(SESSION_STOP, {"session_id": self._id})
                self._stop_phase = "closing"
            self._context.close()
            self._context.free()
            self._stop_phase = "closed"
            self._start_phase = "finished"
        self._active = False

    def retry_stop(self) -> None:
        """Retry this held session's remaining stop/close, never recreate it."""
        self._stop()

    # --- sync context-manager (for use with f.sync(...)) ----------------

    def __enter__(self) -> "Session":
        self._start()
        self._token = _active_session.set(self)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc is not None and self._primary_error is None:
            self._primary_error = exc
        self._reset_contextvar()
        self._stop()

    # --- async context-manager (for use with await f(...)) --------------

    async def __aenter__(self) -> "Session":
        if self._host_backed:
            if self._start_task is not None:
                raise self._retained_failure(
                    self._start_error, "session entry cannot repeat its original start worker"
                )
            self._prepare_start()
            if not self._reserve_error_slots(1):
                raise self._retained_failure(
                    self._cleanup_primary(), "no guaranteed start-wait error slot remains"
                )
            coroutine = None
            try:
                coroutine = asyncio.to_thread(self._start)
                self._start_task = asyncio.create_task(coroutine)
                self._start_task.add_done_callback(self._observe_worker_completion)
            except BaseException as error:
                if self._start_task is None and coroutine is not None:
                    coroutine.close()
                self._finish_error_slot(error)
                raise self._retained_failure(error, "original start worker setup failed") from None
            await self._wait_reserved_worker(self._start_task, "start")
        self._token = _active_session.set(self)
        return self

    def _observe_worker_completion(self, task: asyncio.Task[None]) -> None:
        # Retrieve without discarding: the original error remains on the task
        # and in this Session even when its original waiter was cancelled.
        if not task.cancelled():
            task.exception()

    async def wait_started(self) -> None:
        """Await only this held start worker, never restart or dispatch.

        Cancellation does not stop a worker thread. Its CancelledError-subclass
        carries this Session/context; retain it, await wait_started(), then use
        retry_stop(). Unknown replies remain unresolved, not stopped.
        """
        task = self._start_task
        if task is None:
            if not self._host_backed or self._start_phase in ("active", "finished"):
                return
            raise self._retained_failure(self._start_error, "no completed original start is available")
        await self._wait_held_worker(task, "start")

    async def wait_cleanup(self) -> None:
        """Await only the already-held cleanup worker, never retry or dispatch.

        Its original result/errors remain inspectable even after a later
        explicit retry succeeds. Cancellation retains this Session and task.
        """
        task = self._cleanup_task
        if task is None:
            if not self._host_backed or self._stop_phase == "closed":
                return
            raise self._retained_failure(
                self._cleanup_primary(), "no original cleanup worker is available"
            )
        await self._wait_held_worker(task, "cleanup")

    async def _wait_held_worker(self, task: asyncio.Task[None], phase: str) -> None:
        if task.done():
            try:
                task.result()
            except BaseException as error:
                raise self._decorate_failure(error, task)
            return
        if not self._reserve_error_slots(1):
            raise self._retained_failure(
                self._cleanup_primary(), "no guaranteed worker-wait error slot remains"
            )
        await self._wait_reserved_worker(task, phase)

    async def _wait_reserved_worker(self, task: asyncio.Task[None], phase: str) -> None:
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as cancellation:
            self._finish_error_slot(cancellation, phase)
            failure = (
                _SessionStartCancelled(cancellation, self)
                if phase == "start" else _SessionCleanupCancelled(cancellation, self)
            )
            raise self._decorate_failure(failure, task) from cancellation
        except BaseException as error:
            self._finish_error_slot(None)
            raise self._decorate_failure(error, task)
        else:
            self._finish_error_slot(None)

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc is not None and self._primary_error is None:
            self._primary_error = exc
        self._reset_contextvar()
        if not self._host_backed:
            self._stop()
            return
        if self._cleanup_task is not None:
            await self.wait_cleanup()
            return
        # One slot for the worker outcome and one for cancellation of this
        # waiter, reserved atomically BEFORE task creation or cleanup effects.
        if not self._reserve_error_slots(2):
            raise self._retained_failure(
                self._cleanup_primary(), "no guaranteed cleanup outcome and wait slots remain"
            )
        coroutine = None
        try:
            coroutine = asyncio.to_thread(self._stop_reserved)
            self._cleanup_task = asyncio.create_task(coroutine)
            self._cleanup_task.add_done_callback(self._observe_worker_completion)
        except BaseException as error:
            if self._cleanup_task is None:
                if coroutine is not None:
                    coroutine.close()
                self._finish_error_slot(None)
            self._finish_error_slot(error)
            raise self._retained_failure(error, "original cleanup worker setup failed") from None
        await self._wait_reserved_worker(self._cleanup_task, "cleanup")

    def _reset_contextvar(self) -> None:
        if self._token is not None:
            try:
                _active_session.reset(self._token)
            except ValueError:
                # Token reset from a foreign Context; ignore. The user's
                # code escaped the with-block via task switching.
                pass
            self._token = None

    # --- explicit lifecycle methods ------------------------------------

    async def invoke(self, fn: "RemoteFunction", /, *args: Any, **kwargs: Any) -> Any:
        """Dispatch ``fn`` within this session.

        Equivalent to entering this session's context and calling
        ``await fn(*args, **kwargs)`` — surfaced as an explicit method
        so callers can exercise the cross-workload guard without
        re-binding context-vars.
        """
        if fn.workload_id != self._workload_id:
            raise ValueError(
                f"Session({self._workload_id!r}) cannot invoke RemoteFunction "
                f"bound to workload {fn.workload_id!r}. Hint: open a session "
                "for the right workload, or invoke without a session."
            )
        if self._host_backed and (self._id is None or not self._active):
            raise MvmTransportError(
                f"Session({self._workload_id!r}) has no running microVM: enter it with "
                "`with` or `async with` before invoking through it"
            )
        prev = _active_session.set(self)
        try:
            return await fn(*args, **kwargs)
        finally:
            _active_session.reset(prev)

    async def set_timeout(self, seconds: float) -> None:
        """Set this session's idle timeout.

        A local session records it and reports it from :meth:`info`. A host
        session takes it when it boots; once its VM is running the timeout is
        fixed, so pass it to :func:`session` or set it before entering."""
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds < 0:
            raise ValueError("set_timeout seconds must be a non-negative number")
        if self._host_backed and self._id is not None:
            raise MvmTransportError(
                "a host session's idle timeout is fixed when its microVM boots; pass "
                "idle_timeout_secs to mvm.session(...) instead"
            )
        self._timeout = float(seconds)

    async def kill(self) -> None:
        """End the session, stopping its microVM when it has one. Later
        :meth:`info` calls report it inactive."""
        await asyncio.to_thread(self._stop)

    async def info(self) -> dict[str, Any]:
        """What is known about this session: for a host session that has
        booted, the host's own record under ``record``."""
        if self._host_backed and self._id is not None:
            record = await asyncio.to_thread(
                _hostlib.call, SESSION_INFO, {"session_id": self._id}
            )
            fields = record if isinstance(record, dict) else {}
            return {
                "id": self._id,
                "workload_id": self._workload_id,
                "active": fields.get("state") == "running",
                "idle_timeout_secs": fields.get("idle_timeout_secs"),
                "local": False,
                "record": record,
            }
        return {
            "id": self._id,
            "workload_id": self._workload_id,
            "active": self._active,
            "idle_timeout_secs": self._timeout,
            "local": not self._host_backed,
        }


def session(workload_id: str, *, idle_timeout_secs: int | None = None) -> Session:
    """Open a session bound to ``workload_id``.

    Returns a :class:`Session` you can use as either ``with`` or
    ``async with``. Under ``MVM_NO_VM=1`` this is a local scope; otherwise
    entering it boots the workload's microVM and leaving it stops the VM (see
    the module docstring). ``idle_timeout_secs`` bounds how long the host
    keeps an idle session VM; the host's default applies when it is omitted.

    Raises :class:`mvm.EmittingContextError` if called while ``mvm emit`` is
    running (``MVM_EMITTING=1``).
    """
    _check_emitting_context("mv.session(...)")
    if not workload_id:
        raise ValueError("session(workload_id) requires a non-empty id")
    _check_id("workload_id", workload_id)
    if idle_timeout_secs is not None and (
        isinstance(idle_timeout_secs, bool)
        or not isinstance(idle_timeout_secs, int)
        or idle_timeout_secs <= 0
    ):
        raise ValueError("idle_timeout_secs must be a positive integer")
    if _no_vm():
        handle = Session(workload_id, f"local-{secrets.token_hex(8)}")
        if idle_timeout_secs is not None:
            handle._timeout = float(idle_timeout_secs)
        return handle
    return Session._on_host(workload_id, idle_timeout_secs)
