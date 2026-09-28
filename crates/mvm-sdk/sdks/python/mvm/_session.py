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
import re
import secrets
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

# What the host mints as a session id: base32, lower case.
_HOST_SESSION_ID = re.compile(r"^[a-z2-7]{16,64}$")

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

    def _start(self) -> None:
        if not self._host_backed or self._id is not None:
            return
        request: dict[str, Any] = {"workload": self._workload_id}
        if self._timeout is not None:
            request["idle_timeout_secs"] = int(self._timeout)
        reply = _hostlib.call(SESSION_START, request)
        session_id = reply.get("session_id") if isinstance(reply, dict) else None
        if not isinstance(session_id, str) or not _HOST_SESSION_ID.match(session_id):
            raise MvmTransportError(f"session.start returned no usable session id: {reply!r}")
        self._id = session_id
        self._vm_name = reply.get("vm_name")
        self._active = True

    def _stop(self) -> None:
        if self._host_backed and self._active and self._id is not None:
            self._active = False
            _hostlib.call(SESSION_STOP, {"session_id": self._id})
        self._active = False

    # --- sync context-manager (for use with f.sync(...)) ----------------

    def __enter__(self) -> "Session":
        self._start()
        self._token = _active_session.set(self)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._reset_contextvar()
        # A failure to stop never masks the body's own exception.
        try:
            self._stop()
        except Exception:
            if exc_type is None:
                raise

    # --- async context-manager (for use with await f(...)) --------------

    async def __aenter__(self) -> "Session":
        await asyncio.to_thread(self._start)
        self._token = _active_session.set(self)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._reset_contextvar()
        try:
            await asyncio.to_thread(self._stop)
        except Exception:
            if exc_type is None:
                raise

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
