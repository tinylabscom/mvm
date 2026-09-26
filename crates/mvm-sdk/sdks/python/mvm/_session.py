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

What a session is today follows from where calls run (see ``mvm._remote``).
Under ``MVM_NO_VM=1`` calls run in this process, so a session is a local
scope: it has an id of the form ``local-<hex>``, :func:`current_session_id`
reports it inside the body, and there is no VM behind it to keep warm or to
stop. Without ``MVM_NO_VM=1``, opening a session raises
:class:`MvmTransportError`, for the same reason a call does: the host
library has no session surface yet, and the SDK never starts a process to
stand in for one.

Because a session is only ever local, every method on :class:`Session` acts
locally — ``set_timeout`` records the value, ``kill`` ends the scope, and
``info`` reports what the SDK knows. None of them reach a host.
"""

from __future__ import annotations

import contextvars
import secrets
from typing import TYPE_CHECKING, Any

from mvm._remote import (
    _check_emitting_context,
    _check_id,
    _dispatch_unavailable,
    _no_vm,
)

if TYPE_CHECKING:
    from mvm._remote import RemoteFunction

__all__ = ["Session", "session", "current_session_id"]


_active_session: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mvm_session", default=None
)


def current_session_id() -> str | None:
    """Return the session id active in the current context, or ``None``."""
    return _active_session.get()


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

    __slots__ = ("_workload_id", "_id", "_token", "_active", "_timeout")

    def __init__(self, workload_id: str, session_id: str):
        _check_id("session_id", session_id)
        self._workload_id = workload_id
        self._id = session_id
        self._token: contextvars.Token[str | None] | None = None
        self._active = True
        self._timeout: float | None = None

    @property
    def id(self) -> str:
        """The session identifier."""
        return self._id

    @property
    def workload_id(self) -> str:
        """The workload this session is bound to."""
        return self._workload_id

    def __str__(self) -> str:
        return self._id

    def __repr__(self) -> str:
        return f"Session(workload_id={self._workload_id!r}, id={self._id!r})"

    # --- sync context-manager (for use with f.sync(...)) ----------------

    def __enter__(self) -> "Session":
        self._token = _active_session.set(self._id)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._reset_contextvar()
        self._active = False

    # --- async context-manager (for use with await f(...)) --------------

    async def __aenter__(self) -> "Session":
        self._token = _active_session.set(self._id)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._reset_contextvar()
        self._active = False

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
        prev = _active_session.set(self._id)
        try:
            return await fn(*args, **kwargs)
        finally:
            _active_session.reset(prev)

    async def set_timeout(self, seconds: float) -> None:
        """Record an idle timeout for this session.

        Kept locally and reported by :meth:`info`; a local session has no VM
        for an idle timeout to reap."""
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds < 0:
            raise ValueError("set_timeout seconds must be a non-negative number")
        self._timeout = float(seconds)

    async def kill(self) -> None:
        """End the session. Later :meth:`info` calls report it inactive."""
        self._active = False

    async def info(self) -> dict[str, Any]:
        """What the SDK knows about this session. ``local`` is always true
        today: no session is backed by a VM yet."""
        return {
            "id": self._id,
            "workload_id": self._workload_id,
            "active": self._active,
            "idle_timeout_secs": self._timeout,
            "local": True,
        }


def session(workload_id: str) -> Session:
    """Open a session bound to ``workload_id``.

    Returns a :class:`Session` you can use as either ``with`` or
    ``async with``. Under ``MVM_NO_VM=1`` this is a local scope; otherwise it
    raises :class:`MvmTransportError` (see the module docstring).

    Raises :class:`mvm.EmittingContextError` if called while ``mvm emit`` is
    running (``MVM_EMITTING=1``). Layer-3 calls are dev-only by design
    (ADR-0010).
    """
    _check_emitting_context("mv.session(...)")
    if not workload_id:
        raise ValueError("session(workload_id) requires a non-empty id")
    _check_id("workload_id", workload_id)
    if not _no_vm():
        raise _dispatch_unavailable(f"mv.session({workload_id!r})")
    return Session(workload_id, f"local-{secrets.token_hex(8)}")
