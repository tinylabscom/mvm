"""Warm-VM sessions for function-entrypoint workloads (plan-0010 W7).

A session holds a single VM warm across multiple ``await f(...)`` calls
so each call doesn't pay the cold-boot tax. The boundary is explicit in
the SDK so callers understand state persists across calls within a
session (per ADR-0009 / mvm M5).

Both async-first and sync usage patterns are supported::

    async with mv.session("adder") as sess:
        await add(2, 3)            # boots the VM, dispatches
        await add(4, 5)            # reuses the warm VM

    with mv.session("adder") as sess:
        add.sync(2, 3)
        add.sync(4, 5)

Outside a session, ``await f(...)`` shells out to ``mvmctl invoke``
without ``--session``; the substrate decides whether to spin up a
one-shot VM or fail fast.
"""

from __future__ import annotations

import asyncio
import contextvars
import os
import re
import shutil
import warnings
import weakref
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mvm._remote import RemoteFunction

_VALID_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


def _check_id(label: str, value: str) -> None:
    if not _VALID_ID.match(value):
        raise ValueError(
            f"{label} must match ^[a-z][a-z0-9-]{{0,62}}$ (got {value!r})"
        )

from mvm._subprocess import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_SESSION_START_TIMEOUT_SEC,
    DEFAULT_SESSION_STOP_TIMEOUT_SEC,
    TransportOutputOverflow,
    TransportTimeout,
    env_float,
    env_int,
    run_capped,
)

__all__ = ["Session", "session", "current_session_id"]


_active_session: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mvm_session", default=None
)


def current_session_id() -> str | None:
    """Return the session id active in the current context, or ``None``."""
    return _active_session.get()


def _locate_mvmctl() -> str:
    explicit = os.environ.get("MVM_MVM_BIN")
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
        raise RuntimeError(
            f"MVM_MVM_BIN points at {explicit!r} but it is not an executable file"
        )
    found = shutil.which("mvm") or shutil.which("mvmctl")
    if found is None:
        raise RuntimeError(
            "mvmctl not found via MVM_MVM_BIN or PATH; set MVM_MVM_BIN to the binary"
        )
    return found


def _start(workload_id: str) -> str:
    _check_id("workload_id", workload_id)
    bin_path = _locate_mvmctl()
    timeout = env_float(
        "MVM_SESSION_START_TIMEOUT_SEC", DEFAULT_SESSION_START_TIMEOUT_SEC
    )
    cap = env_int("MVM_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES)
    try:
        proc = run_capped(
            [bin_path, "session", "start", "--", workload_id],
            input_bytes=None,
            timeout=timeout,
            max_output_bytes=cap,
        )
    except TransportTimeout as exc:
        raise RuntimeError(
            f"mvmctl session start {workload_id} timed out after {timeout}s"
        ) from exc
    except TransportOutputOverflow as exc:
        raise RuntimeError(
            f"mvmctl session start {workload_id} exceeded {cap}-byte output cap"
        ) from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"mvmctl session start {workload_id} exited {proc.returncode}: "
            f"{stderr or '(no stderr)'}"
        )
    sid = proc.stdout.decode("utf-8", errors="replace").strip()
    if not sid:
        raise RuntimeError(
            f"mvmctl session start {workload_id} returned an empty session id"
        )
    return sid


def _verb(session_id: str, verb: str, *extra_args: str, timeout_env: str = "MVM_SESSION_STOP_TIMEOUT_SEC", default_timeout: float = DEFAULT_SESSION_STOP_TIMEOUT_SEC) -> bytes:
    """Dispatch ``mvmctl session <verb> <session_id> [extras...]`` synchronously.

    Returns stdout bytes on success; raises ``RuntimeError`` on failure or
    transport error. Used by ``stop|set-timeout|kill|info`` paths.
    """
    _check_id("session_id", session_id)
    bin_path = _locate_mvmctl()
    timeout = env_float(timeout_env, default_timeout)
    cap = env_int("MVM_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES)
    argv = [bin_path, "session", verb]
    argv += list(extra_args)
    argv += ["--", session_id]
    try:
        proc = run_capped(
            argv,
            input_bytes=None,
            timeout=timeout,
            max_output_bytes=cap,
        )
    except TransportTimeout as exc:
        raise RuntimeError(
            f"mvmctl session {verb} {session_id} timed out after {timeout}s"
        ) from exc
    except TransportOutputOverflow as exc:
        raise RuntimeError(
            f"mvmctl session {verb} {session_id} exceeded {cap}-byte output cap"
        ) from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"mvmctl session {verb} {session_id} exited {proc.returncode}: "
            f"{stderr or '(no stderr)'}"
        )
    return proc.stdout


def _stop(session_id: str) -> None:
    _verb(session_id, "stop")


def _best_effort_stop(session_id: str) -> None:
    """Best-effort teardown for abandonment finalizer; never raises."""
    try:
        _stop(session_id)
    except Exception:
        pass


class Session:
    """Typed handle for a warm-VM session.

    Use as a context manager — ``async with`` is the canonical form when
    you're already in async code; ``with`` works for synchronous callers
    that pair with :meth:`RemoteFunction.sync`. ``str(sess)`` returns the
    underlying session id so logs/breadcrumbs stay readable.

    Within the ``with`` body, ``await f(...)`` and ``f.sync(...)`` calls
    auto-attach to this session via context-vars.

    Cross-workload guard: :meth:`invoke` raises if the supplied
    ``RemoteFunction``'s ``workload_id`` doesn't match the session's.

    Abandonment: if a ``Session`` is dropped without ``with``/``async
    with`` lifecycle, a ``weakref.finalize`` fires a best-effort stop and
    emits a :class:`ResourceWarning`. The canonical pattern is the
    context-manager form.
    """

    __slots__ = ("_workload_id", "_id", "_token", "_active", "_finalizer", "__weakref__")

    def __init__(self, workload_id: str, session_id: str):
        self._workload_id = workload_id
        self._id = session_id
        self._token: contextvars.Token[str | None] | None = None
        self._active = True
        # Finalizer fires on GC if the user dropped the handle without
        # closing it. Best-effort stop + warning so leaked sessions
        # don't pile up against the substrate's session-pool budget.
        self._finalizer = weakref.finalize(
            self,
            _abandonment_finalizer,
            workload_id,
            session_id,
        )

    @property
    def id(self) -> str:
        """The substrate-issued session identifier."""
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
        self._teardown()

    # --- async context-manager (for use with await f(...)) --------------

    async def __aenter__(self) -> "Session":
        self._token = _active_session.set(self._id)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        # Reset the contextvar in the same task that set it (Token must
        # be reset in its originating Context — asyncio.to_thread runs in
        # a different Context). The synchronous stop can safely run in a
        # thread.
        self._reset_contextvar()
        await asyncio.to_thread(self._teardown)

    def _reset_contextvar(self) -> None:
        if self._token is not None:
            try:
                _active_session.reset(self._token)
            except ValueError:
                # Token reset from a foreign Context; ignore. The user's
                # code escaped the with-block via task switching.
                pass
            self._token = None

    def _teardown(self) -> None:
        if not self._active:
            return
        self._active = False
        # Detach the finalizer first so it doesn't double-fire.
        self._finalizer.detach()
        try:
            _stop(self._id)
        except RuntimeError:
            # Teardown errors must not mask a body exception. The
            # session-timeout reaper on the substrate side will reap
            # the VM regardless. Tests assert teardown was *invoked*,
            # not that it succeeded.
            pass

    # --- explicit lifecycle methods ------------------------------------

    async def invoke(self, fn: "RemoteFunction", /, *args: Any, **kwargs: Any) -> Any:
        """Dispatch ``fn`` against this session.

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
        """Update the substrate-side idle timeout for this session."""
        if seconds < 0:
            raise ValueError("set_timeout seconds must be non-negative")
        await asyncio.to_thread(_verb, self._id, "set-timeout", str(seconds))

    async def kill(self) -> None:
        """Terminate the session immediately. Inflight invokes resolve as failures."""
        await asyncio.to_thread(_verb, self._id, "kill")
        self._active = False

    async def info(self) -> dict[str, Any]:
        """Return substrate-reported metadata for the session."""
        import json

        out = await asyncio.to_thread(_verb, self._id, "info")
        text = out.decode("utf-8", errors="replace").strip()
        if not text:
            return {}
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"mvmctl session info {self._id} returned non-JSON: {text!r}"
            ) from exc
        if not isinstance(value, dict):
            raise RuntimeError(
                f"mvmctl session info {self._id} returned non-object: {value!r}"
            )
        return value


def _abandonment_finalizer(workload_id: str, session_id: str) -> None:
    warnings.warn(
        f"Session(workload_id={workload_id!r}, id={session_id!r}) was not "
        "closed via with/async-with; firing best-effort cleanup. Use "
        "`async with mv.session(...)` (or `with mv.session(...)`) to bound "
        "the session lifetime explicitly.",
        ResourceWarning,
        stacklevel=2,
    )
    _best_effort_stop(session_id)


def session(workload_id: str) -> Session:
    """Open a warm-VM session bound to ``workload_id``.

    Returns a :class:`Session` you can use as either ``with`` or
    ``async with``. Within the body, ``await f(...)`` and ``f.sync(...)``
    auto-attach to this session via context-vars.

    Raises :class:`mvm.EmittingContextError` if called inside an
    ``mvm emit`` subprocess (``MVM_EMITTING=1``). Layer-3
    calls are dev-only by design (ADR-0010).
    """
    # ADR-0010 §2 Layer-3 guard. Imported here to avoid a circular
    # import between _session and _remote at module-load time.
    from mvm._remote import _check_emitting_context

    _check_emitting_context("mv.session(...)")
    if not workload_id:
        raise ValueError("session(workload_id) requires a non-empty id")
    sid = _start(workload_id)
    return Session(workload_id, sid)
