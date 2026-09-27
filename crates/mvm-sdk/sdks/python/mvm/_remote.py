"""Host-side call surface for function-entrypoint workloads.

A ``@mvm.func(...)`` decoration returns a :class:`RemoteFunction` whose
``__call__`` *is* the dispatch — calling the function is calling the
workload. The local body (for tests) lives on ``f.local``; a synchronous
escape hatch lives on ``f.sync``.

::

    @mv.func(name="adder", image=..., resources=...)
    async def add(a: int, b: int) -> int:
        return a + b

    await add(2, 3)        # dispatches through the workload's wire format
    add.local(2, 3)        # plain in-process call (for unit tests)
    add.sync(2, 3)         # synchronous escape hatch

Where a call runs:

- ``MVM_NO_VM=1``: in this process. The arguments are encoded as
  ``[args, kwargs]`` in the workload's declared format (JSON or msgpack),
  size-checked against ``MVM_MAX_PAYLOAD_BYTES``, decoded back, and handed
  to the wrapped function; its result is encoded, size-checked against
  ``MVM_MAX_OUTPUT_BYTES``, and decoded with the same hardening the host
  applies to a result from a microVM (nesting depth, non-finite floats,
  duplicate keys). What survives the round trip is what the function would
  receive and return inside a microVM, so a value that would not cross the
  wire fails here too. An exception the function raises propagates as
  itself.
- Otherwise: the SDK loads the host library in-process and never starts a
  process of its own, and the library has no function-dispatch surface yet,
  so the call raises :class:`MvmTransportError` saying so. Every check that
  does not need a microVM still runs first, so an oversized payload or a
  secret-shaped argument is reported the same way in both modes.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import os
import re
import threading
import warnings
from typing import Any, Awaitable, Callable

# The error taxonomy is owned by the Rust registry
# (crates/mvm-sdk/src/error_taxonomy.rs) and generated into
# `_errors/types.py`. Re-exported here for existing importers.
from mvm._errors.types import (  # noqa: F401
    EmittingContextError,
    MsgpackUnavailable,
    MvmTransportError,
    NoVmIntrospectionError,
    PayloadTooLarge,
    RemoteError,
    SecretInArgError,
    SecretInArgWarning,
)

# Mirror of the IR-side `is_valid_id` rule. Defense-in-depth: even if a
# caller bypassed the host validator (constructed IR by hand, etc.), the
# dispatch layer refuses a malformed id.
_VALID_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


def _check_id(label: str, value: str) -> None:
    if not _VALID_ID.match(value):
        raise ValueError(
            f"{label} must match ^[a-z][a-z0-9-]{{0,62}}$ (got {value!r})"
        )


# Heuristic for secret-shaped kwarg names. Conservative: matches when the
# whole kwarg name (or its trailing suffix after a `_`) looks secrety. We
# don't scan values — that would false-positive everywhere a string is
# passed.
_SECRET_KWARG_PATTERN = re.compile(
    r"(?ix) (?:^|_) (token|password|passwd|secret|api_?key|apitoken|credential|bearer|private_?key|auth_?token) $"
)


def _check_secret_args(kwargs: dict[str, Any]) -> None:
    if not kwargs:
        return
    flagged = [k for k in kwargs if _SECRET_KWARG_PATTERN.search(k)]
    if not flagged:
        return
    detail = (
        f"kwarg name(s) {flagged!r} look like secrets; secrets should flow via "
        "/run/mvm-secrets/<svc>/ (ADR-0009), not function args. "
        "Suppress with MVM_STRICT_SECRETS=0 or rename the kwarg."
    )
    if os.environ.get("MVM_STRICT_SECRETS") == "1":
        raise SecretInArgError(detail)
    warnings.warn(detail, SecretInArgWarning, stacklevel=3)


# Mirrors the guest runner's `MAX_NESTING_DEPTH`. The runner enforces it on
# what it receives; the host enforces it on what it decodes, so neither side
# trusts the other to have done it.
MAX_RESULT_NESTING_DEPTH = 64

__all__ = [
    "RemoteFunction",
    "RemoteError",
    "MvmTransportError",
    "MsgpackUnavailable",
    "PayloadTooLarge",
    "SecretInArgWarning",
    "SecretInArgError",
    "EmittingContextError",
    "NoVmIntrospectionError",
    "WorkloadRef",
]


DEFAULT_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024


# ADR-0010 §2: structural enforcement that the runtime SDK's Layer-3
# execution surface (.remote(), session(), Session.exec_*) is
# unreachable during `mvm emit`. The host sets MVM_EMITTING=1
# when invoking the SDK to emit IR; the guard catches build-time
# recursion where an entry module tries to call into a VM that doesn't
# exist yet because the artifact for it is still being built.
EMITTING_ENV_VAR = "MVM_EMITTING"

# Setting MVM_NO_VM=1 runs a RemoteFunction call in this process, through the
# same encode and decode path a microVM call takes. Only a RemoteFunction has
# a local body to run; a WorkloadRef names another workload's function, which
# this process does not have.
NO_VM_ENV_VAR = "MVM_NO_VM"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _check_emitting_context(call_site: str) -> None:
    if os.environ.get(EMITTING_ENV_VAR) == "1":
        raise EmittingContextError(
            f"{call_site} is unreachable during `mvm emit` "
            f"({EMITTING_ENV_VAR}=1 is set). Layer-3 calls require a "
            "live microVM and only run in dev iteration; production "
            "should not import the runtime SDK's transport surface "
            "(see ADR-0010)."
        )


def _no_vm() -> bool:
    return os.environ.get(NO_VM_ENV_VAR) == "1"


def _dispatch_unavailable(call_site: str) -> MvmTransportError:
    """The refusal for a call that would need a microVM.

    Spelled out in one place because sessions raise it too, and the two
    should never disagree about what to do instead."""
    return MvmTransportError(
        f"{call_site}: dispatching a function-entrypoint call into a microVM from "
        "a host process is not available through the in-process host library yet. "
        f"Set {NO_VM_ENV_VAR}=1 to run the function locally through the same "
        "encode/decode path, or call `.local(...)` for a plain in-process call."
    )


def _encode_value(format: str, value: Any) -> bytes:
    if format == "json":
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if format == "msgpack":
        try:
            import msgpack
        except ImportError as exc:
            raise MsgpackUnavailable(
                "workload declared format='msgpack' but the msgpack package is not installed"
            ) from exc
        return msgpack.packb(value, use_bin_type=True)
    raise ValueError(f"unknown serialization format: {format!r}")


def _encode(format: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> bytes:
    return _encode_value(format, [list(args), dict(kwargs)])


def _check_depth(value: Any, what: str, current: int = 0) -> None:
    if current > MAX_RESULT_NESTING_DEPTH:
        raise MvmTransportError(
            f"decoded {what} exceeds max nesting depth {MAX_RESULT_NESTING_DEPTH}"
        )
    if isinstance(value, dict):
        for v in value.values():
            _check_depth(v, what, current + 1)
    elif isinstance(value, list):
        for v in value:
            _check_depth(v, what, current + 1)


def _check_no_nonfinite(value: Any, what: str) -> None:
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise MvmTransportError(f"decoded {what} contains non-finite float")
    elif isinstance(value, dict):
        for v in value.values():
            _check_no_nonfinite(v, what)
    elif isinstance(value, list):
        for v in value:
            _check_no_nonfinite(v, what)


def _decode(format: str, data: bytes, what: str = "result") -> Any:
    if not data:
        return None
    if format == "json":
        # object_pairs_hook rejects duplicate keys; parse_constant rejects
        # non-finite JSON literals (NaN, Infinity, -Infinity) up front.
        def reject_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for k, v in pairs:
                if k in out:
                    raise MvmTransportError(f"duplicate key in decoded JSON: {k!r}")
                out[k] = v
            return out

        def reject_const(c: str) -> Any:
            raise MvmTransportError(f"non-finite JSON constant in {what}: {c}")

        try:
            value = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=reject_dupes,
                parse_constant=reject_const,
            )
        except json.JSONDecodeError as exc:
            raise MvmTransportError(f"failed to decode JSON {what}: {exc}") from exc
    elif format == "msgpack":
        try:
            import msgpack
        except ImportError as exc:
            raise MsgpackUnavailable(
                "workload declared format='msgpack' but the msgpack package is not installed"
            ) from exc
        try:
            value = msgpack.unpackb(data, raw=False, strict_map_key=True)
        except Exception as exc:
            raise MvmTransportError(f"failed to decode msgpack {what}: {exc}") from exc
    else:
        raise ValueError(f"unknown serialization format: {format!r}")
    _check_depth(value, what)
    _check_no_nonfinite(value, what)
    return value


def _prepare(
    call_site: str,
    workload_id: str,
    format: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> bytes:
    """Run the checks every dispatch shares and return the encoded payload.

    These run whether or not the call can go anywhere, so a caller learns
    about an oversized or secret-bearing call from the check that exists for
    it rather than from the transport refusal."""
    _check_emitting_context(call_site)
    _check_id("workload_id", workload_id)
    _check_secret_args(kwargs)
    payload = _encode(format, args, kwargs)
    payload_cap = _env_int("MVM_MAX_PAYLOAD_BYTES", DEFAULT_MAX_PAYLOAD_BYTES)
    if len(payload) > payload_cap:
        raise PayloadTooLarge(
            f"encoded payload for {workload_id} is {len(payload)} bytes, "
            f"exceeding MVM_MAX_PAYLOAD_BYTES={payload_cap}. "
            "Hint: pass large blobs via a mounted volume rather than function args."
        )
    return payload


def _local_target(call_site: str, fn: Callable[..., Any] | None) -> Callable[..., Any]:
    if not _no_vm():
        raise _dispatch_unavailable(call_site)
    if fn is None:
        raise NoVmIntrospectionError(
            f"{NO_VM_ENV_VAR}=1 is set but {call_site} has no local function to "
            "run: it names another workload's function, which only that "
            "workload's microVM has."
        )
    return fn


def _decode_call(format: str, payload: bytes) -> tuple[list[Any], dict[str, Any]]:
    """Decode ``[args, kwargs]`` the way the guest runner would receive it."""
    decoded = _decode(format, payload, "arguments")
    if (
        not isinstance(decoded, list)
        or len(decoded) != 2
        or not isinstance(decoded[0], list)
        or not isinstance(decoded[1], dict)
    ):
        raise MvmTransportError("encoded call payload is not an [args, kwargs] pair")
    return decoded[0], decoded[1]


def _round_trip_result(workload_id: str, format: str, result: Any) -> Any:
    try:
        encoded = _encode_value(format, result)
    except (TypeError, ValueError, OverflowError) as exc:
        raise MvmTransportError(
            f"the result of {workload_id} cannot be encoded as {format}: {exc}"
        ) from exc
    cap = _env_int("MVM_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES)
    if len(encoded) > cap:
        raise MvmTransportError(f"the result of {workload_id} exceeded the {cap}-byte output cap")
    return _decode(format, encoded)


async def _await(awaitable: Awaitable[Any]) -> Any:
    return await awaitable


def _run_to_completion(awaitable: Awaitable[Any]) -> Any:
    """Drive an awaitable from synchronous code.

    ``f.sync(...)`` on an ``async def`` body still has to produce a value.
    With no loop running on this thread a private one does it. With a loop
    already running (``f.sync`` called from inside async code) that loop
    cannot be re-entered, so the body runs on its own loop in a worker thread
    while this thread waits, which is what blocking in async code means."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_await(awaitable))
    outcome: dict[str, Any] = {}

    def runner() -> None:
        try:
            outcome["value"] = asyncio.run(_await(awaitable))
        except BaseException as exc:  # re-raised on the calling thread below
            outcome["error"] = exc

    worker = threading.Thread(target=runner, name="mvm-sync-dispatch")
    worker.start()
    worker.join()
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def _invoke_sync(
    workload_id: str,
    format: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    call_site: str = "RemoteFunction.sync(...)",
    fn: Callable[..., Any] | None = None,
) -> Any:
    payload = _prepare(call_site, workload_id, format, args, kwargs)
    target = _local_target(call_site, fn)
    call_args, call_kwargs = _decode_call(format, payload)
    result = target(*call_args, **call_kwargs)
    if inspect.isawaitable(result):
        result = _run_to_completion(result)
    return _round_trip_result(workload_id, format, result)


async def _invoke_async(
    workload_id: str,
    format: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    call_site: str = "RemoteFunction.__call__(...)",
    fn: Callable[..., Any] | None = None,
) -> Any:
    payload = _prepare(call_site, workload_id, format, args, kwargs)
    target = _local_target(call_site, fn)
    call_args, call_kwargs = _decode_call(format, payload)
    result = target(*call_args, **call_kwargs)
    if inspect.isawaitable(result):
        result = await result
    return _round_trip_result(workload_id, format, result)


class RemoteFunction:
    """Wraps a decorated function with the host-side call surface.

    ``await f(2, 3)`` is the canonical form — it dispatches the call through
    the workload's declared wire format. Calling the function *is* the
    dispatch. Variants:

    - ``f.local(2, 3)`` — plain in-process call against the wrapped
      Python body, with no encoding. Useful for unit tests.
    - ``f.sync(2, 3)`` — synchronous escape hatch that does the same
      dispatch as ``__call__`` but blocks instead of returning a
      coroutine. Convenient at REPL prompts and in non-async code.

    See the module docstring for where a dispatched call runs today.
    """

    def __init__(
        self,
        fn: Callable[..., Any],
        *,
        workload_id: str,
        format: str,
    ):
        if format not in ("json", "msgpack"):
            raise ValueError(f"format must be 'json' or 'msgpack', got {format!r}")
        self._fn = fn
        self._workload_id = workload_id
        self._format = format
        functools.update_wrapper(self, fn)

    @property
    def workload_id(self) -> str:
        return self._workload_id

    @property
    def format(self) -> str:
        return self._format

    @property
    def local(self) -> Callable[..., Any]:
        """The undecorated local function, for explicit in-process dispatch."""
        return self._fn

    def __call__(self, *args: Any, **kwargs: Any) -> Awaitable[Any]:
        return _invoke_async(
            self._workload_id, self._format, args, kwargs, fn=self._fn
        )

    def sync(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronous dispatch. Same path as ``await f(...)``."""
        return _invoke_sync(
            self._workload_id, self._format, args, kwargs, fn=self._fn
        )


class _BoundRemoteCall:
    """Callable returned by ``WorkloadRef.<attribute>``.

    Bound to a (workload_id, function_name) pair and dispatched through the
    same checks as :class:`RemoteFunction`. JSON by default, since the caller
    cannot introspect the callee's declared format; pass ``format="msgpack"``
    to :func:`workload_ref` if you know the callee uses msgpack.

    A cross-workload call always needs the callee's microVM, so it raises
    :class:`MvmTransportError` after those checks until the host library can
    dispatch one.
    """

    __slots__ = ("_workload_id", "_function", "_format")

    def __init__(self, workload_id: str, function: str, format: str):
        self._workload_id = workload_id
        self._function = function
        self._format = format

    def __call__(self, *args: Any, **kwargs: Any) -> Awaitable[Any]:
        return _invoke_async(
            self._workload_id,
            self._format,
            args,
            kwargs,
            call_site=f"WorkloadRef({self._workload_id!r}).{self._function}(...)",
        )

    def sync(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronous cross-workload dispatch. Mirrors
        :meth:`RemoteFunction.sync`."""
        return _invoke_sync(
            self._workload_id,
            self._format,
            args,
            kwargs,
            call_site=f"WorkloadRef({self._workload_id!r}).{self._function}.sync(...)",
        )

    def __repr__(self) -> str:
        return (
            f"<bound remote call {self._workload_id}.{self._function} "
            f"format={self._format!r}>"
        )


class WorkloadRef:
    """A typed handle for declaring + calling another workload (ADR-0014).

    Construct via :func:`workload_ref`. The returned object validates
    the workload id at construction time, exposes ``id`` for use in
    ``depends_on=[...]`` declarations, and dispatches cross-workload
    calls via attribute access::

        math = mv.workload_ref("math-svc")

        @mv.func(name="caller", depends_on=[math])
        async def add_then_double(a: int, b: int) -> int:
            s = await math.add(a, b)
            return s * 2

    The proxy reuses the same dispatch checks as :class:`RemoteFunction`
    (encode → payload-cap check → secret-args heuristic), so a mistake is
    reported the same way on both surfaces.

    Cross-workload dispatch is JSON by default. Pass ``format="msgpack"``
    to :func:`workload_ref` when calling a callee whose declared format
    is msgpack.
    """

    __slots__ = ("_id", "_format")

    def __init__(self, workload_id: str, format: str = "json"):
        _check_id("workload_ref id", workload_id)
        if format not in ("json", "msgpack"):
            raise ValueError(
                f"workload_ref format must be 'json' or 'msgpack', got {format!r}"
            )
        self._id = workload_id
        self._format = format

    @property
    def id(self) -> str:
        """The referenced workload's id. Used by ``depends_on=[...]``."""
        return self._id

    @property
    def format(self) -> str:
        return self._format

    def __getattr__(self, name: str) -> _BoundRemoteCall:
        # Dunder + private-prefixed attribute lookups must not be
        # intercepted as remote calls — `__class__`, `__repr__`, and
        # similar introspection paths must keep working. Without this
        # guard, even `repr(ref)` would spuriously construct a bound
        # call for `__repr__`.
        if name.startswith("_"):
            raise AttributeError(name)
        return _BoundRemoteCall(self._id, name, self._format)

    def __repr__(self) -> str:
        return f"WorkloadRef({self._id!r}, format={self._format!r})"


def workload_ref(workload_id: str, *, format: str = "json") -> WorkloadRef:
    """Return a :class:`WorkloadRef` for the workload at ``workload_id``.

    Validate-on-construction wrapper that gives you a typed handle for
    cross-workload calls and for declaring `depends_on=[...]`. See
    :class:`WorkloadRef` for usage.
    """
    return WorkloadRef(workload_id, format=format)
