"""Host-side call surface for function-entrypoint workloads (plan-0003 + plan-0010 W5/W6).

A ``@mvm.func(...)`` decoration returns a :class:`RemoteFunction` whose
``__call__`` *is* the remote dispatch — calling the function is calling
the VM. The local body (for tests) lives on ``f.local``; a synchronous
escape hatch lives on ``f.sync``.

::

    @mv.func(name="adder", image=..., resources=...)
    async def add(a: int, b: int) -> int:
        return a + b

    await add(2, 3)        # dispatches to VM
    add.local(2, 3)        # in-process call (for unit tests)
    add.sync(2, 3)         # synchronous escape hatch

Transport contract (matches mvm plan-41 / ADR-0009):

- stdin to ``mvmctl invoke``: encoded ``[args, kwargs]`` per the workload's
  declared format. JSON is UTF-8 bytes; msgpack is the wire-level binary.
- stdout from ``mvmctl invoke``: encoded return value in the same format.
- Non-zero exit + structured stderr envelope (``{kind, error_id, message}``)
  on user-code failure inside the VM. The SDK parses the envelope and
  raises :class:`RemoteError`. A non-envelope failure raises
  :class:`MvmTransportError`.

Cancellation contract (W6): an :class:`asyncio.CancelledError` propagated
into ``await f(...)`` (e.g. via :func:`asyncio.wait_for`) terminates the
underlying ``mvmctl`` subprocess: SIGTERM, then SIGKILL after a grace
period (env: ``MVM_INVOKE_KILL_GRACE_SEC``, default 5s).

Input cap (W6): payload size is checked **after** encode and **before**
subprocess spawn. The cap is ``MVM_MAX_PAYLOAD_BYTES`` (default
16 MiB); exceeding raises :class:`PayloadTooLarge`.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import os
import re
import shutil
import signal
import warnings
from typing import Any, Awaitable, Callable

# Mirror of the IR-side `is_valid_id` rule. Defense-in-depth: even if a
# caller bypassed the host validator (constructed IR by hand, etc.), the
# transport layer refuses to spawn mvmctl with a malformed id.
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

from mvm._session import current_session_id
from mvm._subprocess import (
    DEFAULT_INVOKE_TIMEOUT_SEC,
    DEFAULT_MAX_OUTPUT_BYTES,
    TransportOutputOverflow,
    TransportTimeout,
    env_float,
    env_int,
    run_capped,
)

# Mirrors `nix/wrappers/python-runner.py::MAX_NESTING_DEPTH`. The wrapper
# enforces this on inbound; we enforce on the host's outbound-decode path
# as defense-in-depth in case the substrate is compromised or buggy.
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
DEFAULT_KILL_GRACE_SEC = 5.0


# ADR-0010 §2: structural enforcement that the runtime SDK's Layer-3
# execution surface (.remote(), session(), Session.exec_*) is
# unreachable during `mvm emit`. The host sets MVM_EMITTING=1
# when invoking the SDK as the emit subprocess; the guard catches
# build-time recursion where an entry module tries to call into a VM
# that doesn't exist yet because the artifact for it is still being
# built.
EMITTING_ENV_VAR = "MVM_EMITTING"

# Setting MVM_NO_VM=1 routes dispatch through mvmctl's hidden SDK
# host-wrapper transport, which runs the wrapper directly on the host
# (no VM boot, no vsock). Per-call module/function/source-path are
# derived from the wrapped Python function via `inspect`. Only valid
# for :class:`RemoteFunction` (cross-workload :class:`WorkloadRef`
# calls have no local fn to introspect).
NO_VM_ENV_VAR = "MVM_NO_VM"


class EmittingContextError(RuntimeError):
    """Raised when a Layer-3 SDK call fires inside an `mvm emit`
    subprocess. ADR-0010 prohibits host-side runtime interaction with
    the VM during build/emit; a misconfigured entry module that calls
    `.remote(...)` at import time will trigger this. Production code
    must not import the runtime SDK's transport surface at all; this
    guard is a build-time backstop, not a production-mode gate."""


def _check_emitting_context(call_site: str) -> None:
    if os.environ.get(EMITTING_ENV_VAR) == "1":
        raise EmittingContextError(
            f"{call_site} is unreachable during `mvm emit` "
            f"({EMITTING_ENV_VAR}=1 is set). Layer-3 calls require a "
            "live microVM and only run in dev iteration; production "
            "should not import the runtime SDK's transport surface "
            "(see ADR-0010)."
        )


class SecretInArgWarning(UserWarning):
    """Heuristic flagged a secret-shaped value passed to ``f.remote(...)``.

    Function args flow through ``mvmctl invoke`` argv → VM stdin →
    application memory. Secrets should use the secrets subsystem
    (``/run/mvm-secrets/<svc>/`` per ADR-0009), not be passed as
    ordinary args. This warning is the heuristic catch; a future
    schema-bound check (plan-0009) will replace it with a hard
    validation gate at the IR level.
    """


class SecretInArgError(RuntimeError):
    """Strict-mode counterpart to :class:`SecretInArgWarning`.

    Raised instead of warning when ``MVM_STRICT_SECRETS=1``.
    """


class RemoteError(Exception):
    """User code inside the VM raised; structured envelope was parsed."""

    def __init__(self, *, kind: str, error_id: str, message: str):
        super().__init__(f"{kind}: {message} (error_id={error_id})")
        self.kind = kind
        self.error_id = error_id
        self.message = message


class MvmTransportError(RuntimeError):
    """Couldn't reach the substrate or got an unparseable response."""


class MsgpackUnavailable(RuntimeError):
    """The workload declared msgpack but the SDK has no msgpack dependency.

    Install ``msgpack`` (``pip install msgpack``) to use this format. JSON
    requires no extra dependency.
    """


class PayloadTooLarge(MvmTransportError):
    """Encoded request payload exceeded ``MVM_MAX_PAYLOAD_BYTES`` (W6).

    Raised before the subprocess spawns — no orphan ``mvmctl`` process,
    no partial pipe write. Default cap is 16 MiB; override via env. Hint:
    if your function genuinely needs to receive a large blob, prefer a
    mounted volume or the secrets subsystem over the args channel.
    """


class NoVmIntrospectionError(MvmTransportError):
    """``MVM_NO_VM=1`` was set but the call has no in-process Python
    function to introspect (e.g. cross-workload :class:`WorkloadRef`
    dispatch). Cross-workload calls require a real VM."""


def _no_vm_flags_for(fn: Callable[..., Any], format: str) -> list[str]:
    """Derive the per-call host-wrapper argv flags from the wrapped fn.

    The Rust side wants `--language` / `--module` / `--function` /
    `--format` / `--source-path` and uses these to write a temp
    `wrapper.json` + spawn the embedded oneshot wrapper. Module and
    function come from the function object itself; the source path is
    the directory of the file `fn` is defined in.

    A function defined in `__main__` (script-style execution, REPL)
    has no stable module name the wrapper can import — raise the same
    determinism error the emit path would.
    """
    module = getattr(fn, "__module__", None)
    function_name = getattr(fn, "__name__", None)
    if not isinstance(module, str) or not module or module == "__main__":
        raise NoVmIntrospectionError(
            f"MVM_NO_VM=1 cannot dispatch a function whose __module__ "
            f"is {module!r}. Define the function in an importable "
            "module so the wrapper can locate it."
        )
    if not isinstance(function_name, str) or not function_name:
        raise NoVmIntrospectionError(
            "MVM_NO_VM=1 cannot dispatch a function with no __name__"
        )
    try:
        source_file = inspect.getfile(fn)
    except (TypeError, OSError) as exc:
        raise NoVmIntrospectionError(
            f"MVM_NO_VM=1 could not locate the source file for "
            f"{module}.{function_name}: {exc}"
        ) from exc
    source_path = os.path.dirname(os.path.abspath(source_file))
    return [
        "--language", "python",
        "--module", module,
        "--function", function_name,
        "--format", format,
        "--source-path", source_path,
    ]


def _locate_mvmctl() -> str:
    explicit = os.environ.get("MVM_MVM_BIN")
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
        raise MvmTransportError(
            f"MVM_MVM_BIN points at {explicit!r} but it is not an executable file"
        )
    found = shutil.which("mvm") or shutil.which("mvmctl")
    if found is None:
        raise MvmTransportError(
            "mvmctl not found via MVM_MVM_BIN or PATH; set MVM_MVM_BIN to the binary"
        )
    return found


def _encode(format: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> bytes:
    payload = [list(args), dict(kwargs)]
    if format == "json":
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if format == "msgpack":
        try:
            import msgpack
        except ImportError as exc:
            raise MsgpackUnavailable(
                "workload declared format='msgpack' but the msgpack package is not installed"
            ) from exc
        return msgpack.packb(payload, use_bin_type=True)
    raise ValueError(f"unknown serialization format: {format!r}")


def _check_depth(value: Any, current: int = 0) -> None:
    if current > MAX_RESULT_NESTING_DEPTH:
        raise MvmTransportError(
            f"decoded result exceeds max nesting depth {MAX_RESULT_NESTING_DEPTH}"
        )
    if isinstance(value, dict):
        for v in value.values():
            _check_depth(v, current + 1)
    elif isinstance(value, list):
        for v in value:
            _check_depth(v, current + 1)


def _check_no_nonfinite(value: Any) -> None:
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise MvmTransportError("decoded result contains non-finite float")
    elif isinstance(value, dict):
        for v in value.values():
            _check_no_nonfinite(v)
    elif isinstance(value, list):
        for v in value:
            _check_no_nonfinite(v)


def _decode(format: str, data: bytes) -> Any:
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
            raise MvmTransportError(f"non-finite JSON constant in result: {c}")

        try:
            value = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=reject_dupes,
                parse_constant=reject_const,
            )
        except json.JSONDecodeError as exc:
            raise MvmTransportError(f"failed to decode JSON result: {exc}") from exc
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
            raise MvmTransportError(f"failed to decode msgpack result: {exc}") from exc
    else:
        raise ValueError(f"unknown serialization format: {format!r}")
    _check_depth(value)
    _check_no_nonfinite(value)
    return value


_ENVELOPE_MARKER = "MVM_ENVELOPE: "


def _parse_error_envelope(stderr: bytes) -> RemoteError | None:
    """Find a structured envelope in the wrapper's stderr.

    Primary path: scan for a line starting with ``MVM_ENVELOPE: `` and
    parse the JSON suffix. Fallback (for one release of compat with the
    pre-marker wrapper): treat the last non-empty line as the envelope if
    it parses as the right-shaped JSON object.
    """
    text = stderr.decode("utf-8", errors="replace")
    for line in text.splitlines():
        idx = line.find(_ENVELOPE_MARKER)
        if idx < 0:
            continue
        body = line[idx + len(_ENVELOPE_MARKER) :].strip()
        env = _decode_envelope(body)
        if env is not None:
            return env
    # Fallback: last non-empty stripped line shaped like a JSON object.
    stripped = text.strip()
    if not stripped:
        return None
    last_line = stripped.splitlines()[-1].strip()
    if last_line.startswith("{") and last_line.endswith("}"):
        return _decode_envelope(last_line)
    return None


def _decode_envelope(body: str) -> RemoteError | None:
    try:
        env = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(env, dict):
        return None
    kind = env.get("kind")
    error_id = env.get("error_id")
    message = env.get("message")
    if not (isinstance(kind, str) and isinstance(error_id, str) and isinstance(message, str)):
        return None
    return RemoteError(kind=kind, error_id=error_id, message=message)


def _prepare_invoke(
    call_site: str,
    workload_id: str,
    format: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    fn_selector: str | None = None,
    use_active_session: bool = True,
    fn: Callable[..., Any] | None = None,
) -> tuple[list[str], bytes, float, int, str]:
    """Run pre-spawn checks shared by sync and async dispatch paths.

    Returns ``(argv, payload, timeout_sec, output_cap_bytes, command_label)``.
    Raises before any subprocess spawn, leaving no orphan process behind.

    ``fn_selector``: when set, append ``--fn <name>`` to the argv. The
    ``WorkloadRef`` proxy passes the attribute the user wrote so the
    callee's wrapper can dispatch by function name (relevant once
    ADR-0014 Phase 2 multi-function apps land; single-function callees
    ignore the selector).

    ``use_active_session``: by default, an active ``mv.session(...)``
    contextvar adds ``--session <id>`` to the argv. Cross-workload
    dispatch via :class:`WorkloadRef` opts out — sessions are scoped
    to a single workload, so a session for workload A must not leak
    into a call against workload B.

    ``fn``: the wrapped Python function. Required when ``MVM_NO_VM=1``
    so the SDK can derive module / function / source-path from the
    local definition and feed them to mvmctl's hidden SDK no-VM transport.
    ``None`` is fine outside no-VM mode.
    """
    _check_emitting_context(call_site)
    _check_id("workload_id", workload_id)
    _check_secret_args(kwargs)
    payload = _encode(format, args, kwargs)
    payload_cap = env_int("MVM_MAX_PAYLOAD_BYTES", DEFAULT_MAX_PAYLOAD_BYTES)
    if len(payload) > payload_cap:
        raise PayloadTooLarge(
            f"encoded payload for {workload_id} is {len(payload)} bytes, "
            f"exceeding MVM_MAX_PAYLOAD_BYTES={payload_cap}. "
            "Hint: pass large blobs via a mounted volume rather than function args."
        )
    bin_path = _locate_mvmctl()
    # `--` argv separator: the substrate's CLI parser treats every token
    # after it as positional, so an id starting with `-` (already rejected
    # at IR + SDK level, but defense in depth) cannot be misparsed as a
    # flag. All optional flags must come *before* the separator.
    no_vm = os.environ.get(NO_VM_ENV_VAR) == "1"
    if no_vm:
        if fn is None:
            raise NoVmIntrospectionError(
                f"MVM_NO_VM=1 set but no local function available to "
                f"introspect for {call_site}. no-VM mode is only valid "
                "for RemoteFunction calls; cross-workload WorkloadRef "
                "dispatch requires a real VM."
            )
        argv: list[str] = [bin_path, "__sdk-no-vm"]
        command_label = "mvmctl __sdk-no-vm"
        argv += _no_vm_flags_for(fn, format)
        # Sessions, --fn, and workload_id don't apply on the local-dispatch
        # path: the wrapper picks `fn` from the inspected definition, and
        # there's no warm VM to attach to.
    else:
        argv = [bin_path, "invoke"]
        command_label = "mvmctl invoke"
        if use_active_session:
            session_id = current_session_id()
            if session_id is not None:
                _check_id("session_id", session_id)
                argv += ["--session", session_id]
        if fn_selector is not None:
            argv += ["--fn", fn_selector]
    # The SDK always feeds the encoded `[args, kwargs]` payload to
    # mvmctl over our own stdin pipe; `--stdin -` tells mvmctl to
    # consume it rather than discarding stdin (default is empty).
    argv += ["--stdin", "-"]
    if not no_vm:
        argv += ["--", workload_id]
    timeout = env_float("MVM_INVOKE_TIMEOUT_SEC", DEFAULT_INVOKE_TIMEOUT_SEC)
    cap = env_int("MVM_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES)
    return argv, payload, timeout, cap, command_label


def _decode_or_raise(
    workload_id: str,
    format: str,
    returncode: int,
    stdout: bytes,
    stderr: bytes,
    command_label: str,
) -> Any:
    if returncode != 0:
        envelope = _parse_error_envelope(stderr)
        if envelope is not None:
            raise envelope
        msg = stderr.decode("utf-8", errors="replace").strip()
        raise MvmTransportError(
            f"{command_label} {workload_id} exited {returncode}: {msg or '(no stderr)'}"
        )
    return _decode(format, stdout)


def _invoke_sync(
    workload_id: str,
    format: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    call_site: str = "RemoteFunction.sync(...)",
    fn_selector: str | None = None,
    use_active_session: bool = True,
    fn: Callable[..., Any] | None = None,
) -> Any:
    argv, payload, timeout, cap, command_label = _prepare_invoke(
        call_site,
        workload_id,
        format,
        args,
        kwargs,
        fn_selector=fn_selector,
        use_active_session=use_active_session,
        fn=fn,
    )
    try:
        proc = run_capped(
            argv,
            input_bytes=payload,
            timeout=timeout,
            max_output_bytes=cap,
        )
    except TransportTimeout as exc:
        raise MvmTransportError(
            f"{command_label} {workload_id} timed out after {timeout}s"
        ) from exc
    except TransportOutputOverflow as exc:
        raise MvmTransportError(
            f"{command_label} {workload_id} exceeded {cap}-byte output cap"
        ) from exc
    except FileNotFoundError as exc:
        raise MvmTransportError(f"failed to spawn mvmctl: {exc}") from exc
    return _decode_or_raise(
        workload_id,
        format,
        proc.returncode,
        proc.stdout,
        proc.stderr,
        command_label,
    )


async def _invoke_async(
    workload_id: str,
    format: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    call_site: str = "RemoteFunction.__call__(...)",
    fn_selector: str | None = None,
    use_active_session: bool = True,
    fn: Callable[..., Any] | None = None,
) -> Any:
    argv, payload, timeout, cap, command_label = _prepare_invoke(
        call_site,
        workload_id,
        format,
        args,
        kwargs,
        fn_selector=fn_selector,
        use_active_session=use_active_session,
        fn=fn,
    )
    # `create_subprocess_exec` is the argv-list (no-shell) async spawn
    # primitive — equivalent of POSIX execve, not shell-style exec.
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        raise MvmTransportError(f"failed to spawn mvmctl: {exc}") from exc

    grace = env_float("MVM_INVOKE_KILL_GRACE_SEC", DEFAULT_KILL_GRACE_SEC)

    async def _terminate_process_group() -> None:
        # SIGTERM the whole group, give the child a grace window to exit
        # cleanly, then SIGKILL if still alive. `start_new_session=True`
        # above puts the child in its own process group so we can reach
        # any grand-children too.
        if proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=grace)
        except asyncio.TimeoutError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            try:
                await proc.wait()
            except Exception:
                pass

    try:
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=payload), timeout=timeout
            )
        except asyncio.TimeoutError as exc:
            await _terminate_process_group()
            raise MvmTransportError(
                f"{command_label} {workload_id} timed out after {timeout}s"
            ) from exc
    except asyncio.CancelledError:
        await _terminate_process_group()
        raise

    if len(stdout) > cap or len(stderr) > cap:
        raise MvmTransportError(
            f"{command_label} {workload_id} exceeded {cap}-byte output cap"
        )

    return _decode_or_raise(
        workload_id,
        format,
        proc.returncode or 0,
        stdout,
        stderr,
        command_label,
    )


class RemoteFunction:
    """Wraps a decorated function with the host-side call surface.

    ``await f(2, 3)`` is the canonical form — it dispatches the call to
    the workload's microVM via ``mvmctl invoke``. Calling the function
    *is* the remote call. Variants:

    - ``f.local(2, 3)`` — pure in-process call against the wrapped
      Python body. Useful for unit tests that don't want a microVM in
      the loop.
    - ``f.sync(2, 3)`` — synchronous escape hatch that does the same
      remote dispatch as ``__call__`` but blocks instead of returning a
      coroutine. Convenient at REPL prompts and in non-async code.
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
        """Synchronous remote dispatch. Same wire path as ``await f(...)``."""
        return _invoke_sync(
            self._workload_id, self._format, args, kwargs, fn=self._fn
        )


class _BoundRemoteCall:
    """Callable returned by ``WorkloadRef.<attribute>``.

    Bound to a (workload_id, function_name) pair. Calling it dispatches
    to ``mvmctl invoke <workload> --fn <function>`` through the same
    transport machinery as :class:`RemoteFunction`. JSON wire format
    only — cross-workload dispatch defaults to JSON since the caller
    can't introspect the callee's IR-declared format. Pass
    ``format="msgpack"`` to :func:`workload_ref` if you know the callee
    uses msgpack.
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
            fn_selector=self._function,
            use_active_session=False,
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
            fn_selector=self._function,
            use_active_session=False,
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
            s = await math.add(a, b)        # mvmctl invoke math-svc --fn add
            return s * 2

    The proxy reuses the same dispatch path as :class:`RemoteFunction`
    (encode → payload-cap check → spawn ``mvmctl`` → decode envelope),
    so payload caps, secret-args heuristics, and decoder hardening
    apply identically. Sessions don't propagate across workload
    boundaries — a ``mv.session("a")`` context doesn't add ``--session``
    to a call against workload ``"b"``.

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
