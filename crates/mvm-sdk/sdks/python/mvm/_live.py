"""Pieces the live facades (`Sandbox` and `Machine`) share.

Both talk to the host library through `mvm._hostlib.call`, and both need the
same three things on top of it: bytes carried as base64 inside JSON, egress
targets validated before a boot request leaves the process, and the loop that
drains a guest process's output stream. Keeping one copy means the two
facades cannot drift into reporting the same process ending with different
exit codes.
"""

from __future__ import annotations

import base64
import binascii
import math
from dataclasses import dataclass
from typing import Any, Callable

from mvm import _hostlib
from mvm._errors.types import HostLibraryError, MvmTransportError
from mvm._hostabi.methods import (
    GUEST_PROC_STREAM_CLOSE,
    GUEST_PROC_STREAM_NEXT,
    GUEST_PROC_STREAM_OPEN,
)

#: Exit code reported for a process whose wait ran out of time. It matches
#: what the coreutils `timeout` command returns, which is what a shell user
#: already expects to see for "killed because it took too long".
TIMED_OUT_EXIT_CODE = 124

# Hosts that would turn an allowlist entry into "anywhere". The egress gate
# refuses them too; refusing here means the caller learns before a boot.
_WILDCARD_HOSTS = frozenset({"*", "0.0.0.0", "::", "0.0.0.0/0", "::/0"})

ErrorFactory = Callable[[str], Exception]


def encode_bytes(data: bytes) -> str:
    """Bytes as the standard base64 text every ``*_b64`` field carries."""
    return base64.standard_b64encode(data).decode("ascii")


def decode_bytes(text: Any, field: str, error: ErrorFactory) -> bytes:
    """Decode a ``*_b64`` reply field, refusing anything that is not valid
    base64 rather than handing the caller silently truncated output."""
    if not isinstance(text, str):
        raise error(f"host library reply field `{field}` is not a base64 string")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise error(f"host library reply field `{field}` is not valid base64") from exc


def egress_problem(host: Any, port: Any) -> str | None:
    """Why ``host:port`` cannot be an egress allowlist entry, or ``None``."""
    if not isinstance(host, str) or not host or host in _WILDCARD_HOSTS:
        return "allowlist hosts must be specific"
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return "allowlist ports must be 1..65535"
    return None


def parse_host_port(text: str) -> tuple[str, int]:
    """Split ``host:port`` or ``[v6-address]:port``.

    The brackets are the only unambiguous way to write an IPv6 address with a
    port, so a bare address containing colons is refused rather than guessed
    at.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("an allow-host entry must be a non-empty 'host:port' string")
    if text.startswith("["):
        close = text.find("]")
        if close < 0 or text[close + 1 : close + 2] != ":":
            raise ValueError(f"allow-host {text!r} must look like '[address]:port'")
        host, port_text = text[1:close], text[close + 2 :]
    else:
        host, sep, port_text = text.rpartition(":")
        if not sep or ":" in host:
            raise ValueError(
                f"allow-host {text!r} must look like 'host:port' (bracket IPv6 addresses)"
            )
    try:
        port = int(port_text)
    except ValueError:
        raise ValueError(f"allow-host {text!r} has a non-numeric port") from None
    problem = egress_problem(host, port)
    if problem is not None:
        raise ValueError(f"allow-host {text!r}: {problem}")
    return host, port


def timeout_seconds(timeout: float | None) -> int | None:
    """A caller's timeout as the whole seconds the library takes.

    Rounded up, so a sub-second timeout still grants the process a second
    rather than becoming zero, which would read as "no time at all".
    """
    if timeout is None:
        return None
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout > 0:
        raise ValueError("timeout must be a positive number of seconds")
    return math.ceil(timeout)


def exit_code_for(outcome: Any, error: ErrorFactory) -> int:
    """Map a wait outcome to the exit code a shell would report.

    A signal death is ``128 + signal`` and a timeout is 124, so callers that
    only look at ``exit_code`` still see a failure for both.
    """
    if not isinstance(outcome, dict):
        raise error("host library ended a process stream without an outcome")
    kind = outcome.get("kind")
    if kind == "exited":
        code = outcome.get("code")
        if isinstance(code, int) and not isinstance(code, bool):
            return code
    elif kind == "killed":
        signal = outcome.get("signal")
        if isinstance(signal, int) and not isinstance(signal, bool):
            return 128 + signal
    elif kind == "timed_out":
        return TIMED_OUT_EXIT_CODE
    raise error(f"host library reported an unrecognised process outcome: {outcome!r}")


@dataclass(frozen=True)
class ProcessOutput:
    """Everything a finished guest process produced."""

    exit_code: int
    stdout: bytes
    stderr: bytes


def stream_process(
    vm_id: str,
    token: str,
    *,
    timeout: float | None,
    on_chunk: Callable[[str, bytes], None] | None,
    error: ErrorFactory,
) -> ProcessOutput:
    """Wait for a guest process, delivering its output as it arrives.

    The stream API is used rather than the buffered wait because the buffered
    one caps each stream and drops the rest; here every byte reaches the
    caller. The library holds a queue per open stream, so the stream is closed
    on every exit that did not see it finish, including a callback raising.
    """
    request: dict[str, Any] = {"id": vm_id, "token": token}
    seconds = timeout_seconds(timeout)
    if seconds is not None:
        request["timeout_secs"] = seconds
    opened = _hostlib.call(GUEST_PROC_STREAM_OPEN, request)
    stream = opened.get("stream") if isinstance(opened, dict) else None
    if not isinstance(stream, int) or isinstance(stream, bool):
        raise error(f"host library opened a process stream without an id: {opened!r}")

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    finished = False
    try:
        while True:
            batch = _hostlib.call(GUEST_PROC_STREAM_NEXT, {"stream": stream})
            if not isinstance(batch, dict):
                raise error(f"host library returned a malformed stream batch: {batch!r}")
            events = batch.get("events", [])
            done = batch.get("done")
            if not isinstance(events, list) or not isinstance(done, bool):
                raise error(f"host library returned a malformed stream batch: {batch!r}")
            for event in events:
                name = event.get("stream") if isinstance(event, dict) else None
                if name not in buffers:
                    raise error(f"host library returned an event for no known stream: {event!r}")
                data = decode_bytes(event.get("data_b64"), "data_b64", error)
                buffers[name].extend(data)
                if on_chunk is not None:
                    on_chunk(name, data)
            if done:
                # The library forgets a stream once it reports the end, so
                # there is nothing left to close even if the outcome is bad.
                finished = True
                return ProcessOutput(
                    exit_code=exit_code_for(batch.get("outcome"), error),
                    stdout=bytes(buffers["stdout"]),
                    stderr=bytes(buffers["stderr"]),
                )
    finally:
        if not finished:
            try:
                _hostlib.call(GUEST_PROC_STREAM_CLOSE, {"stream": stream})
            except (HostLibraryError, MvmTransportError):
                # We are already unwinding with the error that matters; a
                # failed close must not replace it.
                pass
