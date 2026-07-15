#!/usr/bin/env python3
# /// mvm function-entrypoint wrapper (Python, ADR-0011 warm-process tier).
# ///
# /// Counterpart to ./oneshot.py: same dispatch + envelope semantics, but
# /// stays alive across many calls and speaks the framed multi-call
# /// protocol on its own stdin/stdout (matching mvm_agentd::worker_protocol::
# /// {WorkerCallRequest, WorkerCallResponse}).
# ///
# /// Wire format (per call, both directions):
# ///   [4-byte big-endian length prefix] [JSON body of length bytes]
# ///
# /// Request body  (WorkerCallRequest):
# ///   { "stdin": base64-encoded encoded-args, "timeout_secs": u64 }
# ///
# /// Response body (WorkerCallResponse):
# ///   { "stdout": base64-encoded encoded-return,
# ///     "stderr": base64-encoded user-stderr,
# ///     "outcome": { "exit": { "code": 0 } }
# ///              | { "error": { "kind": "...", "message": "..." } } }
# ///
# /// Lifecycle:
# ///   - On startup: load /etc/mvm/wrapper.json, apply prod hardening
# ///     (PR_SET_DUMPABLE=0), import the user module ONCE.
# ///   - Per call: read frame, dispatch fn, capture stdout/stderr, write
# ///     response frame, loop.
# ///   - On EOF (agent closed the pipe): exit 0 cleanly.
# ///
# /// Per ADR-0011, **cross-call state is the user's responsibility**. The
# /// wrapper does NOT scrub Python globals, /tmp, file descriptors, or
# /// anything else between calls. Users opting into warm-process accept
# /// that.

"""mvm warm-process wrapper for Python workloads (ADR-0011)."""

from __future__ import annotations

import base64
import contextlib
import ctypes
import importlib
import io
import json
import os
import secrets
import signal
import struct
import sys
from typing import Any

WRAPPER_CONFIG_PATH = os.environ.get(
    "MVM_WRAPPER_CONFIG_PATH", "/etc/mvm/wrapper.json"
)
MAX_NESTING_DEPTH = 64
DEFAULT_MAX_INPUT_BYTES = 16 * 1024 * 1024  # 16 MiB
MAX_FRAME_BYTES = 256 * 1024  # mvm_agentd::worker_protocol cap
ENVELOPE_MARKER = "MVM_ENVELOPE: "


def _set_no_dumpable() -> None:
    from ctypes.util import find_library

    libc_path = find_library("c")
    if libc_path is None:
        return
    try:
        libc = ctypes.CDLL(libc_path, use_errno=True)
        libc.prctl(4, 0, 0, 0, 0)
    except (OSError, AttributeError):
        pass


def _load_config() -> dict[str, Any]:
    with open(WRAPPER_CONFIG_PATH, "rb") as f:
        text = f.read().decode("utf-8")
    cfg = json.loads(text)
    if not isinstance(cfg, dict):
        raise RuntimeError("wrapper config must be a JSON object")
    for required in ("module", "function", "format"):
        if not isinstance(cfg.get(required), str):
            raise RuntimeError(f"wrapper config missing/invalid: {required}")
    if cfg["format"] not in ("json", "msgpack"):
        raise RuntimeError(f"unsupported format: {cfg['format']}")
    cfg.setdefault("mode", "prod")
    cfg.setdefault("working_dir", "/app")
    cfg.setdefault("max_input_bytes", DEFAULT_MAX_INPUT_BYTES)
    if not isinstance(cfg["max_input_bytes"], int) or cfg["max_input_bytes"] <= 0:
        raise RuntimeError("max_input_bytes must be a positive integer")
    return cfg


def _depth(value: Any, current: int = 0) -> int:
    if current > MAX_NESTING_DEPTH:
        raise ValueError(f"payload nesting depth exceeds {MAX_NESTING_DEPTH}")
    if isinstance(value, dict):
        return max((_depth(v, current + 1) for v in value.values()), default=current)
    if isinstance(value, list):
        return max((_depth(v, current + 1) for v in value), default=current)
    return current


def _check_no_finite_floats(value: Any) -> None:
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite floats are forbidden in payload")
    elif isinstance(value, dict):
        for v in value.values():
            _check_no_finite_floats(v)
    elif isinstance(value, list):
        for v in value:
            _check_no_finite_floats(v)


def _decode_json(data: bytes) -> Any:
    def reject_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise ValueError(f"duplicate key in JSON object: {k!r}")
            out[k] = v
        return out

    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=reject_dupes,
        parse_constant=lambda c: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON constant rejected: {c}")
        ),
    )


def _decode_msgpack(data: bytes) -> Any:
    import msgpack

    return msgpack.unpackb(data, raw=False, strict_map_key=True)


def _encode_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _encode_msgpack(value: Any) -> bytes:
    import msgpack

    return msgpack.packb(value, use_bin_type=True)


def _decode(format: str, data: bytes) -> Any:
    payload = _decode_json(data) if format == "json" else _decode_msgpack(data)
    _depth(payload)
    _check_no_finite_floats(payload)
    return payload


def _encode(format: str, value: Any) -> bytes:
    return _encode_json(value) if format == "json" else _encode_msgpack(value)


def _scrub(message: str) -> str:
    redacted = " ".join(part for part in message.split() if "/" not in part)
    return redacted[:200] if redacted else type(message).__name__


def _read_exact(stream, n: int) -> bytes | None:
    """Read exactly n bytes, or None on clean EOF before any byte is read.

    Raises RuntimeError on partial read after at least one byte arrived
    (truncated frame — protocol violation).
    """
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            if remaining == n:
                return None
            raise RuntimeError(
                f"truncated frame: expected {n} bytes, got {n - remaining}"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame() -> bytes | None:
    """Read one length-prefixed frame from stdin. None on clean EOF."""
    prefix = _read_exact(sys.stdin.buffer, 4)
    if prefix is None:
        return None
    (length,) = struct.unpack(">I", prefix)
    if length > MAX_FRAME_BYTES:
        raise RuntimeError(
            f"frame length {length} exceeds protocol cap {MAX_FRAME_BYTES}"
        )
    body = _read_exact(sys.stdin.buffer, length)
    if body is None:
        raise RuntimeError("unexpected EOF after frame length prefix")
    return body


def _write_frame(body: bytes) -> None:
    """Write a length-prefixed frame to stdout and flush."""
    if len(body) > MAX_FRAME_BYTES:
        raise RuntimeError(
            f"response frame length {len(body)} exceeds protocol cap {MAX_FRAME_BYTES}"
        )
    sys.stdout.buffer.write(struct.pack(">I", len(body)))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def _emit_envelope_to_stderr(mode: str, exc: BaseException) -> None:
    """Write a sanitized envelope to the wrapper's own stderr (operator log).

    Per-call user-code errors propagate through the WorkerCallResponse's
    `outcome.error` field; the operator log gets a marker line for any
    *wrapper-level* error (frame protocol violation, config invalid).
    """
    error_id = secrets.token_hex(8)
    if mode == "dev":
        import traceback

        traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
        sys.stderr.write("\n")
    envelope = {
        "kind": type(exc).__name__,
        "error_id": error_id,
        "message": str(exc) if mode == "dev" else _scrub(str(exc)),
    }
    sys.stderr.write(ENVELOPE_MARKER)
    sys.stderr.write(json.dumps(envelope, ensure_ascii=False))
    sys.stderr.write("\n")
    sys.stderr.flush()


class _CallTimeout(Exception):
    pass


@contextlib.contextmanager
def _per_call_timeout(timeout_secs: int):
    """Best-effort wall-clock cap per call via SIGALRM.

    SIGALRM is Linux-only; on platforms where it's unavailable we
    just no-op. mvm enforces a substrate-side hard cap regardless.
    """
    if timeout_secs <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _handler(signum, frame):
        raise _CallTimeout(f"call exceeded {timeout_secs}-second cap")

    prev = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(timeout_secs)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, prev)


def _dispatch_one_call(fn, format: str, request_body: bytes, mode: str) -> dict:
    """Decode a WorkerCallRequest, run the user fn, build a response dict."""
    request = _decode_json(request_body)
    if not isinstance(request, dict):
        raise ValueError("WorkerCallRequest must be a JSON object")
    stdin_b64 = request.get("stdin", "")
    if not isinstance(stdin_b64, str):
        raise ValueError("WorkerCallRequest.stdin must be a base64 string")
    timeout_secs = request.get("timeout_secs", 60)
    if not isinstance(timeout_secs, int):
        raise ValueError("WorkerCallRequest.timeout_secs must be an integer")

    try:
        call_input = base64.b64decode(stdin_b64.encode("ascii"), validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"WorkerCallRequest.stdin not valid base64: {exc}") from None

    captured_out = io.BytesIO()
    captured_err = io.BytesIO()
    captured_out_text = io.TextIOWrapper(captured_out, encoding="utf-8", write_through=True)
    captured_err_text = io.TextIOWrapper(captured_err, encoding="utf-8", write_through=True)

    outcome: dict[str, Any]
    with (
        contextlib.redirect_stdout(captured_out_text),
        contextlib.redirect_stderr(captured_err_text),
    ):
        try:
            with _per_call_timeout(timeout_secs):
                decoded = _decode(format, call_input)
                if not (
                    isinstance(decoded, list)
                    and len(decoded) == 2
                    and isinstance(decoded[0], list)
                    and isinstance(decoded[1], dict)
                ):
                    raise ValueError("payload must be a 2-element list: [args, kwargs]")
                args, kwargs = decoded[0], decoded[1]
                result = fn(*args, **kwargs)
                encoded_return = _encode(format, result)
            captured_out.write(encoded_return)
            outcome = {"exit": {"code": 0}}
        except BaseException as exc:
            outcome = {
                "error": {
                    "kind": type(exc).__name__,
                    "message": str(exc) if mode == "dev" else _scrub(str(exc)),
                },
            }
    captured_out_text.flush()
    captured_err_text.flush()

    return {
        "stdout": base64.b64encode(captured_out.getvalue()).decode("ascii"),
        "stderr": base64.b64encode(captured_err.getvalue()).decode("ascii"),
        "outcome": outcome,
    }


def main() -> int:
    cfg = _load_config()
    mode: str = cfg["mode"]
    if mode == "prod":
        _set_no_dumpable()

    try:
        os.chdir(cfg["working_dir"])
        sys.path.insert(0, cfg["working_dir"])
        module = importlib.import_module(cfg["module"])
        fn = getattr(module, cfg["function"])
    except BaseException as exc:
        _emit_envelope_to_stderr(mode, exc)
        return 1

    while True:
        try:
            body = _read_frame()
        except RuntimeError as exc:
            _emit_envelope_to_stderr(mode, exc)
            return 1
        if body is None:
            return 0  # clean EOF — agent closed the pipe

        try:
            response = _dispatch_one_call(fn, cfg["format"], body, mode)
            response_body = _encode_json(response)
            _write_frame(response_body)
        except BaseException as exc:
            # Wrapper-level error (protocol violation, encode failure).
            # Mirror to stderr and try to keep the loop going by sending
            # a synthetic error response so the agent can correlate.
            _emit_envelope_to_stderr(mode, exc)
            try:
                _write_frame(
                    _encode_json(
                        {
                            "stdout": "",
                            "stderr": "",
                            "outcome": {
                                "error": {
                                    "kind": type(exc).__name__,
                                    "message": _scrub(str(exc)),
                                },
                            },
                        }
                    )
                )
            except OSError:
                # Pipe closed while we were writing — agent is gone.
                return 1


if __name__ == "__main__":
    sys.exit(main())
