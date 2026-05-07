#!/usr/bin/env python3
# /// mvmforge function-entrypoint wrapper (Python). ADR-0009 / plan-0003.
# ///
# /// Baked into rootfs by mkPythonFunctionService (mvm side, future). Reads
# /// `[args, kwargs]` from stdin in the IR-declared format, dispatches
# /// `module:function`, writes the encoded return on stdout, exits 0.
# ///
# /// ADR-0009 invariants enforced here:
# ///   - Two-mode (prod | dev) gated by /etc/mvm/wrapper.json's `mode`.
# ///   - prod: PR_SET_DUMPABLE=0; sanitized error envelope on stderr;
# ///     no traceback, no file paths, no payload bytes in logs.
# ///   - decoder hardening: max nesting depth 64, reject duplicate keys,
# ///     reject non-finite floats.
# ///   - serialization format is closed (json | msgpack). Code-executing
# ///     formats listed in ADR-0009 §Decision are forbidden — never imported.
# ///
# /// Config at /etc/mvm/wrapper.json (written at image build time):
# ///   { "module": str, "function": str, "format": "json"|"msgpack",
# ///     "working_dir": str, "mode": "prod"|"dev" }
"""mvmforge function-entrypoint wrapper for Python workloads.

Single-shot invariant
---------------------
This wrapper assumes exactly one invocation per process — the substrate
agent spawns a fresh wrapper for every call (mvm ADR-007 §6 hygiene).
The wrapper takes shortcuts that depend on this:

  * `os.chdir(working_dir)` — never undone.
  * `sys.path.insert(0, working_dir)` — never popped.
  * Imported user modules and their side effects persist for the
    lifetime of the process.
  * Per-call envelope error_id is generated once at exit time.

If you adapt this wrapper for a warm-process / microbatching mode, you
**must** scrub all of the above between calls before reading the next
input. Set `MVMFORGE_WRAPPER_ALLOW_REENTRY=1` to opt out of the safety
check below; otherwise the wrapper hard-errors on a second invocation
attempt.
"""

from __future__ import annotations

import ctypes
import importlib
import json
import os
import secrets
import sys
from typing import Any

WRAPPER_CONFIG_PATH = "/etc/mvm/wrapper.json"
MAX_NESTING_DEPTH = 64
_main_invoked = False
# Defense-in-depth stdin cap. The substrate enforces a hard cap upstream
# (mvm M1); this is a belt-and-suspenders ceiling so a misconfigured
# substrate doesn't let arbitrary-size payloads OOM the wrapper.
DEFAULT_MAX_INPUT_BYTES = 16 * 1024 * 1024  # 16 MiB


def _set_no_dumpable() -> None:
    # PR_SET_DUMPABLE = 4. Disable core dumps for this process. Belt-and-
    # suspenders with the agent's RLIMIT_CORE per ADR-0009.
    #
    # Resolve libc dynamically rather than hardcoding `libc.so.6`
    # (glibc-only). Alpine/musl rootfs use `ld-musl-<arch>.so.1`;
    # NixOS minimal closures expose whatever's in the closure. On
    # platforms where we can't find libc (or aren't Linux at all),
    # we fall back to no-op — the agent's RLIMIT_CORE remains the
    # primary defense.
    from ctypes.util import find_library

    libc_path = find_library("c")
    if libc_path is None:
        return
    try:
        libc = ctypes.CDLL(libc_path, use_errno=True)
        libc.prctl(4, 0, 0, 0, 0)
    except (OSError, AttributeError):
        # AttributeError: this libc doesn't expose prctl (non-Linux).
        # OSError: dlopen / dlsym failed. Both: best-effort.
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
    # Optional schemas (plan-0009 v2). Stored as dicts; validated at
    # call time if the jsonschema library is importable.
    if "args_schema" in cfg and not isinstance(cfg["args_schema"], dict):
        raise RuntimeError("args_schema must be a JSON object")
    if "return_schema" in cfg and not isinstance(cfg["return_schema"], dict):
        raise RuntimeError("return_schema must be a JSON object")
    return cfg


def _validate_against_schema(value, schema, where: str) -> None:
    """Validate `value` against `schema`. If the jsonschema lib isn't
    importable (the rootfs didn't bake it in), skip with no-op — the
    host-side build-time check still runs and other defenses (caps,
    decoder hardening) remain intact.
    """
    try:
        import jsonschema
    except ImportError:
        return
    try:
        jsonschema.validate(value, schema)
    except jsonschema.ValidationError as exc:
        # Re-raise as a generic ValidationError so the envelope's `kind`
        # is consistent regardless of which validator backend ran.
        raise ValueError(f"{where} validation failed: {exc.message}") from None


def _read_stdin_capped(max_bytes: int) -> bytes:
    """Read stdin in chunks, refusing to buffer more than ``max_bytes``.

    Reads one extra byte beyond the cap so we can detect overflow without
    relying on the producer to close the pipe at exactly the limit.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = sys.stdin.buffer.read(65536)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > max_bytes:
            raise RuntimeError(
                f"input payload exceeded {max_bytes}-byte cap before EOF"
            )
        chunks.append(chunk)


def _depth(value: Any, current: int = 0) -> int:
    if current > MAX_NESTING_DEPTH:
        raise ValueError(f"payload nesting depth exceeds {MAX_NESTING_DEPTH}")
    if isinstance(value, dict):
        return max(
            (_depth(v, current + 1) for v in value.values()),
            default=current,
        )
    if isinstance(value, list):
        return max(
            (_depth(v, current + 1) for v in value),
            default=current,
        )
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
    import msgpack  # build-time dep; never falls back

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


ENVELOPE_MARKER = "MVMFORGE_ENVELOPE: "


def _emit_envelope(mode: str, exc: BaseException) -> None:
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
    # Marker prefix lets the host SDK find the envelope unambiguously
    # even if other lines get written to stderr before/after. The host
    # parser scans for this prefix; the JSON body is the rest of the line.
    sys.stderr.write(ENVELOPE_MARKER)
    sys.stderr.write(json.dumps(envelope, ensure_ascii=False))
    sys.stderr.write("\n")


def _scrub(message: str) -> str:
    redacted = " ".join(part for part in message.split() if "/" not in part)
    return redacted[:200] if redacted else type(message).__name__


def main() -> int:
    global _main_invoked
    if _main_invoked and os.environ.get("MVMFORGE_WRAPPER_ALLOW_REENTRY") != "1":
        # Guards the single-shot invariant in the docstring. Per-call
        # respawn is the substrate's contract; if you intentionally
        # adapted this wrapper for warm reuse, set the opt-in env var
        # and ensure all per-call state is scrubbed first.
        raise RuntimeError(
            "wrapper main() called twice without MVMFORGE_WRAPPER_ALLOW_REENTRY=1; "
            "this wrapper assumes per-call respawn (mvm ADR-007 §6)"
        )
    _main_invoked = True
    cfg = _load_config()
    mode: str = cfg["mode"]
    if mode == "prod":
        _set_no_dumpable()

    try:
        data = _read_stdin_capped(cfg["max_input_bytes"])
        decoded = _decode(cfg["format"], data)
        if not (
            isinstance(decoded, list) and len(decoded) == 2
            and isinstance(decoded[0], list) and isinstance(decoded[1], dict)
        ):
            raise ValueError("payload must be a 2-element list: [args, kwargs]")
        args, kwargs = decoded[0], decoded[1]

        os.chdir(cfg["working_dir"])
        sys.path.insert(0, cfg["working_dir"])
        module = importlib.import_module(cfg["module"])
        fn = getattr(module, cfg["function"])

        # Plan-0009 v2: schema-bound validation. Bind positional+keyword
        # args to the function's signature so an `args_schema` of shape
        # `{"type":"object","properties":{...}}` validates the call as
        # a single object. Best-effort if `jsonschema` isn't installed;
        # the host's build-time check still rejects secret-shaped names.
        if cfg.get("args_schema") is not None:
            try:
                import inspect

                bound = inspect.signature(fn).bind(*args, **kwargs)
                bound.apply_defaults()
                arg_dict = dict(bound.arguments)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"args binding failed: {exc}") from None
            _validate_against_schema(arg_dict, cfg["args_schema"], "args_schema")

        result = fn(*args, **kwargs)
        if cfg.get("return_schema") is not None:
            _validate_against_schema(result, cfg["return_schema"], "return_schema")
        out = _encode(cfg["format"], result)
        sys.stdout.buffer.write(out)
        return 0
    except BaseException as exc:
        _emit_envelope(mode, exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
