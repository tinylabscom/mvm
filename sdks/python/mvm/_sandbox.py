"""Sandbox — e2b-style imperative runtime SDK. SDK port Phase 7b.

The decorator surface (``@mvm.app(...)``) is static; the host
parses the source AST and never imports the script. The runtime
surface (``Sandbox.create(...)``) is imperative: the host *does*
execute the user's Python script (per S2 in the SDK plan — a
documented departure), with the SDK reconfigured to record each
``Sandbox`` method call into a :class:`RuntimeRecording` instead
of dialing a real microVM.

Phase 7b ships *only record mode*. ``MVM_SDK_MODE=record`` is the
mode the recorder reads; ``live`` and ``plan`` raise
:class:`NotImplementedError` until Plan 71 unblocks
``mvmctl up``/``exec``. The record-mode lowering happens on the
Rust side (``crates/mvm-sdk/src/runtime.rs::compile_recording``);
this module's job is just to build a wire-compatible recording
JSON document.

Wire shape (matches the Rust ``RuntimeRecording`` serde types,
``deny_unknown_fields`` on both sides — a typo'd field name fails
closed at the Rust boundary)::

    {
      "workload_id": "etl",
      "create": {
        "template": "python-3.12",
        "env": {"MODEL": {"kind": "literal", "value": "/data/m.pt"}},
        "include": ["src"],
        "tags": {},
        "ttl_seconds": 1800,
        "resources": {"cpu_cores": 1, "memory_mb": 256,
                      "rootfs_size_mb": 512},
        "network": null
      },
      "ops": [
        {"kind": "command_start", "argv": ["python", "run.py"],
         "env": {}},
        {"kind": "files_write", "path": "/app/cfg.json",
         "bytes_b64": "..."},
        {"kind": "kill"}
      ]
    }
"""

from __future__ import annotations

import base64
import dataclasses
import enum
import json
import os
import re
from typing import Any

from mvm import _ir
from mvm._dsl import literal as _literal_value

__all__ = [
    "DEFAULT_TTL_SECONDS",
    "RecordingNotActiveError",
    "Sandbox",
    "SandboxModeError",
    "current_recording_dict",
    "emit_recording_json",
    "reset_recording",
]


MVM_SDK_MODE_ENV = "MVM_SDK_MODE"

#: Plan ``Considerations to fold in or defer`` — every
#: ``Sandbox.create()`` sets a default 30-minute TTL so the
#: orchestrator can reap orphaned VMs after a crashed record-mode
#: script.
DEFAULT_TTL_SECONDS = 1800


class SandboxModeError(RuntimeError):
    """Raised when the configured ``MVM_SDK_MODE`` isn't supported by
    this SDK build. Phase 7b ships record-only — ``live`` and ``plan``
    are blocked on Plan 71."""


class RecordingNotActiveError(RuntimeError):
    """Raised when a ``Sandbox`` method is called outside a recording
    session (i.e. before ``Sandbox.create`` ran, or after
    :func:`reset_recording`)."""


# ────────────────────────────────────────────────────────────────────
# Module-global recording state.
#
# The CLI invokes the user's script in a fresh Python process, so a
# module-global is appropriate — one recording per process. Tests
# call :func:`reset_recording` between runs.
# ────────────────────────────────────────────────────────────────────

_recording: dict[str, Any] | None = None


def reset_recording() -> None:
    """Clear the in-flight recording. Tests use this between
    runs; production never calls it (the process exits)."""
    global _recording
    _recording = None


def current_recording_dict() -> dict[str, Any] | None:
    """Return the wire-shape dict for the currently-active recording,
    or ``None`` if no ``Sandbox.create()`` has run."""
    return _recording


def emit_recording_json() -> str:
    """Serialize the active recording to the JSON wire shape the
    Rust core consumes. Raises :class:`RecordingNotActiveError` if
    no recording has been started."""
    if _recording is None:
        raise RecordingNotActiveError(
            "no Sandbox.create() recorded yet — emit_recording_json "
            "called before any Sandbox method"
        )
    return json.dumps(_recording, separators=(",", ":"), sort_keys=True)


# ────────────────────────────────────────────────────────────────────
# Mode + TTL helpers.
# ────────────────────────────────────────────────────────────────────


def _resolve_mode() -> str:
    """Read ``MVM_SDK_MODE``. Defaults to ``record`` so a bare
    ``python sandbox.py`` invoked by the CLI works without an env
    var. ``live`` and ``plan`` aren't supported in Phase 7b."""
    raw = os.environ.get(MVM_SDK_MODE_ENV, "record").strip().lower()
    if raw == "record":
        return raw
    if raw in {"live", "plan"}:
        raise SandboxModeError(
            f"MVM_SDK_MODE={raw!r} is not supported in this SDK build — "
            "live/plan transports are blocked on Plan 71. Use 'record' or "
            "the @mvm.app decorator path."
        )
    raise SandboxModeError(
        f"MVM_SDK_MODE={raw!r} is invalid — expected one of: record, live, plan"
    )


_TTL_RE = re.compile(r"^\s*(\d+)\s*(s|m|h)?\s*$")


def _parse_ttl(ttl: str | int | None) -> int | None:
    """Accept ``"30m"`` / ``"1h"`` / ``"3600s"`` / ``"3600"`` / ``3600``
    / ``None`` and return integer seconds. ``None`` means "default of
    :data:`DEFAULT_TTL_SECONDS`" — callers in ``Sandbox.create``
    substitute the default after this call returns."""
    if ttl is None:
        return None
    if isinstance(ttl, int):
        if ttl <= 0:
            raise ValueError(f"ttl must be > 0 seconds, got {ttl}")
        return ttl
    if not isinstance(ttl, str):
        raise TypeError(f"ttl must be int, str, or None; got {type(ttl).__name__}")
    m = _TTL_RE.match(ttl)
    if not m:
        raise ValueError(
            f"unrecognized ttl format {ttl!r} — expected '<n>s', '<n>m', '<n>h', "
            "or a bare integer of seconds"
        )
    value, unit = int(m.group(1)), m.group(2) or "s"
    seconds = value * {"s": 1, "m": 60, "h": 3600}[unit]
    if seconds <= 0:
        raise ValueError(f"ttl must be > 0 seconds, got {seconds}")
    return seconds


# ────────────────────────────────────────────────────────────────────
# Wire-shape encoders.
#
# We accept dsl-shaped objects (``_ir.EnvValue1``, ``_ir.Resources``,
# ``_ir.Network``, …) as well as bare Python builtins. Everything
# normalizes to the Rust serde wire format.
# ────────────────────────────────────────────────────────────────────


def _encode_env_value(value: Any) -> dict[str, Any]:
    """Coerce an env-mapping value into the Rust ``EnvValue`` wire
    shape. Bare ``str`` is wrapped via :func:`mvm.literal`; the SDK
    helpers (``mvm.literal``, ``mvm.secret``) are passed through
    after a dataclass→dict normalization step."""
    if isinstance(value, str):
        return _dataclass_to_dict(_literal_value(value))
    if dataclasses.is_dataclass(value):
        return _dataclass_to_dict(value)
    if isinstance(value, dict):
        return value
    raise TypeError(
        f"env value must be str, mvm.literal/secret, or dict; got "
        f"{type(value).__name__}"
    )


def _encode_env_map(env: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if env is None:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for k, v in env.items():
        if not isinstance(k, str):
            raise TypeError(f"env keys must be str; got {type(k).__name__}")
        out[k] = _encode_env_value(v)
    return out


def _dataclass_to_dict(obj: Any) -> Any:
    """Recursively convert a dataclass / list / dict into plain
    Python primitives, stripping ``None``-valued keys so the wire
    shape matches Rust's ``skip_serializing_if = Option::is_none``
    rule. Necessary because ``dataclasses.asdict`` keeps ``None``s,
    which would trip the Rust ``deny_unknown_fields`` check on the
    union variants."""
    if isinstance(obj, enum.Enum):
        # The IR dataclasses use string-valued enums for `kind` tags;
        # extract `.value` so the wire JSON has bare strings (which
        # is what Rust's serde internal tagging expects).
        return obj.value
    if dataclasses.is_dataclass(obj):
        out: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            v = getattr(obj, f.name)
            if v is None:
                continue
            out[f.name] = _dataclass_to_dict(v)
        return out
    if isinstance(obj, list):
        return [_dataclass_to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _dataclass_to_dict(v) for k, v in obj.items()}
    return obj


def _encode_resources(resources: Any) -> dict[str, Any] | None:
    if resources is None:
        return None
    if dataclasses.is_dataclass(resources):
        return _dataclass_to_dict(resources)
    if isinstance(resources, dict):
        return resources
    raise TypeError(
        f"resources must be a mvm.resources(...) call or dict; got "
        f"{type(resources).__name__}"
    )


def _encode_network(network: Any) -> dict[str, Any] | None:
    if network is None:
        return None
    if dataclasses.is_dataclass(network):
        return _dataclass_to_dict(network)
    if isinstance(network, dict):
        return network
    raise TypeError(
        f"network must be a mvm.network(...) call or dict; got "
        f"{type(network).__name__}"
    )


# ────────────────────────────────────────────────────────────────────
# Sandbox.
# ────────────────────────────────────────────────────────────────────


class _Commands:
    """Namespace for ``sb.commands.*`` methods."""

    def __init__(self, sandbox: "Sandbox") -> None:
        self._sandbox = sandbox

    def start(
        self, argv: list[str], *, env: dict[str, Any] | None = None
    ) -> None:
        """Record a ``commands.start(argv, env=...)`` op.

        The *last* ``commands.start`` in the recording becomes the
        workload's entrypoint; everything earlier becomes a
        ``before_start`` hook in declaration order. Live transport
        (actually exec'ing the command in a microVM) is deferred to a
        post-Plan-71 follow-up."""
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            raise TypeError("argv must be a list[str]")
        if not argv:
            raise ValueError("argv must be non-empty")
        _require_recording()
        _recording["ops"].append(
            {
                "kind": "command_start",
                "argv": argv,
                "env": _encode_env_map(env),
            }
        )


class _Files:
    """Namespace for ``sb.files.*`` methods."""

    def __init__(self, sandbox: "Sandbox") -> None:
        self._sandbox = sandbox

    def write(self, path: str, content: bytes | str) -> None:
        """Record a ``files.write(path, content)`` op.

        ``content`` is bytes (passed through verbatim) or str
        (utf-8 encoded). The recording stores base64 so JSON
        survives any byte content; the Rust lowering emits a
        ``before_start`` shell hook that ``base64 -d``s back to the
        file."""
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty str")
        if isinstance(content, str):
            data = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray)):
            data = bytes(content)
        else:
            raise TypeError(
                f"files.write content must be bytes or str; got "
                f"{type(content).__name__}"
            )
        _require_recording()
        _recording["ops"].append(
            {
                "kind": "files_write",
                "path": path,
                "bytes_b64": base64.standard_b64encode(data).decode("ascii"),
            }
        )


class Sandbox:
    """A recordable handle for an imperative ``Sandbox`` script.

    Construct via :meth:`Sandbox.create` — the direct constructor is
    used internally so the recording session can be set up first.
    Supports context-manager usage; ``__exit__`` records a final
    ``kill`` op (dropped by the Rust lowering, but the
    bookkeeping is preserved for tooling)."""

    def __init__(self, workload_id: str) -> None:
        self._workload_id = workload_id
        self._commands = _Commands(self)
        self._files = _Files(self)

    @classmethod
    def create(
        cls,
        template: str,
        *,
        workload_id: str | None = None,
        env: dict[str, Any] | None = None,
        include: list[str] | None = None,
        tags: dict[str, str] | None = None,
        ttl: str | int | None = None,
        resources: Any = None,
        network: Any = None,
    ) -> "Sandbox":
        """Start a new sandbox session.

        ``template`` resolves to a base image on the Rust side (see
        ``runtime::resolve_base_image``); unknown templates fail at
        lower time, not here, because the wire shape preserves them
        verbatim. ``workload_id`` defaults to the template (the CLI
        overrides with the script's basename when invoked via
        ``mvmctl compile``)."""
        _resolve_mode()  # raises if MVM_SDK_MODE is live/plan/garbage
        global _recording
        if _recording is not None:
            raise RuntimeError(
                "a Sandbox session is already active — call "
                "Sandbox.kill() or exit the `with` block before "
                "creating another. Per the SDK plan's 'v1 scope: "
                "one app per workload' decision, a script may "
                "construct at most one Sandbox."
            )
        if not isinstance(template, str) or not template:
            raise ValueError("template must be a non-empty str")
        ttl_seconds = _parse_ttl(ttl)
        if ttl_seconds is None:
            ttl_seconds = DEFAULT_TTL_SECONDS
        wid = workload_id or template

        create_dict: dict[str, Any] = {
            "template": template,
            "env": _encode_env_map(env),
            "include": list(include) if include else [],
            "tags": dict(tags) if tags else {},
            "ttl_seconds": ttl_seconds,
        }
        if (encoded := _encode_resources(resources)) is not None:
            create_dict["resources"] = encoded
        if (encoded := _encode_network(network)) is not None:
            create_dict["network"] = encoded

        _recording = {
            "workload_id": wid,
            "create": create_dict,
            "ops": [],
        }
        return cls(wid)

    @property
    def workload_id(self) -> str:
        return self._workload_id

    @property
    def commands(self) -> _Commands:
        return self._commands

    @property
    def files(self) -> _Files:
        return self._files

    def kill(self) -> None:
        """Record a ``kill`` op. The Rust lowering drops these (the
        microVM TTL is the orchestrator's job), but the bookkeeping
        is preserved through the recording so tooling can introspect
        intent."""
        _require_recording()
        _recording["ops"].append({"kind": "kill"})

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.kill()


def _require_recording() -> None:
    if _recording is None:
        raise RecordingNotActiveError(
            "Sandbox method called before Sandbox.create() — every "
            "script must construct a Sandbox first."
        )
