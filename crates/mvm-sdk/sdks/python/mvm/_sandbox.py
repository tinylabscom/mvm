"""Sandbox — imperative runtime SDK. SDK port Phase 7b +
Plan 73 Followup H-live.

The decorator surface (``@mvm.app(...)``) is static; the host
parses the source AST and never imports the script. The runtime
surface (``Sandbox.create(...)``) is imperative: the host *does*
execute the user's Python script (per S2 in the SDK plan — a
documented departure), with the SDK reconfigured to either record
each ``Sandbox`` method call into a :class:`RuntimeRecording` or
shell each call to ``mvmctl`` against a real microVM, depending
on the active mode.

Two modes are live:

- ``MVM_SDK_MODE=record`` (the original Phase 7b contract):
  every ``Sandbox`` call appends to an in-process recording. The
  host's ``mvmctl compile`` / ``mvmctl run --mode plan`` verbs
  lower the recording via ``compile_recording``.
- ``MVM_SDK_MODE=live`` (Plan 73 Followup H-live): every
  ``Sandbox`` call shells to ``$MVM_CLI_BIN`` (``mvmctl machine run``,
  ``mvmctl machine proc start``, ``mvmctl fs write``, ``mvmctl machine stop``)
  against a real microVM. The shell is dispatched by
  :class:`_LiveTransport` below.

``MVM_SDK_MODE=plan`` remains an error here — the host's
``mvmctl run --mode plan`` verb is what runs a Sandbox script
under that transport; the SDK itself never enters "plan" mode
directly.

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

import asyncio
import atexit
import base64
import dataclasses
import enum
import json
import os
import re
import secrets
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable

from mvm import _ir
from mvm._cli import MVM_CLI_BIN_ENV, cli_resolution_hint, resolve_cli_bin
from mvm._dsl import literal as _literal_value
# Owned by the Rust registry (crates/mvm-sdk/src/env.rs), generated into
# `_env/vars.py`. Re-exported from this module for existing importers.
from mvm._env.vars import (
    MVM_SDK_MODE_ENV,
    MVM_SDK_OUT_PATH_ENV,
    MVM_SDK_RUN_PROFILE_ENV,
)
from mvm._runtime.runtime import (
    RuntimeFsEntry,
    RuntimeFsStat,
)

__all__ = [
    "DEFAULT_TTL_SECONDS",
    "MVM_CLI_BIN_ENV",
    "MVM_SDK_RUN_PROFILE_ENV",
    "ExecResult",
    "FsEntry",
    "FsStat",
    "ProcessHandle",
    "ProcessResult",
    "ProcessStreamEvent",
    "RecordingNotActiveError",
    "Sandbox",
    "SandboxDevOnly",
    "SandboxLiveError",
    "SandboxModeError",
    "current_recording",
    "emit_recording_json",
    "reset_recording",
]


@dataclass(frozen=True)
class ExecResult:
    """Result of a one-shot ``Sandbox.exec(...)`` call.

    ``exit_code`` is the child's exit code (0 on success). ``stdout``
    and ``stderr`` are captured strings — exec is a one-shot that
    *captures* the streams rather than forwarding them, which is the
    distinction from ``commands.start`` + ``proc wait``."""

    exit_code: int
    stdout: str
    stderr: str


FsEntry = RuntimeFsEntry
FsStat = RuntimeFsStat


@dataclass(frozen=True)
class ProcessStreamEvent:
    """Native Python view of a generated runtime stream event."""

    stream: str
    data: bytes


@dataclass(frozen=True)
class ProcessResult:
    """Native Python view of a generated runtime process result."""

    exit_code: int
    stdout: bytes
    stderr: bytes


class ProcessHandle:
    """Opaque handle for a live development-sandbox process."""

    def __init__(self, transport: "_LiveTransport", token: str) -> None:
        self._transport = transport
        self.token = token

    def wait(
        self,
        *,
        timeout: float | None = None,
        on_event: Callable[[ProcessStreamEvent], None] | None = None,
    ) -> ProcessResult:
        return self._transport.process_wait(self.token, timeout=timeout, on_event=on_event)

    def send_stdin(self, data: bytes | str) -> None:
        payload = data.encode("utf-8") if isinstance(data, str) else data
        self._transport.process_stdin(self.token, payload)

    def signal(self, signum: int) -> None:
        self._transport.process_signal(self.token, signum)

    def kill(self) -> None:
        self._transport.process_kill(self.token)


@dataclass(frozen=True)
class SandboxInfo:
    """Snapshot of a :class:`Sandbox`'s identity + mode (local; no VM round-trip).

    ``id`` is the live VM id when live, else the workload id. ``build_mode``
    is ``"dev"`` / ``"prod"`` when live and ``None`` in record mode."""

    id: str
    workload_id: str
    build_mode: str | None
    live: bool


#: Plan ``Considerations to fold in or defer`` — every
#: ``Sandbox.create()`` sets a default 30-minute TTL so the
#: orchestrator can reap orphaned VMs after a crashed record-mode
#: script.
DEFAULT_TTL_SECONDS = 1800


class SandboxModeError(RuntimeError):
    """Raised when the configured ``MVM_SDK_MODE`` isn't supported by
    this SDK build (e.g. ``MVM_SDK_MODE=plan`` against the in-process
    SDK — plan mode lives in the host CLI, not here)."""


class RecordingNotActiveError(RuntimeError):
    """Raised when a ``Sandbox`` method is called outside a recording
    session (i.e. before ``Sandbox.create`` ran, or after
    :func:`reset_recording`)."""


class SandboxLiveError(RuntimeError):
    """Raised when a live-mode shell to ``mvmctl`` fails. Carries the
    failing argv, exit code, and captured stderr so user scripts can
    see exactly which verb refused and why."""

    def __init__(
        self,
        message: str,
        *,
        argv: list[str] | None = None,
        exit_code: int | None = None,
        stderr: str | None = None,
    ) -> None:
        super().__init__(message)
        self.argv = list(argv) if argv else []
        self.exit_code = exit_code
        self.stderr = stderr or ""


class SandboxDevOnly(SandboxLiveError):
    """Raised when the SDK refuses a live-mode ``commands.start``
    call because the resolved template is a *prod* template.

    The guest agent's runtime profile and signed grant refuse DevOnly
    process-control requests in production. The agent itself fails closed, but the SDK refuses
    *before* any vsock traffic so a user typo doesn't make a
    spurious round-trip. ``commands.start`` is the only Sandbox
    surface that hits ``proc start``; ``files.write`` and
    ``kill`` route to verbs that are available in prod builds
    too."""


# ────────────────────────────────────────────────────────────────────
# Module-global recording state.
#
# The CLI invokes the user's script in a fresh Python process, so a
# module-global is appropriate — one recording per process. Tests
# call :func:`reset_recording` between runs.
# ────────────────────────────────────────────────────────────────────

_recording: dict[str, Any] | None = None

#: Live-mode bookkeeping. Mirrors `_recording`'s "one session per
#: process" invariant — a live Sandbox is stashed here so a second
#: `Sandbox.create(...)` call inside the same process is refused.
_live_sandbox: "Sandbox | None" = None


def _live_sandbox_active() -> bool:
    """Return True if a live-mode Sandbox is currently registered."""
    return _live_sandbox is not None


def _register_live(sb: "Sandbox") -> None:
    """Register a live-mode Sandbox so the one-per-process gate
    fires on a second `Sandbox.create` call."""
    global _live_sandbox
    _live_sandbox = sb


def _clear_live() -> None:
    """Clear the live-mode registration. Called by
    `Sandbox.kill()` so a script that explicitly kills + reopens
    works as expected (the context-manager exit path also
    clears)."""
    global _live_sandbox
    _live_sandbox = None


def reset_recording() -> None:
    """Clear the in-flight recording state and any live registration.
    Tests use this between runs; production never calls it (the
    process exits)."""
    global _recording, _live_sandbox
    _recording = None
    _live_sandbox = None


def current_recording() -> dict[str, Any] | None:
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


def _flush_recording_to_out_path() -> None:
    """`atexit` handler — when ``MVM_SDK_OUT_PATH`` is set and a
    recording is active, write the wire-shape JSON to that path so
    the CLI's auto-exec path can pick it up after the script
    exits.

    No-op when the env var isn't set (the script was run directly
    by a user, not auto-exec'd) or no recording was built (the
    script imported ``mvm`` but never called ``Sandbox.create``).
    Errors are surfaced on stderr but don't raise — the user's
    script has already finished and a print is the most we can
    usefully do here."""
    out_path = os.environ.get(MVM_SDK_OUT_PATH_ENV)
    if not out_path:
        return
    if _recording is None:
        # The CLI distinguishes "no recording emitted" from "file
        # missing" by checking the file's existence: skipping the
        # write keeps that signal clear.
        return
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(_recording, f, separators=(",", ":"), sort_keys=True)
    except OSError as exc:
        print(
            f"mvm-sdk: failed to write recording to {out_path}: {exc}",
            file=sys.stderr,
        )


atexit.register(_flush_recording_to_out_path)


# ────────────────────────────────────────────────────────────────────
# Mode + TTL helpers.
# ────────────────────────────────────────────────────────────────────


def _resolve_mode() -> str:
    """Read ``MVM_SDK_MODE``. Defaults to ``record`` so a bare
    ``python sandbox.py`` invoked by the CLI works without an env
    var.

    Accepts ``record`` (Phase 7b record transport, in-process
    recording) and ``live`` (Plan 73 Followup H-live, shells to
    ``mvmctl``). ``plan`` belongs to the host CLI's
    ``mvmctl run --mode plan`` verb — not a valid value here, so
    we refuse it with an actionable hint."""
    raw = os.environ.get(MVM_SDK_MODE_ENV, "record").strip().lower()
    if raw == "record":
        return "record"
    if raw == "live":
        try:
            resolve_cli_bin(purpose="MVM_SDK_MODE=live")
        except RuntimeError as exc:
            raise SandboxModeError(
                str(exc)
            ) from exc
        return "live"
    if raw == "plan":
        raise SandboxModeError(
            "MVM_SDK_MODE=plan is not a SDK-side transport — the host CLI's "
            "`mvmctl run --mode plan` verb runs your script under record mode and "
            "synthesises ExecutionPlans for admission dry-run. Drop MVM_SDK_MODE and "
            "let `mvmctl run --mode plan` set the recording state for you."
        )
    raise SandboxModeError(
        f"MVM_SDK_MODE={raw!r} is invalid — expected one of: record, live"
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


def _reject_live_option(name: str, reason: str) -> None:
    raise SandboxModeError(
        f"Sandbox live mode cannot represent `{name}` safely: {reason}"
    )


def _format_allow_host(host: Any, port: Any) -> str:
    if not isinstance(host, str) or not host or host in {
        "*",
        "0.0.0.0",
        "::",
        "0.0.0.0/0",
        "::/0",
    }:
        _reject_live_option("network.egress", "allowlist hosts must be specific")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        _reject_live_option("network.egress", "allowlist ports must be 1..65535")
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{rendered_host}:{port}"


def _lower_live_options(
    *,
    env: dict[str, Any] | None,
    include: list[str] | None,
    tags: dict[str, str] | None,
    resources: Any,
    network: Any,
) -> list[str]:
    """Lower the subset with exact CLI equivalents; reject everything else.

    Live mode must never accept an option and then silently boot a different
    workload. Secret references also stay off argv by construction.
    """
    argv: list[str] = []
    encoded_env = _encode_env_map(env)
    for key in sorted(encoded_env):
        value = encoded_env[key]
        if set(value) != {"kind", "value"} or value.get("kind") != "literal":
            _reject_live_option("env", "only literal values can be placed on CLI argv")
        literal = value.get("value")
        if not isinstance(literal, str):
            _reject_live_option("env", "literal values must be strings")
        argv.extend(["--env", f"{key}={literal}"])

    if include:
        _reject_live_option("include", "the live CLI has no source-bundle equivalent")
    if tags:
        _reject_live_option("tags", "the live CLI has no tag equivalent")
    if resources is not None:
        _reject_live_option(
            "resources",
            "rootfs_size_mb has no live CLI equivalent, so partial lowering is refused",
        )

    encoded_network = _encode_network(network)
    if encoded_network is None:
        return argv
    unknown = set(encoded_network) - {
        "mode",
        "egress",
        "ports",
        "peers",
        "dns",
    }
    if unknown:
        _reject_live_option("network", f"unknown fields: {sorted(unknown)}")
    if encoded_network.get("mode", "none") != "none":
        _reject_live_option("network.mode", "only the NIC-less `none` mode is supported")
    if encoded_network.get("peers"):
        _reject_live_option("network.peers", "the live CLI has no peer equivalent")
    if encoded_network.get("dns") is not None:
        _reject_live_option("network.dns", "the live CLI has no DNS equivalent")

    egress = encoded_network.get("egress")
    if egress is None:
        return argv
    if not isinstance(egress, dict) or set(egress) != {"allowlist"}:
        _reject_live_option("network.egress", "expected only an allowlist")
    allowlist = egress.get("allowlist")
    if not isinstance(allowlist, list):
        _reject_live_option("network.egress", "allowlist must be a list")
    for entry in allowlist:
        if not isinstance(entry, dict) or set(entry) != {"host", "port"}:
            _reject_live_option("network.egress", "entries must contain host and port")
        argv.extend(["--allow-host", _format_allow_host(entry["host"], entry["port"])])
    return argv


# ────────────────────────────────────────────────────────────────────
# Sandbox.
# ────────────────────────────────────────────────────────────────────


class _Commands:
    """Namespace for ``sb.commands.*`` methods."""

    def __init__(self, sandbox: "Sandbox") -> None:
        self._sandbox = sandbox

    def start(
        self, argv: list[str], *, env: dict[str, Any] | None = None
    ) -> ProcessHandle | None:
        """Record or shell a ``commands.start(argv, env=...)`` op.

        In record mode the *last* ``commands.start`` in the recording
        becomes the workload's entrypoint; everything earlier
        becomes a ``before_start`` hook in declaration order.

        In live mode the call shells to ``mvmctl proc start <vm>``
        against the running microVM. The SDK refuses with
        :class:`SandboxDevOnly` if the resolved template is a
        prod template (the agent's W4.3 ``do_exec`` strip would
        refuse anyway, but the SDK fails closed first to avoid a
        spurious vsock round-trip — ADR-001 claim 4)."""
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            raise TypeError("argv must be a list[str]")
        if not argv:
            raise ValueError("argv must be non-empty")
        if self._sandbox._live is not None:
            return self._sandbox._live.commands_start(argv, env)
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

    def write(
        self,
        path: str,
        content: bytes | str,
        *,
        mode: int = 0o644,
        create_parents: bool = False,
        follow_symlinks: bool = False,
    ) -> None:
        """Record or shell a ``files.write(path, content)`` op.

        In record mode: ``content`` is bytes (passed through
        verbatim) or str (utf-8 encoded). The recording stores
        base64 so JSON survives any byte content; the Rust lowering
        emits a ``before_start`` shell hook that ``base64 -d``s
        back to the file.

        In live mode: the same bytes stream via stdin into
        ``mvmctl fs write <vm> <path>`` — ``mvmctl fs write``
        already accepts stdin when ``--content`` is omitted."""
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
        if self._sandbox._live is not None:
            self._sandbox._live.files_write(
                path,
                data,
                mode=mode,
                create_parents=create_parents,
                follow_symlinks=follow_symlinks,
            )
            return
        _require_recording()
        _recording["ops"].append(
            {
                "kind": "files_write",
                "path": path,
                "bytes_b64": base64.standard_b64encode(data).decode("ascii"),
            }
        )

    def read(
        self,
        path: str,
        *,
        offset: int = 0,
        length: int = 16 * 1024 * 1024,
    ) -> bytes:
        self._require_live("files.read")
        return self._sandbox._live.files_read(path, offset=offset, length=length)

    def list(self, path: str) -> list[FsEntry]:
        self._require_live("files.list")
        return self._sandbox._live.files_list(path)

    def stat(self, path: str, *, follow_symlinks: bool = True) -> FsStat:
        self._require_live("files.stat")
        return self._sandbox._live.files_stat(path, follow_symlinks=follow_symlinks)

    def mkdir(self, path: str, *, parents: bool = False, mode: int = 0o755) -> None:
        self._require_live("files.mkdir")
        self._sandbox._live.files_mkdir(path, parents=parents, mode=mode)

    def remove(self, path: str, *, recursive: bool = False) -> None:
        self._require_live("files.remove")
        self._sandbox._live.files_remove(path, recursive=recursive)

    def move(self, source: str, destination: str) -> None:
        self._require_live("files.move")
        self._sandbox._live.files_move(source, destination)

    def _require_live(self, operation: str) -> None:
        if self._sandbox._live is None:
            raise SandboxModeError(
                f"`{operation}` is a live-mode operation; record mode cannot "
                "resolve guest filesystem state."
            )


class _LiveTransport:
    """Live-mode transport — shells each Sandbox call to the host's
    ``mvmctl`` binary.

    Created by :meth:`Sandbox.create` when ``MVM_SDK_MODE=live``.
    Holds the resolved ``mvmctl`` binary path, the generated
    ``vm_id``, and the template's ``build_mode`` ("dev" / "prod")
    parsed from ``mvmctl machine run --up-json``'s stdout envelope. The
    ``build_mode`` is what the SDK uses to enforce the W4.3
    dev-only ``proc start`` rule client-side."""

    SCHEMA_VERSION = 1

    def __init__(
        self,
        *,
        mvm_cli_bin: str,
        vm_id: str,
        build_mode: str,
    ) -> None:
        self.mvm_cli_bin = mvm_cli_bin
        self.vm_id = vm_id
        self.build_mode = build_mode
        self._killed = False
    @classmethod
    def for_source(
        cls,
        *,
        source_kind: str,
        source: str,
        workload_id: str,
        ttl_seconds: int,
        create_args: list[str],
        boot_command: list[str] | None,
        ports: list[dict[str, Any]],
    ) -> "_LiveTransport":
        """Run ``mvmctl machine run`` with a typed boot source and parse its
        JSON envelope. Raises
        :class:`SandboxLiveError` on any failure."""
        try:
            mvm_cli_bin = resolve_cli_bin(purpose="Sandbox live mode")
        except RuntimeError as exc:
            raise SandboxModeError(str(exc)) from exc
        # Generate a short, validatable VM id. `mvmctl machine run` rejects
        # names that don't match its validator; alphanumerics with
        # a hyphen are safe.
        suffix = secrets.token_hex(4)
        vm_id = f"sdk-{workload_id[:24]}-{suffix}".lower()
        vm_id = "".join(c if (c.isalnum() or c == "-") else "-" for c in vm_id)

        argv = [
            mvm_cli_bin,
            "machine",
            "run",
        ]
        if not ports:
            argv.append("-d")
        argv.extend(["--up-json", "--name", vm_id])
        profile = os.environ.get(MVM_SDK_RUN_PROFILE_ENV)
        if profile is not None:
            profile = profile.strip().lower()
            if profile not in {"restrictive", "standard", "dev", "permissive"}:
                raise SandboxModeError(
                    f"{MVM_SDK_RUN_PROFILE_ENV}={profile!r} is invalid — expected one of: "
                    "restrictive, standard, dev, permissive"
                )
            argv.extend(["--profile", profile])
        argv.extend(["--manifest" if source_kind == "manifest" else "--image", source])
        argv.extend(create_args)
        argv.extend(["--ttl", f"{ttl_seconds}s"])
        for port in ports:
            if (
                port.get("proto") != "tcp"
                or port.get("transform") != "opaque"
                or port.get("host_addr") != "127.0.0.1"
                or port.get("guest_addr") != "127.0.0.1"
            ):
                raise SandboxModeError(
                    "Sandbox live mode currently accepts only opaque TCP ingress "
                    "bound to host and guest 127.0.0.1"
                )
            argv.extend(["--port", f"{port['host']}:{port['guest']}"])
        if boot_command is not None:
            argv.append("--")
            argv.extend(boot_command)
        try:
            result = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{mvm_cli_bin}` not found on disk; {cli_resolution_hint()}",
                argv=argv,
            ) from exc

        if result.returncode != 0:
            raise SandboxLiveError(
                f"`mvmctl machine run` failed with exit code {result.returncode}",
                argv=argv,
                exit_code=result.returncode,
                stderr=result.stderr,
            )

        envelope = _parse_up_envelope(result.stdout, argv=argv)
        return cls(
            mvm_cli_bin=mvm_cli_bin,
            vm_id=envelope["vm_id"],
            build_mode=envelope["build_mode"],
        )

    @classmethod
    def for_existing(cls, *, vm_id: str) -> "_LiveTransport":
        """Attach to an already-running machine by name.

        Shells ``mvmctl machine ls --json`` and re-derives the
        machine's ``build_mode`` from its listing entry — the attach
        path never boots, so there is no ``--up-json`` envelope to
        read it from. Fails closed: only an explicit
        ``build_mode == "dev"`` unlocks the dev-only exec path; a
        prod / missing / unknown value resolves to ``"prod"`` so the
        same guard that protects :meth:`for_template` also protects
        the attach path (security claim 4). Raises
        :class:`SandboxLiveError` when no machine of that name is
        listed (there is nothing to attach to)."""
        try:
            mvm_cli_bin = resolve_cli_bin(purpose="Sandbox.connect")
        except RuntimeError as exc:
            raise SandboxModeError(str(exc)) from exc
        argv = [mvm_cli_bin, "machine", "ls", "--json"]
        try:
            result = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{mvm_cli_bin}` not found on disk; {cli_resolution_hint()}",
                argv=argv,
            ) from exc
        if result.returncode != 0:
            raise SandboxLiveError(
                f"`mvmctl machine ls --json` failed with exit code {result.returncode}",
                argv=argv,
                exit_code=result.returncode,
                stderr=result.stderr,
            )
        build_mode = _derive_attached_build_mode(
            result.stdout, vm_id=vm_id, argv=argv
        )
        return cls(mvm_cli_bin=mvm_cli_bin, vm_id=vm_id, build_mode=build_mode)

    def commands_start(
        self, argv: list[str], env: dict[str, Any] | None
    ) -> ProcessHandle:
        """Shell ``mvmctl proc start <vm> -e ... -- <argv>``.

        Refuses with :class:`SandboxDevOnly` when the resolved
        template is prod (ADR-001 §W4.3, claim 4). The agent fails
        closed anyway; the SDK refuses first so a typo doesn't
        emit a spurious vsock request."""
        if self.build_mode != "dev":
            raise SandboxDevOnly(
                f"`commands.start` requires a dev-mode template; resolved template "
                f"build_mode={self.build_mode!r}. ADR-001 §W4.3 (security claim 4) "
                f"strips the agent's `do_exec` handler in prod builds — re-build the "
                f"template with `mvmctl template build --dev <name>`, or use "
                f"`files.write` to stage inputs into the running VM instead.",
                argv=["machine", "proc", "start", self.vm_id, *argv],
            )
        shell = [self.mvm_cli_bin, "machine", "proc", "start", self.vm_id]
        if env:
            # `mvmctl machine proc start` expects `-e KEY=VALUE` pairs.
            # We only forward literal env values in live mode;
            # secret_ref values would need the host keystore round-trip
            # the orchestrator owns.
            for key, value in env.items():
                if isinstance(value, str):
                    shell += ["-e", f"{key}={value}"]
                elif isinstance(value, dict) and value.get("kind") == "literal":
                    shell += ["-e", f"{key}={value['value']}"]
                else:
                    # secret_ref / unknown — refuse rather than leak.
                    raise SandboxLiveError(
                        f"`commands.start` env {key!r} carries a non-literal value; "
                        f"live mode only forwards literal env vars (secrets must be "
                        f"injected via the host keystore + `--secret` on `mvmctl machine run`).",
                        argv=shell,
                    )
        shell += ["--", *argv]
        return self._start_process(shell)

    def _require_dev(self, operation: str, argv: list[str]) -> None:
        if self.build_mode != "dev":
            raise SandboxDevOnly(
                f"`{operation}` requires a dev-mode template; resolved template "
                f"build_mode={self.build_mode!r}. The guest policy refuses this "
                "runtime operation on production templates.",
                argv=argv,
            )

    def _start_process(self, shell: list[str]) -> ProcessHandle:
        try:
            result = subprocess.run(shell, check=False, capture_output=True, text=True)
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; {cli_resolution_hint()}",
                argv=shell,
            ) from exc
        if result.returncode != 0:
            raise SandboxLiveError(
                f"`mvmctl machine proc start` failed with exit code {result.returncode}",
                argv=shell,
                exit_code=result.returncode,
                stderr=result.stderr,
            )
        token = result.stdout.strip()
        if not token:
            raise SandboxLiveError(
                "`mvmctl machine proc start` produced no pid_token on stdout",
                argv=shell,
                stderr=result.stderr,
            )
        return ProcessHandle(self, token)

    def commands_exec(
        self,
        argv: list[str],
        env: dict[str, Any] | None,
        *,
        timeout: float | None = None,
        cwd: str | None = None,
    ) -> ExecResult:
        """One-shot exec: shell ``mvmctl proc start ... -- argv`` to
        obtain a ``pid_token``, then ``mvmctl proc wait <pid_token>``
        to capture stdout/stderr/exit. Refuses with
        :class:`SandboxDevOnly` when the resolved template is prod
        (matches ``commands_start``'s policy — ADR-001 §W4.3, claim
        4)."""
        self._require_dev("exec", ["machine", "proc", "start", self.vm_id, *argv])

        # 1) `proc start` → pid_token on stdout.
        start_shell: list[str] = [self.mvm_cli_bin, "machine", "proc", "start", self.vm_id]
        if env:
            for key, value in env.items():
                if isinstance(value, str):
                    start_shell += ["-e", f"{key}={value}"]
                elif isinstance(value, dict) and value.get("kind") == "literal":
                    start_shell += ["-e", f"{key}={value['value']}"]
                else:
                    raise SandboxLiveError(
                        f"`exec` env {key!r} carries a non-literal value; live mode "
                        f"only forwards literal env vars (secrets must be injected via "
                        f"the host keystore + `--secret` on `mvmctl machine run`).",
                        argv=start_shell,
                    )
        if cwd is not None:
            start_shell += ["--cwd", cwd]
        start_shell += ["--", *argv]
        result = self._start_process(start_shell).wait(timeout=timeout)
        return ExecResult(
            exit_code=result.exit_code,
            stdout=result.stdout.decode("utf-8", errors="replace"),
            stderr=result.stderr.decode("utf-8", errors="replace"),
        )

    def process_wait(
        self,
        token: str,
        *,
        timeout: float | None = None,
        on_event: Callable[[ProcessStreamEvent], None] | None = None,
    ) -> ProcessResult:
        self._require_dev("process wait", ["machine", "proc", "wait", self.vm_id, token])
        shell = [self.mvm_cli_bin, "machine", "proc", "wait", self.vm_id, token]
        if timeout is not None:
            shell += ["--timeout", str(int(timeout))]
        try:
            proc = subprocess.Popen(shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; {cli_resolution_hint()}",
                argv=shell,
            ) from exc
        chunks: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}

        def drain(stream: str, source: Any) -> None:
            while chunk := source.read(65536):
                chunks[stream].extend(chunk)
                if on_event is not None:
                    on_event(ProcessStreamEvent(stream, chunk))

        readers = [
            threading.Thread(target=drain, args=(name, source), daemon=True)
            for name, source in (("stdout", proc.stdout), ("stderr", proc.stderr))
            if source is not None
        ]
        for reader in readers:
            reader.start()
        try:
            proc.wait(timeout=timeout + 5 if timeout is not None else None)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            raise SandboxLiveError(
                "`mvmctl machine proc wait` did not return before its timeout",
                argv=shell,
            ) from exc
        for reader in readers:
            reader.join()
        return ProcessResult(proc.returncode, bytes(chunks["stdout"]), bytes(chunks["stderr"]))

    def process_stdin(self, token: str, data: bytes) -> None:
        self._require_dev("process stdin", ["machine", "proc", "stdin", self.vm_id, token])
        self._run_bytes([self.mvm_cli_bin, "machine", "proc", "stdin", self.vm_id, token], data)

    def process_signal(self, token: str, signum: int) -> None:
        if not isinstance(signum, int) or isinstance(signum, bool) or signum <= 0:
            raise ValueError("signum must be a positive integer")
        self._require_dev("process signal", ["machine", "proc", "signal", self.vm_id, token])
        self._run_shell([self.mvm_cli_bin, "machine", "proc", "signal", self.vm_id, token, str(signum)])

    def process_kill(self, token: str) -> None:
        self._require_dev("process kill", ["machine", "proc", "kill", self.vm_id, token])
        self._run_shell([self.mvm_cli_bin, "machine", "proc", "kill", self.vm_id, token])

    def _run_bytes(self, shell: list[str], data: bytes) -> None:
        try:
            result = subprocess.run(shell, input=data, check=False, capture_output=True)
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; {cli_resolution_hint()}",
                argv=shell,
            ) from exc
        if result.returncode != 0:
            raise SandboxLiveError(
                f"`{' '.join(shell)}` failed with exit code {result.returncode}",
                argv=shell,
                exit_code=result.returncode,
                stderr=result.stderr.decode("utf-8", errors="replace"),
            )

    def _run_json(self, shell: list[str]) -> Any:
        try:
            result = subprocess.run(shell, check=False, capture_output=True, text=True)
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; {cli_resolution_hint()}",
                argv=shell,
            ) from exc
        if result.returncode != 0:
            raise SandboxLiveError(
                f"`{' '.join(shell)}` failed with exit code {result.returncode}",
                argv=shell,
                exit_code=result.returncode,
                stderr=result.stderr,
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxLiveError(
                f"`{' '.join(shell)}` returned invalid JSON: {exc.msg}",
                argv=shell,
                stderr=result.stdout,
            ) from exc

    def files_write(
        self,
        path: str,
        data: bytes,
        *,
        mode: int = 0o644,
        create_parents: bool = False,
        follow_symlinks: bool = False,
    ) -> None:
        """Shell ``mvmctl fs write <vm> <path>`` with the file
        bytes piped through stdin. The mvmctl verb accepts stdin
        when ``--content`` is omitted."""
        self._require_dev("files.write", ["machine", "fs", "write", self.vm_id, path])
        shell = [self.mvm_cli_bin, "machine", "fs", "write", self.vm_id, path, "--mode", str(mode)]
        if create_parents:
            shell.append("--create-parents")
        if follow_symlinks:
            shell.append("--follow-symlinks")
        self._run_bytes(shell, data)

    def files_read(self, path: str, *, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        self._require_dev("files.read", ["machine", "fs", "read", self.vm_id, path])
        shell = [
            self.mvm_cli_bin, "machine", "fs", "read", self.vm_id, path,
            "--offset", str(offset), "--length", str(length),
        ]
        try:
            result = subprocess.run(shell, check=False, capture_output=True)
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; {cli_resolution_hint()}", argv=shell
            ) from exc
        if result.returncode != 0:
            raise SandboxLiveError(
                f"`{' '.join(shell)}` failed with exit code {result.returncode}",
                argv=shell,
                exit_code=result.returncode,
                stderr=result.stderr.decode("utf-8", errors="replace"),
            )
        return result.stdout

    def files_list(self, path: str) -> list[FsEntry]:
        self._require_dev("files.list", ["machine", "fs", "ls", self.vm_id, path])
        parsed = self._run_json([self.mvm_cli_bin, "machine", "fs", "ls", self.vm_id, path, "--json"])
        if not isinstance(parsed, list):
            raise SandboxLiveError("filesystem listing must be a JSON array")
        try:
            return [FsEntry(name=item["name"], kind=item["kind"], size=int(item["size"])) for item in parsed]
        except (KeyError, TypeError, ValueError) as exc:
            raise SandboxLiveError("filesystem listing returned an invalid payload") from exc

    def files_stat(self, path: str, *, follow_symlinks: bool) -> FsStat:
        self._require_dev("files.stat", ["machine", "fs", "stat", self.vm_id, path])
        shell = [self.mvm_cli_bin, "machine", "fs", "stat", self.vm_id, path, "--json"]
        if not follow_symlinks:
            shell.append("--no-follow")
        parsed = self._run_json(shell)
        if not isinstance(parsed, dict):
            raise SandboxLiveError("filesystem stat must be a JSON object")
        try:
            return FsStat(
                canonical_path=parsed["canonical_path"],
                kind=parsed["kind"],
                mode=int(parsed["mode"]),
                size=int(parsed["size"]),
                mtime=parsed.get("mtime"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SandboxLiveError("filesystem stat returned an invalid payload") from exc

    def files_mkdir(self, path: str, *, parents: bool, mode: int) -> None:
        self._require_dev("files.mkdir", ["machine", "fs", "mkdir", self.vm_id, path])
        shell = [self.mvm_cli_bin, "machine", "fs", "mkdir", self.vm_id, path, "--mode", str(mode)]
        if parents:
            shell.append("--parents")
        self._run_shell(shell)

    def files_remove(self, path: str, *, recursive: bool) -> None:
        self._require_dev("files.remove", ["machine", "fs", "rm", self.vm_id, path])
        shell = [self.mvm_cli_bin, "machine", "fs", "rm", self.vm_id, path]
        if recursive:
            shell.append("--recursive")
        self._run_shell(shell)

    def files_move(self, source: str, destination: str) -> None:
        self._require_dev("files.move", ["machine", "fs", "mv", self.vm_id, source, destination])
        self._run_shell([self.mvm_cli_bin, "machine", "fs", "mv", self.vm_id, source, destination])

    def cp(self, source: str, destination: str) -> None:
        """Shell ``mvmctl cp <source> <destination>``. Endpoints use
        ``VM:/absolute/path`` for the guest side; `mvmctl machine cp` reads the
        host file and streams it over the agent fs RPC (and back)."""
        self._require_dev("copy", ["machine", "cp", source, destination])
        shell = [self.mvm_cli_bin, "machine", "cp", source, destination]
        try:
            result = subprocess.run(shell, check=False, capture_output=True)
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; {cli_resolution_hint()}",
                argv=shell,
            ) from exc
        if result.returncode != 0:
            raise SandboxLiveError(
                f"`mvmctl machine cp` failed with exit code {result.returncode}",
                argv=shell,
                exit_code=result.returncode,
                stderr=result.stderr.decode("utf-8", errors="replace"),
            )

    def kill(self) -> None:
        """Shell ``mvmctl machine stop <vm>``. Idempotent — repeated kills
        from the context manager + an explicit `sb.kill()` are
        coalesced so we don't trip on a double-down."""
        if self._killed:
            return
        self._killed = True
        # `--yes` skips the interactive confirmation prompt; the sandbox tears
        # down non-interactively.
        shell = [self.mvm_cli_bin, "machine", "stop", self.vm_id, "--yes"]
        try:
            result = subprocess.run(
                shell,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; {cli_resolution_hint()}",
                argv=shell,
            ) from exc
        if result.returncode != 0:
            # Print but don't raise — kill is the cleanup path; a
            # failure here usually means the VM was already torn
            # down by the orchestrator's TTL reaper.
            sys.stderr.write(
                f"mvm-sdk live: `mvmctl machine stop {self.vm_id}` exited "
                f"with {result.returncode}: {result.stderr}\n"
            )

    def _run_shell(self, shell: list[str]) -> None:
        try:
            result = subprocess.run(
                shell,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; {cli_resolution_hint()}",
                argv=shell,
            ) from exc
        # Mirror the SDK's "user prints to their own stdout"
        # contract: the wrapped verbs' stdout is the SDK's value
        # for the call (e.g. proc start prints a pid token), so
        # forward it verbatim. stderr goes to our stderr.
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        if result.returncode != 0:
            raise SandboxLiveError(
                f"`{' '.join(shell)}` failed with exit code {result.returncode}",
                argv=shell,
                exit_code=result.returncode,
                stderr=result.stderr,
            )


def _parse_up_envelope(stdout: str, *, argv: list[str]) -> dict[str, str]:
    """Parse ``mvmctl machine run --up-json`` stdout. The envelope is a single
    JSON line; trailing newlines tolerated. Raises
    :class:`SandboxLiveError` if the envelope is malformed."""
    line = stdout.strip()
    if not line:
        raise SandboxLiveError(
            "`mvmctl machine run --up-json` produced empty stdout — expected a JSON envelope.",
            argv=argv,
        )
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SandboxLiveError(
            f"`mvmctl machine run --up-json` stdout is not valid JSON: {exc.msg}",
            argv=argv,
            stderr=line,
        ) from exc
    if not isinstance(parsed, dict):
        raise SandboxLiveError(
            f"`mvmctl machine run --up-json` envelope must be a JSON object; got {type(parsed).__name__}",
            argv=argv,
        )
    schema = parsed.get("schema_version")
    if schema != _LiveTransport.SCHEMA_VERSION:
        raise SandboxLiveError(
            f"`mvmctl machine run --up-json` envelope schema_version={schema!r}; "
            f"SDK supports {_LiveTransport.SCHEMA_VERSION}",
            argv=argv,
        )
    vm_id = parsed.get("vm_id")
    build_mode = parsed.get("build_mode")
    if not isinstance(vm_id, str) or not vm_id:
        raise SandboxLiveError(
            "`mvmctl machine run --up-json` envelope is missing a non-empty `vm_id` field.",
            argv=argv,
        )
    if build_mode not in ("dev", "prod"):
        raise SandboxLiveError(
            f"`mvmctl machine run --up-json` envelope build_mode={build_mode!r}; "
            f"expected 'dev' or 'prod'.",
            argv=argv,
        )
    return {"vm_id": vm_id, "build_mode": build_mode}


def _derive_attached_build_mode(
    stdout: str, *, vm_id: str, argv: list[str]
) -> str:
    """Re-derive ``build_mode`` for an attached machine from
    ``mvmctl machine ls --json`` output.

    The listing is a JSON array of machine entries; we match on the
    ``name`` field. Fail-closed by construction: only an explicit
    ``"dev"`` returns ``"dev"``; a ``"prod"`` / missing / unknown
    value returns ``"prod"``, so a stale or hostile listing can never
    *open* the dev-only exec path — it can only keep it shut. Raises
    :class:`SandboxLiveError` when ``vm_id`` is absent from the
    listing (there is nothing to attach to)."""
    line = stdout.strip()
    if not line:
        raise SandboxLiveError(
            f"`mvmctl machine ls --json` produced no output; cannot attach to {vm_id!r}.",
            argv=argv,
        )
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SandboxLiveError(
            f"`mvmctl machine ls --json` stdout is not valid JSON: {exc.msg}",
            argv=argv,
            stderr=line,
        ) from exc
    if not isinstance(parsed, list):
        raise SandboxLiveError(
            f"`mvmctl machine ls --json` must be a JSON array; got "
            f"{type(parsed).__name__}",
            argv=argv,
        )
    for entry in parsed:
        if isinstance(entry, dict) and entry.get("name") == vm_id:
            return "dev" if entry.get("build_mode") == "dev" else "prod"
    raise SandboxLiveError(
        f"no machine named {vm_id!r} in `mvmctl machine ls`; is it running?",
        argv=argv,
    )


class Sandbox:
    """A recordable / live handle for an imperative ``Sandbox``
    script.

    Construct via :meth:`Sandbox.create`. Under ``MVM_SDK_MODE=record``
    the constructor sets up an in-process recording; under
    ``MVM_SDK_MODE=live`` it shells ``mvmctl machine run`` to boot a real
    microVM and stashes the resulting handle on
    ``self._live``. Supports context-manager usage; ``__exit__``
    issues a ``kill`` (record-mode: appends a kill op; live-mode:
    shells ``mvmctl machine stop``)."""

    def __init__(
        self,
        workload_id: str,
        *,
        live: "_LiveTransport | None" = None,
    ) -> None:
        self._workload_id = workload_id
        self._commands = _Commands(self)
        self._files = _Files(self)
        self._live = live

    @classmethod
    def create(
        cls,
        template: str | None = None,
        *,
        image: str | None = None,
        workload_id: str | None = None,
        env: dict[str, Any] | None = None,
        include: list[str] | None = None,
        tags: dict[str, str] | None = None,
        ttl: str | int | None = None,
        resources: Any = None,
        network: Any = None,
        command: list[str] | None = None,
    ) -> "Sandbox":
        """Start a new sandbox session.

        ``template`` resolves to a base image on the Rust side (see
        ``runtime::resolve_base_image``); in record mode unknown
        templates fail at lower time, not here, because the wire
        shape preserves them verbatim. In live mode unknown
        templates fail when ``mvmctl machine run --manifest <template>``
        rejects them — that failure surfaces as
        :class:`SandboxLiveError` here.

        ``template`` selects a manifest/template source; ``image`` selects an
        OCI source. Exactly one must be provided. ``command`` overrides the
        OCI image command in live mode and records the same entrypoint in
        record mode.

        ``workload_id`` defaults to the resolved template (the CLI
        overrides with the script's basename when invoked via
        ``mvmctl compile``)."""
        mode = _resolve_mode()  # raises if MVM_SDK_MODE is invalid
        global _recording
        if _recording is not None or _live_sandbox_active():
            raise RuntimeError(
                "a Sandbox session is already active — call "
                "Sandbox.kill() or exit the `with` block before "
                "creating another. Per the SDK plan's 'v1 scope: "
                "one app per workload' decision, a script may "
                "construct at most one Sandbox."
            )
        if template is None and image is None:
            raise ValueError(
                "Sandbox.create requires `template` (positional) or `image` (keyword)"
            )
        if template is not None and image is not None:
            raise ValueError(
                "Sandbox.create accepts `template` OR `image`, not both"
            )
        source = template if template is not None else image
        if not isinstance(source, str) or not source:
            raise ValueError(
                "template/image must be a non-empty str"
            )
        if command is not None:
            if not isinstance(command, list) or not command or not all(
                isinstance(arg, str) and arg for arg in command
            ):
                raise ValueError("command must be a non-empty list[str]")
            command = list(command)
        ttl_seconds = _parse_ttl(ttl)
        if ttl_seconds is None:
            ttl_seconds = DEFAULT_TTL_SECONDS
        wid = workload_id or source

        if mode == "live":
            create_args = _lower_live_options(
                env=env,
                include=include,
                tags=tags,
                resources=resources,
                network=network,
            )
            live = _LiveTransport.for_source(
                source_kind="manifest" if template is not None else "image",
                source=source,
                workload_id=wid,
                ttl_seconds=ttl_seconds,
                create_args=create_args,
                boot_command=command,
                ports=list((_encode_network(network) or {}).get("ports", [])),
            )
            sb = cls(wid, live=live)
            _register_live(sb)
            return sb

        # record mode (existing path).
        create_dict: dict[str, Any] = {
            "template" if template is not None else "image": source,
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
            "ops": (
                [{"kind": "command_start", "argv": command, "env": {}}]
                if command is not None
                else []
            ),
        }
        return cls(wid)

    @classmethod
    def connect(cls, id: str) -> "Sandbox":
        """Attach to an already-running machine by name, from a fresh
        process.

        Unlike :meth:`create`, ``connect`` never boots a VM — it binds
        to a machine that is already up. Because it does not boot, it
        has no ``--up-json`` envelope to read the machine's
        ``build_mode`` from, so it re-derives it from
        ``mvmctl machine ls --json`` (see
        :meth:`_LiveTransport.for_existing`).

        The dev-only exec guard is inherited unchanged: the derived
        ``build_mode`` is never defaulted to ``"dev"`` — a prod /
        missing / unknown value resolves to ``"prod"``, so
        ``connect(...).exec(...)`` / ``.commands.start(...)`` on a
        sealed prod machine raises :class:`SandboxDevOnly` exactly like
        the ``create`` path (security claim 4).

        Always a live operation: it resolves the mvm CLI regardless of
        ``MVM_SDK_MODE`` (attaching to a running VM has no record-mode
        meaning). Raises :class:`SandboxLiveError` when no machine of
        that name is listed."""
        if not isinstance(id, str) or not id:
            raise ValueError("Sandbox.connect requires a non-empty machine id")
        if _recording is not None or _live_sandbox_active():
            raise RuntimeError(
                "a Sandbox session is already active — call "
                "Sandbox.kill() or exit the `with` block before "
                "attaching to another machine."
            )
        live = _LiveTransport.for_existing(vm_id=id)
        sb = cls(id, live=live)
        _register_live(sb)
        return sb

    @property
    def workload_id(self) -> str:
        return self._workload_id

    @property
    def id(self) -> str:
        """Stable identifier: the live VM id when live, else the workload id."""
        return self._live.vm_id if self._live is not None else self._workload_id

    def info(self) -> SandboxInfo:
        """Local snapshot of this sandbox's identity + mode (no VM round-trip)."""
        return SandboxInfo(
            id=self.id,
            workload_id=self._workload_id,
            build_mode=self._live.build_mode if self._live is not None else None,
            live=self._live is not None,
        )

    @property
    def commands(self) -> _Commands:
        return self._commands

    @property
    def files(self) -> _Files:
        return self._files

    def exec(
        self,
        *argv: str,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict[str, Any] | None = None,
    ) -> ExecResult:
        """One-shot: run ``argv`` inside the sandbox, collect
        stdout/stderr/exit, return :class:`ExecResult`.

        Convenience over ``commands.start`` + the underlying
        ``mvmctl proc wait`` round-trip. Refuses with
        :class:`SandboxDevOnly` when the resolved template is prod
        (ADR-001 §W4.3, claim 4) — no silent fallback.

        Live mode only: in record mode the call raises
        :class:`SandboxModeError` because the recording's lowering
        doesn't materialise return values (use ``commands.start``
        to append an op for later execution).

        Example::

            with Sandbox.create(image="python:slim") as sb:
                r = sb.exec("python", "-c", "print(2 + 2)")
                assert r.exit_code == 0
                assert r.stdout.strip() == "4"
        """
        if not argv:
            raise ValueError("exec requires at least one argv element")
        if not all(isinstance(a, str) for a in argv):
            raise TypeError("exec argv must all be str")
        if self._live is None:
            raise SandboxModeError(
                "`Sandbox.exec` is a live-mode operation; under "
                "MVM_SDK_MODE=record use `commands.start(argv)` to "
                "append an op (return values are materialised when "
                "the recording is lowered, not at call time)."
            )
        return self._live.commands_exec(list(argv), env, timeout=timeout, cwd=cwd)

    async def aexec(
        self,
        *argv: str,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict[str, Any] | None = None,
    ) -> ExecResult:
        """Async face of :meth:`exec` — same one-shot semantics, awaitable
        for use inside ``async with Sandbox.create(...) as sb``. One impl,
        two faces: it runs the blocking :meth:`exec` in a worker thread
        (``asyncio.to_thread``), so `SandboxDevOnly` / `SandboxModeError` /
        the captured `ExecResult` all behave identically."""
        return await asyncio.to_thread(
            self.exec, *argv, timeout=timeout, cwd=cwd, env=env
        )

    def shell(
        self,
        command: str,
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict[str, Any] | None = None,
    ) -> ExecResult:
        """Run shell syntax in a live development sandbox."""
        if not isinstance(command, str) or not command:
            raise ValueError("shell command must be a non-empty str")
        return self.exec("/bin/sh", "-lc", command, timeout=timeout, cwd=cwd, env=env)

    def copy_in(self, host_path: str, guest_path: str) -> None:
        """Copy a host file into the running sandbox at ``guest_path``.

        Shells ``mvmctl cp <host_path> <vm>:<guest_path>`` — the host
        file streams into the guest over the agent fs RPC.

        Live mode only: in record mode this raises
        :class:`SandboxModeError`. To stage a file declaratively for a
        recorded workload, use ``files.write(guest_path, content)``.
        """
        if not isinstance(host_path, str) or not host_path:
            raise ValueError("host_path must be a non-empty str")
        if not isinstance(guest_path, str) or not guest_path:
            raise ValueError("guest_path must be a non-empty str")
        if self._live is None:
            raise SandboxModeError(
                "`Sandbox.copy_in` is a live-mode operation; under "
                "MVM_SDK_MODE=record use `files.write(path, content)` to "
                "stage a file declaratively."
            )
        self._live.cp(host_path, f"{self._live.vm_id}:{guest_path}")

    def copy_out(self, guest_path: str, host_path: str) -> None:
        """Copy a file out of the running sandbox to ``host_path``.

        Shells ``mvmctl cp <vm>:<guest_path> <host_path>`` — the guest
        file streams back over the agent fs RPC.

        Live mode only: pulling a file out of a running VM has no
        record-mode meaning, so in record mode this raises
        :class:`SandboxModeError`.
        """
        if not isinstance(guest_path, str) or not guest_path:
            raise ValueError("guest_path must be a non-empty str")
        if not isinstance(host_path, str) or not host_path:
            raise ValueError("host_path must be a non-empty str")
        if self._live is None:
            raise SandboxModeError(
                "`Sandbox.copy_out` is a live-mode operation; it pulls a "
                "file from a running VM and has no record-mode meaning."
            )
        self._live.cp(f"{self._live.vm_id}:{guest_path}", host_path)

    def forward(self, host_port: int, guest_port: int) -> None:
        """Refuse dynamic ingress changes after admission.

        Declare the mapping with ``network=mvm.network(ports=[...])`` when
        creating the sandbox so it is covered by the signed admission plan.
        """
        if not isinstance(host_port, int) or isinstance(host_port, bool):
            raise TypeError("host_port must be an int")
        if not isinstance(guest_port, int) or isinstance(guest_port, bool):
            raise TypeError("guest_port must be an int")
        if not (0 < host_port < 65536) or not (0 < guest_port < 65536):
            raise ValueError("ports must be in 1..65535")
        raise SandboxModeError(
            "dynamic `Sandbox.forward` is retired; declare ingress with "
            "`Sandbox.create(..., network=mvm.network(ports=[...]))` before boot"
        )

    def kill(self) -> None:
        """Issue a ``kill`` against the active transport.

        In record mode, appends a ``kill`` op (the Rust lowering
        drops these; the microVM TTL is the orchestrator's job, but
        the bookkeeping is preserved through the recording so
        tooling can introspect intent). In live mode, shells
        ``mvmctl machine stop <vm>``."""
        if self._live is not None:
            self._live.kill()
            _clear_live()
            return
        _require_recording()
        _recording["ops"].append({"kind": "kill"})

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.kill()

    async def __aenter__(self) -> "Sandbox":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        # Same teardown as `__exit__`, off the event loop so a slow
        # `mvmctl machine stop` doesn't block the caller's loop.
        await asyncio.to_thread(self.kill)


def _require_recording() -> None:
    if _recording is None:
        raise RecordingNotActiveError(
            "Sandbox method called before Sandbox.create() — every "
            "script must construct a Sandbox first."
        )
