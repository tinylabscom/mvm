"""Sandbox — the imperative runtime SDK.

The decorator surface (``@mvm.app(...)``) is static; the host parses the
source AST and never imports the script. The runtime surface
(``Sandbox.create(...)``) is imperative: the host *does* execute the user's
Python script, with the SDK configured either to record each ``Sandbox``
method call into a runtime recording or to carry it out against a real
microVM, depending on the active mode.

Two modes are live:

- ``MVM_SDK_MODE=record`` (the default): every ``Sandbox`` call appends to an
  in-process recording. The host's ``mvmctl build compile`` /
  ``mvmctl run --mode plan`` verbs lower the recording via
  ``compile_recording``.
- ``MVM_SDK_MODE=live``: every ``Sandbox`` call goes to the host library,
  loaded in-process (see ``mvm._hostlib``), against a real microVM. The
  library runs the same admission, audit and guest-agent paths the CLI does,
  so a sandbox booted here is admitted exactly like one booted from a shell.

``MVM_SDK_MODE=plan`` remains an error here — the host's
``mvmctl run --mode plan`` verb is what runs a Sandbox script under that
transport; the SDK itself never enters "plan" mode directly.

Wire shape (matches the Rust ``RuntimeRecording`` serde types,
``deny_unknown_fields`` on both sides — a typo'd field name fails closed at
the Rust boundary)::

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
import sys
from dataclasses import dataclass
from typing import Any, Callable

from mvm import _hostlib, _ir
from mvm._dsl import literal as _literal_value
# Owned by the Rust registry (crates/mvm-sdk/src/env.rs), generated into
# `_env/vars.py`. Re-exported from this module for existing importers.
from mvm._env.vars import (
    MVM_SDK_MODE_ENV,
    MVM_SDK_OUT_PATH_ENV,
    MVM_SDK_RUN_PROFILE_ENV,
)
from mvm._errors.types import HostLibraryError, MvmTransportError
from mvm._hostabi.methods import (
    GUEST_CP,
    GUEST_FS_LIST,
    GUEST_FS_MKDIR,
    GUEST_FS_READ,
    GUEST_FS_REMOVE,
    GUEST_FS_RENAME,
    GUEST_FS_STAT,
    GUEST_FS_WRITE,
    GUEST_PROC_KILL,
    GUEST_PROC_SIGNAL,
    GUEST_PROC_START,
    GUEST_PROC_STDIN,
    MACHINE_INVENTORY,
    MACHINE_RUN,
    MACHINE_STOP,
)
from mvm._live import (
    decode_bytes,
    egress_problem,
    encode_bytes,
    stream_process,
)
from mvm._runtime.runtime import (
    RuntimeFsEntry,
    RuntimeFsStat,
)

__all__ = [
    "DEFAULT_TTL_SECONDS",
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
    "SandboxInfo",
    "SandboxLiveError",
    "SandboxModeError",
    "current_recording",
    "emit_recording_json",
    "reset_recording",
]


@dataclass(frozen=True)
class ExecResult:
    """Result of a one-shot ``Sandbox.exec(...)`` call.

    ``exit_code`` is the child's exit code (0 on success; ``128 + signal``
    when a signal ended it; 124 when its timeout did). ``stdout`` and
    ``stderr`` are captured strings — exec is a one-shot that *captures* the
    streams rather than forwarding them, which is the distinction from
    ``commands.start`` + ``ProcessHandle.wait``."""

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
        """Wait for the process to end, calling ``on_event`` for each chunk of
        output in the order it arrived."""
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


#: Every ``Sandbox.create()`` sets a default 30-minute TTL so the host can
#: reap a VM that a crashed script left behind.
DEFAULT_TTL_SECONDS = 1800


class SandboxModeError(RuntimeError):
    """Raised when a call cannot be carried out in the configured
    ``MVM_SDK_MODE`` (e.g. ``MVM_SDK_MODE=plan``, which lives in the host CLI,
    or a live-mode option the host library has no faithful form for)."""


class RecordingNotActiveError(RuntimeError):
    """Raised when a ``Sandbox`` method is called outside a recording
    session (i.e. before ``Sandbox.create`` ran, or after
    :func:`reset_recording`)."""


class SandboxLiveError(RuntimeError):
    """Raised when the SDK cannot make sense of a live-mode exchange: a reply
    of the wrong shape, a machine that is not there to attach to, a value it
    will not forward.

    Refusals from the host library itself are not rewrapped into this type:
    they arrive as the typed ``HostLibraryError`` subclass the library named
    (``MachineSpecError``, ``MachineNotFoundError``, ...), carrying its
    ``code`` and ``retryable`` flag, so a caller can tell a policy refusal
    from a transient backend failure without parsing a message."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class SandboxDevOnly(SandboxLiveError):
    """Raised when the SDK refuses a live-mode guest operation because the
    machine is not a development build.

    The guest agent's runtime profile and signed grant refuse DevOnly process
    and filesystem requests in production, so the agent fails closed on its
    own. The SDK refuses first anyway, before any call reaches the library:
    a typo against a sealed machine should not cost a round-trip, and should
    not leave a refused request in the audit log."""


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

    Accepts ``record`` (in-process recording) and ``live`` (the host
    library). Live mode does not look for the library here: it is loaded on
    the first call that needs it, and a missing one surfaces there as a
    ``MvmTransportError`` naming every place it looked. ``plan`` belongs to
    the host CLI's ``mvmctl run --mode plan`` verb — not a valid value here,
    so we refuse it with an actionable hint."""
    raw = os.environ.get(MVM_SDK_MODE_ENV, "record").strip().lower()
    if raw == "record":
        return "record"
    if raw == "live":
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


def _egress_target(host: Any, port: Any) -> dict[str, Any]:
    problem = egress_problem(host, port)
    if problem is not None:
        _reject_live_option("network.egress", problem)
    return {"host": host, "port": port}


def _ingress_mapping(port: Any) -> str:
    """One declared ingress mapping as the ``host:guest`` string the host
    library takes. Only the shape the NIC-less port relay actually provides
    is accepted, so a mapping cannot be declared with one meaning and booted
    with another."""
    if (
        not isinstance(port, dict)
        or port.get("proto") != "tcp"
        or port.get("transform") != "opaque"
        or port.get("host_addr") != "127.0.0.1"
        or port.get("guest_addr") != "127.0.0.1"
    ):
        raise SandboxModeError(
            "Sandbox live mode currently accepts only opaque TCP ingress "
            "bound to host and guest 127.0.0.1"
        )
    host, guest = port.get("host"), port.get("guest")
    for value in (host, guest):
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
            raise SandboxModeError("Sandbox live mode ingress ports must be 1..65535")
    return f"{host}:{guest}"


@dataclass(frozen=True)
class _LiveOptions:
    """The subset of ``Sandbox.create`` options the host library can carry."""

    egress: list[dict[str, Any]]
    ports: list[str]


def _lower_live_options(
    *,
    env: dict[str, Any] | None,
    include: list[str] | None,
    tags: dict[str, str] | None,
    resources: Any,
    network: Any,
) -> _LiveOptions:
    """Lower the options with an exact host-library equivalent; reject the rest.

    Live mode must never accept an option and then silently boot a different
    workload. Secret references also stay out of the request by construction.
    """
    if env:
        _reject_live_option(
            "env",
            "the launch cannot deliver environment to the workload yet; declare it "
            "in the image or pass env to Sandbox.commands.start",
        )
    if include:
        _reject_live_option("include", "the host library has no source-bundle equivalent")
    if tags:
        _reject_live_option("tags", "the host library has no tag equivalent")
    if resources is not None:
        _reject_live_option(
            "resources",
            "rootfs_size_mb has no host-library equivalent, so partial lowering is refused",
        )

    encoded_network = _encode_network(network)
    if encoded_network is None:
        return _LiveOptions(egress=[], ports=[])
    unknown = set(encoded_network) - {"mode", "egress", "ports", "peers", "dns"}
    if unknown:
        _reject_live_option("network", f"unknown fields: {sorted(unknown)}")
    if encoded_network.get("mode", "none") != "none":
        _reject_live_option("network.mode", "only the NIC-less `none` mode is supported")
    if encoded_network.get("peers"):
        _reject_live_option("network.peers", "the host library has no peer equivalent")
    if encoded_network.get("dns") is not None:
        _reject_live_option("network.dns", "the host library has no DNS equivalent")

    ports = [_ingress_mapping(port) for port in encoded_network.get("ports") or []]
    egress = encoded_network.get("egress")
    if egress is None:
        return _LiveOptions(egress=[], ports=ports)
    if not isinstance(egress, dict) or set(egress) != {"allowlist"}:
        _reject_live_option("network.egress", "expected only an allowlist")
    allowlist = egress.get("allowlist")
    if not isinstance(allowlist, list):
        _reject_live_option("network.egress", "allowlist must be a list")
    targets = []
    for entry in allowlist:
        if not isinstance(entry, dict) or set(entry) != {"host", "port"}:
            _reject_live_option("network.egress", "entries must contain host and port")
        targets.append(_egress_target(entry["host"], entry["port"]))
    return _LiveOptions(egress=targets, ports=ports)


_RUN_PROFILES = ("restrictive", "standard", "dev", "permissive")


def _run_profile() -> str | None:
    """The security profile ``mvmctl run`` handed this script, if any.

    Validated here rather than left to the library so a typo fails before a
    boot is attempted, with the variable named in the message."""
    profile = os.environ.get(MVM_SDK_RUN_PROFILE_ENV)
    if profile is None:
        return None
    profile = profile.strip().lower()
    if profile not in _RUN_PROFILES:
        raise SandboxModeError(
            f"{MVM_SDK_RUN_PROFILE_ENV}={profile!r} is invalid — expected one of: "
            + ", ".join(_RUN_PROFILES)
        )
    return profile


def _literal_env(env: dict[str, Any] | None, operation: str) -> dict[str, str]:
    """Reduce ``env`` to plain strings, refusing anything that is not a literal.

    A secret reference has to be resolved by the host's substitution endpoint;
    forwarding it here would either leak the reference as a value or put the
    secret itself into a guest environment, and both are wrong."""
    out: dict[str, str] = {}
    for key, value in (env or {}).items():
        if not isinstance(key, str) or not key:
            raise TypeError(f"`{operation}` env keys must be non-empty str")
        if isinstance(value, str):
            out[key] = value
            continue
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            value = _dataclass_to_dict(value)
        if (
            not isinstance(value, dict)
            or value.get("kind") != "literal"
            or not isinstance(value.get("value"), str)
        ):
            raise SandboxLiveError(
                f"`{operation}` env {key!r} carries a non-literal value; live mode "
                "only forwards literal env vars (secrets are injected by the host, "
                "never passed through the SDK)."
            )
        out[key] = value["value"]
    return out


def _parse_run_reply(reply: Any) -> tuple[str, str]:
    """Pull ``(vm_id, build_mode)`` out of a ``machine.run`` reply.

    ``build_mode`` must be exactly ``dev`` or ``prod``: it is what unlocks the
    DevOnly guest verbs client-side, so a reply that names neither is treated
    as malformed rather than guessed at."""
    if not isinstance(reply, dict):
        raise SandboxLiveError(f"machine.run returned a malformed reply: {reply!r}")
    machine = reply.get("machine")
    name = machine.get("name") if isinstance(machine, dict) else None
    if not isinstance(name, str) or not name:
        raise SandboxLiveError("machine.run reply is missing a non-empty `machine.name`")
    build_mode = reply.get("build_mode")
    if build_mode not in ("dev", "prod"):
        raise SandboxLiveError(
            f"machine.run reply build_mode={build_mode!r}; expected 'dev' or 'prod'"
        )
    return name, build_mode


def _attached_build_mode(records: Any, *, vm_id: str) -> str:
    """Re-derive ``build_mode`` for an attached machine from the inventory.

    Fail-closed by construction: only an explicit ``"dev"`` returns
    ``"dev"``; a ``"prod"`` / missing / unknown value returns ``"prod"``, so a
    stale or hostile record can never *open* the dev-only guest verbs — it
    can only keep them shut. Raises :class:`SandboxLiveError` when ``vm_id``
    is not in the inventory (there is nothing to attach to)."""
    if not isinstance(records, list):
        raise SandboxLiveError(
            f"machine.inventory must return a list; got {type(records).__name__}"
        )
    for record in records:
        if isinstance(record, dict) and record.get("name") == vm_id:
            return "dev" if record.get("build_mode") == "dev" else "prod"
    raise SandboxLiveError(f"no machine named {vm_id!r} in the machine inventory; is it running?")


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
        """Record or run a ``commands.start(argv, env=...)`` op.

        In record mode the *last* ``commands.start`` in the recording
        becomes the workload's entrypoint; everything earlier
        becomes a ``before_start`` hook in declaration order.

        In live mode the process starts in the running microVM and a
        :class:`ProcessHandle` comes back. The SDK refuses with
        :class:`SandboxDevOnly` if the machine is not a development build —
        the guest agent would refuse too, but the SDK fails closed first so a
        mistake never reaches the machine (security claim 4)."""
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
        """Record or perform a ``files.write(path, content)`` op.

        In record mode: ``content`` is bytes (passed through
        verbatim) or str (utf-8 encoded). The recording stores
        base64 so JSON survives any byte content; the Rust lowering
        emits a ``before_start`` shell hook that ``base64 -d``s
        back to the file.

        In live mode the bytes are written into the running guest."""
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
    """Live mode's handle on one running machine, spoken to through the host
    library.

    Holds the machine's name, which every ``machine.*`` and ``guest.*``
    method takes as its ``id``, and the ``build_mode`` the library resolved
    for it. The ``build_mode`` is what the SDK uses to refuse DevOnly guest
    operations client-side."""

    def __init__(self, *, vm_id: str, build_mode: str) -> None:
        self.vm_id = vm_id
        self.build_mode = build_mode
        self._killed = False

    @classmethod
    def boot(
        cls,
        *,
        image: str,
        workload_id: str,
        ttl_seconds: int,
        options: _LiveOptions,
        command: list[str] | None,
    ) -> "_LiveTransport":
        """Boot a transient machine from ``image`` and wrap it.

        ``command`` is forwarded even though the in-process launcher refuses a
        command override today: the refusal then comes from the library, as a
        ``MachineSpecError`` saying why, and the call starts working unchanged
        when the launcher learns to honour it."""
        profile = _run_profile()
        # A short, validatable name. The library rejects names outside its
        # validator; lowercase alphanumerics with hyphens are always safe.
        suffix = secrets.token_hex(4)
        vm_id = f"sdk-{workload_id[:24]}-{suffix}".lower()
        vm_id = "".join(c if (c.isalnum() or c == "-") else "-" for c in vm_id)

        request: dict[str, Any] = {
            "image": image,
            "mode": "transient",
            "name": vm_id,
            "ttl_seconds": ttl_seconds,
        }
        if profile is not None:
            request["profile"] = profile
        if options.ports:
            request["ports"] = options.ports
        if options.egress:
            request["egress"] = options.egress
        if command is not None:
            request["command"] = command
        name, build_mode = _parse_run_reply(_hostlib.call(MACHINE_RUN, request))
        return cls(vm_id=name, build_mode=build_mode)

    @classmethod
    def attach(cls, *, vm_id: str) -> "_LiveTransport":
        """Attach to an already-running machine by name.

        The attach path never boots, so there is no ``machine.run`` reply to
        read ``build_mode`` from; it comes from the machine inventory instead,
        resolved fail-closed (see :func:`_attached_build_mode`) so the guard
        that protects a booted sandbox also protects an attached one
        (security claim 4)."""
        records = _hostlib.call(MACHINE_INVENTORY)
        return cls(vm_id=vm_id, build_mode=_attached_build_mode(records, vm_id=vm_id))

    def _require_dev(self, operation: str) -> None:
        if self.build_mode != "dev":
            raise SandboxDevOnly(
                f"`{operation}` requires a dev-mode template; resolved template "
                f"build_mode={self.build_mode!r}. The guest agent refuses DevOnly "
                "process and filesystem requests on production builds — re-build the "
                "image as a dev build, or bake the inputs into the image instead."
            )

    def _start(
        self, argv: list[str], env: dict[str, Any] | None, cwd: str | None, operation: str
    ) -> ProcessHandle:
        request: dict[str, Any] = {"id": self.vm_id, "argv": list(argv)}
        literal = _literal_env(env, operation)
        if literal:
            request["env"] = literal
        if cwd is not None:
            request["cwd"] = cwd
        reply = _hostlib.call(GUEST_PROC_START, request)
        token = reply.get("token") if isinstance(reply, dict) else None
        if not isinstance(token, str) or not token:
            raise SandboxLiveError(f"guest.proc.start returned no process token: {reply!r}")
        return ProcessHandle(self, token)

    def commands_start(self, argv: list[str], env: dict[str, Any] | None) -> ProcessHandle:
        """Start ``argv`` in the guest and return its handle."""
        self._require_dev("commands.start")
        return self._start(argv, env, None, "commands.start")

    def commands_exec(
        self,
        argv: list[str],
        env: dict[str, Any] | None,
        *,
        timeout: float | None = None,
        cwd: str | None = None,
    ) -> ExecResult:
        """Start ``argv`` in the guest and wait for it, capturing its output."""
        self._require_dev("exec")
        result = self._start(argv, env, cwd, "exec").wait(timeout=timeout)
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
        self._require_dev("process wait")
        on_chunk = None
        if on_event is not None:
            on_chunk = lambda stream, data: on_event(ProcessStreamEvent(stream, data))  # noqa: E731
        output = stream_process(
            self.vm_id, token, timeout=timeout, on_chunk=on_chunk, error=SandboxLiveError
        )
        return ProcessResult(output.exit_code, output.stdout, output.stderr)

    def process_stdin(self, token: str, data: bytes) -> None:
        self._require_dev("process stdin")
        _hostlib.call(
            GUEST_PROC_STDIN, {"id": self.vm_id, "token": token, "data_b64": encode_bytes(data)}
        )

    def process_signal(self, token: str, signum: int) -> None:
        if not isinstance(signum, int) or isinstance(signum, bool) or signum <= 0:
            raise ValueError("signum must be a positive integer")
        self._require_dev("process signal")
        _hostlib.call(GUEST_PROC_SIGNAL, {"id": self.vm_id, "token": token, "signum": signum})

    def process_kill(self, token: str) -> None:
        self._require_dev("process kill")
        _hostlib.call(GUEST_PROC_KILL, {"id": self.vm_id, "token": token})

    def files_write(
        self,
        path: str,
        data: bytes,
        *,
        mode: int = 0o644,
        create_parents: bool = False,
        follow_symlinks: bool = False,
    ) -> None:
        self._require_dev("files.write")
        _hostlib.call(
            GUEST_FS_WRITE,
            {
                "id": self.vm_id,
                "path": path,
                "data_b64": encode_bytes(data),
                "mode": mode,
                "create_parents": create_parents,
                "follow_symlinks": follow_symlinks,
            },
        )

    def files_read(self, path: str, *, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        self._require_dev("files.read")
        reply = _hostlib.call(
            GUEST_FS_READ, {"id": self.vm_id, "path": path, "offset": offset, "length": length}
        )
        data = reply.get("data_b64") if isinstance(reply, dict) else None
        return decode_bytes(data, "data_b64", SandboxLiveError)

    def files_list(self, path: str) -> list[FsEntry]:
        """List ``path``. The agent caps a listing's size; past the cap the
        entries it returned are all there is."""
        self._require_dev("files.list")
        reply = _hostlib.call(GUEST_FS_LIST, {"id": self.vm_id, "path": path})
        entries = reply.get("entries") if isinstance(reply, dict) else None
        if not isinstance(entries, list):
            raise SandboxLiveError("filesystem listing reply has no `entries` array")
        try:
            return [
                FsEntry(name=item["name"], kind=item["kind"], size=int(item["size"]))
                for item in entries
            ]
        except (KeyError, TypeError, ValueError) as exc:
            raise SandboxLiveError("filesystem listing returned an invalid payload") from exc

    def files_stat(self, path: str, *, follow_symlinks: bool) -> FsStat:
        self._require_dev("files.stat")
        parsed = _hostlib.call(
            GUEST_FS_STAT, {"id": self.vm_id, "path": path, "follow_symlinks": follow_symlinks}
        )
        if not isinstance(parsed, dict):
            raise SandboxLiveError("filesystem stat reply must be a JSON object")
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
        self._require_dev("files.mkdir")
        _hostlib.call(
            GUEST_FS_MKDIR, {"id": self.vm_id, "path": path, "mode": mode, "parents": parents}
        )

    def files_remove(self, path: str, *, recursive: bool) -> None:
        self._require_dev("files.remove")
        _hostlib.call(GUEST_FS_REMOVE, {"id": self.vm_id, "path": path, "recursive": recursive})

    def files_move(self, source: str, destination: str) -> None:
        self._require_dev("files.move")
        _hostlib.call(GUEST_FS_RENAME, {"id": self.vm_id, "from": source, "to": destination})

    def cp(self, direction: str, host_path: str, guest_path: str) -> None:
        """Copy one file across the host/guest boundary.

        The host path is made absolute here because the library resolves it
        in this process, and an absolute path is what a reader of the audit
        entry needs to see."""
        self._require_dev("copy")
        _hostlib.call(
            GUEST_CP,
            {
                "id": self.vm_id,
                "direction": direction,
                "host_path": os.path.abspath(host_path),
                "guest_path": guest_path,
            },
        )

    def kill(self) -> None:
        """Stop the machine. Idempotent — the context manager and an explicit
        ``sb.kill()`` both land here, and the second call must not try again.

        A failure is reported on stderr, not raised: this is the cleanup
        path, often running while another exception unwinds, and a machine
        that is already gone (its TTL reaped it) is the usual cause."""
        if self._killed:
            return
        self._killed = True
        try:
            _hostlib.call(MACHINE_STOP, {"id": self.vm_id})
        except (HostLibraryError, MvmTransportError) as exc:
            sys.stderr.write(f"mvm-sdk live: stopping {self.vm_id} failed: {exc}\n")


class Sandbox:
    """A recordable / live handle for an imperative ``Sandbox``
    script.

    Construct via :meth:`Sandbox.create`. Under ``MVM_SDK_MODE=record``
    the constructor sets up an in-process recording; under
    ``MVM_SDK_MODE=live`` it boots a real microVM through the host library
    and stashes the resulting handle on ``self._live``. Supports
    context-manager usage; ``__exit__`` issues a ``kill`` (record mode:
    appends a kill op; live mode: stops the machine)."""

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

        ``template`` selects a manifest/template source; ``image`` selects an
        OCI reference, an absolute path, or ``flake:<ref>#<attr>``. Exactly
        one must be provided. In record mode ``template`` is preserved
        verbatim and resolved to a base image on the Rust side, so an unknown
        template fails at lower time, not here.

        Live mode boots only from ``image``: the host library has no
        template launch, so ``template`` raises :class:`SandboxModeError`
        before anything is booted. ``command`` overrides the image command;
        the in-process launcher refuses a command override today, and that
        refusal arrives as ``MachineSpecError``. Live mode also refuses
        ``env``, ``include``, ``tags`` and ``resources``, which it cannot
        carry faithfully; pass ``env`` to ``Sandbox.commands.start`` instead.
        Record mode continues to encode all of them in the workload
        declaration.

        ``workload_id`` defaults to the resolved template (the CLI
        overrides with the script's basename when invoked via
        ``mvmctl build compile``)."""
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
            if template is not None:
                raise SandboxModeError(
                    f"Sandbox live mode cannot boot template {template!r}: the host "
                    "library launches images only. Pass `image=` (an OCI reference, "
                    "an absolute path, or `flake:<ref>#<attr>`), or run the script "
                    "under record mode."
                )
            options = _lower_live_options(
                env=env,
                include=include,
                tags=tags,
                resources=resources,
                network=network,
            )
            live = _LiveTransport.boot(
                image=source,
                workload_id=wid,
                ttl_seconds=ttl_seconds,
                options=options,
                command=command,
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
        to a machine that is already up, and reads its ``build_mode`` from
        the machine inventory.

        The dev-only guard is inherited unchanged: the derived
        ``build_mode`` is never defaulted to ``"dev"`` — a prod /
        missing / unknown value resolves to ``"prod"``, so
        ``connect(...).exec(...)`` / ``.commands.start(...)`` on a
        sealed prod machine raises :class:`SandboxDevOnly` exactly like
        the ``create`` path (security claim 4).

        Always a live operation, regardless of ``MVM_SDK_MODE``: attaching
        to a running VM has no record-mode meaning. Raises
        :class:`SandboxLiveError` when no machine of that name exists."""
        if not isinstance(id, str) or not id:
            raise ValueError("Sandbox.connect requires a non-empty machine id")
        if _recording is not None or _live_sandbox_active():
            raise RuntimeError(
                "a Sandbox session is already active — call "
                "Sandbox.kill() or exit the `with` block before "
                "attaching to another machine."
            )
        live = _LiveTransport.attach(vm_id=id)
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

        Convenience over ``commands.start`` + ``ProcessHandle.wait``.
        Refuses with :class:`SandboxDevOnly` when the machine is not a dev
        build (security claim 4) — no silent fallback.

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
        self._live.cp("host_to_guest", host_path, guest_path)

    def copy_out(self, guest_path: str, host_path: str) -> None:
        """Copy a file out of the running sandbox to ``host_path``.

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
        self._live.cp("guest_to_host", host_path, guest_path)

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
        tooling can introspect intent). In live mode, stops the
        machine."""
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
        # Same teardown as `__exit__`, off the event loop: stopping a
        # machine waits on the VMM, and the caller's loop should not.
        await asyncio.to_thread(self.kill)


def _require_recording() -> None:
    if _recording is None:
        raise RecordingNotActiveError(
            "Sandbox method called before Sandbox.create() — every "
            "script must construct a Sandbox first."
        )
