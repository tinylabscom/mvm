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
  ``Sandbox`` call shells to ``$MVM_CLI_BIN`` (``mvmctl up``,
  ``mvmctl proc start``, ``mvmctl fs write``, ``mvmctl down``)
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
from dataclasses import dataclass
from typing import Any

from mvm import _ir
from mvm._dsl import literal as _literal_value

__all__ = [
    "DEFAULT_TTL_SECONDS",
    "MVM_CLI_BIN_ENV",
    "ExecResult",
    "RecordingNotActiveError",
    "Sandbox",
    "SandboxDevOnly",
    "SandboxLiveError",
    "SandboxModeError",
    "current_recording_dict",
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


MVM_SDK_MODE_ENV = "MVM_SDK_MODE"

#: When set in the environment, the SDK writes the wire-shape
#: recording JSON to this path on process exit. The CLI's Phase 7e
#: auto-exec path uses this to capture the recording without
#: parsing stdout (which the user's own script may write to).
MVM_SDK_OUT_PATH_ENV = "MVM_SDK_OUT_PATH"

#: Plan 73 Followup H-live — when ``MVM_SDK_MODE=live`` is set, the
#: SDK shells out to the ``mvmctl`` binary at this path. The host's
#: ``mvmctl run --mode live`` verb sets it to its own
#: ``current_exe()`` so a `cargo run -- run --mode live` flow finds
#: the same binary it invoked through.
MVM_CLI_BIN_ENV = "MVM_CLI_BIN"

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

    Per ADR-002 §W4.3 (security claim 4 in :doc:`CLAUDE.md`) the
    guest agent strips the ``do_exec`` handler in production
    builds. The agent itself fails closed, but the SDK refuses
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
        if not os.environ.get(MVM_CLI_BIN_ENV):
            raise SandboxModeError(
                "MVM_SDK_MODE=live requires MVM_CLI_BIN to point at a `mvmctl` binary. "
                "The host's `mvmctl run --mode live` verb sets this automatically; if "
                "you're running the SDK directly, export MVM_CLI_BIN=/path/to/mvmctl "
                "before invoking your script."
            )
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
        """Record or shell a ``commands.start(argv, env=...)`` op.

        In record mode the *last* ``commands.start`` in the recording
        becomes the workload's entrypoint; everything earlier
        becomes a ``before_start`` hook in declaration order.

        In live mode the call shells to ``mvmctl proc start <vm>``
        against the running microVM. The SDK refuses with
        :class:`SandboxDevOnly` if the resolved template is a
        prod template (the agent's W4.3 ``do_exec`` strip would
        refuse anyway, but the SDK fails closed first to avoid a
        spurious vsock round-trip — ADR-002 claim 4)."""
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            raise TypeError("argv must be a list[str]")
        if not argv:
            raise ValueError("argv must be non-empty")
        if self._sandbox._live is not None:
            self._sandbox._live.commands_start(argv, env)
            return
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
            self._sandbox._live.files_write(path, data)
            return
        _require_recording()
        _recording["ops"].append(
            {
                "kind": "files_write",
                "path": path,
                "bytes_b64": base64.standard_b64encode(data).decode("ascii"),
            }
        )


class _LiveTransport:
    """Live-mode transport — shells each Sandbox call to the host's
    ``mvmctl`` binary.

    Created by :meth:`Sandbox.create` when ``MVM_SDK_MODE=live``.
    Holds the resolved ``mvmctl`` binary path, the generated
    ``vm_id``, and the template's ``build_mode`` ("dev" / "prod")
    parsed from ``mvmctl up --up-json``'s stdout envelope. The
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
    def for_template(
        cls,
        *,
        template: str,
        workload_id: str,
        ttl_seconds: int,
    ) -> "_LiveTransport":
        """Run ``mvmctl up --up-json --detach --name <id> --manifest
        <template>`` and parse the JSON envelope. Raises
        :class:`SandboxLiveError` on any failure."""
        mvm_cli_bin = os.environ.get(MVM_CLI_BIN_ENV) or ""
        if not mvm_cli_bin:
            raise SandboxModeError(
                "MVM_SDK_MODE=live requires MVM_CLI_BIN to point at a `mvmctl` binary."
            )
        # Generate a short, validatable VM id. `mvmctl up` rejects
        # names that don't match its validator; alphanumerics with
        # a hyphen are safe.
        suffix = secrets.token_hex(4)
        vm_id = f"sdk-{workload_id[:24]}-{suffix}".lower()
        vm_id = "".join(c if (c.isalnum() or c == "-") else "-" for c in vm_id)

        argv = [
            mvm_cli_bin,
            "up",
            "--up-json",
            "--name",
            vm_id,
            "--manifest",
            template,
            "--ttl",
            f"{ttl_seconds}s",
        ]
        try:
            result = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{mvm_cli_bin}` not found on disk; check MVM_CLI_BIN",
                argv=argv,
            ) from exc

        if result.returncode != 0:
            raise SandboxLiveError(
                f"`mvmctl up` failed with exit code {result.returncode}",
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

    def commands_start(
        self, argv: list[str], env: dict[str, Any] | None
    ) -> None:
        """Shell ``mvmctl proc start <vm> -e ... -- <argv>``.

        Refuses with :class:`SandboxDevOnly` when the resolved
        template is prod (ADR-002 §W4.3, claim 4). The agent fails
        closed anyway; the SDK refuses first so a typo doesn't
        emit a spurious vsock request."""
        if self.build_mode != "dev":
            raise SandboxDevOnly(
                f"`commands.start` requires a dev-mode template; resolved template "
                f"build_mode={self.build_mode!r}. ADR-002 §W4.3 (security claim 4) "
                f"strips the agent's `do_exec` handler in prod builds — re-build the "
                f"template with `mvmctl template build --dev <name>`, or use "
                f"`files.write` to stage inputs into the running VM instead.",
                argv=["proc", "start", self.vm_id, *argv],
            )
        shell = [self.mvm_cli_bin, "proc", "start", self.vm_id]
        if env:
            # `mvmctl proc start` expects `-e KEY=VALUE` pairs.
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
                        f"injected via the host keystore + `--secret` on `mvmctl up`).",
                        argv=shell,
                    )
        shell += ["--", *argv]
        self._run_shell(shell)

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
        (matches ``commands_start``'s policy — ADR-002 §W4.3, claim
        4)."""
        if self.build_mode != "dev":
            raise SandboxDevOnly(
                f"`exec` requires a dev-mode template; resolved template "
                f"build_mode={self.build_mode!r}. ADR-002 §W4.3 (security claim 4) "
                f"strips the agent's `do_exec` handler in prod builds — re-build the "
                f"template with `mvmctl template build --dev <name>`, or use "
                f"`files.write` to stage inputs into the running VM instead.",
                argv=["proc", "start", self.vm_id, *argv],
            )

        # 1) `proc start` → pid_token on stdout.
        start_shell: list[str] = [self.mvm_cli_bin, "proc", "start", self.vm_id]
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
                        f"the host keystore + `--secret` on `mvmctl up`).",
                        argv=start_shell,
                    )
        if cwd is not None:
            start_shell += ["--cwd", cwd]
        start_shell += ["--", *argv]
        try:
            start_result = subprocess.run(
                start_shell,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; check MVM_CLI_BIN",
                argv=start_shell,
            ) from exc
        if start_result.returncode != 0:
            raise SandboxLiveError(
                f"`mvmctl proc start` failed with exit code {start_result.returncode}",
                argv=start_shell,
                exit_code=start_result.returncode,
                stderr=start_result.stderr,
            )
        pid_token = start_result.stdout.strip()
        if not pid_token:
            raise SandboxLiveError(
                "`mvmctl proc start` produced no pid_token on stdout",
                argv=start_shell,
                stderr=start_result.stderr,
            )

        # 2) `proc wait <token>` → captured stdout/stderr/exit.
        wait_shell: list[str] = [
            self.mvm_cli_bin,
            "proc",
            "wait",
            self.vm_id,
            pid_token,
        ]
        if timeout is not None:
            wait_shell += ["--timeout", str(int(timeout))]
        try:
            # The +5s slack on subprocess.run's timeout is so the
            # agent's pgroup-kill (on `--timeout` overrun) has time
            # to land before subprocess.run gives up. Should never
            # actually trip — agent enforces first.
            wait_result = subprocess.run(
                wait_shell,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout + 5 if timeout is not None else None,
            )
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; check MVM_CLI_BIN",
                argv=wait_shell,
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise SandboxLiveError(
                f"`mvmctl proc wait` did not return within "
                f"{timeout + 5 if timeout is not None else 'no'} seconds",
                argv=wait_shell,
            ) from exc

        return ExecResult(
            exit_code=wait_result.returncode,
            stdout=wait_result.stdout,
            stderr=wait_result.stderr,
        )

    def files_write(self, path: str, data: bytes) -> None:
        """Shell ``mvmctl fs write <vm> <path>`` with the file
        bytes piped through stdin. The mvmctl verb accepts stdin
        when ``--content`` is omitted."""
        shell = [self.mvm_cli_bin, "fs", "write", self.vm_id, path]
        try:
            result = subprocess.run(
                shell,
                input=data,
                check=False,
                capture_output=True,
            )
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; check MVM_CLI_BIN",
                argv=shell,
            ) from exc
        if result.returncode != 0:
            raise SandboxLiveError(
                f"`mvmctl fs write` failed with exit code {result.returncode}",
                argv=shell,
                exit_code=result.returncode,
                stderr=result.stderr.decode("utf-8", errors="replace"),
            )

    def cp(self, source: str, destination: str) -> None:
        """Shell ``mvmctl cp <source> <destination>``. Endpoints use
        ``VM:/absolute/path`` for the guest side; `mvmctl cp` reads the
        host file and streams it over the agent fs RPC (and back)."""
        shell = [self.mvm_cli_bin, "cp", source, destination]
        try:
            result = subprocess.run(shell, check=False, capture_output=True)
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; check MVM_CLI_BIN",
                argv=shell,
            ) from exc
        if result.returncode != 0:
            raise SandboxLiveError(
                f"`mvmctl cp` failed with exit code {result.returncode}",
                argv=shell,
                exit_code=result.returncode,
                stderr=result.stderr.decode("utf-8", errors="replace"),
            )

    def kill(self) -> None:
        """Shell ``mvmctl down <vm>``. Idempotent — repeated kills
        from the context manager + an explicit `sb.kill()` are
        coalesced so we don't trip on a double-down."""
        if self._killed:
            return
        self._killed = True
        shell = [self.mvm_cli_bin, "down", self.vm_id]
        try:
            result = subprocess.run(
                shell,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise SandboxLiveError(
                f"`{self.mvm_cli_bin}` not found on disk; check MVM_CLI_BIN",
                argv=shell,
            ) from exc
        if result.returncode != 0:
            # Print but don't raise — kill is the cleanup path; a
            # failure here usually means the VM was already torn
            # down by the orchestrator's TTL reaper.
            sys.stderr.write(
                f"mvm-sdk live: `mvmctl down {self.vm_id}` exited "
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
                f"`{self.mvm_cli_bin}` not found on disk; check MVM_CLI_BIN",
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
    """Parse ``mvmctl up --up-json`` stdout. The envelope is a single
    JSON line; trailing newlines tolerated. Raises
    :class:`SandboxLiveError` if the envelope is malformed."""
    line = stdout.strip()
    if not line:
        raise SandboxLiveError(
            "`mvmctl up --up-json` produced empty stdout — expected a JSON envelope.",
            argv=argv,
        )
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SandboxLiveError(
            f"`mvmctl up --up-json` stdout is not valid JSON: {exc.msg}",
            argv=argv,
            stderr=line,
        ) from exc
    if not isinstance(parsed, dict):
        raise SandboxLiveError(
            f"`mvmctl up --up-json` envelope must be a JSON object; got {type(parsed).__name__}",
            argv=argv,
        )
    schema = parsed.get("schema_version")
    if schema != _LiveTransport.SCHEMA_VERSION:
        raise SandboxLiveError(
            f"`mvmctl up --up-json` envelope schema_version={schema!r}; "
            f"SDK supports {_LiveTransport.SCHEMA_VERSION}",
            argv=argv,
        )
    vm_id = parsed.get("vm_id")
    build_mode = parsed.get("build_mode")
    if not isinstance(vm_id, str) or not vm_id:
        raise SandboxLiveError(
            "`mvmctl up --up-json` envelope is missing a non-empty `vm_id` field.",
            argv=argv,
        )
    if build_mode not in ("dev", "prod"):
        raise SandboxLiveError(
            f"`mvmctl up --up-json` envelope build_mode={build_mode!r}; "
            f"expected 'dev' or 'prod'.",
            argv=argv,
        )
    return {"vm_id": vm_id, "build_mode": build_mode}


class Sandbox:
    """A recordable / live handle for an imperative ``Sandbox``
    script.

    Construct via :meth:`Sandbox.create`. Under ``MVM_SDK_MODE=record``
    the constructor sets up an in-process recording; under
    ``MVM_SDK_MODE=live`` it shells ``mvmctl up`` to boot a real
    microVM and stashes the resulting handle on
    ``self._live``. Supports context-manager usage; ``__exit__``
    issues a ``kill`` (record-mode: appends a kill op; live-mode:
    shells ``mvmctl down``)."""

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
    ) -> "Sandbox":
        """Start a new sandbox session.

        ``template`` resolves to a base image on the Rust side (see
        ``runtime::resolve_base_image``); in record mode unknown
        templates fail at lower time, not here, because the wire
        shape preserves them verbatim. In live mode unknown
        templates fail when ``mvmctl up --manifest <template>``
        rejects them — that failure surfaces as
        :class:`SandboxLiveError` here.

        Plan 120 §Task 5 — ``image=<name>`` is the friendlier
        keyword alias for ``template=<name>``, matching the
        ``docker run <image>`` / ``podman run <image>`` shape the
        demo's five-line snippet uses. Exactly one of ``template``
        (positional or keyword) or ``image`` (keyword) must be
        provided.

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
        resolved_template = template if template is not None else image
        if not isinstance(resolved_template, str) or not resolved_template:
            raise ValueError(
                "template/image must be a non-empty str"
            )
        ttl_seconds = _parse_ttl(ttl)
        if ttl_seconds is None:
            ttl_seconds = DEFAULT_TTL_SECONDS
        wid = workload_id or resolved_template

        if mode == "live":
            live = _LiveTransport.for_template(
                template=resolved_template,
                workload_id=wid,
                ttl_seconds=ttl_seconds,
            )
            sb = cls(wid, live=live)
            _register_live(sb)
            return sb

        # record mode (existing path).
        create_dict: dict[str, Any] = {
            "template": resolved_template,
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
        (ADR-002 §W4.3, claim 4) — no silent fallback.

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

    def kill(self) -> None:
        """Issue a ``kill`` against the active transport.

        In record mode, appends a ``kill`` op (the Rust lowering
        drops these; the microVM TTL is the orchestrator's job, but
        the bookkeeping is preserved through the recording so
        tooling can introspect intent). In live mode, shells
        ``mvmctl down <vm>``."""
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


def _require_recording() -> None:
    if _recording is None:
        raise RecordingNotActiveError(
            "Sandbox method called before Sandbox.create() — every "
            "script must construct a Sandbox first."
        )
