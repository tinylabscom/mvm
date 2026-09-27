"""Machine lifecycle for host automation, through the host library.

Every method is one ``machine.*`` or ``guest.*`` call into ``libmvm_hostlib``
(see ``mvm._hostlib``), the library ``mvmctl`` itself is built on. Admission,
policy, receipts, audit, OCI verification and persistent machine state are
the library's; this module validates arguments, shapes requests, and turns
replies into Python values. A refusal from the library arrives as the typed
``HostLibraryError`` subclass it named, unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from mvm import _hostlib
from mvm._hostabi.methods import (
    GUEST_PROC_START,
    MACHINE_CREATE,
    MACHINE_INSPECT,
    MACHINE_INVENTORY,
    MACHINE_LOGS,
    MACHINE_RM,
    MACHINE_RUN,
    MACHINE_START,
    MACHINE_STOP,
)
from mvm._live import decode_bytes, parse_host_port, stream_process


@dataclass(frozen=True)
class MachineResult:
    """What a command run by :meth:`Machine.exec` produced.

    ``exit_code`` is ``128 + signal`` when a signal ended the command and 124
    when its timeout did, the way a shell reports both."""

    exit_code: int
    stdout: str
    stderr: str


class MachineError(RuntimeError):
    """The host library answered with something this SDK cannot use.

    Refusals are not this type: the library's own errors propagate as the
    ``HostLibraryError`` subclass its error code names."""


def _require_non_empty_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty str")
    return value


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} must be a positive int")
    return value


def _command(values: Iterable[str] | None) -> list[str] | None:
    if values is None:
        return None
    if isinstance(values, str):
        # A bare string would otherwise be split into one argument per
        # character, which boots something nobody asked for.
        raise ValueError("command must be a list of str, not a single str")
    out = list(values)
    if not out or not all(isinstance(v, str) and v for v in out):
        raise ValueError("command must be a non-empty list of non-empty str")
    return out


def _env(values: dict[str, str] | None) -> dict[str, str] | None:
    if values is None:
        return None
    if not isinstance(values, dict) or not all(
        isinstance(k, str) and k and isinstance(v, str) for k, v in values.items()
    ):
        raise ValueError("env must map non-empty str names to str values")
    return dict(values)


def _ports(values: Iterable[str] | None) -> list[str] | None:
    """Validate ``host:guest`` port mappings before they reach a boot."""
    if values is None:
        return None
    out = []
    for mapping in values:
        host, sep, guest = mapping.partition(":") if isinstance(mapping, str) else ("", "", "")
        try:
            numbers = [int(host), int(guest)] if sep else []
        except ValueError:
            numbers = []
        if len(numbers) != 2 or not all(1 <= n <= 65535 for n in numbers):
            raise ValueError(f"port mapping {mapping!r} must be 'host:guest' with ports 1..65535")
        out.append(f"{numbers[0]}:{numbers[1]}")
    return out


def _egress(allow_hosts: Iterable[str] | None) -> list[dict[str, Any]] | None:
    if allow_hosts is None:
        return None
    if isinstance(allow_hosts, str):
        raise ValueError("allow_hosts must be a list of 'host:port' str, not a single str")
    return [{"host": host, "port": port} for host, port in map(parse_host_port, allow_hosts)]


def _launch_request(**fields: Any) -> dict[str, Any]:
    """Drop the options the caller left unset.

    The library refuses unknown fields and treats an omitted optional field
    as its default, so sending ``null`` would be both noisier and, for some
    fields, a parse error."""
    return {key: value for key, value in fields.items() if value is not None}


def _machine_name(state: Any, method: str) -> str:
    name = state.get("name") if isinstance(state, dict) else None
    if not isinstance(name, str) or not name:
        raise MachineError(f"{method} returned no machine name: {state!r}")
    return name


class Machine:
    """A handle on one machine, by name.

    ``Machine.run`` boots a transient machine and ``Machine.create`` persists
    one without booting it; both return a handle. ``Machine("name")`` binds a
    handle to a machine that already exists."""

    def __init__(self, name: str) -> None:
        self.name = _require_non_empty_str(name, "name")
        #: ``dev`` or ``prod`` when this handle came from :meth:`run`, else
        #: ``None``: only a boot reply carries it.
        self.build_mode: str | None = None
        #: The admitted plan's id when this handle came from :meth:`run`, for
        #: finding the boot in the audit log.
        self.plan_id: str | None = None

    def __repr__(self) -> str:
        return f"Machine({self.name!r})"

    @staticmethod
    def run(
        image: str,
        *,
        name: str | None = None,
        command: Iterable[str] | None = None,
        env: dict[str, str] | None = None,
        cpus: int | None = None,
        memory_mib: int | None = None,
        profile: str | None = None,
        allow_hosts: Iterable[str] | None = None,
        ports: Iterable[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> "Machine":
        """Boot a transient machine from ``image`` and return a handle to it.

        ``allow_hosts`` entries are ``host:port`` (``[address]:port`` for
        IPv6) and become the machine's egress allowlist; everything else is
        denied. ``command`` and ``env`` are forwarded as given; the in-process
        launcher refuses both today with ``MachineSpecError``, saying why."""
        request = _launch_request(
            image=_require_non_empty_str(image, "image"),
            mode="transient",
            name=None if name is None else _require_non_empty_str(name, "name"),
            command=_command(command),
            env=_env(env),
            cpus=None if cpus is None else _positive_int(cpus, "cpus"),
            memory_mib=None if memory_mib is None else _positive_int(memory_mib, "memory_mib"),
            profile=None if profile is None else _require_non_empty_str(profile, "profile"),
            ttl_seconds=None if ttl_seconds is None else _positive_int(ttl_seconds, "ttl_seconds"),
            ports=_ports(ports),
            egress=_egress(allow_hosts),
        )
        reply = _hostlib.call(MACHINE_RUN, request)
        if not isinstance(reply, dict):
            raise MachineError(f"{MACHINE_RUN} returned a malformed reply: {reply!r}")
        machine = Machine(_machine_name(reply.get("machine"), MACHINE_RUN))
        machine.build_mode = reply.get("build_mode")
        machine.plan_id = reply.get("plan_id")
        return machine

    @staticmethod
    def create(
        name: str,
        image: str,
        *,
        command: Iterable[str] | None = None,
        env: dict[str, str] | None = None,
        cpus: int | None = None,
        memory_mib: int | None = None,
        profile: str | None = None,
        allow_hosts: Iterable[str] | None = None,
        ports: Iterable[str] | None = None,
        force: bool = False,
    ) -> "Machine":
        """Persist a machine definition without booting it; start it with
        :meth:`start`. ``force`` replaces an existing definition of the same
        name."""
        request = _launch_request(
            name=_require_non_empty_str(name, "name"),
            image=_require_non_empty_str(image, "image"),
            command=_command(command),
            env=_env(env),
            cpus=None if cpus is None else _positive_int(cpus, "cpus"),
            memory_mib=None if memory_mib is None else _positive_int(memory_mib, "memory_mib"),
            profile=None if profile is None else _require_non_empty_str(profile, "profile"),
            ports=_ports(ports),
            egress=_egress(allow_hosts),
            force=True if force else None,
        )
        return Machine(_machine_name(_hostlib.call(MACHINE_CREATE, request), MACHINE_CREATE))

    @staticmethod
    def ls() -> list[dict[str, Any]]:
        """Every machine on this host, each with its fail-closed ``build_mode``."""
        records = _hostlib.call(MACHINE_INVENTORY)
        if not isinstance(records, list):
            raise MachineError(f"{MACHINE_INVENTORY} returned {type(records).__name__}, not a list")
        return records

    def start(self) -> dict[str, Any]:
        """Boot a persisted machine; returns its state."""
        return _hostlib.call(MACHINE_START, {"id": self.name})

    def stop(self) -> None:
        """Stop the machine. Stopping a stopped machine is not an error."""
        _hostlib.call(MACHINE_STOP, {"id": self.name})

    def rm(self) -> None:
        """Remove the machine. A running persistent machine is refused with
        ``MachineConflictError``: stop it first."""
        _hostlib.call(MACHINE_RM, {"id": self.name})

    def inspect(self) -> dict[str, Any]:
        """The machine's current state."""
        return _hostlib.call(MACHINE_INSPECT, {"id": self.name})

    def logs(self, lines: int | None = None) -> str:
        """Captured console output, optionally only the last ``lines`` lines.

        Decoded with replacement: console output is whatever the guest wrote,
        and a stray byte should not make the rest unreadable."""
        request: dict[str, Any] = {"id": self.name}
        if lines is not None:
            request["tail_lines"] = _positive_int(lines, "lines")
        reply = _hostlib.call(MACHINE_LOGS, request)
        data = reply.get("data_b64") if isinstance(reply, dict) else None
        return decode_bytes(data, "data_b64", MachineError).decode("utf-8", errors="replace")

    def exec(
        self,
        command: Iterable[str],
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> MachineResult:
        """Run ``command`` in the machine and wait for it.

        This drives the guest agent's process verbs, which only a development
        build serves; on a production machine the agent refuses and the
        refusal arrives as ``MachineBackendError``."""
        argv = _command(command)
        if argv is None:
            raise ValueError("command must be a non-empty list of non-empty str")
        request: dict[str, Any] = {"id": self.name, "argv": argv}
        if env:
            request["env"] = _env(env)
        if cwd is not None:
            request["cwd"] = _require_non_empty_str(cwd, "cwd")
        reply = _hostlib.call(GUEST_PROC_START, request)
        token = reply.get("token") if isinstance(reply, dict) else None
        if not isinstance(token, str) or not token:
            raise MachineError(f"{GUEST_PROC_START} returned no process token: {reply!r}")
        output = stream_process(self.name, token, timeout=timeout, on_chunk=None, error=MachineError)
        return MachineResult(
            exit_code=output.exit_code,
            stdout=output.stdout.decode("utf-8", errors="replace"),
            stderr=output.stderr.decode("utf-8", errors="replace"),
        )


__all__ = [
    "Machine",
    "MachineError",
    "MachineResult",
]
