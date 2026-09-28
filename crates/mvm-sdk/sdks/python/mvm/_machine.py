"""Machine lifecycle for host automation, through the host library.

Every method is one ``machine.*`` or ``guest.*`` call into ``libmvm_hostlib``
(see ``mvm._hostlib``), the library ``mvmctl`` itself is built on. Admission,
policy, receipts, audit, OCI verification and persistent machine state are
the library's; this module validates arguments, shapes requests, and turns
replies into Python values. A refusal from the library arrives as the typed
``HostLibraryError`` subclass it named, unchanged.
"""

from __future__ import annotations

import secrets
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Literal, overload

from mvm import _hostlib
from mvm._errors.types import HostLibraryError, MvmTransportError
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
from mvm._live import decode_bytes, follow_output, parse_host_port, stream_process


@dataclass(frozen=True)
class MachineResult:
    """What a command run by :meth:`Machine.run` or :meth:`Machine.exec`
    produced.

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


def _source(
    image: str | None, template: str | None, manifest: str | None
) -> dict[str, str]:
    """The one boot source a launch names, as its request field."""
    given = {
        field: _require_non_empty_str(value, field)
        for field, value in (("image", image), ("template", template), ("manifest", manifest))
        if value is not None
    }
    if len(given) != 1:
        raise ValueError("pass exactly one of image, template and manifest")
    return given


def _generated_name(prefix: str) -> str:
    """A machine name the library's validator accepts, unique per boot."""
    return f"sdk-{prefix}-{secrets.token_hex(4)}"


def _optional_str(value: Any, label: str) -> str | None:
    return None if value is None else _require_non_empty_str(value, label)


def _optional_positive(value: Any, label: str) -> int | None:
    return None if value is None else _positive_int(value, label)


def _machine_name(state: Any, method: str) -> str:
    name = state.get("name") if isinstance(state, dict) else None
    if not isinstance(name, str) or not name:
        raise MachineError(f"{method} returned no machine name: {state!r}")
    return name


def _collected(name: str, token: str, timeout: float | None) -> MachineResult:
    """Wait for guest process ``token`` in machine ``name`` and decode what it
    wrote."""
    output = stream_process(name, token, timeout=timeout, on_chunk=None, error=MachineError)
    return MachineResult(
        exit_code=output.exit_code,
        stdout=output.stdout.decode("utf-8", errors="replace"),
        stderr=output.stderr.decode("utf-8", errors="replace"),
    )


class Machine:
    """A handle on one machine, by name.

    ``Machine.run`` boots a machine for one command and returns what the
    command produced. ``Machine.launch`` boots one and returns a handle to it,
    and ``Machine.create`` persists one without booting it. ``Machine("name")``
    binds a handle to a machine that already exists.

    Every boot is a named machine started the way ``mvmctl machine run -d``
    starts one, so the SDK and the CLI admit it under the same plan."""

    def __init__(self, name: str) -> None:
        self.name = _require_non_empty_str(name, "name")
        #: ``dev`` or ``prod`` when this handle came from :meth:`launch`, else
        #: ``None``: only a boot reply carries it.
        self.build_mode: str | None = None
        #: The admitted plan's id when this handle came from :meth:`launch`,
        #: for finding the boot in the audit log.
        self.plan_id: str | None = None
        #: The token of the process a launch's ``command`` started, for
        #: :meth:`wait`; ``None`` when the launch carried no command.
        self.process: str | None = None

    def __repr__(self) -> str:
        return f"Machine({self.name!r})"

    @staticmethod
    def run(
        image: str,
        command: Iterable[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        cpus: int | None = None,
        memory_mib: int | None = None,
        profile: str | None = None,
        allow_hosts: Iterable[str] | None = None,
        timeout: float | None = None,
    ) -> MachineResult:
        """Boot a machine from ``image``, run ``command`` in it, and return
        what the command produced once it ends. The machine is stopped and
        removed on every exit, including an exception.

        ``allow_hosts`` entries are ``host:port`` (``[address]:port`` for
        IPv6) and become the machine's egress allowlist; everything else is
        denied. ``env`` passes the host's environment denylist: a loader,
        shell or credential variable is refused. ``timeout`` bounds the
        command, reported as exit code 124 when it runs out. Running a command
        is a DevOnly guest operation, so a sealed image refuses it."""
        argv = _command(command)
        if argv is None:
            raise ValueError("command must be a non-empty list of non-empty str")
        machine = Machine.launch(
            image,
            name=_generated_name("run"),
            command=argv,
            env=env,
            cwd=cwd,
            cpus=cpus,
            memory_mib=memory_mib,
            profile=profile,
            allow_hosts=allow_hosts,
        )
        try:
            return machine.wait(timeout=timeout)
        finally:
            machine._discard()

    @staticmethod
    def launch(
        image: str | None = None,
        *,
        template: str | None = None,
        manifest: str | None = None,
        name: str | None = None,
        command: Iterable[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        cpus: int | None = None,
        memory_mib: int | None = None,
        profile: str | None = None,
        allow_hosts: Iterable[str] | None = None,
        ports: Iterable[str] | None = None,
        ttl_seconds: int | None = None,
        force: bool = False,
    ) -> "Machine":
        """Boot a machine and return a handle to it.

        Boots exactly one of ``image`` (an OCI reference, a rootfs path, or
        ``flake:<ref>#<attr>``), ``template`` (a template built on this host,
        by the name its image was built under) or ``manifest`` (a manifest
        path or a built slot's address). The machine is named — ``name``, or
        one generated here — and outlives this process until :meth:`stop` and
        :meth:`rm`, or until ``ttl_seconds`` runs out. ``force`` replaces a
        same-name definition whose configuration differs.

        ``command`` starts once the machine is up and keeps running; its token
        is :attr:`process`, and :meth:`wait` collects its output. ``env`` and
        ``cwd`` apply to it and need it."""
        source = _source(image, template, manifest)
        request = _launch_request(
            **source,
            mode="persistent",
            name=_require_non_empty_str(name, "name") if name is not None else _generated_name("machine"),
            command=_command(command),
            env=_env(env),
            cwd=_optional_str(cwd, "cwd"),
            cpus=_optional_positive(cpus, "cpus"),
            memory_mib=_optional_positive(memory_mib, "memory_mib"),
            profile=_optional_str(profile, "profile"),
            ttl_seconds=_optional_positive(ttl_seconds, "ttl_seconds"),
            ports=_ports(ports),
            egress=_egress(allow_hosts),
            force=True if force else None,
        )
        reply = _hostlib.call(MACHINE_RUN, request)
        if not isinstance(reply, dict):
            raise MachineError(f"{MACHINE_RUN} returned a malformed reply: {reply!r}")
        machine = Machine(_machine_name(reply.get("machine"), MACHINE_RUN))
        machine.build_mode = reply.get("build_mode")
        machine.plan_id = reply.get("plan_id")
        process = reply.get("process")
        if request.get("command") is not None and (not isinstance(process, str) or not process):
            raise MachineError(f"{MACHINE_RUN} started a command but named no process: {reply!r}")
        machine.process = process if isinstance(process, str) else None
        return machine

    @staticmethod
    def create(
        name: str,
        image: str | None = None,
        *,
        template: str | None = None,
        manifest: str | None = None,
        cpus: int | None = None,
        memory_mib: int | None = None,
        profile: str | None = None,
        allow_hosts: Iterable[str] | None = None,
        ports: Iterable[str] | None = None,
        force: bool = False,
    ) -> "Machine":
        """Persist a machine definition without booting it; start it with
        :meth:`start`. It boots exactly one of ``image``, ``template`` and
        ``manifest``, as :meth:`launch` describes. ``force`` replaces an
        existing definition of the same name."""
        request = _launch_request(
            name=_require_non_empty_str(name, "name"),
            **_source(image, template, manifest),
            cpus=_optional_positive(cpus, "cpus"),
            memory_mib=_optional_positive(memory_mib, "memory_mib"),
            profile=_optional_str(profile, "profile"),
            ports=_ports(ports),
            egress=_egress(allow_hosts),
            force=True if force else None,
        )
        return Machine(_machine_name(_hostlib.call(MACHINE_CREATE, request), MACHINE_CREATE))

    def _discard(self) -> None:
        """Stop the machine and remove its definition, reporting rather than
        raising a failure: this is cleanup, and whatever ended the caller's
        work is what they need to see."""
        for verb, method in (("stopping", MACHINE_STOP), ("removing", MACHINE_RM)):
            try:
                _hostlib.call(method, {"id": self.name})
            except (HostLibraryError, MvmTransportError) as exc:
                sys.stderr.write(f"mvm: {verb} {self.name} failed: {exc}\n")
                return

    def wait(self, *, timeout: float | None = None) -> MachineResult:
        """Wait for the command :meth:`launch` started and return what it
        produced. ``timeout`` bounds the wait, reported as exit code 124."""
        if self.process is None:
            raise MachineError(f"{self!r} was not launched with a command to wait for")
        return _collected(self.name, self.process, timeout)

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

    @overload
    def logs(self, lines: int | None = None, *, follow: Literal[False] = False) -> str: ...

    @overload
    def logs(self, lines: int | None = None, *, follow: Literal[True]) -> Iterator[str]: ...

    def logs(self, lines: int | None = None, *, follow: bool = False) -> str | Iterator[str]:
        """Captured console output, optionally only the last ``lines`` lines.

        With ``follow=True`` the output arrives as an iterator of text chunks
        that keeps yielding as the machine writes, until it stops or the
        iterator is closed; leaving a ``for`` loop early closes it.

        Decoded with replacement: console output is whatever the guest wrote,
        and a stray byte should not make the rest unreadable."""
        if follow:
            return follow_output(
                self.name,
                tail_lines=_optional_positive(lines, "lines"),
                error=MachineError,
            )
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
        return _collected(self.name, token, timeout)


__all__ = [
    "Machine",
    "MachineError",
    "MachineResult",
]
