"""Machine-oriented host SDK wrappers.

These wrappers intentionally shell to ``mvmctl machine ...`` instead of
reimplementing launch logic in Python. Admission, policy, receipts, audit, OCI
verification, and persistent spec handling stay in the CLI path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from mvm._cli import cli_resolution_hint, resolve_cli_bin
from mvm._subprocess import (
    DEFAULT_INVOKE_TIMEOUT_SEC,
    DEFAULT_MAX_OUTPUT_BYTES,
    TransportOutputOverflow,
    TransportTimeout,
    env_float,
    env_int,
    run_capped,
)

MVM_MACHINE_TIMEOUT_ENV = "MVM_MACHINE_TIMEOUT_SEC"
MVM_MACHINE_MAX_OUTPUT_ENV = "MVM_MACHINE_MAX_OUTPUT_BYTES"


@dataclass(frozen=True)
class MachineResult:
    """Captured result from a ``mvmctl machine`` subprocess."""

    exit_code: int
    stdout: str
    stderr: str


class MachineError(RuntimeError):
    """Raised when a machine SDK wrapper cannot invoke ``mvmctl``."""

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


def _cli_bin() -> str:
    return resolve_cli_bin(purpose="Machine CLI commands")


def _timeout() -> float:
    return env_float(MVM_MACHINE_TIMEOUT_ENV, DEFAULT_INVOKE_TIMEOUT_SEC)


def _max_output_bytes() -> int:
    return env_int(MVM_MACHINE_MAX_OUTPUT_ENV, DEFAULT_MAX_OUTPUT_BYTES)


def _require_non_empty_str(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty str")
    return value


def _string_list(values: Iterable[str] | None, label: str) -> list[str]:
    if values is None:
        return []
    out = list(values)
    if not all(isinstance(v, str) and v for v in out):
        raise ValueError(f"{label} must contain only non-empty str values")
    return out


def _append_repeated(argv: list[str], flag: str, values: Iterable[str] | None) -> None:
    for value in _string_list(values, flag):
        argv.extend([flag, value])


def _run_machine(argv: list[str]) -> MachineResult:
    try:
        cli_bin = _cli_bin()
    except RuntimeError as exc:
        raise MachineError(str(exc)) from exc
    full = [cli_bin, "machine", *argv]
    try:
        result = run_capped(
            full,
            input_bytes=None,
            timeout=_timeout(),
            max_output_bytes=_max_output_bytes(),
        )
    except FileNotFoundError as exc:
        raise MachineError(
            f"`{full[0]}` not found on disk; {cli_resolution_hint()}",
            argv=full,
        ) from exc
    except TransportTimeout as exc:
        raise MachineError(str(exc), argv=full) from exc
    except TransportOutputOverflow as exc:
        raise MachineError(str(exc), argv=full) from exc

    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    if result.returncode != 0:
        raise MachineError(
            f"`{' '.join(full[:3])}` failed with exit code {result.returncode}",
            argv=full,
            exit_code=result.returncode,
            stderr=stderr,
        )
    return MachineResult(exit_code=result.returncode, stdout=stdout, stderr=stderr)


def _machine_run_argv(
    *,
    image: str,
    command: list[str],
    net: bool = False,
    allow_hosts: Iterable[str] | None = None,
    cpus: int | None = None,
    memory: str | None = None,
    profile: str | None = None,
    volumes: Iterable[str] | None = None,
    env: Iterable[str] | None = None,
    timeout: int | None = None,
    receipt: str | None = None,
    json: bool = False,
    dry_run: bool = False,
) -> list[str]:
    _require_non_empty_str(image, "image")
    command = _string_list(command, "command")
    if not command:
        raise ValueError("command must be non-empty")
    argv = ["run", "--image", image]
    if net:
        argv.append("--net")
    _append_repeated(argv, "--allow-host", allow_hosts)
    if cpus is not None:
        argv.extend(["--cpus", str(cpus)])
    if memory is not None:
        argv.extend(["--memory", _require_non_empty_str(memory, "memory")])
    if profile is not None:
        argv.extend(["--profile", _require_non_empty_str(profile, "profile")])
    _append_repeated(argv, "--mount", volumes)
    _append_repeated(argv, "--env", env)
    if timeout is not None:
        argv.extend(["--timeout", str(timeout)])
    if receipt is not None:
        argv.extend(["--receipt", _require_non_empty_str(receipt, "receipt")])
    if json:
        argv.append("--json")
    if dry_run:
        argv.append("--dry-run")
    argv.extend(["--", *command])
    return argv


def _machine_create_argv(
    *,
    name: str,
    image: str | None = None,
    manifest: str | None = None,
    net: bool = False,
    allow_hosts: Iterable[str] | None = None,
    cpus: int | None = None,
    memory: str | None = None,
    mem_initial: str | None = None,
    profile: str | None = None,
    force: bool = False,
    json: bool = False,
) -> list[str]:
    name = _require_non_empty_str(name, "name")
    if image is not None and manifest is not None:
        raise ValueError("Machine.create accepts image OR manifest, not both")
    argv = ["create", name]
    if image is not None:
        argv.extend(["--image", _require_non_empty_str(image, "image")])
    if manifest is not None:
        argv.extend(["--manifest", _require_non_empty_str(manifest, "manifest")])
    if net:
        argv.append("--net")
    _append_repeated(argv, "--allow-host", allow_hosts)
    if cpus is not None:
        argv.extend(["--cpus", str(cpus)])
    if memory is not None:
        argv.extend(["--memory", _require_non_empty_str(memory, "memory")])
    if mem_initial is not None:
        argv.extend(["--mem-initial", _require_non_empty_str(mem_initial, "mem_initial")])
    if profile is not None:
        argv.extend(["--profile", _require_non_empty_str(profile, "profile")])
    if force:
        argv.append("--force")
    if json:
        argv.append("--json")
    return argv


def _machine_check_artifact_argv(
    *,
    path: str,
    key: str | None = None,
    json: bool = False,
) -> list[str]:
    argv = ["check-artifact", _require_non_empty_str(path, "path")]
    if key is not None:
        argv.extend(["--key", _require_non_empty_str(key, "key")])
    if json:
        argv.append("--json")
    return argv


def _machine_start_argv(
    *,
    name: str,
    receipt: str | None = None,
    json: bool = False,
    dry_run: bool = False,
) -> list[str]:
    # `machine start` takes a positional name, not `--name`.
    argv = ["start", _require_non_empty_str(name, "name")]
    if receipt is not None:
        argv.extend(["--receipt", _require_non_empty_str(receipt, "receipt")])
    if json:
        argv.append("--json")
    if dry_run:
        argv.append("--dry-run")
    return argv


def _machine_exec_argv(
    *,
    name: str,
    command: list[str],
    force: bool = False,
) -> list[str]:
    command = _string_list(command, "command")
    if not command:
        raise ValueError("command must be non-empty")
    # `machine exec` takes a positional name, not `--name`.
    argv = ["exec", _require_non_empty_str(name, "name")]
    if force:
        argv.append("--force")
    argv.extend(["--", *command])
    return argv


def _machine_shell_argv(*, name: str, force: bool = False) -> list[str]:
    # `machine shell` takes a positional name, not `--name`.
    argv = ["shell", _require_non_empty_str(name, "name")]
    if force:
        argv.append("--force")
    return argv


def _machine_stop_argv(*, name: str) -> list[str]:
    # `machine stop` takes a positional name, not `--name` (the CLI rejects the
    # flag form). See the shared `stop.argv` fixture. Pass `--yes` because the
    # SDK runs the CLI non-interactively — without it `machine stop` prompts for
    # y/n confirmation and aborts on no TTY.
    return ["stop", _require_non_empty_str(name, "name"), "--yes"]


def _machine_ls_argv(*, json: bool = False) -> list[str]:
    argv = ["ls"]
    if json:
        argv.append("--json")
    return argv


def _machine_logs_argv(
    *,
    name: str,
    follow: bool = False,
    lines: int | None = None,
) -> list[str]:
    argv = ["logs", _require_non_empty_str(name, "name")]
    if follow:
        argv.append("--follow")
    if lines is not None:
        argv.extend(["--lines", str(lines)])
    return argv


def _machine_inspect_argv(*, name: str, json: bool = False) -> list[str]:
    argv = ["inspect", _require_non_empty_str(name, "name")]
    if json:
        argv.append("--json")
    return argv


def _machine_rm_argv(
    *,
    names: Iterable[str] | None = None,
    all: bool = False,
    yes: bool = False,
    json: bool = False,
) -> list[str]:
    name_list = _string_list(names, "names")
    # The CLI requires exactly one of names / --all (a clap ArgGroup).
    if all == bool(name_list):
        raise ValueError("Machine.rm requires exactly one of names or all=True")
    argv = ["rm"]
    if all:
        argv.append("--all")
    else:
        argv.extend(name_list)
    if yes:
        argv.append("--yes")
    if json:
        argv.append("--json")
    return argv


class Machine:
    """Persistent machine handle plus ephemeral ``machine run`` helpers."""

    def __init__(self, name: str) -> None:
        self.name = _require_non_empty_str(name, "name")

    @staticmethod
    def run(
        *,
        image: str,
        command: list[str],
        net: bool = False,
        allow_hosts: Iterable[str] | None = None,
        cpus: int | None = None,
        memory: str | None = None,
        profile: str | None = None,
        volumes: Iterable[str] | None = None,
        env: Iterable[str] | None = None,
        timeout: int | None = None,
        receipt: str | None = None,
        json: bool = False,
        dry_run: bool = False,
    ) -> MachineResult:
        return _run_machine(
            _machine_run_argv(
                image=image,
                command=command,
                net=net,
                allow_hosts=allow_hosts,
                cpus=cpus,
                memory=memory,
                profile=profile,
                volumes=volumes,
                env=env,
                timeout=timeout,
                receipt=receipt,
                json=json,
                dry_run=dry_run,
            )
        )

    @staticmethod
    def create(
        *,
        name: str,
        image: str | None = None,
        manifest: str | None = None,
        net: bool = False,
        allow_hosts: Iterable[str] | None = None,
        cpus: int | None = None,
        memory: str | None = None,
        mem_initial: str | None = None,
        profile: str | None = None,
        force: bool = False,
        json: bool = False,
    ) -> "Machine":
        _run_machine(
            _machine_create_argv(
                name=name,
                image=image,
                manifest=manifest,
                net=net,
                allow_hosts=allow_hosts,
                cpus=cpus,
                memory=memory,
                mem_initial=mem_initial,
                profile=profile,
                force=force,
                json=json,
            )
        )
        return Machine(name)

    @staticmethod
    def check_artifact(
        *,
        path: str,
        key: str | None = None,
        json: bool = False,
    ) -> MachineResult:
        return _run_machine(_machine_check_artifact_argv(path=path, key=key, json=json))

    @staticmethod
    def ls(*, json: bool = False) -> MachineResult:
        return _run_machine(_machine_ls_argv(json=json))

    def start(
        self,
        *,
        receipt: str | None = None,
        json: bool = False,
        dry_run: bool = False,
    ) -> MachineResult:
        return _run_machine(
            _machine_start_argv(name=self.name, receipt=receipt, json=json, dry_run=dry_run)
        )

    def exec(self, command: list[str], *, force: bool = False) -> MachineResult:
        return _run_machine(_machine_exec_argv(name=self.name, command=command, force=force))

    def shell(self, *, force: bool = False) -> MachineResult:
        return _run_machine(_machine_shell_argv(name=self.name, force=force))

    def stop(self) -> MachineResult:
        return _run_machine(_machine_stop_argv(name=self.name))

    def logs(self, *, follow: bool = False, lines: int | None = None) -> MachineResult:
        return _run_machine(_machine_logs_argv(name=self.name, follow=follow, lines=lines))

    def inspect(self, *, json: bool = False) -> MachineResult:
        return _run_machine(_machine_inspect_argv(name=self.name, json=json))

    def rm(self, *, yes: bool = False, json: bool = False) -> MachineResult:
        return _run_machine(_machine_rm_argv(names=[self.name], yes=yes, json=json))


__all__ = [
    "MVM_MACHINE_MAX_OUTPUT_ENV",
    "MVM_MACHINE_TIMEOUT_ENV",
    "Machine",
    "MachineError",
    "MachineResult",
]
