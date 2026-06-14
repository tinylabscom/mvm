"""Live-mode Sandbox tests (Plan 73 Followup H-live).

Each test stands up a fixture `mvmctl` shell script that records its
argv to a sidecar file and emits whatever stdout the live transport
needs (e.g. the `mvmctl up --up-json` envelope). The SDK shells to
the fixture via `MVM_CLI_BIN`; no real microVM boots.

What we assert:

1. `Sandbox.create` parses the JSON envelope and stashes vm_id +
   build_mode on the live transport.
2. `Sandbox.commands.start` against a dev template shells to
   `mvmctl proc start` with the right argv shape.
3. `Sandbox.commands.start` against a prod template raises
   `SandboxDevOnly` *before* any vsock shell (security claim 4
   client-side enforcement).
4. `Sandbox.files.write` shells to `mvmctl fs write` with bytes on
   stdin.
5. `Sandbox.kill()` shells to `mvmctl down`.
6. The context-manager `__exit__` calls `mvmctl down` once.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

import mvm
from mvm._sandbox import _parse_up_envelope


@pytest.fixture(autouse=True)
def _isolate() -> None:
    """Clean module state + env between tests."""
    mvm.reset_recording()
    os.environ.pop("MVM_SDK_MODE", None)
    os.environ.pop("MVM_CLI_BIN", None)
    yield
    mvm.reset_recording()
    os.environ.pop("MVM_SDK_MODE", None)
    os.environ.pop("MVM_CLI_BIN", None)


def _write_fixture_mvmctl(
    tmp_path: Path,
    *,
    up_envelope: dict[str, str | int] | None,
    up_exit: int = 0,
    proc_exit: int = 0,
    fs_exit: int = 0,
    cp_exit: int = 0,
    down_exit: int = 0,
) -> Path:
    """Write a shell script that pretends to be `mvmctl`. It
    records each invocation's argv + stdin to sidecar files so
    tests can assert wire shape, and emits the requested
    envelope on `mvmctl up --up-json`.
    """
    log = tmp_path / "fixture-calls.log"
    stdin_dir = tmp_path / "fixture-stdin"
    stdin_dir.mkdir(exist_ok=True)

    envelope_json = json.dumps(up_envelope) if up_envelope is not None else ""

    script = tmp_path / "fake-mvmctl"
    script.write_text(
        f"""#!/usr/bin/env bash
set -u
verb=${{1:-}}
shift || true
echo "$verb $*" >> {log!s}
case "$verb" in
  up)
    # Record stdin for completeness (mvmctl up has none).
    if [ -t 0 ]; then :; else cat > {stdin_dir!s}/up-stdin.bin || true; fi
    if [ "{up_exit}" -eq 0 ]; then
      echo '{envelope_json}'
    fi
    exit {up_exit}
    ;;
  proc)
    sub=$1
    if [ -t 0 ]; then :; else cat > {stdin_dir!s}/proc-stdin.bin || true; fi
    if [ "{proc_exit}" -eq 0 ] && [ "$sub" = "start" ]; then
      echo "pid-token-abc123"
    fi
    exit {proc_exit}
    ;;
  fs)
    sub=$1
    if [ "$sub" = "write" ]; then
      cat > {stdin_dir!s}/fs-write-stdin.bin
    fi
    exit {fs_exit}
    ;;
  cp)
    exit {cp_exit}
    ;;
  down)
    exit {down_exit}
    ;;
  *)
    echo "fake-mvmctl: unrecognized verb $verb" >&2
    exit 2
    ;;
esac
"""
    )
    script.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)
    return script


def _read_fixture_log(tmp_path: Path) -> list[str]:
    log = tmp_path / "fixture-calls.log"
    if not log.exists():
        return []
    return [line for line in log.read_text().splitlines() if line]


# ── envelope parsing ─────────────────────────────────────────────────


def test_parse_up_envelope_accepts_dev_payload() -> None:
    parsed = _parse_up_envelope(
        '{"schema_version": 1, "vm_id": "sb-xyz", "build_mode": "dev"}\n',
        argv=["mvmctl", "up"],
    )
    assert parsed == {"vm_id": "sb-xyz", "build_mode": "dev"}


def test_parse_up_envelope_rejects_unknown_schema() -> None:
    with pytest.raises(mvm.SandboxLiveError, match="schema_version"):
        _parse_up_envelope(
            '{"schema_version": 99, "vm_id": "x", "build_mode": "dev"}',
            argv=["mvmctl", "up"],
        )


def test_parse_up_envelope_rejects_missing_vm_id() -> None:
    with pytest.raises(mvm.SandboxLiveError, match="vm_id"):
        _parse_up_envelope(
            '{"schema_version": 1, "build_mode": "dev"}',
            argv=["mvmctl", "up"],
        )


def test_parse_up_envelope_rejects_unknown_build_mode() -> None:
    with pytest.raises(mvm.SandboxLiveError, match="build_mode"):
        _parse_up_envelope(
            '{"schema_version": 1, "vm_id": "x", "build_mode": "staging"}',
            argv=["mvmctl", "up"],
        )


def test_parse_up_envelope_rejects_empty_stdout() -> None:
    with pytest.raises(mvm.SandboxLiveError, match="empty stdout"):
        _parse_up_envelope("", argv=["mvmctl", "up"])


def test_parse_up_envelope_rejects_invalid_json() -> None:
    with pytest.raises(mvm.SandboxLiveError, match="not valid JSON"):
        _parse_up_envelope("not json", argv=["mvmctl", "up"])


# ── live-mode boot ───────────────────────────────────────────────────


def test_sandbox_create_live_parses_envelope_and_records_vm(
    tmp_path: Path,
) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={
            "schema_version": 1,
            "vm_id": "sb-test-vm",
            "build_mode": "dev",
        },
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.create("python-3.12", workload_id="testwid")
    assert sb._live is not None
    assert sb._live.vm_id == "sb-test-vm"
    assert sb._live.build_mode == "dev"

    calls = _read_fixture_log(tmp_path)
    assert len(calls) == 1
    assert calls[0].startswith("up --up-json --name ")
    assert "--manifest python-3.12" in calls[0]
    assert "--ttl" in calls[0]


def test_sandbox_create_live_propagates_mvmctl_failure(
    tmp_path: Path,
) -> None:
    script = _write_fixture_mvmctl(tmp_path, up_envelope=None, up_exit=7)
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    with pytest.raises(mvm.SandboxLiveError, match="exit code 7"):
        mvm.Sandbox.create("python-3.12")


# ── commands.start (claim-4 dev-only enforcement) ──────────────────


def test_commands_start_dev_template_shells_to_proc_start(
    tmp_path: Path,
) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={
            "schema_version": 1,
            "vm_id": "sb-dev-vm",
            "build_mode": "dev",
        },
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.create("python-dev")
    sb.commands.start(["python", "run.py"], env={"MODE": "test"})

    calls = _read_fixture_log(tmp_path)
    # 1: up, 2: proc start
    assert len(calls) == 2
    assert calls[1].startswith("proc start sb-dev-vm")
    assert "-e MODE=test" in calls[1]
    assert "-- python run.py" in calls[1]


def test_commands_start_prod_template_raises_sandbox_dev_only(
    tmp_path: Path,
) -> None:
    """Security claim 4: SDK refuses commands.start client-side
    before any vsock traffic when the template is prod."""
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={
            "schema_version": 1,
            "vm_id": "sb-prod-vm",
            "build_mode": "prod",
        },
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.create("python-prod")
    # Only 1 call (`up`) so far.
    assert len(_read_fixture_log(tmp_path)) == 1

    with pytest.raises(mvm.SandboxDevOnly, match="dev-mode template"):
        sb.commands.start(["python", "run.py"])

    # The SDK must NOT have shelled to `mvmctl proc start`.
    calls = _read_fixture_log(tmp_path)
    assert len(calls) == 1, f"unexpected vsock traffic: {calls}"
    assert not any(c.startswith("proc") for c in calls)


# ── files.write ──────────────────────────────────────────────────────


def test_files_write_shells_with_stdin_bytes(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={
            "schema_version": 1,
            "vm_id": "sb-fs-vm",
            "build_mode": "dev",
        },
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.create("python-dev")
    sb.files.write("/app/config.json", b'{"x":1}')

    calls = _read_fixture_log(tmp_path)
    assert any(c.startswith("fs write sb-fs-vm /app/config.json") for c in calls)
    stdin_path = tmp_path / "fixture-stdin" / "fs-write-stdin.bin"
    assert stdin_path.read_bytes() == b'{"x":1}'


# ── kill / context manager ───────────────────────────────────────────


def test_kill_shells_to_mvmctl_down(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={
            "schema_version": 1,
            "vm_id": "sb-kill-vm",
            "build_mode": "dev",
        },
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.create("python-dev")
    sb.kill()

    calls = _read_fixture_log(tmp_path)
    assert any(c == "down sb-kill-vm" for c in calls)


def test_context_manager_kills_on_exit(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={
            "schema_version": 1,
            "vm_id": "sb-ctx-vm",
            "build_mode": "dev",
        },
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    with mvm.Sandbox.create("python-dev") as sb:
        sb.files.write("/app/data.txt", "hi")

    calls = _read_fixture_log(tmp_path)
    down_calls = [c for c in calls if c.startswith("down ")]
    assert len(down_calls) == 1


def test_one_sandbox_per_process_in_live_mode(tmp_path: Path) -> None:
    """v1 scope: one app per workload — a second `Sandbox.create`
    must refuse while the first is live."""
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={
            "schema_version": 1,
            "vm_id": "sb-first",
            "build_mode": "dev",
        },
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    mvm.Sandbox.create("python-dev")
    with pytest.raises(RuntimeError, match="already active"):
        mvm.Sandbox.create("python-dev")


# ── copy_in / copy_out (Plan 125 B1) ─────────────────────────────────


def test_copy_in_shells_to_mvmctl_cp(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-cp-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    host_file = tmp_path / "local.txt"
    host_file.write_text("hello")

    sb = mvm.Sandbox.create("python-dev")
    sb.copy_in(str(host_file), "/app/local.txt")

    calls = _read_fixture_log(tmp_path)
    assert any(
        c.startswith(f"cp {host_file} sb-cp-vm:/app/local.txt") for c in calls
    ), calls


def test_copy_out_shells_to_mvmctl_cp(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-cp-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    dest = tmp_path / "out.txt"

    sb = mvm.Sandbox.create("python-dev")
    sb.copy_out("/app/out.txt", str(dest))

    calls = _read_fixture_log(tmp_path)
    assert any(
        c.startswith(f"cp sb-cp-vm:/app/out.txt {dest}") for c in calls
    ), calls


def test_copy_in_propagates_mvmctl_failure(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-cp-vm", "build_mode": "dev"},
        cp_exit=4,
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    host_file = tmp_path / "local.txt"
    host_file.write_text("x")

    sb = mvm.Sandbox.create("python-dev")
    with pytest.raises(mvm.SandboxLiveError):
        sb.copy_in(str(host_file), "/app/local.txt")


def test_copy_in_refused_in_record_mode() -> None:
    # Live-only, like exec — record mode has no return-value materialisation
    # for a host→guest copy; declarative staging uses files.write.
    os.environ["MVM_SDK_MODE"] = "record"
    sb = mvm.Sandbox.create("python-dev")
    with pytest.raises(mvm.SandboxModeError):
        sb.copy_in("/tmp/x", "/app/x")
