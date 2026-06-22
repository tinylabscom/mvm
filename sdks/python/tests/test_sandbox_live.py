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
    proc_wait_stdout: str = "",
    proc_wait_exit: int = 0,
    fs_exit: int = 0,
    cp_exit: int = 0,
    forward_sleep: int = 0,
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
if [ "$verb" = "machine" ]; then
  verb=${{1:-}}
  shift || true
fi
case "$verb" in
  up | run)
    # Record stdin for completeness (mvmctl machine run has none).
    if [ -t 0 ]; then :; else cat > {stdin_dir!s}/up-stdin.bin || true; fi
    if [ "{up_exit}" -eq 0 ]; then
      echo '{envelope_json}'
    fi
    exit {up_exit}
    ;;
  proc)
    sub=$1
    if [ -t 0 ]; then :; else cat > {stdin_dir!s}/proc-stdin.bin || true; fi
    if [ "$sub" = "start" ]; then
      if [ "{proc_exit}" -eq 0 ]; then echo "pid-token-abc123"; fi
      exit {proc_exit}
    elif [ "$sub" = "wait" ]; then
      printf '%s' '{proc_wait_stdout}'
      exit {proc_wait_exit}
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
  forward)
    # `mvmctl forward` blocks in real use; the fixture optionally sleeps
    # so a test can assert the SDK terminates it on teardown.
    sleep {forward_sleep}
    exit 0
    ;;
  stop)
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
    assert calls[0].startswith("machine run -d --up-json --name ")
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
    assert calls[1].startswith("machine proc start sb-dev-vm")
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
    assert not any(c.startswith("machine proc") for c in calls)


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
    assert any(c.startswith("machine fs write sb-fs-vm /app/config.json") for c in calls)
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
    assert any(c == "machine stop sb-kill-vm" for c in calls)


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
    down_calls = [c for c in calls if c.startswith("machine stop ")]
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
        c.startswith(f"machine cp {host_file} sb-cp-vm:/app/local.txt") for c in calls
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
        c.startswith(f"machine cp sb-cp-vm:/app/out.txt {dest}") for c in calls
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


# ── forward / ports (Plan 125 B1b) ───────────────────────────────────


def test_forward_shells_to_mvmctl_forward(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-fwd-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.create("python-dev")
    sb.forward(8080, 80)

    # The fixture `forward` exits immediately (sleep 0); wait for it so its
    # log line is flushed before we assert.
    sb._live._forwards[0].wait(timeout=5)
    calls = _read_fixture_log(tmp_path)
    assert any(
        c.startswith("machine forward sb-fwd-vm --port 8080:80") for c in calls
    ), calls


def test_forward_process_terminated_on_kill(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-fwd-vm", "build_mode": "dev"},
        forward_sleep=30,
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.create("python-dev")
    sb.forward(8080, 80)
    proc = sb._live._forwards[0]
    assert proc.poll() is None  # still running (blocked on sleep)

    sb.kill()
    proc.wait(timeout=5)
    assert proc.returncode is not None  # terminated by teardown


def test_forward_refused_in_record_mode() -> None:
    os.environ["MVM_SDK_MODE"] = "record"
    sb = mvm.Sandbox.create("python-dev")
    with pytest.raises(mvm.SandboxModeError):
        sb.forward(8080, 80)


# ── async surface: aexec + `async with` (Plan 125 B2) ────────────────


def test_aexec_runs_and_returns_result(tmp_path: Path) -> None:
    import asyncio

    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-aex-vm", "build_mode": "dev"},
        proc_wait_stdout="4",
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    async def body() -> None:
        async with mvm.Sandbox.create("python-dev") as sb:
            r = await sb.aexec("python", "-c", "print(2 + 2)")
            assert r.exit_code == 0
            assert r.stdout == "4"

    asyncio.run(body())
    calls = _read_fixture_log(tmp_path)
    assert any(c.startswith("machine proc start sb-aex-vm") for c in calls), calls
    assert any(c.startswith("machine proc wait sb-aex-vm pid-token-abc123") for c in calls), calls


def test_async_context_manager_kills_on_exit(tmp_path: Path) -> None:
    import asyncio

    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-aex-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    async def body() -> None:
        async with mvm.Sandbox.create("python-dev"):
            pass

    asyncio.run(body())
    calls = _read_fixture_log(tmp_path)
    assert sum(1 for c in calls if c.startswith("machine stop ")) == 1, calls


def test_aexec_dev_only_on_prod_template(tmp_path: Path) -> None:
    import asyncio

    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-prod-vm", "build_mode": "prod"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    async def body() -> None:
        async with mvm.Sandbox.create("python-prod") as sb:
            with pytest.raises(mvm.SandboxDevOnly):
                await sb.aexec("python", "-c", "x")

    asyncio.run(body())


def test_aexec_refused_in_record_mode() -> None:
    import asyncio

    os.environ["MVM_SDK_MODE"] = "record"

    async def body() -> None:
        sb = mvm.Sandbox.create("python-dev")
        with pytest.raises(mvm.SandboxModeError):
            await sb.aexec("python")

    asyncio.run(body())


# ── lifecycle: id + info (Plan 125 B3) ───────────────────────────────


def test_id_is_vm_id_when_live(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-id-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    sb = mvm.Sandbox.create("python-dev", workload_id="wl-1")
    assert sb.id == "sb-id-vm"


def test_id_is_workload_id_in_record_mode() -> None:
    os.environ["MVM_SDK_MODE"] = "record"
    sb = mvm.Sandbox.create("python-dev", workload_id="wl-1")
    assert sb.id == "wl-1"


def test_info_reflects_live_state(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-id-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    sb = mvm.Sandbox.create("python-dev", workload_id="wl-1")
    info = sb.info()
    assert info.id == "sb-id-vm"
    assert info.workload_id == "wl-1"
    assert info.build_mode == "dev"
    assert info.live is True


def test_info_reflects_record_state() -> None:
    os.environ["MVM_SDK_MODE"] = "record"
    sb = mvm.Sandbox.create("python-dev", workload_id="wl-1")
    info = sb.info()
    assert info.id == "wl-1"
    assert info.workload_id == "wl-1"
    assert info.build_mode is None
    assert info.live is False


# ── CodeSandbox typed helper (Plan 125 C1) ───────────────────────────


def test_code_sandbox_run_returns_stdout(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-cs-vm", "build_mode": "dev"},
        proc_wait_stdout="4",
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    with mvm.CodeSandbox(image="python:slim") as cs:
        assert cs.run("print(2 + 2)") == "4"

    calls = _read_fixture_log(tmp_path)
    assert any(c.startswith("machine proc start sb-cs-vm") and "-- python -c" in c for c in calls), calls
    assert any(c.startswith("machine proc wait sb-cs-vm") for c in calls), calls


def test_code_sandbox_run_raises_on_nonzero(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-cs-vm", "build_mode": "dev"},
        proc_wait_exit=1,
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    with mvm.CodeSandbox(image="python:slim") as cs:
        with pytest.raises(mvm.CodeError):
            cs.run("raise SystemExit(1)")


def test_code_sandbox_install_package(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-cs-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    with mvm.CodeSandbox(image="python:slim") as cs:
        cs.install_package("requests")

    calls = _read_fixture_log(tmp_path)
    assert any("-- pip install requests" in c for c in calls), calls


def test_code_sandbox_run_script_copies_then_execs(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-cs-vm", "build_mode": "dev"},
        proc_wait_stdout="ok",
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    host_script = tmp_path / "job.py"
    host_script.write_text("print('ok')")

    with mvm.CodeSandbox(image="python:slim") as cs:
        assert cs.run_script(str(host_script)) == "ok"

    calls = _read_fixture_log(tmp_path)
    assert any(c.startswith("machine cp ") and "sb-cs-vm:/tmp/job.py" in c for c in calls), calls
    assert any("-- python /tmp/job.py" in c for c in calls), calls


def test_code_sandbox_node_uses_node_runner(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-cs-vm", "build_mode": "dev"},
        proc_wait_stdout="4",
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    with mvm.CodeSandbox(image="node:22") as cs:
        cs.run("console.log(2 + 2)")

    calls = _read_fixture_log(tmp_path)
    assert any("-- node -e" in c for c in calls), calls


# ── BrowserSandbox typed helper (Plan 125 C2) ────────────────────────


def test_browser_sandbox_forwards_cdp_and_endpoint(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-br-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    bs = mvm.BrowserSandbox("chromium")
    try:
        assert bs.endpoint() == "http://localhost:9222"
        bs.sandbox._live._forwards[0].wait(timeout=5)
        calls = _read_fixture_log(tmp_path)
        assert any(c.startswith("machine forward sb-br-vm --port 9222:9222") for c in calls), calls
    finally:
        bs.kill()


def test_browser_sandbox_custom_host_port(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-br-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    bs = mvm.BrowserSandbox("chromium", host_port=18222)
    try:
        assert bs.endpoint() == "http://localhost:18222"
        bs.sandbox._live._forwards[0].wait(timeout=5)
        calls = _read_fixture_log(tmp_path)
        assert any(c.startswith("machine forward sb-br-vm --port 18222:9222") for c in calls), calls
    finally:
        bs.kill()


def test_browser_sandbox_unknown_browser_raises() -> None:
    with pytest.raises(ValueError, match="browser"):
        mvm.BrowserSandbox("safari")
