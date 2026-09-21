"""Live-mode Sandbox tests (Plan 73 Followup H-live).

Each test stands up a fixture `mvmctl` shell script that records its
argv to a sidecar file and emits whatever stdout the live transport
needs (e.g. the `mvmctl machine run --up-json` envelope). The SDK shells to
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
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import mvm
from mvm._sandbox import _derive_attached_build_mode, _parse_up_envelope


@pytest.fixture(autouse=True)
def _isolate() -> None:
    """Clean module state + env between tests."""
    mvm.reset_recording()
    os.environ.pop("MVM_SDK_MODE", None)
    os.environ.pop("MVM_CLI_BIN", None)
    os.environ.pop("MVM_SDK_RUN_PROFILE", None)
    yield
    mvm.reset_recording()
    os.environ.pop("MVM_SDK_MODE", None)
    os.environ.pop("MVM_CLI_BIN", None)
    os.environ.pop("MVM_SDK_RUN_PROFILE", None)


def _write_fixture_mvmctl(
    tmp_path: Path,
    *,
    up_envelope: dict[str, str | int] | None,
    up_exit: int = 0,
    proc_exit: int = 0,
    proc_wait_stdout: str = "",
    proc_wait_stderr: str = "",
    proc_wait_exit: int = 0,
    fs_exit: int = 0,
    fs_read_stdout: bytes = b"",
    fs_ls_json: str = "[]",
    fs_stat_json: str = "{}",
    cp_exit: int = 0,
    forward_sleep: int = 0,
    down_exit: int = 0,
    ls_out: str = "[]",
    ls_exit: int = 0,
) -> Path:
    """Write a shell script that pretends to be `mvmctl`. It
    records each invocation's argv + stdin to sidecar files so
    tests can assert wire shape, and emits the requested
    envelope on `mvmctl machine run --up-json`.
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
      printf '%s' '{proc_wait_stderr}' >&2
      exit {proc_wait_exit}
    fi
    exit {proc_exit}
    ;;
  fs)
    sub=$1
    if [ "$sub" = "write" ]; then
      cat > {stdin_dir!s}/fs-write-stdin.bin
    elif [ "$sub" = "read" ]; then
      printf '%s' '{fs_read_stdout.decode("latin1")}'
    elif [ "$sub" = "ls" ]; then
      printf '%s' '{fs_ls_json}'
    elif [ "$sub" = "stat" ]; then
      printf '%s' '{fs_stat_json}'
    fi
    exit {fs_exit}
    ;;
  ls)
    # `mvmctl machine ls --json` — Sandbox.connect() reads this to
    # re-derive an attached machine's build_mode.
    echo '{ls_out}'
    exit {ls_exit}
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


def test_sandbox_create_live_propagates_an_explicit_dev_profile(
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
    os.environ[mvm.MVM_SDK_RUN_PROFILE_ENV] = "dev"

    mvm.Sandbox.create("python-3.12", workload_id="testwid")

    call = _read_fixture_log(tmp_path)[0]
    assert "--profile dev" in call


def test_sandbox_create_live_rejects_an_unknown_profile_before_boot(
    tmp_path: Path,
) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={
            "schema_version": 1,
            "vm_id": "unused",
            "build_mode": "dev",
        },
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    os.environ[mvm.MVM_SDK_RUN_PROFILE_ENV] = "unknown"

    with pytest.raises(mvm.SandboxModeError, match="MVM_SDK_RUN_PROFILE"):
        mvm.Sandbox.create("python-3.12")

    assert _read_fixture_log(tmp_path) == []


def test_live_image_boot_lowers_literal_env_allowlist_and_command(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "browser", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    mvm.Sandbox.create(
        image=mvm.OBSCURA_IMAGE,
        env={"MODE": "safe"},
        network={
            "mode": "none",
            "egress": {"allowlist": [{"host": "example.com", "port": 443}]},
        },
        command=["/obscura", "serve"],
    )
    call = _read_fixture_log(tmp_path)[0]
    assert f"--image {mvm.OBSCURA_IMAGE}" in call
    assert "--env MODE=safe" in call
    assert "--allow-host example.com:443" in call
    assert "-- /obscura serve" in call


def test_live_create_rejects_secret_and_unrepresentable_options_before_boot(
    tmp_path: Path,
) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "unused", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    with pytest.raises(mvm.SandboxModeError, match="only literal"):
        mvm.Sandbox.create(
            "minimal",
            env={
                "TOKEN": mvm.secret(
                    "token", type="bearer", hosts=["example.com"]
                )
            },
        )
    assert _read_fixture_log(tmp_path) == []

    with pytest.raises(mvm.SandboxModeError, match="resources"):
        mvm.Sandbox.create("minimal", resources={"cpu_cores": 1})
    assert _read_fixture_log(tmp_path) == []

    with pytest.raises(mvm.SandboxModeError, match="unknown fields"):
        mvm.Sandbox.create("minimal", network={"raw_ip_stack": True})
    assert _read_fixture_log(tmp_path) == []


def test_sandbox_create_live_propagates_mvmctl_failure(
    tmp_path: Path,
) -> None:
    script = _write_fixture_mvmctl(tmp_path, up_envelope=None, up_exit=7)
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    with pytest.raises(mvm.SandboxLiveError, match="exit code 7"):
        mvm.Sandbox.create("python-3.12")


def test_obscura_provider_uses_pinned_image_fixed_safe_command_and_allowlist(
    tmp_path: Path,
) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "obscura", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    browser = mvm.BrowserSandbox(
        "obscura",
        network={
            "mode": "none",
            "egress": {"allowlist": [{"host": "example.com", "port": 443}]},
        },
    )
    try:
        call = _read_fixture_log(tmp_path)[0]
        assert f"--image {mvm.OBSCURA_IMAGE}" in call
        assert "--allow-host example.com:443" in call
        assert "-- /obscura --proxy http://127.0.0.1:1080 serve" in call
        assert "--host 127.0.0.1 --port 9222" in call
        assert "private" not in call
        assert "stealth" not in call
    finally:
        browser.kill()


def test_obscura_provider_refuses_command_override_before_boot(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "unused", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    with pytest.raises(ValueError, match="does not allow command overrides"):
        mvm.BrowserSandbox("obscura", command=["/bin/sh"])
    assert _read_fixture_log(tmp_path) == []


def test_browser_readiness_validates_cdp_and_timeout_cleans_up(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = json.dumps(
                {"webSocketDebuggerUrl": "ws://127.0.0.1/devtools/browser/test"}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "browser", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    browser = mvm.BrowserSandbox("chromium", host_port=port)
    try:
        assert browser.wait_until_ready(timeout=1) == (
            "ws://127.0.0.1/devtools/browser/test"
        )
    finally:
        browser.kill()
        server.shutdown()
        server.server_close()

    mvm.reset_recording()
    failing = mvm.BrowserSandbox("chromium", host_port=port)
    with pytest.raises(mvm.BrowserReadyError):
        failing.wait_until_ready(timeout=0.02, retry_interval=0.002)
    assert any(call.startswith("machine stop browser --yes") for call in _read_fixture_log(tmp_path))


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


def test_process_handle_waits_streams_and_controls_process(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-proc-vm", "build_mode": "dev"},
        proc_wait_stdout="out",
        proc_wait_stderr="err",
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    sb = mvm.Sandbox.create("python-3.12")
    handle = sb.commands.start(["python", "run.py"])
    assert handle is not None
    events: list[mvm.ProcessStreamEvent] = []
    result = handle.wait(on_event=events.append)
    assert result.stdout == b"out"
    assert result.stderr == b"err"
    assert {(event.stream, event.data) for event in events} == {
        ("stdout", b"out"),
        ("stderr", b"err"),
    }
    handle.send_stdin("input")
    handle.signal(15)
    handle.kill()
    calls = _read_fixture_log(tmp_path)
    assert any("machine proc stdin sb-proc-vm" in call for call in calls)
    assert any("machine proc signal sb-proc-vm" in call for call in calls)
    assert any("machine proc kill sb-proc-vm" in call for call in calls)
    sb.kill()


def test_files_runtime_surface_reads_lists_stats_and_mutates(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-fs-vm", "build_mode": "dev"},
        fs_read_stdout=b"hello",
        fs_ls_json='[{"name":"note.txt","kind":"file","size":5}]',
        fs_stat_json='{"canonical_path":"/app/note.txt","kind":"file","mode":420,"size":5,"mtime":null}',
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    sb = mvm.Sandbox.create("python-3.12")
    assert sb.files.read("/app/note.txt") == b"hello"
    assert sb.files.list("/app")[0].name == "note.txt"
    assert sb.files.stat("/app/note.txt").size == 5
    sb.files.mkdir("/app/new", parents=True)
    sb.files.remove("/app/old", recursive=True)
    sb.files.move("/app/a", "/app/b")
    calls = _read_fixture_log(tmp_path)
    assert any("machine fs read sb-fs-vm /app/note.txt" in call for call in calls)
    assert any("machine fs ls sb-fs-vm /app --json" in call for call in calls)
    assert any("machine fs stat sb-fs-vm /app/note.txt --json" in call for call in calls)
    assert any("machine fs mkdir sb-fs-vm /app/new" in call for call in calls)
    assert any("machine fs rm sb-fs-vm /app/old" in call for call in calls)
    assert any("machine fs mv sb-fs-vm /app/a /app/b" in call for call in calls)
    sb.kill()


def test_all_dev_only_live_verbs_fail_closed_on_prod(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-prod-vm", "build_mode": "prod"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)
    sb = mvm.Sandbox.create("python-3.12")
    operations = [
        lambda: sb.commands.start(["python"]),
        lambda: sb.exec("python"),
        lambda: sb.files.write("/app/x", b"x"),
        lambda: sb.files.read("/app/x"),
        lambda: sb.files.list("/app"),
        lambda: sb.files.stat("/app/x"),
        lambda: sb.files.mkdir("/app/x"),
        lambda: sb.files.remove("/app/x"),
        lambda: sb.files.move("/app/x", "/app/y"),
        lambda: sb.copy_in("/tmp/x", "/app/x"),
        lambda: sb.copy_out("/app/x", "/tmp/x"),
    ]
    for operation in operations:
        with pytest.raises(mvm.SandboxDevOnly):
            operation()
    with pytest.raises(mvm.SandboxModeError):
        sb.forward(8080, 80)
    assert not any("proc start" in call or "fs " in call or "machine cp" in call for call in _read_fixture_log(tmp_path)[1:])
    sb.kill()


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
    assert any(c == "machine stop sb-kill-vm --yes" for c in calls)


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


# ── declared ingress ─────────────────────────────────────────────────


def test_forward_refuses_dynamic_ingress_with_migration(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-fwd-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.create("python-dev")
    with pytest.raises(mvm.SandboxModeError, match="before boot"):
        sb.forward(8080, 80)
    assert not any(c.startswith("machine forward") for c in _read_fixture_log(tmp_path))


def test_declared_ingress_is_passed_to_machine_run(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-fwd-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    mvm.Sandbox.create(
        "python-dev",
        network={
            "mode": "none",
            "ports": [{
                "mapping_id": 1,
                "proto": "tcp",
                "host_addr": "127.0.0.1",
                "host": 8080,
                "guest_addr": "127.0.0.1",
                "guest": 80,
                "transform": "opaque",
            }],
        },
    )
    run = _read_fixture_log(tmp_path)[0]
    assert "--port 8080:80" in run
    assert " -d " not in f" {run} "


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


def test_browser_sandbox_declares_cdp_and_endpoint(tmp_path: Path) -> None:
    script = _write_fixture_mvmctl(
        tmp_path,
        up_envelope={"schema_version": 1, "vm_id": "sb-br-vm", "build_mode": "dev"},
    )
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ["MVM_CLI_BIN"] = str(script)

    bs = mvm.BrowserSandbox("chromium")
    try:
        assert bs.endpoint() == "http://localhost:9222"
        assert "--port 9222:9222" in _read_fixture_log(tmp_path)[0]
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
        assert "--port 18222:9222" in _read_fixture_log(tmp_path)[0]
    finally:
        bs.kill()


def test_browser_sandbox_unknown_browser_raises() -> None:
    with pytest.raises(ValueError, match="browser"):
        mvm.BrowserSandbox("safari")


# ── connect (attach to a running machine; inherits dev-only guard) ────


def _connect_fixture(tmp_path: Path, ls_out: str, **kw: object) -> Path:
    """A fixture mvmctl that boots nothing — only serves `machine ls
    --json`. `connect()` never boots, so `up_envelope` is None."""
    return _write_fixture_mvmctl(tmp_path, up_envelope=None, ls_out=ls_out, **kw)


def test_derive_attached_build_mode_matches_by_name() -> None:
    stdout = json.dumps(
        [
            {"name": "a", "build_mode": "prod", "status": "running"},
            {"name": "b", "build_mode": "dev", "status": "running"},
        ]
    )
    assert _derive_attached_build_mode(stdout, vm_id="b", argv=["mvmctl"]) == "dev"
    assert _derive_attached_build_mode(stdout, vm_id="a", argv=["mvmctl"]) == "prod"


def test_derive_attached_build_mode_fail_closed_on_missing_field() -> None:
    stdout = json.dumps([{"name": "a", "status": "running"}])
    assert _derive_attached_build_mode(stdout, vm_id="a", argv=["mvmctl"]) == "prod"


def test_derive_attached_build_mode_fail_closed_on_unknown_value() -> None:
    stdout = json.dumps([{"name": "a", "build_mode": "staging"}])
    assert _derive_attached_build_mode(stdout, vm_id="a", argv=["mvmctl"]) == "prod"


def test_derive_attached_build_mode_raises_when_absent() -> None:
    stdout = json.dumps([{"name": "other", "build_mode": "dev"}])
    with pytest.raises(mvm.SandboxLiveError, match="no machine named"):
        _derive_attached_build_mode(stdout, vm_id="ghost", argv=["mvmctl"])


def test_connect_dev_machine_allows_exec(tmp_path: Path) -> None:
    ls_out = json.dumps(
        [
            {"name": "web-1", "build_mode": "dev", "status": "running"},
            {"name": "other", "build_mode": "prod", "status": "running"},
        ]
    )
    script = _connect_fixture(tmp_path, ls_out, proc_wait_stdout="4")
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.connect("web-1")
    assert sb._live is not None
    assert sb._live.vm_id == "web-1"
    assert sb._live.build_mode == "dev"

    result = sb.exec("python", "-c", "print(2 + 2)")
    assert result.exit_code == 0
    assert result.stdout == "4"

    calls = _read_fixture_log(tmp_path)
    assert calls[0].startswith("machine ls --json")
    assert any(c.startswith("machine proc start web-1") for c in calls)


def test_connect_prod_machine_refuses_exec_fail_closed(tmp_path: Path) -> None:
    """Mirror of the create-path prod refusal: connect() to a sealed
    prod machine must refuse exec/commands.start client-side before any
    vsock traffic (security claim 4)."""
    ls_out = json.dumps([{"name": "sealed", "build_mode": "prod", "status": "running"}])
    script = _connect_fixture(tmp_path, ls_out)
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.connect("sealed")
    assert sb._live.build_mode == "prod"

    with pytest.raises(mvm.SandboxDevOnly, match="dev-mode template"):
        sb.exec("python", "-c", "x")
    with pytest.raises(mvm.SandboxDevOnly):
        sb.commands.start(["python", "run.py"])

    # The SDK must NOT have shelled to `mvmctl machine proc *`.
    calls = _read_fixture_log(tmp_path)
    assert not any(c.startswith("machine proc") for c in calls), calls


def test_connect_missing_build_mode_refuses_exec(tmp_path: Path) -> None:
    """A listing entry that omits build_mode must be treated as
    non-dev — never defaulted to dev."""
    ls_out = json.dumps([{"name": "m", "status": "running"}])
    script = _connect_fixture(tmp_path, ls_out)
    os.environ["MVM_CLI_BIN"] = str(script)

    sb = mvm.Sandbox.connect("m")
    assert sb._live.build_mode == "prod"
    with pytest.raises(mvm.SandboxDevOnly):
        sb.exec("echo", "hi")


def test_connect_machine_not_listed_raises(tmp_path: Path) -> None:
    ls_out = json.dumps([{"name": "other", "build_mode": "dev", "status": "running"}])
    script = _connect_fixture(tmp_path, ls_out)
    os.environ["MVM_CLI_BIN"] = str(script)

    with pytest.raises(mvm.SandboxLiveError, match="no machine named"):
        mvm.Sandbox.connect("ghost")


def test_connect_propagates_ls_failure(tmp_path: Path) -> None:
    script = _connect_fixture(tmp_path, "[]", ls_exit=5)
    os.environ["MVM_CLI_BIN"] = str(script)
    with pytest.raises(mvm.SandboxLiveError, match="exit code 5"):
        mvm.Sandbox.connect("web-1")


def test_connect_refuses_second_session(tmp_path: Path) -> None:
    ls_out = json.dumps([{"name": "a", "build_mode": "dev", "status": "running"}])
    script = _connect_fixture(tmp_path, ls_out)
    os.environ["MVM_CLI_BIN"] = str(script)

    mvm.Sandbox.connect("a")
    with pytest.raises(RuntimeError, match="already active"):
        mvm.Sandbox.connect("a")


def test_connect_rejects_empty_id() -> None:
    with pytest.raises(ValueError, match="non-empty machine id"):
        mvm.Sandbox.connect("")


# ── error rendering ──────────────────────────────────────────────────


def test_live_error_renders_the_stderr_that_says_why() -> None:
    """The captured stderr is the only place the refusing verb explains itself.

    Storing it on the exception and rendering only the summary line is the
    same as not capturing it: the failure surfaces as "failed with exit code
    1" and the diagnosis has to be re-run by hand outside the SDK. A live
    documented-surface failure was undiagnosable from its CI log for exactly
    this reason.
    """
    error = mvm.SandboxLiveError(
        "`mvmctl machine proc start` failed with exit code 1",
        argv=["mvmctl", "machine", "proc", "start", "--", "uname", "-s"],
        exit_code=1,
        stderr="Error: the guest refused the request\n",
    )

    rendered = str(error)
    assert "failed with exit code 1" in rendered
    assert "the guest refused the request" in rendered, (
        "the reason the verb refused must be in the rendered message, not "
        "only reachable through the .stderr attribute"
    )
    assert "mvmctl machine proc start -- uname -s" in rendered

    # The structured attributes stay available and unchanged.
    assert error.exit_code == 1
    assert error.stderr == "Error: the guest refused the request\n"
    assert error.argv[0] == "mvmctl"


def test_live_error_without_detail_renders_only_its_message() -> None:
    """No argv and no stderr must not grow blank sections."""
    assert str(mvm.SandboxLiveError("plain refusal")) == "plain refusal"
    assert str(mvm.SandboxLiveError("plain refusal", stderr="   \n")) == "plain refusal"
