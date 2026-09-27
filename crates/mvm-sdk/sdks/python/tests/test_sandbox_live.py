"""Live-mode Sandbox, driven through the host-library seam.

Every test replaces `mvm._hostlib._invoke` with the recorder from
`conftest.py`, so the facade's real request building and reply parsing run
and nothing else does: no library, no VM, no process. What is asserted is
the exact request each call sends, how each reply is read, and — for the
DevOnly guard — that a refused call sends nothing at all.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import mvm
from mvm import _hostlib
from mvm._sandbox import _attached_build_mode, _parse_run_reply


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch):
    mvm.reset_recording()
    monkeypatch.delenv("MVM_SDK_RUN_PROFILE", raising=False)
    monkeypatch.setenv("MVM_SDK_MODE", "live")
    yield
    mvm.reset_recording()


def _b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode("ascii")


def _run_reply(name: str = "sb-vm", build_mode: str = "dev") -> dict:
    return {
        "machine": {"id": f"id-{name}", "name": name, "status": "running"},
        "plan_id": "plan-1",
        "build_mode": build_mode,
    }


def _boot(hostlib, *, name: str = "sb-vm", build_mode: str = "dev", **kwargs) -> mvm.Sandbox:
    hostlib.reply("machine.run", _run_reply(name, build_mode))
    kwargs.setdefault("image", "python:slim")
    return mvm.Sandbox.create(**kwargs)


def _chunk(stream: str, data: bytes) -> dict:
    return {"stream": stream, "data_b64": _b64(data)}


def _script_process(hostlib, *batches: dict, token: str = "tok-1", stream: int = 7) -> None:
    """Script a started process whose output arrives in ``batches``."""
    hostlib.reply("guest.proc.start", {"token": token})
    hostlib.reply("guest.proc.stream.open", {"stream": stream})
    for batch in batches:
        hostlib.reply("guest.proc.stream.next", batch)


def _done(code: int = 0, *events: dict) -> dict:
    return {"events": list(events), "done": True, "outcome": {"kind": "exited", "code": code}}


def _guest_calls(hostlib) -> list[str]:
    return [method for method in hostlib.methods if method.startswith("guest.")]


# ── reply parsing ────────────────────────────────────────────────────


def test_a_run_reply_yields_the_machine_name_and_build_mode() -> None:
    assert _parse_run_reply(_run_reply("sb-x", "prod")) == ("sb-x", "prod")


@pytest.mark.parametrize(
    "reply, match",
    [
        ([], "malformed"),
        ({"machine": {}, "build_mode": "dev"}, "machine.name"),
        ({"machine": {"name": ""}, "build_mode": "dev"}, "machine.name"),
        ({"machine": {"name": "x"}, "build_mode": "staging"}, "build_mode"),
        ({"machine": {"name": "x"}}, "build_mode"),
    ],
)
def test_a_malformed_run_reply_is_refused_not_guessed(reply, match) -> None:
    with pytest.raises(mvm.SandboxLiveError, match=match):
        _parse_run_reply(reply)


def test_attached_build_mode_matches_by_name_and_fails_closed() -> None:
    records = [
        {"name": "a", "build_mode": "prod"},
        {"name": "b", "build_mode": "dev"},
        {"name": "c"},
        {"name": "d", "build_mode": "staging"},
    ]
    assert _attached_build_mode(records, vm_id="b") == "dev"
    assert _attached_build_mode(records, vm_id="a") == "prod"
    assert _attached_build_mode(records, vm_id="c") == "prod"
    assert _attached_build_mode(records, vm_id="d") == "prod"
    with pytest.raises(mvm.SandboxLiveError, match="no machine named"):
        _attached_build_mode(records, vm_id="ghost")
    with pytest.raises(mvm.SandboxLiveError, match="must return a list"):
        _attached_build_mode({"name": "b"}, vm_id="b")


# ── boot ─────────────────────────────────────────────────────────────


def test_create_sends_one_transient_run_and_keeps_the_reply(hostlib) -> None:
    sb = _boot(hostlib, name="sb-test-vm", workload_id="testwid")

    assert hostlib.methods == ["machine.run"]
    request = hostlib.request("machine.run")
    assert request.pop("name").startswith("sdk-testwid-")
    assert request == {"image": "python:slim", "mode": "transient", "ttl_seconds": 1800}
    assert sb.id == "sb-test-vm"
    assert sb.info().build_mode == "dev"


def test_the_generated_name_is_safe_for_the_name_validator(hostlib) -> None:
    _boot(hostlib, workload_id="My_Work.load")
    name = hostlib.request("machine.run")["name"]
    assert name.startswith("sdk-my-work-load-")
    assert all(c.isalnum() or c == "-" for c in name)
    assert name == name.lower()


def test_ttl_is_sent_in_seconds(hostlib) -> None:
    _boot(hostlib, ttl="5m")
    assert hostlib.request("machine.run")["ttl_seconds"] == 300


def test_an_explicit_profile_is_forwarded(hostlib, monkeypatch) -> None:
    monkeypatch.setenv(mvm.MVM_SDK_RUN_PROFILE_ENV, " Dev ")
    _boot(hostlib)
    assert hostlib.request("machine.run")["profile"] == "dev"


def test_an_unknown_profile_is_refused_before_boot(hostlib, monkeypatch) -> None:
    monkeypatch.setenv(mvm.MVM_SDK_RUN_PROFILE_ENV, "unknown")
    with pytest.raises(mvm.SandboxModeError, match="MVM_SDK_RUN_PROFILE"):
        mvm.Sandbox.create(image="python:slim")
    assert hostlib.calls == []


def test_egress_ingress_and_command_are_lowered_into_the_run_request(hostlib) -> None:
    _boot(
        hostlib,
        network={
            "mode": "none",
            "egress": {
                "allowlist": [
                    {"host": "example.com", "port": 443},
                    {"host": "2001:db8::1", "port": 8443},
                ]
            },
            "ports": [
                {
                    "mapping_id": 1,
                    "proto": "tcp",
                    "host_addr": "127.0.0.1",
                    "host": 8080,
                    "guest_addr": "127.0.0.1",
                    "guest": 80,
                    "transform": "opaque",
                }
            ],
        },
        command=["/app/serve", "--port", "80"],
    )
    request = hostlib.request("machine.run")
    assert request["egress"] == [
        {"host": "example.com", "port": 443},
        {"host": "2001:db8::1", "port": 8443},
    ]
    assert request["ports"] == ["8080:80"]
    assert request["command"] == ["/app/serve", "--port", "80"]


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"env": {"MODE": "safe"}}, "Sandbox.commands.start"),
        ({"resources": {"cpu_cores": 1}}, "resources"),
        ({"include": ["src"]}, "include"),
        ({"tags": {"team": "a"}}, "tags"),
        ({"network": {"raw_ip_stack": True}}, "unknown fields"),
        ({"network": {"mode": "bridge"}}, "network.mode"),
        ({"network": {"egress": {"allowlist": [{"host": "*", "port": 443}]}}}, "specific"),
        ({"network": {"egress": {"allowlist": [{"host": "a.io", "port": 0}]}}}, "1..65535"),
        (
            {"network": {"ports": [{"proto": "udp", "host": 1, "guest": 1}]}},
            "opaque TCP",
        ),
    ],
)
def test_options_live_mode_cannot_carry_are_refused_before_boot(hostlib, kwargs, match) -> None:
    with pytest.raises(mvm.SandboxModeError, match=match):
        mvm.Sandbox.create(image="python:slim", **kwargs)
    assert hostlib.calls == []


def test_a_template_cannot_be_booted_in_process(hostlib) -> None:
    with pytest.raises(mvm.SandboxModeError, match="image="):
        mvm.Sandbox.create("python-3.12")
    assert hostlib.calls == []


def test_a_library_refusal_propagates_typed(hostlib) -> None:
    hostlib.fail("machine.run", "INVALID_SPEC", "command overrides are not supported")
    with pytest.raises(mvm.MachineSpecError, match="command overrides") as raised:
        mvm.Sandbox.create(image="python:slim", command=["/bin/true"])
    assert raised.value.code == "INVALID_SPEC"
    assert raised.value.retryable is False
    # A failed boot registers nothing, so the script can try again.
    _boot(hostlib)


def test_a_retryable_refusal_says_so(hostlib) -> None:
    hostlib.fail("machine.run", "UNAVAILABLE", "backend busy", retryable=True)
    with pytest.raises(mvm.MachineUnavailableError) as raised:
        mvm.Sandbox.create(image="python:slim")
    assert raised.value.retryable is True


def test_a_malformed_boot_reply_is_a_live_error(hostlib) -> None:
    hostlib.reply("machine.run", {"plan_id": "p"})
    with pytest.raises(mvm.SandboxLiveError, match="machine.name"):
        mvm.Sandbox.create(image="python:slim")


def test_a_missing_library_is_a_transport_error_naming_the_override(monkeypatch) -> None:
    monkeypatch.setattr(_hostlib, "_lib", None)
    monkeypatch.setenv("MVM_HOSTLIB_PATH", "/nonexistent/libmvm_hostlib.so")
    with pytest.raises(mvm.MvmTransportError, match="MVM_HOSTLIB_PATH"):
        mvm.Sandbox.create(image="python:slim")


def test_one_sandbox_per_process(hostlib) -> None:
    _boot(hostlib)
    with pytest.raises(RuntimeError, match="already active"):
        mvm.Sandbox.create(image="python:slim")


# ── processes ────────────────────────────────────────────────────────


def test_commands_start_sends_argv_and_literal_env(hostlib) -> None:
    sb = _boot(hostlib, name="sb-dev-vm")
    hostlib.reply("guest.proc.start", {"token": "tok-9"})

    handle = sb.commands.start(
        ["python", "run.py"], env={"MODE": "test", "LEVEL": mvm.literal("3")}
    )

    assert handle.token == "tok-9"
    assert hostlib.request("guest.proc.start") == {
        "id": "sb-dev-vm",
        "argv": ["python", "run.py"],
        "env": {"MODE": "test", "LEVEL": "3"},
    }


def test_a_secret_env_value_is_never_forwarded(hostlib) -> None:
    sb = _boot(hostlib)
    with pytest.raises(mvm.SandboxLiveError, match="non-literal"):
        sb.commands.start(
            ["python"],
            env={"TOKEN": mvm.secret("api-key", type="bearer", hosts=["api.example.com"])},
        )
    assert _guest_calls(hostlib) == []


def test_a_start_reply_without_a_token_is_a_live_error(hostlib) -> None:
    sb = _boot(hostlib)
    hostlib.reply("guest.proc.start", {})
    with pytest.raises(mvm.SandboxLiveError, match="token"):
        sb.commands.start(["python"])


def test_wait_drains_every_batch_in_order_and_needs_no_close(hostlib) -> None:
    sb = _boot(hostlib, name="sb-proc-vm")
    _script_process(
        hostlib,
        {"events": [_chunk("stdout", b"he"), _chunk("stderr", b"e1")], "done": False},
        {"events": [], "done": False},
        {"events": [_chunk("stdout", b"llo")], "done": False},
        _done(0, _chunk("stderr", b"e2")),
    )
    handle = sb.commands.start(["python", "run.py"])
    events: list[mvm.ProcessStreamEvent] = []

    result = handle.wait(timeout=30, on_event=events.append)

    assert result == mvm.ProcessResult(0, b"hello", b"e1e2")
    assert [(e.stream, e.data) for e in events] == [
        ("stdout", b"he"),
        ("stderr", b"e1"),
        ("stdout", b"llo"),
        ("stderr", b"e2"),
    ]
    assert hostlib.request("guest.proc.stream.open") == {
        "id": "sb-proc-vm",
        "token": "tok-1",
        "timeout_secs": 30,
    }
    assert hostlib.requests("guest.proc.stream.next") == [{"stream": 7}] * 4
    # A stream that reported its end is already gone on the library side.
    assert "guest.proc.stream.close" not in hostlib.methods


@pytest.mark.parametrize(
    "outcome, code",
    [
        ({"kind": "exited", "code": 3}, 3),
        ({"kind": "killed", "signal": 9}, 137),
        ({"kind": "timed_out"}, 124),
    ],
)
def test_outcomes_map_to_shell_exit_codes(hostlib, outcome, code) -> None:
    sb = _boot(hostlib)
    _script_process(hostlib, {"events": [], "done": True, "outcome": outcome})
    assert sb.commands.start(["x"]).wait().exit_code == code


def test_an_unrecognised_outcome_is_a_live_error(hostlib) -> None:
    sb = _boot(hostlib)
    _script_process(hostlib, {"events": [], "done": True, "outcome": {"kind": "vanished"}})
    with pytest.raises(mvm.SandboxLiveError, match="outcome"):
        sb.commands.start(["x"]).wait()


def test_a_sub_second_timeout_rounds_up_rather_than_to_zero(hostlib) -> None:
    sb = _boot(hostlib)
    _script_process(hostlib, _done())
    sb.commands.start(["x"]).wait(timeout=0.2)
    assert hostlib.request("guest.proc.stream.open")["timeout_secs"] == 1


def test_a_nonpositive_timeout_is_refused_before_opening_a_stream(hostlib) -> None:
    sb = _boot(hostlib)
    hostlib.reply("guest.proc.start", {"token": "t"})
    handle = sb.commands.start(["x"])
    with pytest.raises(ValueError, match="timeout"):
        handle.wait(timeout=0)
    assert "guest.proc.stream.open" not in hostlib.methods


def test_the_stream_is_closed_when_the_callback_raises(hostlib) -> None:
    sb = _boot(hostlib)
    _script_process(hostlib, {"events": [_chunk("stdout", b"x")], "done": False})

    def explode(_event: mvm.ProcessStreamEvent) -> None:
        raise KeyError("callback failed")

    with pytest.raises(KeyError, match="callback failed"):
        sb.commands.start(["x"]).wait(on_event=explode)
    assert hostlib.request("guest.proc.stream.close") == {"stream": 7}


def test_a_failed_wait_after_output_is_raised_typed_and_the_stream_closed(hostlib) -> None:
    sb = _boot(hostlib)
    _script_process(hostlib, {"events": [_chunk("stdout", b"partial")], "done": False})
    hostlib.fail("guest.proc.stream.next", "BACKEND_ERROR", "the guest agent went away")
    seen: list[bytes] = []

    with pytest.raises(mvm.MachineBackendError, match="went away"):
        sb.commands.start(["x"]).wait(on_event=lambda e: seen.append(e.data))

    assert seen == [b"partial"]
    assert hostlib.request("guest.proc.stream.close") == {"stream": 7}


def test_a_close_failure_does_not_mask_the_original_error(hostlib) -> None:
    sb = _boot(hostlib)
    _script_process(hostlib)
    hostlib.fail("guest.proc.stream.next", "BACKEND_ERROR", "original")
    hostlib.fail("guest.proc.stream.close", "INTERNAL", "close broke")
    with pytest.raises(mvm.MachineBackendError, match="original"):
        sb.commands.start(["x"]).wait()


def test_a_bad_base64_chunk_is_a_live_error(hostlib) -> None:
    sb = _boot(hostlib)
    _script_process(
        hostlib, {"events": [{"stream": "stdout", "data_b64": "!!"}], "done": False}
    )
    with pytest.raises(mvm.SandboxLiveError, match="base64"):
        sb.commands.start(["x"]).wait()
    assert "guest.proc.stream.close" in hostlib.methods


def test_process_control_sends_token_scoped_requests(hostlib) -> None:
    sb = _boot(hostlib, name="sb-proc-vm")
    hostlib.reply("guest.proc.start", {"token": "tok-1"})
    handle = sb.commands.start(["python"])

    handle.send_stdin("input")
    handle.signal(15)
    handle.kill()

    assert hostlib.request("guest.proc.stdin") == {
        "id": "sb-proc-vm",
        "token": "tok-1",
        "data_b64": _b64(b"input"),
    }
    assert hostlib.request("guest.proc.signal") == {
        "id": "sb-proc-vm",
        "token": "tok-1",
        "signum": 15,
    }
    assert hostlib.request("guest.proc.kill") == {"id": "sb-proc-vm", "token": "tok-1"}
    with pytest.raises(ValueError, match="signum"):
        handle.signal(0)


def test_exec_starts_with_cwd_and_env_then_waits(hostlib) -> None:
    sb = _boot(hostlib, name="sb-exec")
    _script_process(hostlib, _done(0, _chunk("stdout", b"4\n"), _chunk("stderr", b"\xff")))

    result = sb.exec("python", "-c", "print(2 + 2)", cwd="/app", env={"A": "1"}, timeout=5)

    assert result == mvm.ExecResult(exit_code=0, stdout="4\n", stderr="�")
    assert hostlib.request("guest.proc.start") == {
        "id": "sb-exec",
        "argv": ["python", "-c", "print(2 + 2)"],
        "env": {"A": "1"},
        "cwd": "/app",
    }
    assert hostlib.request("guest.proc.stream.open")["timeout_secs"] == 5


def test_shell_runs_through_sh(hostlib) -> None:
    sb = _boot(hostlib)
    _script_process(hostlib, _done())
    sb.shell("echo hi | wc -c")
    assert hostlib.request("guest.proc.start")["argv"] == ["/bin/sh", "-lc", "echo hi | wc -c"]


def test_aexec_and_async_context_manager(hostlib) -> None:
    hostlib.reply("machine.run", _run_reply("sb-aex-vm"))
    _script_process(hostlib, _done(0, _chunk("stdout", b"4")))

    async def body() -> None:
        async with mvm.Sandbox.create(image="python:slim") as sb:
            result = await sb.aexec("python", "-c", "print(2 + 2)")
            assert result.stdout == "4"

    asyncio.run(body())
    assert hostlib.requests("machine.stop") == [{"id": "sb-aex-vm"}]


# ── the DevOnly guard ────────────────────────────────────────────────


def test_every_dev_only_operation_refuses_before_any_guest_call(hostlib) -> None:
    sb = _boot(hostlib, build_mode="prod")
    operations = [
        lambda: sb.commands.start(["python"]),
        lambda: sb.exec("python"),
        lambda: sb.shell("true"),
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
        with pytest.raises(mvm.SandboxDevOnly, match="dev-mode"):
            operation()
    assert _guest_calls(hostlib) == []
    assert hostlib.methods == ["machine.run"]


def test_async_exec_is_guarded_too(hostlib) -> None:
    sb = _boot(hostlib, build_mode="prod")
    with pytest.raises(mvm.SandboxDevOnly):
        asyncio.run(sb.aexec("python", "-c", "x"))
    assert _guest_calls(hostlib) == []


# ── files ────────────────────────────────────────────────────────────


def test_files_write_sends_bytes_as_base64_with_its_options(hostlib) -> None:
    sb = _boot(hostlib, name="sb-fs-vm")
    sb.files.write("/app/config.json", b'{"x":1}')
    sb.files.write("/app/deep/file", "hé", mode=0o600, create_parents=True, follow_symlinks=True)

    assert hostlib.requests("guest.fs.write") == [
        {
            "id": "sb-fs-vm",
            "path": "/app/config.json",
            "data_b64": _b64(b'{"x":1}'),
            "mode": 0o644,
            "create_parents": False,
            "follow_symlinks": False,
        },
        {
            "id": "sb-fs-vm",
            "path": "/app/deep/file",
            "data_b64": _b64("hé".encode()),
            "mode": 0o600,
            "create_parents": True,
            "follow_symlinks": True,
        },
    ]


def test_files_read_list_stat_and_mutations(hostlib) -> None:
    sb = _boot(hostlib, name="sb-fs-vm")
    hostlib.reply("guest.fs.read", {"data_b64": _b64(b"hello")})
    hostlib.reply(
        "guest.fs.list",
        {"entries": [{"name": "note.txt", "kind": "file", "size": 5}], "truncated": False},
    )
    hostlib.reply(
        "guest.fs.stat",
        {
            "canonical_path": "/app/note.txt",
            "kind": "file",
            "size": 5,
            "mode": 0o100644,
            "mtime": "2026-01-01T00:00:00Z",
        },
    )

    assert sb.files.read("/app/note.txt", offset=2, length=3) == b"hello"
    assert sb.files.list("/app") == [mvm.FsEntry(kind="file", name="note.txt", size=5)]
    stat = sb.files.stat("/app/note.txt", follow_symlinks=False)
    assert (stat.canonical_path, stat.size, stat.mtime) == (
        "/app/note.txt",
        5,
        "2026-01-01T00:00:00Z",
    )
    sb.files.mkdir("/app/new", parents=True)
    sb.files.remove("/app/old", recursive=True)
    sb.files.move("/app/a", "/app/b")

    assert hostlib.request("guest.fs.read") == {
        "id": "sb-fs-vm",
        "path": "/app/note.txt",
        "offset": 2,
        "length": 3,
    }
    assert hostlib.request("guest.fs.list") == {"id": "sb-fs-vm", "path": "/app"}
    assert hostlib.request("guest.fs.stat") == {
        "id": "sb-fs-vm",
        "path": "/app/note.txt",
        "follow_symlinks": False,
    }
    assert hostlib.request("guest.fs.mkdir") == {
        "id": "sb-fs-vm",
        "path": "/app/new",
        "mode": 0o755,
        "parents": True,
    }
    assert hostlib.request("guest.fs.remove") == {
        "id": "sb-fs-vm",
        "path": "/app/old",
        "recursive": True,
    }
    assert hostlib.request("guest.fs.rename") == {"id": "sb-fs-vm", "from": "/app/a", "to": "/app/b"}


def test_malformed_file_replies_are_live_errors(hostlib) -> None:
    sb = _boot(hostlib)
    hostlib.reply("guest.fs.read", {})
    hostlib.reply("guest.fs.list", {"entries": [{"name": "x"}]})
    hostlib.reply("guest.fs.stat", {"kind": "file"})
    with pytest.raises(mvm.SandboxLiveError):
        sb.files.read("/x")
    with pytest.raises(mvm.SandboxLiveError):
        sb.files.list("/")
    with pytest.raises(mvm.SandboxLiveError):
        sb.files.stat("/x")


def test_file_operations_are_live_only() -> None:
    os.environ["MVM_SDK_MODE"] = "record"
    sb = mvm.Sandbox.create("python-dev")
    with pytest.raises(mvm.SandboxModeError):
        sb.files.read("/x")
    with pytest.raises(mvm.SandboxModeError):
        sb.copy_in("/tmp/x", "/app/x")
    with pytest.raises(mvm.SandboxModeError):
        sb.copy_out("/app/x", "/tmp/x")
    with pytest.raises(mvm.SandboxModeError):
        sb.exec("python")


def test_copy_in_and_out_name_a_direction_and_an_absolute_host_path(
    hostlib, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    sb = _boot(hostlib, name="sb-cp-vm")
    sb.copy_in("local.txt", "/app/local.txt")
    sb.copy_out("/app/out.txt", str(tmp_path / "out.txt"))

    assert hostlib.requests("guest.cp") == [
        {
            "id": "sb-cp-vm",
            "direction": "host_to_guest",
            "host_path": str(tmp_path / "local.txt"),
            "guest_path": "/app/local.txt",
        },
        {
            "id": "sb-cp-vm",
            "direction": "guest_to_host",
            "host_path": str(tmp_path / "out.txt"),
            "guest_path": "/app/out.txt",
        },
    ]


def test_a_copy_refusal_propagates_typed(hostlib) -> None:
    sb = _boot(hostlib)
    hostlib.fail("guest.cp", "NOT_FOUND", "no such file")
    with pytest.raises(mvm.MachineNotFoundError):
        sb.copy_in("/tmp/x", "/app/x")


# ── teardown ─────────────────────────────────────────────────────────


def test_kill_stops_the_machine_once(hostlib) -> None:
    with _boot(hostlib, name="sb-kill-vm") as sb:
        sb.kill()
    assert hostlib.requests("machine.stop") == [{"id": "sb-kill-vm"}]
    # Killing released the one-per-process slot.
    _boot(hostlib)


def test_a_stop_failure_is_reported_not_raised(hostlib, capsys) -> None:
    sb = _boot(hostlib, name="sb-gone")
    hostlib.fail("machine.stop", "NOT_FOUND", "already reaped")
    sb.kill()
    assert "stopping sb-gone failed: already reaped" in capsys.readouterr().err


def test_forward_is_refused_with_a_migration_hint(hostlib) -> None:
    sb = _boot(hostlib)
    with pytest.raises(mvm.SandboxModeError, match="before boot"):
        sb.forward(8080, 80)
    assert hostlib.methods == ["machine.run"]


# ── identity ─────────────────────────────────────────────────────────


def test_id_and_info_reflect_live_state(hostlib) -> None:
    sb = _boot(hostlib, name="sb-id-vm", workload_id="wl-1")
    assert sb.id == "sb-id-vm"
    assert sb.info() == mvm.SandboxInfo(
        id="sb-id-vm", workload_id="wl-1", build_mode="dev", live=True
    )


def test_id_and_info_reflect_record_state() -> None:
    os.environ["MVM_SDK_MODE"] = "record"
    sb = mvm.Sandbox.create("python-dev", workload_id="wl-1")
    assert sb.id == "wl-1"
    assert sb.info() == mvm.SandboxInfo(id="wl-1", workload_id="wl-1", build_mode=None, live=False)


# ── connect ──────────────────────────────────────────────────────────


def test_connect_reads_build_mode_from_the_inventory(hostlib) -> None:
    hostlib.reply(
        "machine.inventory",
        [{"name": "web-1", "build_mode": "dev"}, {"name": "other", "build_mode": "prod"}],
    )
    _script_process(hostlib, _done(0, _chunk("stdout", b"4")))

    sb = mvm.Sandbox.connect("web-1")
    assert sb.info().build_mode == "dev"
    assert sb.exec("python", "-c", "print(2 + 2)").stdout == "4"
    assert hostlib.request("machine.inventory") is None
    assert hostlib.request("guest.proc.start")["id"] == "web-1"


@pytest.mark.parametrize("record", [{"name": "m", "build_mode": "prod"}, {"name": "m"}])
def test_connect_to_a_non_dev_machine_refuses_guest_verbs(hostlib, record) -> None:
    hostlib.reply("machine.inventory", [record])
    sb = mvm.Sandbox.connect("m")
    with pytest.raises(mvm.SandboxDevOnly):
        sb.exec("echo", "hi")
    with pytest.raises(mvm.SandboxDevOnly):
        sb.commands.start(["echo"])
    assert _guest_calls(hostlib) == []


def test_connect_to_an_absent_machine_is_a_live_error(hostlib) -> None:
    hostlib.reply("machine.inventory", [{"name": "other", "build_mode": "dev"}])
    with pytest.raises(mvm.SandboxLiveError, match="no machine named"):
        mvm.Sandbox.connect("ghost")


def test_connect_propagates_an_inventory_failure_typed(hostlib) -> None:
    hostlib.fail("machine.inventory", "UNAVAILABLE", "busy", retryable=True)
    with pytest.raises(mvm.MachineUnavailableError):
        mvm.Sandbox.connect("web-1")


def test_connect_refuses_a_second_session_and_an_empty_id(hostlib) -> None:
    with pytest.raises(ValueError, match="non-empty machine id"):
        mvm.Sandbox.connect("")
    hostlib.reply("machine.inventory", [{"name": "a", "build_mode": "dev"}])
    mvm.Sandbox.connect("a")
    with pytest.raises(RuntimeError, match="already active"):
        mvm.Sandbox.connect("a")


# ── errors ───────────────────────────────────────────────────────────


def test_live_error_is_a_plain_message_with_an_optional_code() -> None:
    assert str(mvm.SandboxLiveError("plain refusal")) == "plain refusal"
    assert mvm.SandboxLiveError("x").code is None
    assert mvm.SandboxLiveError("x", code="MALFORMED").code == "MALFORMED"
    assert issubclass(mvm.SandboxDevOnly, mvm.SandboxLiveError)


# ── CodeSandbox ──────────────────────────────────────────────────────


def test_code_sandbox_run_returns_stdout(hostlib) -> None:
    hostlib.reply("machine.run", _run_reply("sb-cs-vm"))
    _script_process(hostlib, _done(0, _chunk("stdout", b"4")))
    with mvm.CodeSandbox(image="python:slim") as cs:
        assert cs.run("print(2 + 2)") == "4"
    assert hostlib.request("guest.proc.start")["argv"] == ["python", "-c", "print(2 + 2)"]
    assert hostlib.requests("machine.stop") == [{"id": "sb-cs-vm"}]


def test_code_sandbox_run_raises_on_nonzero(hostlib) -> None:
    hostlib.reply("machine.run", _run_reply())
    _script_process(hostlib, _done(1, _chunk("stderr", b"boom")))
    with mvm.CodeSandbox(image="python:slim") as cs:
        with pytest.raises(mvm.CodeError) as raised:
            cs.run("raise SystemExit(1)")
    assert (raised.value.exit_code, raised.value.stderr) == (1, "boom")


def test_code_sandbox_install_package_and_node_runner(hostlib) -> None:
    hostlib.reply("machine.run", _run_reply())
    _script_process(hostlib, _done())
    with mvm.CodeSandbox(image="python:slim") as cs:
        cs.install_package("requests")
    assert hostlib.request("guest.proc.start")["argv"] == ["pip", "install", "requests"]

    hostlib.reply("machine.run", _run_reply())
    _script_process(hostlib, _done(0, _chunk("stdout", b"4")))
    with mvm.CodeSandbox(image="node:22") as cs:
        cs.run("console.log(2 + 2)")
    assert hostlib.requests("guest.proc.start")[-1]["argv"] == ["node", "-e", "console.log(2 + 2)"]


def test_code_sandbox_run_script_copies_then_execs(hostlib, tmp_path: Path) -> None:
    hostlib.reply("machine.run", _run_reply("sb-cs-vm"))
    _script_process(hostlib, _done(0, _chunk("stdout", b"ok")))
    host_script = tmp_path / "job.py"
    host_script.write_text("print('ok')")

    with mvm.CodeSandbox(image="python:slim") as cs:
        assert cs.run_script(str(host_script)) == "ok"

    assert hostlib.request("guest.cp") == {
        "id": "sb-cs-vm",
        "direction": "host_to_guest",
        "host_path": str(host_script),
        "guest_path": "/tmp/job.py",
    }
    assert hostlib.request("guest.proc.start")["argv"] == ["python", "/tmp/job.py"]
    assert hostlib.methods.index("guest.cp") < hostlib.methods.index("guest.proc.start")


# ── BrowserSandbox ───────────────────────────────────────────────────


def test_obscura_uses_the_pinned_image_fixed_command_allowlist_and_cdp_port(hostlib) -> None:
    hostlib.reply("machine.run", _run_reply("obscura"))
    browser = mvm.BrowserSandbox(
        "obscura",
        network={
            "mode": "none",
            "egress": {"allowlist": [{"host": "example.com", "port": 443}]},
        },
    )
    try:
        request = hostlib.request("machine.run")
        assert request["image"] == mvm.OBSCURA_IMAGE
        assert request["egress"] == [{"host": "example.com", "port": 443}]
        assert request["ports"] == ["9222:9222"]
        assert request["command"] == [
            "/obscura",
            "--proxy",
            "http://127.0.0.1:1080",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "9222",
        ]
        assert browser.endpoint() == "http://localhost:9222"
    finally:
        browser.kill()


def test_obscura_custom_host_port_and_refused_command_override(hostlib) -> None:
    with pytest.raises(ValueError, match="does not allow command overrides"):
        mvm.BrowserSandbox("obscura", command=["/bin/sh"])
    assert hostlib.calls == []

    hostlib.reply("machine.run", _run_reply())
    browser = mvm.BrowserSandbox("obscura", host_port=18222)
    try:
        assert browser.endpoint() == "http://localhost:18222"
        assert hostlib.request("machine.run")["ports"] == ["18222:9222"]
    finally:
        browser.kill()


def test_template_browsers_are_refused_in_live_mode(hostlib) -> None:
    with pytest.raises(mvm.SandboxModeError, match="template 'chromium'"):
        mvm.BrowserSandbox("chromium")
    assert hostlib.calls == []


def test_browser_sandbox_unknown_browser_raises() -> None:
    with pytest.raises(ValueError, match="browser"):
        mvm.BrowserSandbox("safari")


def test_browser_readiness_validates_cdp_and_timeout_cleans_up(hostlib) -> None:
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
    hostlib.reply("machine.run", _run_reply("browser"))
    browser = mvm.BrowserSandbox("obscura", host_port=port)
    try:
        assert browser.wait_until_ready(timeout=1) == "ws://127.0.0.1/devtools/browser/test"
    finally:
        browser.kill()
        server.shutdown()
        server.server_close()

    hostlib.reply("machine.run", _run_reply("browser-2"))
    failing = mvm.BrowserSandbox("obscura", host_port=port)
    with pytest.raises(mvm.BrowserReadyError):
        failing.wait_until_ready(timeout=0.02, retry_interval=0.002)
    assert {"id": "browser-2"} in hostlib.requests("machine.stop")
