"""`mvm.Machine`, driven through the host-library seam.

Each test asserts the exact request a method sends and how its reply is read.
Argument validation is asserted to happen before any call, since a request
the library would refuse should not be sent at all.
"""

from __future__ import annotations

import base64

import pytest

import mvm


def _state(name: str = "web", status: str = "running") -> dict:
    return {"id": f"id-{name}", "name": name, "status": status, "backend": "hvf"}


def _b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode("ascii")


def _exited(code: int, stdout: bytes = b"", stderr: bytes = b"") -> dict:
    events = [
        {"stream": name, "data_b64": _b64(data)}
        for name, data in (("stdout", stdout), ("stderr", stderr))
        if data
    ]
    return {"events": events, "done": True, "outcome": {"kind": "exited", "code": code}}


def test_run_boots_runs_the_command_and_stops_the_machine(hostlib) -> None:
    hostlib.reply(
        "machine.run",
        {"machine": _state("run-1"), "plan_id": "p-1", "build_mode": "dev", "process": "tok-1"},
    )
    hostlib.reply("guest.proc.stream.open", {"stream": 4})
    hostlib.reply("guest.proc.stream.next", _exited(0, stdout=b"Linux\n"))

    result = mvm.Machine.run(
        "alpine:latest",
        ["uname"],
        env={"LANG": "C"},
        cwd="/",
        cpus=2,
        memory_mib=512,
        allow_hosts=["example.com:443"],
        timeout=30,
    )

    assert result == mvm.MachineResult(exit_code=0, stdout="Linux\n", stderr="")
    request = hostlib.request("machine.run")
    assert request.pop("name").startswith("sdk-run-")
    assert request == {
        "image": "alpine:latest",
        "mode": "persistent",
        "command": ["uname"],
        "env": {"LANG": "C"},
        "cwd": "/",
        "cpus": 2,
        "memory_mib": 512,
        "egress": [{"host": "example.com", "port": 443}],
    }
    assert hostlib.request("guest.proc.stream.open") == {
        "id": "run-1",
        "token": "tok-1",
        "timeout_secs": 30,
    }
    assert hostlib.methods[-2:] == ["machine.stop", "machine.rm"]
    assert hostlib.request("machine.stop") == {"id": "run-1"}
    assert hostlib.request("machine.rm") == {"id": "run-1"}


def test_run_reports_rather_than_raises_a_failed_teardown(hostlib, capsys) -> None:
    hostlib.reply(
        "machine.run",
        {"machine": _state("run-3"), "plan_id": "p", "build_mode": "dev", "process": "tok"},
    )
    hostlib.reply("guest.proc.stream.open", {"stream": 1})
    hostlib.reply("guest.proc.stream.next", _exited(0))
    hostlib.fail("machine.stop", "NOT_FOUND", "already reaped")
    assert mvm.Machine.run("alpine:latest", ["true"]).exit_code == 0
    assert "stopping run-3 failed: already reaped" in capsys.readouterr().err
    assert "machine.rm" not in hostlib.methods


def test_run_stops_the_machine_when_the_wait_fails(hostlib) -> None:
    hostlib.reply(
        "machine.run",
        {"machine": _state("run-2"), "plan_id": "p", "build_mode": "dev", "process": "tok"},
    )
    hostlib.fail("guest.proc.stream.open", "BACKEND_ERROR", "the agent went away")
    with pytest.raises(mvm.MachineBackendError, match="went away"):
        mvm.Machine.run("alpine:latest", ["true"])
    assert hostlib.request("machine.stop") == {"id": "run-2"}
    assert hostlib.request("machine.rm") == {"id": "run-2"}


def test_run_needs_a_command(hostlib) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        mvm.Machine.run("alpine:latest", [])
    assert hostlib.calls == []


def test_a_refused_command_environment_is_the_librarys_refusal(hostlib) -> None:
    hostlib.fail("machine.run", "INVALID_SPEC", "variable LD_PRELOAD is denied")
    with pytest.raises(mvm.MachineSpecError, match="LD_PRELOAD"):
        mvm.Machine.run("alpine:latest", ["true"], env={"LD_PRELOAD": "/x.so"})
    assert "machine.stop" not in hostlib.methods


def test_launch_boots_a_named_machine_and_returns_a_handle(hostlib) -> None:
    hostlib.reply("machine.run", {"machine": _state("web-1"), "plan_id": "p-1", "build_mode": "dev"})

    machine = mvm.Machine.launch(
        "alpine:latest",
        name="web-1",
        cpus=2,
        memory_mib=512,
        profile="dev",
        allow_hosts=["example.com:443", "[2001:db8::1]:8443"],
        ports=["8080:80"],
        ttl_seconds=600,
    )

    assert (machine.name, machine.build_mode, machine.plan_id) == ("web-1", "dev", "p-1")
    assert machine.process is None
    assert hostlib.request("machine.run") == {
        "image": "alpine:latest",
        "mode": "persistent",
        "name": "web-1",
        "cpus": 2,
        "memory_mib": 512,
        "profile": "dev",
        "ttl_seconds": 600,
        "ports": ["8080:80"],
        "egress": [
            {"host": "example.com", "port": 443},
            {"host": "2001:db8::1", "port": 8443},
        ],
    }


def test_launch_sends_only_what_was_given(hostlib) -> None:
    hostlib.reply("machine.run", {"machine": _state("gen-1"), "plan_id": "p", "build_mode": "prod"})
    assert mvm.Machine.launch("alpine:latest").name == "gen-1"
    request = hostlib.request("machine.run")
    assert request.pop("name").startswith("sdk-machine-")
    assert request == {"image": "alpine:latest", "mode": "persistent"}


def test_launch_with_a_command_keeps_its_process_to_wait_on(hostlib) -> None:
    hostlib.reply(
        "machine.run",
        {"machine": _state("svc"), "plan_id": "p", "build_mode": "dev", "process": "tok-9"},
    )
    hostlib.reply("guest.proc.stream.open", {"stream": 1})
    hostlib.reply("guest.proc.stream.next", _exited(3, stderr=b"bad"))

    machine = mvm.Machine.launch("alpine:latest", command=["serve"], name="svc")

    assert machine.process == "tok-9"
    assert machine.wait() == mvm.MachineResult(exit_code=3, stdout="", stderr="bad")


def test_a_launch_that_started_a_command_but_named_no_process_is_a_machine_error(hostlib) -> None:
    hostlib.reply("machine.run", {"machine": _state("svc"), "plan_id": "p", "build_mode": "dev"})
    with pytest.raises(mvm.MachineError, match="named no process"):
        mvm.Machine.launch("alpine:latest", command=["serve"])


def test_waiting_without_a_command_is_a_machine_error(hostlib) -> None:
    with pytest.raises(mvm.MachineError, match="command to wait for"):
        mvm.Machine("idle").wait()
    assert hostlib.calls == []


@pytest.mark.parametrize("field", ["template", "manifest"])
def test_a_built_source_boots_by_its_field(hostlib, field) -> None:
    hostlib.reply("machine.run", {"machine": _state("b"), "plan_id": "p", "build_mode": "dev"})
    mvm.Machine.launch(**{field: "chromium"}, name="b")
    assert hostlib.request("machine.run") == {field: "chromium", "mode": "persistent", "name": "b"}


@pytest.mark.parametrize(
    "kwargs",
    [{}, {"image": "alpine", "template": "chromium"}, {"template": "a", "manifest": "b"}],
)
def test_a_launch_names_exactly_one_source(hostlib, kwargs) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        mvm.Machine.launch(**kwargs)
    assert hostlib.calls == []


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"allow_hosts": ["example.com"]}, "host:port"),
        ({"allow_hosts": ["2001:db8::1:443"]}, "bracket"),
        ({"allow_hosts": ["[2001:db8::1]443"]}, r"\[address\]:port"),
        ({"allow_hosts": ["*:443"]}, "specific"),
        ({"allow_hosts": ["example.com:0"]}, "1..65535"),
        ({"allow_hosts": ["example.com:https"]}, "non-numeric"),
        ({"allow_hosts": "example.com:443"}, "not a single str"),
        ({"ports": ["8080"]}, "host:guest"),
        ({"ports": ["8080:99999"]}, "host:guest"),
        ({"command": []}, "non-empty"),
        ({"command": "uname -a"}, "not a single str"),
        ({"env": {"A": 1}}, "env"),
        ({"cwd": ""}, "cwd"),
        ({"cpus": 0}, "cpus"),
        ({"memory_mib": True}, "memory_mib"),
        ({"ttl_seconds": -1}, "ttl_seconds"),
        ({"name": ""}, "name"),
    ],
)
def test_invalid_launch_arguments_are_refused_before_any_call(hostlib, kwargs, match) -> None:
    with pytest.raises(ValueError, match=match):
        mvm.Machine.launch("alpine:latest", **kwargs)
    assert hostlib.calls == []


def test_a_malformed_launch_reply_is_a_machine_error(hostlib) -> None:
    hostlib.reply("machine.run", {"plan_id": "p"})
    with pytest.raises(mvm.MachineError, match="no machine name"):
        mvm.Machine.launch("alpine:latest")


def test_create_persists_without_booting(hostlib) -> None:
    hostlib.reply("machine.create", _state("devbox", status="stopped"))

    machine = mvm.Machine.create(
        "devbox", "alpine:latest", profile="dev", allow_hosts=["pypi.org:443"], force=True
    )

    assert machine.name == "devbox"
    assert machine.build_mode is None
    assert hostlib.request("machine.create") == {
        "name": "devbox",
        "image": "alpine:latest",
        "profile": "dev",
        "egress": [{"host": "pypi.org", "port": 443}],
        "force": True,
    }


def test_create_omits_force_when_false(hostlib) -> None:
    hostlib.reply("machine.create", _state("devbox"))
    mvm.Machine.create("devbox", "alpine:latest")
    assert hostlib.request("machine.create") == {"name": "devbox", "image": "alpine:latest"}


def test_create_from_a_manifest(hostlib) -> None:
    hostlib.reply("machine.create", _state("tmpl", status="stopped"))
    mvm.Machine.create("tmpl", manifest="./mvm.toml")
    assert hostlib.request("machine.create") == {"name": "tmpl", "manifest": "./mvm.toml"}


def test_ls_returns_the_inventory_records(hostlib) -> None:
    records = [{"name": "a", "build_mode": "dev", "status": "running"}]
    hostlib.reply("machine.inventory", records)
    assert mvm.Machine.ls() == records
    assert hostlib.request("machine.inventory") is None


def test_ls_refuses_a_non_list_reply(hostlib) -> None:
    hostlib.reply("machine.inventory", {"name": "a"})
    with pytest.raises(mvm.MachineError, match="not a list"):
        mvm.Machine.ls()


def test_lifecycle_methods_address_the_machine_by_name(hostlib) -> None:
    hostlib.reply("machine.start", _state("devbox"))
    hostlib.reply("machine.inspect", _state("devbox", status="stopped"))
    machine = mvm.Machine("devbox")

    assert machine.start()["status"] == "running"
    assert machine.stop() is None
    assert machine.inspect()["status"] == "stopped"
    assert machine.rm() is None

    assert hostlib.calls == [
        ("machine.start", {"id": "devbox"}),
        ("machine.stop", {"id": "devbox"}),
        ("machine.inspect", {"id": "devbox"}),
        ("machine.rm", {"id": "devbox"}),
    ]


def test_rm_of_a_running_machine_propagates_the_conflict(hostlib) -> None:
    hostlib.fail("machine.rm", "CONFLICT", "stop it first")
    with pytest.raises(mvm.MachineConflictError, match="stop it first"):
        mvm.Machine("devbox").rm()


def test_inspect_of_a_missing_machine_propagates_not_found(hostlib) -> None:
    hostlib.fail("machine.inspect", "NOT_FOUND", "no machine named ghost")
    with pytest.raises(mvm.MachineNotFoundError):
        mvm.Machine("ghost").inspect()


def test_logs_decodes_console_output(hostlib) -> None:
    hostlib.reply("machine.logs", {"data_b64": _b64(b"booted\n\xffdone\n")})
    hostlib.reply("machine.logs", {"data_b64": _b64(b"done\n")})
    machine = mvm.Machine("devbox")

    assert machine.logs() == "booted\n�done\n"
    assert machine.logs(lines=1) == "done\n"
    assert hostlib.requests("machine.logs") == [{"id": "devbox"}, {"id": "devbox", "tail_lines": 1}]
    with pytest.raises(ValueError, match="lines"):
        machine.logs(lines=0)


def test_logs_refuses_a_reply_without_data(hostlib) -> None:
    hostlib.reply("machine.logs", {})
    with pytest.raises(mvm.MachineError, match="data_b64"):
        mvm.Machine("devbox").logs()


def test_logs_follow_yields_output_as_it_arrives_and_decodes_across_chunks(hostlib) -> None:
    snowman = "\u2603".encode()
    hostlib.reply("machine.logs.stream.open", {"stream": 8})
    hostlib.reply(
        "machine.logs.stream.next",
        {"events": [{"stream": "stdout", "data_b64": _b64(b"boot " + snowman[:1])}], "done": False},
    )
    hostlib.reply("machine.logs.stream.next", {"events": [], "done": False})
    hostlib.reply(
        "machine.logs.stream.next",
        {"events": [{"stream": "stderr", "data_b64": _b64(snowman[1:] + b" up")}], "done": True},
    )

    chunks = mvm.Machine("web").logs(5, follow=True)
    assert hostlib.calls == [], "nothing is opened until the caller reads"
    assert "".join(chunks) == "boot \u2603 up"
    assert hostlib.request("machine.logs.stream.open") == {
        "id": "web",
        "follow": True,
        "streams": ["stdout", "stderr"],
        "tail_lines": 5,
    }
    assert hostlib.requests("machine.logs.stream.next")[0] == {"stream": 8, "wait_ms": 5000}
    assert "machine.logs.stream.close" not in hostlib.methods, "an ended stream is already gone"


def test_leaving_a_followed_log_early_closes_its_stream(hostlib) -> None:
    hostlib.reply("machine.logs.stream.open", {"stream": 2})
    hostlib.reply(
        "machine.logs.stream.next",
        {"events": [{"stream": "stdout", "data_b64": _b64(b"line\n")}], "done": False},
    )
    for chunk in mvm.Machine("web").logs(follow=True):
        assert chunk == "line\n"
        break
    assert hostlib.request("machine.logs.stream.close") == {"stream": 2}


def test_following_a_machine_with_no_captured_output_propagates_not_found(hostlib) -> None:
    hostlib.fail("machine.logs.stream.open", "NOT_FOUND", "no captured output")
    with pytest.raises(mvm.MachineNotFoundError):
        list(mvm.Machine("ghost").logs(follow=True))


def test_exec_starts_a_guest_process_and_streams_it_to_the_end(hostlib) -> None:
    hostlib.reply("guest.proc.start", {"token": "tok-1"})
    hostlib.reply("guest.proc.stream.open", {"stream": 3})
    hostlib.reply(
        "guest.proc.stream.next",
        {"events": [{"stream": "stdout", "data_b64": _b64(b"hello ")}], "done": False},
    )
    hostlib.reply(
        "guest.proc.stream.next",
        {
            "events": [
                {"stream": "stdout", "data_b64": _b64(b"world")},
                {"stream": "stderr", "data_b64": _b64(b"warn")},
            ],
            "done": True,
            "outcome": {"kind": "exited", "code": 2},
        },
    )

    result = mvm.Machine("devbox").exec(["echo", "hi"], timeout=10, cwd="/srv", env={"A": "1"})

    assert result == mvm.MachineResult(exit_code=2, stdout="hello world", stderr="warn")
    assert hostlib.request("guest.proc.start") == {
        "id": "devbox",
        "argv": ["echo", "hi"],
        "env": {"A": "1"},
        "cwd": "/srv",
    }
    assert hostlib.request("guest.proc.stream.open") == {
        "id": "devbox",
        "token": "tok-1",
        "timeout_secs": 10,
    }


def test_exec_on_a_production_machine_propagates_the_agent_refusal(hostlib) -> None:
    hostlib.fail("guest.proc.start", "BACKEND_ERROR", "the guest agent refused a DevOnly verb")
    with pytest.raises(mvm.MachineBackendError, match="DevOnly"):
        mvm.Machine("sealed").exec(["id"])


def test_exec_requires_a_command(hostlib) -> None:
    with pytest.raises(ValueError, match="command"):
        mvm.Machine("devbox").exec([])
    assert hostlib.calls == []


def test_a_handle_needs_a_name() -> None:
    with pytest.raises(ValueError, match="name"):
        mvm.Machine("")
    assert repr(mvm.Machine("devbox")) == "Machine('devbox')"


def test_retired_cli_shaped_surface_is_gone() -> None:
    """These existed only because the facade used to build a command line."""
    for name in ("shell", "check_artifact"):
        assert not hasattr(mvm.Machine, name)
    for name in ("MVM_MACHINE_TIMEOUT_ENV", "MVM_MACHINE_MAX_OUTPUT_ENV", "MVM_CLI_BIN_ENV"):
        assert not hasattr(mvm, name)
