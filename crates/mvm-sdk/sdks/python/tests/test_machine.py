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


def test_run_sends_a_transient_launch_and_returns_a_handle(hostlib) -> None:
    hostlib.reply("machine.run", {"machine": _state("web-1"), "plan_id": "p-1", "build_mode": "dev"})

    machine = mvm.Machine.run(
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
    assert hostlib.request("machine.run") == {
        "image": "alpine:latest",
        "mode": "transient",
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


def test_run_sends_only_what_was_given(hostlib) -> None:
    hostlib.reply("machine.run", {"machine": _state("gen-1"), "plan_id": "p", "build_mode": "prod"})
    assert mvm.Machine.run("alpine:latest").name == "gen-1"
    assert hostlib.request("machine.run") == {"image": "alpine:latest", "mode": "transient"}


def test_run_forwards_command_and_env_and_the_refusal_is_the_librarys(hostlib) -> None:
    hostlib.fail("machine.run", "INVALID_SPEC", "the launcher cannot override the command yet")
    with pytest.raises(mvm.MachineSpecError, match="override") as raised:
        mvm.Machine.run("alpine:latest", command=["uname", "-a"], env={"A": "1"})
    assert raised.value.code == "INVALID_SPEC"
    request = hostlib.request("machine.run")
    assert request["command"] == ["uname", "-a"]
    assert request["env"] == {"A": "1"}


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
        ({"cpus": 0}, "cpus"),
        ({"memory_mib": True}, "memory_mib"),
        ({"ttl_seconds": -1}, "ttl_seconds"),
        ({"name": ""}, "name"),
    ],
)
def test_invalid_run_arguments_are_refused_before_any_call(hostlib, kwargs, match) -> None:
    with pytest.raises(ValueError, match=match):
        mvm.Machine.run("alpine:latest", **kwargs)
    assert hostlib.calls == []


def test_a_malformed_run_reply_is_a_machine_error(hostlib) -> None:
    hostlib.reply("machine.run", {"plan_id": "p"})
    with pytest.raises(mvm.MachineError, match="no machine name"):
        mvm.Machine.run("alpine:latest")


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
