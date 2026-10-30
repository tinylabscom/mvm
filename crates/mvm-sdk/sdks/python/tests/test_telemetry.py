"""Real SDK marshalling over a scripted ABI, never a collector or VM."""
import pytest
import mvm
from mvm._errors.types import MachineNotFoundError, MachineSpecError


@pytest.mark.parametrize("reply", [
    {"collection": "not_provisioned"},
    *[
        {"collection": "provisioned", "vm_name": "selected", "state": state,
         "shed": 0, "records_bytes": 42}
        for state in [{"kind": "connecting"}, {"kind": "collecting", "generation": 7},
                      {"kind": "stopped"}, {"kind": "degraded", "code": "writer_failed"}]
    ],
    {"collection": "provisioned", "vm_name": "selected",
     "state": {"kind": "degraded", "code": "writer_failed"}, "shed": 3,
     "losses": {"queue_full": 1, "cap_reached": 0, "write_failed": 2, "secret_withheld": 0},
     "records_bytes": 1234, "snapshot_age_ms": 42},
])
def test_status_preserves_all_fields_without_inventing_health(hostlib, reply):
    hostlib.reply("telemetry.status", reply)
    assert mvm.telemetry.status("selected") == reply
    assert hostlib.calls == [("telemetry.status", {"id": "selected"})]


def test_pages_preserve_identity_cursor_and_opaque_records_without_polling(hostlib):
    first = {"records": [{"received_at_ms": 123, "record": {"sequence": 1, "future": [1]}}],
             "next_cursor": {"offset": 300}, "undecodable": 2, "exhausted": False}
    last = {"records": [{"record": {"sequence": 2}}],
            "next_cursor": {"offset": 500}, "undecodable": 0, "exhausted": True}
    empty = {**last, "records": []}
    for reply in [first, last, empty]:
        hostlib.reply("telemetry.records", reply)
    assert mvm.telemetry.records("selected", limit=0) == first
    assert mvm.telemetry.records("selected", cursor=first["next_cursor"], limit=4096) == last
    assert mvm.telemetry.records("selected", cursor=last["next_cursor"]) == empty
    assert hostlib.calls == [
        ("telemetry.records", {"id": "selected", "limit": 0}),
        ("telemetry.records", {"id": "selected", "cursor": {"offset": 300}, "limit": 4096}),
        ("telemetry.records", {"id": "selected", "cursor": {"offset": 500}}),
    ]


def test_defaults_and_u64_cursor_are_not_reinterpreted(hostlib):
    reply = {"records": [], "next_cursor": {"offset": 2**64 - 1},
             "undecodable": 0, "exhausted": True}
    hostlib.reply("telemetry.records", reply).reply("telemetry.records", reply)
    assert mvm.telemetry.records("selected") == reply
    assert mvm.telemetry.records("selected", cursor=reply["next_cursor"]) == reply
    assert hostlib.calls[0] == ("telemetry.records", {"id": "selected"})
    assert hostlib.calls[1][1]["cursor"] == reply["next_cursor"]


@pytest.mark.parametrize(("method", "code", "error"), [
    ("status", "NOT_FOUND", MachineNotFoundError),
    ("records", "INVALID_SPEC", MachineSpecError),
])
def test_refusals_propagate_without_retry(hostlib, method, code, error):
    hostlib.fail(f"telemetry.{method}", code, "refused")
    with pytest.raises(error) as caught:
        getattr(mvm.telemetry, method)("selected")
    assert caught.value.code == code
    assert caught.value.retryable is False
    assert len(hostlib.calls) == 1


@pytest.mark.parametrize("id", ["", None, 1, True])
def test_invalid_identity_never_calls_host(hostlib, id):
    for method in ["status", "records"]:
        with pytest.raises(ValueError):
            getattr(mvm.telemetry, method)(id)
    assert hostlib.calls == []


@pytest.mark.parametrize("cursor", [
    {}, {"offset": -1}, {"offset": True}, {"offset": 1.5},
    {"offset": 2**64}, {"offset": 0, "generation": 1}, "0",
])
def test_invalid_cursor_never_calls_host(hostlib, cursor):
    with pytest.raises(ValueError):
        mvm.telemetry.records("selected", cursor=cursor)
    assert hostlib.calls == []


@pytest.mark.parametrize("limit", [-1, True, 1.5, "2", 2**64])
def test_invalid_limit_never_calls_host(hostlib, limit):
    with pytest.raises(ValueError):
        mvm.telemetry.records("selected", limit=limit)
    assert hostlib.calls == []


@pytest.mark.parametrize("reply", [None, [], {}, {"records": []},
    {"records": [], "next_cursor": {"offset": -1}, "undecodable": 0, "exhausted": True}])
def test_malformed_page_is_not_success(hostlib, reply):
    hostlib.reply("telemetry.records", reply)
    with pytest.raises(mvm.telemetry.TelemetryError):
        mvm.telemetry.records("selected")


@pytest.mark.parametrize("reply", [
    {}, [], {"collection": "unknown"},
    {"collection": "provisioned", "vm_name": "selected", "state": {"kind": "collecting"},
     "shed": 0, "records_bytes": 0},
    {"collection": "provisioned", "vm_name": "selected", "state": {"kind": "stopped"},
     "shed": True, "records_bytes": 0},
    {"collection": "provisioned", "vm_name": "selected", "state": {"kind": "stopped"},
     "shed": 0, "records_bytes": 0, "snapshot_age_ms": None},
])
def test_malformed_status_is_refused_without_payload_in_error(hostlib, reply):
    hostlib.reply("telemetry.status", reply)
    with pytest.raises(mvm.telemetry.TelemetryError) as caught:
        mvm.telemetry.status("selected")
    assert str(caught.value) == "telemetry.status returned an invalid status envelope"


def test_reads_use_only_host_transport_without_subprocesses(hostlib, monkeypatch):
    import subprocess
    def forbidden(*args, **kwargs):
        pytest.fail("telemetry read attempted a subprocess")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    hostlib.reply("telemetry.status", {"collection": "not_provisioned"})
    hostlib.reply("telemetry.records", {
        "records": [], "next_cursor": {"offset": 0}, "undecodable": 0, "exhausted": True,
    })
    mvm.telemetry.status("selected")
    mvm.telemetry.records("selected")
    assert hostlib.methods == ["telemetry.status", "telemetry.records"]


def test_additive_reply_fields_are_preserved_but_not_interpreted(hostlib):
    status = {"collection": "not_provisioned", "future": {"enabled": False}}
    page = {"records": [{"record": {"future": 1}, "extra": "retained"}],
            "next_cursor": {"offset": 0}, "undecodable": 0, "exhausted": True,
            "future": [1, 2]}
    hostlib.reply("telemetry.status", status).reply("telemetry.records", page)
    assert mvm.telemetry.status("selected") == status
    assert mvm.telemetry.records("selected") == page
