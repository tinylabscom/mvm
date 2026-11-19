"""Actor lifecycle marshalling; transport and authority remain in the host runtime."""

import json

import pytest

from mvm import _hostsvc, actor


@pytest.fixture
def endpoint(monkeypatch):
    calls = []
    response = {"version": 1, "outcome": {"status": "pending", "request_id": "launch-1"}}

    def invoke(method, request, timeout_secs):
        calls.append((method, json.loads(request), timeout_secs))
        return 0, json.dumps(response).encode()

    monkeypatch.setattr(_hostsvc, "_invoke", invoke)
    return calls, response


def test_launch_has_no_mutable_vm_configuration(endpoint):
    calls, _ = endpoint
    outcome = actor.launch_child("grant", "worker", idempotency_key="launch-1")
    assert outcome == actor.Pending("launch-1")
    assert calls == [
        (
            "host.actor.call",
            {
                "version": 1,
                "operation": {
                    "operation": "launch",
                    "grant_id": "grant",
                    "template_id": "worker",
                    "idempotency_key": "launch-1",
                },
            },
            60.0,
        )
    ]


def test_handle_roundtrip_is_opaque_and_redacted(endpoint):
    calls, response = endpoint
    mailbox = {
        "tenant": [1] * 32,
        "authorization_domain": [2] * 32,
        "mailbox": [3] * 32,
        "recipient": [4] * 32,
    }
    wire_handle = {"token": [173] * 32, "mailbox": mailbox}
    response["outcome"] = {"status": "running", "handle": wire_handle}
    result = actor.launch_child("grant", "worker", idempotency_key="launch-1")
    assert isinstance(result, actor.Running)
    assert "173" not in repr(result)
    assert result.handle.mailbox == mailbox
    # A caller cannot mutate the stored destination through its readback.
    result.handle.mailbox["mailbox"][0] = 99
    actor.observe_child(result.handle)
    assert calls[-1][1]["operation"] == {
        "operation": "observe_child",
        "handle": wire_handle,
    }
    response["outcome"] = {"status": "released", "request_id": "release-1"}
    assert actor.release_child(result.handle, idempotency_key="release-1") == actor.Released("release-1")
    assert calls[-1][1]["operation"]["idempotency_key"] == "release-1"


@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        ({"status": "unknown", "request_id": "lost-receipt"}, actor.Unknown("lost-receipt")),
        ({"status": "refused", "code": "capacity"}, actor.Refused("capacity")),
    ],
)
def test_non_success_outcomes_are_not_treated_as_running(endpoint, wire, expected):
    calls, response = endpoint
    response["outcome"] = wire
    assert actor.launch_child("grant", "worker", idempotency_key="launch-1") == expected
    assert len(calls) == 1  # Never silently retry an uncertain lifecycle effect.


@pytest.mark.parametrize("response", [
    {"version": 2, "outcome": {"status": "pending", "request_id": "x"}},
    {"version": 1, "outcome": {"status": "accepted"}},
    {"version": 1, "outcome": {"status": "running", "handle": {"token": [], "mailbox": {}}}},
])
def test_malformed_responses_refuse(endpoint, response):
    _, box = endpoint
    box.clear()
    box.update(response)
    with pytest.raises(ValueError):
        actor.launch_child("grant", "worker", idempotency_key="launch-1")
