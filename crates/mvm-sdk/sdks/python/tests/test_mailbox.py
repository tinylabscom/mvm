"""The Python mailbox veneer preserves explicit identities and acknowledgement."""

import base64
import json

import pytest

from mvm import _hostsvc, mailbox


@pytest.fixture
def endpoint(monkeypatch):
    calls = []
    response = {"outcome": "pending"}

    def invoke(method, body, timeout):
        calls.append((method, json.loads(body), timeout))
        return 0, json.dumps(response).encode()

    monkeypatch.setattr(_hostsvc, "_invoke", invoke)
    return calls, response


def test_call_preserves_ids_and_does_not_ack_or_retry(endpoint):
    calls, response = endpoint
    response.update(outcome="queued", call_message_id=[1] * 32)
    destination = {"mailbox": [4] * 32}
    result = mailbox.call(
        destination, b"\x00\xff",
        message_id=b"\x01" * 32, correlation_id=b"\x02" * 32,
        deadline_unix_ms=12345, content_type={"name": "application/octet-stream", "version": 1},
    )
    assert result["outcome"] == "queued"
    assert len(calls) == 1
    assert calls[0][0] == "host.mailbox.call"
    assert calls[0][1]["message_id"] == [1] * 32
    assert calls[0][1]["correlation_id"] == [2] * 32
    assert calls[0][1]["destination"] == destination
    assert base64.b64decode(calls[0][1]["payload_b64"]) == b"\x00\xff"


def test_delivery_requires_separate_application_ack(endpoint):
    calls, response = endpoint
    lease = {"fixture": "exact-signed-delivery-lease"}
    response.update(
        outcome="delivery", header={"message_id": [2] * 32},
        payload_b64="aGVsbG8=", lease=lease,
    )
    result = mailbox.receive_result(b"\x01" * 32)
    assert result["payload"] == b"hello"
    assert len(calls) == 1
    assert calls[0][0] == "host.mailbox.receive_result"
    response.clear()
    response.update(outcome="acknowledged")
    mailbox.ack_result(b"\x01" * 32, b"\x02" * 32, lease=result["lease"])
    assert calls[1][1] == {
        "call_message_id": [1] * 32, "result_message_id": [2] * 32, "lease": lease,
    }


def test_child_reply_has_no_arbitrary_destination(endpoint):
    calls, _ = endpoint
    mailbox.receive()
    mailbox.reply(
        b"\x01" * 32, b"done", message_id=b"\x02" * 32,
        content_type={"name": "application/octet-stream", "version": 1},
    )
    lease = {"fixture": "exact-signed-request-lease"}
    mailbox.ack_request(b"\x01" * 32, lease=lease)
    assert [call[0] for call in calls] == [
        "host.mailbox.receive", "host.mailbox.reply", "host.mailbox.ack_request",
    ]
    assert "destination" not in calls[1][1]
    assert calls[2][1] == {"request_message_id": [1] * 32, "lease": lease}


def test_receive_budget_reaches_shared_rust_transport_without_becoming_authority(endpoint):
    calls, _ = endpoint
    mailbox.receive_result(b"\x01" * 32, timeout_secs=90)
    assert calls == [(
        "host.mailbox.receive_result",
        {"call_message_id": [1] * 32},
        90,
    )]


@pytest.mark.parametrize("timeout", [0, -1, 0.5, 301, float("inf"), float("nan")])
def test_invalid_wait_budget_refuses_before_transport(endpoint, timeout):
    calls, _ = endpoint
    with pytest.raises(ValueError):
        mailbox.receive(timeout_secs=timeout)
    assert calls == []


@pytest.mark.parametrize("identity", [b"", b"x" * 31, b"x" * 33, [0] * 32])
def test_bad_id_refuses_without_transport(endpoint, identity):
    calls, _ = endpoint
    with pytest.raises(ValueError):
        mailbox.receive_result(identity)
    assert calls == []
