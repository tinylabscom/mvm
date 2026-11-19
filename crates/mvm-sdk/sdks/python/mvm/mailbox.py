"""Durable actor messages over the dedicated, encrypted mailbox channel.

These methods do not use the lifecycle broker. ``call`` queues a durable
source intent; it does not report destination acceptance or an application
result. Receive results explicitly and ACK only after application processing.
A timeout never proves that the remote handler did not execute.
"""

import base64
import math

from mvm import _hostsvc

_TIMEOUT_SECS = 60.0


def _identity(value: bytes) -> list[int]:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("mailbox message identities must contain 32 bytes")
    return list(value)


def _request(method: str, body: dict, timeout_secs: float) -> dict:
    if not math.isfinite(timeout_secs) or not 1 <= timeout_secs <= 300:
        raise ValueError("mailbox timeout must be between 1 and 300 seconds")
    response = _hostsvc.call(f"host.mailbox.{method}", body, timeout_secs=timeout_secs)
    if response.get("outcome") == "delivery":
        response = dict(response)
        response["payload"] = base64.b64decode(response.pop("payload_b64"), validate=True)
    return response


def call(
    destination: dict,
    payload: bytes,
    *,
    message_id: bytes,
    correlation_id: bytes,
    deadline_unix_ms: int,
    content_type: dict,
    timeout_secs: float = _TIMEOUT_SECS,
) -> dict:
    """Queue one call with caller-retained identities; never retry implicitly."""
    return _request("call", {
        "destination": destination,
        "message_id": _identity(message_id),
        "correlation_id": _identity(correlation_id),
        "deadline_unix_ms": deadline_unix_ms,
        "content_type": content_type,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
    }, timeout_secs)


def receive(*, timeout_secs: float = _TIMEOUT_SECS) -> dict:
    """Receive an authorized request, without acknowledging its application effect."""
    return _request("receive", {}, timeout_secs)


def reply(
    request_message_id: bytes,
    payload: bytes,
    *,
    message_id: bytes,
    content_type: dict,
    timeout_secs: float = _TIMEOUT_SECS,
) -> dict:
    """Reply using the exact request's scoped authority, never general reverse Send."""
    return _request("reply", {
        "request_message_id": _identity(request_message_id),
        "message_id": _identity(message_id),
        "content_type": content_type,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
    }, timeout_secs)


def receive_result(call_message_id: bytes, *, timeout_secs: float = _TIMEOUT_SECS) -> dict:
    """Receive a correlated reply; only ``outcome == 'delivery'`` carries a result."""
    return _request("receive_result", {"call_message_id": _identity(call_message_id)}, timeout_secs)


def ack_result(
    call_message_id: bytes,
    result_message_id: bytes,
    *,
    lease: dict,
    timeout_secs: float = _TIMEOUT_SECS,
) -> dict:
    """ACK the exact delivered lease after processing; the guest bridge signs it."""
    return _request("ack_result", {
        "call_message_id": _identity(call_message_id),
        "result_message_id": _identity(result_message_id),
        "lease": lease,
    }, timeout_secs)


def ack_request(
    request_message_id: bytes, *, lease: dict, timeout_secs: float = _TIMEOUT_SECS,
) -> dict:
    """Acknowledge request processing; this is not an application reply."""
    return _request("ack_request", {
        "request_message_id": _identity(request_message_id),
        "lease": lease,
    }, timeout_secs)
