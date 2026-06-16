"""In-guest host-services veneer (`mvm.audit` / `mvm.host`) over a mock broker.

The real transport opens ``AF_VSOCK`` (Linux guest only); these tests inject a
``connect`` factory returning one end of an ``AF_UNIX`` socket pair and run a
one-shot mock broker on the other end, so they exercise the framing + envelope +
typed-error mapping without a VM (mirroring the Rust `_on` stream tests).
"""

from __future__ import annotations

import json
import socket
import struct
import threading
from typing import Any, Callable

import pytest

import mvm
from mvm import audit, host
from mvm._broker import transport


def _read_frame(sock: socket.socket) -> Any:
    (length,) = struct.unpack(">I", _read_exact(sock, 4))
    return json.loads(_read_exact(sock, length))


def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AssertionError("client closed mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def _write_frame(sock: socket.socket, obj: Any) -> None:
    body = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(body)) + body)


def mock_broker(respond: Callable[[dict], dict]) -> tuple[transport.Connect, dict, threading.Thread]:
    """Return a ``connect`` factory + a captured-call dict + the server thread.

    The factory hands the veneer the client half of a socket pair; the server
    half reads the one ``ServiceCall``, captures it, and writes ``respond(call)``.
    """
    client, server = socket.socketpair()
    captured: dict = {}

    def serve() -> None:
        with server:
            call = _read_frame(server)
            captured["call"] = call
            _write_frame(server, respond(call))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return (lambda: client), captured, thread


def test_audit_emit_sends_host_audit_v1_envelope_and_returns_chain_head():
    connect, captured, thread = mock_broker(
        lambda call: {"kind": "ok", "correlation_id": call["correlation_id"], "payload": {"chain_head": "head-001"}}
    )
    resp = audit.emit({"action": "login"}, ts="2026-06-16T00:00:00Z", connect=connect)
    thread.join(timeout=2)
    assert resp.chain_head == "head-001"
    call = captured["call"]
    assert call["service"] == "host.audit.v1"
    assert call["verb"] == "emit"
    # The workload cannot express a category — the record carries none.
    assert "category" not in call["payload"]
    assert call["payload"] == {"ts": "2026-06-16T00:00:00Z", "fields": {"action": "login"}}


def test_audit_emit_maps_bad_request_to_typed_error():
    connect, _captured, thread = mock_broker(
        lambda call: {"kind": "err", "correlation_id": call["correlation_id"], "code": "bad_request", "message": "record 5121 bytes exceeds cap 4096"}
    )
    with pytest.raises(audit.AuditBadRequest):
        audit.emit({"big": "x"}, connect=connect)
    thread.join(timeout=2)


def test_audit_emit_maps_rate_limit_to_typed_error():
    connect, _captured, thread = mock_broker(
        lambda call: {"kind": "err", "correlation_id": call["correlation_id"], "code": "rate_limit_exceeded", "message": "20/s exceeded"}
    )
    with pytest.raises(audit.AuditRateLimited):
        audit.emit({"a": 1}, connect=connect)
    thread.join(timeout=2)


def test_audit_emit_batch_sends_entries_and_returns_statuses():
    connect, captured, thread = mock_broker(
        lambda call: {
            "kind": "ok",
            "correlation_id": call["correlation_id"],
            "payload": {"chain_head": "head-b2", "statuses": [{"kind": "ok", "chain_head": "head-b1"}, {"kind": "ok", "chain_head": "head-b2"}]},
        }
    )
    resp = audit.emit_batch([{"ts": "t1", "fields": {"a": 1}}, {"b": 2}], connect=connect)
    thread.join(timeout=2)
    assert resp.chain_head == "head-b2"
    assert len(resp.statuses) == 2
    call = captured["call"]
    assert call["service"] == "host.audit.v1"
    assert call["verb"] == "emit_batch"
    assert len(call["payload"]["entries"]) == 2
    # The bare-fields entry was wrapped into a {ts, fields} record.
    assert call["payload"]["entries"][1]["fields"] == {"b": 2}


def test_host_time_returns_wall_ms():
    connect, captured, thread = mock_broker(
        lambda call: {"kind": "ok", "correlation_id": call["correlation_id"], "payload": {"wall_ms": 1717000000000}}
    )
    assert host.time(connect=connect) == 1717000000000
    thread.join(timeout=2)
    assert captured["call"]["service"] == "host.time.v1"
    assert captured["call"]["verb"] == "now"
    assert captured["call"]["payload"] == {}


def test_host_cost_workload_and_tenant_verbs():
    for scope, verb in [("workload", "workload"), ("tenant", "tenant")]:
        connect, captured, thread = mock_broker(
            lambda call: {"kind": "ok", "correlation_id": call["correlation_id"], "payload": {"spent_micros_usd": 4200000}}
        )
        assert host.cost(scope, connect=connect) == 4200000
        thread.join(timeout=2)
        assert captured["call"]["service"] == "host.cost.v1"
        assert captured["call"]["verb"] == verb


def test_host_cost_rejects_unknown_scope():
    with pytest.raises(ValueError):
        host.cost("everyone")


def test_host_time_maps_service_error():
    connect, _captured, thread = mock_broker(
        lambda call: {"kind": "err", "correlation_id": call["correlation_id"], "code": "not_bound", "message": "host.time.v1 not bound"}
    )
    with pytest.raises(host.HostServiceError):
        host.time(connect=connect)
    thread.join(timeout=2)


def test_malformed_response_is_transport_error():
    connect, _captured, thread = mock_broker(
        lambda call: {"correlation_id": call["correlation_id"], "no_kind": True}
    )
    with pytest.raises(transport.BrokerTransportError):
        host.time(connect=connect)
    thread.join(timeout=2)


def test_surface_is_reachable_from_top_level_package():
    # `import mvm; mvm.audit.emit` / `mvm.host.time` resolve without a connection.
    assert mvm.audit is audit
    assert mvm.host is host
    assert callable(mvm.audit.emit)
    assert callable(mvm.host.time)
