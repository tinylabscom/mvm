"""In-guest host-services veneer (``mvm.audit`` / ``mvm.host``).

These exercise the marshalling + status→exception mapping over a monkeypatched
C-call seam (``mvm._hostsvc._invoke``), so no real ``.so`` or vsock broker is
needed — exactly mirroring the Rust ``dispatch_on`` socket-pair tests one layer
down. The actual ``ctypes`` load + broker dial is the live-VM E2E (b4).
"""

import json

import pytest

from mvm import _hostsvc, audit, host


@pytest.fixture
def fake_invoke(monkeypatch):
    """Replace the ctypes C-call with a fake returning a settable
    ``(status, body)``; capture each ``(method, request, timeout)``."""
    calls = []
    box = {"status": 0, "body": b"{}"}

    def _fake(method, request_json, timeout_secs):
        calls.append((method, json.loads(request_json), timeout_secs))
        return box["status"], box["body"]

    monkeypatch.setattr(_hostsvc, "_invoke", _fake)
    return calls, box


def test_emit_sends_audit_emit_envelope_and_returns_chain_head(fake_invoke):
    calls, box = fake_invoke
    box["status"], box["body"] = 0, b'{"chain_head": "head-001"}'

    head = audit.emit({"action": "login", "user": "alice"}, ts="2026-06-16T00:00:00Z")

    assert head == "head-001"
    method, request, _timeout = calls[0]
    assert method == "host.audit.emit"
    assert request == {
        "ts": "2026-06-16T00:00:00Z",
        "fields": {"action": "login", "user": "alice"},
    }
    # Claim 8: the workload can never express a category.
    assert "category" not in request


def test_emit_defaults_ts_to_an_rfc3339_string(fake_invoke):
    calls, box = fake_invoke
    box["status"], box["body"] = 0, b'{"chain_head": "h"}'
    audit.emit({"x": 1})
    _method, request, _ = calls[0]
    assert isinstance(request["ts"], str)
    assert request["ts"].endswith("Z")


def test_emit_bad_request_raises_typed(fake_invoke):
    _calls, box = fake_invoke
    box["status"], box["body"] = (
        1,
        b'{"code":"bad_request","message":"record 5121 bytes exceeds cap 4096"}',
    )
    with pytest.raises(_hostsvc.BadRequestError) as ei:
        audit.emit({"x": 1})
    assert "exceeds cap" in str(ei.value)
    # Every typed error is a HostServiceError.
    assert isinstance(ei.value, _hostsvc.HostServiceError)


def test_emit_rate_limited_raises(fake_invoke):
    _calls, box = fake_invoke
    box["status"], box["body"] = 2, b'{"code":"rate_limited","message":"rate"}'
    with pytest.raises(_hostsvc.RateLimitedError):
        audit.emit({"x": 1})


def test_emit_batch_sends_entries_and_returns_chain_head(fake_invoke):
    calls, box = fake_invoke
    box["status"], box["body"] = 0, b'{"chain_head":"hb","statuses":[]}'

    head = audit.emit_batch([{"a": 1}, {"b": 2}])

    assert head == "hb"
    method, request, _ = calls[0]
    assert method == "host.audit.emit_batch"
    assert len(request["entries"]) == 2
    assert request["entries"][0]["fields"] == {"a": 1}
    assert request["entries"][1]["fields"] == {"b": 2}
    assert all("ts" in e for e in request["entries"])


def test_time_returns_wall_ms(fake_invoke):
    calls, box = fake_invoke
    box["status"], box["body"] = 0, b'{"wall_ms": 1717000000000}'
    assert host.time() == 1717000000000
    assert calls[0][0] == "host.time.now"
    assert calls[0][1] == {}


def test_time_not_bound_raises_typed(fake_invoke):
    _calls, box = fake_invoke
    box["status"], box["body"] = 4, b'{"code":"not_bound","message":"nb"}'
    with pytest.raises(_hostsvc.NotBoundError):
        host.time()


def test_cost_workload_and_tenant_route_distinct_verbs(fake_invoke):
    calls, box = fake_invoke
    box["status"], box["body"] = 0, b'{"spent_micros_usd": 4200000}'
    assert host.cost() == 4200000
    assert calls[0][0] == "host.cost.workload"
    assert host.cost("tenant") == 4200000
    assert calls[1][0] == "host.cost.tenant"


def test_cost_rejects_unknown_scope_before_calling(fake_invoke):
    calls, _box = fake_invoke
    with pytest.raises(ValueError):
        host.cost("nope")
    assert calls == []


def test_cost_tenant_not_implemented_raises_typed(fake_invoke):
    _calls, box = fake_invoke
    box["status"], box["body"] = 5, b'{"code":"not_implemented","message":"ni"}'
    with pytest.raises(_hostsvc.VerbNotImplementedError):
        host.cost("tenant")


def test_unavailable_transport_invalid_input_map_to_typed_errors(fake_invoke):
    _calls, box = fake_invoke
    for status, exc in [
        (3, _hostsvc.UnavailableError),
        (6, _hostsvc.ServiceError),
        (7, _hostsvc.TransportError),
        (8, _hostsvc.InvalidInputError),
    ]:
        box["status"], box["body"] = status, b'{"code":"x","message":"m"}'
        with pytest.raises(exc):
            host.time()
