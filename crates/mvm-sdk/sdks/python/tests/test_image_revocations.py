import json

import pytest

import mvm
from mvm import _hostlib


@pytest.mark.parametrize("operation,method,expected_request", [
    (lambda: mvm.image_revocations.status(), "image_revocations.status", {}),
    (lambda: mvm.image_revocations.update("/document", "/bundle"), "image_revocations.update",
     {"document_path": "/document", "bundle_path": "/bundle"}),
])
def test_exact_canonical_administration_requests(
    hostlib, monkeypatch, operation, method, expected_request
):
    reply = {"publication": 9, "issued_at": "2026-01-01T00:00:00Z", "sha256": "00"}
    hostlib.reply(method, reply)
    invoke = _hostlib._invoke
    raw = []

    def record(name, body):
        raw.append(body)
        return invoke(name, body)

    monkeypatch.setattr(_hostlib, "_invoke", record)
    assert operation() == reply
    assert hostlib.calls == [(method, expected_request)]
    assert raw == [json.dumps(expected_request, separators=(",", ":")).encode()]
