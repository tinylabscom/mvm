import json

import pytest

import mvm
from mvm import _hostlib


@pytest.mark.parametrize("operation,method,expected_request,reply", [
    (lambda: mvm.attestation.export(), "attestation.export", {},
     {"payload": [0, 255], "signature": [1], "signer_id": "host"}),
    (lambda: mvm.attestation.status(), "attestation.status", {},
     {"signer_id": "host", "pubkey_hex": "00", "secret_path": "/identity",
      "public_path": "/public", "providers": []}),
    (lambda: mvm.attestation.verify("/report", trust={"kind": "self_identity"}),
     "attestation.verify", {"report_path": "/report", "trust": {"kind": "self_identity"}},
     {"signer_id": "host", "body": {"hw_measurement": None}, "trust": {"kind": "self_identity"}}),
    (lambda: mvm.attestation.verify("/report", trust={"kind": "public_key_file", "path": "/key"}),
     "attestation.verify", {"report_path": "/report",
                            "trust": {"kind": "public_key_file", "path": "/key"}}, {}),
])
def test_exact_requests_and_literal_empty_objects(
    hostlib, monkeypatch, operation, method, expected_request, reply
):
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
