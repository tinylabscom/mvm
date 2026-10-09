"""Public manifest adapters exercise the real host-library marshalling seam."""

import pytest

import mvm
from mvm._errors.types import HostLibraryError, MachineBackendError


@pytest.mark.parametrize(
    ("operation", "method", "expected_request", "reply"),
    [
        (lambda: mvm.manifest.list(), "manifest.list",
         {"orphans": False, "tags": []}, []),
        (lambda: mvm.manifest.list(orphans=True, tags=["prod", "web"]),
         "manifest.list", {"orphans": True, "tags": ["prod", "web"]},
         [{"slot_hash": "abc", "manifest_path": "/build/manifest.json",
           "name": None, "updated_at": "2026-01-01T00:00:00Z", "orphan": True,
           "tags": ["prod", "web"]}]),
        (lambda: mvm.manifest.info(), "manifest.info", {"path": None},
         {"slot_hash": "abc", "persisted": {"future": [None, {"x": 1}]},
          "snapshot": None}),
        (lambda: mvm.manifest.info("/build/manifest.json"), "manifest.info",
         {"path": "/build/manifest.json"},
         {"slot_hash": "abc", "persisted": {"version": 2},
          "snapshot": {"unknown": {"nested": [True, 4]}}}),
        (lambda: mvm.manifest.verify(), "manifest.verify",
         {"path": None, "revision": None, "check_signature": False},
         {"slot_hash": "abc", "manifest_path": "/build/manifest.json"}),
        (lambda: mvm.manifest.verify("/build/manifest.json", revision="rev",
                                     check_signature=True),
         "manifest.verify",
         {"path": "/build/manifest.json", "revision": "rev", "check_signature": True},
         {"slot_hash": "abc", "manifest_path": "/build/manifest.json"}),
    ],
)
def test_requests_and_preserved_replies(hostlib, operation, method, expected_request, reply):
    hostlib.reply(method, reply)
    assert operation() == reply
    assert hostlib.calls == [(method, expected_request)]


@pytest.mark.parametrize(
    ("operation", "method", "message"),
    [
        (lambda: mvm.manifest.verify(check_signature=True), "manifest.verify",
         "manifest signature checking is unsupported"),
        (lambda: mvm.manifest.info("invalid.json"), "manifest.info",
         "invalid manifest: missing slot_hash"),
        (lambda: mvm.manifest.list(), "manifest.list",
         "invalid manifest: malformed JSON"),
    ],
)
def test_failures_preserve_backend_error(hostlib, operation, method, message):
    hostlib.fail(method, "BACKEND_ERROR", message)
    with pytest.raises(MachineBackendError) as caught:
        operation()
    assert isinstance(caught.value, HostLibraryError)
    assert str(caught.value) == message
    assert caught.value.code == "BACKEND_ERROR"
