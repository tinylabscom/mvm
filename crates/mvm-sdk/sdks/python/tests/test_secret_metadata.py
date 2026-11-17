"""Public metadata lookup uses the host library without the CLI executable."""

import pytest

import mvm
from mvm._errors.types import MachineBackendError


def test_get_preserves_metadata_and_absence(hostlib, monkeypatch):
    monkeypatch.setenv("PATH", "")
    metadata = {
        "tenant": "local", "name": "sample", "binding": None, "referenced_by": ["machine"]
    }
    hostlib.reply("secret.get", metadata).reply("secret.get", None)
    assert mvm.secrets.get("sample") == metadata
    assert mvm.secrets.get("missing", tenant="other") is None
    assert hostlib.calls == [
        ("secret.get", {"tenant": "local", "name": "sample"}),
        ("secret.get", {"tenant": "other", "name": "missing"}),
    ]


def test_get_does_not_turn_storage_fault_into_miss(hostlib, monkeypatch):
    monkeypatch.setenv("PATH", "")
    hostlib.fail("secret.get", "BACKEND_ERROR", "host-local operation failed")
    with pytest.raises(MachineBackendError) as caught:
        mvm.secrets.get("sample")
    assert caught.value.retryable is False
    assert "private-marker" not in str(caught.value)
