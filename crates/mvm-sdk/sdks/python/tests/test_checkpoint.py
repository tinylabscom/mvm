"""Checkpoint adapters preserve full catalog JSON and host refusals."""

import json
from pathlib import Path

import pytest

import mvm
from mvm._errors.types import MachineBackendError, MachineConflictError, MachineSpecError


CATALOG = json.loads(
    (Path(__file__).resolve().parents[5] / "tests/fixtures/checkpoint/catalog.json").read_text()
)


@pytest.mark.parametrize("reply", [[], CATALOG])
def test_list_preserves_complete_and_legacy_metadata(hostlib, reply):
    hostlib.reply("checkpoint.list", reply)
    assert mvm.checkpoint.list() == reply
    assert hostlib.calls == [("checkpoint.list", {})]


def test_list_preserves_nonretryable_host_refusal(hostlib):
    hostlib.fail("checkpoint.list", "BACKEND_ERROR", "host-local operation failed")
    with pytest.raises(MachineBackendError) as caught:
        mvm.checkpoint.list()
    assert caught.value.code == "BACKEND_ERROR"
    assert str(caught.value) == "host-local operation failed"


def test_remove_calls_only_the_host_local_closed_operation(hostlib):
    hostlib.reply("checkpoint.remove", {})
    assert mvm.checkpoint.remove("ckpt-local") is None
    assert hostlib.calls == [("checkpoint.remove", {"id": "ckpt-local"})]


@pytest.mark.parametrize(
    ("code", "error_type"),
    [
        ("INVALID_SPEC", MachineSpecError),
        ("CONFLICT", MachineConflictError),
        ("BACKEND_ERROR", MachineBackendError),
    ],
)
def test_remove_preserves_nonretryable_host_refusals(hostlib, code, error_type):
    hostlib.fail("checkpoint.remove", code, "checkpoint removal refused")
    with pytest.raises(error_type) as caught:
        mvm.checkpoint.remove("ckpt-local")
    assert caught.value.code == code
    assert caught.value.retryable is False
    assert str(caught.value) == "checkpoint removal refused"
    assert hostlib.calls == [("checkpoint.remove", {"id": "ckpt-local"})]
