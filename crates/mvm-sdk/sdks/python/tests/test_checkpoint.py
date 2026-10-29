"""Checkpoint adapters preserve full catalog JSON and host refusals."""

import json
from pathlib import Path

import pytest

import mvm
from mvm._errors.types import MachineBackendError


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
