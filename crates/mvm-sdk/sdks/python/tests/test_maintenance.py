"""Maintenance uses the host ABI without reimplementing its repair policy."""

import pytest

import mvm


@pytest.mark.parametrize("apply", [False, True])
def test_reconcile_forwards_explicit_intent_and_preserves_errors(hostlib, apply):
    report = {"live": [], "errors": ["could not repair"]}
    hostlib.reply("maintenance.reconcile", report)
    assert mvm.maintenance.reconcile(apply=apply) == report
    assert hostlib.calls == [("maintenance.reconcile", {"apply": apply})]


def test_reconcile_defaults_to_preview(hostlib):
    hostlib.reply("maintenance.reconcile", {"errors": []})
    assert mvm.maintenance.reconcile() == {"errors": []}
    assert hostlib.calls == [("maintenance.reconcile", {"apply": False})]
