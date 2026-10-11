"""Defaults, explicit intent and opaque reports across the real ABI seam."""

import pytest

import mvm
from mvm._errors.types import MachineBackendError


CASES = [
    (lambda: mvm.manifest.remove(), "manifest.remove",
     {"path": None, "force": False, "manifest_file": False}),
    (lambda: mvm.manifest.remove("mvm.toml", force=True, manifest_file=True),
     "manifest.remove", {"path": "mvm.toml", "force": True, "manifest_file": True}),
    (lambda: mvm.manifest.prune(), "manifest.prune", {"orphans": False, "dry_run": True}),
    (lambda: mvm.manifest.prune(orphans=True, dry_run=False), "manifest.prune",
     {"orphans": True, "dry_run": False}),
    (lambda: mvm.manifest.export_oci("template", "image.tar.gz"), "manifest.export_oci",
     {"template": "template", "out": "image.tar.gz"}),
    (lambda: mvm.storage.info(), "storage.info", {"mock": False}),
    (lambda: mvm.storage.info(mock=True), "storage.info", {"mock": True}),
    (lambda: mvm.storage.gc(), "storage.gc",
     {"apply": False, "mock": False, "keep_prefix": []}),
    (lambda: mvm.storage.gc(apply=True, mock=True, keep_prefix=["live-"]), "storage.gc",
     {"apply": True, "mock": True, "keep_prefix": ["live-"]}),
    (lambda: mvm.bundle.export("template", "out.mvmpkg"), "bundle.export",
     {"template": "template", "out": "out.mvmpkg", "label": None, "cmdline": None, "posture": None}),
    (lambda: mvm.bundle.export("template", "out.mvmpkg", label="label", cmdline="cmdline",
                              posture={"profile": "dev", "allow_egress": True,
                                       "allow_volumes": True, "allow_unauthenticated": True}),
     "bundle.export",
     {"template": "template", "out": "out.mvmpkg", "label": "label", "cmdline": "cmdline",
      "posture": {"profile": "dev", "allow_egress": True,
                  "allow_volumes": True, "allow_unauthenticated": True}}),
]


@pytest.mark.parametrize(("operation", "method", "expected_request"), CASES)
def test_requests_and_reports(hostlib, operation, method, expected_request):
    report = {"path": "out", "removed": [], "future": {"nested": [None, True, 42]}}
    hostlib.reply(method, report)
    assert operation() == report
    assert hostlib.calls == [(method, expected_request)]


@pytest.mark.parametrize(("operation", "method", "expected_request"), CASES)
def test_errors_propagate(hostlib, operation, method, expected_request):
    message = "outer operation: inner cause"
    hostlib.fail(method, "BACKEND_ERROR", message)
    with pytest.raises(MachineBackendError, match=message):
        operation()


def test_posture_unknown_fields_reach_client_validation(hostlib):
    posture = {"profile": "dev", "unexpected": True}
    hostlib.fail("bundle.export", "BACKEND_ERROR", "unknown field")
    with pytest.raises(MachineBackendError):
        mvm.bundle.export("template", "out", posture=posture)
    assert hostlib.calls[0][1]["posture"] == posture
