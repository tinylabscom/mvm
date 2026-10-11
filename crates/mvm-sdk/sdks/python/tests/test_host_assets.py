"""Host assets: exact defaults, explicit intent, preserved reports and failures."""
import pytest

import mvm
from mvm._errors.types import MachineBackendError

WORKSPACE = {"vm": "worker", "volume": None, "exclude": [], "protected_paths": []}
CASES = [
    (lambda: mvm.artifact.inspect("abc"), "artifact.inspect", {"id": "abc"}),
    (lambda: mvm.artifact.validate("abc"), "artifact.validate", {"id": "abc"}),
    (lambda: mvm.artifact.configure_firecracker("abc"), "artifact.configure_firecracker", {"id": "abc"}),
    (lambda: mvm.volumes.list(), "volume.list", {}),
    (lambda: mvm.volumes.inspect("data"), "volume.inspect", {"name": "data"}),
    (lambda: mvm.volumes.create("data", 16), "volume.create", {"name": "data", "capacity_mib": 16, "root": None}),
    (lambda: mvm.volumes.unlock("data"), "volume.unlock", {"name": "data"}),
    (lambda: mvm.volumes.lock("data"), "volume.lock", {"name": "data"}),
    (lambda: mvm.volumes.mount("worker", "data", "/data"), "volume.mount",
     {"vm": "worker", "volume": "data", "guest_path": "/data", "host": None, "access": "read-only"}),
    (lambda: mvm.volumes.mount("worker", "data", "/data", host="/source", access="read-write"),
     "volume.mount", {"vm": "worker", "volume": "data", "guest_path": "/data", "host": "/source", "access": "read-write"}),
    (lambda: mvm.volumes.detach("worker", "/data"), "volume.detach", {"vm": "worker", "guest_path": "/data"}),
    (lambda: mvm.volumes.attachments("worker"), "volume.attachments", {"vm": "worker"}),
    (lambda: mvm.volumes.snapshot("data", "before"), "volume.snapshot", {"name": "data", "snapshot": "before"}),
    (lambda: mvm.volumes.restore("data", "before"), "volume.restore", {"name": "data", "snapshot": "before"}),
    (lambda: mvm.workspaces.review("worker"), "workspace.review", WORKSPACE),
    (lambda: mvm.workspaces.apply("worker", "digest"), "workspace.apply",
     {"workspace": WORKSPACE, "expected_fingerprint": "digest", "approved": False}),
    (lambda: mvm.workspaces.apply("worker", "digest", approved=True), "workspace.apply",
     {"workspace": WORKSPACE, "expected_fingerprint": "digest", "approved": True}),
    (lambda: mvm.workspaces.undo("worker"), "workspace.undo", {"workspace": WORKSPACE, "approved": False}),
    (lambda: mvm.workspaces.redo("worker", approved=True), "workspace.redo", {"workspace": WORKSPACE, "approved": True}),
    (lambda: mvm.audit.sessions.list(), "audit.sessions.list", {"tenant": "local", "range": {"since": None, "until": None}}),
    (lambda: mvm.audit.sessions.show("abcdef01"), "audit.sessions.show",
     {"tenant": "local", "selector": "abcdef01", "filter": {"kind": None, "range": {"since": None, "until": None}}}),
    (lambda: mvm.audit.sessions.verify("abcdef01"), "audit.sessions.verify", {"tenant": "local", "selector": "abcdef01"}),
    (lambda: mvm.posture.inspect(), "posture.inspect", {}),
]


@pytest.mark.parametrize(("operation", "method", "expected_request"), CASES)
def test_marshalling_and_honest_reports(hostlib, operation, method, expected_request):
    report = {"recoveries": [{"kind": "interrupted", "apply_id": "old"}],
              "review": {"status": "ready", "fingerprint": "digest"}, "future": [None, True]}
    hostlib.reply(method, report)
    assert operation() == report
    assert hostlib.calls == [(method, expected_request)]


@pytest.mark.parametrize(("operation", "method", "expected_request"), CASES)
def test_error_chain_is_not_replaced(hostlib, operation, method, expected_request):
    hostlib.fail(method, "BACKEND_ERROR", "outer operation: inner cause")
    with pytest.raises(MachineBackendError, match="outer operation: inner cause"):
        operation()


def test_apply_requires_fingerprint_and_preserves_policy(hostlib):
    with pytest.raises(TypeError):
        mvm.workspaces.apply("worker")
    hostlib.reply("workspace.review", {"review": {"status": "refused"}})
    mvm.workspaces.review("worker", exclude=["build/**"], protected_paths=["private/**"])
    assert hostlib.calls[-1][1]["protected_paths"] == ["private/**"]
    assert hostlib.calls[-1][1]["exclude"] == ["build/**"]
    assert callable(mvm.audit.emit)
    assert callable(mvm.secret)
