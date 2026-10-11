"""Durable operations cross the ABI seam, retaining defaults, reports and errors."""
import pytest
import mvm
from mvm._errors.types import MachineBackendError


def execute(request):
    return {"intent": "execute", "request": request}


CASES = [
    (lambda: mvm.agent_sessions.list(), "agent_sessions.list", {}),
    (lambda: mvm.agent_sessions.show("s"), "agent_sessions.show", {"session_id": "s"}),
    (lambda: mvm.agent_sessions.open("s", intent="execute"), "agent_sessions.open",
     execute({"session_id": "s", "members": [], "resume_point": None})),
    (lambda: mvm.agent_sessions.park("s", intent="execute", reason="operator", journal_cursor=7),
     "agent_sessions.park", execute({"session_id": "s", "reason": "operator", "journal_cursor": 7,
                                   "approval_head": None, "retain_for": None, "expected_generation": None})),
    (lambda: mvm.agent_sessions.renew("s", intent="execute", extend_for="1h"),
     "agent_sessions.renew", execute({"session_id": "s", "extend_for": "1h",
                                    "expected_deadline": None, "expected_generation": None})),
    (lambda: mvm.agent_sessions.resume("s", intent="execute", backend="mock", image="test",
                                      image_sha256="digest", cpus=1, mem_mib=128, boot=False),
     "agent_sessions.resume", execute({"session_id": "s", "backend": "mock", "image": "test",
                                      "image_sha256": "digest", "cpus": 1, "mem_mib": 128, "boot": False,
                                      "kernel_sha256": None, "kernel": None, "approval_head": None,
                                      "expected_generation": None})),
    (lambda: mvm.checkpoints.list(), "checkpoints.list", {}),
    (lambda: mvm.checkpoints.info("c"), "checkpoints.info", {"id": "c"}),
    (lambda: mvm.checkpoints.diff("a", "b"), "checkpoints.diff", {"a": "a", "b": "b"}),
    (lambda: mvm.checkpoints.verify("c"), "checkpoints.verify", {"id": "c"}),
    (lambda: mvm.checkpoints.timeline("c"), "checkpoints.timeline", {"target": "c", "kind": None}),
    (lambda: mvm.checkpoints.remove("c", intent="execute"), "checkpoints.remove", execute({"id": "c"})),
    (lambda: mvm.checkpoints.capture("vm", intent="execute", checkpoint_class="fs_quick"),
     "checkpoints.capture", execute({"name": "vm", "class": "fs_quick", "tag": None})),
    (lambda: mvm.checkpoints.restore("c", intent="execute", tenant="t"),
     "checkpoints.restore", execute({"id": "c", "tenant": "t"})),
    (lambda: mvm.checkpoints.fork("c", intent="execute", tenant="t", boot=False),
     "checkpoints.fork", execute({"id": "c", "tenant": "t", "boot": False, "new_id": None,
                                 "hypervisor": "", "cpus": None, "memory": None})),
    (lambda: mvm.replay.run_session("s", tenant="t", timeout_secs=30), "replay.run_session",
     {"selection": {"session_id": "s", "from": None, "as_name": None},
      "dry_run": True, "tenant": "t", "timeout_secs": 30}),
    (lambda: mvm.replay.run_session("s", tenant="t", timeout_secs=30, dry_run=False,
                                  from_checkpoint="c", as_name="child"), "replay.run_session",
     {"selection": {"session_id": "s", "from": "c", "as_name": "child"},
      "dry_run": False, "tenant": "t", "timeout_secs": 30}),
]


@pytest.mark.parametrize(("operation", "method", "expected_request"), CASES)
def test_requests_and_reports(hostlib, operation, method, expected_request):
    report = {"generation": 3, "replayed": True, "warnings": ["audit unavailable"],
              "summary": {"checkpoint": "c"}, "execution": None, "future": [None, True]}
    hostlib.reply(method, report)
    assert operation() == report
    assert hostlib.calls == [(method, expected_request)]


@pytest.mark.parametrize(("operation", "method", "expected_request"), CASES)
def test_errors_preserve_client_context(hostlib, operation, method, expected_request):
    hostlib.fail(method, "BACKEND_ERROR", "outer operation: tenant refused")
    with pytest.raises(MachineBackendError, match="outer operation: tenant refused"):
        operation()


def test_no_implicit_mutation_or_privileged_namespace(hostlib):
    with pytest.raises(TypeError):
        mvm.agent_sessions.open("s")
    with pytest.raises(TypeError):
        mvm.checkpoints.remove("c")
    assert hostlib.calls == []
    assert callable(mvm.session)
    assert not hasattr(mvm.agent_sessions, "at")
    for name in ("revert", "rewind", "advance"):
        assert not hasattr(mvm.checkpoints, name)
