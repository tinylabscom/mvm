"""The host library binding.

Resolution and marshalling are tested without the library: path lookup takes
its environment, ``which`` and ``exists`` as arguments, and ``call`` takes the
C-call seam. The live tests at the end load a real library when
``MVM_HOSTLIB_PATH`` names one and ``MVM_HOME`` names a scratch directory for
it to keep state in, and are skipped otherwise.
"""

import json
import os

import pytest

import mvm
from mvm import _hostlib
from mvm._errors.types import (
    HostLibraryAbiError,
    HostLibraryError,
    HostLibraryInputError,
    MachineNotFoundError,
    MachineSpecError,
    MachineUnavailableError,
    MvmTransportError,
)


@pytest.mark.parametrize("unknown_start", [False, True])
def test_context_close_and_free_refusal_hold_original_pointer_and_library(monkeypatch, unknown_start):
    import ctypes

    class Function:
        def __init__(self, run):
            self.run = run
        def __call__(self, *args):
            return self.run(*args)

    class Library:
        def __init__(self):
            self.buffers = []
            self.fail_close = True
            self.mvm_hostlib_free = Function(lambda _out: None)
            self.mvm_hostlib_context_create = Function(self.create)
            self.mvm_hostlib_context_call = Function(lambda *args: self.reply(args[-1], 0, {}))
            self.mvm_hostlib_context_inspect = Function(lambda *args: self.reply(args[-1], 0, {}))
            self.mvm_hostlib_context_retry_stop = Function(lambda *args: self.reply(args[-1], 0, {}))
            self.mvm_hostlib_context_close = Function(self.close)
            self.mvm_hostlib_context_checked_free = Function(self.free)
        def reply(self, out, status, body):
            encoded = json.dumps(body).encode()
            buffer = (ctypes.c_uint8 * len(encoded)).from_buffer_copy(encoded)
            self.buffers.append(buffer)
            out._obj.data = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint8))
            out._obj.len = len(encoded)
            return status
        def create(self, _major, _minor, pointer, out):
            pointer._obj.value = 123  # transport fixture, NOT a native owner/proof
            return self.reply(out, 0, {})
        def close(self, _pointer, out):
            if self.fail_close:
                return self.reply(out, 5, {"code": "CONFLICT", "message": "fixture", "retryable": False})
            return self.reply(out, 0, {})
        def free(self, pointer):
            if self.fail_close:
                return 5
            pointer._obj.value = None
            return 0

    library = Library()
    negotiation = []
    def load(*, negotiate=True):
        negotiation.append(negotiate)
        return library
    monkeypatch.setattr(_hostlib, "_load", load)
    context = _hostlib.NativeContext()
    status, body = context._invoke("transport.fixture", b"{}")
    assert status == 0 and json.loads(body) == {}
    assert negotiation == [False]
    original = None
    if unknown_start:
        library.mvm_hostlib_context_call = Function(lambda *args: library.reply(
            args[-1], 6, {"code": "REJECTED", "message": "local fixture", "retryable": False}
        ))
        with pytest.raises(BaseException) as failed:
            context.call("session.start", {"workload": "fixture"})
        original = failed.value
        assert context._session_error is original
    with pytest.raises(HostLibraryError):
        context.close()
    assert context._pointer.value == 123 and context._library is library
    if unknown_start:
        assert context._session_phase == "unknown"
        assert context._session_error is original
    with pytest.raises(MvmTransportError):
        context.free()
    assert context._pointer.value == 123
    library.fail_close = False
    context.close()
    context.free()
    assert context._pointer.value is None
    if unknown_start:
        assert context._session_phase == "finished"
        assert context._session_error is original


def test_context_refuses_second_session_start_and_foreign_stop_before_transport(hostlib):
    sid = "abcdefghijklmnopqrstuvwx"
    hostlib.reply("session.start", {"session_id": sid})
    hostlib.reply("session.stop", {})
    context = _hostlib.NativeContext()
    context.call("session.start", {"workload": "fixture"})
    for method, request in [
        ("session.start", {"workload": "second"}),
        ("session.stop", {"session_id": "zyxwvutsrqponmlkjihgfedc"}),
    ]:
        with pytest.raises(MvmTransportError) as caught:
            context.call(method, request)
        assert caught.value.recovery is context
    assert hostlib.methods == ["session.start"]
    for cleanup in [context.retry_stop, context.close, context.free]:
        with pytest.raises(MvmTransportError):
            cleanup()
    context.call("session.stop", {"session_id": sid})
    with pytest.raises(MvmTransportError):
        context.call("session.start", {"workload": "second"})
    assert hostlib.methods == ["session.start", "session.stop"]
    context.close()
    context.free()
    # Actual SDK binding state, but the installed recorder created no child.


@pytest.mark.parametrize("raw", [
    b"{}", b'{"session_id":7}', b'{"session_id":null}',
    b'{"session_id":"NOT-BASE32"}',
    b'{"session_id":"abcdefghijklmnopqrstuvwx\\n"}',
    b'{"session_id":"abcdefghijklmnopqrstuvwx","session_id":"abcdefghijklmnopqrstuvwx"}',
    b'{"session_id":"abcdefghijklmnopqrstuvwx","session_\\u0069d":"abcdefghijklmnopqrstuvwx"}',
    b'{"private_marker":"must-not-render"}', b"not-json",
])
def test_unknown_start_keeps_wire_reply_and_original_error_without_false_free(monkeypatch, raw):
    calls = []

    def inprocess_transport(method, request):
        calls.append((method, request))
        return 0, raw

    monkeypatch.setattr(_hostlib, "_invoke", inprocess_transport)
    context = _hostlib.NativeContext()
    with pytest.raises(BaseException) as first:
        context.call("session.start", {"workload": "fixture"})
    original = first.value
    assert original.recovery is context
    assert context._session_error is original
    assert context._session_reply_bytes == raw
    for cleanup in [context.retry_stop, context.close, context.free, context.inspect]:
        with pytest.raises(MvmTransportError) as refused:
            cleanup()
        assert "must-not-render" not in str(refused.value)
    with pytest.raises(MvmTransportError):
        context.call("session.start", {"workload": "second"})
    assert context._session_error is original
    assert context._session_reply_bytes == raw
    assert len(calls) == 1
    assert not context._pointer
    assert not context._freed
    # Even a genuine no-C-allocation fixture cannot turn unknown-start policy
    # into fake native stop evidence or an acknowledged cleanup.


def test_the_file_name_follows_the_platform():
    assert _hostlib.library_file_name("darwin") == "libmvm_hostlib.dylib"
    assert _hostlib.library_file_name("linux") == "libmvm_hostlib.so"

def test_recovery_details_use_the_generated_error_and_immutable_typed_value():
    from dataclasses import FrozenInstanceError

    fields = {"machine_id": "machine", "plan_id": "plan", "reason": "recover"}
    body = json.dumps({"code": "RECOVERY_REQUIRED", "message": "context",
                       "retryable": False, "details": fields}).encode()
    with pytest.raises(mvm.MachineRecoveryRequiredError) as caught:
        _hostlib.call("machine.inspect", {}, invoke=lambda *_: (12, body))
    error = caught.value
    assert str(error) == "context"
    assert error.retryable is False
    assert error.details == mvm.RecoveryRequiredDetails(**fields)
    with pytest.raises(FrozenInstanceError):
        error.details.machine_id = "replacement"


@pytest.mark.parametrize("details", [
    None, [], "private-marker", {}, {"machine_id": "m"},
    {"machine_id": "m", "plan_id": "p", "reason": 7},
    {"machine_id": "m", "plan_id": "p", "reason": "r", "extra": "private-marker"},
])
def test_malformed_recovery_details_are_nonretryable_without_payload_echo(details):
    body = json.dumps({"code": "RECOVERY_REQUIRED", "message": "private-marker",
                       "retryable": False, "details": details}).encode()
    with pytest.raises(HostLibraryError) as caught:
        _hostlib.call("machine.inspect", {}, invoke=lambda *_: (12, body))
    error = caught.value
    assert error.retryable is False
    assert not isinstance(error, mvm.MachineRecoveryRequiredError)
    assert not hasattr(error, "details")
    assert "private-marker" not in str(error)
    assert "private-marker" not in repr(error)
    assert error.__cause__ is None and error.__context__ is None


@pytest.mark.parametrize("status,code,retryable", [
    (12, "UNAVAILABLE", True), (7, "RECOVERY_REQUIRED", False),
    (12, "RECOVERY_REQUIRED", True), (12, "RECOVERY_REQUIRED", "false"),
    (12, "RECOVERY_REQUIRED", None),
])
def test_recovery_status_code_and_retryability_must_agree(status, code, retryable):
    body = json.dumps({"code": code, "message": "private-marker", "retryable": retryable,
                       "details": {"machine_id": "m", "plan_id": "p", "reason": "r"}}).encode()
    with pytest.raises(HostLibraryError) as caught:
        _hostlib.call("machine.inspect", {}, invoke=lambda *_: (status, body))
    assert caught.value.retryable is False
    assert not hasattr(caught.value, "details")
    assert "private-marker" not in str(caught.value)


def test_malformed_error_json_does_not_retain_a_decoder_source():
    with pytest.raises(HostLibraryError) as caught:
        _hostlib.call("machine.inspect", {}, invoke=lambda *_: (12, b"private-marker"))
    assert caught.value.retryable is False
    assert caught.value.__context__ is None
    assert "private-marker" not in str(caught.value)


def test_old_unknown_code_rule_drops_details_but_does_not_retry():
    # The pre-addition decoder's generic fallback has no typed details projection.
    fields = {"code": "RECOVERY_REQUIRED", "message": "recover", "retryable": False,
              "details": {"machine_id": "m", "plan_id": "p", "reason": "r"}}
    old_codes = {code: cls for code, cls in _hostlib.CODE_ERRORS.items()
                 if code != "RECOVERY_REQUIRED"}
    error = old_codes.get(fields["code"], HostLibraryError)(fields["message"])
    error.retryable = bool(fields.get("retryable", False))
    assert type(error) is HostLibraryError
    assert error.retryable is False
    assert not hasattr(error, "details")


def test_an_explicit_path_is_the_only_candidate():
    paths = _hostlib.candidate_paths(
        {"MVM_HOSTLIB_PATH": "/opt/lib/libmvm_hostlib.so"},
        which=lambda _: "/usr/bin/mvmctl",
        packaged_dir="/pkg/mvm/_native",
    )
    assert paths == ["/opt/lib/libmvm_hostlib.so"]


def test_the_override_variable_is_the_registry_name():
    assert _hostlib.LIB_PATH_ENV == mvm.MVM_HOSTLIB_PATH_ENV == "MVM_HOSTLIB_PATH"


def test_the_approval_callback_is_public():
    assert mvm.set_approval_callback is _hostlib.set_approval_callback


def test_the_packaged_copy_comes_before_mvmctl_and_both_sides_of_its_link(tmp_path):
    real_dir = tmp_path / "cellar" / "bin"
    real_dir.mkdir(parents=True)
    real = real_dir / "mvmctl"
    real.write_text("")
    link_dir = tmp_path / "bin"
    link_dir.mkdir()
    link = link_dir / "mvmctl"
    link.symlink_to(real)

    paths = _hostlib.candidate_paths(
        {}, which=lambda _: str(link), platform="linux", packaged_dir="/pkg/mvm/_native"
    )
    assert paths == [
        "/pkg/mvm/_native/libmvm_hostlib.so",
        str(link_dir / "libmvm_hostlib.so"),
        os.path.join(os.path.realpath(real_dir), "libmvm_hostlib.so"),
    ]


def test_without_mvmctl_only_the_packaged_copy_is_a_candidate():
    paths = _hostlib.candidate_paths(
        {}, which=lambda _: None, platform="darwin", packaged_dir="/pkg/mvm/_native"
    )
    assert paths == ["/pkg/mvm/_native/libmvm_hostlib.dylib"]


def test_the_default_packaged_directory_is_inside_the_package():
    package_dir = os.path.dirname(os.path.abspath(mvm.__file__))
    assert _hostlib.PACKAGED_DIR == os.path.join(package_dir, "_native")


def test_a_packaged_library_that_exists_wins_over_one_beside_mvmctl(tmp_path):
    packaged = tmp_path / "_native"
    packaged.mkdir()
    (packaged / "libmvm_hostlib.so").write_text("")
    beside = tmp_path / "bin"
    beside.mkdir()
    (beside / "libmvm_hostlib.so").write_text("")

    path = _hostlib.resolve_library_path(
        {},
        which=lambda _: str(beside / "mvmctl"),
        platform="linux",
        packaged_dir=str(packaged),
    )
    assert path == str(packaged / "libmvm_hostlib.so")


def test_beside_mvmctl_is_used_when_nothing_is_packaged():
    path = _hostlib.resolve_library_path(
        {},
        which=lambda _: "/usr/local/bin/mvmctl",
        exists=lambda path: path == "/usr/local/bin/libmvm_hostlib.so",
        platform="linux",
        packaged_dir="/pkg/mvm/_native",
    )
    assert path == "/usr/local/bin/libmvm_hostlib.so"


def test_nothing_found_is_a_typed_error_naming_every_place():
    with pytest.raises(MvmTransportError) as raised:
        _hostlib.resolve_library_path(
            {}, which=lambda _: None, exists=lambda _: False, packaged_dir="/pkg/mvm/_native"
        )
    message = str(raised.value)
    assert "MVM_HOSTLIB_PATH" in message
    assert "/pkg/mvm/_native" in message
    assert "mvmctl on PATH" in message


def test_an_override_naming_a_missing_file_is_refused_not_ignored():
    with pytest.raises(MvmTransportError, match="does not exist"):
        _hostlib.resolve_library_path(
            {"MVM_HOSTLIB_PATH": "/nope/libmvm_hostlib.so"},
            which=lambda _: "/usr/bin/mvmctl",
            exists=lambda path: path != "/nope/libmvm_hostlib.so",
        )


@pytest.fixture
def seam():
    calls = []
    box = {"status": 0, "body": b"[]"}

    def invoke(method, request_json):
        calls.append((method, json.loads(request_json) if request_json else None))
        return box["status"], box["body"]

    return calls, box, invoke


def test_a_call_sends_the_request_and_returns_the_reply(seam):
    calls, box, invoke = seam
    box["body"] = b'[{"id": "web"}]'
    assert _hostlib.call("machine.list", {"name": "web"}, invoke=invoke) == [{"id": "web"}]
    assert calls == [("machine.list", {"name": "web"})]


def test_a_call_with_no_request_sends_an_empty_body(seam):
    calls, _, invoke = seam
    _hostlib.call("backend.capabilities", invoke=invoke)
    assert calls == [("backend.capabilities", None)]


@pytest.mark.parametrize(
    "code, exc",
    [
        ("NOT_FOUND", MachineNotFoundError),
        ("UNAVAILABLE", MachineUnavailableError),
        ("INVALID_INPUT", HostLibraryInputError),
        ("ABI_NOT_NEGOTIATED", HostLibraryAbiError),
    ],
)
def test_an_error_body_raises_the_type_its_code_names(seam, code, exc):
    _, box, invoke = seam
    box["status"] = 1
    box["body"] = json.dumps(
        {"code": code, "message": "it failed", "retryable": code == "UNAVAILABLE"}
    ).encode()
    with pytest.raises(exc, match="it failed") as raised:
        _hostlib.call("machine.inspect", {"id": "x"}, invoke=invoke)
    assert raised.value.code == code
    assert raised.value.retryable == (code == "UNAVAILABLE")
    assert isinstance(raised.value, HostLibraryError)


def test_an_unknown_code_raises_the_base_type(seam):
    _, box, invoke = seam
    box["status"] = 99
    box["body"] = b'{"code": "SOMETHING_NEW", "message": "?"}'
    with pytest.raises(HostLibraryError) as raised:
        _hostlib.call("machine.list", invoke=invoke)
    assert type(raised.value) is HostLibraryError


def test_the_default_seam_is_the_module_level_invoke(monkeypatch, seam):
    """Tests replace `_invoke` on the module; `call` must look it up at call
    time, or the seam would silently miss."""
    calls, _, invoke = seam
    monkeypatch.setattr(_hostlib, "_invoke", invoke)
    assert _hostlib.call("machine.list") == []
    assert calls == [("machine.list", None)]


def test_approval_callback_maps_the_bounded_decisions_and_receives_the_prompt():
    seen = []
    prompt = {
        "request_id": "approval-1",
        "subject": {"kind": "tool_call", "tool": "shell"},
        "expires_in_ms": 1000,
    }

    def decide(value):
        seen.append(value)
        return "session"

    encoded = json.dumps(prompt).encode()
    assert _hostlib._approval_result(decide, encoded) == 2
    assert seen == [prompt]
    assert _hostlib._approval_result(lambda _: "once", encoded) == 1
    assert _hostlib._approval_result(lambda _: "deny", encoded) == 0


def test_approval_callback_failures_and_unknown_answers_deny():
    def raises(_):
        raise RuntimeError("application failure")

    assert _hostlib._approval_result(raises, b"{}") == 0
    assert _hostlib._approval_result(lambda _: "forever", b"{}") == 0
    assert _hostlib._approval_result(lambda _: "once", b"not json") == 0


_LIVE = pytest.mark.skipif(
    not os.environ.get("MVM_HOSTLIB_PATH") or not os.environ.get("MVM_HOME"),
    reason="needs MVM_HOSTLIB_PATH naming a built library and MVM_HOME naming a scratch directory",
)


@_LIVE
def test_a_real_library_negotiates_and_answers():
    assert isinstance(_hostlib.call("machine.list"), list)
    with pytest.raises(HostLibraryInputError):
        _hostlib.call("machine.shell")


@_LIVE
def test_a_real_library_registers_and_clears_an_approval_callback():
    _hostlib.set_approval_callback(lambda _: "once")
    _hostlib.set_approval_callback(None)


@_LIVE
def test_a_real_library_lists_the_inventory_through_the_facade():
    records = mvm.Machine.ls()
    assert isinstance(records, list)
    for record in records:
        assert record["build_mode"] in ("dev", "prod")


@_LIVE
def test_a_real_library_refuses_a_command_override_at_launch(tmp_path):
    """Reaches the launcher end to end — request parsing, the builder, the
    launcher's own refusal — and proves the refusal arrives typed, without
    booting anything."""
    rootfs = tmp_path / "rootfs.ext4"
    rootfs.write_bytes(b"\0" * 4096)
    with pytest.raises(MachineSpecError) as raised:
        mvm.Machine.run(str(rootfs), name="sdk-live-cmd", command=["/bin/true"])
    assert raised.value.code == "INVALID_SPEC"
    assert all(record["name"] != "sdk-live-cmd" for record in mvm.Machine.ls())
