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


def test_the_file_name_follows_the_platform():
    assert _hostlib.library_file_name("darwin") == "libmvm_hostlib.dylib"
    assert _hostlib.library_file_name("linux") == "libmvm_hostlib.so"


def test_an_explicit_path_is_the_only_candidate():
    paths = _hostlib.candidate_paths(
        {"MVM_HOSTLIB_PATH": "/opt/lib/libmvm_hostlib.so"},
        which=lambda _: "/usr/bin/mvmctl",
        packaged_dir="/pkg/mvm/_native",
    )
    assert paths == ["/opt/lib/libmvm_hostlib.so"]


def test_the_override_variable_is_the_registry_name():
    assert _hostlib.LIB_PATH_ENV == mvm.MVM_HOSTLIB_PATH_ENV == "MVM_HOSTLIB_PATH"


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
