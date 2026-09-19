"""The host library binding.

Resolution and marshalling are tested without the library: path lookup takes
its environment, ``which`` and ``exists`` as arguments, and ``call`` takes the
C-call seam. The live test at the end loads a real library when
``MVM_HOSTLIB_PATH`` names one, and is skipped otherwise.
"""

import json
import os

import pytest

from mvm import _hostlib
from mvm._errors.types import (
    HostLibraryAbiError,
    HostLibraryError,
    HostLibraryInputError,
    MachineNotFoundError,
    MachineUnavailableError,
    MvmTransportError,
)


def test_the_file_name_follows_the_platform():
    assert _hostlib.library_file_name("darwin") == "libmvm_hostlib.dylib"
    assert _hostlib.library_file_name("linux") == "libmvm_hostlib.so"


def test_an_explicit_path_is_the_only_candidate():
    paths = _hostlib.candidate_paths(
        {"MVM_HOSTLIB_PATH": "/opt/lib/libmvm_hostlib.so"}, which=lambda _: "/usr/bin/mvmctl"
    )
    assert paths == ["/opt/lib/libmvm_hostlib.so"]


def test_the_library_is_looked_for_beside_mvmctl(tmp_path):
    real_dir = tmp_path / "cellar" / "bin"
    real_dir.mkdir(parents=True)
    real = real_dir / "mvmctl"
    real.write_text("")
    link_dir = tmp_path / "bin"
    link_dir.mkdir()
    link = link_dir / "mvmctl"
    link.symlink_to(real)

    paths = _hostlib.candidate_paths({}, which=lambda _: str(link), platform="linux")
    assert paths == [
        str(link_dir / "libmvm_hostlib.so"),
        os.path.join(os.path.realpath(real_dir), "libmvm_hostlib.so"),
    ]


def test_no_mvmctl_and_no_override_is_a_typed_error():
    with pytest.raises(MvmTransportError, match="MVM_HOSTLIB_PATH"):
        _hostlib.resolve_library_path({}, which=lambda _: None, exists=lambda _: False)


def test_an_override_naming_a_missing_file_is_refused_not_ignored():
    with pytest.raises(MvmTransportError, match="does not exist"):
        _hostlib.resolve_library_path(
            {"MVM_HOSTLIB_PATH": "/nope/libmvm_hostlib.so"},
            which=lambda _: "/usr/bin/mvmctl",
            exists=lambda path: path != "/nope/libmvm_hostlib.so",
        )


def test_the_first_existing_candidate_wins():
    path = _hostlib.resolve_library_path(
        {},
        which=lambda _: "/usr/local/bin/mvmctl",
        exists=lambda path: path == "/usr/local/bin/libmvm_hostlib.so",
        platform="linux",
    )
    assert path == "/usr/local/bin/libmvm_hostlib.so"


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


def test_the_binding_never_spawns_a_process():
    """The binding's whole transport is the C call. A reference to a process
    API in this module would be a second entrypoint to every verb."""
    source = open(_hostlib.__file__, encoding="utf-8").read()
    for forbidden in ("subprocess", "os.system", "os.exec", "os.spawn", "Popen"):
        assert forbidden not in source, forbidden


@pytest.mark.skipif(
    not os.environ.get("MVM_HOSTLIB_PATH"), reason="needs MVM_HOSTLIB_PATH naming a built library"
)
def test_a_real_library_negotiates_and_answers():
    assert isinstance(_hostlib.call("machine.list"), list)
    with pytest.raises(HostLibraryInputError):
        _hostlib.call("machine.shell")
