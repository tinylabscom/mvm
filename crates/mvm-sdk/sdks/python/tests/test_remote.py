"""End-to-end tests for the host-side remote call surface.

The tests run against the bundled ``tests/fixtures/fake-mvm`` shim, which
implements the ``mvmctl invoke`` and ``mvmctl session`` verbs against
env-controlled responses. This validates the SDK transport contract
without needing a real `mvm` substrate.

Per Plan-0010 W5/W6, the canonical surface is:

- ``await f(...)`` — async dispatch (returns a coroutine)
- ``f.sync(...)`` — synchronous escape (used in most tests for brevity)
- ``f.local(...)`` — pure in-process call against the wrapped body
"""

from __future__ import annotations

import asyncio
import json
import warnings
from pathlib import Path

import pytest

import mvm

FAKE_MVM = (
    Path(__file__).parent / "fixtures" / "fake-mvm"
).resolve()


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch) -> None:
    mvm.reset()
    monkeypatch.setenv("MVM_MVM_BIN", str(FAKE_MVM))
    yield
    mvm.reset()


def _build_adder(format: str = "json") -> mvm.RemoteFunction:
    mvm.workload(id="adder")

    @mvm.app(
        name="adder",
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        entrypoint=mvm.entrypoint_function(
            language="python", module="adder", function="add", format=format
        ),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
    )
    def add(a: int, b: int) -> int:
        return a + b

    assert isinstance(add, mvm.RemoteFunction)
    return add


def test_app_with_function_entrypoint_returns_remote_function() -> None:
    add = _build_adder()
    assert add.workload_id == "adder"
    assert add.format == "json"


def test_app_with_command_entrypoint_returns_callable_unchanged() -> None:
    mvm.workload(id="hello")

    @mvm.app(
        name="hello",
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        entrypoint=mvm.entrypoint(command=["python", "-m", "hello"]),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
    )
    def hello() -> str:
        return "local"

    assert hello() == "local"
    assert not isinstance(hello, mvm.RemoteFunction)


def test_local_call_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    add = _build_adder()
    # f.local(...) is the in-process body — no subprocess. Calling
    # `add(...)` directly returns a coroutine and dispatches remotely
    # (covered in test_async_call_invokes_mvmctl below).
    assert add.local(4, 5) == 9


def test_remote_call_invokes_mvmctl_with_json_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")

    add = _build_adder()
    assert add.sync(2, 3) == 5

    text = record.read_text()
    assert "subcommand=invoke" in text
    assert "workload=adder" in text
    assert 'stdin=[[2,3],{}]' in text


def test_remote_call_encodes_kwargs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", '"ok"')

    add = _build_adder()
    add.sync(1, b=2)

    text = record.read_text()
    assert 'stdin=[[1],{"b":2}]' in text


def test_remote_decodes_complex_json_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", '{"sum":5,"detail":[2,3]}')
    add = _build_adder()
    assert add.sync(2, 3) == {"sum": 5, "detail": [2, 3]}


def test_remote_raises_remote_error_from_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = json.dumps(
        {"kind": "ValueError", "error_id": "abc-123", "message": "negative input"}
    )
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_STDERR", envelope)
    monkeypatch.setenv("MVM_FAKE_MVM_EXIT", "1")

    add = _build_adder()
    with pytest.raises(mvm.RemoteError) as excinfo:
        add.sync(2, 3)
    assert excinfo.value.kind == "ValueError"
    assert excinfo.value.error_id == "abc-123"
    assert excinfo.value.message == "negative input"


def test_remote_raises_transport_error_when_stderr_not_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_STDERR", "broken pipe")
    monkeypatch.setenv("MVM_FAKE_MVM_EXIT", "1")

    add = _build_adder()
    with pytest.raises(mvm.MvmTransportError, match="broken pipe"):
        add.sync(2, 3)


def test_secret_kwarg_warns_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MVM_STRICT_SECRETS", raising=False)
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")
    add = _build_adder()
    with pytest.warns(mvm.SecretInArgWarning, match="api_key"):
        add.sync(api_key="sk-deadbeef")


def test_secret_kwarg_raises_in_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MVM_STRICT_SECRETS", "1")
    add = _build_adder()
    with pytest.raises(mvm.SecretInArgError, match="api_key"):
        add.sync(api_key="sk-deadbeef")


def test_innocent_kwarg_does_not_warn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MVM_STRICT_SECRETS", raising=False)
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")
    add = _build_adder()
    with warnings.catch_warnings():
        warnings.simplefilter("error", mvm.SecretInArgWarning)
        add.sync(name="hello", count=3)


def test_remote_rejects_malformed_workload_id(monkeypatch: pytest.MonkeyPatch) -> None:
    add = _build_adder()
    # Override workload_id post-hoc to bypass the IR validator (the kind of
    # bypass we're guarding against). The transport refuses to spawn.
    add._workload_id = "-flag-injection"  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="workload_id"):
        add.sync(2, 3)


def test_remote_decode_rejects_nonfinite(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", '{"x": NaN}')
    add = _build_adder()
    with pytest.raises(mvm.MvmTransportError, match="non-finite"):
        add.sync(2, 3)


def test_remote_decode_rejects_duplicate_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "MVM_FAKE_MVM_INVOKE_OUT", '{"a": 1, "a": 2}'
    )
    add = _build_adder()
    with pytest.raises(mvm.MvmTransportError, match="duplicate key"):
        add.sync(2, 3)


def test_remote_parses_envelope_with_marker_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = json.dumps(
        {"kind": "ValueError", "error_id": "abc", "message": "oops"}
    )
    monkeypatch.setenv(
        "MVM_FAKE_MVM_INVOKE_STDERR",
        f"some unrelated log\nMVM_ENVELOPE: {envelope}\nmore noise after\n",
    )
    monkeypatch.setenv("MVM_FAKE_MVM_EXIT", "1")
    add = _build_adder()
    with pytest.raises(mvm.RemoteError) as excinfo:
        add.sync(2, 3)
    assert excinfo.value.kind == "ValueError"
    assert excinfo.value.error_id == "abc"


def test_remote_decode_rejects_excessive_nesting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 100-deep nested array — exceeds MAX_RESULT_NESTING_DEPTH=64
    nested = "[" * 100 + "1" + "]" * 100
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", nested)
    add = _build_adder()
    with pytest.raises(mvm.MvmTransportError, match="nesting depth"):
        add.sync(2, 3)


def test_remote_format_must_be_json_or_msgpack() -> None:
    add = _build_adder()
    # Construct via private path to verify validation; users can't reach this.
    with pytest.raises(ValueError, match="format"):
        mvm.RemoteFunction(add.local, workload_id="x", format="yaml")


def test_remote_timeout_kills_subprocess_and_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MVM_INVOKE_TIMEOUT_SEC", "0.5")
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_DELAY_MS", "5000")
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")

    add = _build_adder()
    with pytest.raises(mvm.MvmTransportError, match="timed out"):
        add.sync(2, 3)


def test_remote_output_cap_kills_subprocess_and_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Cap at 1 KiB; have fake-mvm emit 4 KiB.
    monkeypatch.setenv("MVM_MAX_OUTPUT_BYTES", "1024")
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT_KIB", "4")

    add = _build_adder()
    with pytest.raises(mvm.MvmTransportError, match="output cap"):
        add.sync(2, 3)


def test_msgpack_path_raises_clearly_when_dependency_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Force the import to fail even if msgpack happens to be installed in the
    # dev env. The host call site must surface a user-readable ImportError.
    import sys

    monkeypatch.setitem(sys.modules, "msgpack", None)
    add = _build_adder(format="msgpack")
    with pytest.raises(mvm.MsgpackUnavailable):
        add.sync(1, 2)


# --- Plan-0010 W6: async-first dispatch ------------------------------------


def test_async_call_invokes_mvmctl_with_json_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")

    add = _build_adder()
    assert asyncio.run(add(2, 3)) == 5

    text = record.read_text()
    assert "subcommand=invoke" in text
    assert "workload=adder" in text
    assert 'stdin=[[2,3],{}]' in text


def test_async_cancellation_terminates_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_DELAY_MS", "5000")
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")
    monkeypatch.setenv("MVM_INVOKE_KILL_GRACE_SEC", "1.0")
    monkeypatch.setenv("MVM_INVOKE_TIMEOUT_SEC", "60")
    add = _build_adder()

    async def cancel_after_short_wait() -> None:
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(add(2, 3), timeout=0.2)

    asyncio.run(cancel_after_short_wait())


def test_payload_cap_raises_before_subprocess_spawn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))
    # Cap below the encoded payload size for [[blob], {}].
    monkeypatch.setenv("MVM_MAX_PAYLOAD_BYTES", "32")
    add = _build_adder()
    big = "x" * 1024
    with pytest.raises(mvm.PayloadTooLarge, match="MVM_MAX_PAYLOAD_BYTES"):
        add.sync(big)
    # No subprocess should have been spawned.
    assert not record.exists() or record.read_text() == ""


def test_payload_cap_raises_on_async_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MVM_MAX_PAYLOAD_BYTES", "32")
    add = _build_adder()
    big = "y" * 1024
    with pytest.raises(mvm.PayloadTooLarge):
        asyncio.run(add(big))
