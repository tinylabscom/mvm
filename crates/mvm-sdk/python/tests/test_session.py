"""Tests for ``mvm.session(...)`` warm-VM context manager (plan-0003 + W7)."""

from __future__ import annotations

import asyncio
import gc
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


def _adder() -> mvm.RemoteFunction:
    mvm.workload(id="adder")

    @mvm.app(
        name="adder",
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        entrypoint=mvm.entrypoint_function(
            language="python", module="adder", function="add"
        ),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
    )
    def add(a: int, b: int) -> int:
        return a + b

    assert isinstance(add, mvm.RemoteFunction)
    return add


def test_session_starts_and_stops(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))
    monkeypatch.setenv("MVM_FAKE_MVM_SESSION_ID", "s-warm")

    with mvm.session("adder") as sess:
        assert isinstance(sess, mvm.Session)
        assert sess.id == "s-warm"
        assert sess.workload_id == "adder"
        # __str__ returns the id so logs/breadcrumbs stay readable.
        assert str(sess) == "s-warm"

    text = record.read_text()
    assert "verb=start" in text
    assert "workload=adder" in text
    assert "verb=stop" in text
    assert "session_id=s-warm" in text


def test_session_propagates_id_to_invoke(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))
    monkeypatch.setenv("MVM_FAKE_MVM_SESSION_ID", "s-warm")
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")

    add = _adder()
    with mvm.session("adder"):
        add.sync(2, 3)
        add.sync(4, 5)

    text = record.read_text()
    assert text.count("subcommand=invoke") == 2
    # Every invoke during the session must carry --session s-warm.
    invoke_blocks = [b for b in text.split("--\n") if "subcommand=invoke" in b]
    assert all("session=s-warm" in b for b in invoke_blocks)


def test_invoke_outside_session_carries_no_session_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")

    add = _adder()
    add.sync(2, 3)

    text = record.read_text()
    invoke_blocks = [b for b in text.split("--\n") if "subcommand=invoke" in b]
    assert all("session=\n" in b for b in invoke_blocks)


def test_session_torn_down_on_body_exception(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))

    with pytest.raises(RuntimeError, match="boom"):
        with mvm.session("adder"):
            raise RuntimeError("boom")

    text = record.read_text()
    assert "verb=start" in text
    assert "verb=stop" in text


def test_session_id_is_thread_local_via_contextvar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert mvm.session is not None
    from mvm._session import current_session_id

    assert current_session_id() is None
    with mvm.session("adder"):
        assert current_session_id() is not None
    assert current_session_id() is None


def test_empty_workload_id_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        with mvm.session(""):
            pass


def test_session_start_timeout_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MVM_SESSION_START_TIMEOUT_SEC", "0.5")
    monkeypatch.setenv("MVM_FAKE_MVM_SESSION_DELAY_MS", "5000")
    with pytest.raises(RuntimeError, match="timed out"):
        with mvm.session("adder"):
            pass


def test_session_start_output_cap_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force a session id larger than the cap by using session_delay + a long
    # session id. Simpler: drop the cap so even the small session id breaches.
    monkeypatch.setenv("MVM_MAX_OUTPUT_BYTES", "1")
    monkeypatch.setenv("MVM_FAKE_MVM_SESSION_ID", "session-id-longer-than-one-byte")
    with pytest.raises(RuntimeError, match="output cap"):
        with mvm.session("adder"):
            pass


# --- Plan-0010 W7: typed Session class -------------------------------------


def test_async_with_session_dispatches_via_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))
    monkeypatch.setenv("MVM_FAKE_MVM_SESSION_ID", "s-warm")
    monkeypatch.setenv("MVM_FAKE_MVM_INVOKE_OUT", "5")

    add = _adder()

    async def body() -> None:
        async with mvm.session("adder") as sess:
            assert isinstance(sess, mvm.Session)
            await add(2, 3)
            await sess.invoke(add, 4, 5)

    asyncio.run(body())
    text = record.read_text()
    assert text.count("subcommand=invoke") == 2
    invoke_blocks = [b for b in text.split("--\n") if "subcommand=invoke" in b]
    assert all("session=s-warm" in b for b in invoke_blocks)


def test_session_invoke_cross_workload_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MVM_FAKE_MVM_SESSION_ID", "s-1")
    add = _adder()
    # Hand-rebind the workload_id to simulate a cross-workload mistake.
    add._workload_id = "subtractor"  # type: ignore[attr-defined]

    async def body() -> None:
        async with mvm.session("adder") as sess:
            with pytest.raises(ValueError, match="cannot invoke"):
                await sess.invoke(add, 1, 2)

    asyncio.run(body())


def test_abandoned_session_warns_and_best_effort_stops(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = tmp_path / "record"
    monkeypatch.setenv("MVM_FAKE_MVM_RECORD", str(record))
    monkeypatch.setenv("MVM_FAKE_MVM_SESSION_ID", "s-leak")

    sess = mvm.session("adder")
    assert sess.id == "s-leak"
    # Drop the only reference without entering the with-block; the
    # weakref.finalize should fire on GC.
    with pytest.warns(ResourceWarning, match="not closed"):
        del sess
        gc.collect()

    text = record.read_text()
    assert "verb=stop" in text
    assert "session_id=s-leak" in text
