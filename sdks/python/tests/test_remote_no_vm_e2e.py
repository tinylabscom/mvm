"""End-to-end test for SDK no-VM dispatch against the real binary.

Validates the full SDK wire contract:

    Python SDK  --(encode args)-->  mvmctl __sdk-no-vm
                                          |
                                          v
                                    embedded oneshot.py wrapper
                                          |
                                          v
                                    user function in temp module
                                          |
                                    --(encode return)-->
    Python SDK  <--(decode)----------    stdout

Skips when a built `mvmctl` binary cannot be located. CI sets
``MVM_E2E_MVM_BIN`` to the path. Local dev: the test finds
``target/debug/mvmctl`` automatically once `cargo build -p mvm-cli`
has run.

This is the regression net for slice E2 — once the IR-to-image
pipeline lands, the same `await f(2, 3) == 5` assertion guards
against drift in the wire contract.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
from pathlib import Path
from typing import Iterator

import pytest

import mvm

# Repo root is four levels up from this file:
#   sdks/python/tests/test_remote_no_vm_e2e.py → repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_DEBUG_BIN = _REPO_ROOT / "target" / "debug" / "mvmctl"


def _locate_mvmctl() -> Path | None:
    """Resolve a built mvmctl binary. Prefer the explicit env var so CI
    can point at a release build; fall back to the cargo debug output."""
    explicit = os.environ.get("MVM_E2E_MVM_BIN")
    if explicit:
        candidate = Path(explicit)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
        return None
    if _DEFAULT_DEBUG_BIN.is_file() and os.access(_DEFAULT_DEBUG_BIN, os.X_OK):
        return _DEFAULT_DEBUG_BIN
    return None


@pytest.fixture
def real_mvmctl() -> Path:
    binary = _locate_mvmctl()
    if binary is None:
        pytest.skip(
            "no built mvmctl found at target/debug/mvmctl or "
            "MVM_E2E_MVM_BIN; run `cargo build -p mvm-cli` from the "
            "repo root first"
        )
    return binary


@pytest.fixture(autouse=True)
def _clean_state() -> Iterator[None]:
    mvm.reset()
    yield
    mvm.reset()


@pytest.fixture
def adder_module(tmp_path: Path) -> Iterator[object]:
    """Write a single-function source file to a fresh tmp dir, import
    it, and yield the module. The wrapper subprocess will rediscover
    the module the same way: `sys.path.insert(0, working_dir)` +
    `importlib.import_module(cfg["module"])`.
    """
    mod_path = tmp_path / "adder_mod.py"
    mod_path.write_text("def add(a, b):\n    return a + b\n")
    sys.path.insert(0, str(tmp_path))
    try:
        if "adder_mod" in sys.modules:
            mod = importlib.reload(sys.modules["adder_mod"])
        else:
            mod = importlib.import_module("adder_mod")
        yield mod
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("adder_mod", None)


def _decorate(adder_module: object) -> mvm.RemoteFunction:
    """Wrap the imported `adder_mod.add` directly so its `__module__`
    points at `adder_mod` (not at this test file) — the SDK's
    no-VM argv-builder reads `fn.__module__` to tell mvmctl where
    to import the function from.
    """
    return mvm.func(name="adder")(adder_module.add)


def test_no_vm_sync_roundtrip_returns_real_value(
    real_mvmctl: Path,
    adder_module: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``f.sync(2, 3) == 5`` against the real mvmctl no-VM path."""
    monkeypatch.setenv("MVM_NO_VM", "1")
    monkeypatch.setenv("MVM_MVM_BIN", str(real_mvmctl))

    add = _decorate(adder_module)
    assert add.sync(2, 3) == 5


def test_no_vm_async_roundtrip_returns_real_value(
    real_mvmctl: Path,
    adder_module: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``await f(2, 3) == 5`` against the real mvmctl no-VM path.

    Confirms the async dispatch path (the canonical SDK call form)
    works end-to-end, not just the sync escape hatch.
    """
    monkeypatch.setenv("MVM_NO_VM", "1")
    monkeypatch.setenv("MVM_MVM_BIN", str(real_mvmctl))

    add = _decorate(adder_module)
    assert asyncio.run(add(2, 3)) == 5


def test_no_vm_rejects_main_module(
    real_mvmctl: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Functions whose `__module__` is `__main__` can't be located by
    the wrapper — fail clearly at the SDK boundary instead of letting
    mvmctl spawn a subprocess that imports `__main__` from a tmp dir.
    """
    monkeypatch.setenv("MVM_NO_VM", "1")
    monkeypatch.setenv("MVM_MVM_BIN", str(real_mvmctl))

    def add(a: int, b: int) -> int:  # noqa: ARG001 — never called
        return a + b

    # Force the rejection branch — pytest normally loads the test
    # module under a dotted name, so `add.__module__` is the test
    # file's path. The decorator's own __main__ check would reject
    # this, but `_no_vm_flags_for` is the layer we want to exercise:
    # patch the function's module attr post-hoc.
    add.__module__ = "__main__"
    # Construct a RemoteFunction by hand so we sidestep `mv.func`'s
    # own __main__ guard (which would catch this earlier).
    rf = mvm.RemoteFunction(add, workload_id="adder", format="json")

    with pytest.raises(mvm.NoVmIntrospectionError) as excinfo:
        rf.sync(2, 3)
    assert "__main__" in str(excinfo.value)
