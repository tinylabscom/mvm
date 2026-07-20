"""Tests for ``mvm.func`` — the workload + app + function-entrypoint
shortcut decorator (plan-0010 phase A). Mirrors the TypeScript SDK's
``mv.func({...}, fn)`` shape per ADR-0010 §1's unified-pipeline goal.
"""

from __future__ import annotations

import json
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


def _adder_module_name() -> str:
    """Modules in pytest fixtures resolve to their dotted path; capture
    it so tests don't hard-code the test runner's module-naming policy."""
    return __name__


def test_func_registers_workload_app_and_entrypoint() -> None:
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
    )
    def add(a: int, b: int) -> int:
        return a + b

    payload = json.loads(mvm.emit_json())
    assert payload["id"] == "adder"
    assert len(payload["apps"]) == 1
    app = payload["apps"][0]
    assert app["name"] == "adder"
    ep = app["entrypoints"][0]
    assert ep["kind"] == "function"
    assert ep["language"] == "python"
    assert ep["function"] == "add"
    assert ep["module"] == _adder_module_name()
    assert app["dependencies"] == {"kind": "none"}


def test_func_returns_remote_function() -> None:
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
    )
    def add(a: int, b: int) -> int:
        return a + b

    assert isinstance(add, mvm.RemoteFunction)
    # Per W5, calling the function returns a coroutine for remote
    # dispatch — the local body is reached via .local.
    assert add.local(2, 3) == 5
    assert add.local(4, 5) == 9
    assert add.workload_id == "adder"
    coro = add(2, 3)
    assert hasattr(coro, "__await__")
    coro.close()  # don't actually dispatch in this unit test


def test_func_explicit_module_overrides_inference() -> None:
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
        module="custom.module",
        function="explicit_name",
    )
    def add(a: int, b: int) -> int:
        return a + b

    payload = json.loads(mvm.emit_json())
    ep = payload["apps"][0]["entrypoints"][0]
    assert ep["module"] == "custom.module"
    assert ep["function"] == "explicit_name"


def test_func_rejects_main_module_inference() -> None:
    # Simulate a function defined under __main__ — running
    # `python entry.py` would set __module__ to "__main__", which would
    # otherwise drift the IR depending on invocation style. Per
    # plan-0010 phase A, the SDK requires `module=` explicitly in this
    # case.
    def add(a: int, b: int) -> int:
        return a + b

    add.__module__ = "__main__"  # type: ignore[attr-defined]

    decorator = mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
    )
    with pytest.raises(ValueError, match="module"):
        decorator(add)


def test_func_default_dependencies_is_no_deps() -> None:
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
    )
    def add(a: int, b: int) -> int:
        return a + b

    payload = json.loads(mvm.emit_json())
    assert payload["apps"][0]["dependencies"] == {"kind": "none"}


def test_func_explicit_dependencies_passes_through() -> None:
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
        dependencies=mvm.python_deps(lockfile="uv.lock", tool="uv"),
    )
    def add(a: int, b: int) -> int:
        return a + b

    payload = json.loads(mvm.emit_json())
    deps = payload["apps"][0]["dependencies"]
    assert deps["kind"] == "python"
    assert deps["lockfile"] == "uv.lock"
    assert deps["tool"] == "uv"


def test_func_default_source_is_dot() -> None:
    # The SDK records local_path("."); the host resolves it relative to
    # manifest_dir at compile time (NOT cwd). Avoids the "ran from $HOME
    # → bundled $HOME" foot-gun.
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
    )
    def add(a: int, b: int) -> int:
        return a + b

    payload = json.loads(mvm.emit_json())
    src = payload["apps"][0]["source"]
    assert src["kind"] == "local_path"
    assert src["path"] == "."


def test_func_language_default_is_python() -> None:
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
    )
    def add(a: int, b: int) -> int:
        return a + b

    payload = json.loads(mvm.emit_json())
    assert payload["apps"][0]["entrypoints"][0]["language"] == "python"


def test_func_language_can_be_overridden() -> None:
    # Cross-language manifest authoring: Python SDK declaring a Node
    # workload. The host validator gates this against
    # SUPPORTED_LANGUAGES; "node" is allowed.
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["nodejs_22"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
        language="node",
        module="adder",
    )
    def add(a: int, b: int) -> int:
        return a + b

    payload = json.loads(mvm.emit_json())
    assert payload["apps"][0]["entrypoints"][0]["language"] == "node"


def test_func_format_msgpack_round_trips() -> None:
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
        format="msgpack",
    )
    def add(a: int, b: int) -> int:
        return a + b

    assert add.format == "msgpack"
    payload = json.loads(mvm.emit_json())
    assert payload["apps"][0]["entrypoints"][0]["format"] == "msgpack"


def test_func_anonymous_function_requires_explicit_name() -> None:
    decorator = mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
    )
    fn = lambda a, b: a + b  # noqa: E731
    fn.__name__ = ""  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="function"):
        decorator(fn)


def test_func_with_args_and_return_schemas() -> None:
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(
            cpu_cores=1, memory_mb=256, rootfs_size_mb=512
        ),
        args_schema={
            "type": "object",
            "properties": {
                "a": {"type": "integer"},
                "b": {"type": "integer"},
            },
            "required": ["a", "b"],
        },
        return_schema={"type": "integer"},
    )
    def add(a: int, b: int) -> int:
        return a + b

    payload = json.loads(mvm.emit_json())
    ep = payload["apps"][0]["entrypoints"][0]
    assert ep["args_schema"]["type"] == "object"
    assert ep["return_schema"]["type"] == "integer"


def test_func_threads_warm_process_concurrency_into_emit() -> None:
    @mvm.func(
        name="adder",
        image=mvm.nix_packages(["python312"]),
        resources=mvm.resources(cpu_cores=1, memory_mb=512, rootfs_size_mb=1024),
        concurrency=mvm.warm_process(
            max_calls_per_worker=1000,
            max_rss_mb=256,
            pool_size=1,
        ),
    )
    def add(a: int, b: int) -> int:
        return a + b

    ep = json.loads(mvm.emit_json())["apps"][0]["entrypoints"][0]
    # `_to_plain` walks all dataclass fields, so unset Optional becomes
    # null in the JSON output (Rust then skip-serializes after re-
    # canonicalization on the host side). Pin the value rather than
    # absence so this stays robust to either emit convention.
    assert ep["concurrency"] == {
        "kind": "warm_process",
        "max_calls_per_worker": 1000,
        "max_rss_mb": 256,
        "pool_size": 1,
        "in_process": "serial",
        "max_queue_depth": None,
    }


def test_func_omits_concurrency_when_unset() -> None:
    @mvm.func(name="adder", module="adder", function="add")
    def add(a: int, b: int) -> int:
        return a + b

    ep = json.loads(mvm.emit_json())["apps"][0]["entrypoints"][0]
    # Pre-existing convention: optional IR fields emit as null when
    # unset (Rust's skip_serializing_if applies post-canonicalization
    # on the host). Either way, the IR validator accepts both forms.
    assert ep.get("concurrency") is None


def test_warm_process_helper_rejects_invalid_in_process() -> None:
    with pytest.raises(ValueError, match="in_process"):
        mvm.warm_process(
            max_calls_per_worker=1000, max_rss_mb=256, in_process="bogus"
        )


def test_warm_process_with_max_queue_depth_emits_field() -> None:
    @mvm.func(
        name="adder",
        resources=mvm.resources(cpu_cores=1, memory_mb=512, rootfs_size_mb=1024),
        concurrency=mvm.warm_process(
            max_calls_per_worker=5000,
            max_rss_mb=256,
            pool_size=2,
            max_queue_depth=32,
        ),
    )
    def add(a: int, b: int) -> int:
        return a + b

    ep = json.loads(mvm.emit_json())["apps"][0]["entrypoints"][0]
    assert ep["concurrency"]["max_queue_depth"] == 32
    assert ep["concurrency"]["pool_size"] == 2
