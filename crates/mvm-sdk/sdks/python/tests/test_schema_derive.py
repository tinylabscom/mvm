"""Tests for `mvm.derive_schema` (plan-0009 v2)."""

from __future__ import annotations

import pytest

import mvm


def test_derive_schema_from_simple_signature() -> None:
    def add(a: int, b: int) -> int:
        return a + b

    schema = mvm.derive_schema(add)
    assert schema["type"] == "object"
    assert schema["properties"]["a"]["type"] == "integer"
    assert schema["properties"]["b"]["type"] == "integer"
    assert sorted(schema["required"]) == ["a", "b"]
    assert schema["additionalProperties"] is False


def test_derive_schema_with_default_makes_param_optional() -> None:
    def greet(name: str, greeting: str = "hello") -> str:
        return f"{greeting} {name}"

    schema = mvm.derive_schema(greet)
    assert schema["required"] == ["name"]


def test_derive_schema_handles_list_type() -> None:
    def total(xs: list[int]) -> int:
        return sum(xs)

    schema = mvm.derive_schema(total)
    assert schema["properties"]["xs"]["type"] == "array"
    assert schema["properties"]["xs"]["items"]["type"] == "integer"


def test_derive_schema_return_only() -> None:
    def add(a: int, b: int) -> list[int]:
        return [a, b]

    schema = mvm.derive_schema(add, return_only=True)
    assert schema["type"] == "array"
    assert schema["items"]["type"] == "integer"


def test_derive_schema_rejects_var_args() -> None:
    def variadic(*args: int) -> int:
        return sum(args)

    with pytest.raises(TypeError, match="\\*args / \\*\\*kwargs"):
        mvm.derive_schema(variadic)


def test_derive_schema_rejects_unannotated_param() -> None:
    def bad(a, b: int) -> int:
        return b

    with pytest.raises(TypeError, match="no type annotation"):
        mvm.derive_schema(bad)


def test_derive_schema_return_only_requires_return_annotation() -> None:
    def no_ret(a: int):
        return a

    with pytest.raises(TypeError, match="no return annotation"):
        mvm.derive_schema(no_ret, return_only=True)


def test_derive_schema_round_trips_into_entrypoint_function(monkeypatch) -> None:
    """The derived schema is a valid `args_schema=` value."""
    def add(a: int, b: int) -> int:
        return a + b

    schema = mvm.derive_schema(add)
    mvm.reset()
    mvm.workload(id="adder")

    @mvm.app(
        name="adder",
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        entrypoint=mvm.entrypoint_function(
            language="python",
            module="adder",
            function="add",
            args_schema=schema,
            return_schema=mvm.derive_schema(add, return_only=True),
        ),
        resources=mvm.resources(cpu_cores=1, memory_mb=128, rootfs_size_mb=256),
        dependencies=mvm.no_deps(),
    )
    def add_workload(a: int, b: int) -> int:
        return a + b

    ir = mvm.emit_json()
    assert '"args_schema":{' in ir
    assert '"return_schema":{' in ir
    mvm.reset()
