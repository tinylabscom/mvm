"""Tests for the SDK-port Phase 5 additions to mvm._dsl:

- ``python_image`` / ``node_image`` convenience wrappers around
  ``nix_packages``
- ``hook`` / ``literal`` / ``secret`` value helpers
- ``app(before_build=…, before_start=…, after_start=…, before_stop=…)``
  hook kwargs

The shape mirrors the host-side static decorator parser
(``crates/mvm-sdk/src/decorator/python.rs``) so a Python file that
``import mvm; @mvm.app(...)`` runs cleanly under both the in-process
SDK (this test) and the AST-walking compiler (mvmctl compile).
"""

from __future__ import annotations

import json

import mvm
from mvm._ir import workload as _ir


def _reset():
    mvm.reset()


def test_python_image_default_python_3_12():
    img = mvm.python_image()
    assert isinstance(img, _ir.Image1)
    assert img.packages == ["python312"]


def test_python_image_strips_dot_and_appends_packages():
    img = mvm.python_image(python="3.13", packages=["curl", "git"])
    assert img.packages == ["python313", "curl", "git"]


def test_node_image_default():
    img = mvm.node_image()
    assert img.packages == ["nodejs_22"]


def test_node_image_with_packages():
    img = mvm.node_image(node="20", packages=["jq"])
    assert img.packages == ["nodejs_20", "jq"]


def test_hook_string_is_shell():
    h = mvm.hook("echo hi")
    assert isinstance(h, _ir.HookCmd1)
    assert h.kind.value == "shell"
    assert h.line == "echo hi"


def test_hook_list_is_argv():
    h = mvm.hook(["python", "-m", "migrate"])
    assert isinstance(h, _ir.HookCmd2)
    assert h.kind.value == "argv"
    assert h.argv == ["python", "-m", "migrate"]


def test_hook_rejects_bad_input():
    import pytest

    with pytest.raises(TypeError):
        mvm.hook(42)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        mvm.hook(["a", 1])  # type: ignore[list-item]


def test_literal_wraps_str_as_env_value():
    v = mvm.literal("hello")
    assert isinstance(v, _ir.EnvValue1)
    assert v.kind.value == "literal"
    assert v.value == "hello"


def test_secret_default_var_matches_name():
    s = mvm.secret("api-key")
    assert isinstance(s, _ir.EnvValue2)
    assert s.kind.value == "secret_ref"
    assert s.ref.name == "api-key"
    assert isinstance(s.ref.mount, _ir.SecretMount1)
    assert s.ref.mount.var == "api-key"


def test_secret_with_explicit_var():
    s = mvm.secret("api-key", var="API_KEY")
    assert s.ref.mount.var == "API_KEY"


def test_app_with_all_four_hook_phases_emits_merged_hooks():
    _reset()
    mvm.workload(id="hello-hooks")

    @mvm.app(
        name="hello-hooks",
        source=mvm.local_path("."),
        image=mvm.python_image(),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        entrypoint=mvm.entrypoint(command=["python", "-m", "hello"]),
        before_build="python -m migrate",
        before_start=["export", "MODEL=/m"],
        after_start=mvm.hook(["curl", "-fsS", "/h"]),
        before_stop="pkill app",
    )
    def hello():
        pass

    payload = json.loads(mvm.emit_json())
    hooks = payload["apps"][0]["hooks"]

    assert len(hooks["before_build"]) == 1
    assert hooks["before_build"][0] == {"kind": "shell", "line": "python -m migrate"}
    assert len(hooks["before_start"]) == 1
    assert hooks["before_start"][0] == {
        "kind": "argv",
        "argv": ["export", "MODEL=/m"],
    }
    assert len(hooks["after_start"]) == 1
    assert hooks["after_start"][0] == {
        "kind": "argv",
        "argv": ["curl", "-fsS", "/h"],
    }
    assert len(hooks["before_stop"]) == 1
    assert hooks["before_stop"][0] == {"kind": "shell", "line": "pkill app"}


def test_app_without_hooks_serializes_as_none():
    _reset()
    mvm.workload(id="hello-no-hooks")

    @mvm.app(
        name="hello-no-hooks",
        source=mvm.local_path("."),
        image=mvm.python_image(),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        entrypoint=mvm.entrypoint(command=["python", "-m", "hello"]),
    )
    def hello():
        pass

    payload = json.loads(mvm.emit_json())
    app = payload["apps"][0]
    # The Python emit serializes the dataclass directly (no
    # skip-serializing-on-default), so an undeclared hooks block lands
    # as JSON null. The Rust IR's `#[serde(default,
    # skip_serializing_if = "Hooks::is_empty")]` does drop it on the
    # producing side — equivalence of the two paths happens at the
    # consumer (Nix factory) which treats null and an empty struct
    # identically.
    assert app["hooks"] is None


def test_env_with_literal_and_secret_helpers():
    _reset()
    mvm.workload(id="hello-env")

    @mvm.app(
        name="hello-env",
        source=mvm.local_path("."),
        image=mvm.python_image(),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        entrypoint=mvm.entrypoint(command=["python", "-m", "hello"]),
        env={
            "MODEL_PATH": mvm.literal("/data/model.pt"),
            "API_KEY": mvm.secret("api-key"),
        },
    )
    def hello():
        pass

    payload = json.loads(mvm.emit_json())
    env = payload["apps"][0]["env"]
    assert env["MODEL_PATH"] == {"kind": "literal", "value": "/data/model.pt"}
    assert env["API_KEY"]["kind"] == "secret_ref"
    assert env["API_KEY"]["ref"]["name"] == "api-key"


def test_hook_list_of_mvm_hooks_passes_through():
    _reset()
    mvm.workload(id="hello-multi-hook")

    @mvm.app(
        name="hello-multi-hook",
        source=mvm.local_path("."),
        image=mvm.python_image(),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        entrypoint=mvm.entrypoint(command=["python", "-m", "hello"]),
        before_start=[
            mvm.hook("setup-1"),
            mvm.hook(["setup-2", "--flag"]),
        ],
    )
    def hello():
        pass

    payload = json.loads(mvm.emit_json())
    bs = payload["apps"][0]["hooks"]["before_start"]
    assert len(bs) == 2
    assert bs[0] == {"kind": "shell", "line": "setup-1"}
    assert bs[1] == {"kind": "argv", "argv": ["setup-2", "--flag"]}
