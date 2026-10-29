"""The Python PackSpec builder against the contract's shared fixtures.

Each fixture under ``crates/mvm-contract/tests/fixtures/pack-spec-v1`` is the
authored document the Rust contract accepts. Rebuilding it through the fluent
API must produce exactly the bytes the Rust canonical writer emits for it, so
the lock digest is the same whichever language wrote the spec.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mvm.packs import Pack, PackSpecError, canonical_json, pack

FIXTURES = Path(__file__).resolve().parents[4] / "mvm-contract/tests/fixtures/pack-spec-v1"


def test_pack_authoring_is_exported_on_the_public_sdk_surface() -> None:
    import mvm

    assert "packs" in mvm.__all__
    assert mvm.packs.pack is pack
    assert mvm.packs.Pack is Pack
    assert isinstance(mvm.packs.pack("acme/hello", "1.0.0"), Pack)


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _from_document(doc: dict) -> Pack:
    built = pack(doc["identity"]["name"], doc["identity"]["version"])
    built.target(doc["target"]).source(doc["source"]["path"])
    for p in doc["packages"]:
        built.package(p["name"], p.get("version"), scope=p["scope"])
    for d in doc["dependencies"]:
        add = built.dependencies if d["kind"] == "python" else built.node_dependencies
        add(d["tool"], d["manifest"], d["lockfile"])
    for c in doc["copy"]:
        built.copy(c["source"], c["destination"])
    built.entrypoint(*doc["entrypoint"])
    built.resources(
        cpu_cores=doc["resources"]["cpu_cores"], memory_mib=doc["resources"]["memory_mb"]
    )
    return built


@pytest.mark.parametrize("name", ["minimal", "python", "claude-style"])
def test_every_fixture_rebuilds_to_its_canonical_bytes(name: str) -> None:
    doc = _fixture(name)
    built = _from_document(doc)
    assert built.to_json() == canonical_json(doc)
    golden = FIXTURES / "canonical" / f"{name}.json"
    if golden.exists():
        assert built.to_json() == golden.read_bytes()
        digest = (FIXTURES / "canonical" / f"{name}.sha256").read_text().strip()
        assert built.sha256() == digest


def test_the_minimal_example_reads_the_way_the_docs_show() -> None:
    spec = (
        pack("acme/hello", "1.0.0")
        .target("aarch64-linux")
        .source(".")
        .package("busybox")
        .copy("hello.txt", "/app/hello.txt")
        .entrypoint("cat", "/app/hello.txt")
        .resources(cpu_cores=1, memory_mib=128)
    )
    assert spec.to_json() == canonical_json(_fixture("minimal"))


def test_canonical_bytes_are_compact_sorted_and_keep_list_order() -> None:
    text = _from_document(_fixture("python")).to_json().decode()
    assert not text.endswith("\n")
    assert ", " not in text and ": " not in text
    assert text.startswith('{"copy":')
    assert '["python3","/app/main.py","one argument",""]' in text
    # An absent package version is omitted, never written as null.
    assert '{"name":"pkg-config","scope":"build"}' in text


def test_write_returns_the_digest_of_what_it_wrote(tmp_path: Path) -> None:
    spec = _from_document(_fixture("minimal"))
    out = tmp_path / "pack.json"
    digest = spec.write(out)
    assert digest == hashlib.sha256(out.read_bytes()).hexdigest() == spec.sha256()


def _valid() -> Pack:
    return _from_document(_fixture("minimal"))


@pytest.mark.parametrize("field", ["target", "source", "entrypoint", "resources"])
def test_a_missing_field_names_itself(field: str) -> None:
    built = pack("acme/hello", "1.0.0")
    for name in ("target", "source", "entrypoint", "resources"):
        if name == field:
            continue
        if name == "target":
            built.target("aarch64-linux")
        elif name == "source":
            built.source(".")
        elif name == "entrypoint":
            built.entrypoint("true")
        else:
            built.resources(cpu_cores=1, memory_mib=1)
    with pytest.raises(PackSpecError) as err:
        built.to_json()
    assert err.value.code == "missing"
    assert err.value.field == field


@pytest.mark.parametrize(
    "name,version",
    [
        ("hello", "1.0.0"),
        ("acme/hello/extra", "1.0.0"),
        ("Acme/hello", "1.0.0"),
        ("acme/../x", "1.0.0"),
        ("acme/hello", "1.0"),
        ("acme/hello", "01.0.0"),
        ("acme/hello", "1.0.0-01"),
        ("acme/hello", "1.0.0\n"),
    ],
)
def test_bad_identities_share_the_identity_code(name: str, version: str) -> None:
    built = _valid()
    built._name, built._version = name, version
    with pytest.raises(PackSpecError) as err:
        built.to_json()
    assert err.value.code == "identity"


def test_semver_build_metadata_and_prerelease_survive() -> None:
    doc = _fixture("claude-style")
    assert _from_document(doc).to_dict()["identity"]["version"] == "1.2.3-rc.1+build.7"


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda p: p.source("../up"), "path"),
        (lambda p: p.source("/abs"), "path"),
        (lambda p: p.source("a//b"), "path"),
        (lambda p: p.source("a\\b"), "path"),
        (lambda p: p.source("c:x"), "path"),
        (lambda p: p.copy("a", "/"), "path"),
        (lambda p: p.copy("a", "relative"), "path"),
        (lambda p: p.copy("a", "/app/../etc"), "path"),
        (lambda p: p.dependencies("uv", ".", "uv.lock"), "path"),
        (lambda p: p.dependencies("poetry", "pyproject.toml", "poetry.lock"), "dependency"),
        (lambda p: p.node_dependencies("bun", "package.json", "bun.lockb"), "dependency"),
        (lambda p: p.package("bad name"), "package"),
        (lambda p: p.package("ok", "1 0"), "package"),
        (lambda p: p.package("ok", scope="sometimes"), "package"),
        (lambda p: p.entrypoint(" "), "entrypoint"),
        (lambda p: p.entrypoint("sh", "a\0b"), "entrypoint"),
        (lambda p: p.resources(cpu_cores=0, memory_mib=1), "resources"),
        (lambda p: p.resources(cpu_cores=1, memory_mib=4294967296), "resources"),
        (lambda p: p.resources(cpu_cores=True, memory_mib=1), "resources"),
        (lambda p: p.target("riscv64-linux"), "target"),
    ],
)
def test_invalid_input_fails_with_the_shared_code(mutate, code: str) -> None:
    built = _valid()
    mutate(built)
    with pytest.raises(PackSpecError) as err:
        built.to_json()
    assert err.value.code == code


def test_empty_later_arguments_are_kept() -> None:
    built = _valid().entrypoint("echo", "", "x")
    assert built.to_dict()["entrypoint"] == ["echo", "", "x"]


def test_the_builder_reads_no_file_and_runs_nothing(tmp_path: Path, monkeypatch) -> None:
    # A spec naming a source tree that does not exist still serializes: the
    # builder describes intent, and only the shared Rust path touches files.
    monkeypatch.chdir(tmp_path)
    built = _valid().source("does-not-exist")
    assert json.loads(built.to_json())["source"] == {"kind": "local", "path": "does-not-exist"}


def test_node_dependencies_keep_their_place_among_python_ones() -> None:
    built = (
        _valid()
        .dependencies("uv", "pyproject.toml", "uv.lock")
        .node_dependencies("npm", "package.json", "package-lock.json")
    )
    assert built.to_dict()["dependencies"] == [
        {"kind": "python", "tool": "uv", "manifest": "pyproject.toml", "lockfile": "uv.lock"},
        {"kind": "node", "tool": "npm", "manifest": "package.json", "lockfile": "package-lock.json"},
    ]
