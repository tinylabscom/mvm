"""Checkpoint adapters use real JSON marshalling with a mocked native-call seam."""

import json
from pathlib import Path
from types import UnionType
from typing import Literal, Union, get_args, get_origin, get_type_hints, is_typeddict

import pytest

import mvm
from mvm import _hostlib, checkpoint
from mvm._errors.types import HostLibraryError, MachineBackendError


HEX = "a" * 64
DIGEST = "sha256:" + HEX
PIN = {
    "bundle_sha256": HEX,
    "manifest_sig_base64": "A" * 86 + "==",
    "key_id": "publisher",
}
ARTIFACTS = {
    "overlay_path": "/runtime/overlay",
    "overlay_verity_path": "/runtime/overlay.verity",
    "initramfs_path": "/runtime/initramfs",
    "overlay_roothash": HEX,
}
RELEASE = {
    "kind": "release",
    "proof": {
        "archive": "/runtime/archive",
        "checksum": "/runtime/checksum",
        "signature_bundle": "/runtime/signature",
        "archive_sha256": HEX,
        "version": "1.0.0",
        "arch": "aarch64",
    },
}
BINDINGS = [
    {"runtime": "cli_assembly", **ARTIFACTS, "provenance": RELEASE},
    {
        "runtime": "cli_assembly", **ARTIFACTS,
        "provenance": {
            "kind": "source", "version": "dev", "arch": "x86_64",
            "archive_sha256": HEX,
        },
    },
    {
        "runtime": "legacy_bundle", "proof": {"archive": "/bundle", "pin": PIN},
        "rootfs_path": "/rootfs", "initramfs_path": None,
    },
    {
        "runtime": "legacy_portable", **ARTIFACTS,
        "proof": {
            "archive": "/portable", "pin": PIN,
            "manifest_sha256": HEX, "arch": "x86_64",
        },
        "rootfs_path": "/rootfs", "kernel_path": "/kernel", "version": "legacy",
    },
]
GRANTS = {
    "cpu": {"unit": "share", "millicores": 1500},
    "wall_clock": {"kind": "secs", "secs": 60},
    "egress": {"allow": [{"host": "example.com", "port": 443}]},
    "drive": {
        "workspace_roots": ["/workspace"], "program_id": "editor",
        "max_bytes_in": 1024, "max_bytes_out": 2048, "ttl": 30,
    },
    "display_input": {
        "attended": True, "clipboard": {"max_paste_bytes": 1024},
        "human_credential": {"destinations": [{"host": "example.com", "port": 443}]},
    },
    "application_terminal": {"argv": ["/usr/bin/application", "--interactive"]},
}


def minimal_record(identifier="cp-0"):
    return {
        "id": identifier, "class": "fs_quick", "vm_name": "vm",
        "tag": None, "parent": None, "created_unix": 1,
        "content": [{"name": "rootfs", "sha256": HEX}],
        "supervisor_config_digest": HEX, "meta_digest": DIGEST, "audit_ref": None,
    }


def complete_reply():
    records = [minimal_record()]
    for identifier, binding in zip(("cp-1", "cp-10", "cp-2", "cp-3"), BINDINGS):
        records.append({
            **minimal_record(identifier),
            "class": "vm_full", "tag": "saved", "parent": DIGEST,
            "key_domain": "tenant:tenant-a", "protection": "sealed_v1",
            "runtime_overlay_version": "1.0.0", "runtime_launch_binding": binding,
            "snapshot_id": DIGEST, "grants": GRANTS,
            "session": {
                "session_id": "session-1", "generation": 2, "journal_cursor": 3,
                "approval_head": DIGEST, "replay_input_digest": DIGEST,
            },
            "machine_input_cursor": 0, "audit_ref": "audit-entry-1",
        })
    records[2]["grants"] = {
        "cpu": {"unit": "fuel", "instructions": 42},
        "wall_clock": {"kind": "unbounded"},
        "egress": {"allow": []}, "display_input": {},
    }
    records[3]["session"] = {
        "session_id": "session-2", "generation": 0, "journal_cursor": 0,
        "approval_head": DIGEST,
    }
    records[4]["grants"] = {}
    return records


def shared_reply():
    root = Path(__file__).resolve().parents[5]
    return json.loads(
        (root / "crates/mvm-core/tests/fixtures/checkpoint-list.json").read_text()
    )


@pytest.mark.parametrize("reply", [[], complete_reply(), shared_reply()])
def test_list_marshalling_and_complete_reply(hostlib, monkeypatch, reply):
    hostlib.reply("checkpoint.list", reply)
    invoke = _hostlib._invoke
    raw = []

    def record(method, body):
        raw.append(body)
        return invoke(method, body)

    monkeypatch.setattr(_hostlib, "_invoke", record)
    actual = mvm.checkpoint.list()
    assert actual == reply
    assert [row["id"] for row in actual] == sorted(row["id"] for row in reply)
    assert hostlib.calls == [("checkpoint.list", {})]
    assert raw == [b"{}"]


def test_public_export_and_no_arguments(hostlib):
    assert mvm.checkpoint is checkpoint
    assert "checkpoint" in mvm.__all__
    with pytest.raises(TypeError):
        checkpoint.list({"filter": "vm"})
    assert hostlib.calls == []


def test_backend_error_passthrough(hostlib):
    hostlib.fail("checkpoint.list", "BACKEND_ERROR", "invalid checkpoint metadata")
    with pytest.raises(MachineBackendError) as caught:
        checkpoint.list()
    assert isinstance(caught.value, HostLibraryError)
    assert str(caught.value) == "invalid checkpoint metadata"
    assert caught.value.code == "BACKEND_ERROR"
    assert caught.value.retryable is False
    assert hostlib.calls == [("checkpoint.list", {})]


def _choice(shapes):
    variants = sorted(set(shapes), key=repr)
    return variants[0] if len(variants) == 1 else ("union", tuple(variants))


def _annotation_shape(annotation):
    """Only wire field/type contracts; no runtime schema validator or decoder."""
    if is_typeddict(annotation):
        return ("object", tuple(sorted(
            (name, name in annotation.__required_keys__, _annotation_shape(value))
            for name, value in get_type_hints(annotation).items()
        )))
    origin = get_origin(annotation)
    if origin is list:
        return ("array", _annotation_shape(get_args(annotation)[0]))
    if origin in (Union, UnionType):
        return _choice(_annotation_shape(value) for value in get_args(annotation))
    if origin is Literal:
        return _choice(("literal", value) for value in get_args(annotation))
    return ({str: "string", int: "integer", bool: "boolean", type(None): "null"}[annotation],)


def _schema_shape(schema, document):
    """Compare the full closure, ignoring prose and numeric/string constraints."""
    if "$ref" in schema:
        target = document
        assert schema["$ref"].startswith("#/")
        for part in schema["$ref"][2:].split("/"):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        return _schema_shape(target, document)
    if "allOf" in schema:
        assert len(schema["allOf"]) == 1, "unexpected intersection in wire schema"
        return _schema_shape(schema["allOf"][0], document)
    for keyword in ("anyOf", "oneOf"):
        if keyword in schema:
            return _choice(_schema_shape(part, document) for part in schema[keyword])
    if "const" in schema:
        return ("literal", schema["const"])
    if "enum" in schema:
        return _choice(("literal", value) for value in schema["enum"])
    kind = schema["type"]
    if isinstance(kind, list):
        return _choice(_schema_shape({**schema, "type": item}, document) for item in kind)
    if kind == "array":
        return ("array", _schema_shape(schema["items"], document))
    if kind == "object":
        assert "properties" in schema, "opaque object in checkpoint reply"
        return ("object", tuple(sorted(
            (name, name in schema.get("required", []), _schema_shape(value, document))
            for name, value in schema["properties"].items()
        )))
    assert kind in ("string", "integer", "boolean", "null")
    return (kind,)


def test_public_wire_types_match_generated_canonical_schema():
    root = Path(__file__).resolve().parents[5]
    document = json.loads((root / "schema/host-abi-v0.json").read_text())
    reply_schema = document["definitions"]["CheckpointListReply"]
    assert _annotation_shape(checkpoint.CheckpointListReply) == _schema_shape(
        reply_schema, document
    )


def test_required_nullable_is_distinct_from_optional_omitted():
    fields = get_type_hints(checkpoint.CheckpointMeta)
    for name in ("tag", "parent", "audit_ref"):
        assert name in checkpoint.CheckpointMeta.__required_keys__
        assert type(None) in get_args(fields[name])
    for name in checkpoint.CheckpointMeta.__optional_keys__:
        assert type(None) not in get_args(fields[name])
    assert "initramfs_path" in checkpoint.LegacyBundleLaunchBinding.__required_keys__
    assert type(None) in get_args(
        get_type_hints(checkpoint.LegacyBundleLaunchBinding)["initramfs_path"]
    )
