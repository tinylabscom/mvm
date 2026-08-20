"""Tests for the Sandbox record-mode SDK. SDK port Phase 7b."""

from __future__ import annotations

import base64
import json
import os

import pytest

import mvm


@pytest.fixture(autouse=True)
def _isolate() -> None:
    """Each test starts with a clean recording + record mode."""
    path = os.environ.get("PATH")
    mvm.reset_recording()
    os.environ.pop("MVM_CLI_BIN", None)
    os.environ.pop("MVM_SDK_MODE", None)
    yield
    mvm.reset_recording()
    os.environ.pop("MVM_CLI_BIN", None)
    os.environ.pop("MVM_SDK_MODE", None)
    if path is None:
        os.environ.pop("PATH", None)
    else:
        os.environ["PATH"] = path


# ── basic recording shape ────────────────────────────────────────────


def test_create_records_the_template_and_default_ttl() -> None:
    mvm.Sandbox.create("python-3.12")
    rec = mvm.current_recording()
    assert rec is not None
    assert rec["create"]["template"] == "python-3.12"
    assert rec["create"]["ttl_seconds"] == mvm.DEFAULT_TTL_SECONDS
    assert rec["ops"] == []


def test_create_records_pinned_image_and_explicit_command() -> None:
    mvm.Sandbox.create(
        image="docker.io/example/browser@sha256:" + "a" * 64,
        command=["/browser", "serve"],
    )
    rec = mvm.current_recording()
    assert rec is not None
    assert "template" not in rec["create"]
    assert rec["create"]["image"].endswith("a" * 64)
    assert rec["ops"] == [
        {"kind": "command_start", "argv": ["/browser", "serve"], "env": {}}
    ]


def test_workload_id_defaults_to_template() -> None:
    sb = mvm.Sandbox.create("python-3.12")
    assert sb.workload_id == "python-3.12"


def test_workload_id_override() -> None:
    sb = mvm.Sandbox.create("python-3.12", workload_id="etl-job")
    assert sb.workload_id == "etl-job"
    assert mvm.current_recording()["workload_id"] == "etl-job"


def test_create_rejects_empty_template() -> None:
    with pytest.raises(ValueError):
        mvm.Sandbox.create("")


def test_only_one_sandbox_per_script() -> None:
    mvm.Sandbox.create("python-3.12")
    with pytest.raises(RuntimeError, match="already active"):
        mvm.Sandbox.create("node-22")


# ── commands.start ──────────────────────────────────────────────────


def test_commands_start_appends_op() -> None:
    sb = mvm.Sandbox.create("python-3.12")
    sb.commands.start(["python", "run.py"])
    ops = mvm.current_recording()["ops"]
    assert ops == [
        {"kind": "command_start", "argv": ["python", "run.py"], "env": {}}
    ]


def test_commands_start_carries_env() -> None:
    sb = mvm.Sandbox.create("python-3.12")
    sb.commands.start(
        ["python", "run.py"],
        env={
            "MODE": "prod",
            "API_KEY": mvm.secret("api-key", type="bearer", hosts=["api.example.com"]),
        },
    )
    ops = mvm.current_recording()["ops"]
    env = ops[0]["env"]
    assert env["MODE"] == {"kind": "literal", "value": "prod"}
    assert env["API_KEY"]["kind"] == "secret_ref"
    assert env["API_KEY"]["ref"]["name"] == "api-key"


def test_commands_start_rejects_non_list_argv() -> None:
    sb = mvm.Sandbox.create("python-3.12")
    with pytest.raises(TypeError):
        sb.commands.start("python run.py")  # type: ignore[arg-type]


def test_commands_start_rejects_empty_argv() -> None:
    sb = mvm.Sandbox.create("python-3.12")
    with pytest.raises(ValueError):
        sb.commands.start([])


# ── files.write ────────────────────────────────────────────────────


def test_files_write_encodes_bytes_to_base64() -> None:
    sb = mvm.Sandbox.create("python-3.12")
    sb.files.write("/app/config.json", b'{"x":1}')
    op = mvm.current_recording()["ops"][0]
    assert op["kind"] == "files_write"
    assert op["path"] == "/app/config.json"
    assert base64.standard_b64decode(op["bytes_b64"]) == b'{"x":1}'


def test_files_write_accepts_str_content_as_utf8() -> None:
    sb = mvm.Sandbox.create("python-3.12")
    sb.files.write("/app/note.txt", "héllo")
    op = mvm.current_recording()["ops"][0]
    assert base64.standard_b64decode(op["bytes_b64"]) == "héllo".encode("utf-8")


def test_files_write_rejects_non_bytes_non_str() -> None:
    sb = mvm.Sandbox.create("python-3.12")
    with pytest.raises(TypeError):
        sb.files.write("/app/x", 123)  # type: ignore[arg-type]


def test_files_write_rejects_empty_path() -> None:
    sb = mvm.Sandbox.create("python-3.12")
    with pytest.raises(ValueError):
        sb.files.write("", b"x")


# ── kill / context manager ───────────────────────────────────────────


def test_kill_appends_kill_op() -> None:
    sb = mvm.Sandbox.create("python-3.12")
    sb.kill()
    assert mvm.current_recording()["ops"] == [{"kind": "kill"}]


def test_context_manager_records_kill_on_exit() -> None:
    with mvm.Sandbox.create("python-3.12") as sb:
        sb.commands.start(["python", "run.py"])
    ops = mvm.current_recording()["ops"]
    assert ops[-1] == {"kind": "kill"}


# ── modes ────────────────────────────────────────────────────────────


def test_live_mode_requires_host_cli() -> None:
    """MVM_SDK_MODE=live without the host CLI must fail with an
    actionable hint."""
    os.environ["MVM_SDK_MODE"] = "live"
    os.environ.pop("MVM_CLI_BIN", None)
    os.environ["PATH"] = ""
    with pytest.raises(mvm.SandboxModeError, match="mvmctl"):
        mvm.Sandbox.create("python-3.12")


def test_plan_mode_redirects_to_host_cli() -> None:
    """Plan mode lives in the host CLI; the SDK should refuse with
    a redirect message."""
    os.environ["MVM_SDK_MODE"] = "plan"
    with pytest.raises(mvm.SandboxModeError, match="mvmctl run --mode plan"):
        mvm.Sandbox.create("python-3.12")


def test_invalid_mode_raises_with_actionable_message() -> None:
    os.environ["MVM_SDK_MODE"] = "garbage"
    with pytest.raises(mvm.SandboxModeError, match="invalid"):
        mvm.Sandbox.create("python-3.12")


# ── TTL parsing ──────────────────────────────────────────────────────


def test_ttl_accepts_seconds_int() -> None:
    mvm.Sandbox.create("python-3.12", ttl=120)
    assert mvm.current_recording()["create"]["ttl_seconds"] == 120


def test_ttl_accepts_30m() -> None:
    mvm.Sandbox.create("python-3.12", ttl="30m")
    assert mvm.current_recording()["create"]["ttl_seconds"] == 1800


def test_ttl_accepts_1h() -> None:
    mvm.Sandbox.create("python-3.12", ttl="1h")
    assert mvm.current_recording()["create"]["ttl_seconds"] == 3600


def test_ttl_accepts_bare_integer_string() -> None:
    mvm.Sandbox.create("python-3.12", ttl="3600")
    assert mvm.current_recording()["create"]["ttl_seconds"] == 3600


def test_ttl_rejects_unparseable() -> None:
    with pytest.raises(ValueError, match="unrecognized"):
        mvm.Sandbox.create("python-3.12", ttl="forever")


def test_ttl_rejects_zero_seconds() -> None:
    with pytest.raises(ValueError, match="ttl must be"):
        mvm.Sandbox.create("python-3.12", ttl=0)


# ── resources / network flow-through ────────────────────────────────


def test_create_resources_flow_through() -> None:
    mvm.Sandbox.create(
        "python-3.12",
        resources=mvm.resources(cpu_cores=2, memory_mb=512, rootfs_size_mb=1024),
    )
    rsr = mvm.current_recording()["create"]["resources"]
    assert rsr["cpu_cores"] == 2
    assert rsr["memory_mb"] == 512
    assert rsr["rootfs_size_mb"] == 1024


def test_create_includes_flow_through() -> None:
    mvm.Sandbox.create("python-3.12", include=["src", "lib"])
    assert mvm.current_recording()["create"]["include"] == ["src", "lib"]


# ── emit + reset ─────────────────────────────────────────────────────


def test_emit_recording_json_is_wire_compatible() -> None:
    sb = mvm.Sandbox.create("python-3.12", include=["src"])
    sb.commands.start(["python", "run.py"], env={"X": "1"})
    sb.files.write("/app/cfg", b"data")
    raw = mvm.emit_recording_json()
    parsed = json.loads(raw)
    # Wire-shape fields the Rust serde deny_unknown_fields enforces:
    assert set(parsed) == {"workload_id", "create", "ops"}
    assert set(parsed["create"]) >= {"template", "env", "include", "tags", "ttl_seconds"}
    assert [op["kind"] for op in parsed["ops"]] == ["command_start", "files_write"]


def test_emit_recording_json_raises_when_inactive() -> None:
    with pytest.raises(mvm.RecordingNotActiveError):
        mvm.emit_recording_json()


def test_reset_recording_clears_state() -> None:
    mvm.Sandbox.create("python-3.12")
    assert mvm.current_recording() is not None
    mvm.reset_recording()
    assert mvm.current_recording() is None


# ── Phase 7e — MVM_SDK_OUT_PATH atexit flusher ──────────────────────


def test_flush_recording_writes_to_out_path(tmp_path) -> None:
    from mvm._sandbox import _flush_recording_to_out_path

    out = tmp_path / "rec.json"
    os.environ["MVM_SDK_OUT_PATH"] = str(out)
    try:
        sb = mvm.Sandbox.create("python-3.12")
        sb.commands.start(["python", "run.py"])
        _flush_recording_to_out_path()
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert parsed["workload_id"] == "python-3.12"
        assert parsed["ops"][0]["kind"] == "command_start"
    finally:
        os.environ.pop("MVM_SDK_OUT_PATH", None)


def test_flush_recording_noop_when_out_path_unset(tmp_path) -> None:
    from mvm._sandbox import _flush_recording_to_out_path

    out = tmp_path / "rec.json"
    # Don't set MVM_SDK_OUT_PATH — the flush should be a no-op.
    mvm.Sandbox.create("python-3.12")
    _flush_recording_to_out_path()
    assert not out.exists()


def test_flush_recording_noop_when_no_sandbox_created(tmp_path) -> None:
    from mvm._sandbox import _flush_recording_to_out_path

    out = tmp_path / "rec.json"
    os.environ["MVM_SDK_OUT_PATH"] = str(out)
    try:
        # No Sandbox.create — file existence is the CLI's signal
        # that the script genuinely produced a recording, so a
        # missing file is the correct behavior.
        _flush_recording_to_out_path()
        assert not out.exists()
    finally:
        os.environ.pop("MVM_SDK_OUT_PATH", None)
