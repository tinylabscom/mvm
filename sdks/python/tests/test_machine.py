from __future__ import annotations

import os
from pathlib import Path

import pytest

import mvm
from mvm._machine import (
    _machine_check_artifact_argv,
    _machine_create_argv,
    _machine_run_argv,
)


@pytest.fixture(autouse=True)
def _isolate() -> None:
    os.environ.pop("MVM_CLI_BIN", None)
    os.environ.pop("MVM_FAKE_MVM_RECORD", None)
    os.environ.pop("MVM_FAKE_MVM_EXIT", None)
    os.environ.pop("MVM_FAKE_MVM_MACHINE_RUN_OUT", None)
    yield
    os.environ.pop("MVM_CLI_BIN", None)
    os.environ.pop("MVM_FAKE_MVM_RECORD", None)
    os.environ.pop("MVM_FAKE_MVM_EXIT", None)
    os.environ.pop("MVM_FAKE_MVM_MACHINE_RUN_OUT", None)


def _fake_mvm() -> Path:
    return Path(__file__).parent / "fixtures" / "fake-mvm"


def _records(path: Path) -> list[str]:
    return path.read_text().splitlines()


def _fixture(name: str) -> list[str]:
    return (
        Path(__file__)
        .parents[2]
        .joinpath("machine-fixtures", f"{name}.argv")
        .read_text()
        .splitlines()
    )


def test_machine_run_default_argv_matches_cli_preflight_fixture() -> None:
    assert _machine_run_argv(
        image="alpine:latest",
        command=["true"],
        json=True,
        dry_run=True,
    ) == _fixture("run-default")


def test_machine_run_allow_host_receipt_argv_matches_cli_preflight_fixture() -> None:
    assert _machine_run_argv(
        image="alpine:latest",
        command=["true"],
        allow_hosts=["api.example.com"],
        receipt="/tmp/mvm-sdk-machine.receipt.json",
        json=True,
        dry_run=True,
    ) == _fixture("run-allow-host-receipt")


def test_machine_run_admission_argv_matches_cli_parity_fixture() -> None:
    assert _machine_run_argv(
        image="alpine:latest",
        command=["sh", "-lc", "echo ok"],
        allow_hosts=["api.example.com"],
        cpus=4,
        memory="1G",
        profile="dev",
        volumes=["/tmp/mvm-sdk-src:/workspace:ro"],
        env=["TOKEN=secret", "MODE=test"],
        timeout=30,
        receipt="/tmp/mvm-sdk-machine.receipt.json",
        json=True,
        dry_run=True,
    ) == _fixture("run-admission")


def test_machine_create_manifest_argv_matches_cli_unknown_key_fixture() -> None:
    assert _machine_create_argv(
        name="web",
        manifest="mvm.toml",
        profile="dev",
        force=True,
        json=True,
    ) == _fixture("create-manifest")


def test_machine_check_artifact_argv_matches_cli_fixture() -> None:
    assert _machine_check_artifact_argv(
        path="/tmp/app.mvm",
        key="/tmp/app.pub",
        json=True,
    ) == _fixture("check-artifact")


def test_machine_run_shells_to_cli_machine_run(tmp_path: Path) -> None:
    record = tmp_path / "calls.log"
    os.environ["MVM_CLI_BIN"] = str(_fake_mvm())
    os.environ["MVM_FAKE_MVM_RECORD"] = str(record)
    os.environ["MVM_FAKE_MVM_MACHINE_RUN_OUT"] = "hello\n"

    result = mvm.Machine.run(
        image="alpine:latest",
        command=["uname", "-a"],
        net=True,
        allow_hosts=["example.com:443"],
        cpus=1,
        memory="256M",
        profile="dev",
        env=["MODE=test"],
    )

    assert result.exit_code == 0
    assert result.stdout == "hello\n"
    text = "\n".join(_records(record))
    assert "subcommand=machine" in text
    assert "verb=run" in text
    assert "--image alpine:latest" in text
    assert "--net" in text
    assert "--allow-host example.com:443" in text
    assert "-- uname -a" in text


def test_machine_check_artifact_shells_to_cli(tmp_path: Path) -> None:
    record = tmp_path / "calls.log"
    os.environ["MVM_CLI_BIN"] = str(_fake_mvm())
    os.environ["MVM_FAKE_MVM_RECORD"] = str(record)
    os.environ["MVM_FAKE_MVM_MACHINE_OUT"] = '{"runnable_here":true}\n'

    result = mvm.Machine.check_artifact(
        path="/tmp/app.mvm",
        key="/tmp/app.pub",
        json=True,
    )

    assert result.exit_code == 0
    assert result.stdout == '{"runnable_here":true}\n'
    text = "\n".join(_records(record))
    assert "subcommand=machine" in text
    assert "verb=check-artifact" in text
    assert "args=/tmp/app.mvm --key /tmp/app.pub --json" in text


def test_machine_persistent_lifecycle_shells_to_cli(tmp_path: Path) -> None:
    record = tmp_path / "calls.log"
    os.environ["MVM_CLI_BIN"] = str(_fake_mvm())
    os.environ["MVM_FAKE_MVM_RECORD"] = str(record)

    machine = mvm.Machine.create(
        name="devbox",
        manifest="mvm.toml",
        profile="dev",
        force=True,
    )
    machine.start(dry_run=True)
    machine.exec(["echo", "hi"], force=True)
    machine.shell(force=True)
    machine.stop()

    text = "\n".join(_records(record))
    assert "verb=create" in text
    assert "--name devbox --manifest mvm.toml --profile dev --force" in text
    assert "verb=start" in text
    assert "--name devbox --dry-run" in text
    assert "verb=exec" in text
    assert "--name devbox --force -- echo hi" in text
    assert "verb=shell" in text
    assert "verb=stop" in text


def test_machine_create_rejects_image_and_manifest() -> None:
    with pytest.raises(ValueError, match="image OR manifest"):
        mvm.Machine.create(name="bad", image="alpine", manifest="mvm.toml")


def test_machine_run_requires_command() -> None:
    with pytest.raises(ValueError, match="command"):
        mvm.Machine.run(image="alpine", command=[])


def test_machine_check_artifact_requires_path() -> None:
    with pytest.raises(ValueError, match="path"):
        mvm.Machine.check_artifact(path="")


def test_machine_cli_failure_is_structured(tmp_path: Path) -> None:
    record = tmp_path / "calls.log"
    os.environ["MVM_CLI_BIN"] = str(_fake_mvm())
    os.environ["MVM_FAKE_MVM_RECORD"] = str(record)
    os.environ["MVM_FAKE_MVM_EXIT"] = "17"

    with pytest.raises(mvm.MachineError) as raised:
        mvm.Machine.run(image="alpine", command=["true"])

    assert raised.value.exit_code == 17
    assert raised.value.argv[:3] == [str(_fake_mvm()), "machine", "run"]
