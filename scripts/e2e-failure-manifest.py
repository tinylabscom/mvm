#!/usr/bin/env python3
"""Create this invocation's payload-free manifest before bootstrap.

The existing parent directory must be trusted. Exit 2 refuses an existing
destination; exit 3 reports I/O loss. Neither outcome authorizes upload.
"""

import json
import os
import stat
import sys


MAX_MANIFEST_BYTES = 262144
MAX_COMMANDS = 128
MAX_RECORDS = 16
MAX_RECORD_BYTES = 512
PHASES = {"transient_boot", "transient_command", "builder_job", "hvf_readiness"}
CATEGORIES = {"unknown", "internal", "invalid_request", "unsupported", "version",
              "fetch", "nix_build", "nix_eval", "timeout", "output_contract"}
STAGES = {"absent", "unknown", "sign_check", "signing_lock", "signing", "reexec",
          "config_read", "config_parse", "status_publish", "startup_inputs",
          "capture_policy", "capture_setup", "pid_publish", "pid_published"}
STATES = {"not_started", "in_progress", "complete", "loss", "unreadable"}
STATUSES = {"absent", "collected", "unreadable"}


def require(condition):
    if not condition:
        raise ValueError()


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def integer(value, minimum=0, maximum=4294967295):
    require(type(value) is int and minimum <= value <= maximum)


def enum(value, choices):
    require(type(value) is str and value in choices)


def exit_code(value):
    if value is not None:
        integer(value, -2147483648, 2147483647)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def validate(value):
    """Closed source schema; never copy unrecognized fields or free-form text."""
    fields(value, "schema_version state scenario command dropped_commands commands")
    integer(value["schema_version"], 1, 1)
    enum(value["state"], STATES)
    for name in ("scenario", "command", "dropped_commands"):
        integer(value[name])
    require(type(value["commands"]) is list and len(value["commands"]) <= MAX_COMMANDS)
    for command in value["commands"]:
        fields(command, "scenario command success exit_code observation")
        integer(command["scenario"])
        integer(command["command"])
        require(command["success"] is None or type(command["success"]) is bool)
        exit_code(command["exit_code"])
        observation = command["observation"]
        fields(observation, "status records rejected oversize dropped skipped_bytes")
        enum(observation["status"], STATUSES)
        for name in ("rejected", "oversize", "dropped", "skipped_bytes"):
            integer(observation[name])
        records = observation["records"]
        require(type(records) is list and len(records) <= MAX_RECORDS)
        for record in records:
            fields(record, "phase category stage exit_code")
            enum(record["phase"], PHASES)
            enum(record["category"], CATEGORIES)
            enum(record["stage"], STAGES)
            exit_code(record["exit_code"])
            require(len(canonical(record)) <= MAX_RECORD_BYTES)
    require(len(canonical(value)) <= MAX_MANIFEST_BYTES)
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def valid_path(path):
    path.encode("utf-8")
    require(bool(path) and not any(char in path for char in "\r\n\0"))


def safe_manifest(state):
    return {"schema_version": 1, "state": state, "scenario": 0, "command": 0,
            "dropped_commands": 0, "commands": [], "finalization": "unverified"}


def read_observations():
    source = os.environ.get("MVM_E2E_FAILURE_MANIFEST", "")
    authorization = os.environ.get("MVM_E2E_FAILURE_AUTHORIZATION", "")
    try:
        valid_path(source)
        if not authorization:
            return safe_manifest("absent")
        valid_path(authorization)
        require(authorization == source)
        # The source may be legitimately atomically replaced after initialization.
        # Authorization selects it; this independent read validates its contents.
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as input_file:
            metadata = os.fstat(input_file.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                    and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1
                    and metadata.st_size <= MAX_MANIFEST_BYTES)
            data = input_file.read(MAX_MANIFEST_BYTES + 1)
            require(len(data) <= MAX_MANIFEST_BYTES)
        value = validate(json.loads(data.decode("utf-8"), object_pairs_hook=unique_object))
        value["state"] = {"complete": "observed", "loss": "observed_loss"}.get(
            value["state"], value["state"])
        # A source snapshot cannot prove final-write acknowledgment or suite success.
        value["finalization"] = "unverified"
        require(len(canonical(value)) <= MAX_MANIFEST_BYTES)
        return value
    except FileNotFoundError:
        return safe_manifest("absent")
    except (OSError, ValueError, UnicodeError, RecursionError):
        return safe_manifest("unreadable")


def export():
    destination = os.environ.get("MVM_E2E_FAILURE_EXPORT", "")
    try:
        valid_path(destination)
    except (ValueError, UnicodeError):
        print("failure-manifest: refused", file=sys.stderr)
        return 2
    value = read_observations()
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(canonical(value))
            output.flush()
            os.fsync(output.fileno())
        if github_output := os.environ.get("GITHUB_OUTPUT"):
            with open(github_output, "a", encoding="utf-8") as output:
                output.write(f"failure_manifest={destination}\n")
        print("failure-manifest: exported", file=sys.stderr)
        return 0
    except FileExistsError:
        print("failure-manifest: refused", file=sys.stderr)
        return 2
    except OSError:
        print("failure-manifest: unreadable", file=sys.stderr)
        return 3


def initialize():
    destination = os.environ["MVM_E2E_FAILURE_MANIFEST"]
    try:
        destination.encode("utf-8")
    except UnicodeError:
        print("failure-manifest: refused", file=sys.stderr)
        return 2
    if "\r" in destination or "\n" in destination:
        print("failure-manifest: refused", file=sys.stderr)
        return 2
    manifest = {
        "schema_version": 1,
        "state": "not_started",
        "scenario": 0,
        "command": 0,
        "dropped_commands": 0,
        "commands": [],
    }
    data = json.dumps(manifest, separators=(",", ":")).encode("ascii")
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            metadata = os.fstat(output.fileno())
        # Authorization is deliberately not based on the file's existence.
        if github_output := os.environ.get("GITHUB_OUTPUT"):
            with open(github_output, "a", encoding="utf-8") as output:
                output.write(f"failure_manifest={destination}\n")
        print(f"{metadata.st_dev}:{metadata.st_ino}")
        print("failure-manifest: initialized", file=sys.stderr)
        return 0
    except FileExistsError:
        print("failure-manifest: refused", file=sys.stderr)
        return 2
    except OSError:
        print("failure-manifest: unreadable", file=sys.stderr)
        return 3


if __name__ == "__main__":
    if sys.argv[1:] == ["--export"]:
        sys.exit(export())
    if sys.argv[1:]:
        print("failure-manifest: refused", file=sys.stderr)
        sys.exit(2)
    sys.exit(initialize())
