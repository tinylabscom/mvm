"""Security regression tests for the independently validated export boundary."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("e2e-failure-manifest.py")
spec = importlib.util.spec_from_file_location("manifest", SCRIPT)
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)
SENTINEL = b"SENTINEL_SECRET"


def source():
    return {
        "schema_version": 1, "state": "complete", "scenario": 1,
        "command": 1, "dropped_commands": 0,
        "commands": [{
            "scenario": 1, "command": 1, "success": False, "exit_code": 37,
            "observation": {
                "status": "collected", "records": [{
                    "phase": "transient_boot", "category": "unknown",
                    "stage": "absent", "exit_code": None,
                }],
                "rejected": 0, "oversize": 0, "dropped": 0, "skipped_bytes": 0,
            },
        }],
    }


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.src = self.root / "source"
        self.dst = self.root / "export"
        self.output = self.root / "output"
        self.env = dict(os.environ, MVM_E2E_FAILURE_MANIFEST=str(self.src),
                        MVM_E2E_FAILURE_AUTHORIZATION=str(self.src),
                        MVM_E2E_FAILURE_EXPORT=str(self.dst),
                        GITHUB_OUTPUT=str(self.output))

    def write(self, data):
        self.src.write_bytes(data)
        self.src.chmod(0o600)

    def run_export(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--export"],
                                env=self.env, capture_output=True)
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        self.assertNotIn(str(self.src).encode(), result.stdout + result.stderr)
        if self.dst.exists():
            self.assertNotIn(SENTINEL, self.dst.read_bytes())
        return result

    def check_safe(self, state):
        result = self.run_export()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(self.dst.read_bytes())
        self.assertEqual(value["state"], state)
        self.assertEqual(value["finalization"], "unverified")
        self.assertEqual(self.dst.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.read_text(), f"failure_manifest={self.dst}\n")
        return value

    def test_normal_complete_is_only_observed(self):
        self.write(json.dumps(source(), indent=4).encode())
        value = self.check_safe("observed")
        self.assertEqual(value["commands"], source()["commands"])
        self.assertNotIn(b"complete", self.dst.read_bytes())
        self.assertEqual(self.dst.read_bytes(),
                         json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii"))

    def test_partial_and_loss_retained_after_failure(self):
        for state, exported in [("not_started", "not_started"),
                                ("in_progress", "in_progress"), ("loss", "observed_loss")]:
            with self.subTest(state=state):
                data = source()
                data["state"] = state
                data["dropped_commands"] = 3
                self.write(json.dumps(data).encode())
                value = self.check_safe(exported)
                self.assertEqual(value["dropped_commands"], 3)
                self.dst.unlink()
                self.output.unlink()

    def test_missing_authorization_and_absent_source(self):
        self.check_safe("absent")
        self.dst.unlink()
        self.output.unlink()
        self.write(SENTINEL)
        self.env["MVM_E2E_FAILURE_AUTHORIZATION"] = ""
        self.check_safe("absent")

    def test_stale_initializer_refusal_never_authorizes_source(self):
        self.write(json.dumps(source()).encode())
        result = subprocess.run([sys.executable, str(SCRIPT)], env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())
        self.env["MVM_E2E_FAILURE_AUTHORIZATION"] = ""
        self.check_safe("absent")

    def test_atomic_replacement_is_accepted(self):
        self.write(b"{}")
        original = self.src.stat().st_ino
        replacement = self.root / "replacement"
        replacement.write_text(json.dumps(source()))
        replacement.chmod(0o600)
        replacement.replace(self.src)
        self.assertNotEqual(self.src.stat().st_ino, original)
        self.check_safe("observed")

    def test_invalid_inputs_never_leak(self):
        valid = json.dumps(source()).encode()
        inputs = [SENTINEL, b"\xff" + SENTINEL, b"x" * 262145 + SENTINEL,
                  valid.replace(b'"schema_version": 1', b'"schema_version": true'),
                  valid.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'),
                  valid.replace(b'"unknown"', b'"SENTINEL_SECRET"'),
                  valid.replace(b'"exit_code": 37', b'"exit_code": true'),
                  valid.replace(b'"exit_code": 37', b'"exit_code": 2147483648'),
                  valid.replace(b'"scenario": 1', b'"scenario": -1'),
                  valid.replace(b'"scenario": 1', b'"scenario": 4294967296'),
                  valid.replace(b'"success": false', b'"success": 0'),
                  b"[" * 10000]
        for data in inputs:
            with self.subTest(data=data[:60]):
                self.write(data)
                self.check_safe("unreadable")
                self.dst.unlink()
                self.output.unlink()

    def test_closed_schema_at_every_level(self):
        paths = [(), ("commands", 0), ("commands", 0, "observation"),
                 ("commands", 0, "observation", "records", 0)]
        for path in paths:
            for action in ("extra", "missing"):
                data = source()
                node = data
                for key in path:
                    node = node[key]
                if action == "extra":
                    node["SENTINEL_SECRET"] = "SENTINEL_SECRET"
                else:
                    del node[next(iter(node))]
                self.write(json.dumps(data).encode())
                self.check_safe("unreadable")
                self.dst.unlink()
                self.output.unlink()

    def test_count_limits(self):
        for kind in ("commands", "records"):
            data = source()
            if kind == "commands":
                data["commands"] *= 129
            else:
                data["commands"][0]["observation"]["records"] *= 17
            self.write(json.dumps(data).encode())
            self.check_safe("unreadable")
            self.dst.unlink()
            self.output.unlink()

    def test_rust_schema_enums_fields_and_limits_match_exactly(self):
        root = SCRIPT.parent.parent
        records = (root / "crates/mvm-core/src/launch_trace/failure.rs").read_text()
        collector = (root / "crates/mvm-conformance/tests/support/failure_diagnostics.rs").read_text()
        for rust, name, expected in [
            (records, "Phase", manifest.PHASES),
            (records, "Category", manifest.CATEGORIES),
            (records, "Stage", manifest.STAGES),
            (collector, "CollectionState", manifest.STATES),
            (collector, "Status", manifest.STATUSES),
        ]:
            body = re.search(r"enum " + name + r" \{([^}]+)\}", rust).group(1)
            variants = re.findall(r"^\s+([A-Z][a-zA-Z]+),", body, re.M)
            actual = {re.sub(r"(?<!^)(?=[A-Z])", "_", item).lower() for item in variants}
            self.assertEqual(actual, expected)
        data = source()
        for rust, name, value in [
            (collector, "Manifest", data),
            (collector, "CommandObservation", data["commands"][0]),
            (collector, "Observation", data["commands"][0]["observation"]),
            (records, "Record", data["commands"][0]["observation"]["records"][0]),
        ]:
            body = re.search(r"struct " + name + r" \{([^}]+)\}", rust).group(1)
            actual = dict(re.findall(r"^\s+(?:pub )?(\w+): ([^\n,]+),", body, re.M))
            self.assertEqual(set(actual), set(value))
            for field, kind in actual.items():
                if field in {"schema_version", "scenario", "command", "dropped_commands",
                             "rejected", "oversize", "dropped", "skipped_bytes"}:
                    self.assertEqual(kind, "u32")
                elif field == "exit_code":
                    self.assertEqual(kind, "Option<i32>")
                elif field == "success":
                    self.assertEqual(kind, "Option<bool>")
        for rust, name in [(collector, "MAX_MANIFEST_BYTES"), (collector, "MAX_COMMANDS"),
                           (collector, "MAX_RECORDS"), (records, "MAX_RECORD_BYTES")]:
            expression = re.search(r"const " + name + r": usize = ([^;]+);", rust).group(1)
            factors = expression.split("*")
            value = 1
            for factor in factors:
                value *= int(factor.strip())
            self.assertEqual(value, getattr(manifest, name))

    def test_all_enums_and_integer_boundaries_accepted(self):
        data = source()
        record = data["commands"][0]["observation"]["records"][0]
        for name, values in [("phase", manifest.PHASES), ("category", manifest.CATEGORIES),
                             ("stage", manifest.STAGES), ("exit_code", [None, -2147483648, 2147483647])]:
            for value in values:
                record[name] = value
                manifest.validate(data)
        for value in [0, 4294967295]:
            data["scenario"] = value
            data["commands"][0]["observation"]["skipped_bytes"] = value
            manifest.validate(data)
        data["commands"][0]["observation"]["records"] *= 16
        manifest.validate(data)
        data["commands"][0]["observation"]["records"] = []
        data["commands"] *= 128
        manifest.validate(data)

    def test_unsafe_source_types_and_permissions(self):
        for kind in ("symlink", "hardlink", "directory", "fifo", "public"):
            target = self.root / "target"
            target.write_bytes(SENTINEL)
            target.chmod(0o600)
            if kind == "symlink":
                self.src.symlink_to(target)
            elif kind == "hardlink":
                os.link(target, self.src)
            elif kind == "directory":
                self.src.mkdir()
            elif kind == "fifo":
                os.mkfifo(self.src)
            else:
                self.write(json.dumps(source()).encode())
                self.src.chmod(0o644)
            self.check_safe("unreadable")
            self.assertEqual(target.read_bytes(), SENTINEL)
            if kind == "directory":
                self.src.rmdir()
            else:
                self.src.unlink()
            target.unlink()
            self.dst.unlink()
            self.output.unlink()

    def test_fresh_destination_required(self):
        self.write(json.dumps(source()).encode())
        self.dst.write_bytes(b"existing")
        result = self.run_export()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.dst.read_bytes(), b"existing")
        self.assertFalse(self.output.exists())

    def test_wrong_owner_is_refused_without_privileged_setup(self):
        self.write(json.dumps(source()).encode())
        with patch.dict(os.environ, self.env), patch.object(
                manifest.os, "geteuid", return_value=os.geteuid() + 1):
            self.assertEqual(manifest.read_observations(), manifest.safe_manifest("unreadable"))

    def test_duplicate_keys_at_every_level_are_refused(self):
        for key, value in [("schema_version", "1"), ("success", "false"),
                           ("rejected", "0"), ("phase", '"transient_boot"')]:
            data = json.dumps(source())
            data = data.replace(f'"{key}": {value}', f'"{key}": {value}, "{key}": {value}')
            self.write(data.encode())
            self.check_safe("unreadable")
            self.dst.unlink()
            self.output.unlink()

    def test_invalid_numeric_types_and_ranges_at_every_counter(self):
        data = source()
        nodes = [data, data["commands"][0], data["commands"][0]["observation"]]
        counters = {"schema_version", "scenario", "command", "dropped_commands",
                    "rejected", "oversize", "dropped", "skipped_bytes"}
        for node in nodes:
            for key in set(node) & counters:
                original = node[key]
                for invalid in [True, False, -1, 4294967296, 1.0, None, "SENTINEL_SECRET"]:
                    node[key] = invalid
                    with self.assertRaises(ValueError):
                        manifest.validate(data)
                node[key] = original

    def test_source_and_export_paths_cannot_inject_outputs(self):
        for name in ("MVM_E2E_FAILURE_MANIFEST", "MVM_E2E_FAILURE_EXPORT"):
            for suffix in ("\rinjected=true", "\ninjected=true", "\udcff"):
                original = self.env[name]
                self.env[name] += suffix
                result = self.run_export()
                if name.endswith("EXPORT"):
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(self.output.exists())
                else:
                    self.assertEqual(json.loads(self.dst.read_bytes())["state"], "unreadable")
                    self.dst.unlink()
                    self.output.unlink()
                self.env[name] = original


if __name__ == "__main__":
    unittest.main()
