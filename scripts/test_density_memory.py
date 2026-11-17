"""Memory accounting fixtures; no workload VM or host configuration changes."""

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import density_memory


class FakeLibproc:
    def pids(self):
        return [1, 2, 3, 4]

    def program(self, pid):
        if pid == 4:
            raise OSError("exited before classification")
        return {1: "/private/path/mvm-hvf-supervisor", 2: "mvmctl", 3: "sleep"}[pid]

    def rusage(self, pid):
        if pid == 2:
            raise OSError("sample denied")
        return bytes(64) + struct.pack("<QQQ", 100, 40, 123)


class DensityMemoryTests(unittest.TestCase):
    def test_fields_follow_the_sdk_layout_not_the_wakeup_offsets(self):
        raw = bytes(16) + struct.pack("<9Q", *range(11, 20))
        self.assertEqual(density_memory.memory_from_rusage(raw), (17, 18, 19))
        with self.assertRaises(struct.error):
            density_memory.memory_from_rusage(raw[:87])

    def test_partial_samples_preserve_missing_values_and_do_not_export_paths(self):
        report = density_memory.collect(FakeLibproc())
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["scope"], "host_wide_matching_processes")
        self.assertEqual(report["unclassified_processes"], 1)
        self.assertLessEqual(
            report["capture_started_monotonic_ns"], report["capture_finished_monotonic_ns"]
        )
        self.assertEqual(len(report["processes"]), 2)
        measured, missing = report["processes"]
        self.assertEqual(measured["resident_bytes"], 100)
        self.assertEqual(measured["physical_footprint_bytes"], 40)
        self.assertEqual(measured["process_start_abstime"], 123)
        self.assertEqual(missing["status"], "unavailable")
        self.assertIsNone(missing["physical_footprint_bytes"])
        self.assertNotIn("/private/path", json.dumps(report))

    def test_reused_pids_have_distinct_birth_times(self):
        reader = FakeLibproc()
        first = density_memory.collect(reader)["processes"][0]
        with patch.object(reader, "rusage", return_value=bytes(64) + struct.pack("<QQQ", 100, 40, 456)):
            second = density_memory.collect(reader)["processes"][0]
        self.assertEqual(first["pid"], second["pid"])
        self.assertNotEqual(first["process_start_abstime"], second["process_start_abstime"])

    def test_reuse_during_classification_is_unavailable_not_attributed_to_old_component(self):
        reader = FakeLibproc()
        old = bytes(64) + struct.pack("<QQQ", 100, 40, 123)
        new = bytes(64) + struct.pack("<QQQ", 200, 80, 456)
        for programs, usages in (
            (["mvmctl", "sleep"], [old, old]),
            (["mvmctl", "mvmctl"], [old, new]),
        ):
            with self.subTest(programs=programs), \
                    patch.object(reader, "pids", return_value=[1]), \
                    patch.object(reader, "program", side_effect=programs), \
                    patch.object(reader, "rusage", side_effect=usages):
                report = density_memory.collect(reader)
            self.assertEqual(report["status"], "partial")
            self.assertEqual(report["processes"][0]["status"], "unavailable")
            self.assertIsNone(report["processes"][0]["physical_footprint_bytes"])

    def test_unsupported_platform_is_not_reported_as_zero_memory(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("density_memory.sys.platform", "linux"), \
                patch("density_memory.sys.argv", ["density_memory.py", directory, "before"]):
            self.assertEqual(density_memory.main(), 0)
            report = json.loads((Path(directory) / "physical-memory-before.json").read_text())
        self.assertEqual(report["status"], "unavailable")
        self.assertNotIn("processes", report)

    def test_empty_success_and_failed_enumeration_are_distinct(self):
        reader = FakeLibproc()
        with patch.object(reader, "pids", return_value=[]):
            report = density_memory.collect(reader)
        self.assertEqual(report["status"], "measured")
        self.assertEqual(report["processes"], [])
        with tempfile.TemporaryDirectory() as directory, \
                patch("density_memory.sys.platform", "darwin"), \
                patch("density_memory.Libproc", side_effect=OSError("unavailable")), \
                patch("density_memory.sys.argv", ["density_memory.py", directory, "settled"]):
            self.assertEqual(density_memory.main(), 0)
            report = json.loads((Path(directory) / "physical-memory-settled.json").read_text())
        self.assertEqual(report["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
