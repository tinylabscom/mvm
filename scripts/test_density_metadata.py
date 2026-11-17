"""Offline provenance and measurement-boundary tests; no guest is launched."""

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import density_metadata


class DensityMetadataTests(unittest.TestCase):
    def test_fingerprint_measures_bytes_and_preserves_missing_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            self.assertEqual(density_metadata.fingerprint(path), {
                "status": "unavailable", "sha256": None,
            })
            path.write_bytes(b"fixture")
            self.assertEqual(density_metadata.fingerprint(path), {
                "status": "measured",
                "sha256": hashlib.sha256(b"fixture").hexdigest(),
            })

    @patch("density_metadata.probe", return_value=None)
    def test_unavailable_metadata_and_fixture_runs_cannot_claim_live_success(self, _probe):
        with tempfile.TemporaryDirectory() as directory:
            summary = dict.fromkeys((
                "run_id", "image", "backend", "launch_mode", "waves", "memory",
                "cpus", "settle_seconds", "idle_sample_seconds", "custom_workload",
            ), "fixture")
            summary.update({
                "backend": "hvf", "host_memory_mib": "8192", "cache_dir": directory,
                "mvmctl": directory, "network_endpoint": directory, "supervisor": directory,
            })
            report = density_metadata.collect(Path(directory), summary, {
                "MVM_HVF_DENSITY_ALLOW_UNSUPPORTED": "1",
                "MVM_HVF_DENSITY_ALLOW_BUSY_HOST": "1",
                "UNRELATED_SECRET": "must-not-appear",
            })
            self.assertEqual(report["schema_version"], 1)
            self.assertEqual(report["status"], "metadata_only")
            self.assertIsNone(report["source"]["revision"])
            self.assertIsNone(report["source"]["dirty"])
            self.assertEqual(report["evidence"]["classification"], "non_native_or_fixture")
            self.assertTrue(report["guards"]["busy_host_bypassed"])
            self.assertIn("for availability", report["boundaries"]["physical_footprint"])
            self.assertEqual(report["artifacts"]["supervisor"]["status"], "unavailable")
            self.assertNotIn("must-not-appear", str(report))
            native = density_metadata.collect(Path(directory), summary, {})
            self.assertEqual(native["evidence"]["classification"], "native_requested")
            self.assertEqual(native["status"], "metadata_only")
            for status, dirty in (("?? private-customer-file\n", True), ("", False)):
                with patch("density_metadata.probe", side_effect=lambda *args: (
                    status if "status" in args else None
                )):
                    private = density_metadata.collect(Path(directory), summary, {})
                self.assertEqual(private["source"]["dirty"], dirty)
                self.assertNotIn("private-customer-file", str(private))

    @patch("density_metadata.subprocess.run", side_effect=FileNotFoundError)
    def test_missing_probe_is_not_an_empty_success(self, _run):
        self.assertIsNone(density_metadata.probe("missing-tool"))


if __name__ == "__main__":
    unittest.main()
