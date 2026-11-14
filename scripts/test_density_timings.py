"""Offline checks for density-wave boot timing evidence."""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from scripts.density_timings import summarize


class DensityTimingsTests(unittest.TestCase):
    def test_nearest_rank_percentiles_and_per_vm_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wave = Path(directory)
            start_ns = time.time_ns()
            launches = []
            for index, milliseconds in enumerate((1, 2, 3, 4, 5)):
                name = f"vm-{index}"
                launches.append(f"{name}\t123\tstdout\tstderr\t{start_ns}\n")
                receipt = wave / f"{name}.receipt.json"
                receipt.write_text(
                    json.dumps(
                        {"payload": {
                            "schema_version": 1,
                            "invocation": {"machine_name": name},
                        }}
                    )
                )
                end_ns = start_ns + milliseconds * 1_000_000
                os.utime(receipt, ns=(end_ns, end_ns))
            (wave / "launches.tsv").write_text("".join(launches))

            report = summarize(wave, 5)

            self.assertIn("wave_5_boot_receipt_p50_ms\t3.000\n", report)
            self.assertIn("wave_5_boot_receipt_p95_ms\t5.000\n", report)
            self.assertIn("wave_5_boot_receipt_p99_ms\t5.000\n", report)
            self.assertIn("vm-4\t5.000\n", (wave / "boot-receipt-ms.tsv").read_text())

    def test_missing_or_foreign_receipt_never_produces_a_latency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wave = Path(directory)
            with self.assertRaisesRegex(ValueError, "positive"):
                summarize(wave, 0)
            (wave / "launches.tsv").write_text("vm-a\t123\tstdout\tstderr\t1\n")
            with self.assertRaises(FileNotFoundError):
                summarize(wave, 1)
            (wave / "vm-a.receipt.json").write_text(
                json.dumps({"payload": {
                    "schema_version": 1,
                    "invocation": {"machine_name": "vm-b"},
                }})
            )
            with self.assertRaisesRegex(ValueError, "another machine"):
                summarize(wave, 1)


if __name__ == "__main__":
    unittest.main()
