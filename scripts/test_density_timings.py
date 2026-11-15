"""Offline checks for density-wave boot timing evidence."""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from scripts.density_timings import summarize


class DensityTimingsTests(unittest.TestCase):
    IMAGE = "alpine"
    CPUS = 2
    MEMORY = "512M"

    def summarize(self, wave: Path, count: int, mode: str = "cold") -> str:
        return summarize(wave, count, mode, self.IMAGE, self.CPUS, self.MEMORY)

    def write_pair(self, wave: Path, name: str, start_ns: int, mode: str) -> Path:
        receipt = wave / f"{name}.receipt.json"
        receipt.write_text(json.dumps({"payload": {
            "schema_version": 1,
            "invocation": {
                "image": self.IMAGE, "cpus": self.CPUS, "memory": self.MEMORY
            },
        }}))
        sample = wave / f"{name}.sample.json"
        sample.write_text(json.dumps({"schema_version": 4, "launch_mode": mode}))
        os.utime(sample, ns=(start_ns + 1, start_ns + 1))
        return receipt

    def test_nearest_rank_percentiles_and_per_vm_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wave = Path(directory)
            start_ns = time.time_ns()
            launches = []
            for index, milliseconds in enumerate((1, 2, 3, 4, 5)):
                name = f"vm-{index}"
                launches.append(f"{name}\t123\tstdout\tstderr\t{start_ns}\n")
                receipt = self.write_pair(wave, name, start_ns, "cold")
                end_ns = start_ns + milliseconds * 1_000_000
                os.utime(receipt, ns=(end_ns, end_ns))
            (wave / "launches.tsv").write_text("".join(launches))

            report = self.summarize(wave, 5)

            self.assertIn("wave_5_boot_receipt_p50_ms\t3.000\n", report)
            self.assertIn("wave_5_boot_receipt_p95_ms\t5.000\n", report)
            self.assertIn("wave_5_boot_receipt_p99_ms\t5.000\n", report)
            self.assertIn("vm-4\t5.000\n", (wave / "boot-receipt-ms.tsv").read_text())

    def test_missing_or_mismatched_evidence_never_produces_a_latency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wave = Path(directory)
            with self.assertRaisesRegex(ValueError, "positive"):
                self.summarize(wave, 0)
            (wave / "launches.tsv").write_text("vm-a\t123\tstdout\tstderr\t1\n")
            with self.assertRaises(FileNotFoundError):
                self.summarize(wave, 1)
            receipt = self.write_pair(wave, "vm-a", 1, "cold")
            with self.assertRaisesRegex(ValueError, "expected warm launch"):
                self.summarize(wave, 1, "warm")
            with self.assertRaisesRegex(ValueError, "launch shape"):
                receipt.write_text(json.dumps({"payload": {
                    "schema_version": 1,
                    "invocation": {"image": "other", "cpus": 2, "memory": "512M"},
                }}))
                self.summarize(wave, 1)
            self.assertFalse((wave / "boot-receipt-ms.tsv").exists())

    def test_warm_pair_without_machine_name_and_missing_sample(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wave = Path(directory)
            start_ns = time.time_ns() - 1_000_000
            (wave / "launches.tsv").write_text(
                f"label-1\t123\tstdout\tstderr\t{start_ns}\n"
            )
            receipt = self.write_pair(wave, "label-1", start_ns, "warm")
            os.utime(receipt, ns=(start_ns + 2_000_000, start_ns + 2_000_000))
            self.assertIn("wave_1_boot_receipt_p50_ms\t2.000", self.summarize(wave, 1, "warm"))
            (wave / "label-1.sample.json").unlink()
            with self.assertRaises(FileNotFoundError):
                self.summarize(wave, 1, "warm")


if __name__ == "__main__":
    unittest.main()
