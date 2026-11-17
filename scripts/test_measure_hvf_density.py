"""Offline command-construction checks using a fake mvmctl, never a VM."""

import json
import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class DensityHarnessTests(unittest.TestCase):
    def test_cold_and_warm_invocations(self) -> None:
        for mode in ("cold", "warm"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir="/tmp") as tmp:
                base = Path(tmp)
                ctl = base / "mvmctl"
                ctl.write_text("""#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

args = sys.argv[1:]
with (Path(os.environ["MVM_HOME"]).parent / "commands.jsonl").open("a") as log:
    log.write(json.dumps([args, {
        key: os.environ.get(key)
        for key in ("MVM_RESIDENCY", "MVM_HVF_WARM_REQUIRE_CLAIM",
                    "MVM_PHASE_TIMING", "MVM_LAUNCH_SAMPLE_JSON")
    }]) + "\\n")
if args[:2] == ["machine", "run"]:
    def flag(name):
        return args[args.index(name) + 1]
    if "--receipt" not in args:
        if os.environ.get("MVM_FAKE_PRIME_FAIL") == "1":
            sys.exit(3)
        sys.exit(0)  # The first-use preparation is outside the measured wave.
    if os.environ.get("MVM_FAKE_RESIDENT") == "1":
        time.sleep(30)  # No completion receipt while the guest is resident.
        sys.exit(0)
    receipt = Path(flag("--receipt"))
    Path(os.environ["MVM_LAUNCH_SAMPLE_JSON"]).write_text(json.dumps({
        "schema_version": 4, "launch_mode": os.environ["MVM_RESIDENCY"]
    }))
    receipt.write_text(json.dumps({"payload": {
        "schema_version": 1, "invocation": {
            "image": flag("--image"), "cpus": int(flag("--cpus")),
            "memory": flag("--memory")
        }
    }}))
    time.sleep(30)
""")
                ctl.chmod(0o755)
                env = dict(os.environ)
                env.update({
                    "MVM_HVF_DENSITY_BACKEND": (
                        "hvf" if platform.system() == "Darwin" else "firecracker"
                    ),
                    "MVM_HVF_DENSITY_MODE": mode,
                    "MVM_HVF_DENSITY_OUT_DIR": str(base / "out"),
                    "MVM_HVF_DENSITY_MVMCTL": str(ctl),
                    "MVM_SUBSTITUTION_ENDPOINT_PATH": str(ctl),
                    "MVM_HVF_SUPERVISOR_PATH": str(ctl),
                    "MVM_HVF_DENSITY_ALLOW_UNSUPPORTED": "1",
                    "MVM_HVF_DENSITY_ALLOW_BUSY_HOST": "1",
                    "MVM_HVF_DENSITY_SKIP_BUILD": "1",
                    "MVM_HVF_DENSITY_SKIP_PREPULL": "1",
                    "MVM_HVF_DENSITY_SEED_HOST_KERNEL": "0",
                    "MVM_HVF_DENSITY_WAVES": "1",
                    "MVM_HVF_DENSITY_GUEST_SLEEP_SECONDS": "61",
                    "MVM_HVF_DENSITY_SETTLE_SECONDS": "0",
                    "MVM_HVF_DENSITY_IDLE_SAMPLE_SECONDS": "0",
                    "MVM_HVF_DENSITY_LAUNCH_SPACING_SECONDS": "0",
                    "MVM_HVF_DENSITY_CLEANUP_GRACE_SECONDS": "0",
                })
                result = subprocess.run(
                    ["/bin/bash" if platform.system() == "Darwin" else "bash",
                     str(ROOT / "scripts/measure-hvf-density.sh")],
                    env=env, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                metadata = json.loads((base / "out/metadata.json").read_text())
                self.assertEqual(metadata["configuration"]["launch_mode"], mode)
                self.assertEqual(metadata["status"], "metadata_only")
                self.assertEqual(
                    metadata["evidence"]["classification"], "non_native_or_fixture"
                )
                self.assertEqual(metadata["artifacts"]["mvmctl"]["status"], "measured")
                self.assertEqual(
                    metadata["boundaries"]["workload_readiness"], "not_measured_separately"
                )
                for phase in ("before", "settled", "after-cleanup"):
                    memory = json.loads(
                        (base / f"out/wave-1/physical-memory-{phase}.json").read_text()
                    )
                    self.assertIn(memory["status"], ("measured", "partial", "unavailable"))
                commands = [
                    json.loads(line)
                    for line in (base / "out/commands.jsonl").read_text().splitlines()
                ]
                prime = commands[0][0]
                self.assertEqual(prime[:2], ["machine", "run"])
                self.assertNotIn("--receipt", prime)
                self.assertRegex(prime[prime.index("--name") + 1], r"^[a-z0-9-]+$")
                self.assertEqual(commands[1][0][:2], ["machine", "stop"])
                self.assertEqual(commands[2][0][:2], ["machine", "rm"])
                launch = next(
                    (args, vars) for args, vars in commands
                    if args[:2] == ["machine", "run"] and "--receipt" in args
                )
                self.assertEqual(launch[1]["MVM_RESIDENCY"], mode)
                self.assertEqual(launch[1]["MVM_PHASE_TIMING"], "1")
                self.assertTrue(launch[1]["MVM_LAUNCH_SAMPLE_JSON"].endswith(".sample.json"))
                self.assertEqual("--name" in launch[0], mode == "cold")
                if mode == "cold":
                    self.assertRegex(
                        launch[0][launch[0].index("--name") + 1], r"^[a-z0-9-]+$"
                    )
                if mode == "warm":
                    warm = commands[3][0]
                    self.assertEqual(warm[:3], ["pool", "warm", "1"])
                    self.assertEqual(warm[3:], [
                        "--image", "docker.io/library/alpine:latest",
                        "--cpus", "2", "--memory", "512M",
                    ])
                    self.assertEqual(launch[1]["MVM_HVF_WARM_REQUIRE_CLAIM"], "1")
                self.assertIn(
                    f"wave_1_boot_receipt_p50_ms",
                    (base / "out/summary.tsv").read_text(),
                )
                env["MVM_FAKE_RESIDENT"] = "1"
                env["MVM_HVF_DENSITY_OUT_DIR"] = str(base / "out-resident")
                resident = subprocess.run(
                    ["/bin/bash" if platform.system() == "Darwin" else "bash",
                     str(ROOT / "scripts/measure-hvf-density.sh")],
                    env=env, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(resident.returncode, 0, resident.stderr)
                self.assertIn(
                    "wave_1_boot_receipt_p50_ms\tunavailable:resident_workload",
                    (base / "out-resident/summary.tsv").read_text(),
                )
                env.pop("MVM_FAKE_RESIDENT")
                env["MVM_FAKE_PRIME_FAIL"] = "1"
                env["MVM_HVF_DENSITY_OUT_DIR"] = str(base / "out-fail")
                failed = subprocess.run(
                    ["/bin/bash" if platform.system() == "Darwin" else "bash",
                     str(ROOT / "scripts/measure-hvf-density.sh")],
                    env=env, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(failed.returncode, 71, failed.stderr)
                self.assertIn("first-use preparation failed", failed.stderr)
                self.assertFalse((base / "out-fail/wave-1").exists())


if __name__ == "__main__":
    unittest.main()
