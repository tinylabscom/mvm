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
                    ["bash", str(ROOT / "scripts/measure-hvf-density.sh")],
                    env=env, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                commands = [
                    json.loads(line)
                    for line in (base / "out/commands.jsonl").read_text().splitlines()
                ]
                launch = next((args, vars) for args, vars in commands if args[:2] == ["machine", "run"])
                self.assertEqual(launch[1]["MVM_RESIDENCY"], mode)
                self.assertEqual(launch[1]["MVM_PHASE_TIMING"], "1")
                self.assertTrue(launch[1]["MVM_LAUNCH_SAMPLE_JSON"].endswith(".sample.json"))
                self.assertEqual("--name" in launch[0], mode == "cold")
                if mode == "warm":
                    warm = commands[0][0]
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


if __name__ == "__main__":
    unittest.main()
