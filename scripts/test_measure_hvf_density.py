"""Offline command-construction checks using a fake mvmctl, never a VM."""

import json
import os
import platform
import shutil
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
if args[:2] == ["bench", "report"]:
    if os.environ.get("MVM_FAKE_REPORT_FAIL") == "1":
        print("report refused", file=sys.stderr)
        sys.exit(1)
    Path(args[args.index("--out") + 1]).write_text("{}")
    print("| report |")
    sys.exit(0)
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
                # The fake binaries are overrides, so the run cannot claim release.
                self.assertEqual(
                    metadata["configuration"]["build_profile"], "unknown:binary_override"
                )
                self.assertEqual(
                    metadata["boundaries"]["workload_readiness"], "not_measured_separately"
                )
                for phase in ("before", "settled", "after-cleanup"):
                    memory = json.loads(
                        (base / f"out/wave-1/physical-memory-{phase}.json").read_text()
                    )
                    self.assertIn(memory["status"], ("measured", "partial", "unavailable"))
                zero = base / "out/wave-0"
                memory = json.loads((zero / "physical-memory-settled.json").read_text())
                self.assertIn(memory["status"], ("measured", "partial", "unavailable"))
                for name in ("host-memory", "filesystem", "vm-state-blocks", "mvm-home-blocks"):
                    self.assertTrue((zero / f"{name}-settled.txt").is_file(), name)
                home_kib = (zero / "mvm-home-blocks-settled.txt").read_text().split()[0]
                self.assertRegex(home_kib, r"^[0-9]+$")
                self.assertIn(
                    f"wave_0_mvm_home_du_kib\t{home_kib}\n",
                    (base / "out/summary.tsv").read_text(),
                )
                self.assertFalse((base / "out/wave-1/mvm-home-blocks-settled.txt").exists())
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
                self.assertNotIn("--allow-host", prime + launch[0])
                self.assertEqual(metadata["configuration"]["endpoint_form"], "collector_only")
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
                env.pop("MVM_FAKE_PRIME_FAIL")
                env["MVM_HVF_DENSITY_SERVING_ENDPOINT"] = "1"
                env["MVM_HVF_DENSITY_OUT_DIR"] = str(base / "out-serving")
                serving = subprocess.run(
                    ["/bin/bash" if platform.system() == "Darwin" else "bash",
                     str(ROOT / "scripts/measure-hvf-density.sh")],
                    env=env, capture_output=True, text=True, timeout=20,
                )
                if mode == "warm":
                    self.assertEqual(serving.returncode, 70, serving.stderr)
                    self.assertIn("cold launches only", serving.stderr)
                    continue
                self.assertEqual(serving.returncode, 0, serving.stderr)
                runs = [
                    json.loads(line)[0]
                    for line in (base / "out-serving/commands.jsonl").read_text().splitlines()
                    if json.loads(line)[0][:2] == ["machine", "run"]
                ]
                prime, measured = runs  # the unmeasured prime, then the one launch
                for run in (prime, measured):
                    at = run.index("--allow-host")
                    self.assertEqual(run[at + 1], "192.0.2.1:443")
                    self.assertLess(at, run.index("--"))
                self.assertIn(
                    "endpoint_form\tserving\n",
                    (base / "out-serving/summary.tsv").read_text(),
                )
                metadata = json.loads((base / "out-serving/metadata.json").read_text())
                self.assertEqual(metadata["configuration"]["endpoint_form"], "serving")
                env["MVM_HVF_DENSITY_SERVING_ENDPOINT"] = "yes"
                env["MVM_HVF_DENSITY_OUT_DIR"] = str(base / "out-bad")
                bad = subprocess.run(
                    ["/bin/bash" if platform.system() == "Darwin" else "bash",
                     str(ROOT / "scripts/measure-hvf-density.sh")],
                    env=env, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(bad.returncode, 70, bad.stderr)
                self.assertIn("must be 0 or 1", bad.stderr)


class StandbyHoldTests(unittest.TestCase):
    FAKE = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

args = sys.argv[1:]
home = Path(os.environ["MVM_HOME"])
with (home.parent / "commands.jsonl").open("a") as log:
    log.write(json.dumps([args, os.environ.get("MVM_RESIDENCY"),
                          os.environ.get("MVM_HVF_WARM_REQUIRE_CLAIM")]) + "\\n")
if args[:2] == ["bench", "report"]:
    if os.environ.get("MVM_FAKE_REPORT_FAIL") == "1":
        print("report refused", file=sys.stderr)
        sys.exit(1)
    Path(args[args.index("--out") + 1]).write_text("{}")
    print("| report |")
    sys.exit(0)
if args[:2] == ["pool", "warm"]:
    (home / "pool" / "standby-1").mkdir(parents=True)
    if os.environ.get("MVM_FAKE_SNAPSHOT_STANDBY") == "1":
        (home / "snapshots").mkdir(exist_ok=True)
        (home / "snapshots" / "standby-1.bin").write_bytes(b"x" * 8192)
if args[:3] == ["pool", "status", "--json"]:
    pid = 0 if os.environ.get("MVM_FAKE_SNAPSHOT_STANDBY") == "1" else 4321
    print(json.dumps({"idle": 1, "claimed": 0, "parked": 0, "dead": 0,
                      "standbys": [{"id": "standby-1", "state": "idle", "pid": pid}]}))
"""

    def run_standby(self, base: Path, extra: dict) -> subprocess.CompletedProcess:
        ctl = base / "mvmctl"
        ctl.write_text(self.FAKE)
        ctl.chmod(0o755)
        env = dict(os.environ)
        env.update({
            "MVM_HVF_DENSITY_BACKEND": "hvf" if platform.system() == "Darwin" else "firecracker",
            "MVM_HVF_DENSITY_MODE": "standby",
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
        env.update(extra)
        return subprocess.run(
            ["/bin/bash" if platform.system() == "Darwin" else "bash",
             str(ROOT / "scripts/measure-hvf-density.sh")],
            env=env, capture_output=True, text=True, timeout=20,
        )

    def test_standby_warms_holds_and_clears_its_own_pool(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            base = Path(tmp)
            result = self.run_standby(base, {})
            self.assertEqual(result.returncode, 0, result.stderr)
            commands = [
                json.loads(line)
                for line in (base / "out/commands.jsonl").read_text().splitlines()
            ]
            warm = next(c for c in commands if c[0][:2] == ["pool", "warm"])
            self.assertEqual(warm[0][2], "1")
            self.assertEqual(warm[1], "warm")  # standby is not a residency value
            self.assertFalse(any(c[2] for c in commands))  # nothing is claimed
            self.assertEqual(
                [c[0] for c in commands if c[0][:2] == ["machine", "run"]],
                [c[0] for c in commands[:1]],  # only the unmeasured prime launch
            )
            self.assertFalse((base / "out/mvm-data/pool").exists())
            summary = (base / "out/summary.tsv").read_text()
            self.assertIn("launch_mode\tstandby", summary)
            self.assertIn("wave_0_matching_processes\t0", summary)
            self.assertIn("wave_0_sampler_scope\thost_wide_matching_processes", summary)

    def test_snapshot_standbys_are_counted_from_the_pool_and_charged_their_bytes(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            base = Path(tmp)
            meminfo = base / "meminfo"
            meminfo.write_text("MemTotal:       16777216 kB\n")
            result = self.run_standby(base, {
                "MVM_HVF_DENSITY_BACKEND": "firecracker",
                "MVM_HVF_DENSITY_MEMINFO": str(meminfo),
                "MVM_FAKE_SNAPSHOT_STANDBY": "1",
            })
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = (base / "out/summary.tsv").read_text()
            self.assertIn("standby_form\ton_disk_snapshot\n", summary)
            self.assertIn("wave_1_vmm_processes\t0\n", summary)
            self.assertIn("wave_1_standby_count\t1\n", summary)
            self.assertRegex(summary, r"wave_1_standby_snapshot_du_kib\t[1-9][0-9]*\n")
            self.assertIn("wave_1_idle_sampler\tnot_applicable:no_resident_process", summary)
            metadata = json.loads((base / "out/metadata.json").read_text())
            self.assertEqual(metadata["configuration"]["standby_form"], "on_disk_snapshot")

    # Only HVF keeps a resident process per standby, and its run reads macOS
    # host memory tools; the Firecracker form is the snapshot test above.
    @unittest.skipUnless(platform.system() == "Darwin", "the HVF standby form needs macOS")
    def test_a_resident_standby_records_its_form_as_a_process(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            base = Path(tmp)
            result = self.run_standby(base, {"MVM_HVF_DENSITY_BACKEND": "hvf"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("standby_form\tresident_process\n", (base / "out/summary.tsv").read_text())

    def test_a_too_long_data_dir_refuses_a_firecracker_standby_before_anything_runs(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            base = Path(tmp)
            long_dir = base / ("d" * 60) / "mvm-data"
            meminfo = base / "meminfo"
            meminfo.write_text("MemTotal:       16777216 kB\n")
            result = self.run_standby(base, {
                "MVM_HVF_DENSITY_BACKEND": "firecracker",
                "MVM_HVF_DENSITY_MEMINFO": str(meminfo),
                "MVM_HVF_DENSITY_DATA_DIR": str(long_dir),
            })
            self.assertEqual(result.returncode, 65, result.stderr)
            self.assertIn("MVM_HVF_DENSITY_DATA_DIR", result.stderr)
            self.assertFalse(long_dir.exists())
            self.assertFalse((base / "out/commands.jsonl").exists())

    def test_the_resource_report_is_written_and_its_failure_fails_the_run(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            base = Path(tmp)
            result = self.run_standby(base, {})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((base / "out/resource-report.json").read_text(), "{}")
            self.assertEqual((base / "out/resource-report.md").read_text(), "| report |\n")
            commands = [
                json.loads(line)[0]
                for line in (base / "out/commands.jsonl").read_text().splitlines()
            ]
            report = next(c for c in commands if c[:2] == ["bench", "report"])
            self.assertEqual(report[2], "--density-dir")
            self.assertEqual(report[3], str(base / "out"))
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            result = self.run_standby(Path(tmp), {"MVM_FAKE_REPORT_FAIL": "1"})
            self.assertEqual(result.returncode, 74, result.stderr)
            self.assertIn("resource report generation failed", result.stderr)
            self.assertIn("report refused",
                          (Path(tmp) / "out/resource-report.stderr").read_text())

    def test_pool_is_never_cleared_under_the_default_mvm_home(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            base = Path(tmp)
            (base / "home").mkdir()
            result = self.run_standby(
                base,
                {"HOME": str(base / "home"),
                 "MVM_HVF_DENSITY_DATA_DIR": str(base / "home/.mvm")},
            )
            self.assertEqual(result.returncode, 71, result.stderr)
            self.assertIn("will not clear pool state", result.stderr)
            self.assertTrue((base / "home/.mvm/pool/standby-1").exists())


HARNESS = ["/bin/bash" if platform.system() == "Darwin" else "bash",
           str(ROOT / "scripts/measure-hvf-density.sh")]


def write_exe(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


class FirecrackerPreflightTests(unittest.TestCase):
    """The Linux launch requirements refuse before any build or VM."""

    def run_preflight(self, base: Path, uid: str, kvm: bool, bus: str | None):
        bin_dir = base / "bin"
        bin_dir.mkdir(exist_ok=True)
        write_exe(bin_dir / "id", f"""#!/bin/sh
case "$1" in -u) echo {uid} ;; -un) echo tester ;; *) exit 1 ;; esac
""")
        # Linux is the native host, so a Mac can exercise the pass case too.
        write_exe(bin_dir / "uname", f"""#!/bin/sh
[ "$1" = "-s" ] && {{ echo Linux; exit 0; }}
exec "{shutil.which("uname")}" "$@"
""")
        device = base / "kvm"
        device.write_text("")
        device.chmod(0o600 if kvm else 0o400)
        env = {k: v for k, v in os.environ.items()
               if k not in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
                            "MVM_HVF_DENSITY_ALLOW_UNSUPPORTED")}
        runtime = base / "run-user"
        runtime.mkdir(exist_ok=True)
        if bus == "address":
            env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/run/user/1000/bus"
        elif bus == "socket":
            (runtime / "bus").write_text("")
            env["XDG_RUNTIME_DIR"] = str(runtime)
        elif bus == "runtime-only":
            env["XDG_RUNTIME_DIR"] = str(runtime)
        env.update({
            "PATH": f"{bin_dir}:{env['PATH']}",
            "MVM_HVF_DENSITY_BACKEND": "firecracker",
            "MVM_HVF_DENSITY_KVM_DEVICE": str(device),
            "MVM_HVF_DENSITY_OUT_DIR": str(base / "out"),
            # An invalid wave stops a passing preflight before anything runs.
            "MVM_HVF_DENSITY_WAVES": "0",
        })
        return subprocess.run(HARNESS, env=env, capture_output=True, text=True, timeout=20)

    def test_each_requirement_refuses_with_its_fix(self) -> None:
        cases = (
            ("0", True, "address", "as root"),
            ("1000", False, "address", "usermod -aG kvm tester"),
            ("1000", True, None, "enable-linger"),
            ("1000", True, "runtime-only", "enable-linger"),
        )
        for uid, kvm, bus, needle in cases:
            with self.subTest(uid=uid, kvm=kvm, bus=bus), \
                    tempfile.TemporaryDirectory(dir="/tmp") as tmp:
                result = self.run_preflight(Path(tmp), uid, kvm, bus)
                self.assertEqual(result.returncode, 73, result.stderr)
                self.assertIn(needle, result.stderr)
                self.assertEqual(result.stderr.count("refusing:"), 1, result.stderr)
                self.assertFalse((Path(tmp) / "out").exists())

    def test_a_host_meeting_every_requirement_passes(self) -> None:
        for bus in ("address", "socket"):
            with self.subTest(bus=bus), tempfile.TemporaryDirectory(dir="/tmp") as tmp:
                result = self.run_preflight(Path(tmp), "1000", True, bus)
                self.assertEqual(result.returncode, 70, result.stderr)
                self.assertIn("invalid wave size 0", result.stderr)

    def test_help_names_the_requirements(self) -> None:
        result = subprocess.run(HARNESS + ["--help"], capture_output=True, text=True,
                                timeout=20)
        self.assertEqual(result.returncode, 0)
        for needle in ("non-root user", "/dev/kvm", "systemd user session bus",
                       "release binaries"):
            self.assertIn(needle, result.stdout)


class WaveBusyHostTests(unittest.TestCase):
    """The busy-host check repeats after the build and at each wave."""

    def run_busy(self, base: Path, busy_from: int) -> subprocess.CompletedProcess:
        bin_dir = base / "bin"
        bin_dir.mkdir()
        state = base / "ps-state"
        state.mkdir()
        # Busy-check calls in order: start, after build, wave 0, wave 1.
        # PID 777 stands for this run's own resident daemon from wave 0 on.
        write_exe(bin_dir / "ps", f"""#!/bin/sh
case "$*" in
  *ppid=*)
    n=$(( $(cat "{state}/n" 2>/dev/null || echo 0) + 1 ))
    echo "$n" >"{state}/n"
    [ "$n" -ge 3 ] && echo "777 1 /opt/mvm/mvm-host-agent mvm-host-agent"
    [ "$n" -ge {busy_from} ] && echo "4242 1 /usr/bin/cargo cargo build"
    exit 0 ;;
  *"pid=,comm="*)
    "{shutil.which("ps")}" "$@"
    echo "777 /opt/mvm/mvm-host-agent"
    exit 0 ;;
esac
exec "{shutil.which("ps")}" "$@"
""")
        ctl = base / "mvmctl"
        write_exe(ctl, """#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
with (Path(os.environ["MVM_HOME"]).parent / "commands.jsonl").open("a") as log:
    log.write(json.dumps(args) + "\\n")
if args[:2] == ["bench", "report"]:
    Path(args[args.index("--out") + 1]).write_text("{}")
    sys.exit(0)
if args[:2] == ["machine", "run"] and "--receipt" in args:
    time.sleep(30)
""")
        env = dict(os.environ)
        env.pop("MVM_HVF_DENSITY_ALLOW_BUSY_HOST", None)
        env.update({
            "PATH": f"{bin_dir}:{env['PATH']}",
            "MVM_HVF_DENSITY_BACKEND": "hvf" if platform.system() == "Darwin" else "firecracker",
            "MVM_HVF_DENSITY_OUT_DIR": str(base / "out"),
            "MVM_HVF_DENSITY_MVMCTL": str(ctl),
            "MVM_SUBSTITUTION_ENDPOINT_PATH": str(ctl),
            "MVM_HVF_SUPERVISOR_PATH": str(ctl),
            "MVM_HVF_DENSITY_ALLOW_UNSUPPORTED": "1",
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
        return subprocess.run(HARNESS, env=env, capture_output=True, text=True, timeout=30)

    def test_a_wave_that_starts_busy_is_marked_and_its_own_daemons_are_not(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            base = Path(tmp)
            result = self.run_busy(base, busy_from=4)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = (base / "out/summary.tsv").read_text()
            self.assertIn("wave_1_contaminated\tbusy_host:cargo\n", summary)
            self.assertNotIn("wave_0_contaminated", summary)
            self.assertIn("4242", (base / "out/wave-1/busy-host-processes.txt").read_text())
            self.assertIn("777", (base / "out/resident-pids.txt").read_text().split())

    def test_a_host_that_turns_busy_during_the_build_refuses_before_any_vm(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            base = Path(tmp)
            result = self.run_busy(base, busy_from=2)
            self.assertEqual(result.returncode, 72, result.stderr)
            self.assertFalse((base / "out/commands.jsonl").exists())
            self.assertFalse((base / "out/wave-0").exists())


if __name__ == "__main__":
    unittest.main()
