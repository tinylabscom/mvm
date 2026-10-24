#!/usr/bin/env python3
"""Mock-only benchmark contract tests; no Rust tools or runtime operations."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
MOCK = r'''
import json, os, signal, subprocess, sys, time
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as log:
    keys = ("HOME", "MVM_HOME", "TMPDIR", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS",
            "CARGO_INCREMENTAL", "RUSTUP_AUTO_INSTALL", "CARGO_NET_OFFLINE",
            "CARGO_HOME", "RUSTUP_HOME")
    log.write(json.dumps({"tool": name, "args": args,
                         "env": {key: os.environ.get(key) for key in keys}}) + "\n")
if name == "df":
    print("Filesystem 1024-blocks Used Available Capacity Mounted")
    print("disk 999999999 0 " + os.environ.get("FREE_KIB", "999999999") + " 0% /")
elif name == "time":
    if args == ["--version"]:
        print("GNU time")
    else:
        output = args[1]
        status = subprocess.call(args[4:])
        Path(output).write_text("1.23 / 456\n")
        sys.exit(status)
elif name == "setsid":
    os.setsid()
    os.execvp(args[0], args)
elif name == "timeout":
    if args == ["--version"]:
        print("GNU timeout")
    elif os.environ.get("TIMEOUT") == "1":
        sys.exit(124)
    else:
        os.execvp(args[3], args[3:])
elif name == "rm":
    os.execv("/bin/rm", ["rm"] + [a for a in args if a != "--one-file-system"])
elif name == "rustup":
    assert args[:3] == ["run", "--no-install", "nightly-2026-08-25"], args
    assert os.environ["RUSTUP_AUTO_INSTALL"] == "0"
    if "--version" in args:
        sys.exit(int(os.environ.get("PREFLIGHT_STATUS", "0")))
    arm = Path(os.environ["CARGO_TARGET_DIR"]).parent
    assert not (arm.parent / "workers-2").exists() or os.environ["CARGO_BUILD_JOBS"] == "2"
    if os.environ.get("BLOCK") == "1":
        print("MOCK_READY", flush=True)
        time.sleep(60)
    phase = "BUILD" if "--no-run" in args else "TEST"
    sys.exit(int(os.environ.get(phase + "_STATUS", "0")))
else:
    raise AssertionError("unexpected execution of " + name)
'''


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="mvm-worker-test-", dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.bin = self.root / "home/.cargo/bin"
        self.bin.mkdir(parents=True)
        for tool in ("df", "time", "setsid", "timeout", "rm", "rustup", "cargo", "cargo-nextest"):
            path = self.bin / tool
            path.write_text(f"#!{sys.executable}\n" + MOCK)
            path.chmod(0o755)
        # Absolute GNU time is intentionally mocked on macOS as well as Linux.
        source = (ROOT / "scripts/benchmark-cargo-workers.sh").read_text()
        self.script = self.root / "benchmark.sh"
        self.script.write_text(source.replace("/usr/bin/time", str(self.bin / "time")))
        (self.root / "Cargo.toml").write_text("[workspace]\n")
        (self.root / "rust-toolchain.toml").write_text('channel = "nightly-2026-08-25"\n')
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.base = self.runner / "mvm-w-123-1-1"
        self.calls = self.root / "calls.jsonl"
        self.summary = self.root / "summary.md"
        self.env = {
            **os.environ,
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.root / "home"),
            "RUNNER_TEMP": str(self.runner),
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "abc123",
            "BENCHMARK_COMMIT_SHA": "a" * 40,
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "CARGO_HOME": str(self.root / "existing-cargo"),
            "RUSTUP_HOME": str(self.root / "existing-rustup"),
            "CALLS": str(self.calls),
        }

    def run_script(self, **env):
        return subprocess.run(
            ["bash", str(self.script)], cwd=self.root, env={**self.env, **env},
            text=True, capture_output=True, timeout=15,
        )

    def records(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_two_cold_arms_and_fixed_test_concurrency(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        runs = [r for r in self.records() if r["tool"] == "rustup" and "run" in r["args"][4:]]
        self.assertEqual(len(runs), 4)
        for record, workers, build in zip(runs, ("2", "2", "6", "6"), (True, False, True, False)):
            self.assertEqual(record["args"], [
                "run", "--no-install", "nightly-2026-08-25", "cargo", "nextest", "run",
                "--workspace", "--all-targets", "--frozen", "--offline", "--test-threads", "2",
            ] + (["--no-run"] if build else []))
            env = record["env"]
            self.assertEqual(env["CARGO_BUILD_JOBS"], workers)
            self.assertEqual(env["CARGO_INCREMENTAL"], "0")
            self.assertEqual(env["RUSTUP_AUTO_INSTALL"], "0")
            self.assertEqual(env["CARGO_NET_OFFLINE"], "true")
            for key, leaf in (("HOME", "home"), ("MVM_HOME", "mvm"), ("TMPDIR", "tmp"), ("CARGO_TARGET_DIR", "target")):
                self.assertEqual(env[key], str(self.base / f"workers-{workers}" / leaf))
            for key in ("CARGO_HOME", "RUSTUP_HOME"):
                self.assertEqual(env[key], self.env[key])
        limits = [r["args"][:3] for r in self.records() if r["tool"] == "timeout" and "--version" not in r["args"]]
        self.assertEqual(limits, [["--signal=TERM", "--kill-after=10s", limit] for limit in ("20m", "8m", "20m", "8m")])
        self.assertFalse(self.base.exists())
        summary = self.summary.read_text()
        self.assertIn("a" * 40, summary)
        self.assertNotIn("abc123", summary)
        self.assertIn("NOT simultaneous total", summary)
        self.assertIn("1.23 / 456", summary)

    def test_build_failure_skips_tests_preserves_status_and_runs_other_arm(self):
        result = self.run_script(BUILD_STATUS="17")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(result.stdout.count("skipped (build failed)"), 2)
        self.assertIn("| 6 | build | 17 |", result.stdout)
        self.assertIn("no speedup conclusion", result.stdout)
        self.assertFalse(self.base.exists())

    def test_test_failure_preserves_status(self):
        result = self.run_script(TEST_STATUS="19")
        self.assertEqual(result.returncode, 19, result.stderr)
        self.assertIn("| 6 | test | 19 |", result.stdout)
        self.assertFalse(self.base.exists())

    def test_timeout_is_reported_and_cleanup_runs(self):
        result = self.run_script(TIMEOUT="1")
        self.assertEqual(result.returncode, 124)
        self.assertIn("| 2 | build | 124 |", result.stdout)
        self.assertIn("unavailable", result.stdout)
        self.assertFalse(self.base.exists())

    def test_preflight_failure_never_builds_or_installs(self):
        result = self.run_script(PREFLIGHT_STATUS="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("will not install", result.stdout)
        self.assertFalse(self.base.exists())
        for record in self.records():
            self.assertNotIn("install", record["args"])
            self.assertNotIn("--no-run", record["args"])

    def test_low_disk_refused_before_creation(self):
        result = self.run_script(FREE_KIB="100")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("80 GiB", result.stdout)
        self.assertFalse(self.base.exists())

    def test_missing_tool_is_reported_without_installing(self):
        (self.bin / "cargo-nextest").unlink()
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing installed tool: cargo-nextest", result.stdout)
        self.assertFalse(self.calls.exists())

    def test_optional_summary_and_foreign_paths_survive(self):
        target = self.root / "target"
        target.mkdir()
        sentinel = target / "keep"
        sentinel.write_text("warm cache")
        result = self.run_script(GITHUB_STEP_SUMMARY="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.summary.exists())
        self.assertEqual(sentinel.read_text(), "warm cache")
        self.assertFalse(self.base.exists())

    def test_existing_directory_is_not_reused_or_deleted(self):
        self.base.mkdir()
        sentinel = self.base / "keep"
        sentinel.write_text("foreign")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), "foreign")

    def test_foreign_base_and_symlink_are_never_removed(self):
        foreign = self.root / "foreign"
        foreign.mkdir()
        sentinel = foreign / "keep"
        sentinel.write_text("keep")
        self.base.symlink_to(foreign, target_is_directory=True)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.base.is_symlink())
        self.assertEqual(sentinel.read_text(), "keep")

    def test_invalid_run_id_cannot_escape_runner_temp(self):
        result = self.run_script(GITHUB_RUN_ID="../foreign")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_source_sha_is_required_not_workflow_sha(self):
        result = self.run_script(BENCHMARK_COMMIT_SHA="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checked-out source's full SHA", result.stdout)
        self.assertFalse(self.calls.exists())

    def test_termination_signals_owned_group_and_cleans(self):
        process = subprocess.Popen(
            ["bash", str(self.script)], cwd=self.root, env={**self.env, "BLOCK": "1"},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.addCleanup(lambda: process.poll() is None and process.kill())
        # Event handshake from the mock child, not a sleep/poll loop.
        for line in process.stdout:
            if line.strip() == "MOCK_READY":
                break
        else:
            self.fail("child did not start")
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 143, stderr)
        self.assertIn("terminated (143)", stdout)
        self.assertFalse(self.base.exists())


if __name__ == "__main__":
    unittest.main()
