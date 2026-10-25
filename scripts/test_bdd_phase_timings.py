#!/usr/bin/env python3
"""Run the real BDD recipe with recording stand-ins, never Cargo or live BDD."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
COMMANDS = [
    ["cargo", "build", "--bin", "mvmctl", "--features", "user"],
    ["cargo-fast.sh", "build", "-p", "xtask"],
    ["cargo-fast.sh", "build", "-p", "mvm-sdk", "--features", "schema",
     "--bin", "emit_workload_schema", "--bin", "emit_runtime_schema"],
    ["cargo-fast.sh", "build", "-p", "mvm-agentd", "--features", "schema",
     "--bin", "emit_protocol_schema"],
    ["cargo-fast.sh", "build", "-p", "mvm-core", "--features", "schema",
     "--bin", "emit_broker_schema"],
    ["cargo-fast.sh", "build", "-p", "mvm-sdk", "--bin", "emit_sdk_env",
     "--bin", "emit_sdk_errors", "--bin", "emit_sdk_ctors"],
    ["just", "sdk::install-typescript"],
    ["just", "sdk::build-typescript"],
    ["cargo-fast.sh", "test", "-p", "mvm-conformance", "--test", "conformance",
     "--features", "bdd"],
]
PHASES = ["mvmctl-build", "schema-emitters", "typescript-preparation",
          "conformance-compile-and-run"]
COMMAND_PHASES = [PHASES[0]] + [PHASES[1]] * 5 + [PHASES[2]] * 2 + [PHASES[3]]


class BddPhaseTimings(unittest.TestCase):
    def setUp(self):
        self.just = shutil.which("just")
        self.assertIsNotNone(self.just, "just is required for recipe coverage")
        directory = tempfile.TemporaryDirectory(prefix="mvm-bdd-timing-", dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        module = self.root / "just/bdd"
        module.mkdir(parents=True)
        shutil.copyfile(ROOT / "just/bdd/mod.just", module / "mod.just")
        (self.root / "justfile").write_text("mod bdd 'just/bdd/mod.just'\n")
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copyfile(ROOT / "scripts/e2e-phase-timings.sh",
                        scripts / "e2e-phase-timings.sh")
        for name in ["cargo", "cargo-fast.sh", "just"]:
            stub = scripts / name
            stub.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "log = Path('commands.jsonl')\n"
                "count = len(log.read_text().splitlines()) if log.exists() else 0\n"
                "with log.open('a') as stream:\n"
                "    stream.write(json.dumps([Path(sys.argv[0]).name, "
                "*sys.argv[1:]]) + '\\n')\n"
                "if 'CARGO_BIN_EXE_mvmctl' in os.environ:\n"
                "    Path('binary').write_text(os.environ['CARGO_BIN_EXE_mvmctl'])\n"
                "sys.exit(37 if count + 1 == int(os.environ.get('FAIL_AT', '0')) else 0)\n"
            )
            stub.chmod(0o755)

    def run_recipe(self, fail_at=0, summary=True, broken_summary=False):
        for name in ["commands.jsonl", "summary.md", "binary"]:
            (self.root / name).unlink(missing_ok=True)
        env = {**os.environ, "PATH": f"{self.root / 'scripts'}:{os.environ['PATH']}",
               "FAIL_AT": str(fail_at), "CARGO_TARGET_DIR": "custom target"}
        env.pop("GITHUB_STEP_SUMMARY", None)
        env.pop("CARGO_BIN_EXE_mvmctl", None)
        if summary:
            env["GITHUB_STEP_SUMMARY"] = str(
                self.root if broken_summary else self.root / "summary.md")
        return subprocess.run(
            [self.just, "--justfile", str(self.root / "justfile"), "bdd::run"],
            cwd=self.root, env=env, capture_output=True, text=True, check=False,
        )

    def commands(self):
        return [json.loads(line) for line in
                (self.root / "commands.jsonl").read_text().splitlines()]

    def test_success_preserves_exact_commands_order_and_runner_environment(self):
        result = self.run_recipe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.commands(), COMMANDS)
        self.assertEqual((self.root / "binary").read_text(), "custom target/debug/mvmctl")
        table = (self.root / "summary.md").read_text()
        for phase in PHASES:
            self.assertRegex(result.stdout, rf"\[phase\] name={phase} seconds=\d+")
            self.assertRegex(table, rf"\| {phase} \| \d+ \|")
        self.assertIn("exit=0", table)
        self.assertIn("| total |", table)

    def test_every_command_failure_stops_and_reports_original_status_and_phase(self):
        for index, phase in enumerate(COMMAND_PHASES, 1):
            with self.subTest(command=index):
                result = self.run_recipe(fail_at=index)
                self.assertEqual(result.returncode, 37, result.stderr)
                self.assertEqual(self.commands(), COMMANDS[:index])
                outcome = f"exit=37 failed-phase={phase}"
                self.assertIn(outcome, result.stdout)
                table = (self.root / "summary.md").read_text()
                self.assertIn(outcome, table)
                self.assertIn(f"| {phase} |", table)
                for unstarted in PHASES[PHASES.index(phase) + 1:]:
                    self.assertNotIn(f"| {unstarted} |", table)

    def test_local_run_needs_no_summary(self):
        result = self.run_recipe(summary=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[phase-result] exit=0", result.stdout)
        self.assertFalse((self.root / "summary.md").exists())

    def test_summary_write_failure_never_replaces_command_status(self):
        for fail_at, status in [(0, 0), (3, 37)]:
            with self.subTest(status=status):
                result = self.run_recipe(fail_at=fail_at, broken_summary=True)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn(f"[phase-result] exit={status}", result.stdout)

    def test_helper_reports_elapsed_seconds_and_supports_existing_callers(self):
        result = subprocess.run(
            ["bash", "-c",
             "set -euo pipefail; source scripts/e2e-phase-timings.sh; "
             "e2e_phase_summary empty; e2e_phase first; "
             "E2E_PHASE_STARTED=$((SECONDS - 7)); e2e_phase_summary Fixture"],
            cwd=self.root, env={k: v for k, v in os.environ.items()
                                if k != "GITHUB_STEP_SUMMARY"},
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[phase] name=first seconds=7", result.stdout)
        self.assertNotIn("[phase-result]", result.stdout)


if __name__ == "__main__":
    unittest.main()
