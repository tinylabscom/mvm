"""Hermetic cleanup witnesses: fake CLI only, no VM or build commands."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/e2e-documented-surface.sh"


def function(source, name):
    start = source.index(f"{name}() {{")
    return source[start : source.index("\n}\n", start) + 3]


class DocumentedCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mvm-cleanup-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.name = f"cleanup-test-{uuid.uuid4().hex}"
        self.baseline = self.home / ".e2e-machines-before"
        self.baseline.write_text("existing\n")
        self.evidence = self.home / "vms" / self.name / "retained-evidence"
        self.evidence.parent.mkdir(parents=True)
        self.evidence.write_text("must survive uncertain cleanup")
        self.existing = self.home / "vms/existing/retained-evidence"
        self.existing.parent.mkdir(parents=True)
        self.existing.write_text("not created by this run")
        self.log = self.root / "calls.jsonl"
        target = self.root / "target"
        cli = target / "debug/mvmctl"
        cli.parent.mkdir(parents=True)
        cli.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, shutil, sys\n"
            "args = sys.argv[1:]\n"
            "assert os.environ['MVM_HOME'] == os.environ['TEST_HOME']\n"
            "with open(os.environ['TEST_CALLS'], 'a') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if args == ['machine', 'ls']:\n"
            "    print('NAME STATUS')\n"
            "    print('existing running')\n"
            "    print(os.environ['TEST_NAME'] + ' running')\n"
            "    sys.exit(9 if os.environ.get('FAIL_LIST') else 0)\n"
            "assert args[0] == 'machine' and args[1] in ('stop', 'rm')\n"
            "assert args[2] in ('existing', os.environ['TEST_NAME'])\n"
            "if os.environ.get('FAIL_' + args[1].upper()):\n"
            "    sys.exit(3)\n"
            "if args[1] == 'rm':\n"
            "    shutil.rmtree(pathlib.Path(os.environ['MVM_HOME']) / 'vms' / args[2])\n"
        )
        cli.chmod(0o755)
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.root),
            "TMPDIR": str(self.root),
            "CARGO_TARGET_DIR": str(target),
            "MVM_E2E_HOME": str(self.home),
            "MVM_E2E_PROFILE": "dev",
            "MVM_E2E_FOLLOW": "0",
            "TEST_HOME": str(self.home),
            "TEST_NAME": self.name,
            "TEST_CALLS": str(self.log),
        }
        self.cli = cli

    def clean_only(self, **overrides):
        # Execute the real early cleanup path, which exits before any build.
        return subprocess.run(
            ["bash", str(SCRIPT), "--clean-only"],
            env=self.env | overrides,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def exit_seam(self, command, **overrides):
        # Execute the unchanged production functions and EXIT trap without
        # entering the live build/suite body. Only unrelated timing/watch helpers
        # are stubs. The full --clean-only entrypoint is exercised separately.
        source = SCRIPT.read_text()
        names = [
            "ensure_private_home",
            "machine_names",
            "snapshot_machines",
            "reap",
            "start_watcher",
        ]
        if "cleanup_failure() {" in source:
            names.append("cleanup_failure")
        if "reap_orphan_supervisors() {" in source:
            names.append("reap_orphan_supervisors")
        functions = "\n".join(function(source, name) for name in names)
        shell = (
            "set -euo pipefail\n"
            'E2E_HOME="$MVM_E2E_HOME"\n'
            'MVMCTL="$TEST_CLI"\n'
            'SNAPSHOT="$E2E_HOME/.e2e-machines-before"\n'
            "CLEANUP_BLOCKED=0\nREAPED_NAMES=''\n"
            + functions
            + "\nstop_watcher() { :; }\n"
            'e2e_phase_summary() { printf "%s\\n" "$1" > "$TEST_PHASE_SUMMARY"; '
            '[[ "${FAIL_TIMINGS:-0}" == 0 ]]; }\n'
            "release_lock() { :; }\n"
            + function(source, "on_exit")
            + "\ntrap on_exit EXIT\n"
            + command
        )
        return subprocess.run(
            ["bash", "-c", shell],
            env=self.env
            | {
                "TEST_CLI": str(self.cli),
                "TEST_PHASE_SUMMARY": str(self.root / "phase-summary"),
            }
            | overrides,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def calls(self, verb=None):
        calls = (
            [json.loads(line) for line in self.log.read_text().splitlines()]
            if self.log.exists()
            else []
        )
        return [call for call in calls if verb is None or call[1] == verb]

    def assert_retained(self):
        self.assertEqual(self.evidence.read_text(), "must survive uncertain cleanup")
        self.assertTrue(self.existing.exists())

    def test_stop_failure_skips_removal_and_retains_evidence(self):
        result = self.clean_only(FAIL_STOP="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls("rm"), [])
        self.assert_retained()
        self.assertIn(str(self.home), result.stdout + result.stderr)

    def test_remove_failure_retains_evidence(self):
        result = self.clean_only(FAIL_RM="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.calls("stop")), 1)
        self.assertEqual(len(self.calls("rm")), 1)
        self.assert_retained()
        self.assertIn(str(self.home), result.stdout + result.stderr)

    def test_current_listing_failure_prevents_all_cleanup(self):
        result = self.clean_only(FAIL_LIST="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls("stop"), [])
        self.assertEqual(self.calls("rm"), [])
        self.assert_retained()

    def test_baseline_listing_failure_preserves_old_baseline_and_blocks_exit_cleanup(self):
        result = self.exit_seam("snapshot_machines\n", FAIL_LIST="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.baseline.read_text(), "existing\n")
        self.assertEqual(self.calls("stop"), [])
        self.assertEqual(self.calls("rm"), [])
        self.assert_retained()

    def test_missing_baseline_refuses_manual_cleanup(self):
        self.baseline.unlink()
        result = self.clean_only()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls(), [])
        self.assert_retained()

    def test_production_pre_run_transition_establishes_the_baseline_and_continues(self):
        self.baseline.unlink()
        source = SCRIPT.read_text()
        start = source.index('reap "pre-run"\n')
        end = source.index("# The TypeScript SDK scenarios", start)
        marker = self.root / "next-phase"
        result = self.exit_seam(
            source[start:end] + '\nprintf ready > "$NEXT_PHASE"\nexit 0\n',
            NEXT_PHASE=str(marker),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(marker.read_text(), "ready")
        self.assertEqual(self.calls("stop"), [])
        self.assertEqual(self.calls("rm"), [])
        self.assertEqual(
            set(self.baseline.read_text().splitlines()), {"existing", self.name}
        )
        self.assert_retained()

    def test_cleanup_failure_fails_an_otherwise_successful_suite(self):
        result = self.exit_seam("exit 0\n", FAIL_STOP="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls("rm"), [])
        self.assert_retained()

    def test_original_failure_or_interruption_status_survives_cleanup_failure(self):
        for status in [7, 70, 130]:
            with self.subTest(status=status):
                result = self.exit_seam(f"exit {status}\n", FAIL_STOP="1")
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assert_retained()
        self.assertEqual(self.calls("rm"), [])

    def test_successful_cleanup_keeps_success_and_existing_machine(self):
        result = self.exit_seam("exit 0\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.evidence.exists())
        self.assertTrue(self.existing.exists())
        self.assertEqual(self.calls("rm"), [["machine", "rm", self.name, "--yes"]])

    def test_failed_suite_still_reports_timings(self):
        result = self.exit_seam("exit 7\n", FAIL_STOP="1")
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertIn(
            "Documented surface phase timings",
            (self.root / "phase-summary").read_text(),
        )
        self.assert_retained()

    def test_timing_failure_does_not_skip_cleanup(self):
        result = self.exit_seam("exit 0\n", FAIL_TIMINGS="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.calls("stop")), 1)
        self.assertEqual(len(self.calls("rm")), 1)
        self.assertFalse(self.evidence.exists())
        self.assertTrue(self.existing.exists())

    def test_unrelated_same_name_process_survives_clean_only(self):
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys; print('ready', flush=True); sys.stdin.readline()",
                "mvm-hvf-supervisor",
                self.name,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.assertEqual(child.stdout.readline(), b"ready\n")
            result = self.clean_only()
            child.communicate(b"finish\n", timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(child.returncode, 0, "cleanup signalled an unrelated process")
            self.assertTrue(self.existing.exists())
        finally:
            if child.poll() is None:
                child.terminate()
            child.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
