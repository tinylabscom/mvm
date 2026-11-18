"""Offline checks that live CLI commands see the artifacts the suite prepared."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


class LiveHomeTests(unittest.TestCase):
    def suite_environment(self, ambient_home, live_home, scenario_home=None):
        script = Path(__file__).with_name("e2e-documented-surface.sh").read_text()
        suite = script.index('SUITE_LOG="$(mktemp ')
        start = script.index('CARGO_BIN_EXE_mvmctl="$MVMCTL"', suite)
        end = script.index("  python3 scripts/run-bounded-command.py", start)
        prefix = script[start:end]
        capture = """
import json, os, subprocess, sys
homes = {key: os.environ[key] for key in ["MVM_HOME", "MVM_E2E_HOME"]}
child = subprocess.check_output(
    [sys.executable, "-c", "import os; print(os.environ['MVM_HOME'])"], text=True
).strip()
print(json.dumps({"runner": homes, "child_home": child}))
"""
        command = shlex.join([sys.executable, "-c", capture])
        if scenario_home is not None:
            command = f'env MVM_HOME="$SCENARIO_HOME" {command}'
        result = subprocess.run(
            ["bash", "-c", prefix + command],
            env={
                **os.environ,
                "MVMCTL": "/unused/mvmctl",
                "MVM_BDD_GUEST_BIN_DIR": "/unused/guest-bins",
                "ALLOWED_SKIPS": "",
                "MVM_HOME": str(ambient_home),
                "E2E_HOME": str(live_home),
                "SCENARIO_HOME": str(scenario_home),
            },
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def test_plain_cli_steps_use_the_prepared_live_home_not_the_ambient_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            live = root / "prepared suite home"
            actual = self.suite_environment(root / "unprepared ambient home", live)
            self.assertEqual(
                actual["runner"], {"MVM_HOME": str(live), "MVM_E2E_HOME": str(live)}
            )
            self.assertEqual(actual["child_home"], str(live))

    def test_explicit_scenario_home_still_overrides_the_suite_default(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario = root / "isolated scenario home"
            live = root / "prepared suite home"
            actual = self.suite_environment(root / "ambient", live, scenario)
            self.assertEqual(actual["runner"]["MVM_HOME"], str(scenario))
            self.assertEqual(actual["runner"]["MVM_E2E_HOME"], str(live))
            self.assertEqual(actual["child_home"], str(scenario))


class PostRunListingTests(unittest.TestCase):
    """The cleanup's machine listing: retried, and self-explaining when it fails."""

    def reap(self, stub_body):
        script = Path(__file__).with_name("e2e-documented-surface.sh").read_text()
        start = script.index('SNAPSHOT="$E2E_HOME')
        end = script.index("# Following the run.", start)
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            (home / "vms" / "bdd-leftover").mkdir(parents=True)
            (home / ".e2e-machines-before").write_text("keep\n")
            stub = Path(temporary) / "mvmctl"
            stub.write_text("#!/usr/bin/env bash\n" + stub_body.replace("@HOME@", temporary))
            stub.chmod(0o755)
            program = (
                "set -euo pipefail\n"
                f"E2E_HOME={shlex.quote(str(home))}\nMVMCTL={shlex.quote(str(stub))}\n"
                "sleep() { :; }\n" + script[start:end] + '\nrc=0; reap post-run || rc=$?; echo "reap=$rc"\n'
            )
            result = subprocess.run(
                ["bash", "-c", program], capture_output=True, text=True
            )
            return result, Path(temporary)

    LISTING = 'echo "NAME STATE"; echo "keep running"\n'

    def test_a_listing_that_succeeds_reaps_nothing_and_stays_quiet(self):
        result, _ = self.reap('if [ "$2" = ls ]; then ' + self.LISTING + "fi\n")
        self.assertIn("reap=0", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_a_listing_that_fails_once_is_retried(self):
        body = (
            'if [ "$2" = ls ]; then\n'
            '  if [ ! -e "@HOME@/seen" ]; then touch "@HOME@/seen"; echo boom >&2; exit 7; fi\n'
            + self.LISTING
            + "fi\n"
        )
        result, _ = self.reap(body)
        self.assertIn("reap=0", result.stdout)
        self.assertNotIn("!!!", result.stderr)

    def test_a_listing_that_always_fails_blocks_and_says_why(self):
        result, _ = self.reap('if [ "$2" = ls ]; then echo "state is unreadable" >&2; exit 7; fi\n')
        self.assertIn("reap=1", result.stdout)
        self.assertIn("could not list machines", result.stderr)
        self.assertIn("machine ls exited 7", result.stderr)
        self.assertIn("state is unreadable", result.stderr)
        self.assertIn("bdd-leftover", result.stderr)


if __name__ == "__main__":
    unittest.main()
