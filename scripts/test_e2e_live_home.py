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


if __name__ == "__main__":
    unittest.main()
