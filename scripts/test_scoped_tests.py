#!/usr/bin/env python3
"""Exercise the scoped-test recipe with an argv-recording Cargo stand-in."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class ScopedTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="mvm-scoped-", dir="/tmp")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        module = self.root / "just/tests"
        module.mkdir(parents=True)
        shutil.copyfile(ROOT / "just/tests/mod.just", module / "mod.just")
        (self.root / "justfile").write_text("mod tests 'just/tests/mod.just'\n")
        scripts = self.root / "scripts"
        scripts.mkdir()
        guard = scripts / "require-nextest.sh"
        guard.write_text('#!/bin/sh\nexit "${GUARD_STATUS:-0}"\n')
        guard.chmod(0o755)
        cargo = scripts / "cargo.sh"
        cargo.write_text(
            '#!/usr/bin/env python3\nimport json, os, sys\n'
            'from pathlib import Path\n'
            'Path("argv.json").write_text(json.dumps(sys.argv[1:]))\n'
            'sys.exit(int(os.environ.get("CARGO_STATUS", "0")))\n'
        )
        cargo.chmod(0o755)

    def run_recipe(self, *arguments, **environment):
        return subprocess.run(
            ["just", "--justfile", str(self.root / "justfile"), "tests::scoped", *arguments],
            cwd=self.root,
            env={**os.environ, **environment},
            capture_output=True,
            text=True,
            check=False,
        )

    def argv(self):
        return json.loads((self.root / "argv.json").read_text())

    def test_existing_crate_and_filter_calls_keep_their_selection(self):
        for args, expected in [
            (["mvm-core"], ["nextest", "run", "-p", "mvm-core"]),
            (["mvm-core", "roundtrip"], ["nextest", "run", "-p", "mvm-core", "-E", "test(roundtrip)"]),
        ]:
            with self.subTest(args=args):
                result = self.run_recipe(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.argv(), expected)

    def test_library_filter_avoids_unrelated_integration_targets(self):
        result = self.run_recipe("mvm-cli", "roundtrip", "--lib")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.argv(), ["nextest", "run", "-p", "mvm-cli", "--lib", "-E", "test(roundtrip)"])

    def test_one_integration_target_without_a_name_filter(self):
        result = self.run_recipe("mvmctl", "", "--test", "workspace_shard_isolation")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.argv(), ["nextest", "run", "-p", "mvmctl", "--test", "workspace_shard_isolation"])

    def test_arguments_are_data_not_shell_source(self):
        name = "dollar$(touch injected)' space"
        result = self.run_recipe("mvm-core", name, "--lib")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.argv()[-1], f"test({name})")
        self.assertFalse((self.root / "injected").exists())

    def test_failures_are_not_masked(self):
        self.assertNotEqual(self.run_recipe("mvm-core", GUARD_STATUS="7").returncode, 0)
        self.assertFalse((self.root / "argv.json").exists())
        self.assertNotEqual(self.run_recipe("mvm-core", CARGO_STATUS="9").returncode, 0)


if __name__ == "__main__":
    unittest.main()
