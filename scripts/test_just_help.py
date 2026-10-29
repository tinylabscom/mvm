"""Bare command groups must show help, never run their first action."""

import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


def just(*args):
    return subprocess.run(
        ["just", "--color", "never", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout


class JustHelpTests(unittest.TestCase):
    def test_bare_groups_list_their_recipes(self):
        modules = json.loads(just("--dump", "--dump-format", "json"))["modules"]
        for command, module in [("docs", "site"), *[(m, m) for m in modules]]:
            with self.subTest(command=command):
                # Guard the execution path before running it: a regression must
                # fail safely rather than install tools or publish a release.
                dry_run = subprocess.run(
                    ["just", "--dry-run", command],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(dry_run.stderr.strip(), f"just --list {module}")
                expected = just("--list", module)
                self.assertIn("Available recipes:", expected)
                self.assertEqual(just(command), expected)


if __name__ == "__main__":
    unittest.main()
