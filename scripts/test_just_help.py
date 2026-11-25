"""The recipe entry points: bare groups show usage, and `release` resumes."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
JUST = shutil.which("just")
# Recipes that are only variants: bare, they print usage and run nothing.
GROUPS = ["docs", "e2e", "setup", "mem"]
# A stand-in for git, gh and everything a release would run. It records its
# argv and answers the state questions from the environment, so no test can
# reach origin, GitHub or the checkout.
STUB = r"""#!/usr/bin/env python3
import os, sys
from pathlib import Path
name, args = Path(sys.argv[0]).name, sys.argv[1:]
with open(os.environ["CALLS"], "a") as log:
    log.write(" ".join([name, *args]) + "\n")
version = 'version = "%s"' % os.environ.get("MAIN_VERSION", "0.1.0")
if name == "git" and args[:1] == ["ls-remote"]:
    sys.exit(0 if os.environ.get("TAGGED") and "--tags" in args else 2)
if name == "git" and args[:1] == ["rev-parse"]:
    sys.exit(1)
if name == "git" and args[:1] == ["show"]:
    print(version)
if name == "gh" and args[:1] == ["api"]:
    print(version)
if name == "gh" and args[:2] == ["pr", "list"]:
    print(os.environ.get("PR", ""))
if name == "gh" and args[:2] == ["pr", "view"]:
    print("MERGED")
"""
READS = ("git ls-remote", "gh api", "gh pr list")


def just(*args, **kwargs):
    return subprocess.run(
        [JUST, "--color", "never", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        **kwargs,
    )


class JustHelpTests(unittest.TestCase):
    def test_bare_groups_print_usage_and_run_nothing(self):
        for group in GROUPS:
            with self.subTest(group=group):
                result = just(group)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(result.stdout.splitlines()), 1, result.stdout)
                self.assertTrue(result.stdout.startswith(f"usage: just {group} <"))

    def test_an_unknown_variant_is_refused(self):
        for recipe in ["build", "check", "lint", "clean", *GROUPS]:
            with self.subTest(recipe=recipe):
                result = just(recipe, "no-such-variant")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("no-such-variant", result.stderr)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="mvm-release-", dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.bin = Path(directory.name)
        for name in ["git", "gh", "cargo", "git-cliff", "sed", "rm", "sleep"]:
            stub = self.bin / name
            stub.write_text(STUB)
            stub.chmod(0o755)
        self.calls = self.bin / "calls"

    def release(self, *args, **state):
        self.calls.write_text("")
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}",
               "CALLS": str(self.calls), **state}
        result = just("release", *args, env=env)
        return result, self.calls.read_text().splitlines()

    def writes(self, calls):
        return [call for call in calls if not call.startswith(READS)]

    def test_a_version_that_is_not_a_release_is_refused_before_anything_runs(self):
        for args in [[], ["v0.99.0"], ["0.99"], ["0.99.0-beta"], ["--dry-run"]]:
            with self.subTest(args=args):
                result, calls = self.release(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_a_pushed_tag_leaves_nothing_but_the_follow_ups(self):
        result, calls = self.release("0.99.0", TAGGED="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.writes(calls), [])
        self.assertIn("publish-crates.yml -f tag=v0.99.0", result.stdout)

    def test_a_merged_bump_is_tagged_from_origin_main(self):
        result, calls = self.release("0.99.0-rc.1", MAIN_VERSION="0.99.0-rc.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.writes(calls), [
            "git fetch origin main",
            "git show origin/main:Cargo.toml",
            "git rev-parse -q --verify refs/tags/v0.99.0-rc.1",
            "git tag v0.99.0-rc.1 origin/main",
            "git push origin v0.99.0-rc.1",
        ])
        self.assertNotIn("publish-crates", result.stdout)

    def test_an_open_release_pr_is_merged_through_the_queue_then_tagged(self):
        # The stub answers every `git show` and `gh api` with one version, so
        # main reads as bumped only once the PR is reported merged.
        result, calls = self.release("0.99.0", PR="41 OPEN")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.writes(calls), [
            "gh pr merge 41 --auto --squash",
            "gh pr checks 41 --watch --fail-fast",
            "sleep 0",
            "gh pr view 41 --json state --jq .state",
            "git fetch origin main",
            "git show origin/main:Cargo.toml",
        ])
        self.assertIn("origin/main is not at version 0.99.0", result.stderr)

    def test_a_closed_release_pr_stops_the_release(self):
        result, calls = self.release("0.99.0", PR="41 CLOSED")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.writes(calls), [])

    def test_a_dry_run_changes_nothing_in_any_state(self):
        for state in [{}, {"PR": "41 OPEN"}, {"MAIN_VERSION": "0.99.0"}, {"TAGGED": "1"}]:
            with self.subTest(state=state):
                result, calls = self.release("--dry-run", "0.99.0", **state)
                self.assertEqual(result.returncode, 0, result.stderr)
                # Reading the checkout to say what a real run would refuse.
                reads = (*READS, "git status --porcelain", "git rev-parse")
                self.assertEqual([c for c in calls if not c.startswith(reads)], [])
                if not state.get("TAGGED"):
                    self.assertIn("[dry-run] git push origin v0.99.0", result.stdout)


if __name__ == "__main__":
    unittest.main()
