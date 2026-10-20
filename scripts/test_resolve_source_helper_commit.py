"""Hermetic historical-source validation tests; no network or signing."""

import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "resolver", pathlib.Path(__file__).with_name("resolve-source-helper-commit.py")
)
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)
SOURCE = "a" * 40
WORKFLOW = "b" * 40


class SourceTests(unittest.TestCase):
    def test_exact_ancestor_and_current_commit(self):
        for source in (SOURCE, WORKFLOW):
            with patch.object(
                resolver.subprocess, "check_output", return_value=f"{source}\n"
            ) as rev, patch.object(resolver.subprocess, "run") as ancestor:
                self.assertEqual(resolver.resolve(source, WORKFLOW), source)
                rev.assert_called_once_with(
                    ["git", "rev-parse", "--verify", f"{source}^{{commit}}"], text=True,
                )
                ancestor.assert_called_once_with(
                    ["git", "merge-base", "--is-ancestor", source, WORKFLOW], check=True,
                )

    def test_invalid_inputs_never_invoke_git(self):
        for bad in ("", "main", "A" * 40, "a" * 39, "-option", SOURCE + "\n"):
            for source, workflow in ((bad, WORKFLOW), (SOURCE, bad)):
                with patch.object(resolver.subprocess, "check_output") as rev:
                    with self.assertRaises(ValueError):
                        resolver.resolve(source, workflow)
                    rev.assert_not_called()

    def test_tag_object_cannot_masquerade_as_source_commit(self):
        with patch.object(
            resolver.subprocess, "check_output", return_value=f"{WORKFLOW}\n"
        ), patch.object(resolver.subprocess, "run") as ancestor:
            with self.assertRaisesRegex(ValueError, "exact commit"):
                resolver.resolve(SOURCE, WORKFLOW)
            ancestor.assert_not_called()

    def test_unknown_source_and_non_ancestor_fail_closed(self):
        with patch.object(
            resolver.subprocess, "check_output",
            side_effect=subprocess.CalledProcessError(128, "git"),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                resolver.resolve(SOURCE, WORKFLOW)
        with patch.object(
            resolver.subprocess, "check_output", return_value=f"{SOURCE}\n"
        ), patch.object(
            resolver.subprocess, "run",
            side_effect=subprocess.CalledProcessError(1, "git"),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                resolver.resolve(SOURCE, WORKFLOW)

    def test_workflow_keeps_historical_source_out_of_publisher(self):
        workflow = (
            pathlib.Path(__file__).parent.parent
            / ".github/workflows/source-host-helpers.yml"
        ).read_text()
        source, rest = workflow.split("\n  build:", 1)
        build, publish = rest.split("\n  publish:", 1)
        self.assertIn("if: github.ref == 'refs/heads/main'", source)
        self.assertIn("fetch-depth: 0", source)
        self.assertIn('scripts/resolve-source-helper-commit.py', source)
        self.assertIn("needs: source", build)
        self.assertIn("ref: ${{ github.sha }}", build)
        self.assertIn("ref: ${{ needs.source.outputs.sha }}", build)
        self.assertIn("          cd helper-source\n", build)
        self.assertIn('test "$(git -C helper-source rev-parse HEAD)"', build)
        self.assertIn('${SOURCE_SHA}-${TARGET}', build)
        self.assertIn('"${SOURCE_SHA}" > "dist/${name}/SOURCE_COMMIT"', build)
        self.assertIn('"helper-source/target/${BUILD_TARGET}/release/mvm-network-endpoint"', build)
        self.assertIn('"helper-source/target/${BUILD_TARGET}/release/mvm-hvf-supervisor"', build)
        self.assertIn("needs: [source, build]", publish)
        self.assertIn("ref: ${{ github.sha }}", publish)
        self.assertNotIn("ref: ${{ needs.source.outputs.sha }}", publish)
        self.assertIn('--commit "${SOURCE_SHA}"', publish)
        self.assertIn("contents: read", source)
        self.assertEqual(workflow.count("persist-credentials: false"), 4)
        self.assertNotIn("id-token: write", source + build)
        self.assertIn("id-token: write", publish)


if __name__ == "__main__":
    unittest.main()
