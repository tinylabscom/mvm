"""The PR-only verifier stub must never authenticate a real release asset."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "package_fixture", Path(__file__).with_name("test-distro-package-assembly.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PackageFixtureTests(unittest.TestCase):
    def test_tag_and_dispatch_cannot_use_the_fixture(self):
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event), patch.dict(os.environ, GITHUB_EVENT_NAME=event):
                with self.assertRaisesRegex(SystemExit, "restricted to pull-request"):
                    MODULE.main()

    def test_version_cannot_escape_temporary_directory(self):
        with patch.dict(os.environ, GITHUB_EVENT_NAME="pull_request"):
            with patch.object(sys, "argv", ["fixture", "host", "target", "../1.2.3", "out"]):
                with self.assertRaisesRegex(SystemExit, "bare release version"):
                    MODULE.main()

    def test_stub_is_confined_and_temporary(self):
        real_run = subprocess.run
        observed = []
        original_path = os.environ["PATH"]

        def inspect(argv, *, env, check):
            self.assertTrue(check)
            self.assertEqual(argv[0], "bash")
            runtime = Path(argv[-1])
            observed.append(runtime)
            verifier = Path(env["PATH"].split(os.pathsep)[0]) / "cosign"
            archive = runtime / "mvm-guest-bins-v1.2.3.tar.gz"

            def verify(asset, identity="v1.2.3"):
                return real_run(
                    [str(verifier), "verify-blob", "--bundle", str(asset) + ".bundle",
                     "--certificate-identity",
                     "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/" + identity,
                     "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                     str(asset)], capture_output=True, text=True, env=env,
                ).returncode

            self.assertEqual(verify(archive), 0)
            self.assertEqual(verify(Path(str(archive) + ".sha256")), 0)
            self.assertNotEqual(verify(archive, "v9.9.9"), 0)
            self.assertNotEqual(verify(runtime / "mvmctl-host.tar.gz"), 0)

        with patch.dict(os.environ, GITHUB_EVENT_NAME="pull_request"):
            with patch.object(sys, "argv", ["fixture", "host", "target", "1.2.3", "out"]):
                with patch.object(MODULE.subprocess, "run", side_effect=inspect):
                    MODULE.main()
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].exists())
        self.assertEqual(os.environ["PATH"], original_path)


if __name__ == "__main__":
    unittest.main()
