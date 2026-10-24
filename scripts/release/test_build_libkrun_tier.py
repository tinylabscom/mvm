"""Contract tests for the pinned macOS libkrun release-tier builder."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("build-libkrun-tier.sh")


class BuildLibkrunTierTests(unittest.TestCase):
    def run_script(self, output, target):
        with tempfile.TemporaryDirectory() as runner_temp:
            return subprocess.run(
                [str(SCRIPT), str(output), target],
                env={**os.environ, "RUNNER_TEMP": runner_temp},
                text=True,
                capture_output=True,
                check=False,
            )

    def test_rejects_unsupported_release_target_before_fetching(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_script(Path(directory) / "out", "x86_64-apple-darwin")
        self.assertEqual(result.returncode, 2)
        self.assertIn("supports only aarch64-apple-darwin", result.stderr)

    def test_rejects_nonempty_output_before_fetching(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            output.mkdir()
            (output / "foreign").write_text("keep")
            result = self.run_script(output, "aarch64-apple-darwin")
            self.assertEqual((output / "foreign").read_text(), "keep")
        self.assertEqual(result.returncode, 1)
        self.assertIn("output directory must be empty", result.stderr)

    def test_release_pins_and_relocation_gates_are_concrete(self):
        source = SCRIPT.read_text()
        self.assertRegex(source, r'libkrun_commit="[0-9a-f]{40}"')
        self.assertRegex(source, r'libkrunfw_commit="[0-9a-f]{40}"')
        self.assertRegex(source, r'kernel_sha256="[0-9a-f]{64}"')
        self.assertIn("MACOSX_DEPLOYMENT_TARGET", source)
        self.assertIn("@executable_path/lib", source)
        self.assertIn("/opt/homebrew|/usr/local|mvm-libkrun-tier", source)
        self.assertIn("SOURCE-OFFER.txt", source)
        self.assertIn("libkrunfw-macos-host.patch", source)
        self.assertIn('CC_LINUX="zig cc -target aarch64-linux-musl"', source)
        self.assertIn('SYSROOT_LINUX="$scratch_root/zig-linux-sysroot"', source)
        self.assertIn("CARGO_PROFILE_RELEASE_STRIP=none", source)
        self.assertIn('BINDGEN_EXTRA_CLANG_ARGS="-isysroot $macos_sdk"', source)
        patch = SCRIPT.with_name("libkrunfw-macos-host.patch").read_text()
        self.assertIn("-mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)", patch)
        declared_and_body = patch.rsplit("@@ -0,0 +1,", 1)[1]
        declared, body = declared_and_body.split("@@", 1)
        added_lines = [line for line in body.splitlines() if line.startswith("+")]
        self.assertEqual(len(added_lines), int(declared.strip()))


if __name__ == "__main__":
    unittest.main()
