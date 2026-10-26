"""Contract tests for the pinned macOS libkrun release-tier builder."""

import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from verify_macos_package import extract_package


SCRIPT = Path(__file__).with_name("build-libkrun-tier.sh")


class BuildLibkrunTierTests(unittest.TestCase):
    def alias_staging_command(self):
        commands = [
            line.strip()
            for line in SCRIPT.read_text().splitlines()
            if line.strip().startswith(("cp ", "ln -s "))
            and line.strip().endswith('"$output_dir/lib/libkrunfw.dylib"')
        ]
        self.assertEqual(len(commands), 1)
        return commands[0]

    def test_runtime_alias_is_a_distinct_regular_archive_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "mvmctl-aarch64-apple-darwin"
            libraries = payload / "lib"
            libraries.mkdir(parents=True)
            canonical = libraries / "libkrunfw.5.dylib"
            canonical.write_bytes(b"relocated libkrunfw fixture")
            # Exercise the real staging command, not the build or signing path.
            subprocess.run(
                ["bash", "-euc", self.alias_staging_command()],
                env={
                    **os.environ,
                    "output_dir": str(payload),
                    "libkrunfw": str(canonical),
                    "libkrunfw_abi": "5",
                },
                check=True,
                capture_output=True,
                text=True,
            )
            archive = root / "payload.tar.gz"
            subprocess.run(
                ["tar", "czf", str(archive), "-C", str(root), payload.name],
                check=True,
                capture_output=True,
                text=True,
            )
            unpacked = root / "unpacked"
            extract_package(archive, unpacked, payload.name)
            self.assertEqual(
                (unpacked / payload.name / "lib/libkrunfw.dylib").read_bytes(),
                canonical.read_bytes(),
            )
            name = f"{payload.name}/lib/libkrunfw.dylib"
            with tarfile.open(archive) as package:
                self.assertEqual(package.getnames().count(name), 1)
                alias = package.getmember(name)
                self.assertTrue(
                    alias.isfile(),
                    f"alias has archive type {alias.type!r}, link {alias.linkname!r}",
                )
                self.assertEqual(package.extractfile(alias).read(), canonical.read_bytes())
            self.assertFalse((libraries / "libkrunfw.dylib").is_symlink())
            self.assertNotEqual(
                (libraries / "libkrunfw.dylib").stat().st_ino, canonical.stat().st_ino
            )

    def test_runtime_alias_is_copied_after_loader_fixups(self):
        source = SCRIPT.read_text()
        alias = source.index(self.alias_staging_command())
        self.assertGreater(alias, source.rindex("install_name_tool"))
        self.assertGreater(alias, source.rindex('rewrite_dependency "$libkrun"'))

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
