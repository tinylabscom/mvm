"""Hermetic tests of the install witness, not release-publication evidence."""

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "installed_release", Path(__file__).with_name("smoke-installed-release.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InstalledReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.prefix = Path(self.temp.name).resolve()
        self.payload = self.prefix / "lib" / "mvmctl"
        self.payload.mkdir(parents=True)
        cli = self.payload / "mvmctl"
        cli.write_text('#!/bin/sh\nprintf "mvmctl 1.2.3\\n"\n')
        cli.chmod(0o755)
        (self.prefix / "bin").mkdir()
        (self.prefix / "bin" / "mvmctl").symlink_to(cli)
        runtime = self.payload / "guest-runtime"
        runtime.mkdir()
        self.archive = runtime / "mvm-guest-bins-v1.2.3.tar.gz"
        self.archive.write_bytes(b"hermetic archive fixture")
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        Path(str(self.archive) + ".sha256").write_text(f"{digest}  {self.archive.name}\n")
        Path(str(self.archive) + ".bundle").write_bytes(b"hermetic bundle fixture")
        self.library = Mock()
        self.library.mvm_hostlib_abi_version.return_value = (1 << 16) | 6
        self.enterContext(patch.object(MODULE.platform, "system", return_value="Linux"))
        self.loader = self.enterContext(
            patch.object(MODULE.ctypes, "CDLL", return_value=self.library)
        )

    def test_loads_library_beside_real_installed_executable(self):
        MODULE.smoke(self.prefix, "1.2.3")
        self.loader.assert_called_once_with(str(self.payload / "libmvm_hostlib.so"))
        self.library.mvm_hostlib_abi_version.assert_called_once_with()

    def test_wrong_cli_version_is_rejected_before_library_load(self):
        with self.assertRaisesRegex(RuntimeError, "installed version mismatch"):
            MODULE.smoke(self.prefix, "9.9.9")
        self.loader.assert_not_called()

    def test_darwin_loads_the_installed_dylib(self):
        with patch.object(MODULE.platform, "system", return_value="Darwin"):
            MODULE.smoke(self.prefix, "1.2.3")
        self.loader.assert_called_once_with(str(self.payload / "libmvm_hostlib.dylib"))

    def runtime_downloads(self, *, wrong_checksum=False):
        name = self.archive.name
        data = self.archive.read_bytes()
        digest = "0" * 64 if wrong_checksum else hashlib.sha256(data).hexdigest()
        files = {
            name: data,
            name + ".sha256": f"{digest}  {name}\n".encode(),
            name + ".bundle": b"verifier fixture",
            name + ".sha256.bundle": b"verifier fixture",
        }

        def download(request, *, timeout):
            self.assertEqual(timeout, 60)
            self.assertTrue(request.full_url.startswith(
                "https://github.com/tinylabscom/mvm/releases/download/v1.2.3/"
            ))
            return io.BytesIO(files[request.full_url.rsplit("/", 1)[1]])

        return download

    def test_fetched_runtime_is_authenticated_by_the_installed_cli(self):
        with patch.object(MODULE.urllib.request, "urlopen", side_effect=self.runtime_downloads()):
            with patch.object(MODULE.subprocess, "run") as verify:
                with patch.dict(os.environ, MVM_SKIP_COSIGN_VERIFY="1"):
                    digest = MODULE.fetch_verified_runtime(self.payload / "mvmctl", "1.2.3")
        self.assertEqual(digest, hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(verify.call_count, 2)
        for call, suffix in zip(verify.call_args_list, ("", ".sha256")):
            args = call.args[0]
            self.assertEqual(args[:3], [self.payload / "mvmctl", "env", "verify-release"])
            self.assertEqual(args[3].name, self.archive.name + suffix)
            self.assertEqual(args[4:], ["--tag", "v1.2.3"])
            self.assertTrue(call.kwargs["check"])
            self.assertNotIn("MVM_SKIP_COSIGN_VERIFY", call.kwargs["env"])
            self.assertFalse(args[3].exists(), "temporary downloads must be cleaned")

    def test_fetched_runtime_checksum_and_signature_failures_are_terminal(self):
        with patch.object(MODULE.urllib.request, "urlopen",
                          side_effect=self.runtime_downloads(wrong_checksum=True)):
            with patch.object(MODULE.subprocess, "run") as verify:
                with self.assertRaisesRegex(RuntimeError, "release checksum"):
                    MODULE.fetch_verified_runtime(self.payload / "mvmctl", "1.2.3")
                verify.assert_not_called()
        with patch.object(MODULE.urllib.request, "urlopen", side_effect=self.runtime_downloads()):
            with patch.object(MODULE.subprocess, "run",
                              side_effect=subprocess.CalledProcessError(1, "mvmctl")):
                with self.assertRaises(subprocess.CalledProcessError):
                    MODULE.fetch_verified_runtime(self.payload / "mvmctl", "1.2.3")

    def test_invalid_fetch_version_is_rejected_before_network_access(self):
        with patch.object(MODULE.urllib.request, "urlopen") as download:
            with self.assertRaisesRegex(RuntimeError, "invalid release version"):
                MODULE.fetch_verified_runtime(self.payload / "mvmctl", "../1.2.3")
            download.assert_not_called()

    def test_system_package_layout_loads_beside_binary_and_checks_private_runtime(self):
        public = self.prefix / "bin" / "mvmctl"
        public.unlink()
        (self.payload / "mvmctl").rename(public)
        MODULE.smoke(self.prefix, "1.2.3")
        self.loader.assert_called_once_with(str(public.parent / "libmvm_hostlib.so"))

    def test_incomplete_adjacent_runtime_does_not_fall_through_to_system_copy(self):
        public = self.prefix / "bin" / "mvmctl"
        public.unlink()
        (self.payload / "mvmctl").rename(public)
        adjacent = public.parent / "guest-runtime"
        adjacent.mkdir()
        (adjacent / (self.archive.name + ".bundle")).write_bytes(b"partial triplet")
        with self.assertRaises(FileNotFoundError):
            MODULE.smoke(self.prefix, "1.2.3")

    def test_incompatible_library_is_rejected(self):
        self.library.mvm_hostlib_abi_version.return_value = 2 << 16
        with self.assertRaisesRegex(RuntimeError, "incompatible installed hostlib"):
            MODULE.smoke(self.prefix, "1.2.3")

    def test_tampered_runtime_is_rejected(self):
        self.archive.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "differs from its release checksum"):
            MODULE.smoke(self.prefix, "1.2.3")

    def test_empty_bundle_is_rejected(self):
        Path(str(self.archive) + ".bundle").write_bytes(b"")
        with self.assertRaisesRegex(RuntimeError, "signature bundle is empty"):
            MODULE.smoke(self.prefix, "1.2.3")

    def test_missing_runtime_is_rejected(self):
        self.archive.unlink()
        with self.assertRaises(FileNotFoundError):
            MODULE.smoke(self.prefix, "1.2.3")


if __name__ == "__main__":
    unittest.main()
