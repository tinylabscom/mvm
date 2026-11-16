"""Offline SDK transfer witnesses: mocked GitHub transport, no native code loading."""

import argparse
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sdk_hostlib_artifact", ROOT / "scripts/release/sdk_hostlib_artifact.py")
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)


class TransferTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.library = b"fixture library, never loaded"
        self.env = {
            "GITHUB_REPOSITORY": "caller/sdk",
            "GITHUB_REPOSITORY_ID": "17",
            "GITHUB_RUN_ID": "42",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_SHA": "a" * 40,
        }
        self.args = argparse.Namespace(
            channel="npm", artifact_id="73", artifact_digest="",
            library_sha256=hashlib.sha256(self.library).hexdigest(),
            producer_attempt="2", payload=self.root / "hostlib-out")
        self.make_archive({SDK.LIBRARY: self.library})
        self.head = patch.object(SDK.subprocess, "check_output", return_value="a" * 40)
        self.head.start()
        self.addCleanup(self.head.stop)

    def make_archive(self, members):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        self.archive = stream.getvalue()
        self.args.artifact_digest = hashlib.sha256(self.archive).hexdigest()
        self.metadata = {
            "id": 73, "name": f"unsigned-{self.args.channel}-hostlib-2",
            "expired": False, "digest": "sha256:" + self.args.artifact_digest,
            "size_in_bytes": len(self.archive),
            "workflow_run": {
                "id": 42, "repository_id": 17, "head_repository_id": 17,
                "head_sha": "a" * 40,
            },
        }

    def fetch(self):
        with patch.object(SDK.TRANSPORT, "gh_json", return_value=self.metadata) as metadata, \
             patch.object(SDK.TRANSPORT, "_gh_download",
                          return_value=(io.BytesIO(self.archive), None)) as download:
            SDK.fetch(self.args, self.env)
        endpoint = "repos/caller/sdk/actions/artifacts/73"
        metadata.assert_called_once_with(endpoint)
        download.assert_called_once_with(endpoint)

    def test_both_channels_restore_only_platform_library(self):
        for selected in ("npm", "pypi"):
            with self.subTest(channel=selected):
                self.args.channel = selected
                self.args.payload = self.root / selected
                self.make_archive({SDK.LIBRARY: self.library})
                self.fetch()
                self.assertEqual(SDK.inventory(self.args.payload), self.args.library_sha256)
                self.assertEqual(
                    (self.args.payload / SDK.PLATFORM / SDK.LIBRARY).read_bytes(),
                    self.library)

    def test_wrong_channel_never_reaches_transport(self):
        self.args.channel = "npm\ninjected"
        with patch.object(SDK.TRANSPORT, "retrieve_artifact") as transfer:
            with self.assertRaisesRegex(ValueError, "channel"):
                SDK.fetch(self.args, self.env)
            transfer.assert_not_called()

    def test_wrong_raw_hash_does_not_stage_payload(self):
        self.args.library_sha256 = "0" * 64
        with self.assertRaisesRegex(ValueError, "raw host library"):
            self.fetch()
        self.assertFalse(self.args.payload.exists())

    def test_wrong_zip_hash_is_refused(self):
        self.archive += b"tamper"
        with self.assertRaisesRegex(ValueError, "ZIP digest mismatch"):
            self.fetch()
        self.assertFalse(self.args.payload.exists())

    def test_unexpected_member_is_refused(self):
        self.make_archive({SDK.LIBRARY: self.library, "producer.py": b"not executed"})
        with self.assertRaisesRegex(ValueError, "unexpected members"):
            self.fetch()
        self.assertFalse(self.args.payload.exists())

    def test_source_and_repository_mismatches_are_refused(self):
        for key, value in (("id", 99), ("repository_id", 99),
                           ("head_repository_id", 99), ("head_sha", "b" * 40)):
            with self.subTest(key=key):
                self.make_archive({SDK.LIBRARY: self.library})
                self.metadata["workflow_run"][key] = value
                with self.assertRaisesRegex(ValueError, "repository/run/source"):
                    self.fetch()

    def test_checkout_mismatch_never_downloads(self):
        with patch.object(SDK.subprocess, "check_output", return_value="b" * 40), \
             patch.object(SDK.TRANSPORT, "retrieve_artifact") as transfer:
            with self.assertRaisesRegex(ValueError, "checkout HEAD"):
                SDK.fetch(self.args, self.env)
            transfer.assert_not_called()

    def test_future_attempt_is_refused(self):
        self.args.producer_attempt = "3"
        with self.assertRaisesRegex(ValueError, "newer"):
            self.fetch()

    def test_prior_attempt_pinned_by_name_is_allowed(self):
        self.args.producer_attempt = "1"
        self.metadata["name"] = "unsigned-npm-hostlib-1"
        self.fetch()

    def test_size_limit_is_enforced(self):
        self.metadata["size_in_bytes"] = SDK.MAX_BYTES + 1
        with self.assertRaisesRegex(ValueError, "bounded transfer size"):
            self.fetch()

    def test_inventory_rejects_reports_and_symlinks(self):
        platform = self.args.payload / SDK.PLATFORM
        platform.mkdir(parents=True)
        library = platform / SDK.LIBRARY
        library.write_bytes(self.library)
        report = self.args.payload / "report.json"
        report.write_text("{}")
        with self.assertRaisesRegex(ValueError, "unexpected members"):
            SDK.inventory(self.args.payload)
        report.unlink()
        library.unlink()
        library.symlink_to(self.root / "other")
        with self.assertRaisesRegex(ValueError, "regular file"):
            SDK.inventory(self.args.payload)

    def test_existing_destination_is_not_overlaid(self):
        self.args.payload.mkdir()
        with self.assertRaises(FileExistsError):
            self.fetch()


class WorkflowTests(unittest.TestCase):
    def test_signer_is_fresh_and_secrets_are_step_scoped(self):
        workflow = (ROOT / ".github/workflows/sdk-macos-hostlib.yml").read_text()
        build, signer = workflow.split("\n  sign:\n", 1)
        self.assertEqual(workflow.count("runs-on: macos-15"), 2)
        self.assertEqual(workflow.count("persist-credentials: false"), 2)
        self.assertEqual(workflow.count("ref: ${{ github.sha }}"), 2)
        self.assertNotIn("${{ secrets.", build)
        self.assertNotIn("id-token:", workflow)
        for command in ("cargo ", "pip install", "npm ", "actions/cache", "rust-toolchain@"):
            self.assertNotIn(command, signer)
        self.assertEqual(signer.count("${{ secrets."), 6)
        self.assertIn("actions: read", signer)
        self.assertIn("--skip-unconfigured", signer)
        self.assertIn("!inputs.dry_run || github.ref_type == 'tag'", signer)
        self.assertIn("path: hostlib-out/darwin-arm64/libmvm_hostlib.dylib", build)
        self.assertIn("path: hostlib-out/", signer)


if __name__ == "__main__":
    unittest.main()
