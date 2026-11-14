import gzip
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "public_claude_native", Path(__file__).with_name("check-public-claude-native.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class NativeSmokeTests(unittest.TestCase):
    def test_opt_in_is_checked_before_any_native_work(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
                smoke.Blocked, "opt into native boot"):
            smoke.run(SimpleNamespace())

    def test_input_rejects_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original"
            original.write_bytes(b"public bytes")
            smoke.checked_file(original)
            symlink = root / "symlink"
            symlink.symlink_to(original)
            with self.assertRaises(smoke.Blocked):
                smoke.checked_file(symlink)
            hardlink = root / "hardlink"
            os.link(original, hardlink)
            with self.assertRaises(smoke.Blocked):
                smoke.checked_file(original)

    def test_inventory_requires_one_owned_running_or_stopped_machine(self):
        rows = [{"name": "someone-else", "status": "running"},
                {"name": "our-vm", "status": "running", "last_started_at": "now"}]
        self.assertEqual(smoke.inventory(json.dumps(rows), "our-vm")["status"], "running")
        for value in ("{}", "[]", json.dumps(rows + [rows[-1]])):
            with self.subTest(value=value), self.assertRaises(smoke.Blocked):
                smoke.inventory(value, "our-vm")

    def test_archive_only_requires_identical_raw_bytes_and_no_use_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            bundles = Path(directory)
            raw = b"signed public archive"
            with patch.object(smoke, "ARCHIVE_SHA256", smoke.hashlib.sha256(raw).hexdigest()):
                compressed = bundles / f"{smoke.ARCHIVE_SHA256}.mvmpkg.gz"
                compressed.write_bytes(gzip.compress(raw))
                uses = bundles / f".{smoke.ARCHIVE_SHA256}.uses"
                uses.mkdir()
                with compressed.open("rb") as stream:
                    before = smoke.digest(stream)
                smoke.archive_only(bundles, before)

                (uses / "unknown-vm").write_text("retained")
                with self.assertRaisesRegex(smoke.Blocked, "use claim"):
                    smoke.archive_only(bundles, before)
                (uses / "unknown-vm").unlink()
                compressed.write_bytes(gzip.compress(b"different archive"))
                with self.assertRaisesRegex(smoke.Blocked, "archive changed"):
                    smoke.archive_only(bundles, before)
                with compressed.open("rb") as stream:
                    changed = smoke.digest(stream)
                with self.assertRaisesRegex(smoke.Blocked, "retained archive bytes"):
                    smoke.archive_only(bundles, changed)
                compressed.write_bytes(gzip.compress(raw))
                extracted = bundles / smoke.ARCHIVE_SHA256
                extracted.mkdir()
                with self.assertRaisesRegex(smoke.Blocked, "extracted bundle"):
                    smoke.archive_only(bundles, before)

    def test_sandbox_policy_denies_ip_not_unix(self):
        policy = smoke.sandbox_policy()
        self.assertIn('(deny network-outbound (remote ip "*:*"))', policy)
        self.assertNotIn("deny network-outbound (remote unix", policy)
        self.assertEqual(smoke.FAKE_SECRET, b"test-only-no-network\n")


if __name__ == "__main__":
    unittest.main()
