"""The synthetic CI signer cannot turn unchecked bytes into a base input."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("test-composable-base-input.py")
SPEC = importlib.util.spec_from_file_location("composable_base_input", SCRIPT)
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)


class SyntheticBaseInputTests(unittest.TestCase):
    def test_exact_signed_bytes_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "base"
            BASE.create(root)
            with patch.object(BASE.subprocess, "run") as cosign:
                BASE.verify(root, "https://github.com/test/workflow@refs/pull/1/merge")
                cosign.assert_called_once()
                args = cosign.call_args.args[0]
                self.assertIn("--certificate-identity", args)
                self.assertIn("--certificate-oidc-issuer", args)

                archive = root / "rootfs.tar.gz"
                payload = archive.read_bytes()
                archive.write_bytes(payload[:-1] + bytes([payload[-1] ^ 1]))
                with self.assertRaisesRegex(ValueError, "differs"):
                    BASE.verify(root, "test")

    def test_unknown_descriptor_fields_and_wrong_signer_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "base"
            BASE.create(root)
            manifest = root / "base.json"
            value = json.loads(manifest.read_text())
            value["publisher"] = "official"
            manifest.write_text(json.dumps(value))
            with patch.object(BASE.subprocess, "run"):
                with self.assertRaisesRegex(ValueError, "closed shape"):
                    BASE.verify(root, "test")
            with patch.object(BASE.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cosign")):
                with self.assertRaises(subprocess.CalledProcessError):
                    BASE.verify(root, "test")


if __name__ == "__main__":
    unittest.main()
