import json
from pathlib import Path
import tempfile
import unittest

import owner_component_manifest as owner


class OwnerComponentManifestTests(unittest.TestCase):
    def test_write_binds_exact_bytes_version_target_and_commit(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            binary = root / owner.COMPONENT
            binary.write_bytes(b"final signed owner bytes")
            output = root / "owner-component.json"
            owner.write(binary, output, "1.2.3", "aarch64-apple-darwin", "a" * 40)
            value = json.loads(output.read_text())
            owner.validate(
                value,
                binary,
                "aarch64-apple-darwin",
                "1.2.3",
                "a" * 40,
            )
            binary.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                owner.validate(value, binary)

    def test_unknown_missing_or_changed_identity_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            binary = root / owner.COMPONENT
            binary.write_bytes(b"owner")
            output = root / "owner-component.json"
            owner.write(binary, output, "1", "target", "b" * 40)
            value = json.loads(output.read_text())
            for mutate in (
                lambda item: item.update(extra=True),
                lambda item: item.pop("component"),
                lambda item: item.update(component="other"),
                lambda item: item.update(source_commit="not-a-commit"),
                lambda item: item.update(sha256="0" * 63),
                lambda item: item.update(bootstrap_protocol_version=2),
            ):
                changed = value.copy()
                mutate(changed)
                with self.assertRaises(ValueError):
                    owner.validate(changed)


if __name__ == "__main__":
    unittest.main()
