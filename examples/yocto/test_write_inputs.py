import hashlib
import tempfile
import unittest
from pathlib import Path

from write_inputs import digest_layer, inputs


class YoctoInputsTests(unittest.TestCase):
    def test_archive_and_layer_bytes_are_bound(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            archive = directory / "rootfs.tar.gz"
            archive.write_bytes(b"archive")
            layer = directory / "meta-mvm"
            layer.mkdir()
            recipe = layer / "image.bb"
            recipe.write_bytes(b"v1")

            first = inputs(archive, layer)
            self.assertEqual(
                first["rootfs_archive_sha256"], hashlib.sha256(b"archive").hexdigest()
            )
            self.assertEqual(first["layers"]["meta-mvm"], digest_layer(layer))
            recipe.write_bytes(b"v2")
            self.assertNotEqual(first["layers"]["meta-mvm"], digest_layer(layer))
            archive.write_bytes(b"other archive")
            self.assertNotEqual(
                first["rootfs_archive_sha256"],
                inputs(archive, layer)["rootfs_archive_sha256"],
            )

    def test_symlink_in_layer_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            layer = Path(root)
            (layer / "link").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                digest_layer(layer)


if __name__ == "__main__":
    unittest.main()
