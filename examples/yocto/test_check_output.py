import io
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path

from check_output import check, check_static_pie


def static_pie(tag=0, segment=2):
    program = bytearray(136)
    program[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", program, 16, 3, 183)
    struct.pack_into("<Q", program, 32, 64)
    struct.pack_into("<HH", program, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", program, 64, segment, 4, 120, 0, 0, 16, 16, 8)
    struct.pack_into("<Q", program, 120, tag)
    return bytes(program)


class YoctoOutputTests(unittest.TestCase):
    def test_only_the_static_program_is_installed(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            manifest = directory / "image.manifest"
            manifest.write_text("mvm-hello aarch64 1.0\n", encoding="utf-8")
            archive = directory / "rootfs.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                data = static_pie()
                info = tarfile.TarInfo("./srv/app/hello")
                info.mode = 0o755
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

            compressed, contents = check(manifest, archive)
            self.assertEqual(compressed, archive.stat().st_size)
            self.assertEqual(contents, len(data))

            manifest.write_text(
                "mvm-hello aarch64 1.0\nopenssl aarch64 3.2\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "openssl"):
                check(manifest, archive)

    def test_missing_entrypoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            manifest = directory / "image.manifest"
            manifest.write_text("mvm-hello aarch64 1.0\n", encoding="utf-8")
            archive = directory / "rootfs.tar.gz"
            with tarfile.open(archive, "w:gz"):
                pass
            with self.assertRaisesRegex(ValueError, "no executable"):
                check(manifest, archive)

    def test_loader_and_runtime_dependencies_are_refused(self):
        for label, binary in [
            ("loader", static_pie(segment=3)),
            ("runtime linker", static_pie(tag=1)),
            ("runtime linker", static_pie(tag=0x6FFFFEF5)),
            ("static PIE", b"not an ELF"),
        ]:
            with self.subTest(label=label, binary=binary):
                with self.assertRaisesRegex(ValueError, label):
                    check_static_pie(binary)


if __name__ == "__main__":
    unittest.main()
