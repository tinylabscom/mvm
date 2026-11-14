import io
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path

from check_output import check, check_static_pie


def static_pie(tag=0, segment=2, machine=183):
    program = bytearray(136)
    program[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", program, 16, 3, machine)
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

    def test_x86_64_requires_a_matching_static_pie(self):
        check_static_pie(static_pie(machine=62), "qemux86-64")
        with self.assertRaisesRegex(ValueError, "x86_64 static PIE"):
            check_static_pie(static_pie(), "qemux86-64")
        with self.assertRaisesRegex(ValueError, "aarch64 static PIE"):
            check_static_pie(static_pie(machine=62))

    def test_x86_64_archive_is_checked_for_its_target(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            manifest = directory / "image.manifest"
            manifest.write_text("mvm-hello x86_64 1.0\n", encoding="utf-8")
            archive = directory / "rootfs.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                data = static_pie(machine=62)
                info = tarfile.TarInfo("./srv/app/hello")
                info.mode = 0o755
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            self.assertEqual(check(manifest, archive, "qemux86-64")[1], len(data))
            with self.assertRaisesRegex(ValueError, "aarch64 static PIE"):
                check(manifest, archive)


if __name__ == "__main__":
    unittest.main()
