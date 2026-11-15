#!/usr/bin/env python3
"""Tests for the installed-bytes comparison in published-installed-boot.py."""
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("published-installed-boot.py")
spec = importlib.util.spec_from_file_location("published_installed_boot", SCRIPT)
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)

DARWIN = "aarch64-apple-darwin"
LINUX = "x86_64-unknown-linux-gnu"


def macho(code, signature, trailing=b""):
    """A thin 64-bit Mach-O: header, __LINKEDIT, LC_CODE_SIGNATURE, code, signature."""
    dataoff = 32 + 72 + 16 + len(code)
    header = struct.pack("<IiiIIIII", boot.MH_MAGIC_64, 0x0100000C, 0, 2, 2, 88, 0, 0)
    linkedit = struct.pack("<II16sQQQQiiII", boot.LC_SEGMENT_64, 72, b"__LINKEDIT",
                           0, len(signature), dataoff, len(signature), 1, 1, 0, 0)
    sigcmd = struct.pack("<IIII", boot.LC_CODE_SIGNATURE, 16, dataoff, len(signature))
    return header + linkedit + sigcmd + code + signature + trailing


def tarball(path, members, target):
    with tarfile.open(path, "w:gz") as tar:
        root = tarfile.TarInfo(f"mvmctl-{target}")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        for name, data in members.items():
            info = tarfile.TarInfo(f"mvmctl-{target}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


class UnsignedDigest(unittest.TestCase):
    CODE = bytes(range(256)) * 2

    def test_a_resigned_file_has_the_same_digest_but_other_bytes(self):
        original = macho(self.CODE, b"S" * 100)
        resigned = macho(self.CODE, b"T" * 140)
        self.assertNotEqual(original, resigned)
        self.assertIsNotNone(boot.unsigned_macho_digest(original))
        self.assertEqual(boot.unsigned_macho_digest(original),
                         boot.unsigned_macho_digest(resigned))

    def test_a_changed_code_byte_changes_the_digest(self):
        changed = bytearray(self.CODE)
        changed[10] ^= 1
        self.assertNotEqual(boot.unsigned_macho_digest(macho(self.CODE, b"S" * 100)),
                            boot.unsigned_macho_digest(macho(bytes(changed), b"S" * 100)))

    def test_a_changed_header_byte_outside_the_masked_fields_changes_the_digest(self):
        data = bytearray(macho(self.CODE, b"S" * 100))
        data[4] ^= 1  # cputype
        self.assertNotEqual(boot.unsigned_macho_digest(macho(self.CODE, b"S" * 100)),
                            boot.unsigned_macho_digest(bytes(data)))

    def test_bytes_after_the_signature_are_not_described(self):
        self.assertIsNone(boot.unsigned_macho_digest(
            macho(self.CODE, b"S" * 100, trailing=b"hidden")))

    def test_anything_that_is_not_a_thin_macho_is_not_described(self):
        for data in (b"", b"\x7fELF" + bytes(60), b"#!/bin/sh\n", boot.MH_MAGIC_64.to_bytes(4, "little")):
            self.assertIsNone(boot.unsigned_macho_digest(data), data[:8])

    def test_a_macho_without_a_signature_command_is_not_described(self):
        data = bytearray(macho(self.CODE, b"S" * 100))
        struct.pack_into("<I", data, 32 + 72, 0x2)  # LC_SYMTAB in place of LC_CODE_SIGNATURE
        self.assertIsNone(boot.unsigned_macho_digest(bytes(data)))


class InstalledMatches(unittest.TestCase):
    def check(self, installed, published, unsigned):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mvmctl"
            path.write_bytes(installed)
            return boot.installed_matches(path, hashlib.sha256(published).hexdigest(), unsigned)

    def test_identical_bytes_match(self):
        data = macho(b"C" * 300, b"S" * 100)
        self.assertTrue(self.check(data, data, None))

    def test_a_resigned_file_matches_only_with_its_unsigned_digest(self):
        published = macho(b"C" * 300, b"S" * 100)
        installed = macho(b"C" * 300, b"T" * 140)
        digest = boot.unsigned_macho_digest(published)
        self.assertTrue(self.check(installed, published, digest))
        self.assertFalse(self.check(installed, published, None))

    def test_changed_code_never_matches(self):
        published = macho(b"C" * 300, b"S" * 100)
        installed = macho(b"D" * 300, b"S" * 100)
        self.assertFalse(self.check(installed, published, boot.unsigned_macho_digest(published)))


class InstalledHashes(unittest.TestCase):
    TAG = "v1"

    def layout(self, tmp, installed_cli, target):
        home = (Path(tmp) / "home").resolve()
        base = home / ".local/bin"
        (base / "guest-runtime").mkdir(parents=True)
        archives = Path(tmp) / "archives"
        archives.mkdir()
        published = macho(b"C" * 300, b"S" * 100)
        tarball(archives / f"mvmctl-{target}.tar.gz",
                {"mvmctl": published, "README.md": b"hi\n"}, target)
        runtime = b"guest runtime"
        (archives / f"mvm-guest-bins-{self.TAG}.tar.gz").write_bytes(runtime)
        (base / "guest-runtime" / f"mvm-guest-bins-{self.TAG}.tar.gz").write_bytes(runtime)
        (base / "mvmctl").write_bytes(installed_cli)
        (base / "README.md").write_bytes(b"hi\n")
        return home, archives

    def run_case(self, installed_cli, target):
        with tempfile.TemporaryDirectory() as tmp:
            home, archives = self.layout(tmp, installed_cli, target)
            return boot.installed_hashes(home, archives, target, self.TAG)

    def test_an_unmodified_install_passes_on_either_platform(self):
        published = macho(b"C" * 300, b"S" * 100)
        for target in (DARWIN, LINUX):
            with self.subTest(target=target):
                paths = {item["path"] for item in self.run_case(published, target)}
                self.assertIn("mvmctl", paths)

    def test_a_resigned_install_passes_on_macos(self):
        self.run_case(macho(b"C" * 300, b"T" * 140), DARWIN)

    def test_a_resigned_install_is_refused_off_macos(self):
        with self.assertRaisesRegex(ValueError, "installed entrypoint mismatch"):
            self.run_case(macho(b"C" * 300, b"T" * 140), LINUX)

    def test_a_modified_cli_is_refused_on_macos(self):
        with self.assertRaisesRegex(ValueError, "installed entrypoint mismatch"):
            self.run_case(macho(b"X" * 300, b"S" * 100), DARWIN)


if __name__ == "__main__":
    unittest.main()
