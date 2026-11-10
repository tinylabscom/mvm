"""Offline, unsigned producer tests; no publisher identity is minted here."""

import hashlib
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("build-python-runtime-layer.py")
SPEC = importlib.util.spec_from_file_location("python_runtime_layer", SCRIPT)
PRODUCER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRODUCER)


@unittest.skipUnless(shutil.which("zstd"), "zstd required for the pinned upstream source")
class PythonRuntimeLayerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source.tar.zst"
        self.members = [
            ("python/install/lib/python3.13/importlib/__init__.py", b"# importlib\n", 0o644),
            ("python/install/bin/python3.13", b"\x7fELFtest", 0o755),
            ("python/install/lib/python3.13/encodings/__init__.py", b"# encodings\n", 0o644),
            ("python/install/lib/python3.13/test/irrelevant.py", b"skip", 0o644),
        ]
        self.write_source()

    def write_source(self):
        body = io.BytesIO()
        with tarfile.open(fileobj=body, mode="w") as archive:
            for name, data, mode in self.members:
                member = tarfile.TarInfo(name)
                member.mode = mode
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        self.source.write_bytes(
            subprocess.run(
                ["zstd", "-qc"], input=body.getvalue(), capture_output=True, check=True
            ).stdout
        )
        return hashlib.sha256(self.source.read_bytes()).hexdigest()

    def test_reproducible_runtime_only_plain_tar(self):
        expected = self.write_source()
        first = self.root / "first.tar"
        second = self.root / "second.tar"
        digest, size = PRODUCER.build(self.source, first, expected)
        self.assertEqual(PRODUCER.build(self.source, second, expected), (digest, size))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(), digest)
        with tarfile.open(first) as archive:
            self.assertEqual(
                archive.getnames(),
                [
                    "usr/bin/python3",
                    "usr/lib/python3.13/encodings/__init__.py",
                    "usr/lib/python3.13/importlib/__init__.py",
                ],
            )
            self.assertEqual(archive.getmember("usr/bin/python3").mode, 0o755)
            self.assertEqual(archive.getmember("usr/bin/python3").uid, 0)
        with self.assertRaisesRegex(ValueError, "already exists"):
            PRODUCER.build(self.source, first, expected)

    def test_wrong_source_digest_and_unsafe_selected_entry_never_publish(self):
        output = self.root / "layer.tar"
        with self.assertRaisesRegex(ValueError, "pinned digest"):
            PRODUCER.build(self.source, output, "0" * 64)
        self.assertFalse(output.exists())

        self.members[1] = ("python/install/bin/python3.13", b"\x7fELFtest", 0o4755)
        expected = self.write_source()
        with self.assertRaisesRegex(ValueError, "unsafe"):
            PRODUCER.build(self.source, output, expected)
        self.assertFalse(output.exists())

        self.members[1] = ("python/install/bin/python3.13", b"\x7fELFtest", 0o755)
        self.members.append(self.members[1])
        expected = self.write_source()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            PRODUCER.build(self.source, output, expected)
        self.assertFalse(output.exists())

    def test_command_line_help_does_not_interpret_url_percent_escapes(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pinned upstream tar.zst", result.stdout)


if __name__ == "__main__":
    unittest.main()
