"""Hermetic generation tests, not signature or real package-install smokes."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "render_packages", Path(__file__).with_name("render-packages.py")
)
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.out = self.root / "output"
        self.version = "1.2.3"
        self.guest = f"mvm-guest-bins-v{self.version}.tar.gz"
        self.names = [
            f"mvmctl-{arch}-unknown-linux-gnu.tar.gz" for arch in renderer.HOSTS
        ] + [self.guest]
        rows = []
        for name in self.names:
            artifact = self.assets / name
            artifact.write_bytes(f"hermetic test bytes: {name}".encode())
            (self.assets / (name + ".bundle")).write_text("test bundle")
            row = f"{renderer.digest(artifact)}  {name}\n"
            rows.append(row)
            if name == self.guest:
                (self.assets / (name + ".sha256")).write_text(row)
        self.manifest = self.assets / "checksums-sha256.txt"
        self.manifest.write_text("".join(rows))
        (self.assets / "checksums-sha256.txt.bundle").write_text("test bundle")

    def render(self):
        renderer.render(self.version, self.assets, self.out)

    def test_pinned_recipes_and_exact_tag_verification(self):
        with patch.object(renderer.subprocess, "run") as verify:
            self.render()
        self.assertEqual(verify.call_count, 4)
        for call in verify.call_args_list:
            args = call.args[0]
            self.assertEqual(args[:2], ["cosign", "verify-blob"])
            self.assertIn(
                f"{renderer.REPO}/.github/workflows/release.yml@refs/tags/v1.2.3",
                args,
            )
            self.assertIn("https://token.actions.githubusercontent.com", args)
            self.assertTrue(call.kwargs["check"])
        aur = (self.out / "PKGBUILD").read_text()
        nix = (self.out / "package.nix").read_text()
        for text in (aur, nix):
            names = self.names if text == nix else [
                name for name in self.names if "aarch64" not in name
            ]
            for name in names:
                self.assertIn(renderer.digest(self.assets / name), text)
            for suffix in (".sha256", ".bundle"):
                self.assertIn(renderer.digest(self.assets / (self.guest + suffix)), text)
            for binary in renderer.HOST_BINS:
                self.assertIn(binary, text)
            self.assertIn("libmvm_hostlib.so", text)
            self.assertIn("lib/mvmctl", text)
            self.assertIn("guest-runtime", text)
            self.assertNotIn("runtime-overlay", text)
            self.assertNotIn("@@", text)
            self.assertNotIn("SKIP", text)
            self.assertNotIn("fakeHash", text)
        self.assertIn("arch=('x86_64')", aur)
        self.assertIn('noextract=("$_guest")', aur)
        self.assertIn("{ lib, stdenv, fetchurl, autoPatchelfHook }:", nix)
        self.assertNotIn("import ../", nix)
        subprocess.run(["bash", "-n", str(self.out / "PKGBUILD")], check=True)
        original = (aur, nix)
        with patch.object(renderer.subprocess, "run"):
            self.render()
        self.assertEqual(original, tuple(
            (self.out / name).read_text() for name in ("PKGBUILD", "package.nix")
        ))

    def test_rejects_signature_failure_at_every_verification(self):
        for failure in range(4):
            with self.subTest(failure=failure):
                results = [None] * failure + [subprocess.CalledProcessError(1, "cosign")]
                with patch.object(renderer.subprocess, "run", side_effect=results):
                    with self.assertRaises(subprocess.CalledProcessError):
                        self.render()
                self.assertFalse(self.out.exists())

    def test_no_verifier_is_not_an_unsigned_fallback(self):
        with patch.object(renderer.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                self.render()
        self.assertFalse(self.out.exists())

    def test_refuses_tampered_host_and_guest_archives(self):
        for name in self.names:
            with self.subTest(name=name):
                artifact = self.assets / name
                original = artifact.read_bytes()
                artifact.write_bytes(b"tampered")
                with patch.object(renderer.subprocess, "run"):
                    with self.assertRaisesRegex(ValueError, "digest mismatch"):
                        self.render()
                artifact.write_bytes(original)
                self.assertFalse(self.out.exists())

    def test_refuses_missing_guest_archive(self):
        (self.assets / self.guest).unlink()
        with patch.object(renderer.subprocess, "run"):
            with self.assertRaises(FileNotFoundError):
                self.render()
        self.assertFalse(self.out.exists())

    def test_refuses_missing_signature_bundles(self):
        for name in ["checksums-sha256.txt", *self.names]:
            with self.subTest(name=name):
                bundle = self.assets / (name + ".bundle")
                contents = bundle.read_bytes()
                bundle.unlink()
                with patch.object(renderer.subprocess, "run"):
                    with self.assertRaisesRegex(FileNotFoundError, "required signed"):
                        self.render()
                bundle.write_bytes(contents)
                self.assertFalse(self.out.exists())

    def test_missing_release_fails_through_cli_without_creating_recipes(self):
        result = subprocess.run([
            "python3", str(renderer.HERE / "render-packages.py"),
            "--version", "0.23.1",
            "--assets-dir", str(self.root / "absent-release"),
            "--out-dir", str(self.out),
        ], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required signed release asset missing", result.stderr)
        self.assertFalse(self.out.exists())

    def test_refuses_ambiguous_manifest_and_wrong_sidecar(self):
        original = self.manifest.read_text()
        self.manifest.write_text(original + original)
        with patch.object(renderer.subprocess, "run"):
            with self.assertRaisesRegex(ValueError, "duplicate"):
                self.render()
        self.manifest.write_text(original)
        (self.assets / (self.guest + ".sha256")).write_text("")
        with patch.object(renderer.subprocess, "run"):
            with self.assertRaisesRegex(ValueError, "disagrees"):
                self.render()
        self.assertFalse(self.out.exists())

    def test_refuses_version_injection_before_verification(self):
        for version in ("v1.2.3", "../1.2.3", "1.2.3;echo bad", "latest"):
            with self.subTest(version=version):
                with patch.object(renderer.subprocess, "run") as verify:
                    with self.assertRaises(ValueError):
                        renderer.render(version, self.assets, self.out)
                    verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
