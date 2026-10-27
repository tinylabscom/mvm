#!/usr/bin/env python3
"""Offline execution-gate regressions, not real signature/native acceptance.

The signature checker is deliberately synthetic: it accepts only a fixture
bundle token and records blob names. The packaged mvmctl is a shell stub that
writes a marker. No released binary, network, trust root or crypto is used.
"""

import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("verify-release-assets.sh")
HOST = "x86_64-unknown-linux-gnu"
OTHER = "aarch64-apple-darwin"
VERSION = "1.2.3-rc.1"


class AuthenticationGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.marker = self.root / "executed"
        self.log = self.root / "signatures"
        self.archive = f"mvmctl-{HOST}.tar.gz"
        self.runtime = f"mvm-guest-bins-v{VERSION}.tar.gz"
        self.cli_version = VERSION
        self.cli_exit = 0
        self.cli_output = None
        self.package(HOST)
        self.package(OTHER)
        for name in ("mvmctl_1.2.3-1_amd64.deb", "mvmctl-1.2.3-1.x86_64.rpm"):
            (self.assets / name).write_text("synthetic package\n")
            self.sign(name)
        self.tar(self.runtime, [("manifest.json", b"{}", 0o644)])
        self.sign(self.runtime)
        self.sidecar()
        (self.assets / "sbom.cdx.json").write_text("{}")
        self.sign("sbom.cdx.json")
        self.manifest()
        self.tool("uname", '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; esac\n')
        self.tool("cosign", """#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
blob = pathlib.Path(args[-1])
with open(os.environ["SIGNATURE_LOG"], "a") as log:
    log.write(blob.name + "\\n")
bundle = pathlib.Path(args[args.index("--bundle") + 1])
sys.exit(0 if blob.is_file() and bundle.read_text() == "synthetic-valid" else 1)
""")
        self.env = dict(os.environ, PATH=str(self.tools) + os.pathsep + os.environ["PATH"],
                        EXECUTION_MARKER=str(self.marker), SIGNATURE_LOG=str(self.log),
                        COSIGN_IDENTITY="synthetic-fixture-identity",
                        COSIGN_OIDC_ISSUER="synthetic-fixture-issuer")

    def tool(self, name, text):
        path = self.tools / name
        path.write_text(text)
        path.chmod(0o755)

    def tar(self, name, members):
        with tarfile.open(self.assets / name, "w:gz") as archive:
            for path, data, mode in members:
                entry = tarfile.TarInfo(path)
                entry.mode = mode
                if data is None:
                    entry.type = tarfile.DIRTYPE
                    archive.addfile(entry)
                    continue
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))

    def package(self, target, extra=()):
        output = self.cli_output if self.cli_output is not None else f"mvmctl {self.cli_version}"
        script = (f'#!/bin/sh\nprintf executed > "$EXECUTION_MARKER"\n'
                  f'printf "{output}\\n"\nexit {self.cli_exit}\n').encode()
        names = ["mvmctl", "mvm-network-endpoint"]
        if "apple" in target:
            names.append("mvm-hvf-supervisor")
        members = [(f"mvmctl-{target}/{name}", script, 0o755) for name in names]
        members.append((f"mvmctl-{target}/components.tsv", b"# component table fixture\n", 0o644))
        self.tar(f"mvmctl-{target}.tar.gz", members + list(extra))
        self.sign(f"mvmctl-{target}.tar.gz")

    def sign(self, name):
        (self.assets / (name + ".bundle")).write_text("synthetic-valid")

    def digest(self, name):
        return hashlib.sha256((self.assets / name).read_bytes()).hexdigest()

    def sidecar(self):
        (self.assets / (self.runtime + ".sha256")).write_text(
            f"{self.digest(self.runtime)}  {self.runtime}\n")
        self.sign(self.runtime + ".sha256")

    def manifest(self):
        names = sorted(path.name for path in self.assets.iterdir()
                       if path.name.endswith((".tar.gz", ".deb", ".rpm")))
        (self.assets / "checksums-sha256.txt").write_text(
            "".join(f"{self.digest(name)}  {name}\n" for name in names))
        self.sign("checksums-sha256.txt")

    def run_helper(self, cosign=True):
        args = ["bash", str(SCRIPT), "--assets-dir", str(self.assets),
                "--targets", f"{HOST} {OTHER}", "--expect-version", VERSION]
        if cosign:
            args.append("--cosign")
        return subprocess.run(args, env=self.env, text=True, capture_output=True, timeout=20)

    def blocked(self, diagnostic):
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(diagnostic, result.stderr)
        self.assertFalse(self.marker.exists(), result.stdout + result.stderr)

    def invalidate(self, name):
        (self.assets / (name + ".bundle")).write_text("synthetic-invalid")

    def test_complete_authenticated_inventory_probes(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.marker.exists())
        checked = set(self.log.read_text().splitlines())
        self.assertTrue({"checksums-sha256.txt", self.archive, self.runtime,
                         self.runtime + ".sha256", "sbom.cdx.json",
                         f"mvmctl-{OTHER}.tar.gz", "mvmctl_1.2.3-1_amd64.deb",
                         "mvmctl-1.2.3-1.x86_64.rpm"}.issubset(checked))

    def test_invalid_signed_manifest_blocks_probe(self):
        self.invalidate("checksums-sha256.txt")
        self.blocked("combined checksums manifest cosign verify-blob failed")

    def test_archive_checksum_blocks_probe(self):
        with (self.assets / self.archive).open("ab") as output:
            output.write(b"changed")
        self.blocked("sha256 mismatch")

    def test_archive_signature_blocks_probe(self):
        self.invalidate(self.archive)
        self.blocked("cosign verify-blob failed")

    def test_runtime_signature_blocks_probe(self):
        self.invalidate(self.runtime)
        self.blocked(self.runtime + " cosign verify-blob failed")

    def test_runtime_sidecar_signature_blocks_probe(self):
        self.invalidate(self.runtime + ".sha256")
        self.blocked(".sha256 cosign verify-blob failed")

    def test_runtime_sidecar_digest_blocks_probe(self):
        (self.assets / (self.runtime + ".sha256")).write_text("0  " + self.runtime)
        self.blocked("archive hashes to")

    def test_sbom_signature_blocks_probe(self):
        self.invalidate("sbom.cdx.json")
        self.blocked("sbom.cdx.json cosign verify-blob failed")

    def test_missing_inventory_blocks_probe(self):
        (self.assets / "mvmctl_1.2.3-1_amd64.deb").unlink()
        self.blocked("expected one mvmctl_*_amd64.deb")

    def test_later_target_signature_blocks_host_probe(self):
        self.invalidate(f"mvmctl-{OTHER}.tar.gz")
        self.blocked(f"[{OTHER}] cosign verify-blob failed")

    def test_declared_runtime_version_mismatch_blocks_probe(self):
        old = self.runtime
        self.runtime = "mvm-guest-bins-v1.2.3.tar.gz"
        for suffix in ("", ".bundle", ".sha256", ".sha256.bundle"):
            (self.assets / (old + suffix)).rename(self.assets / (self.runtime + suffix))
        self.sidecar()
        self.manifest()
        self.blocked("is not the guest runtime of version " + VERSION)

    def test_binary_version_mismatch_runs_only_after_authentication(self):
        self.cli_version = "9.9.9"
        self.package(HOST)
        self.manifest()
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--version mismatch", result.stderr)
        self.assertTrue(self.marker.exists())
        self.assertIn("sbom.cdx.json", self.log.read_text())

    def version_rejected_after_authentication(self, output, status=0):
        self.cli_output = output
        self.cli_exit = status
        self.package(HOST)
        self.manifest()
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--version mismatch", result.stderr)
        self.assertIn(f"exit status {status}", result.stderr)
        self.assertTrue(self.marker.exists())
        self.assertIn("sbom.cdx.json", self.log.read_text())
        if output != f"mvmctl {VERSION}":
            self.assertNotIn(output, result.stderr)

    def test_wrong_binary_prefix_rejected_after_authentication(self):
        self.version_rejected_after_authentication(f"other {VERSION}")

    def test_version_prefix_collision_rejected_after_authentication(self):
        self.version_rejected_after_authentication(f"mvmctl 9{VERSION}")

    def test_prerelease_suffix_collision_rejected_after_authentication(self):
        self.version_rejected_after_authentication(f"mvmctl {VERSION}0")

    def test_extra_output_rejected_after_authentication(self):
        self.version_rejected_after_authentication(f"mvmctl {VERSION}\\nextra-output")

    def test_nonzero_correct_version_rejected_after_authentication(self):
        self.version_rejected_after_authentication(f"mvmctl {VERSION}", status=7)

    def test_appledouble_companions_preserve_successful_probe(self):
        root = f"mvmctl-{HOST}"
        self.package(HOST, [(root, None, 0o755), (f"._{root}", b"metadata", 0o644),
                            (f"{root}/._mvmctl", b"metadata", 0o644)])
        self.manifest()
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.marker.exists())

    def test_orphan_appledouble_companion_blocks_probe(self):
        self.package(HOST, [(f"mvmctl-{HOST}/._orphan", b"metadata", 0o644)])
        self.manifest()
        self.blocked("archive envelope validation failed")

    def test_no_cosign_cannot_bypass_execution_gate(self):
        result = self.run_helper(cosign=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires --cosign", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_traversal_envelope_blocks_probe(self):
        self.package(HOST, [(f"mvmctl-{HOST}/../escaped", b"x", 0o644)])
        self.manifest()
        self.blocked("archive envelope validation failed")

    def test_wrong_envelope_blocks_probe(self):
        self.package(HOST, [("outside/file", b"x", 0o644)])
        self.manifest()
        self.blocked("archive envelope validation failed")

    def test_link_envelope_blocks_probe(self):
        with tarfile.open(self.assets / self.archive, "w:gz") as archive:
            entry = tarfile.TarInfo(f"mvmctl-{HOST}/mvmctl")
            entry.type = tarfile.SYMTYPE
            entry.linkname = str(self.marker)
            archive.addfile(entry)
        self.manifest()
        self.blocked("archive envelope validation failed")

    def test_diagnostics_accumulate_without_execution(self):
        self.invalidate(self.archive)
        self.invalidate("sbom.cdx.json")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"[{HOST}] cosign verify-blob failed", result.stderr)
        self.assertIn("sbom.cdx.json cosign verify-blob failed", result.stderr)
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
