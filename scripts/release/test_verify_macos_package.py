"""Offline final-package policy tests: codesign is always mocked."""

import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import zipfile

import verify_macos_package as gate


def macho(kind=6, extra=b""):
    return b"\xcf\xfa\xed\xfe" + b"\0" * 8 + struct.pack("<I", kind) + extra


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / "package.whl"
        self.producer = self.root / "producer.json"
        self.notary = self.root / "notary.json"
        self.report = self.root / "inspection.json"
        self.data = macho()
        self.inventory = [{"path": "darwin-arm64/libmvm_hostlib.dylib",
                           "role": "code", "required_entitlements": [],
                           "sha256": hashlib.sha256(self.data).hexdigest()}]
        self.write_producer()
        self.pack()
        self.addCleanup(patch.stopall)
        patch.object(gate.platform, "system", return_value="Darwin").start()
        self.run = patch.object(gate.sign_macos, "run",
                                return_value=plistlib.dumps({}).decode()).start()
        self.diagnostic = patch.object(
            gate.sign_macos,
            "run_diagnostic",
            return_value="flags=0x10000(runtime)",
        ).start()

    def write_producer(self):
        self.producer.write_text(json.dumps({
            "status": "ProducerAdhocVerified", "notarized": False,
            "files": self.inventory}))

    def pack(self, files=None):
        with zipfile.ZipFile(self.archive, "w") as archive:
            for name, data in (files or {
                    "mvm/_native/libmvm_hostlib.dylib": self.data}).items():
                archive.writestr(name, data)

    def verify(self, notary=None, **kwargs):
        if kwargs.get("require_cli_inventory") or kwargs.get("require_owner_inventory"):
            kwargs.setdefault("owner_version", "1")
            kwargs.setdefault("owner_target", "aarch64-apple-darwin")
            kwargs.setdefault("owner_source_commit", "a" * 40)
        gate.verify(self.archive, self.producer, notary, self.report,
                    sdk_layout=True, **kwargs)

    def test_final_wheel_hash_and_strict_empty_entitlements(self):
        self.verify()
        report = json.loads(self.report.read_text())
        self.assertEqual(report["package_sha256"], gate.sha256(self.archive))
        self.assertEqual(report["files"][0]["sha256"], self.inventory[0]["sha256"])
        self.assertEqual(report["report_source"], str(self.producer))
        self.assertEqual(report["authority"], "package-inspection-only")
        self.assertEqual(self.run.call_args_list[0].args[:4],
                         ("codesign", "--verify", "--strict", "--all-architectures"))
        self.assertEqual(self.run.call_args_list[1].args[:5],
                         ("codesign", "-d", "--entitlements", "-", "--xml"))

    def test_unconfigured_uses_producer_not_accepted(self):
        self.notary.write_text('{"status":"Unconfigured"}')
        self.verify(self.notary)
        self.assertEqual(json.loads(self.report.read_text())["report_source"],
                         str(self.producer))

    def test_accepted_uses_final_not_producer_hash(self):
        self.data = macho(extra=b"signed")
        self.pack()
        self.notary.write_text(json.dumps({
            "status": "Accepted", "id": "submission", "team_id": "TEAM",
            "files": [{"path": self.inventory[0]["path"],
                       "sha256": hashlib.sha256(self.data).hexdigest()}]}))
        self.verify(self.notary)
        self.assertEqual(json.loads(self.report.read_text())["report_source"],
                         str(self.notary))

    def test_failure_unknown_and_incomplete_accepted_reject(self):
        for status in ("Invalid", "Rejected", "In Progress", "Accepted"):
            with self.subTest(status=status):
                self.notary.write_text(json.dumps({"status": status}))
                with self.assertRaises(ValueError):
                    self.verify(self.notary)
                self.assertFalse(self.report.exists())

    def test_tampering_extra_missing_and_ambiguous_reject(self):
        cases = [
            {"mvm/libmvm_hostlib.dylib": macho(extra=b"tamper")},
            {"mvm/libmvm_hostlib.dylib": self.data, "other": macho()},
            {"other": macho()},
        ]
        for files in cases:
            with self.subTest(files=list(files)):
                self.pack(files)
                with self.assertRaises(ValueError):
                    self.verify()
        self.pack()
        self.inventory.append(dict(self.inventory[0], path="other/libmvm_hostlib.dylib"))
        self.write_producer()
        with self.assertRaises(ValueError):
            self.verify()

    def test_code_entitlements_and_strict_failure_reject(self):
        self.run.return_value = plistlib.dumps({"com.apple.security.hypervisor": True}).decode()
        with self.assertRaises(RuntimeError):
            self.verify()
        self.run.side_effect = RuntimeError("strict failed")
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_required_cli_and_multislice_reject(self):
        with self.assertRaises(ValueError):
            self.verify(require_cli_inventory=True)
        self.pack({"mvm/libmvm_hostlib.dylib":
                   b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\0" * 8})
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_cli_roles_exact_entitlements(self):
        files = {
            "mvmctl": macho(2),
            "mvm-hvf-supervisor": macho(2),
            "mvm-hvf-run-owner": macho(2),
            "mvm-libkrun-supervisor": macho(2),
        }
        self.inventory = [{
            "path": name,
            "role": name if name in gate.sign_macos.ROLES else "code",
            "required_entitlements": gate.sign_macos.ROLES.get(name, []),
            "sha256": hashlib.sha256(data).hexdigest(),
        } for name, data in files.items()]
        self.write_producer()
        files["owner-component.json"] = json.dumps({
            "schema_version": 1,
            "component": "mvm-hvf-run-owner",
            "sha256": hashlib.sha256(files["mvm-hvf-run-owner"]).hexdigest(),
            "version": "1",
            "target": "aarch64-apple-darwin",
            "source_commit": "a" * 40,
            "bootstrap_protocol_version": 1,
        }).encode()
        self.pack(files)
        def readback(*args):
            if args[0] == "otool":
                if args[1] == "-L":
                    return f"{args[-1]}:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
                return ""
            if args[1] == "-d":
                return plistlib.dumps(dict.fromkeys(
                    gate.sign_macos.ROLES.get(args[-1].name, []), True)).decode()
            return ""
        self.run.side_effect = readback
        self.verify(require_cli_inventory=True)
        self.assertEqual(
            json.loads(self.report.read_text())["owner_component"]["component"],
            "mvm-hvf-run-owner",
        )
        manifest = files.pop("owner-component.json")
        self.pack(files)
        with self.assertRaisesRegex(ValueError, "missing owner component"):
            self.verify(require_cli_inventory=True)
        for field, value, message in (
            ("sha256", "0" * 64, "bytes differ"),
            ("version", "2", "version differs"),
            ("target", "other-target", "target differs"),
            ("source_commit", "b" * 40, "source commit differs"),
        ):
            changed = json.loads(manifest)
            changed[field] = value
            files["owner-component.json"] = json.dumps(changed).encode()
            self.pack(files)
            with self.assertRaisesRegex(ValueError, message):
                self.verify(require_cli_inventory=True)
        files["owner-component.json"] = manifest
        self.pack(files)
        self.diagnostic.return_value = "flags=0x0"
        with self.assertRaisesRegex(ValueError, "hardened runtime"):
            self.verify(require_cli_inventory=True)
        self.diagnostic.return_value = "flags=0x10000(runtime)"

        def non_system(*args):
            if args[0] == "otool" and args[1] == "-L":
                return f"{args[-1]}:\n\t@rpath/libinjected.dylib\n"
            return readback(*args)

        self.run.side_effect = non_system
        with self.assertRaisesRegex(ValueError, "non-system library"):
            self.verify(require_cli_inventory=True)

    def test_cli_package_rejects_host_specific_macho_paths(self):
        files = {
            "mvmctl": macho(2),
            "mvm-hvf-supervisor": macho(2),
            "mvm-hvf-run-owner": macho(2),
            "mvm-libkrun-supervisor": macho(2),
        }
        self.inventory = [{
            "path": name,
            "role": name if name in gate.sign_macos.ROLES else "code",
            "required_entitlements": gate.sign_macos.ROLES.get(name, []),
            "sha256": hashlib.sha256(data).hexdigest(),
        } for name, data in files.items()]
        self.write_producer()
        files["owner-component.json"] = json.dumps({
            "schema_version": 1,
            "component": "mvm-hvf-run-owner",
            "sha256": hashlib.sha256(files["mvm-hvf-run-owner"]).hexdigest(),
            "version": "1",
            "target": "aarch64-apple-darwin",
            "source_commit": "a" * 40,
            "bootstrap_protocol_version": 1,
        }).encode()
        self.pack(files)
        self.run.side_effect = lambda *args: (
            "/opt/homebrew/opt/libkrun/lib/libkrun.dylib" if args[0] == "otool" else
            plistlib.dumps(dict.fromkeys(
                gate.sign_macos.ROLES.get(args[-1].name, []), True)).decode()
            if args[1] == "-d" else ""
        )
        with self.assertRaisesRegex(ValueError, "non-relocatable path|non-system library"):
            self.verify(require_cli_inventory=True)

    def test_zip_unsafe_normalized_duplicate_and_link_reject(self):
        for names in (["/abs"], ["../up"], ["a/../up"], ["a\\b"],
                      ["a/b", "a//b"], ["C:drive"]):
            with self.subTest(names=names):
                with zipfile.ZipFile(self.archive, "w") as archive:
                    for name in names:
                        archive.writestr(name, b"data")
                with self.assertRaises(ValueError):
                    self.verify()
        with zipfile.ZipFile(self.archive, "w") as archive:
            member = zipfile.ZipInfo("link")
            member.external_attr = 0o120777 << 16
            archive.writestr(member, "target")
        with self.assertRaises(ValueError):
            self.verify()

    def test_tar_reuses_envelope_and_rejects_links(self):
        self.archive = self.root / "package.tgz"
        with tarfile.open(self.archive, "w:gz") as archive:
            member = tarfile.TarInfo("package/libmvm_hostlib.dylib")
            member.size = len(self.data)
            archive.addfile(member, io.BytesIO(self.data))
        self.verify(envelope="package")
        with tarfile.open(self.archive, "w:gz") as archive:
            member = tarfile.TarInfo("package/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "../escape"
            archive.addfile(member)
        with self.assertRaises(ValueError):
            self.verify(envelope="package")

    def test_source_helper_owner_only_archive_checks_identity_and_hardening(self):
        self.archive = self.root / "helpers.tgz"
        owner_bytes = macho(2)
        manifest = {
            "schema_version": 1,
            "component": "mvm-hvf-run-owner",
            "sha256": hashlib.sha256(owner_bytes).hexdigest(),
            "version": "1",
            "target": "aarch64-apple-darwin",
            "source_commit": "a" * 40,
            "bootstrap_protocol_version": 1,
        }
        self.inventory = [{
            "path": "mvm-hvf-run-owner",
            "role": "code",
            "required_entitlements": [],
            "sha256": hashlib.sha256(owner_bytes).hexdigest(),
        }]
        self.write_producer()

        def pack(files):
            with tarfile.open(self.archive, "w:gz") as archive:
                for name, data in files.items():
                    member = tarfile.TarInfo(f"helpers/{name}")
                    member.size = len(data)
                    member.mode = 0o755 if name == "mvm-hvf-run-owner" else 0o644
                    archive.addfile(member, io.BytesIO(data))

        files = {
            "mvm-hvf-run-owner": owner_bytes,
            "owner-component.json": json.dumps(manifest).encode(),
        }
        pack(files)

        def readback(*args):
            if args[0] == "otool":
                if args[1] == "-L":
                    return f"{args[-1]}:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
                return ""
            if args[1] == "-d":
                return plistlib.dumps({}).decode()
            return ""

        self.run.side_effect = readback
        gate.verify(
            self.archive,
            self.producer,
            None,
            self.report,
            envelope="helpers",
            require_owner_inventory=True,
            owner_version="1",
            owner_target="aarch64-apple-darwin",
            owner_source_commit="a" * 40,
        )
        self.assertEqual(
            json.loads(self.report.read_text())["owner_component"],
            manifest,
        )
        with self.assertRaisesRegex(ValueError, "expectation is incomplete"):
            gate.verify(
                self.archive,
                self.producer,
                None,
                self.report,
                envelope="helpers",
                require_owner_inventory=True,
            )
        files.pop("mvm-hvf-run-owner")
        pack(files)
        with self.assertRaisesRegex(ValueError, "missing owner executable"):
            gate.verify(
                self.archive,
                self.producer,
                None,
                self.report,
                envelope="helpers",
                require_owner_inventory=True,
                owner_version="1",
                owner_target="aarch64-apple-darwin",
                owner_source_commit="a" * 40,
            )
        files["mvm-hvf-run-owner"] = owner_bytes
        pack(files)
        self.run.side_effect = lambda *args: (
            "LC_RPATH" if args[0] == "otool" and args[1] == "-l" else readback(*args)
        )
        with self.assertRaisesRegex(ValueError, "rpath"):
            gate.verify(
                self.archive,
                self.producer,
                None,
                self.report,
                envelope="helpers",
                require_owner_inventory=True,
                owner_version="1",
                owner_target="aarch64-apple-darwin",
                owner_source_commit="a" * 40,
            )

    def test_zip_limits_before_extraction(self):
        member = zipfile.ZipInfo("large")
        member.file_size = 2**30 + 1
        with patch.object(gate.zipfile.ZipFile, "infolist", return_value=[member]):
            with self.assertRaisesRegex(ValueError, "limits"):
                gate.extract_zip(self.archive, self.root / "unwritten")
        self.assertFalse((self.root / "unwritten").exists())

    def test_unconfigured_cannot_claim_accepted_evidence(self):
        for field in ({"files": self.inventory}, {"id": "submission"},
                      {"notarized": True}):
            self.notary.write_text(json.dumps(dict(status="Unconfigured", **field)))
            with self.assertRaises(ValueError):
                self.verify(self.notary)

    def test_duplicate_report_inventory_and_changed_final_inventory_reject(self):
        self.inventory.append(dict(self.inventory[0]))
        self.write_producer()
        with self.assertRaises(ValueError):
            self.verify()
        self.inventory.pop()
        self.write_producer()
        self.notary.write_text(json.dumps({
            "status": "Accepted", "id": "submission", "team_id": "TEAM",
            "files": [dict(self.inventory[0], path="different.dylib")]}))
        with self.assertRaises(ValueError):
            self.verify(self.notary)

    def test_stale_report_removed_on_failure_and_inputs_protected(self):
        self.report.write_text('{"status":"FinalPackageVerified"}')
        self.pack({"mvm/libmvm_hostlib.dylib": macho(extra=b"tamper")})
        with self.assertRaises(ValueError):
            self.verify()
        self.assertFalse(self.report.exists())
        with self.assertRaises(ValueError):
            gate.verify(self.archive, self.producer, None, self.producer)
        self.assertTrue(self.producer.exists())

    def test_workflow_gate_order_and_existing_smoke_dependencies(self):
        root = Path(__file__).resolve().parents[2]
        cli = (root / ".github/workflows/release.yml").read_text()
        pypi = (root / ".github/workflows/publish-pypi.yml").read_text()
        npm = (root / ".github/workflows/publish-npm.yml").read_text()
        self.assertLess(cli.index("Package binary and generate checksums"),
                        cli.index("Inspect final macOS package bytes"))
        self.assertLess(cli.index("Inspect final macOS package bytes"),
                        cli.index("- name: Upload artifact\n"))
        self.assertLess(pypi.index("Build sdist + wheel"),
                        pypi.index("Inspect final macOS wheel bytes"))
        self.assertLess(pypi.index("Inspect final macOS wheel bytes"),
                        pypi.index("Smoke the wheel in a fresh venv"))
        self.assertLess(npm.index("Download Darwin producer signing report"),
                        npm.index("Inspect actual packed Darwin npm bytes"))
        self.assertLess(npm.index("Inspect actual packed Darwin npm bytes"),
                        npm.index("Install and load on"))
        self.assertIn("needs: [build, smoke]", npm)

    def test_package_inspection_optional_notary_arguments_under_nounset(self):
        root = Path(__file__).resolve().parents[2]
        for workflow, step in [
            ("release.yml", "Inspect final macOS package bytes"),
            ("publish-pypi.yml", "Inspect final macOS wheel bytes"),
            ("publish-npm.yml", "Inspect actual packed Darwin npm bytes"),
        ]:
            source = (root / ".github/workflows" / workflow).read_text()
            block = source.split(f"      - name: {step}\n", 1)[1]
            body = block.split("        run: |\n", 1)[1].split("\n      - ", 1)[0]
            for signed in [False, True]:
                with self.subTest(workflow=workflow, signed=signed):
                    script = re.sub(r"\$\{\{.*?\}\}", str(signed).lower(),
                                    textwrap.dedent(body))
                    recorder = self.root / "python3"
                    recorder.write_text(
                        '#!/bin/sh\n'
                        'if [ "$1" = -c ]; then printf "1\\n"; exit 0; fi\n'
                        'printf "%s\\n" "$@" > "$ARGV_LOG"\n'
                    )
                    recorder.chmod(0o700)
                    log = self.root / "argv"
                    env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}",
                               RUNNER_TEMP=str(self.root / "runner temp"),
                               GITHUB_REF_TYPE="tag" if signed else "branch",
                               BUILD_TARGET="aarch64-apple-darwin",
                               SOURCE_COMMIT="a" * 40,
                               ARGV_LOG=str(log))
                    subprocess.run(["/bin/bash", "-c", script], env=env,
                                   cwd=self.root, check=True, capture_output=True)
                    args = log.read_text().splitlines()
                    self.assertNotIn("", args)
                    self.assertEqual(args.count("--notary-report"), int(signed))
                    self.assertIn("--producer-report", args)
                    self.assertIn("--report", args)
                    if signed:
                        report = args[args.index("--notary-report") + 1]
                        self.assertTrue(report.endswith("-notarization.json"))

    def assert_live_python_contract(self, source, job):
        body = re.split(r"\n  [a-z][a-z0-9-]*:\n",
                        source.split(f"\n  {job}:\n", 1)[1], maxsplit=1)[0]
        body = "\n".join(line for line in body.splitlines()
                         if not line.lstrip().startswith("#"))
        marker = "      - name: Run the documented surface end to end\n"
        self.assertIn(marker, body)
        setup, step = body.split(marker, 1)
        step = step.split("\n      - ", 1)[0]
        if job == "e2e-docs-linux":
            match = re.search(
                r'uses: actions/setup-python@[0-9a-f]{40}(?: +#[^\n]*)?\n\s+with:\n'
                r'\s+python-version: "(3)\.(\d+)\.\d+"', setup,
            )
            self.assertIsNotNone(match, "Linux must install a pinned interpreter before the suite")
            self.assertGreaterEqual(int(match[2]), 12)
            self.assertIn("        run: just e2e::docs", step)
            return "just e2e::docs"
        self.assertEqual(job, "e2e-docs-macos")
        self.assertNotIn("uses: actions/setup-python@", setup,
                         "the macOS installer requires the hosted /Users/runner path")
        self.assertIn(
            "uses: astral-sh/setup-uv@fac544c07dec837d0ccb6301d7b5580bf5edae39", setup
        )
        self.assertIn('version: "0.12.5"', setup)
        self.assertIn("        run: |\n", step)
        run = textwrap.dedent(step.split("        run: |\n", 1)[1])
        self.assertIn("set -o pipefail", run)
        match = re.search(
            r'^uv run --no-project --python (3)\.(\d+) -- just e2e::docs'
            r' 2>&1 \| tee "\$RUNNER_TEMP/e2e-docs\.log"$', run, re.MULTILINE,
        )
        self.assertIsNotNone(match, "installing uv alone does not select Python for the suite")
        self.assertGreaterEqual(int(match[2]), 12)
        return run

    def test_documented_surface_uses_supported_python_in_both_live_jobs(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / ".github/workflows/e2e-docs.yml").read_text()
        for job in ["e2e-docs-linux", "e2e-docs-macos"]:
            self.assert_live_python_contract(source, job)
        recipe = (root / "just/e2e/mod.just").read_text()
        self.assertIn("docs:\n    ./scripts/e2e-documented-surface.sh", recipe)
        script = (root / "scripts/e2e-documented-surface.sh").read_text()
        for assignment in re.findall(r"^\s*(?:export )?PATH=(.*)$", script, re.MULTILINE):
            self.assertIn("$PATH", assignment, "suite must preserve the selected interpreter PATH")

    def test_documented_surface_refuses_unsupported_unpinned_or_bare_uv(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / ".github/workflows/e2e-docs.yml").read_text()
        for version in ["3.9", "3.11", "3.x", "3"]:
            for job in ["e2e-docs-linux", "e2e-docs-macos"]:
                with self.subTest(version=version, job=job), self.assertRaises(AssertionError):
                    self.assert_live_python_contract(source.replace("3.12", version), job)
        for replacement in ["just e2e::docs", "uv run -- just e2e::docs"]:
            changed = source.replace(
                "uv run --no-project --python 3.12 -- just e2e::docs", replacement,
            )
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                self.assert_live_python_contract(changed, "e2e-docs-macos")

    def test_documented_surface_refuses_hosted_python_installer_on_self_hosted_macos(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / ".github/workflows/e2e-docs.yml").read_text()
        marker = "\n  e2e-docs-macos:\n"
        before, macos = source.split(marker, 1)
        for version in ["v5", "v6"]:
            changed = before + marker + macos.replace(
                "      - name: Set up uv\n",
                f"      - uses: actions/setup-python@{version}\n"
                "        with:\n"
                '          python-version: "3.12"\n'
                "      - name: Set up uv\n",
                1,
            )
            with self.subTest(version=version), self.assertRaises(AssertionError):
                self.assert_live_python_contract(changed, "e2e-docs-macos")

    def test_documented_surface_uv_arguments_and_pipeline_exit_without_running_uv(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / ".github/workflows/e2e-docs.yml").read_text()
        run = self.assert_live_python_contract(source, "e2e-docs-macos")
        stub = self.root / "uv"
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV_LOG"\nexit "$UV_STATUS"\n')
        stub.chmod(0o700)
        for status in [0, 7]:
            env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}",
                       RUNNER_TEMP=str(self.root), ARGV_LOG=str(self.root / "uv-args"),
                       UV_STATUS=str(status))
            result = subprocess.run(
                ["/bin/bash", "-c", run], cwd=self.root, env=env,
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, status, result.stderr)
            self.assertEqual((self.root / "uv-args").read_text().splitlines(),
                             ["run", "--no-project", "--python", "3.12", "--", "just", "e2e::docs"])


if __name__ == "__main__":
    unittest.main()
