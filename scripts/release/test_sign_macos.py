"""Credential-free command assembly tests; never invokes Apple signing services."""

import base64
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("sign_macos", Path(__file__).with_name("sign_macos.py"))
signing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signing)
TOOL_RUN = signing.run


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mvm-sign-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        self.report = self.root / "report.json"
        self.env = dict.fromkeys(signing.CREDENTIALS, "test-only-not-a-credential")
        self.env.update(
            APPLE_DEVELOPER_ID_P12_BASE64=base64.b64encode(b"mock certificate").decode(),
            APPLE_TEAM_ID="TESTTEAM01",
            APPLE_DEVELOPER_ID_IDENTITY="Developer ID Application: Test (TESTTEAM01)",
        )
        self.calls = []
        self.entitlements = {}
        self.status = "Accepted"
        self.fail = None
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, self.env, clear=True).start()
        patch.object(signing.platform, "system", return_value="Darwin").start()
        patch.object(signing, "run", side_effect=self.run_tool).start()

    def binary(self, name, kind=2):
        path = self.payload / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 8 + struct.pack("<I", kind))
        return path

    def run_tool(self, *args):
        args = tuple(map(str, args))
        self.calls.append(args)
        if self.fail and self.fail in args:
            raise RuntimeError("mock tool failed")
        if "--entitlements" in args and "--sign" in args:
            self.entitlements[Path(args[-1]).name] = plistlib.loads(
                Path(args[args.index("--entitlements") + 1]).read_bytes())
        if "-d" in args and "--entitlements" in args:
            return plistlib.dumps(self.entitlements[Path(args[-1]).name]).decode()
        if args[:3] == ("xcrun", "notarytool", "submit"):
            return json.dumps({"status": self.status, "id": "mock-submission"})
        return ""

    def test_complete_payload_hardened_roles_notary_and_online_check(self):
        self.binary("mvmctl")
        self.binary("mvm-hvf-supervisor")
        self.binary("helpers/extensionless-helper")
        self.binary("lib/libmvm_hostlib.dylib", 6)
        signing.sign(self.payload, self.report)
        calls = [c for c in self.calls if "--sign" in c]
        self.assertEqual(len(calls), 4)
        self.assertTrue(calls[0][-1].endswith(".dylib"))
        for call in calls:
            self.assertIn("--timestamp", call)
            self.assertIn("runtime", call)
            self.assertIn(self.env["APPLE_DEVELOPER_ID_IDENTITY"], call)
            self.assertNotIn("--deep", call)
        self.assertEqual(self.entitlements, {
            "mvmctl": {"com.apple.security.virtualization": True},
            "mvm-hvf-supervisor": {"com.apple.security.hypervisor": True},
        })
        submit = next(c for c in self.calls if c[:3] == ("xcrun", "notarytool", "submit"))
        self.assertTrue(submit[3].endswith(".zip"))
        self.assertIn("--wait", submit)
        self.assertEqual(sum("--check-notarization" in c for c in self.calls), 4)
        for call in self.calls:
            if "-R" in call:
                self.assertEqual(
                    call[call.index("-R") + 1],
                    signing.DEVELOPER_ID_REQUIREMENT.format(team="TESTTEAM01"),
                )
                self.assertTrue(call[call.index("-R") + 1].startswith("="))
        self.assertFalse(any("stapler" in c for c in self.calls))
        self.assertEqual(len(json.loads(self.report.read_text())["files"]), 4)
        self.assertEqual(self.calls[-1][:2], ("security", "delete-keychain"))

    def test_missing_credentials_fail_before_tool_or_payload_mutation(self):
        for credential in signing.CREDENTIALS:
            with self.subTest(credential=credential), patch.dict(os.environ, {credential: ""}):
                with self.assertRaisesRegex(RuntimeError, credential):
                    signing.sign(self.payload, self.report)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.report.exists())

    def test_cli_fails_closed_with_no_credentials(self):
        result = subprocess.run(
            [os.sys.executable, str(Path(__file__).with_name("sign_macos.py")),
             "--payload", str(self.payload), "--report", str(self.report)],
            env={}, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing Apple signing credentials", result.stderr)
        self.assertFalse(self.report.exists())

    def test_failed_rerun_removes_stale_accepted_evidence(self):
        self.report.write_text('{"status": "Accepted"}')
        with patch.dict(os.environ, {"APPLE_ID": ""}):
            with self.assertRaisesRegex(RuntimeError, "missing Apple"):
                signing.sign(self.payload, self.report)
        self.assertFalse(self.report.exists())

    def test_tool_errors_do_not_expose_credential_arguments_or_output(self):
        secret = "mock-private-value"
        with patch.object(signing.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 1, secret, secret
        )):
            with self.assertRaisesRegex(RuntimeError, "security import failed") as caught:
                TOOL_RUN("security", "import", "-P", secret)
        self.assertNotIn(secret, str(caught.exception))

    def test_missing_post_sign_entitlement_fails_before_notary(self):
        self.binary("mvm-hvf-supervisor")
        original = self.run_tool

        def no_entitlements(*args):
            result = original(*args)
            if "-d" in args:
                return plistlib.dumps({}).decode()
            return result

        with patch.object(signing, "run", side_effect=no_entitlements):
            with self.assertRaisesRegex(RuntimeError, "entitlement missing"):
                signing.sign(self.payload, self.report)
        self.assertFalse(any("notarytool" in call for call in self.calls))
        self.assertFalse(self.report.exists())

    def test_notary_rejected_or_pending_never_produces_report(self):
        self.binary("mvmctl")
        for status in ("Invalid", "In Progress", None):
            with self.subTest(status=status):
                self.status = status
                with self.assertRaisesRegex(RuntimeError, "not Accepted"):
                    signing.sign(self.payload, self.report)
                self.assertFalse(self.report.exists())
                self.assertEqual(self.calls[-1][:2], ("security", "delete-keychain"))

    def test_sign_or_online_verification_failure_cleans_keychain(self):
        self.binary("mvmctl")
        for flag in ("--sign", "--check-notarization", "import"):
            with self.subTest(flag=flag):
                self.fail = flag
                with self.assertRaisesRegex(RuntimeError, "mock tool failed"):
                    signing.sign(self.payload, self.report)
                self.assertFalse(self.report.exists())
                self.assertEqual(self.calls[-1][:2], ("security", "delete-keychain"))

    def test_empty_or_non_macho_library_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "no Mach-O"):
            signing.targets(self.payload)
        (self.payload / "bad.dylib").write_text("not native code")
        with self.assertRaisesRegex(RuntimeError, "expected Mach-O"):
            signing.targets(self.payload)

    def test_external_symlink_is_rejected(self):
        self.binary("mvmctl")
        (self.payload / "external").symlink_to(self.root)
        with self.assertRaisesRegex(RuntimeError, "escapes"):
            signing.targets(self.payload)

    def test_universal_macho_is_discovered(self):
        binary = self.binary("universal", 6)
        thin = binary.read_bytes()
        binary.write_bytes(b"\xca\xfe\xba\xbe" + struct.pack(">I", 1) +
                           struct.pack(">IIIII", 0, 0, 28, len(thin), 0) + thin)
        self.assertEqual(signing.macho_type(binary), 6)

    def test_identity_team_mismatch_is_rejected(self):
        with patch.dict(os.environ, {"APPLE_TEAM_ID": "OTHERTEAM1"}):
            with self.assertRaisesRegex(RuntimeError, "must match"):
                signing.sign(self.payload, self.report)
        self.assertEqual(self.calls, [])

    def test_report_cannot_be_inside_signed_payload(self):
        with self.assertRaisesRegex(RuntimeError, "outside"):
            signing.sign(self.payload, self.payload / "report.json")

    def test_sdk_signing_precedes_packaging_for_every_publish_and_tag_rehearsal(self):
        repo = Path(__file__).resolve().parents[2]
        for workflow, after in (
            ("publish-pypi.yml", "      - name: Build sdist + wheel"),
            ("publish-npm.yml", "      - name: Upload the platform library"),
        ):
            source = (repo / ".github/workflows" / workflow).read_text()
            start = source.index("      - name: Developer ID sign")
            end = source.index(after)
            block = source[start:end]
            self.assertIn("sign_macos.py", block)
            signing_step = block.split("      - name: Retain")[0]
            self.assertIn(
                "runner.os == 'macOS' && (!inputs.dry_run || github.ref_type == 'tag')",
                signing_step,
            )
            for credential in signing.CREDENTIALS:
                self.assertIn(f"secrets.{credential}", block)

class NativeRequirementTests(unittest.TestCase):
    @unittest.skipUnless(os.sys.platform == "darwin", "requires macOS codesign")
    def test_real_codesign_parses_inline_requirements(self):
        # Read-only verification of an OS binary, not signing or notarization.
        subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", "-R", "=anchor apple", "/usr/bin/true"],
            check=True, capture_output=True,
        )
        result = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", "-R",
             signing.DEVELOPER_ID_REQUIREMENT.format(team="TESTTEAM01"), "/usr/bin/true"],
            capture_output=True, text=True, env=dict(os.environ, LC_ALL="C"),
        )
        self.assertNotEqual(result.returncode, 0, "an OS binary is not our Developer ID release")
        self.assertIn("code failed to satisfy", result.stderr)
        self.assertNotIn("invalid requirement specification", result.stderr)


if __name__ == "__main__":
    unittest.main()
