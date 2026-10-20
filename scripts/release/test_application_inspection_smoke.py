"""Offline harness controls, not a substitute for real CLI signature verification."""

import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "application_smoke", Path(__file__).with_name("check_application_inspection_smoke.py"),
)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


FIXTURE = {
    "reference": "runtime/inspection-fixture@1.0.0",
    "manifest_sha256": "a" * 64,
    "tampered_manifest_sha256": "b" * 64,
    "bundle": {"key_id": "c" * 32},
    "paths": {"revocation_trust": "registry/revocations/trust.toml"},
}


def refusal_message(case, home):
    if case in ("pin", "descriptor"):
        pinned = "0" * 64 if case == "pin" else "a" * 64
        actual = "a" * 64 if case == "pin" else "b" * 64
        return (
            f'Error: pack manifest digest drift for {FIXTURE["reference"]}: '
            f'pinned Sha256Hex("{pinned}"), got Sha256Hex("{actual}")\n'
        )
    if case == "version":
        return "Error: pack runtime/inspection-fixture requested version 1.0.0, but the lock pins 9.0.0\n"
    if case in ("signature", "publisher"):
        return (
            "Error: registry-pack signature is invalid: signature is invalid: "
            "signature verification failed: cryptographic or identity mismatch\n"
        )
    if case == "malformed-revocation-trust":
        path = home / FIXTURE["paths"]["revocation_trust"]
        return (
            f"Error: registry-pack revocation trust at {path} is invalid: "
            "TOML parse error at line 1, column 18\n"
            "  |\n1 | schema_version = false\n  |                  ^^^^^\n"
            "invalid type: boolean `false`, expected u32\n"
        )
    cause = {
        "bundle-key": f'trust store has no entry for key_id {FIXTURE["bundle"]["key_id"]}',
        "archive": "application archive digest differs from its descriptor",
        "missing-archive": "application archive I/O failed: No such file or directory (os error 2)",
    }[case]
    return (
        f'Error: reverifying local application bundle for {FIXTURE["reference"]}; '
        f'use `mvmctl pull {FIXTURE["reference"]}` to acquire a missing archive\n\n'
        f"Caused by:\n    {cause}\n"
    )


class InspectionSmokeTests(unittest.TestCase):
    def test_each_case_requires_its_production_error_and_exit_one(self):
        home = Path("/private/consumer")
        for case in smoke.CASES:
            valid = refusal_message(case, home).encode()
            result = type("Result", (), {"returncode": 1, "stdout": b"", "stderr": valid})()
            with self.subTest(case=case):
                self.assertIsInstance(smoke.assert_refusal(result, case, home, FIXTURE), str)
            for exit_code in (-11, -9, 0, 2, 101, 127):
                bad = type("Result", (), {"returncode": exit_code, "stdout": b"", "stderr": valid})()
                with self.subTest(case=case, exit=exit_code), self.assertRaises(ValueError):
                    smoke.assert_refusal(bad, case, home, FIXTURE)
            for wrong in (
                b"Error: unrelated configuration could not be read\n",
                b"error: unexpected argument '--json'\nUsage: mvmctl\n",
                b"Error: Permission denied (os error 13)\n",
                b"thread 'main' panicked at unrelated.rs:1\n" + valid,
                b"Error: unrelated failure mentioning " + valid,
            ):
                bad = type("Result", (), {"returncode": 1, "stdout": b"", "stderr": wrong})()
                with self.subTest(case=case, wrong=wrong), self.assertRaises(ValueError):
                    smoke.assert_refusal(bad, case, home, FIXTURE)

    def test_wrong_stage_is_refused_even_when_nonzero(self):
        home = Path("/private/consumer")
        for case in smoke.CASES:
            other = "archive" if case != "archive" else "signature"
            bad = type("Result", (), {
                "returncode": 1, "stdout": b"",
                "stderr": refusal_message(other, home).encode(),
            })()
            with self.subTest(case=case), self.assertRaises(ValueError):
                smoke.assert_refusal(bad, case, home, FIXTURE)

    def test_refusal_cannot_emit_a_success_document(self):
        result = type("Result", (), {
            "returncode": 1, "stdout": b'{"kind":"application"}',
            "stderr": refusal_message("archive", Path("/consumer")).encode(),
        })()
        with self.assertRaises(ValueError):
            smoke.assert_refusal(result, "archive", Path("/consumer"), FIXTURE)

    def test_containment_refuses_parent_absolute_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("../escape", "/absolute"):
                with self.assertRaises(ValueError):
                    smoke.contained(root, name)
            (root / "link").symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                smoke.contained(root, "link/file")
            self.assertEqual(smoke.contained(root, "registry/pins"), root / "registry/pins")

    def test_snapshot_detects_bytes_modes_and_extra_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "pin"
            target.write_bytes(b"one")
            original = smoke.snapshot(root)
            target.write_bytes(b"two")
            self.assertNotEqual(original, smoke.snapshot(root))
            target.write_bytes(b"one")
            target.chmod(0o600)
            self.assertNotEqual(original, smoke.snapshot(root))
            (root / "extra").mkdir()
            self.assertNotEqual(original, smoke.snapshot(root))

    def test_closed_environment_does_not_forward_credentials(self):
        with patch.dict("os.environ", {"GITHUB_TOKEN": "not-forwarded", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "not-forwarded"}):
            env = smoke.closed_environment(Path("/consumer"), Path("/scratch"), Path("/catalog"))
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", env)
        self.assertEqual(env["MVM_PACK_REGISTRY"], "file:///catalog")

    def test_inspection_requires_every_authenticated_identity(self):
        fixture = {
            "reference": "runtime/example@1.0.0", "manifest_sha256": "a" * 64,
            "identity": "https://example.test/identity", "bundle": {"key_id": "key"},
        }
        document = {
            "kind": "application", "reference": fixture["reference"],
            "manifest_sha256": fixture["manifest_sha256"],
            "signer_identity": fixture["identity"],
            "signer_issuer": "https://token.actions.githubusercontent.com",
            "guest_arch": "aarch64", "bundle": fixture["bundle"],
            "verification_scope": "descriptor_and_bundle_archive",
        }
        smoke.assert_inspection(document, fixture)
        for field in document:
            changed = dict(document)
            changed[field] = "wrong"
            with self.subTest(field=field), self.assertRaises(ValueError):
                smoke.assert_inspection(changed, fixture)

    def test_refusal_cannot_be_counted_as_positive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, {"reference": "runtime/example@1.0.0"})
            result = type("Result", (), {"returncode": 1, "stdout": b"", "stderr": b"refused"})()
            with patch.object(instance, "command", return_value=result):
                with self.assertRaisesRegex(ValueError, "unexpectedly refused"):
                    instance.inspect("positive", root, True)

    def test_unexpected_negative_success_is_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, {"reference": "runtime/example@1.0.0"})
            result = type("Result", (), {"returncode": 0})()
            with patch.object(instance, "command", return_value=result):
                with self.assertRaisesRegex(ValueError, "unexpectedly accepted"):
                    instance.inspect("archive", root, False)

    def test_command_retains_raw_output_and_actual_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, {})
            result = type("Result", (), {
                "returncode": 19, "stdout": b"partial output", "stderr": b"refused",
            })()
            with patch.object(smoke.subprocess, "run", return_value=result) as run:
                instance.command("failure", root, ["pack", "verify"])
            self.assertEqual(run.call_args.kwargs["timeout"], 120)
            self.assertEqual((root / "failure/stdout").read_bytes(), b"partial output")
            self.assertEqual((root / "failure/stderr").read_bytes(), b"refused")
            self.assertEqual(instance.records[0]["exit"], 19)
            self.assertTrue((root / "failure/status.json").is_file())

    def test_oversize_output_keeps_known_status_before_failing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, {})
            result = type("Result", (), {
                "returncode": 1, "stdout": b"x" * (1024 * 1024 + 1), "stderr": b"failure",
            })()
            with patch.object(smoke.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(ValueError, "retained-output bound"):
                    instance.command("oversize", root, ["pack", "verify"])
            record = json.loads((root / "oversize/status.json").read_text())
            self.assertEqual(record["exit"], 1)
            self.assertEqual(record["stdout_size"], 1024 * 1024 + 1)
            self.assertEqual((root / "oversize/stdout").stat().st_size, 1024 * 1024)

    def test_every_negative_is_an_actual_isolated_state_change(self):
        for case in smoke.CASES:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                descriptor_hash = "a" * 64
                reference = "runtime/inspection-fixture@1.0.0"
                fixture = {
                    "reference": reference, "manifest_sha256": descriptor_hash,
                    "identity": "https://example.test/identity",
                    "paths": {
                        "lock": "registry/lock", "policy": "registry/policy",
                        "registry_cache": "cache/descriptors", "bundle_key": "trust/key.pub",
                        "archive": "bundles/input.mvmpkg", "revocation_trust": "revoke/trust",
                    },
                }
                for key, name in fixture["paths"].items():
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if key == "registry_cache":
                        path.mkdir()
                        path = path / descriptor_hash
                        path.mkdir()
                        (path / "manifest.json").write_bytes(b"descriptor")
                        (path / "manifest.sigstore.json").write_bytes(b"signature")
                    elif key == "lock":
                        path.write_text(reference + "\n" + descriptor_hash)
                    elif key == "policy":
                        path.write_text(fixture["identity"])
                    elif key != "revocation_trust":
                        path.write_bytes(b"fixture bytes")
                wrong = root / "wrong-signature"
                wrong.write_bytes(b"different genuine bundle supplied by the real workflow")
                before = smoke.snapshot(root)
                smoke.mutate(root, fixture, case, wrong)
                self.assertNotEqual(before, smoke.snapshot(root))
                if case == "archive":
                    self.assertEqual((root / fixture["paths"]["archive"]).stat().st_size, 13)

    def test_refusal_with_state_mutation_is_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, FIXTURE)

            def command(*_):
                (root / "new-pin").write_text("mutation")
                return type("Result", (), {
                    "returncode": 1, "stdout": b"",
                    "stderr": refusal_message("archive", root).encode(),
                })()

            with patch.object(instance, "command", side_effect=command):
                with self.assertRaisesRegex(ValueError, "mutated"):
                    instance.inspect("archive", root, False)

    def test_failure_report_survives_and_redacts_private_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, FIXTURE)
            instance.records.append({"name": "archive-info", "exit": 101})
            with patch("builtins.print") as output:
                instance.report("FAIL", "ValueError")
            report = json.loads((root / "report.json").read_text())
            self.assertEqual(report["outcome"], "FAIL")
            self.assertEqual(report["records"][0]["exit"], 101)
            self.assertTrue(output.called)
            text = (
                "Error: private key = never-print-this\n"
                f"Error: failed opening {root}/consumer/registry/pin\n"
            )
            safe = smoke.public_diagnostic(text.encode(), [root])
            self.assertNotIn("never-print-this", safe)
            self.assertNotIn(str(root), safe)
            self.assertIn("[private-path]", safe)
            self.assertLessEqual(len(smoke.public_diagnostic(b"x" * 50000, [])), 16384)

    def test_run_publishes_failure_evidence_before_abort_without_running_a_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / "fixture"
            fixture.mkdir()
            descriptor, archive = b"descriptor-control", b"archive-control"
            (fixture / "manifest.json").write_bytes(descriptor)
            (fixture / "application.mvmpkg").write_bytes(archive)
            metadata = {
                "schema_version": 1, "manifest_sha256": smoke.digest(descriptor),
                "bundle": {"archive_sha256": smoke.digest(archive), "archive_size": len(archive)},
            }
            (fixture / "fixture.json").write_text(json.dumps(metadata))
            (fixture / "manifest.sigstore.json").write_bytes(b"unsigned unit control")
            (fixture / "bundle-author.pub").write_bytes(b"public unit control")
            args = SimpleNamespace(
                fixture_dir=fixture, cli=Path(__file__), wrong_signature=fixture / "manifest.sigstore.json",
                out_dir=root / "results", source_sha="a" * 40,
            )

            def fail(instance, *_):
                instance.records.append({"name": "signature-verify", "exit": 101})
                raise ValueError("wrong failure stage")

            with patch.object(smoke, "exercise", side_effect=fail), patch("builtins.print") as output:
                with self.assertRaisesRegex(ValueError, "wrong failure stage"):
                    smoke.run(args)
            report = json.loads((args.out_dir / "report.json").read_text())
            self.assertEqual(report["outcome"], "FAIL")
            self.assertEqual(report["records"][0]["exit"], 101)
            self.assertEqual(report["error"]["detail"], "wrong failure stage")
            self.assertGreaterEqual(output.call_count, 6)
            self.assertIn("malformed-revocation-trust", smoke.CASES)
            self.assertIn("genuine signed revocation feed", report["open_witnesses"])

    def test_workflow_keeps_existing_gates_and_same_signing_identity(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/pack-signing-smoke.yml").read_text()
        for number in range(3, 8):
            self.assertIn(f"# Step {number}:", workflow)
        self.assertIn('--identity "${IDENTITY}"', workflow)
        self.assertIn("check_application_inspection_smoke.py", workflow)
        self.assertEqual(workflow.count("id-token: write"), 1)
        self.assertIn("timeout-minutes: 45", workflow)
        self.assertNotIn("upload-artifact", workflow)


if __name__ == "__main__":
    unittest.main()
