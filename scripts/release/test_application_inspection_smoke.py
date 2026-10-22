"""Offline harness controls, not a substitute for real CLI signature verification."""

import importlib.util
import json
import os
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
    if case == "missing-revocation-trust":
        path = home / FIXTURE["paths"]["revocation_trust"]
        return f"Error: registry-pack revocation trust is not configured at {path}\n"
    if case == "missing-revocation-feed":
        return "Error: registry-pack revocation cache is missing; a signed feed must be fetched\n"
    if case == "same-revocation-signer":
        path = home / FIXTURE["paths"]["revocation_trust"]
        return (
            f"Error: registry-pack revocation trust at {path} is invalid: "
            "release identity must differ from the pack signer\n"
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


def audit_line(verb, phase, tenant="local"):
    # Deliberately unsigned mock bytes: these test harness controls, not crypto.
    labels = {"category": "cmd", "verb": verb}
    if phase == "invoked":
        labels["pid"] = "12345"
    elif phase == "failed":
        labels["error"] = "synthetic refusal"
    return (json.dumps({"entry": {
        "event": f"cmd.{verb}.{phase}", "tenant": tenant,
        "labels": labels,
    }}) + "\n").encode()


def prepare_audit(instance, home):
    (home / "keys").mkdir()
    (home / "keys/host-signer.pub").write_bytes(b"public audit identity".ljust(32, b"."))
    (home / "audit").mkdir()
    (home / "audit/local.jsonl").write_bytes(
        audit_line("bundle", "invoked") + audit_line("bundle", "completed")
        + audit_line("pull", "invoked") + audit_line("pull", "completed")
    )
    instance.capture_audit_identity(home)


def audit_result(home, entries, code=0):
    return SimpleNamespace(returncode=code, stderr=b"", stdout=(
        f"[mvm] audit chain '{home / 'audit/local.jsonl'}' verifies clean: {entries} entries\n"
        "[mvm] No published audit roots, so nothing attests the log was only appended to. "
        "Roots are published at admission and exit.\n"
        "[mvm] No readable off-host witness configured (MVM_AUDIT_WITNESS), so a rewrite "
        "by this host is undetectable from here.\n"
    ).encode())


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

    def test_changed_state_diagnostic_is_bounded_and_contains_no_file_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "pin"
            target.write_bytes(b"private original value")
            before = smoke.snapshot(root)
            target.write_bytes(b"private substituted value")
            after = smoke.snapshot(root)
            diagnostic = smoke.snapshot_changes(before, after)
            self.assertEqual(diagnostic["changed_count"], 1)
            self.assertEqual(diagnostic["changes"], [{
                "relative_path": "pin", "before": before["pin"], "after": after["pin"],
            }])
            self.assertFalse(diagnostic["truncated"])
            self.assertNotIn("private original value", json.dumps(diagnostic))
            self.assertNotIn("private substituted value", json.dumps(diagnostic))
            self.assertNotIn(str(root), json.dumps(diagnostic))

        many = {f"changed-{number:03}": [0o600, "a" * 64] for number in range(40)}
        diagnostic = smoke.snapshot_changes({}, many)
        self.assertEqual(diagnostic["changed_count"], 40)
        self.assertEqual(len(diagnostic["changes"]), 32)
        self.assertTrue(diagnostic["truncated"])
        long_name = "x" * 513
        self.assertEqual(smoke.snapshot_changes({}, {long_name: [0o700, "directory"]})["changes"], [{
            "relative_path_sha256": smoke.digest(long_name.encode()),
            "before": None, "after": [0o700, "directory"],
        }])

    def test_changed_state_diagnostic_distinguishes_removal_type_and_mode(self):
        before = {
            "removed": [0o600, "a" * 64],
            "mode": [0o600, "b" * 64],
            "type": [0o700, "directory"],
            "same": [0o600, "c" * 64],
        }
        after = {
            "mode": [0o400, "b" * 64],
            "type": [0o600, "d" * 64],
            "same": before["same"],
        }
        diagnostic = smoke.snapshot_changes(before, after)
        self.assertEqual(diagnostic["changed_count"], 3)
        self.assertEqual(
            [entry["relative_path"] for entry in diagnostic["changes"]],
            ["mode", "removed", "type"],
        )
        self.assertIsNone(diagnostic["changes"][1]["after"])

    def test_audit_suffix_refuses_truncation_replacement_reordering_extra_and_wrong_command(self):
        prefix = audit_line("pull", "completed")
        pair = audit_line("pack", "invoked") + audit_line("pack", "completed")
        self.assertEqual(smoke.assert_audit_append(prefix, prefix + pair, "pack", "completed"), 3)
        invalid = (
            pair, prefix[:-1] + pair,
            audit_line("pull", "failed") + pair,
            prefix + audit_line("pack", "completed") + audit_line("pack", "invoked"),
            prefix + pair + audit_line("pack", "completed"),
            prefix + audit_line("trust", "invoked") + audit_line("trust", "completed"),
            prefix + audit_line("pack", "invoked", "other") + audit_line("pack", "completed"),
            prefix + audit_line("pack", "invoked") + audit_line("pack", "failed"),
            prefix + pair[:-1],
            prefix + b'{"entry":{},"entry":{}}\n' + audit_line("pack", "completed"),
        )
        for changed in invalid:
            with self.subTest(changed=changed), self.assertRaises((ValueError, KeyError)):
                smoke.assert_audit_append(prefix, changed, "pack", "completed")

    def test_audit_verification_requires_exact_source_count_and_real_success_status(self):
        home = Path("/private/consumer")
        result = audit_result(home, 7)
        self.assertEqual(smoke.assert_verified_audit(result, home, 6), 7)
        for code in (-11, 1, 2, 101):
            with self.subTest(code=code), self.assertRaises(ValueError):
                smoke.assert_verified_audit(audit_result(home, 7, code), home, 6)
        for invalid in (
            audit_result(home, 6), audit_result(home, 0), audit_result(Path("/other"), 7),
            SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
            SimpleNamespace(returncode=0, stdout=result.stdout, stderr=b"signature invalid"),
            SimpleNamespace(returncode=0, stdout=result.stdout + b"append-only check failed\n", stderr=b""),
        ):
            with self.subTest(result=invalid), self.assertRaises(ValueError):
                smoke.assert_verified_audit(invalid, home, 6)

    def test_default_quiet_verifier_success_is_not_a_coverage_witness(self):
        # Production ui::success/info are silent without an explicit output
        # opt-in. Exit zero alone must never stand in for the signed-tail proof.
        quiet = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with self.assertRaisesRegex(ValueError, "exact inspection tail"):
            smoke.assert_verified_audit(quiet, Path("/private/consumer"), 6)

    def test_verifier_self_events_follow_the_existing_folded_audit_verb(self):
        workspace = Path(__file__).resolve().parents[2]
        dispatch = (workspace / "crates/mvm-cli/src/commands/cmd_audit.rs").read_text()
        trust = (workspace / "crates/mvm-cli/src/commands/trust/mod.rs").read_text()
        self.assertRegex(dispatch, r"Commands::Trust\(a\)\s*=>\s*a\.action\.verb_name\(\)")
        self.assertRegex(trust, r'TrustAction::Audit\(_\)\s*=>\s*"audit"')
        prefix = audit_line("pack", "completed")
        actual = prefix + audit_line("audit", "invoked") + audit_line("audit", "completed")
        self.assertEqual(smoke.assert_audit_append(prefix, actual, "audit", "completed"), 3)
        guessed = prefix + audit_line("trust", "invoked") + audit_line("trust", "completed")
        with self.assertRaises(ValueError):
            smoke.assert_audit_append(prefix, guessed, "audit", "completed")

    def test_all_noncanonical_audit_state_and_security_state_stays_protected(self):
        instance = smoke.Smoke(Path("/cli"), Path("/output"), Path("/catalog"), FIXTURE)
        for name in (
            "registry/packs.lock.toml", "trusted-publishers/author.pub",
            "keys/host-signer.ed25519", "keys/host-signer.pub", "bundles/archive",
            "audit", "audit/other.jsonl", "audit/local.roots.jsonl",
        ):
            before = {name: [0o600, "a" * 64]}
            after = {name: [0o600, "b" * 64]}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "protected"):
                instance.check_protected_state("inspection", before, after)

    def test_audit_inputs_refuse_links_and_detect_replacement_mode_or_identity_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "chain"
            path.write_bytes(b"chain\n")
            _, original = smoke.read_audit_input(path, 32)
            path.chmod(0o400)
            _, changed = smoke.read_audit_input(path, 32)
            self.assertNotEqual(original, changed)
            replacement = root / "replacement"
            replacement.write_bytes(path.read_bytes())
            replacement.replace(path)
            self.assertNotEqual(original, smoke.read_audit_input(path, 32)[1])
            os.link(path, root / "hardlink")
            with self.assertRaises(ValueError):
                smoke.read_audit_input(path, 32)
            link = root / "symlink"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                smoke.read_audit_input(link, 32)

    def test_setup_audit_identity_cannot_be_replaced_before_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, FIXTURE)
            prepare_audit(instance, root)
            (root / "keys/host-signer.pub").write_bytes(b"other identity".ljust(32, b"."))
            with self.assertRaisesRegex(ValueError, "identity changed"):
                instance.audit_snapshot(root)

    def test_verifier_owned_protected_mutation_is_not_exempted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, FIXTURE)
            prepare_audit(instance, root)

            def command(name, home, argv):
                path = home / "audit/local.jsonl"
                before = path.read_bytes()
                verb = "pack" if argv[0] == "pack" else "audit"
                path.write_bytes(before + audit_line(verb, "invoked") + audit_line(verb, "completed"))
                if verb == "pack":
                    return SimpleNamespace(returncode=0, stdout=b"{}", stderr=b"")
                (home / "keys/host-signer.pub").write_bytes(b"replacement".ljust(32, b"."))
                return audit_result(home, len(before.splitlines()) + 1)

            with patch.object(instance, "command", side_effect=command), patch.object(smoke, "assert_inspection"):
                with self.assertRaisesRegex(ValueError, "protected"):
                    instance.inspect("positive", root, True)

    def test_audited_inspection_uses_canonical_verifier_without_exempting_its_own_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, FIXTURE)
            prepare_audit(instance, root)
            calls = []

            def command(name, home, argv):
                calls.append(argv)
                path = home / "audit/local.jsonl"
                before = path.read_bytes()
                if argv[0] == "pack":
                    path.write_bytes(before + audit_line("pack", "invoked") + audit_line("pack", "completed"))
                    return SimpleNamespace(returncode=0, stdout=b"{}", stderr=b"")
                self.assertEqual(argv, ["--verbose", "trust", "audit", "verify", "--tenant", "local"])
                path.write_bytes(before + audit_line("audit", "invoked") + audit_line("audit", "completed"))
                return audit_result(home, len(before.splitlines()) + 1)

            with patch.object(instance, "command", side_effect=command), patch.object(smoke, "assert_inspection"):
                instance.inspect("positive", root, True)
            self.assertEqual(len(calls), 4)
            self.assertEqual(calls[0], ["pack", "info", FIXTURE["reference"], "--json"])
            self.assertEqual(calls[2], ["pack", "verify", FIXTURE["reference"], "--json"])
            self.assertEqual(calls[1], ["--verbose", "trust", "audit", "verify", "--tenant", "local"])
            self.assertEqual(calls[3], calls[1])
            self.assertEqual([record["verified_entries"] for record in instance.records], [7, 11])
            self.assertTrue(all(not record["verifier_final_self_outcome_covered"] for record in instance.records))

    def test_audit_log_may_only_grow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, FIXTURE)
            prepare_audit(instance, root)
            log = root / smoke.AUDIT_LOG
            original = log.read_bytes()
            log.write_bytes(original + b"two\n")
            self.assertEqual(smoke.snapshot(root), smoke.snapshot(root))

            def command(*_):
                log.write_bytes(b"rewritten\n")
                return type("Result", (), {"returncode": 0, "stdout": b"{}", "stderr": b""})()

            with patch.object(instance, "command", side_effect=command), \
                    patch.object(smoke, "assert_inspection"):
                with self.assertRaisesRegex(ValueError, "original prefix"):
                    instance.inspect("positive", root, True)

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
            prepare_audit(instance, root)
            result = type("Result", (), {"returncode": 1, "stdout": b"", "stderr": b"refused"})()
            with patch.object(instance, "command", return_value=result):
                with self.assertRaisesRegex(ValueError, "unexpectedly refused"):
                    instance.inspect("positive", root, True)

    def test_unexpected_negative_success_is_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = smoke.Smoke(Path("/cli"), root, root, {"reference": "runtime/example@1.0.0"})
            prepare_audit(instance, root)
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
                    elif key == "revocation_trust":
                        path.write_bytes(b"explicit private operator trust")
                        for name in ("feed.json", "checkpoint.json"):
                            path.with_name(name).write_bytes(b"unit cached state")
                    else:
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
            prepare_audit(instance, root)

            def command(*_):
                (root / "new-pin").write_text("mutation")
                return type("Result", (), {
                    "returncode": 1, "stdout": b"",
                    "stderr": refusal_message("archive", root).encode(),
                })()

            with patch.object(instance, "command", side_effect=command):
                with self.assertRaisesRegex(ValueError, "mutated"):
                    instance.inspect("archive", root, False)
            mutation = instance.records[-1]
            self.assertEqual(mutation["name"], "archive-info-state-mutation")
            self.assertEqual(mutation["changed_count"], 1)
            self.assertEqual(mutation["changes"][0]["relative_path"], "new-pin")
            self.assertIsNone(mutation["changes"][0]["before"])

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
            feed_document = fixture / "operator-feed.json"
            feed_bundle = fixture / "operator-feed.sigstore.json"
            feed_document.write_bytes(b"unsigned feed control; no verifier is executed")
            feed_bundle.write_bytes(b"unsigned proof control; no verifier is executed")
            args = SimpleNamespace(
                fixture_dir=fixture, cli=Path(__file__), wrong_signature=fixture / "manifest.sigstore.json",
                out_dir=root / "results", source_sha="a" * 40,
                revocation_document=feed_document, revocation_bundle=feed_bundle,
                revocation_source_sha="b" * 40,
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
            self.assertIn(
                "genuine signed revoked-feed refusal for a matching descriptor",
                report["open_witnesses"],
            )

    def test_operator_trust_is_explicit_private_and_not_descriptor_inferred(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            fixture = {**FIXTURE, "identity": "https://example.test/distinct-descriptor"}
            smoke.configure_operator_trust(home, fixture)
            path = home / fixture["paths"]["revocation_trust"]
            text = path.read_text()
            self.assertIn(smoke.OPERATOR_FEED_IDENTITY, text)
            self.assertIn(smoke.OPERATOR_FEED_ISSUER, text)
            self.assertNotIn(fixture["identity"], text)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                smoke.configure_operator_trust(home, fixture)
            self.assertEqual(path.read_bytes(), before)

    def test_same_publisher_is_refused_before_operator_trust_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            fixture = {**FIXTURE, "identity": smoke.OPERATOR_FEED_IDENTITY}
            with self.assertRaisesRegex(ValueError, "publishers must differ"):
                smoke.configure_operator_trust(home, fixture)
            self.assertFalse((home / fixture["paths"]["revocation_trust"]).exists())

    def test_operator_trust_refuses_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (home / "registry").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                smoke.configure_operator_trust(home, {
                    **FIXTURE, "identity": "https://example.test/distinct-descriptor",
                })
            self.assertEqual(list(outside.iterdir()), [])

    def test_operator_feed_update_precedes_bundle_install_and_pull(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_root = root / "fixture"
            (fixture_root / "consumer-home").mkdir(parents=True)
            instance = smoke.Smoke(Path("/cli"), root, root, {
                **FIXTURE, "identity": "https://example.test/distinct-descriptor",
            })
            document, bundle = root / "operator.json", root / "operator.sigstore.json"
            with patch.object(instance, "command", return_value=SimpleNamespace(returncode=0)) as command, \
                    patch.object(instance, "capture_audit_identity"), \
                    patch.object(instance, "inspect") as inspect, patch.object(smoke, "CASES", ()):
                smoke.exercise(instance, fixture_root, root / "wrong-signature", document, bundle)
            calls = [call.args[2] for call in command.call_args_list]
            self.assertEqual(calls[0], [
                "pack", "registry", "revocations", "update",
                "--document", str(document), "--bundle", str(bundle),
            ])
            self.assertNotIn("--official", calls[0])
            self.assertEqual(calls[1][0:2], ["bundle", "install"])
            self.assertEqual(calls[2], ["pull", FIXTURE["reference"], "--json"])
            inspect.assert_called_once()

    def test_workflow_keeps_existing_gates_and_same_signing_identity(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/pack-signing-smoke.yml").read_text()
        for number in range(3, 8):
            self.assertIn(f"# Step {number}:", workflow)
        self.assertIn('--identity "${IDENTITY}"', workflow)
        self.assertIn("check_application_inspection_smoke.py", workflow)
        self.assertEqual(workflow.count("id-token: write"), 1)
        self.assertIn("timeout-minutes: 45", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertIn('timeout 60 git ls-remote', workflow)
        self.assertIn(
            '"https://raw.githubusercontent.com/tinylabscom/mvm-packs/${feed_sha}/packs/${name}"',
            workflow,
        )
        self.assertIn("--max-filesize 1048576", workflow)
        self.assertIn('--revocation-source-sha "${feed_sha}"', workflow)


if __name__ == "__main__":
    unittest.main()
