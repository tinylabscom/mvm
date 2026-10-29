import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location(
    "consumer", Path(__file__).with_name("claude-demo-consumer.py"))
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.args = SimpleNamespace(
            cli=Path("/immutable/released/mvmctl"), cli_sha256="a" * 64,
            mvm_home=self.home, descriptor_sha256="b" * 64,
            archive_sha256="c" * 64, rootfs_sha256="d" * 64,
            rootfs_roothash="e" * 64, runtime_archive_sha256="f" * 64,
            runtime_version="0.26.0", runtime_overlay_roothash="1" * 64,
            kernel_sha256="2" * 64, run_timeout=1,
            authorize_model_request=False, budget_usd="0.50", check_readiness=True,
            archive_url="https://github.com/tinylabscom/mvm-packs/releases/download/public/claude.mvmpkg",
            binding_name="demo-key",
        )
        self.plan = "sha256:" + "3" * 64
        self.vm = "native-run"
        self.budget_id = "d2ab6372-d0ee-4bbf-af5e-5c2a68d91277"
        self.proof = dict(
            instance={"vm_id": self.vm, "boot_nonce": list(range(32))},
            rootfs_sha256=self.args.rootfs_sha256,
            rootfs_roothash=self.args.rootfs_roothash,
            runtime_archive_sha256=self.args.runtime_archive_sha256,
            runtime_version=self.args.runtime_version,
            runtime_overlay_roothash=self.args.runtime_overlay_roothash,
            network_policy={"type": "allowlist",
                            "rules": [{"host": "api.anthropic.com", "port": 443}],
                            "ai": {"request_budget": demo.BUDGET}},
        )
        self.entries = [
            self.entry("plan.admitted", {"kernel_sha256": self.args.kernel_sha256}),
            self.entry("plan.launched", {"backend": "hvf"}),
            self.entry("plan.exited", {"backend": "hvf", "captured": "true", "exit_code": "0"}),
            self.entry("plan.native_completed", {
                "bundle_sha256": self.args.archive_sha256,
                "native_completion": json.dumps(self.proof)}),
        ]
        self.host_entries = [
            self.entry("host.ai.budget_reserved", {
                "vm": self.vm, "budget_id": self.budget_id,
                "host": "api.anthropic.com", "port": "443",
                "request_budget": json.dumps(demo.BUDGET),
                "secret_bindings": '["demo-key"]',
                "reserved_requests": "1", "reserved_spend_microusd": "500000"}),
            self.entry("host.ai.usage", {
                "vm": self.vm, "budget_id": self.budget_id,
                "host": "api.anthropic.com", "port": "443", "method": "POST",
                "path": "/v1/messages", "provider": "anthropic", "status": "200",
                "output_tokens": "15", "budget_exceeded": "false"}),
            self.entry("secret.substituted", {
                "name": "demo-key", "destination": "api.anthropic.com", "auth_type": "bearer"}),
            self.entry("secret.forward_outcome", {
                "destination": "api.anthropic.com", "outcome": "completed", "via": "direct"}),
        ]
        self.verification = {"tenant": "local", "plan_id": self.plan,
                             "verdict": "VERIFIED", "late_entries": 0, "seals": [{}]}
        self.info = {"bundle": {"source": self.args.archive_url}, "bundle_manifest": {
            "members": [{"class": "environment",
                         "pack": {"name": "agent/claude", "version": "2.0.0"},
                         "target": "aarch64-linux", "entrypoint": {"argv": ["/etc/mvm/entrypoint"]},
                         "policy": {"allow_hosts": ["api.anthropic.com:443"],
                                    "request_budget": demo.BUDGET},
                         "secret_slots": [{"name": "ANTHROPIC_API_KEY", "required": True}]}],
            "verity": {"roothash": self.args.rootfs_roothash},
            "artifacts": [{"role": role, "sha256": sha} for role, sha in (
                ("kernel", self.args.kernel_sha256), ("rootfs", self.args.rootfs_sha256))],
        }}

    def entry(self, event, labels):
        plan_id = self.plan if event.startswith("plan.") else demo.UNBOUND
        return {"event": event, "plan_id": plan_id, "tenant": "local",
                "image_sha256": self.args.rootfs_sha256, "caller_commitment": {"pin": "public"},
                "labels": labels}

    def assert_fixture(self):
        return demo.assert_evidence(self.args, self.verification, self.entries, self.host_entries)

    def test_correlates_canonical_evidence_without_joke_matching(self):
        result = self.assert_fixture()
        self.assertEqual(result["run_id"], self.vm)
        self.assertEqual(result["endpoint_budget_id"], self.budget_id)

    def test_missing_native_completion_is_not_replaced_by_successful_exit(self):
        self.entries.pop()
        with self.assertRaises(demo.Blocked):
            self.assert_fixture()

    def test_host_events_require_the_local_tenant_and_exact_unbound_selector(self):
        for field, value in (("tenant", None), ("tenant", "other"),
                             ("plan_id", None), ("plan_id", self.plan)):
            old = self.host_entries[0][field]
            self.host_entries[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(demo.Blocked):
                self.assert_fixture()
            self.host_entries[0][field] = old

    def test_missing_or_duplicate_enforcement_and_usage_refused(self):
        original = copy.deepcopy(self.host_entries)
        for entries in ([], original[:1], original[1:], original + [original[0]],
                        original + [original[1]]):
            self.host_entries = copy.deepcopy(entries)
            with self.subTest(entries=entries), self.assertRaises(demo.Blocked):
                self.assert_fixture()

    def test_endpoint_restart_or_wrong_vm_refused(self):
        for field, value in (("vm", "other"), ("budget_id", "b86e0e4a-b685-48c1-aa92-e942c030f9da")):
            old = self.host_entries[1]["labels"][field]
            self.host_entries[1]["labels"][field] = value
            with self.subTest(field=field), self.assertRaises(demo.Blocked):
                self.assert_fixture()
            self.host_entries[1]["labels"][field] = old

    def test_audit_verification_and_late_entries_fail_closed(self):
        for field, value in (("verdict", "UNSEALED"), ("late_entries", 1),
                             ("seals", []), ("tenant", "other")):
            original = self.verification[field]
            self.verification[field] = value
            with self.subTest(field=field), self.assertRaises(demo.Blocked):
                self.assert_fixture()
            self.verification[field] = original

    def test_runtime_image_and_effective_policy_mismatches_refused(self):
        for field in ("runtime_archive_sha256", "runtime_version", "runtime_overlay_roothash",
                      "rootfs_sha256", "rootfs_roothash", "network_policy", "instance"):
            proof = {**self.proof, field: None}
            self.entries[-1]["labels"]["native_completion"] = json.dumps(proof)
            with self.subTest(field=field), self.assertRaises(demo.Blocked):
                self.assert_fixture()

    def test_wrong_backend_and_exit_refused(self):
        for index, field, value in ((1, "backend", "qemu"), (2, "exit_code", "1"),
                                    (2, "captured", "false")):
            old = self.entries[index]["labels"][field]
            self.entries[index]["labels"][field] = value
            with self.subTest(field=field), self.assertRaises(demo.Blocked):
                self.assert_fixture()
            self.entries[index]["labels"][field] = old

    def test_provider_response_must_be_successful_and_nonempty(self):
        labels = self.host_entries[1]["labels"]
        for field, value in (("status", "401"), ("output_tokens", "0"),
                             ("provider", "openai"), ("host", "example.com"),
                             ("output_tokens", "20001"), ("budget_exceeded", "true")):
            old = labels[field]
            labels[field] = value
            with self.subTest(field=field), self.assertRaises(demo.Blocked):
                self.assert_fixture()
            labels[field] = old

    def test_signed_policy_and_archive_prerequisites(self):
        demo.signed_prerequisites(self.info, self.args)
        for key in ("members", "verity", "artifacts"):
            altered = copy.deepcopy(self.info)
            altered["bundle_manifest"].pop(key)
            with self.subTest(key=key), self.assertRaises(demo.Blocked):
                demo.signed_prerequisites(altered, self.args)
        altered = copy.deepcopy(self.info)
        altered["bundle_manifest"]["members"][0]["policy"]["request_budget"]["max_requests"] = 2
        # Deepcopy matters: the fixture must not alter the gate's expected budget.
        with self.assertRaises(demo.Blocked):
            demo.signed_prerequisites(altered, self.args)

    def test_durable_attempt_cannot_be_reused_and_does_not_cleanup(self):
        path = demo.reserve_attempt(self.args, self.evidence)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            demo.reserve_attempt(self.args, self.evidence)
        self.assertTrue(path.exists())

    def test_live_requires_both_authorizations_before_spawn(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(demo.subprocess, "Popen") as spawn:
            with self.assertRaises(demo.Blocked):
                demo.live_prerequisites(self.args)
            spawn.assert_not_called()

    def fake_spawn(self, *, timeout=False, code=0):
        class Input(io.BytesIO):
            def close(self):
                self.sent = self.getvalue()
                super().close()
        process = Mock(pid=12345, stdin=Input())
        process.wait.side_effect = (
            subprocess.TimeoutExpired("fixture", 1) if timeout else None)
        process.wait.return_value = code
        def spawn(argv, **kwargs):
            self.assertEqual(argv, [str(self.args.cli), "run", "agent/claude"])
            self.assertTrue(kwargs["start_new_session"])
            kwargs["stdout"].write(b"A fresh, arbitrary response\n")
            kwargs["stdout"].flush()
            return process
        return process, spawn

    def test_dispatch_exact_bytes_once_without_flags(self):
        process, spawn = self.fake_spawn()
        report = {"commands": []}
        with patch.object(demo.subprocess, "Popen", side_effect=spawn) as calls:
            demo.dispatch_once(self.args, {}, self.evidence, report)
        self.assertEqual(process.stdin.sent, b"tell me a joke\n")
        calls.assert_called_once()
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        self.assertFalse(report["cleanup_authorized"])
        self.assertTrue((self.home / "claude-demo-attempt.json").exists())

    def test_timeout_retains_original_owner_files_and_reservation(self):
        process, spawn = self.fake_spawn(timeout=True)
        report = {"commands": []}
        with patch.object(demo.subprocess, "Popen", side_effect=spawn), \
                self.assertRaises(subprocess.TimeoutExpired):
            demo.dispatch_once(self.args, {}, self.evidence, report)
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        self.assertEqual(report["status"], "custody_unconfirmed")
        self.assertIsNone(report["model_request_attempted"])
        self.assertTrue((self.home / "claude-demo-attempt.json").exists())
        self.assertTrue((self.evidence / "joke.stdout").exists())

    def test_nonzero_exit_is_not_custody_or_acceptance(self):
        process, spawn = self.fake_spawn(code=1)
        report = {"commands": []}
        with patch.object(demo.subprocess, "Popen", side_effect=spawn), \
                self.assertRaises(demo.Blocked):
            demo.dispatch_once(self.args, {}, self.evidence, report)
        process.kill.assert_not_called()
        self.assertEqual(report["status"], "custody_unconfirmed")

    def test_canonical_collector_checks_one_session_and_uses_verified_show(self):
        calls = []
        def run(label, argv, env):
            calls.append(argv[1:])
            values = {
                "sessions": {"tenant": "local", "ledger": {"intact": True},
                             "sessions": [{"plan_id": self.plan}]},
                "audit-verify": self.verification,
                "session-events": [{"seq": i, "envelope": {"entry": entry}}
                                   for i, entry in enumerate(self.entries)],
                "endpoint-events": [{"seq": i, "envelope": {"entry": entry}}
                                    for i, entry in enumerate(self.host_entries)],
            }
            return {"stdout": json.dumps(values[label])}
        result = demo.collect(self.args, SimpleNamespace(run=run), {})
        self.assertEqual(result["plan_id"], self.plan)
        self.assertEqual(calls, [
            ["trust", "audit", "sessions", "--json"],
            ["trust", "audit", "verify", self.plan, "--json"],
            ["trust", "audit", "show", self.plan, "--json"],
            ["trust", "audit", "show", demo.UNBOUND, "--json"],
        ])

    def test_missing_binding_handoff_refuses_acceptance(self):
        self.host_entries = self.host_entries[:2]
        with self.assertRaises(demo.Blocked):
            self.assert_fixture()

    def test_proxy_and_incomplete_delivery_do_not_count_as_default_route_acceptance(self):
        labels = self.host_entries[-1]["labels"]
        for field, value in (("via", "proxy"), ("via", "no_proxy"), ("outcome", "canceled")):
            old = labels[field]
            labels[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(demo.Blocked):
                self.assert_fixture()
            labels[field] = old

    def test_original_generation_and_effective_network_must_be_exact(self):
        for alteration in ("nonce", "network"):
            proof = copy.deepcopy(self.proof)
            if alteration == "nonce":
                proof["instance"]["boot_nonce"] = [0] * 32
            else:
                proof["network_policy"]["rules"].append({"host": "example.com", "port": 443})
            self.entries[-1]["labels"]["native_completion"] = json.dumps(proof)
            with self.subTest(alteration=alteration), self.assertRaises(demo.Blocked):
                self.assert_fixture()

    def test_interruption_does_not_signal_or_release_the_attempt(self):
        process, spawn = self.fake_spawn()
        process.wait.side_effect = KeyboardInterrupt
        with patch.object(demo.subprocess, "Popen", side_effect=spawn), \
                self.assertRaises(KeyboardInterrupt):
            demo.dispatch_once(self.args, {}, self.evidence, {"commands": []})
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        self.assertTrue((self.home / "claude-demo-attempt.json").exists())

    def test_immutable_executable_is_required_before_live_use(self):
        self.args.authorize_model_request = True
        self.args.cli = Mock()
        self.args.cli.stat.return_value.st_flags = 0
        with patch.dict(os.environ, {"MVM_TEST_CLAUDE_DEMO": "1"}), \
                patch.object(demo.platform, "system", return_value="Darwin"), \
                patch.object(demo.platform, "machine", return_value="arm64"), \
                patch.object(demo.base, "released_cli"), \
                patch.object(demo.subprocess, "Popen") as spawn, \
                self.assertRaises(demo.Blocked):
            demo.live_prerequisites(self.args)
        spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
