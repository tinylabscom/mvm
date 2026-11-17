import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "claude_preflight", Path(__file__).with_name("claude-demo-preflight.py"))
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("DELTA_SCRATCH_DIR", "/tmp"))
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.home.chmod(0o700)
        self.account = self.home / "account"
        self.account.mkdir(mode=0o755)
        account_lookup = patch.object(demo.pwd, "getpwuid",
                                      return_value=SimpleNamespace(pw_dir=str(self.account)))
        self.account_lookup = account_lookup.start()
        self.addCleanup(account_lookup.stop)
        self.mvm = self.home / "mvm"
        self.mvm.mkdir(mode=0o700)
        self.cli = self.home / "mvmctl"
        self.cli.write_bytes(b"hermetic fixture, never executed")
        self.cli.chmod(0o500)
        self.args = SimpleNamespace(
            home=self.home, mvm_home=self.mvm, cli=self.cli,
            cli_sha256=demo.witness.digest(self.cli), version="mvmctl 1.0.0",
            descriptor_sha256="a" * 64, archive_sha256=demo.witness.digest(self.cli),
            archive_size=self.cli.stat().st_size, key_id="test-author",
            endpoint="api.anthropic.com:443", release_commit="b" * 40)
        self.info = dict(
            kind="application", reference=demo.REFERENCE, guest_arch="aarch64",
            manifest_sha256=self.args.descriptor_sha256,
            verification_scope="descriptor_and_bundle_archive",
            signer_identity="test-publisher", signer_issuer="test-issuer",
            bundle=dict(archive_sha256=self.args.archive_sha256,
                        archive_size=self.args.archive_size, key_id=self.args.key_id))
        self.commands = []

    def run_command(self, label, argv, env):
        self.commands.append(argv[1:])
        if label == "pull":
            bundles = self.mvm / "bundles"
            bundles.mkdir()
            (bundles / f"{self.args.archive_sha256}.mvmpkg").write_bytes(self.cli.read_bytes())
        return {"stdout": {
            "version": self.args.version + "\n", "search": "agent/claude@2.0.1\n",
            "pull": "", "verify": json.dumps(self.info),
        }[label], "stderr": ""}

    def execute(self):
        report = {}
        with patch.dict(os.environ, {"MVM_TEST_CLAUDE_DEMO": "1"}):
            demo.preflight(self.args, SimpleNamespace(run=self.run_command), report)
        return report

    def test_canonical_commands_and_measured_bytes(self):
        report = self.execute()
        self.assertEqual(report["status"], "preflight_passed")
        self.assertEqual(self.commands, [
            ["--version"], ["search", "agent/claude"], ["pull", "agent/claude"],
            ["pack", "verify", demo.REFERENCE, "--json"]])
        self.assertEqual(report["measured_archive_size"], self.args.archive_size)

    def test_opt_in_before_any_command(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(demo.Blocked):
            demo.preflight(self.args, SimpleNamespace(run=self.run_command), {})
        self.assertEqual(self.commands, [])

    def test_environment_does_not_forward_ambient_authority(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "not-a-real-key",
                                    "MVM_PACK_REGISTRY": "file:///bad",
                                    "HTTPS_PROXY": "http://bad",
                                    "DYLD_INSERT_LIBRARIES": "/bad"}):
            env = demo.consumer_environment(self.home, self.mvm)
        for key in ("ANTHROPIC_API_KEY", "MVM_PACK_REGISTRY", "HTTPS_PROXY",
                    "DYLD_INSERT_LIBRARIES"):
            self.assertNotIn(key, env)

    def test_native_home_changes_only_child_home(self):
        isolated = demo.consumer_environment(self.home, self.mvm)
        self.assertEqual(isolated["HOME"], str(self.home))
        self.assertEqual(isolated["XDG_STATE_HOME"], str(self.home / ".state"))
        ambient = {"HOME": "/ambient/not-the-account", "ANTHROPIC_API_KEY": "fake",
                   "HTTP_PROXY": "http://bad", "HTTPS_PROXY": "http://bad",
                   "ALL_PROXY": "http://bad", "MVM_HOME": "/bad/.mvm",
                   "MVM_PACK_REGISTRY": "file:///bad", "XDG_CONFIG_HOME": "/bad"}
        with patch.object(demo.platform, "system", return_value="Darwin"), \
                patch.dict(os.environ, ambient):
            native = demo.consumer_environment(self.home, self.mvm, self.account)
        self.assertEqual(native, {**isolated, "HOME": str(self.account)})
        self.account_lookup.assert_called_with(os.getuid())
        self.assertEqual(self.account.stat().st_mode & 0o777, 0o755)
        self.assertEqual(list(self.account.iterdir()), [])

    def test_native_home_refusals(self):
        link = self.home / "account-link"
        link.symlink_to(self.account)
        wrong = self.home / "wrong-account"
        wrong.mkdir()
        for native in (link, link / "missing", wrong, Path("relative"),
                       self.account / ".." / "account", self.home / "missing", self.cli):
            with self.subTest(native=native), \
                    patch.object(demo.platform, "system", return_value="Darwin"), \
                    self.assertRaises(demo.Blocked):
                demo.consumer_environment(self.home, self.mvm, native)
        with patch.object(demo.platform, "system", return_value="Linux"), \
                self.assertRaises(demo.Blocked):
            demo.consumer_environment(self.home, self.mvm, self.account)

    def test_native_home_wrong_owner_and_not_directory(self):
        original_stat = Path.stat

        def wrong_owner(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path == self.account:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() + 1)
            return info

        with patch.object(demo.platform, "system", return_value="Darwin"), \
                patch.object(Path, "stat", wrong_owner), self.assertRaises(demo.Blocked):
            demo.consumer_environment(self.home, self.mvm, self.account)
        self.account_lookup.return_value.pw_dir = str(self.cli)
        with patch.object(demo.platform, "system", return_value="Darwin"), \
                self.assertRaises(demo.Blocked):
            demo.consumer_environment(self.home, self.mvm, self.cli)

    def test_account_home_cannot_be_private_home_even_with_spoofed_home(self):
        self.account_lookup.return_value.pw_dir = str(self.home)
        with patch.dict(os.environ, {"HOME": "/unrelated"}), self.assertRaises(demo.Blocked):
            demo.consumer_environment(self.home, self.mvm)

    def test_mvm_home_must_be_strictly_beneath_private_home(self):
        for mvm in (self.home, self.home.parent):
            with self.subTest(mvm=mvm), self.assertRaises(demo.Blocked):
                demo.consumer_environment(self.home, mvm)

    def test_xdg_roots_must_be_absent_in_both_modes(self):
        for relative in (".config", ".cache", ".state"):
            for kind in ("directory", "file", "symlink"):
                path = self.home / relative
                if kind == "directory":
                    path.mkdir()
                elif kind == "file":
                    path.touch()
                else:
                    path.symlink_to(self.home / "missing")
                for native in (None, self.account):
                    with self.subTest(relative=relative, kind=kind, native=native), \
                            patch.object(demo.platform, "system", return_value="Darwin"), \
                            self.assertRaises(demo.Blocked):
                        demo.consumer_environment(self.home, self.mvm, native)
                path.rmdir() if kind == "directory" else path.unlink()

    def test_state_parent_symlinks_refused_without_traversing_stores(self):
        for relative in ("cache", "registry"):
            path = self.mvm / relative
            path.symlink_to(self.account)
            with self.subTest(relative=relative), self.assertRaises(demo.Blocked):
                demo.consumer_environment(self.home, self.mvm)
            path.unlink()
        for relative in ("trust", "bindings", "identity"):
            (self.mvm / relative).symlink_to(self.home / "missing")
        demo.consumer_environment(self.home, self.mvm)

    def test_preflight_threads_native_home_to_every_command(self):
        self.args.native_home = self.account
        environments = []

        def command(label, argv, env):
            environments.append(env)
            return self.run_command(label, argv, env)

        with patch.dict(os.environ, {"MVM_TEST_CLAUDE_DEMO": "1"}), \
                patch.object(demo.platform, "system", return_value="Darwin"):
            env = demo.preflight(self.args, SimpleNamespace(run=command), {})
        self.assertEqual(len(environments), 4)
        self.assertTrue(all(value is env for value in environments))
        self.assertEqual(env["HOME"], str(self.account))
        self.assertEqual(env["MVM_HOME"], str(self.mvm))

    def test_pristine_state_refusals(self):
        for relative in ("bundles", "cache/registry-packs", "registry/packs.lock.toml",
                         "audit", "sessions", "vms"):
            with self.subTest(relative=relative):
                path = self.mvm / relative
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.touch()
                with self.assertRaises(demo.Blocked):
                    demo.consumer_environment(self.home, self.mvm)
                path.unlink()

    def test_private_mode_and_symlink_refused(self):
        self.mvm.chmod(0o755)
        with self.assertRaises(demo.Blocked):
            demo.consumer_environment(self.home, self.mvm)
        link = self.home / "link"
        link.symlink_to(self.mvm)
        with self.assertRaises(demo.Blocked):
            demo.private_directory(link)

    def test_cli_writable_digest_relative_and_symlink_refused(self):
        for path, digest in ((Path("mvmctl"), self.args.cli_sha256),
                             (self.cli, "c" * 64)):
            with self.assertRaises(demo.Blocked):
                demo.released_cli(path, digest)
        link = self.home / "cli-link"
        link.symlink_to(self.cli)
        with self.assertRaises(demo.Blocked):
            demo.released_cli(link, self.args.cli_sha256)
        self.cli.chmod(0o700)
        with self.assertRaises(demo.Blocked):
            demo.released_cli(self.cli, self.args.cli_sha256)

    def test_descriptor_mismatches(self):
        for field in ("kind", "reference", "guest_arch", "manifest_sha256",
                      "verification_scope", "signer_identity", "signer_issuer"):
            with self.subTest(field=field), self.assertRaises(demo.Blocked):
                demo.assert_application({**self.info, field: None}, self.args)
        for field in ("archive_sha256", "archive_size", "key_id"):
            altered = {**self.info, "bundle": {**self.info["bundle"], field: None}}
            with self.subTest(field=field), self.assertRaises(demo.Blocked):
                demo.assert_application(altered, self.args)

    def test_invalid_assertions_before_commands(self):
        for field, value in (("endpoint", "example.com:443"), ("archive_size", 0),
                             ("release_commit", "main"), ("descriptor_sha256", "bad"),
                             ("key_id", "")):
            old = getattr(self.args, field)
            setattr(self.args, field, value)
            with self.subTest(field=field), self.assertRaises(demo.Blocked):
                self.execute()
            setattr(self.args, field, old)
        self.assertEqual(self.commands, [])

    def test_failure_does_not_retry_or_launch(self):
        calls = []

        def fail(label, argv, env):
            calls.append(label)
            raise demo.Blocked("fixture refusal")

        with patch.dict(os.environ, {"MVM_TEST_CLAUDE_DEMO": "1"}), \
                self.assertRaises(demo.Blocked):
            demo.preflight(self.args, SimpleNamespace(run=fail), {})
        self.assertEqual(calls, ["version"])

    def altered_command(self, target, alter):
        def run(label, argv, env):
            result = self.run_command(label, argv, env)
            return alter(result) if label == target else result
        with patch.dict(os.environ, {"MVM_TEST_CLAUDE_DEMO": "1"}), \
                self.assertRaises((demo.Blocked, json.JSONDecodeError)):
            demo.preflight(self.args, SimpleNamespace(run=run), {})
        self.assertFalse(any(command[0] == "run" for command in self.commands))

    def test_version_mismatch_stops_before_search(self):
        self.altered_command("version", lambda out: {**out, "stdout": "mvmctl wrong"})
        self.assertEqual(self.commands, [["--version"]])

    def test_search_mismatch_stops_before_pull(self):
        self.altered_command("search", lambda out: {**out, "stdout": "no results"})
        self.assertEqual(len(self.commands), 2)

    def test_policy_only_search_result_stops_before_pull(self):
        self.altered_command("search", lambda out: {**out, "stdout": "agent/claude 1.0.1 policy\n"})
        self.assertEqual(len(self.commands), 2)

    def test_invalid_json_stops_after_verification(self):
        self.altered_command("verify", lambda out: {**out, "stdout": "not JSON"})
        self.assertEqual(len(self.commands), 4)

    def test_measured_archive_tampering_refused(self):
        def tamper(out):
            archive = self.mvm / "bundles" / f"{self.args.archive_sha256}.mvmpkg"
            archive.write_bytes(b"x" * self.args.archive_size)
            return out
        self.altered_command("verify", tamper)

    def test_measured_archive_size_refused(self):
        def truncate(out):
            archive = self.mvm / "bundles" / f"{self.args.archive_sha256}.mvmpkg"
            archive.write_bytes(b"")
            return out
        self.altered_command("verify", truncate)

    def test_cli_mutation_refused(self):
        def mutate(out):
            self.cli.chmod(0o700)
            self.cli.write_bytes(b"changed executable")
            self.cli.chmod(0o500)
            return out
        self.altered_command("verify", mutate)

    def test_dangling_configuration_symlink_refused(self):
        (self.home / ".config").symlink_to(self.home / "absent")
        with self.assertRaises(demo.Blocked):
            demo.consumer_environment(self.home, self.mvm)

    def test_ordinary_home_refused(self):
        with patch.object(demo.Path, "home", return_value=self.home), \
                self.assertRaises(demo.Blocked):
            demo.consumer_environment(self.home, self.mvm)

    def test_public_caller_metadata_and_refusals(self):
        installation = "f871c10a-363d-40f4-9b16-ad97f893e4f1"
        key = list(range(32))
        pin = hashlib.sha256(bytes(key)).hexdigest()
        record = {"version": 1, "installation": installation,
                  "state": {"kind": "enrolled", "public_key": key}}
        checked = demo.assert_caller_metadata(record, installation, pin)
        self.assertEqual(checked["installation"], installation)
        self.assertIn("not_native_executable_acl", checked["scope"])
        for bad in (
            {**record, "version": 2}, {**record, "installation": "other"},
            {**record, "state": {"kind": "pending"}},
            {**record, "state": {"kind": "enrolled", "public_key": [True] * 32}},
            {**record, "state": {"kind": "enrolled", "public_key": key[:-1]}},
        ):
            with self.subTest(record=bad), self.assertRaises(demo.Blocked):
                demo.assert_caller_metadata(bad, installation, pin)
        with self.assertRaises(demo.Blocked):
            demo.assert_caller_metadata(record, installation, "f" * 64)

    def test_binding_metadata_is_exact_and_unambiguous(self):
        row = "demo-key\ttype=bearer\thosts=api.anthropic.com\tprovider=anthropic"
        checked = demo.assert_binding_metadata(row + "\n", "demo-key")
        self.assertEqual(checked["host"], "api.anthropic.com")
        for invalid in (
            "", row + "\n" + row, row.replace("demo-key", "another-key"),
            row.replace("api.anthropic.com", "*.anthropic.com"),
            row.replace("api.anthropic.com", "api.anthropic.com,example.com"),
            row + "\tapprove=ask", row.replace("type=bearer", "type=basic"),
            row.replace("provider=anthropic", "provider=unknown"),
        ):
            with self.subTest(row=invalid), self.assertRaises(demo.Blocked):
                demo.assert_binding_metadata(invalid, "demo-key")

    def test_readiness_uses_only_canonical_metadata_commands(self):
        self.args.caller_installation = "f871c10a-363d-40f4-9b16-ad97f893e4f1"
        self.args.caller_public_key_sha256 = hashlib.sha256(bytes(range(32))).hexdigest()
        self.args.binding_name = "demo-key"
        calls = []

        def command(label, argv, env):
            calls.append(argv[1:])
            return {"stdout": json.dumps({
                "version": 1, "installation": self.args.caller_installation,
                "state": {"kind": "enrolled", "public_key": list(range(32))},
            }) if label == "caller-metadata" else
                "demo-key\ttype=bearer\thosts=api.anthropic.com\tprovider=anthropic\n"}

        report = {}
        demo.readiness(self.args, SimpleNamespace(run=command), {}, report)
        self.assertEqual(calls, [["env", "caller-identity", "show"], ["secret", "ls"]])
        self.assertNotIn("custody_verified", report)


if __name__ == "__main__":
    unittest.main()
