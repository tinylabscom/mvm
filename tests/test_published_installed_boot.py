"""Hermetic validator tests, not boot evidence. No release/VM commands run."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "boot", Path(__file__).resolve().parents[1] / "scripts/published-installed-boot.py")
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)
TAG = "v1.2.3"
ENV = {
    "GITHUB_EVENT_NAME": "push", "GITHUB_REF": f"refs/tags/{TAG}",
    "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": "example/mvm",
    "GITHUB_WORKFLOW_REF": f"example/mvm/{boot.WORKFLOW}@refs/tags/{TAG}",
    "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
}


def archive(path, target, content=b"test CLI bytes"):
    with tarfile.open(path, "w:gz") as tar:
        root = tarfile.TarInfo(f"mvmctl-{target}")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        member = tarfile.TarInfo(f"mvmctl-{target}/mvmctl")
        member.size = len(content)
        tar.addfile(member, io.BytesIO(content))


class BootEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, ENV)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.lanes = self.root / "lanes"
        self.lanes.mkdir()
        (self.assets / f"mvm-guest-bins-{TAG}.tar.gz").write_bytes(b"test runtime bytes")
        for target in boot.LANES:
            archive(self.assets / f"mvmctl-{target}.tar.gz", target)
        self.asset_records = sorted(
            [{"name": p.name, "sha256": boot.sha(p)} for p in self.assets.iterdir()],
            key=lambda a: a["name"])
        self.records = []
        for target, (arch, backend, _, _) in boot.LANES.items():
            lane_dir = self.lanes / f"installed-boot-lane-{target}"
            (lane_dir / "smoke").mkdir(parents=True)
            transcript = lane_dir / "smoke/transcript.log"
            transcript.write_text("TEST FIXTURE ONLY\nPASS: simulated validator input\n")
            (lane_dir / "smoke/boot-results.jsonl").write_text(
                "".join(json.dumps(check) + "\n" for check in boot.BOOT_CHECKS))
            installed = boot.payload_hashes(self.assets / f"mvmctl-{target}.tar.gz", target)
            installed[f"guest-runtime/mvm-guest-bins-{TAG}.tar.gz"] = boot.sha(
                self.assets / f"mvm-guest-bins-{TAG}.tar.gz")
            record = boot.identity(TAG)
            record.update(
                assets=[a for a in self.asset_records if a["name"] in (
                    f"mvmctl-{target}.tar.gz", f"mvm-guest-bins-{TAG}.tar.gz")],
                boots=[dict(host_target=target, guest_arch=arch, backend=backend,
                            result="success", checks=copy.deepcopy(boot.BOOT_CHECKS),
                            installed=[{"path": n, "sha256": h}
                                       for n, h in sorted(installed.items())],
                            transcript={"path": "smoke/transcript.log",
                                        "sha256": boot.sha(transcript)})])
            path = lane_dir / "lane.json"
            path.write_text(json.dumps(record))
            self.records.append(path)
        self.args = SimpleNamespace(tag=TAG, assets=self.assets, lanes=self.lanes,
                                    out=self.root / "report/installed-boot.json")

    def aggregate(self):
        with patch.object(boot, "authenticate", return_value=self.asset_records):
            boot.aggregate(self.args)

    def test_exact_aggregate_interface(self):
        self.aggregate()
        report = json.loads(self.args.out.read_text())
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["cli"], {"tag": TAG, "commit": "a" * 40})
        self.assertEqual(report["workflow"]["run_attempt"], "2")
        self.assertEqual(len(report["assets"]), 3)
        self.assertEqual(len(report["boots"]), 2)
        self.assertIn("ARM Linux KVM", report["unverified"][0]["reason"])

    def test_rejects_identity_result_asset_and_installed_tampering(self):
        original = json.loads(self.records[0].read_text())
        changes = [
            lambda r: r["cli"].update(tag="v9.9.9"),
            lambda r: r["cli"].update(commit="b" * 40),
            lambda r: r["workflow"].update(run_id="999"),
            lambda r: r["workflow"].update(run_attempt="1"),
            lambda r: r["workflow"].update(path=".github/workflows/other.yml"),
            lambda r: r["assets"][0].update(sha256="0" * 64),
            lambda r: r["boots"][0].update(result="failed"),
            lambda r: r["boots"][0].pop("result"),
            lambda r: r["boots"][0].update(backend="hvf"),
            lambda r: r["boots"][0]["installed"][0].update(sha256="0" * 64),
            lambda r: r["boots"][0]["transcript"].update(path="../../other"),
        ]
        for change in changes:
            with self.subTest(change=change):
                altered = copy.deepcopy(original)
                change(altered)
                self.records[0].write_text(json.dumps(altered))
                with self.assertRaises((ValueError, KeyError)):
                    self.aggregate()
                self.assertFalse(self.args.out.exists())

    def test_rejects_missing_duplicate_and_tampered_transcript(self):
        original = self.records[1].read_text()
        self.records[1].unlink()
        with self.assertRaises(ValueError):
            self.aggregate()
        self.records[1].write_text(self.records[0].read_text())
        with self.assertRaises(ValueError):
            self.aggregate()
        self.records[1].write_text(original)
        (self.records[0].parent / "smoke/transcript.log").write_text("tampered")
        with self.assertRaises(ValueError):
            self.aggregate()

    def test_missing_success_verdict_even_with_matching_transcript_hash(self):
        path = self.records[0]
        record = json.loads(path.read_text())
        transcript = path.parent / "smoke/transcript.log"
        transcript.write_text("TEST FIXTURE ONLY\nno verdict\n")
        record["boots"][0]["transcript"]["sha256"] = boot.sha(transcript)
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "successful smoke verdict"):
            self.aggregate()

    def test_manual_branch_and_wrong_workflow_are_not_authoritative(self):
        for changes in [
            {"GITHUB_EVENT_NAME": "workflow_dispatch"},
            {"GITHUB_REF": "refs/heads/main"},
            {"GITHUB_WORKFLOW_REF": f"example/mvm/other.yml@refs/tags/{TAG}"},
        ]:
            with patch.dict(os.environ, changes), self.assertRaises(ValueError):
                boot.identity(TAG)

    def test_installed_bytes_not_redownloaded_bytes(self):
        target = next(iter(boot.LANES))
        home = self.root / "home"
        base = home / ".local/lib/mvm/current"
        base.mkdir(parents=True)
        (home / ".local/bin").mkdir()
        (base / "mvmctl").write_bytes(b"test CLI bytes")
        (home / ".local/bin/mvmctl").symlink_to(base / "mvmctl")
        runtime = base / f"guest-runtime/mvm-guest-bins-{TAG}.tar.gz"
        runtime.parent.mkdir()
        runtime.write_bytes(b"test runtime bytes")
        boot.installed_hashes(home, self.assets, target, TAG)
        runtime.write_bytes(b"mutated installed runtime")
        with self.assertRaisesRegex(ValueError, "installed bytes mismatch"):
            boot.installed_hashes(home, self.assets, target, TAG)
        runtime.write_bytes(b"test runtime bytes")
        (base / "mvmctl").write_bytes(b"mutated installed CLI")
        with self.assertRaisesRegex(ValueError, "installed entrypoint mismatch"):
            boot.installed_hashes(home, self.assets, target, TAG)
        (base / "mvmctl").write_bytes(b"test CLI bytes")
        (base / "other").write_bytes(b"wrong executable")
        (home / ".local/bin/mvmctl").unlink()
        (home / ".local/bin/mvmctl").symlink_to(base / "other")
        with self.assertRaisesRegex(ValueError, "installed entrypoint mismatch"):
            boot.installed_hashes(home, self.assets, target, TAG)

    def test_authentication_exact_constraints_and_fail_closed(self):
        manifest = self.assets / "checksums-sha256.txt"
        manifest.write_text("".join(f'{a["sha256"]}  {a["name"]}\n'
                                    for a in self.asset_records))
        with patch.object(boot, "run") as commands:
            result = boot.authenticate(self.assets, TAG, list(boot.LANES))
        self.assertEqual(result, self.asset_records)
        calls = [call.args for call in commands.call_args_list]
        attestations = [c for c in calls if c[:3] == ("gh", "attestation", "verify")]
        self.assertEqual(len(attestations), 3)
        for call in attestations:
            self.assertEqual(call[call.index("--source-ref") + 1], f"refs/tags/{TAG}")
            self.assertEqual(call[call.index("--source-digest") + 1], "a" * 40)
        for call in [c for c in calls if c[:2] == ("cosign", "verify-blob")]:
            self.assertEqual(call[call.index("--certificate-identity") + 1],
                             f"https://github.com/example/mvm/{boot.WORKFLOW}@refs/tags/{TAG}")
            self.assertEqual(call[call.index("--certificate-oidc-issuer") + 1],
                             "https://token.actions.githubusercontent.com")
        with patch.object(boot, "run", side_effect=subprocess.CalledProcessError(1, "cosign")):
            with self.assertRaises(subprocess.CalledProcessError):
                boot.authenticate(self.assets, TAG, list(boot.LANES))
        manifest.write_text(manifest.read_text() + manifest.read_text())
        with patch.object(boot, "run"), self.assertRaisesRegex(ValueError, "duplicate"):
            boot.authenticate(self.assets, TAG, list(boot.LANES))

    def test_failed_smoke_and_bad_state_never_emit_or_delete(self):
        target = next(iter(boot.LANES))
        _, _, system, machine = boot.LANES[target]
        for state in (None, "/home/user\n", "/tmp/mvm-fresh.fake/home\nextra\n"):
            output = self.root / f"failed-{len(list(self.root.iterdir()))}"
            args = SimpleNamespace(tag=TAG, target=target, out=output)
            owned = []

            def failed_run(*args, **kwargs):
                owned.append(Path(kwargs["env"]["MVM_SMOKE_TEMP_PARENT"]))
                if state is not None:
                    Path(kwargs["env"]["MVM_SMOKE_STATE_FILE"]).write_text(state)
                raise subprocess.CalledProcessError(1, "smoke")

            with patch.object(boot.platform, "system", return_value=system), \
                 patch.object(boot.platform, "machine", return_value=machine), \
                 patch.object(boot, "authenticate", return_value=self.asset_records), \
                 patch.object(boot, "run", side_effect=failed_run):
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    boot.lane(args)
                self.assertFalse(owned[0].exists())
                self.assertFalse((output / "lane.json").exists())

    def test_malicious_state_cannot_delete_another_smoke(self):
        target = next(iter(boot.LANES))
        _, _, system, machine = boot.LANES[target]
        with tempfile.TemporaryDirectory(prefix="mvm-fresh.", dir="/tmp") as root:
            home = Path(root) / "home"
            home.mkdir()
            sentinel = home / "keep-me"
            sentinel.write_text("another concurrent smoke's state")
            for failed in (False, True):
                args = SimpleNamespace(tag=TAG, target=target,
                                       out=self.root / f"malicious-{failed}")
                owned = []

                def malicious_run(*args, **kwargs):
                    owned.append(Path(kwargs["env"]["MVM_SMOKE_TEMP_PARENT"]))
                    Path(kwargs["env"]["MVM_SMOKE_STATE_FILE"]).write_text(str(home) + "\n")
                    if failed:
                        raise subprocess.CalledProcessError(1, "smoke")

                with patch.object(boot.platform, "system", return_value=system), \
                     patch.object(boot.platform, "machine", return_value=machine), \
                     patch.object(boot, "authenticate", return_value=self.asset_records), \
                     patch.object(boot, "run", side_effect=malicious_run):
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        boot.lane(args)
                    self.assertFalse(owned[0].exists())
                    self.assertTrue(sentinel.exists())
                    self.assertFalse((args.out / "lane.json").exists())

    def test_state_requires_canonical_owned_descendant(self):
        owned = self.root.resolve() / "owned"
        home = owned / "s.ABC/home"
        home.mkdir(parents=True)
        state = self.root / "state"
        state.write_text(str(home) + "\n")
        self.assertEqual(boot.smoke_home(state, owned), home)
        link = owned / "s.DEF"
        link.symlink_to(home.parent, target_is_directory=True)
        state.write_text(str(link / "home") + "\n")
        with self.assertRaisesRegex(ValueError, "unsafe smoke HOME"):
            boot.smoke_home(state, owned)

    def test_shell_handoff_uses_owned_short_root_without_booting(self):
        # Deliberate installer failure exercises the real shell handoff, but
        # cannot execute mvmctl, boot a guest, or produce successful evidence.
        installer = self.root / "failing-installer.sh"
        installer.write_text("#!/bin/sh\nexit 1\n")
        state = self.root / "shell-state"
        out = self.root / "shell-out"
        env = {k: v for k, v in os.environ.items() if not k.startswith("MVM_")}
        env.pop("GITHUB_STEP_SUMMARY", None)
        env.pop("GITHUB_ACTIONS", None)
        env.update(MVM_SMOKE_KEEP="1", MVM_SMOKE_INSTALLER=str(installer),
                   MVM_SMOKE_STATE_FILE=str(state), MVM_SMOKE_OUT=str(out),
                   MVM_SMOKE_INSTALL_BUDGET_SECS="5")
        with tempfile.TemporaryDirectory(prefix="w.", dir="/tmp") as scratch:
            owned = Path(scratch).resolve()
            env["MVM_SMOKE_TEMP_PARENT"] = str(owned)
            result = subprocess.run(
                ["sh", str(Path(boot.__file__).parent / "smoke-fresh-install.sh"), TAG],
                env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            home = boot.smoke_home(state, owned)
            self.assertTrue(home.is_dir())
            self.assertEqual((out / "boot-results.jsonl").read_text(), "")
            self.assertIn("FAIL: the install exited 1", (out / "transcript.log").read_text())
        self.assertFalse(owned.exists())

    def test_requires_exact_four_successful_outcomes(self):
        path = self.records[0]
        original = json.loads(path.read_text())
        for checks in ([], boot.BOOT_CHECKS[:-1], boot.BOOT_CHECKS + boot.BOOT_CHECKS[:1],
                       [{"name": c["name"], "result": "failed"} for c in boot.BOOT_CHECKS]):
            with self.subTest(checks=checks):
                record = copy.deepcopy(original)
                record["boots"][0]["checks"] = checks
                path.write_text(json.dumps(record))
                (path.parent / "smoke/boot-results.jsonl").write_text(
                    "".join(json.dumps(check) + "\n" for check in checks))
                with self.assertRaisesRegex(ValueError, "four-boot outcomes"):
                    self.aggregate()


if __name__ == "__main__":
    unittest.main()
