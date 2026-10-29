"""Offline validation only: never download, invoke Cargo, or load native code."""

import copy
import argparse
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "rust_registry_smoke", Path(__file__).with_name("rust-registry-smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class RegistrySmokeTests(unittest.TestCase):
    def metadata(self):
        return {
            "resolve": {"root": "consumer"},
            "packages": [
                {"id": "consumer", "name": "registry-witness", "source": None,
                 "manifest_path": "/tmp/consumer/Cargo.toml",
                 "dependencies": [{"name": "runmvm-client", "req": "=1.2.3",
                                   "source": smoke.REGISTRY}]},
                {"id": "facade", "name": "runmvm-client", "version": "1.2.3",
                 "source": smoke.REGISTRY, "manifest_path": "/tmp/cargo/facade/Cargo.toml"},
            ],
        }

    def check(self, metadata):
        return smoke.check_metadata(metadata, Path("/tmp/consumer"),
                                    "1.2.3", Path("/checkout"))

    def test_cargo_config_isolation_real_filesystem(self):
        # These are filesystem checks, not Cargo/registry acceptance evidence.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            project = root / "parent" / "nested" / "consumer"
            project.mkdir(parents=True)
            cargo_home = root / "cargo-home"
            cargo_home.mkdir()
            smoke.check_cargo_config_isolation(project, cargo_home)
            for directory in (
                project / ".cargo", project.parent / ".cargo",
                root / ".cargo", cargo_home,
            ):
                directory.mkdir(exist_ok=True)
                for name in ("config", "config.toml"):
                    with self.subTest(directory=directory, name=name):
                        config = directory / name
                        secret = "fixture-secret-not-for-errors"
                        config.write_text(secret)
                        try:
                            with patch.object(Path, "open", side_effect=AssertionError(
                                    "configuration contents must not be opened")):
                                with self.assertRaisesRegex(
                                        ValueError, "Cargo configuration isolation") as error:
                                    smoke.check_cargo_config_isolation(project, cargo_home)
                            self.assertNotIn(secret, str(error.exception))
                            self.assertNotIn(str(config), str(error.exception))
                        finally:
                            config.unlink()
                        smoke.check_cargo_config_isolation(project, cargo_home)

    def test_cargo_config_isolation_rejects_dangling_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "Cargo configuration isolation"):
                smoke.check_cargo_config_isolation(root, root / "cargo-home")

    def test_exact_registry_facade(self):
        self.assertEqual(self.check(self.metadata())["source"], smoke.REGISTRY)

    def test_rejects_path_git_wrong_version_and_checkout_sources(self):
        for change in (
            {"source": None}, {"source": "git+https://example.com/facade"},
            {"version": "1.2.4"}, {"manifest_path": "/checkout/crates/facade/Cargo.toml"},
        ):
            with self.subTest(change=change):
                metadata = self.metadata()
                metadata["packages"][1].update(change)
                with self.assertRaises(ValueError):
                    self.check(metadata)

    def test_rejects_nonexact_or_extra_direct_dependencies(self):
        metadata = self.metadata()
        metadata["packages"][0]["dependencies"][0]["req"] = "^1.2.3"
        with self.assertRaises(ValueError):
            self.check(metadata)
        metadata = self.metadata()
        metadata["packages"][0]["dependencies"].append(
            copy.deepcopy(metadata["packages"][0]["dependencies"][0]))
        with self.assertRaises(ValueError):
            self.check(metadata)

    def test_rejects_internal_transitive_dependency(self):
        metadata = self.metadata()
        internal = copy.deepcopy(metadata["packages"][1])
        internal.update(id="internal", name="mvm-runtime")
        metadata["packages"].append(internal)
        with self.assertRaises(ValueError):
            self.check(metadata)

    def test_tag_validation(self):
        self.assertEqual(smoke.release_version("v1.2.3"), "1.2.3")
        for tag in ("main", "--latest", "v1.2", "v1.2.3/evil", ""):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                smoke.release_version(tag)

    def test_native_platform_and_gnu_only(self):
        with patch.object(smoke.platform, "system", return_value="Linux"), \
                patch.object(smoke.platform, "machine", return_value="aarch64"), \
                patch.object(smoke.platform, "libc_ver", return_value=("glibc", "2.35")):
            smoke.check_platform("aarch64-unknown-linux-gnu")
            with self.assertRaises(ValueError):
                smoke.check_platform("x86_64-unknown-linux-gnu")
            with patch.object(smoke.platform, "libc_ver", return_value=("musl", "1.2")):
                with self.assertRaises(ValueError):
                    smoke.check_platform("aarch64-unknown-linux-gnu")

    def test_structured_witness_checks_abi_path_method_and_empty_reply(self):
        library = Path("/tmp/released/libmvm_hostlib.so")
        good = {"library": str(library), "abi": (1 << 16) | 7,
                "method": "manifest.list", "reply": []}
        self.assertEqual(smoke.witness(json.dumps(good), library), good)
        for change in (
            {"library": "/checkout/lib.so"}, {"abi": (1 << 16) | 6},
            {"abi": (2 << 16) | 7}, {"method": "machine.run"},
            {"reply": {}}, {"reply": [{"name": "unexpected"}]},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                smoke.witness(json.dumps(good | change), library)

    def archive(self, path, members):
        with tarfile.open(path, "w:gz") as payload:
            for name, kind in members:
                member = tarfile.TarInfo(name)
                member.mode = 0o755
                if kind == "link":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/tmp/outside"
                    payload.addfile(member)
                elif kind == "directory":
                    member.type = tarfile.DIRTYPE
                    payload.addfile(member)
                else:
                    member.size = 4
                    payload.addfile(member, io.BytesIO(b"fake"))

    def test_archive_preserves_helpers_and_requires_hostlib(self):
        target = "aarch64-apple-darwin"
        root = f"mvmctl-{target}"
        names = ["mvmctl", "mvm-network-endpoint", "mvm-hvf-supervisor",
                 "libmvm_hostlib.dylib"]
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            archive = work / "release.tar.gz"
            self.archive(archive, [(f"{root}/{n}", "file") for n in names])
            prefix, library = smoke.extract_release(archive, work / "extract", target)
            self.assertEqual(library.parent, prefix)
            self.assertTrue(all((prefix / name).is_file() for name in names))
            self.archive(archive, [(f"{root}/mvmctl", "file")])
            with self.assertRaises(ValueError):
                smoke.extract_release(archive, work / "missing", target)

    def test_archive_rejects_traversal_links_and_wrong_root(self):
        target = "x86_64-unknown-linux-gnu"
        for name, kind in (("../evil", "file"), ("/absolute", "file"),
                           ("wrong/lib.so", "file"),
                           (f"mvmctl-{target}/lib.so", "link")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                self.archive(work / "bad.tar.gz", [(name, kind)])
                with self.assertRaises(ValueError):
                    smoke.extract_release(work / "bad.tar.gz", work / "out", target)

    def test_shared_archive_parser_accepts_appledouble_companions(self):
        target = "aarch64-apple-darwin"
        root = f"mvmctl-{target}"
        names = ["mvmctl", "mvm-network-endpoint", "mvm-hvf-supervisor",
                 "libmvm_hostlib.dylib"]
        members = [(root, "directory"), (f"._{root}", "file")]
        members += [(f"{root}/{name}", "file") for name in names]
        members += [(f"{root}/._{name}", "file") for name in names]
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            archive = work / "release.tar.gz"
            self.archive(archive, members)
            # Exercise exactly the parser CLI the shell verifier invokes, then
            # the registry consumer seam against the very same archive.
            result = subprocess.run(
                ["python3", smoke._envelope.__file__, str(archive),
                 str(work / "helper"), root], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            prefix, library = smoke.extract_release(archive, work / "consumer", target)
            self.assertEqual(library.parent, prefix)
            self.assertTrue(all((prefix / name).is_file() for name in names))
            self.assertFalse(any((work / "helper").rglob("._*")))
            self.assertFalse(any((work / "consumer").rglob("._*")))

    def test_shared_archive_parser_rejects_orphan_and_malicious_companions(self):
        target = "aarch64-apple-darwin"
        root = f"mvmctl-{target}"
        for bad in (
            [(f"._{root}", "file")],
            [(root, "directory"), (f"._{root}", "link")],
            [(root, "directory"), (f"._{root}/evil", "file")],
            [(root, "directory"), (f"{root}/../._{root}", "file")],
            [(f"{root}/._orphan", "file")],
            [(f"{root}/mvmctl", "file"), (f"{root}/mvmctl", "file")],
        ):
            with self.subTest(members=bad), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                archive = work / "bad.tar.gz"
                self.archive(archive, bad)
                result = subprocess.run(
                    ["python3", smoke._envelope.__file__, str(archive),
                     str(work / "helper"), root], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("archive envelope validation failed", result.stderr)
                self.assertFalse((work / "helper").exists())
                with self.assertRaises(ValueError):
                    smoke.extract_release(archive, work / "consumer", target)
                self.assertFalse((work / "consumer").exists())

    def test_failed_authentication_never_runs_cargo_or_loads_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            args = argparse.Namespace(tag="v1.2.3", target="aarch64-apple-darwin",
                                      repository="tinylabscom/mvm", assets_dir=work,
                                      evidence=work / "evidence")
            failure = subprocess.CompletedProcess([], 1, "rejected", "bad signature")
            with patch.object(smoke, "check_platform"), \
                    patch.object(smoke.subprocess, "run", return_value=failure) as run, \
                    patch.object(smoke, "extract_release") as extract:
                with self.assertRaises(subprocess.CalledProcessError):
                    smoke.smoke(args)
                extract.assert_not_called()
                self.assertEqual(run.call_count, 1)
                argv = run.call_args.args[0]
                self.assertIn("--cosign", argv)
                self.assertIn("--expect-version", argv)
                env = run.call_args.kwargs["env"]
                self.assertEqual(env["COSIGN_IDENTITY"],
                                 "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v1.2.3")
                self.assertNotIn("MVM_HOSTLIB_PATH", env)
                self.assertIn("bad signature", (args.evidence / "commands.log").read_text())

    def test_full_command_sequence_with_mocked_processes(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            target = "aarch64-apple-darwin"
            archive = work / f"mvmctl-{target}.tar.gz"
            self.archive(archive, [(f"mvmctl-{target}/{name}", "file") for name in
                                  ("mvmctl", "mvm-network-endpoint", "mvm-hvf-supervisor",
                                   "libmvm_hostlib.dylib")])
            args = argparse.Namespace(tag="v1.2.3", target=target,
                                      repository="tinylabscom/mvm", assets_dir=work,
                                      evidence=work / "evidence")

            def process(argv, **kwargs):
                cwd = kwargs["cwd"]
                output = ""
                if argv[0] == "cargo":
                    if argv[1] == "generate-lockfile":
                        (cwd / "Cargo.lock").write_text("mock lock\n")
                    elif argv[1] == "metadata":
                        metadata = self.metadata()
                        metadata["packages"][0]["manifest_path"] = str(cwd / "Cargo.toml")
                        metadata["packages"][1]["manifest_path"] = str(work / "cargo/facade/Cargo.toml")
                        output = json.dumps(metadata)
                    elif argv[1] == "run":
                        output = json.dumps({"library": kwargs["env"]["MVM_HOSTLIB_PATH"],
                                             "abi": 65543, "method": "manifest.list", "reply": []})
                elif argv[-1] == "--version":
                    output = "mvmctl 1.2.3\n"
                return subprocess.CompletedProcess(argv, 0, output, "")

            with patch.object(smoke, "check_platform"), \
                    patch.object(smoke.subprocess, "run", side_effect=process), \
                    patch.object(smoke, "check_cargo_config_isolation",
                                 wraps=smoke.check_cargo_config_isolation) as isolation, \
                    patch("builtins.print"):
                smoke.smoke(args)
            self.assertEqual(isolation.call_count, 4)
            for call in isolation.call_args_list:
                self.assertEqual(call.args[0].name, "consumer")
                self.assertEqual(Path(call.args[1]).name, "cargo")
            evidence = json.loads((args.evidence / "evidence.json").read_text())
            cargo = [argv for argv in evidence["argv"] if argv[0] == "cargo"]
            self.assertEqual(cargo, [
                ["cargo", "generate-lockfile"],
                ["cargo", "metadata", "--format-version", "1", "--locked"],
                ["cargo", "build", "--locked"],
                ["cargo", "run", "--locked", "--quiet"],
            ])
            self.assertFalse(evidence["guest_boot_witnessed"])
            self.assertFalse(evidence["vm_boot_witnessed"])
            self.assertEqual(evidence["archive_sha256"],
                             smoke.hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual((args.evidence / "main.rs").read_text(), smoke.RUST_SOURCE)

    def test_workflow_is_only_reusable_and_gated_after_publish(self):
        root = Path(__file__).resolve().parent.parent
        workflow = (root / ".github/workflows/rust-registry-smoke.yml").read_text()
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("musl", workflow)
        self.assertEqual(workflow.count("          - target:"), 3)
        publish = (root / ".github/workflows/publish-crates.yml").read_text()
        gate = publish.split("  rust-registry-smoke:\n", 1)[1].split("  publish:\n", 1)[0]
        for required in ("needs: [publish]", "github.event_name == 'workflow_dispatch'",
                         "format('{0}', inputs.dry_run) == 'false'",
                         "needs.publish.result == 'success'"):
            self.assertIn(required, gate)


if __name__ == "__main__":
    unittest.main()
