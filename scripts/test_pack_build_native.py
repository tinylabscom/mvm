"""Offline driver tests. No subprocess, VM, Nix, signer, or cloud is started."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("pack_native", HERE / "pack-build-native.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
# macOS's system temporary directory has symlinked ancestors. Select its
# canonical spelling explicitly; the production evidence reader must not follow.
tempfile.tempdir = str(Path(tempfile.gettempdir()).resolve(strict=True))


def archive(path, payload=b"rootfs", **extra):
    with tarfile.open(path, "w") as tar:
        for name, data in {"rootfs.ext4": payload, "manifest.json": b"{}", **extra}.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))


class NativeDriverTests(unittest.TestCase):
    def test_command_records_exact_argv_exit_and_isolates_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            seen = []

            def fake(argv, **kwargs):
                seen.append((argv, kwargs))
                return subprocess.CompletedProcess(argv, 0, b"ok\n", b"details\n")

            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "never-forward",
                                          "MVM_HOME": "/producer"}):
                commands = native.Commands("/explicit/mvmctl", evidence, fake)
                commands.call(evidence / "home", "one", ["pack", "lock", "a b.json"])
            self.assertEqual(seen[0][0], ["/explicit/mvmctl", "pack", "lock", "a b.json"])
            self.assertNotIn("ANTHROPIC_API_KEY", seen[0][1]["env"])
            self.assertEqual(seen[0][1]["env"]["MVM_BUILDER_BACKEND"], "firecracker")
            record = json.loads((evidence / "01-one.json").read_text())
            self.assertEqual(record["exit"], 0)
            self.assertEqual((evidence / "01-one.stdout").read_bytes(), b"ok\n")

    def test_refusal_needs_nonzero_exit_and_correct_reason(self):
        for status, stderr in ((0, b"unknown key"), (1, b"unrelated parse error")):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory)
                commands = native.Commands(
                    "/unused", evidence,
                    lambda argv, **kw: subprocess.CompletedProcess(argv, status, b"", stderr))
                with self.assertRaises(RuntimeError):
                    commands.call(evidence / "home", "refuse", [], refusal="unknown key")
                self.assertEqual(json.loads((evidence / "01-refuse.json").read_text())["exit"],
                                 status)

    def test_timeout_preserves_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)

            def timeout(argv, **kwargs):
                raise subprocess.TimeoutExpired(argv, 5, output=b"partial", stderr=b"failure")

            with self.assertRaises(subprocess.TimeoutExpired):
                native.Commands("/unused", evidence, timeout).call(
                    evidence / "home", "timeout", [], timeout=5)
            self.assertEqual((evidence / "01-timeout.stdout").read_bytes(), b"partial")
            self.assertEqual(json.loads((evidence / "01-timeout.json").read_text())["failure"],
                             "timeout")

    def test_tar_reader_refuses_links_duplicates_and_oversized_members(self):
        for kind in ("link", "duplicate", "oversize"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "input.img"
                with tarfile.open(path, "w") as tar:
                    entry = tarfile.TarInfo("work/flake.nix")
                    if kind == "link":
                        entry.type = tarfile.SYMTYPE
                        entry.linkname = "/etc/passwd"
                        tar.addfile(entry)
                    else:
                        data = b"x" * (native.LIMIT + 1) if kind == "oversize" else b"x"
                        entry.size = len(data)
                        tar.addfile(entry, io.BytesIO(data))
                        if kind == "duplicate":
                            tar.addfile(entry, io.BytesIO(data))
                with self.assertRaises(ValueError):
                    native.members(path, {"work/flake.nix"})

    def test_payload_tamper_keeps_manifest_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            before = Path(directory) / "before.mvmpkg"
            after = Path(directory) / "after.mvmpkg"
            archive(before, **{"manifest.sig": b"signature"})
            native.tamper(before, after)
            old = native.members(before, {"rootfs.ext4", "manifest.json", "manifest.sig"})
            new = native.members(after, {"rootfs.ext4", "manifest.json", "manifest.sig"})
            self.assertEqual(old["manifest.json"], new["manifest.json"])
            self.assertEqual(old["manifest.sig"], new["manifest.sig"])
            self.assertNotEqual(old["rootfs.ext4"], new["rootfs.ext4"])

    def test_workflow_order_and_real_sdk_fixture_without_live_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "work"
            workspace.mkdir()
            evidence = Path(directory) / "evidence"
            evidence.mkdir()
            seen = []

            class FakeCommands:
                def call(self, home, label, args, **kwargs):
                    seen.append((home.name, label, args))
                    if label == "lock":
                        Path(args[-1]).write_text('{"compiler":{"mvm_revision":"'
                                                 + "a" * 40 + '"}}')
                    if label == "build":
                        archive(evidence / "native-hello.mvmpkg")
                        (home / "keys").mkdir()
                        (home / "keys/host-signer.pub").write_bytes(b"p" * 32)
                    if label == "trust":
                        (home / "trusted-publishers").mkdir()
                        (home / "trusted-publishers/test.pub").write_bytes(b"p" * 32)
                    if label == "run":
                        self.assert_no_source()
                        return (native.HELLO + "\n").encode()
                    if label == "check-artifact":
                        return json.dumps({
                            "verified": True, "runnable_here": True, "arch": "x86_64",
                            "bundle_sha256": native.digest(evidence / "native-hello.mvmpkg"),
                            "posture": {"profile": "sealed-prod", "verity_protected": True,
                                        "egress": "deny-all", "volumes": False},
                        }).encode()
                    return b""

                def assert_no_source(self):
                    if (workspace / "authored").exists():
                        raise AssertionError("producer source still accessible")

            result = native.workflow(FakeCommands(), workspace, evidence, "a" * 40)
            labels = [item[1] for item in seen]
            self.assertLess(labels.index("lock"), labels.index("build"))
            self.assertLess(labels.index("unknown-key"), labels.index("trust"))
            self.assertLess(labels.index("consumer-bootstrap"), labels.index("run"))
            self.assertLess(labels.index("check-artifact"), labels.index("run"))
            for _, label, args in seen:
                if label.endswith("-audit"):
                    self.assertEqual(args, ["trust", "audit", "verify"])
            self.assertNotIn("bootstrap", [item[2][0] for item in seen
                                           if item[0] == "no-runtime"])
            authored = json.loads((evidence / "pack.json").read_text())
            self.assertEqual(authored["packages"][0]["scope"], "runtime")
            self.assertEqual(authored["copy"][0]["destination"], "/app/hello.txt")
            self.assertEqual(result["locked_revision_consumption"], "unobserved")
            self.assertEqual(result["NoPreparedRuntime"], "refusal-observed")
            self.assertFalse(any(item["exists"] for item in json.loads(
                (evidence / "no-runtime-before.json").read_text()).values()))
            workspace = Path(directory) / "work-acquisition"
            workspace.mkdir()
            evidence = Path(directory) / "evidence-acquisition"
            evidence.mkdir()
            with patch.object(native, "snapshot_files",
                              side_effect=[{}, {}, {}, {}, {}, {
                                  "cache/runtime.img": {"exists": True, "type": "regular",
                                                        "sha256": "unexpected"}}]):
                with self.assertRaisesRegex(RuntimeError, "acquired or modified"):
                    native.workflow(FakeCommands(), workspace, evidence, "a" * 40)

    def test_cleanup_attempts_every_isolated_home_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            for name in ("producer", "consumer", "no-runtime"):
                (workspace / name).mkdir()
            seen = []

            class FailingCleanup:
                def call(self, home, label, args, **kwargs):
                    seen.append((home.name, args))
                    if home.name == "producer":
                        raise RuntimeError("cleanup refused")

            failures = native.cleanup(FailingCleanup(), workspace, verify=lambda home: [])
            self.assertEqual([name for name, _ in seen],
                             ["producer", "consumer", "no-runtime"])
            self.assertEqual(len(failures), 1)
            self.assertEqual(seen[0][1], ["machine", "stop", "--all", "--yes"])

    def test_guard_refuses_host_before_executing_any_binary(self):
        with patch.object(native.platform, "system", return_value="Darwin"):
            with self.assertRaisesRegex(RuntimeError, "native x86_64 Linux"):
                native.guard(Path("/must-not-run"))

    def test_specific_refusals_do_not_accept_filename_or_argv_echo(self):
        for diagnostic, argv in (
            (native.TAMPER_REFUSAL, ["bundle", "fetch", "tampered.mvmpkg"]),
            (native.SEALED_REFUSAL, ["sealed", "entrypoint", "ad-hoc"]),
            (native.RUNTIME_REFUSAL, ["bootstrap"])):
            with tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory)
                commands = native.Commands("/unused", evidence, lambda args, **kw:
                    subprocess.CompletedProcess(args, 1, b"", (" ".join(argv) +
                        ": unrelated error").encode()))
                with self.assertRaisesRegex(RuntimeError, "expected refusal"):
                    commands.call(evidence / "home", "refusal", argv, refusal=diagnostic)

    def test_refusals_accept_actual_branch_diagnostics_only(self):
        diagnostics = (
            (native.TAMPER_REFUSAL, "artifact rootfs.ext4 sha256 mismatch: manifest says "
             + "a" * 64 + ", actual " + "b" * 64),
            (native.SEALED_REFUSAL, "the run needs development-only agent verbs "
             "(an interactive, ad-hoc command, or dev-profile launch), but the bundle is sealed-prod"),
            (native.RUNTIME_REFUSAL, "the published OCI guest runtime is not prepared; "
             "run `mvmctl bootstrap` first"))
        for pattern, reason in diagnostics:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                commands = native.Commands("/unused", root, lambda args, **kw:
                    subprocess.CompletedProcess(args, 1, b"", reason.encode()))
                commands.call(root / "home", "refusal", ["same-argv"], refusal=pattern)

    def test_cache_inventory_tracks_xdg_and_symlink_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = native.snapshot_files(root)
            (root / "xdg-cache").mkdir()
            (root / "xdg-cache/runtime").write_bytes(b"unexpected")
            after = native.snapshot_files(root)
            self.assertNotEqual(before, after)
            (root / "xdg-cache/runtime").unlink()
            (root / "xdg-cache/runtime").symlink_to("/outside")
            self.assertEqual(native.snapshot_files(root)["xdg-cache/runtime"],
                             {"exists": True, "type": "symlink", "symlink": "/outside"})

    def test_inventory_regular_roots_empty_directories_and_special_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            before = native.snapshot_files(root)
            (cache / "empty").mkdir()
            after = native.snapshot_files(root)
            self.assertNotEqual(before, after)
            self.assertEqual(after["cache/empty"],
                             {"exists": True, "type": "directory"})
            os.mkfifo(cache / "fifo")
            with self.assertRaisesRegex(RuntimeError, "entry type"):
                native.snapshot_files(root)
            (cache / "fifo").unlink()
            (cache / "empty").rmdir()
            cache.rmdir()
            cache.write_bytes(b"root file")
            regular = native.snapshot_files(root)
            self.assertNotEqual(before, regular)
            self.assertEqual(regular["cache"]["sha256"], native.digest(cache))
            self.assertEqual(regular["cache"]["type"], "regular")
            cache.unlink()
            os.mkfifo(cache)
            with self.assertRaisesRegex(RuntimeError, "entry type"):
                native.snapshot_files(root)

    def test_tamper_budgets_deadline_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            target = Path(directory) / "target"
            archive(source)
            for setting, limit in (("TAMPER_SOURCE_LIMIT", 1),
                                   ("TAMPER_EXPANDED_LIMIT", 1),
                                   ("TAMPER_OUTPUT_LIMIT", 1),
                                   ("TAMPER_SECONDS", -1)):
                with self.subTest(setting=setting), patch.object(native, setting, limit):
                    with self.assertRaises(ValueError):
                        native.tamper(source, target)
                    self.assertFalse(target.exists())
            target.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                native.tamper(source, target)
            self.assertEqual(target.read_bytes(), b"existing")
            target.unlink()
            # Exhaust deadline after the first output chunk has been written.
            with patch.object(native.time, "monotonic",
                              side_effect=[0] * 8 + [61] * 10):
                with self.assertRaisesRegex(ValueError, "deadline"):
                    native.tamper(source, target)
            self.assertFalse(target.exists())
            link = Path(directory) / "link"
            link.symlink_to(source)
            with self.assertRaises(OSError):
                native.tamper(link, target)
            link.unlink()
            link.symlink_to(Path(directory), target_is_directory=True)
            with self.assertRaises(OSError):
                native.tamper(link / "source", target)
            with self.assertRaises(OSError):
                native.tamper(source, link / "target")
            self.assertFalse(target.exists())

    def test_tamper_rejects_compression_extensions_and_header_excess(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            target = Path(directory) / "target"
            with tarfile.open(source, "w:gz") as tar:
                tar.addfile(tarfile.TarInfo("rootfs.ext4"))
            with self.assertRaises(ValueError):
                native.tamper(source, target)
            for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                         tarfile.GNUTYPE_LONGLINK, tarfile.GNUTYPE_SPARSE,
                         tarfile.SYMTYPE, tarfile.FIFOTYPE):
                entry = tarfile.TarInfo("unsupported")
                entry.type = kind
                entry.size = 16 * 1024 ** 3
                source.write_bytes(entry.tobuf() + b"\0" * 1024)
                with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "unsupported"):
                    native.tamper(source, target)
                self.assertFalse(target.exists())
            source.write_bytes(b"".join(tarfile.TarInfo(str(i)).tobuf()
                                       for i in range(4097)) + b"\0" * 1024)
            with self.assertRaisesRegex(ValueError, "header bound"):
                native.tamper(source, target)
            entry = tarfile.TarInfo("rootfs.ext4")
            entry.size = 1000000
            source.write_bytes(entry.tobuf() + b"\0" * 1024)
            with self.assertRaisesRegex(ValueError, "source size"):
                native.tamper(source, target)

    def test_overflow_cannot_be_positive_or_refusal_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            for status in (0, 1):
                commands = native.Commands("/unused", evidence, lambda args, **kw:
                    subprocess.CompletedProcess(args, status,
                        b"x" * (native.STREAM_LIMIT + 1), b"expected refusal"))
                with self.assertRaisesRegex(RuntimeError, "overflow"):
                    commands.call(evidence / "home", "overflow", [], refusal="expected refusal")

    def test_actual_pipe_drainer_bounds_both_streams_without_launching_process(self):
        class Process:
            pid = 999
            returncode = 0
            def __init__(self):
                self.stdout = self.pipe(b"out" * 100)
                self.stderr = self.pipe(b"err" * 100)
            def pipe(self, data):
                read, write = os.pipe()
                os.write(write, data)
                os.close(write)
                return os.fdopen(read, "rb")
            def wait(self, **kwargs):
                return 0
        with patch.object(native.subprocess, "Popen", return_value=Process()) as spawn:
            with patch.object(native, "STREAM_LIMIT", 16):
                result = native.bounded_run(["never-launched"], cwd=HERE, env={}, timeout=2)
        self.assertTrue(result.overflow)
        self.assertEqual(len(result.stdout), 16)
        self.assertEqual(len(result.stderr), 16)
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])

    def test_hello_requires_standalone_line(self):
        native.require_hello((native.HELLO + "\n").encode())
        for text in ("echo " + native.HELLO, native.HELLO + " suffix",
                     "prefix " + native.HELLO):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                native.require_hello(text.encode())

    def test_adjacent_symlink_and_disk_count_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            evidence = root / "evidence"
            home.mkdir()
            evidence.mkdir()
            archive(home / "input.img", **{"work/flake.nix": b"flake"})
            (home / "config.json").symlink_to(home / "input.img")
            with self.assertRaises(OSError):
                native.collect_builder_candidates(home, evidence)
            (home / "config.json").unlink()
            (home / "input.img").unlink()
            for index in range(33):
                child = home / str(index)
                child.mkdir()
                archive(child / "input.img")
            with self.assertRaisesRegex(ValueError, "disk bound"):
                native.collect_builder_candidates(home, evidence)

    def test_tar_headers_and_external_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "input.img"
            with tarfile.open(path, "w") as tar:
                for index in range(4097):
                    tar.addfile(tarfile.TarInfo(f"unused-{index}"))
            with self.assertRaisesRegex(ValueError, "header"):
                native.members(path, {"work/flake.nix"})
            link = root / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                native.members(link, set())
            parent = root / "parent"
            parent.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                native.digest(parent / "input.img")

    def test_stop_success_is_not_teardown_proof(self):
        class Success:
            def call(self, *args, **kwargs):
                return b""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "consumer").mkdir()
            self.assertTrue(native.cleanup(Success(), root,
                verify=lambda home: [{"pid": 12, "starttime": "42"}]))
            def unavailable(home):
                raise PermissionError("inventory denied")
            self.assertIn("teardown-unverified",
                          native.cleanup(Success(), root, verify=unavailable)[0])

    def test_injected_process_inventory_identity_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "self").mkdir()
            (root / "self/stat").write_text("available")
            process = root / "123"
            process.mkdir()
            fields = ["S", "1", "123", "123"] + ["0"] * 15 + ["900"]
            (process / "stat").write_text("123 (worker (name)) " + " ".join(fields))
            (process / "environ").write_bytes(b"MVM_HOME=/private/consumer\0")
            (process / "cmdline").write_bytes(b"firecracker\0")
            self.assertEqual(native.owned_processes(Path("/private/consumer"), root),
                             [{"pid": 123, "starttime": "900"}])
            self.assertEqual(native.owned_processes(Path("/unrelated"), root), [])
            self.assertTrue(native.owned_processes(Path("/unrelated"), root, sessions={123}))
            original_read = Path.read_text
            reads = []
            def recycled(path, *args, **kwargs):
                text = original_read(path, *args, **kwargs)
                if path == process / "stat":
                    reads.append(path)
                    if len(reads) == 3:
                        return text.removesuffix("900") + "901"
                return text
            with patch.object(Path, "read_text", recycled):
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    native.owned_processes(Path("/unrelated"), root)
            (process / "stat").write_text("malformed")
            with self.assertRaises(ValueError):
                native.owned_processes(Path("/private/consumer"), root)
            (process / "stat").unlink()
            with self.assertRaisesRegex(RuntimeError, "vanished"):
                native.owned_processes(Path("/private/consumer"), root)

    def test_source_revision_is_verified_not_trusted_from_argument(self):
        result = subprocess.CompletedProcess([], 0, ("b" * 40 + "\n").encode(), b"")
        result.overflow = False
        with patch.object(native, "bounded_run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                native.source_identity("a" * 40)

    def test_unknown_key_uses_real_cli_refusal_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            commands = native.Commands(
                "/unused", evidence,
                lambda argv, **kw: subprocess.CompletedProcess(
                    argv, 1, b"", b"trust store has no entry for key_id deadbeef"))
            commands.call(evidence / "consumer", "unknown-key", ["bundle", "fetch", "pack"],
                          refusal=r"trust store has no entry for key_id")

    def test_sealed_preview_requires_actual_schema_values_and_archive_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "pack.mvmpkg"
            archive(package)
            good = {"verified": True, "runnable_here": True, "arch": "x86_64",
                    "bundle_sha256": native.digest(package),
                    "posture": {"profile": "sealed-prod", "verity_protected": True,
                                "egress": "deny-all", "volumes": False}}
            native.require_sealed_artifact(json.dumps(good).encode(), package)
            for key in ("verified", "runnable_here", "arch", "bundle_sha256", "posture"):
                malformed = dict(good)
                malformed.pop(key)
                with self.subTest(missing=key), self.assertRaises(RuntimeError):
                    native.require_sealed_artifact(json.dumps(malformed).encode(), package)
            for key in good["posture"]:
                malformed = {**good, "posture": {**good["posture"], key: None}}
                with self.subTest(null=key), self.assertRaises(RuntimeError):
                    native.require_sealed_artifact(json.dumps(malformed).encode(), package)


if __name__ == "__main__":
    unittest.main()
