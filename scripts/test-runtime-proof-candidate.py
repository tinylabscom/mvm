"""Offline refusal/transport tests, not genuine signing or native witnesses."""
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import runtime_release_proof as proof

spec = importlib.util.spec_from_file_location(
    "runtime_proof_candidate", Path(__file__).with_name("runtime-proof-candidate.py")
)
candidate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = candidate
spec.loader.exec_module(candidate)


class CandidateTransportTests(unittest.TestCase):
    def setUp(self):
        which = patch.object(candidate.shutil, "which", return_value="/usr/bin/gh")
        which.start()
        self.addCleanup(which.stop)

    def env(self, version="0.24.0"):
        return {
            "GITHUB_REPOSITORY": "tinylabscom/mvm",
            "GITHUB_REPOSITORY_ID": "123",
            "GITHUB_RUN_ID": "456",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF_TYPE": "tag",
            "GITHUB_REF": f"refs/tags/v{version}",
            "GITHUB_WORKFLOW_REF":
                f"tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}",
        }

    def metadata(self):
        return {
            "id": 789, "name": "mvm-guest-bins-attempt-1", "digest": "sha256:" + "b" * 64,
            "expired": False, "size_in_bytes": 500,
            "workflow_run": {
                "id": 456, "repository_id": 123, "head_repository_id": 123,
                "head_sha": "a" * 40,
            },
        }

    def zipped(self, entries):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name, data in entries:
                archive.writestr(name, data)
        stream.seek(0)
        return stream

    def test_real_tag_and_matching_rc_only(self):
        for version in ["0.24.0", "0.24.0-rc.1"]:
            self.assertEqual(candidate.tag_source(self.env(version), version).version, version)
        mutations = {
            "GITHUB_EVENT_NAME": ["workflow_dispatch", "pull_request"],
            "GITHUB_REF_TYPE": ["branch"],
            "GITHUB_REF": ["refs/heads/main", "refs/tags/v0.23.1"],
            "GITHUB_WORKFLOW_REF": ["tinylabscom/mvm/.github/workflows/guest-bins.yml@refs/tags/v0.24.0"],
            "GITHUB_REPOSITORY": ["other/mvm"],
            "GITHUB_SHA": ["", "short"],
            "GITHUB_RUN_ID": ["", "0"],
            "GITHUB_RUN_ATTEMPT": ["", "0", "01", "not-an-attempt"],
        }
        for field, values in mutations.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    candidate.tag_source({**self.env(), field: value}, "0.24.0")

    def test_actual_artifact_metadata_is_mandatory(self):
        source = candidate.tag_source(self.env(), "0.24.0")
        expected = (789, "b" * 64, "mvm-guest-bins-attempt-1")
        candidate.validate_artifact(self.metadata(), source, expected)
        for field, value in [("id", 790), ("name", "other"), ("digest", ""), ("digest", None),
                             ("expired", True), ("size_in_bytes", 0),
                             ("size_in_bytes", candidate.MAX_TRANSFER_BYTES + 1)]:
            metadata = self.metadata()
            metadata[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                candidate.validate_artifact(metadata, source, expected)
        for field, value in [("id", 457), ("repository_id", 999),
                             ("head_repository_id", 999), ("head_sha", "c" * 40)]:
            metadata = self.metadata()
            metadata["workflow_run"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                candidate.validate_artifact(metadata, source, expected)

    def test_metadata_cannot_omit_required_digest_or_run(self):
        source = candidate.tag_source(self.env(), "0.24.0")
        for missing in ["digest", "workflow_run", "expired", "size_in_bytes"]:
            metadata = self.metadata()
            del metadata[missing]
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                candidate.validate_artifact(metadata, source, (789, "b" * 64, "mvm-guest-bins-attempt-1"))

    def test_exact_zip_never_overlays_other_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "unsigned"
            candidate.extract_exact(self.zipped([("archive", b"same"), ("checksum", b"pin")]),
                                    destination, ["archive", "checksum"])
            self.assertEqual((destination / "archive").read_bytes(), b"same")
            with self.assertRaises(FileExistsError):
                candidate.extract_exact(self.zipped([("archive", b"replace"), ("checksum", b"bad")]),
                                        destination, ["archive", "checksum"])
            self.assertEqual((destination / "archive").read_bytes(), b"same")

    def test_missing_duplicate_traversal_or_symlink_refuses_before_write(self):
        symlink = zipfile.ZipInfo("archive")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        bad = [
            [("archive", b"a")],
            [("archive", b"a"), ("archive", b"b"), ("checksum", b"c")],
            [("../archive", b"a"), ("checksum", b"c")],
            [(symlink, b"/etc/passwd"), ("checksum", b"c")],
            [("archive", b"a"), ("checksum", b"c"), ("extra", b"x")],
        ]
        for entries in bad:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / "out"
                with self.assertRaises(ValueError):
                    candidate.extract_exact(self.zipped(entries), destination, ["archive", "checksum"])
                self.assertFalse(destination.exists())

    def test_download_digest_is_a_hard_failure_not_action_warning(self):
        source = candidate.tag_source(self.env(), "0.24.0")
        with tempfile.TemporaryDirectory() as temporary:
            args = SimpleNamespace(artifact_id="789", artifact_digest="b" * 64,
                                   kind="unsigned", out_dir=Path(temporary) / "out")
            def download(endpoint, archive, **_kwargs):
                archive.write_bytes(b"different ZIP bytes")
            with patch.object(candidate.subprocess, "check_output",
                              return_value=json.dumps(self.metadata())), \
                 patch.object(candidate, "download_archive", side_effect=download):
                with self.assertRaisesRegex(ValueError, "ZIP digest mismatch"):
                    candidate.fetch(args, source)
            self.assertFalse(args.out_dir.exists())

    def test_download_is_bounded_and_failure_does_not_leave_a_child(self):
        class Download:
            def __init__(self, payload, exit_code):
                self.stdout = io.BytesIO(payload)
                self.exit_code = exit_code
                self.finished = False
                self.killed = False

            def wait(self):
                self.finished = True
                return self.exit_code

            def poll(self):
                return self.exit_code if self.finished else None

            def kill(self):
                self.killed = True

        for payload, code in [(b"too many bytes", 0), (b"x", 1)]:
            process = Download(payload, code)
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temporary:
                with patch.object(candidate.subprocess, "Popen", return_value=process), \
                     patch.object(candidate, "MAX_TRANSFER_BYTES", 4):
                    with self.assertRaises(ValueError):
                        candidate.download_archive("unused", Path(temporary) / "archive.zip")
                self.assertTrue(process.finished)
                self.assertTrue(process.stdout.closed)
                if len(payload) > 4:
                    self.assertTrue(process.killed)

    def test_without_gh_cli_the_rest_api_is_used_and_token_stays_on_api_host(self):
        import urllib.error
        seen = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.close()

        def open_api(request, timeout=None):
            seen.append(request)
            headers = {"Location": "https://blob.example/zip"}
            raise urllib.error.HTTPError(request.full_url, 302, "found", headers, None)

        opener = unittest.mock.MagicMock()
        opener.open.side_effect = open_api
        env = {"GH_TOKEN": "tok"}
        with patch.object(candidate.shutil, "which", return_value=None), \
             patch.dict(candidate.os.environ, env, clear=True), \
             patch.object(candidate.urllib.request, "build_opener", return_value=opener), \
             patch.object(candidate.urllib.request, "urlopen",
                          return_value=Response(b"zipbytes")) as follow:
            stream, process = candidate._gh_download("repos/o/r/actions/artifacts/7")
            self.assertIsNone(process)
            self.assertEqual(stream.read(), b"zipbytes")
        self.assertEqual(seen[0].full_url,
                         "https://api.github.com/repos/o/r/actions/artifacts/7/zip")
        self.assertEqual(seen[0].get_header("Authorization"), "Bearer tok")
        self.assertEqual(follow.call_args.args[0], "https://blob.example/zip")

        with patch.object(candidate.shutil, "which", return_value=None), \
             patch.dict(candidate.os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                candidate.gh_json("repos/o/r")

    def test_checkout_tag_and_unmodified_cargo_must_agree(self):
        cargo = b'[workspace.package]\nversion = "0.24.0"\n'
        for head, tag, original in [
            ("b" * 40, "a" * 40, cargo),
            ("a" * 40, "b" * 40, cargo),
            ("a" * 40, "a" * 40, cargo + b"# changed\n"),
        ]:
            with self.subTest(head=head, tag=tag), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "Cargo.toml").write_bytes(cargo)
                with patch.dict(os.environ, self.env(), clear=True), \
                     patch.object(candidate.subprocess, "check_output",
                                  side_effect=[head, json.dumps({"sha": tag}),
                                               json.dumps({"id": 456, "run_attempt": 1,
                                                           "head_sha": "a" * 40,
                                                           "event": "push",
                                                           "path": ".github/workflows/release.yml"}),
                                               original]):
                    with self.assertRaises(ValueError):
                        candidate.current_source(root)

    def unsigned(self, root, env):
        (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.24.0"\n')
        directory = root / "dist"
        directory.mkdir()
        archive, checksum = proof.runtime_names("0.24.0")[:2]
        (directory / archive).write_bytes(b"unsigned transport fixture")
        (directory / "mvmctl").write_bytes(b"mock canonical reader, never executed")
        digest = hashlib.sha256((directory / archive).read_bytes()).hexdigest()
        (directory / checksum).write_text(f"{digest}  {archive}\n")
        with patch.dict(os.environ, {**env, "GITHUB_JOB": "guest-bins"}, clear=True):
            record = candidate.emit_upload_context(root, directory, "unsigned")
        return directory, record

    def test_current_attempt_context_is_bound_to_exact_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, record = self.unsigned(root, self.env())
            source = candidate.tag_source(self.env(), "0.24.0")
            self.assertEqual(candidate.verify_directory(source, directory, "unsigned"), record["files"])
            self.assertEqual(record["run_attempt"], 1)
            self.assertEqual(record["producer_job"], "guest-bins")
            with patch.dict(os.environ, {**self.env(), "GITHUB_JOB": "guest-bins"}, clear=True):
                with self.assertRaises(ValueError):
                    candidate.emit_upload_context(root, directory, "unsigned")
            self.assertEqual(json.loads((directory / candidate.UPLOAD_CONTEXT).read_text()), record)

    def test_same_run_same_sha_old_attempt_and_rerun_failed_jobs_refuse(self):
        first = candidate.tag_source(self.env(), "0.24.0")
        second = candidate.tag_source({**self.env(), "GITHUB_RUN_ATTEMPT": "2"}, "0.24.0")
        self.assertNotEqual(first, second)
        self.assertNotEqual(candidate.artifact_name(first, "unsigned"),
                            candidate.artifact_name(second, "unsigned"))
        with tempfile.TemporaryDirectory() as temporary:
            directory, record = self.unsigned(Path(temporary), self.env())
            # A failed downstream job reruns while the successful producer did
            # not: its retained output still belongs to attempt 1.
            with self.assertRaisesRegex(ValueError, "attempt"):
                candidate.verify_directory(second, directory, "unsigned")
            del record["run_attempt"]
            (directory / candidate.UPLOAD_CONTEXT).write_text(json.dumps(record))
            with self.assertRaises(ValueError):
                candidate.verify_directory(first, directory, "unsigned")

    def test_complete_fetch_checks_context_even_with_valid_zip_and_metadata(self):
        for consumer_attempt in ["1", "2"]:
            with self.subTest(consumer_attempt=consumer_attempt), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                producer, record = self.unsigned(root, self.env())
                entries = [(p.name, p.read_bytes()) for p in producer.iterdir()]
                zipped = self.zipped(entries).getvalue()
                digest = hashlib.sha256(zipped).hexdigest()
                source = candidate.tag_source(
                    {**self.env(), "GITHUB_RUN_ATTEMPT": consumer_attempt}, "0.24.0"
                )
                metadata = self.metadata()
                metadata["name"] = candidate.artifact_name(source, "unsigned")
                metadata["digest"] = "sha256:" + digest
                metadata["size_in_bytes"] = len(zipped)
                args = SimpleNamespace(artifact_id="789", artifact_digest=digest,
                                       kind="unsigned", out_dir=root / "download")
                def download(endpoint, archive, **_kwargs):
                    archive.write_bytes(zipped)
                with patch.object(candidate.subprocess, "check_output",
                                  return_value=json.dumps(metadata)), \
                     patch.object(candidate, "download_archive", side_effect=download):
                    if consumer_attempt == "1":
                        self.assertEqual(candidate.fetch(args, source), record["files"])
                    else:
                        with self.assertRaisesRegex(ValueError, "attempt"):
                            candidate.fetch(args, source)

    def test_signed_context_also_refuses_prior_attempt_and_boolean_attempt(self):
        env = {**self.env(), "GITHUB_JOB": "runtime-proof-candidate"}
        record = candidate.upload_record(env, "0.24.0", "signed", {"archive": "b" * 64})
        second = candidate.tag_source({**self.env(), "GITHUB_RUN_ATTEMPT": "2"}, "0.24.0")
        with self.assertRaises(ValueError):
            candidate.validate_upload_record(record, second, "signed", record["files"])
        record["run_attempt"] = True
        with self.assertRaises(ValueError):
            candidate.validate_upload_record(
                record, candidate.tag_source(self.env(), "0.24.0"), "signed", record["files"]
            )

    def test_producer_context_missing_unknown_job_or_changed_payload_refuses(self):
        for mutation in ["missing", "producer", "unknown", "payload"]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                directory, record = self.unsigned(Path(temporary), self.env())
                context = directory / candidate.UPLOAD_CONTEXT
                if mutation == "missing":
                    context.unlink()
                elif mutation == "payload":
                    archive, checksum = proof.runtime_names("0.24.0")[:2]
                    (directory / archive).write_bytes(b"coherently substituted")
                    digest = hashlib.sha256((directory / archive).read_bytes()).hexdigest()
                    (directory / checksum).write_text(f"{digest}  {archive}\n")
                else:
                    record["producer_job" if mutation == "producer" else "unrecognized"] = "other"
                    context.write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    candidate.verify_directory(candidate.tag_source(self.env(), "0.24.0"),
                                               directory, "unsigned")

    def test_unsigned_dispatch_context_does_not_gain_tag_authority(self):
        env = {**self.env(), "GITHUB_EVENT_NAME": "workflow_dispatch",
               "GITHUB_REF_TYPE": "branch", "GITHUB_REF": "refs/heads/main",
               "GITHUB_WORKFLOW_REF":
                   "tinylabscom/mvm/.github/workflows/guest-bins.yml@refs/heads/main"}
        with tempfile.TemporaryDirectory() as temporary:
            directory, record = self.unsigned(Path(temporary), env)
            self.assertEqual(record["event"], "workflow_dispatch")
            with self.assertRaises(ValueError):
                candidate.verify_directory(candidate.tag_source(self.env(), "0.24.0"),
                                           directory, "unsigned")

    def test_emitter_requires_actual_producer_job_and_attempt(self):
        for changed in [{"GITHUB_RUN_ATTEMPT": ""}, {"GITHUB_JOB": "different-job"}]:
            env = {**self.env(), "GITHUB_JOB": "guest-bins", **changed}
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                candidate.upload_record(env, "0.24.0", "unsigned", {})

    def test_cli_cannot_stamp_checked_or_signed_context_without_their_gates(self):
        for kind in ["checked", "signed"]:
            with self.subTest(kind=kind), \
                 patch.object(sys, "argv", ["runtime-proof-candidate.py", "emit-upload-context",
                                           "--kind", kind, "--directory", "unused"]), \
                 patch.object(sys, "stderr", io.StringIO()), \
                 patch.object(candidate.subprocess, "check_output") as api:
                with self.assertRaises(SystemExit) as refusal:
                    candidate.main()
                self.assertEqual(refusal.exception.code, 2)
                api.assert_not_called()

    def test_duplicate_context_fields_are_refused(self):
        with self.assertRaises(ValueError):
            json.loads('{"run_attempt":1,"run_attempt":2}', object_pairs_hook=candidate.no_duplicate_keys)

    def test_actual_attempt_api_cannot_report_an_old_attempt(self):
        cargo = b'[workspace.package]\nversion = "0.24.0"\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_bytes(cargo)
            with patch.dict(os.environ, {**self.env(), "GITHUB_RUN_ATTEMPT": "2"}, clear=True), \
                 patch.object(candidate.subprocess, "check_output", side_effect=[
                     "a" * 40, json.dumps({"sha": "a" * 40}),
                     json.dumps({"id": 456, "run_attempt": 1, "head_sha": "a" * 40,
                                 "event": "push",
                                 "path": ".github/workflows/release.yml"}), cargo]):
                with self.assertRaises(ValueError):
                    candidate.current_source(root)

    def test_actual_attempt_event_must_also_be_a_push(self):
        cargo = b'[workspace.package]\nversion = "0.24.0"\n'
        for event in ["push", "workflow_dispatch"]:
            with self.subTest(event=event), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "Cargo.toml").write_bytes(cargo)
                attempt = {"id": 456, "run_attempt": 1, "head_sha": "a" * 40,
                           "path": ".github/workflows/release.yml", "event": event}
                with patch.dict(os.environ, self.env(), clear=True), \
                     patch.object(candidate.subprocess, "check_output", side_effect=[
                         "a" * 40, json.dumps({"sha": "a" * 40}), json.dumps(attempt), cargo
                     ]):
                    if event == "push":
                        self.assertEqual(candidate.current_source(root).run_attempt, 1)
                    else:
                        with self.assertRaises(ValueError):
                            candidate.current_source(root)

    def test_upload_and_existing_readers_select_the_exact_attempt(self):
        workflows = Path(__file__).resolve().parents[1] / ".github/workflows"
        guest = (workflows / "guest-bins.yml").read_text()
        capture = "emit-upload-context --kind unsigned --directory dist"
        self.assertLess(guest.index("dev guest-bins --out dist"), guest.index(capture))
        self.assertLess(guest.index(capture), guest.index("id: upload"))
        self.assertIn("name: mvm-guest-bins-attempt-${{ github.run_attempt }}", guest)
        self.assertNotIn("overwrite: true", guest)
        distro = (workflows / "distro-packages.yml").read_text()
        self.assertIn("name: mvm-guest-bins-attempt-${{ github.run_attempt }}", distro)
        smoke = (workflows / "release-archive-smoke.yml").read_text()
        self.assertIn("name: mvm-guest-bins-attempt-${{ github.run_attempt }}", smoke)
        self.assertIn("name: mvm-guest-bins-attempt-${{ inputs.run_attempt }}", smoke)
        self.assertIn("run_attempt requires run_id", smoke)

    def reader_result(self):
        return SimpleNamespace(stdout=json.dumps({
            "version": "0.24.0",
            "source": {"commit": "a" * 40, "worktree": {"state": "clean"}},
        }).encode(), stderr=b"")

    def test_canonical_reader_uses_bound_binary_without_signing_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, _ = self.unsigned(Path(temporary), self.env())
            source = candidate.tag_source(self.env(), "0.24.0")
            env = {**self.env(), "GITHUB_JOB": "runtime-proof-input-check", "GH_TOKEN": "mock"}
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(candidate.subprocess, "run", return_value=self.reader_result()) as run:
                candidate.validate_unsigned_runtime(source, directory)
            command = run.call_args.args[0]
            self.assertEqual(command[0], str((directory / "mvmctl").resolve()))
            self.assertEqual(command[1:4], ["dev", "guest-bins", "--check-release-archive"])
            options = run.call_args.kwargs
            self.assertEqual(set(options["env"]), {"HOME", "MVM_HOME", "TMPDIR", "PATH"})
            self.assertEqual(options["timeout"], 60)
            self.assertTrue(options["check"])

    def test_reader_is_refused_in_signing_job_or_with_oidc_credentials(self):
        for changed in [
            {"GITHUB_JOB": "runtime-proof-candidate"},
            {"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "mock"},
            {"ACTIONS_ID_TOKEN_REQUEST_URL": "mock"},
        ]:
            env = {**self.env(), "GITHUB_JOB": "runtime-proof-input-check", **changed}
            with self.subTest(changed=changed), patch.dict(os.environ, env, clear=True), \
                 patch.object(candidate.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    candidate.validate_unsigned_runtime(
                        candidate.tag_source(self.env(), "0.24.0"), Path("unused")
                    )
                run.assert_not_called()

    def test_bad_reader_source_version_dirty_state_and_failure_refuse(self):
        for output in [
            {"version": "0.23.1", "source": {"commit": "a" * 40, "worktree": {"state": "clean"}}},
            {"version": "0.24.0", "source": {"commit": "b" * 40, "worktree": {"state": "clean"}}},
            {"version": "0.24.0", "source": {"commit": "a" * 40, "worktree": {"state": "dirty"}}},
            [],
        ]:
            with self.subTest(output=output), tempfile.TemporaryDirectory() as temporary:
                directory, _ = self.unsigned(Path(temporary), self.env())
                result = SimpleNamespace(stdout=json.dumps(output).encode(), stderr=b"")
                with patch.dict(os.environ, {**self.env(), "GITHUB_JOB": "runtime-proof-input-check"},
                                clear=True), \
                     patch.object(candidate.subprocess, "run", return_value=result):
                    with self.assertRaises(ValueError):
                        candidate.validate_unsigned_runtime(
                            candidate.tag_source(self.env(), "0.24.0"), directory
                        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, _ = self.unsigned(root, self.env())
            destination = root / "checked"
            with patch.dict(os.environ, {**self.env(), "GITHUB_JOB": "runtime-proof-input-check"},
                            clear=True), \
                 patch.object(candidate.subprocess, "run",
                              side_effect=subprocess.CalledProcessError(1, ["mock-reader"])):
                with self.assertRaises(subprocess.CalledProcessError):
                    candidate.prepare_checked_input(
                        candidate.tag_source(self.env(), "0.24.0"), directory, destination, root
                    )
            self.assertFalse(destination.exists())

    def test_checked_input_keeps_identical_archive_but_never_carries_the_tool(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, producer = self.unsigned(root, self.env())
            destination = root / "checked"
            source = candidate.tag_source(self.env(), "0.24.0")
            with patch.dict(os.environ, {**self.env(), "GITHUB_JOB": "runtime-proof-input-check"},
                            clear=True), \
                 patch.object(candidate.subprocess, "run", return_value=self.reader_result()):
                hashes = candidate.prepare_checked_input(source, directory, destination, root)
            self.assertEqual(set(hashes), set(proof.runtime_names("0.24.0")[:2]))
            self.assertEqual(hashes, {name: producer["files"][name] for name in hashes})
            self.assertFalse((destination / "mvmctl").exists())
            checked = json.loads((destination / candidate.UPLOAD_CONTEXT).read_text())
            self.assertEqual(checked["producer_job"], "runtime-proof-input-check")
            self.assertEqual(checked["run_attempt"], 1)

    def test_reader_or_archive_mutation_during_validation_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, _ = self.unsigned(Path(temporary), self.env())
            def mutate(*args, **kwargs):
                (directory / "mvmctl").write_bytes(b"changed reader")
                return self.reader_result()
            with patch.dict(os.environ, {**self.env(), "GITHUB_JOB": "runtime-proof-input-check"},
                            clear=True), \
                 patch.object(candidate.subprocess, "run", side_effect=mutate):
                with self.assertRaises(ValueError):
                    candidate.validate_unsigned_runtime(
                        candidate.tag_source(self.env(), "0.24.0"), directory
                    )

    def checked(self, root):
        original, _ = self.unsigned(root, self.env())
        checked = root / "checked"
        source = candidate.tag_source(self.env(), "0.24.0")
        with patch.dict(os.environ, {**self.env(), "GITHUB_JOB": "runtime-proof-input-check"},
                        clear=True), \
             patch.object(candidate.subprocess, "run", return_value=self.reader_result()):
            candidate.prepare_checked_input(source, original, checked, root)
        return source, original, checked

    def test_signer_compares_original_inputs_without_executing_the_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, original, checked = self.checked(root)
            staged = root / "candidate"
            with patch.dict(os.environ, {**self.env(), "GITHUB_JOB": "runtime-proof-candidate"},
                            clear=True), patch.object(candidate.subprocess, "run") as run:
                hashes = candidate.stage_signing_input(source, original, checked, staged)
                run.assert_not_called()
                self.assertEqual(set(p.name for p in staged.iterdir()), set(hashes))
                self.assertNotIn("mvmctl", hashes)
                with self.assertRaises(FileExistsError):
                    candidate.stage_signing_input(source, original, checked, staged)

    def test_signer_refuses_coherently_substituted_checked_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, original, checked = self.checked(root)
            archive, checksum = proof.runtime_names("0.24.0")[:2]
            (checked / archive).write_bytes(b"checker substituted this archive")
            digest = hashlib.sha256((checked / archive).read_bytes()).hexdigest()
            (checked / checksum).write_text(f"{digest}  {archive}\n")
            context = checked / candidate.UPLOAD_CONTEXT
            record = json.loads(context.read_text())
            record["files"] = candidate.payload_hashes("0.24.0", checked, "checked")
            context.write_text(json.dumps(record))
            with patch.dict(os.environ, {**self.env(), "GITHUB_JOB": "runtime-proof-candidate"},
                            clear=True), patch.object(candidate.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "original producer"):
                    candidate.stage_signing_input(source, original, checked, root / "refused")
                run.assert_not_called()
            self.assertFalse((root / "refused").exists())

    def test_sealing_preserves_subjects_and_checks_the_emitted_source_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, original, checked = self.checked(root)
            staged = root / "candidate"
            with patch.dict(os.environ, {**self.env(), "GITHUB_JOB": "runtime-proof-candidate"},
                            clear=True):
                expected = candidate.stage_signing_input(source, original, checked, staged)
                for name in proof.runtime_names("0.24.0")[2:]:
                    (staged / name).write_bytes(b"mock signature verifier seam")
                with patch.object(proof.subprocess, "run") as run:
                    hashes = candidate.seal_candidate(source, original, checked, staged, root)
                self.assertEqual({name: hashes[name] for name in expected}, expected)
                for call in run.call_args_list:
                    args = call.args[0]
                    self.assertEqual(args[args.index("--certificate-github-workflow-sha") + 1],
                                     source.sha)
                    self.assertEqual(args[args.index("--certificate-oidc-issuer") + 1], proof.ISSUER)
                    self.assertEqual(args[args.index("--certificate-github-workflow-trigger") + 1],
                                     "push")

    def test_bounded_subject_copy_refuses_growth(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "subject").write_bytes(b"larger than the test limit")
            (root / "out").mkdir()
            with patch.object(candidate, "MAX_TRANSFER_BYTES", 2):
                with self.assertRaisesRegex(ValueError, "size bound"):
                    candidate.copy_exact_subjects(source, root / "out", {"subject": "a" * 64})

    def test_subject_copy_bound_is_per_subject_not_cumulative(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (root / "out").mkdir()
            expected = {}
            for name in ("one", "two", "three"):
                (source / name).write_bytes(b"abcd")
                expected[name] = hashlib.sha256(b"abcd").hexdigest()
            candidate.copy_exact_subjects(source, root / "out", expected, max_bytes=5)
            self.assertEqual(sorted(p.name for p in (root / "out").iterdir()), sorted(expected))

    def test_signing_job_permissions_and_failure_truth_table(self):
        release = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
        reader = release.split("\n  runtime-proof-input-check:", 1)[1].split(
            "\n  runtime-proof-candidate:", 1
        )[0]
        signer = release.split("\n  runtime-proof-candidate:", 1)[1].split("\n  build:", 1)[0]
        self.assertIn("id-token: none", reader)
        self.assertIn("contents: read", reader)
        self.assertIn("persist-credentials: false", reader)
        self.assertNotIn("id-token: write", reader)
        self.assertNotIn("contents: write", reader)
        self.assertIn("prepare-checked", reader)
        self.assertIn("environment: release-signing", signer)
        self.assertIn("id-token: write", signer)
        self.assertIn("contents: read", signer)
        self.assertIn("persist-credentials: false", signer)
        self.assertNotIn("contents: write", signer)
        self.assertNotIn("prepare-checked", signer)
        self.assertNotIn("validate-input", signer)
        self.assertNotIn("--check-release-archive", signer)
        self.assertIn("stage-signing", signer)
        self.assertIn("seal-candidate", signer)
        self.assertLess(signer.index("stage-signing"), signer.index("cosign sign-blob"))
        self.assertIn("timeout-minutes: 10", reader)
        self.assertIn("timeout-minutes: 10", signer)
        condition = re.search(r"^    if: \$\{\{ (.+) \}\}$", signer, re.MULTILINE)[1]
        terms = condition.split(" && ")
        self.assertEqual(set(terms), {
            "!cancelled()", "github.event_name == 'push'", "github.ref_type == 'tag'",
            "needs.guest-runtime.result == 'success'",
            "needs.runtime-proof-input-check.result == 'success'",
        })
        for event, ref_type, cancelled, producer, checker in itertools.product(
            ["push", "workflow_dispatch", "pull_request"], ["tag", "branch"], [False, True],
            ["success", "failure", "cancelled", "skipped"],
            ["success", "failure", "cancelled", "skipped"],
        ):
            values = {
                "!cancelled()": not cancelled,
                "github.event_name == 'push'": event == "push",
                "github.ref_type == 'tag'": ref_type == "tag",
                "needs.guest-runtime.result == 'success'": producer == "success",
                "needs.runtime-proof-input-check.result == 'success'": checker == "success",
            }
            actual = all(values[term] for term in terms)
            expected = (not cancelled and event == "push" and ref_type == "tag"
                        and producer == checker == "success")
            self.assertEqual(actual, expected)

    def release_inputs(self, root, attempt="2"):
        env = {**self.env(), "GITHUB_RUN_ATTEMPT": attempt}
        with patch.object(self, "env", return_value=env):
            source, original, checked = self.checked(root)
        candidate_dir = root / "sealed"
        with patch.dict(os.environ, {**env, "GITHUB_JOB": "runtime-proof-candidate"}, clear=True):
            candidate.stage_signing_input(source, original, checked, candidate_dir)
            for name in proof.runtime_names(source.version)[2:]:
                (candidate_dir / name).write_bytes(b"mock signature seam, not genuine")
            with patch.object(proof.subprocess, "run"):
                pins = candidate.seal_candidate(source, original, checked, candidate_dir, root)
        blobs = {}
        metadata = {}
        def add(identity, name, entries):
            blob = self.zipped(entries).getvalue()
            blobs[identity] = blob
            item = self.metadata()
            item.update(id=identity, name=name, digest="sha256:" + hashlib.sha256(blob).hexdigest(),
                        size_in_bytes=len(blob))
            metadata[identity] = item
        for index, target in enumerate(candidate.RELEASE_TARGETS, 101):
            name = f"mvmctl-{target}.tar.gz"
            data = f"mock CLI {target}".encode()
            digest = hashlib.sha256(data).hexdigest()
            add(index, f"mvmctl-{target}-attempt-{attempt}",
                [(name, data), (name + ".sha256", f"{digest}  {name}\n")])
        packages = [
            "mvmctl_0.24.0-1_amd64.deb", "mvmctl_0.24.0-1_arm64.deb",
            "mvmctl-0.24.0-1.x86_64.rpm", "mvmctl-0.24.0-1.aarch64.rpm",
        ]
        entries = []
        for name in packages:
            data = f"mock package {name}".encode()
            entries += [(name, data), (name + ".sha256",
                        f"{hashlib.sha256(data).hexdigest()}  {name}\n")]
        add(104, f"distro-packages-attempt-{attempt}", entries)
        add(105, candidate.artifact_name(source, "signed"),
            [(path.name, path.read_bytes()) for path in candidate_dir.iterdir()])
        labels = ["ARCHIVE_SHA256", "CHECKSUM_SHA256", "ARCHIVE_BUNDLE_SHA256",
                  "CHECKSUM_BUNDLE_SHA256"]
        env.update({"RUNTIME_" + label: pins[name]
                    for label, name in zip(labels, proof.runtime_names(source.version))})
        env["GITHUB_JOB"] = "release"
        args = SimpleNamespace(candidate_id="105", candidate_digest=metadata[105]["digest"],
                               out_dir=root / "release")
        listing = {"total_count": len(metadata), "artifacts": list(metadata.values())}
        def api(endpoint):
            if endpoint.endswith("/artifacts?per_page=100"):
                return listing
            return metadata[int(endpoint.rsplit("/", 1)[1])]
        def download(endpoint, path, **_kwargs):
            path.write_bytes(blobs[int(endpoint.rsplit("/", 1)[1])])
        return source, env, args, listing, api, download, pins

    def test_collector_is_current_attempt_exact_and_does_not_ship_transport_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, env, args, _, api, download, pins = self.release_inputs(root)
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(candidate, "gh_json", side_effect=api), \
                 patch.object(candidate, "download_archive", side_effect=download), \
                 patch.object(proof.subprocess, "run"):
                self.assertEqual(candidate.collect_release(source, args), pins)
                with self.assertRaises(FileExistsError):
                    candidate.collect_release(source, args)
            self.assertEqual(len(list(args.out_dir.iterdir())), 18)
            self.assertFalse((args.out_dir / "mvmctl").exists())
            self.assertFalse((args.out_dir / candidate.UPLOAD_CONTEXT).exists())
            for name, digest in pins.items():
                self.assertEqual(hashlib.sha256((args.out_dir / name).read_bytes()).hexdigest(), digest)

    def test_collector_refuses_old_attempt_ambiguous_and_incomplete_lists(self):
        for mutation in ["old", "duplicate", "incomplete"]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                source, env, args, listing, api, download, _ = self.release_inputs(Path(temporary))
                if mutation == "old":
                    listing["artifacts"][0]["name"] = listing["artifacts"][0]["name"].replace(
                        "attempt-2", "attempt-1"
                    )
                elif mutation == "duplicate":
                    listing["artifacts"].append(dict(listing["artifacts"][0]))
                    listing["total_count"] += 1
                else:
                    listing["total_count"] += 1
                with patch.dict(os.environ, env, clear=True), \
                     patch.object(candidate, "gh_json", side_effect=api), \
                     patch.object(candidate, "download_archive", side_effect=download), \
                     patch.object(proof.subprocess, "run"):
                    with self.assertRaises(ValueError):
                        candidate.collect_release(source, args)
                self.assertFalse(args.out_dir.exists())

    def test_valid_signature_with_changed_envelope_still_refuses_the_original_pins(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, env, args, _, api, download, pins = self.release_inputs(Path(temporary))
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(candidate, "gh_json", side_effect=api), \
                 patch.object(candidate, "download_archive", side_effect=download), \
                 patch.object(proof.subprocess, "run"):
                candidate.collect_release(source, args)
                bundle = proof.runtime_names(source.version)[2]
                (args.out_dir / bundle).write_bytes(b"different yet mock-valid re-signature")
                with self.assertRaisesRegex(ValueError, "original candidate"):
                    candidate.verify_collected_candidate(source, args.out_dir, pins)

    def test_package_member_selector_requires_both_arches_and_exact_pairs(self):
        names = [
            "mvmctl_0.24.0-1_amd64.deb", "mvmctl_0.24.0-1_arm64.deb",
            "mvmctl-0.24.0-1.x86_64.rpm", "mvmctl-0.24.0-1.aarch64.rpm",
        ]
        entries = [(name, b"mock") for name in names + [name + ".sha256" for name in names]]
        self.assertEqual(len(candidate.package_members("0.24.0", self.zipped(entries))), 8)
        for changed in [entries[:-1], entries + [("../other", b"bad")],
                        [(name.replace("amd64", "riscv64"), data) for name, data in entries]]:
            with self.assertRaises(ValueError):
                candidate.package_members("0.24.0", self.zipped(changed))

    def test_checksum_sidecar_cannot_add_an_unrelated_subject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "subject").write_bytes(b"mock")
            digest = hashlib.sha256(b"mock").hexdigest()
            (root / "subject.sha256").write_text(
                f"{digest}  subject\n{'0' * 64}  ../../unrelated\n"
            )
            with self.assertRaises(ValueError):
                candidate.checksum_pairs(root, ["subject", "subject.sha256"])

    def test_final_workflow_never_overlays_or_resigns_runtime_subjects(self):
        release = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
        publish = release.split("\n  release:", 1)[1].split("\n  verify-release:", 1)[0]
        self.assertIn("collect-release", publish)
        self.assertNotIn("merge-multiple:", publish)
        signing = publish.split("- name: Sign release tarballs", 1)[1].split(
            "- name: Render and sign", 1
        )[0]
        self.assertNotIn("artifacts/mvm-guest-bins-v*.tar.gz.sha256", signing)
        self.assertIn('artifacts/mvm-guest-bins-${GITHUB_REF_NAME}.tar.gz', signing)
        self.assertLess(signing.index("continue"), signing.index("cosign sign-blob"))
        self.assertLess(publish.index("verify-collected"), publish.index("Create GitHub Release"))
        self.assertIn("needs.runtime-proof-candidate.result == 'success'", publish)
        condition = re.search(r"^    if: \$\{\{ (.+) \}\}$", publish, re.MULTILINE)[1]
        needs = re.search(r"^    needs: \[([^]]+)\]", publish, re.MULTILINE)[1].split(", ")
        terms = condition.split(" && ")
        expected = {"!cancelled()", "github.event_name == 'push'", "github.ref_type == 'tag'"}
        expected |= {f"needs.{job}.result == 'success'" for job in needs}
        self.assertEqual(set(terms), expected)
        for job in needs:
            for status in ["failure", "cancelled", "skipped"]:
                values = {term: True for term in terms}
                values[f"needs.{job}.result == 'success'"] = status == "success"
                self.assertFalse(all(values[term] for term in terms))

    def producer_code(self, root):
        hostd = root / "crates/mvm-hostd"
        hostd.mkdir(parents=True)
        (hostd / "Cargo.toml").write_text('[[bin]]\nname = "mvm-host-agent"\n')
        original = root / "consumer/bin"
        original.mkdir(parents=True)
        for name in ["mvmctl", "mvm-host-agent"]:
            (original / name).write_bytes(f"mock code {name}".encode())
            (original / name).chmod(0o755)
        (original / "signing.key").write_bytes(b"mock private data; never stage")
        (original / "cache").mkdir()
        return original

    def test_producer_staging_does_not_modify_or_seed_the_consumer_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, env, _, _, _, _, pins = self.release_inputs(root)
            original = self.producer_code(root)
            destination = root / "producer"
            with patch.dict(os.environ, env, clear=True), patch.object(proof.subprocess, "run"):
                result = candidate.stage_producer(
                    source, root / "sealed", original / "mvmctl", destination, root
                )
            self.assertEqual(result["runtime"], pins)
            self.assertFalse((original / "guest-runtime").exists())
            self.assertFalse((destination / "signing.key").exists())
            self.assertFalse((destination / "cache").exists())
            self.assertNotEqual((original / "mvmctl").stat().st_ino,
                                (destination / "mvmctl").stat().st_ino)
            (destination / "mvmctl").write_bytes(b"staged code modification")
            self.assertEqual((original / "mvmctl").read_bytes(), b"mock code mvmctl")

    def test_producer_staging_refuses_ambient_candidates_and_symlinked_helpers(self):
        for mutation in ["adjacent", "system-layout", "symlink"]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, env, _, _, _, _, _ = self.release_inputs(root)
                original = self.producer_code(root)
                if mutation == "symlink":
                    helper = original / "mvm-host-agent"
                    helper.unlink()
                    helper.symlink_to(original / "signing.key")
                else:
                    directory = (original / "guest-runtime" if mutation == "adjacent"
                                 else original.parent / "lib/mvmctl/guest-runtime")
                    directory.mkdir(parents=True)
                    (directory / proof.runtime_names(source.version)[0]).write_bytes(b"ambient")
                with patch.dict(os.environ, env, clear=True), patch.object(proof.subprocess, "run"):
                    with self.assertRaises(ValueError):
                        candidate.stage_producer(
                            source, root / "sealed", original / "mvmctl", root / "refused", root
                        )
                self.assertFalse((root / "refused").exists())

    def test_native_staging_is_after_prebuild_and_only_a_producer_locator(self):
        root = Path(__file__).resolve().parents[1]
        script = (root / "scripts/e2e-documented-surface.sh").read_text()
        self.assertLess(script.index('build_sdk_hostlib "$MVMCTL" "$E2E_PROFILE"'),
                        script.index("stage-producer"))
        self.assertIn('export MVM_E2E_PRODUCER_MVMCTL="$producer_root/bin/mvmctl"', script)
        self.assertNotIn('export MVMCTL="$producer_root', script)
        self.assertIn('export MVM_E2E_IMAGE_REVOCATIONS_DIR="$revocations_dir"', script)
        self.assertIn("releases/download/revocations", script)
        action = (root / ".github/actions/fetch-runtime-candidate/action.yml").read_text()
        self.assertLess(action.index("fetch --kind signed"), action.index("verify-collected"))
        self.assertLess(action.index("verify-collected"), action.index('echo "directory='))


class RuntimeProofTests(unittest.TestCase):
    def fixture(self, directory):
        names = proof.runtime_names("0.24.0")
        (directory / names[0]).write_bytes(b"synthetic archive, not a runtime")
        digest = hashlib.sha256((directory / names[0]).read_bytes()).hexdigest()
        (directory / names[1]).write_text(f"{digest}  {names[0]}\n")
        for name in names[2:]:
            (directory / name).write_bytes(b"synthetic verifier seam")
        return names

    def test_version_is_a_bounded_tag_component(self):
        for version in ["0.24.0", "0.24.0-rc.1"]:
            self.assertEqual(len(proof.runtime_names(version)), 4)
        for version in ["", "v0.24.0", "../0.24.0", "01.24.0", "0.24.0/evil", "0.24.0-rc.01"]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                proof.runtime_names(version)

    def test_quartet_uses_only_fixed_workflow_and_issuer(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            names = self.fixture(directory)
            with patch("runtime_release_proof.subprocess.run") as run:
                hashes = proof.verify_quartet("0.24.0", directory)
            self.assertEqual(set(hashes), set(names))
            self.assertEqual(run.call_count, 2)
            for call in run.call_args_list:
                args = call.args[0]
                self.assertEqual(
                    args[args.index("--certificate-identity") + 1],
                    "https://github.com/tinylabscom/mvm/.github/workflows/"
                    "release.yml@refs/tags/v0.24.0",
                )
                self.assertEqual(
                    args[args.index("--certificate-oidc-issuer") + 1], proof.ISSUER
                )
                self.assertTrue(call.kwargs["check"])

    def test_missing_or_symlinked_proof_refuses_before_verifier(self):
        for symlink in [False, True]:
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                names = self.fixture(directory)
                (directory / names[2]).unlink()
                if symlink:
                    (directory / names[2]).symlink_to(directory / names[3])
                with patch("runtime_release_proof.subprocess.run") as run:
                    with self.assertRaises(ValueError):
                        proof.verify_quartet("0.24.0", directory)
                    run.assert_not_called()

    def test_signature_failure_is_not_checksum_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.fixture(directory)
            with patch("runtime_release_proof.subprocess.run",
                       side_effect=subprocess.CalledProcessError(1, ["cosign"])):
                with self.assertRaises(subprocess.CalledProcessError):
                    proof.verify_quartet("0.24.0", directory)

    def test_archive_substitution_and_duplicate_checksum_refuse(self):
        for duplicate in [False, True]:
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                names = self.fixture(directory)
                if duplicate:
                    text = (directory / names[1]).read_text()
                    (directory / names[1]).write_text(text + text)
                else:
                    (directory / names[0]).write_bytes(b"substituted")
                with patch("runtime_release_proof.subprocess.run"):
                    with self.assertRaises(ValueError):
                        proof.verify_quartet("0.24.0", directory)


if __name__ == "__main__":
    unittest.main()
