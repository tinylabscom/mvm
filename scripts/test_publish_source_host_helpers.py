"""Hermetic gh state-machine tests; no GitHub requests or release mutations."""

import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "publisher", pathlib.Path(__file__).with_name("publish-source-host-helpers.py")
)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)
SHA = "a" * 40
TAG = f"source-builds-{SHA}"


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = pathlib.Path(self.tmp.name)
        self.names = [
            f"mvm-host-helpers-{SHA}-{target}.tar.gz{suffix}"
            for target in publisher.TARGETS for suffix in ("", ".bundle")
        ]
        for name in self.names:
            (self.directory / name).write_bytes(b"signed bytes")
        self.release = None
        self.target = None
        self.uploads = []
        self.create_race = False
        self.annotated = False

    def gh(self, command, **kwargs):
        self.assertEqual(command[0], "gh")
        if command[1:3] == ["release", "upload"]:
            self.assertNotIn("--clobber", command)
            self.assertEqual(command[3], TAG)
            names = [pathlib.Path(name).name for name in command[4:6]]
            self.uploads.extend(names)
            self.release["assets"].extend({"name": name} for name in names)
            return subprocess.CompletedProcess(command, 0)
        endpoint = command[3].removeprefix("repos/test/repo/")
        status = 200
        if endpoint == f"git/ref/tags/{TAG}":
            result = None if self.target is None else {
                "object": {"type": "tag" if self.annotated else "commit",
                           "sha": self.target}
            }
        elif endpoint.startswith("git/tags/"):
            result = {"object": {"type": "commit", "sha": self.target}}
        elif endpoint == f"releases/tags/{TAG}":
            result = self.release
        elif endpoint == "releases":
            body = json.loads(kwargs["input"])
            self.assertEqual(body["target_commitish"], SHA)
            self.assertEqual(body["tag_name"], TAG)
            self.assertEqual(body["make_latest"], "false")
            self.target = SHA
            self.release = {"prerelease": True, "draft": False, "assets": []}
            result = self.release
            status = 422 if self.create_race else 201
        else:
            self.fail(f"unexpected gh request {command}")
        if result is None:
            status = 404
        return subprocess.CompletedProcess(
            command, 0 if status < 400 else 1,
            f"HTTP/2.0 {status} Response\nContent-Type: application/json\n\n"
            + json.dumps(result), "",
        )

    def publish(self):
        with patch.object(publisher.subprocess, "run", side_effect=self.gh):
            publisher.publish("test/repo", SHA, self.directory)

    def test_create_then_retry_keeps_all_six_assets(self):
        self.publish()
        self.assertEqual(self.uploads, self.names)
        self.uploads.clear()
        self.publish()
        self.assertEqual(self.uploads, [])

    def test_concurrent_creator_and_annotated_tag(self):
        self.create_race = True
        self.annotated = True
        self.publish()
        self.assertEqual(self.uploads, self.names)

    def test_wrong_existing_tag_is_refused_before_mutation(self):
        self.target = "b" * 40
        with self.assertRaisesRegex(RuntimeError, "different commit"):
            self.publish()
        self.assertEqual(self.uploads, [])

    def test_either_partial_pair_refused_without_rewrite(self):
        for name in self.names:
            self.target = SHA
            self.release = {
                "prerelease": True, "draft": False,
                "assets": [{"name": name}],
            }
            with self.assertRaisesRegex(RuntimeError, f"partial helper pair in {TAG}") as error:
                self.publish()
            self.assertIn(name.removesuffix(".bundle"), str(error.exception))
            self.assertIn("original matching bytes", str(error.exception))
            self.assertEqual(self.uploads, [])

    def test_missing_whole_pair_resumes(self):
        self.target = SHA
        self.release = {
            "prerelease": True, "draft": False,
            "assets": [{"name": name} for name in self.names[:2]],
        }
        self.publish()
        self.assertEqual(self.uploads, self.names[2:])

    def test_invalid_commit_or_missing_inputs_never_calls_gh(self):
        with patch.object(publisher.subprocess, "run") as gh:
            with self.assertRaises(ValueError):
                publisher.publish("test/repo", "main", self.directory)
            (self.directory / self.names[0]).unlink()
            with self.assertRaises(ValueError):
                publisher.publish("test/repo", SHA, self.directory)
            gh.assert_not_called()

    def test_only_404_is_missing(self):
        for status in (401, 403, 422, 500):
            with self.subTest(status=status), patch.object(
                publisher.subprocess, "run",
                return_value=subprocess.CompletedProcess(
                    [], 1, f"HTTP/2.0 {status} Error\n\n{{}}", ""
                ),
            ):
                with self.assertRaises(RuntimeError):
                    publisher.api("test/repo", "releases")
        with patch.object(
            publisher.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 1, "", "network failure"),
        ):
            with self.assertRaises(RuntimeError):
                publisher.api("test/repo", "releases")


if __name__ == "__main__":
    unittest.main()
