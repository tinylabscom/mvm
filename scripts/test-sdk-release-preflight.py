"""Hermetic release orchestration tests. Run with Python 3.11 or newer."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location(
    "preflight", Path(__file__).with_name("sdk-release-preflight.py"))
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)
ROOT = Path(__file__).resolve().parents[1]


class PreflightTests(unittest.TestCase):
    def test_workspace_compatibility_and_independent_sdk_version(self):
        release = preflight.validate_metadata(ROOT, "workflow_dispatch", "", True)
        self.assertNotEqual(release["version"], release["runtime_version"])
        preflight.validate_metadata(ROOT, "release", "sdk-v" + release["version"], False)
        with self.assertRaises(ValueError):
            preflight.validate_metadata(ROOT, "release", "v" + release["runtime_version"], False)
        with self.assertRaises(ValueError):
            preflight.validate_metadata(ROOT, "workflow_dispatch", "", False)

    def test_incompatible_runtime_fails(self):
        original = preflight.tomllib.loads

        def loads(text):
            data = original(text)
            if "runtime_version" in data:
                data["runtime_version"] = "0.0.1"
            return data

        with patch.object(preflight.tomllib, "loads", side_effect=loads):
            with self.assertRaisesRegex(ValueError, "compiled hostlib"):
                preflight.validate_metadata(ROOT, "workflow_dispatch", "", True)

    def test_partial_publication_is_resumable(self):
        release = preflight.validate_metadata(ROOT, "workflow_dispatch", "", True)
        calls = []

        def fetch(url):
            calls.append(url)
            return {} if "pypi.org" in url else None

        state = preflight.registry_state(release, fetch)
        self.assertEqual(len(calls), 7)
        self.assertEqual(state["pypi"], "present; resume/verify")
        self.assertEqual(state["@runmvm/mvm"], "absent")
        with self.assertRaises(OSError):
            preflight.registry_state(release, lambda _: (_ for _ in ()).throw(OSError("network")))

    def test_registry_only_404_is_absent(self):
        for code in (404, 401, 429, 500):
            with patch.object(preflight.urllib.request, "urlopen",
                              side_effect=urllib.error.HTTPError("url", code, "failure", {}, None)):
                if code == 404:
                    self.assertIsNone(preflight.fetch_json("url"))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        preflight.fetch_json("url")

    def test_checksum_filename_uniqueness(self):
        record = "a" * 64 + "  runtime.tar.gz\n"
        self.assertEqual(preflight.checksum_record(record, "runtime.tar.gz"), "a" * 64)
        for bad in ("", record + record, record.replace("runtime.tar.gz", "other.tar.gz")):
            with self.assertRaises(ValueError):
                preflight.checksum_record(bad, "runtime.tar.gz")

    def test_signature_provenance_and_hash_gate(self):
        archive = "mvm-guest-bins-v0.23.1.tar.gz"
        payload = b"fixture: signature and archive completeness are external verifier responsibilities"
        digest = hashlib.sha256(payload).hexdigest()
        assets = {
            archive: payload,
            archive + ".sha256": f"{digest}  {archive}\n".encode(),
            "checksums-sha256.txt": f"{digest}  {archive}\n".encode(),
        }

        def download(url, **_):
            name = url.rsplit("/", 1)[1]
            self.assertIn("/v0.23.1/", url)
            return io.BytesIO(b"bundle" if name.endswith(".bundle") else assets[name])

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(preflight.urllib.request, "urlopen", side_effect=download):
                with patch.object(preflight.subprocess, "run") as run:
                    self.assertEqual(preflight.verify_runtime("0.23.1", Path(directory)), digest)
                    self.assertEqual(run.call_count, 4)
                    for call in run.call_args_list[:3]:
                        self.assertIn("https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.23.1", call.args[0])
                    self.assertIn("--source-ref", run.call_args.args[0])
                with patch.object(preflight.subprocess, "run",
                                  side_effect=subprocess.CalledProcessError(1, "verifier")):
                    with self.assertRaises(subprocess.CalledProcessError):
                        preflight.verify_runtime("0.23.1", Path(directory))
                assets[archive + ".sha256"] = f"{'0' * 64}  {archive}\n".encode()
                with patch.object(preflight.subprocess, "run"):
                    with self.assertRaisesRegex(ValueError, "does not match"):
                        preflight.verify_runtime("0.23.1", Path(directory))

    def test_dry_run_does_not_access_network(self):
        with patch.dict(preflight.os.environ, {"SDK_EVENT_NAME": "workflow_dispatch", "SDK_DRY_RUN": "true"}):
            with patch.object(preflight.urllib.request, "urlopen", side_effect=AssertionError("network")):
                preflight.main()

    def test_registry_smoke_empty_environment_and_exact_registry_commands(self):
        # Command doubles record arguments and environment; never invoke a
        # package manager, network, native library, container or VM.
        for language in ("python", "node"):
            with self.subTest(language=language), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                log = directory / "commands"
                fake = directory / "fake"
                fake.mkdir()
                recorder = """#!/bin/sh
set -eu
test -z "${MVM_HOSTLIB_PATH:-}${PYTHONPATH:-}${PYTHONHOME:-}${NODE_PATH:-}${NODE_OPTIONS:-}"
test "$PWD" != "$SOURCE"
if [ "${0##*/}" = npm ]; then
  test "$npm_config_userconfig" != "$npm_config_globalconfig"
  test -f "$npm_config_userconfig" && test ! -s "$npm_config_userconfig"
  test -f "$npm_config_globalconfig" && test ! -s "$npm_config_globalconfig"
fi
printf '%s\\n' "$*" >> "$LOG"
if [ "${1:-}" = -m ] && [ "${2:-}" = venv ]; then
  mkdir -p venv/bin
  cp "$0" venv/bin/python
fi
"""
                for command in ("python3", "node", "npm"):
                    file = fake / command
                    file.write_text(recorder)
                    file.chmod(0o755)
                smoke = directory / ("smoke_installed.py" if language == "python" else "smoke-installed.mjs")
                smoke.write_text("not executed by command doubles")
                env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", LOG=str(log),
                           SOURCE=str(ROOT), MVM_HOSTLIB_PATH="/wrong", PYTHONPATH="/wrong",
                           NODE_PATH="/wrong", PYTHON=str(fake / "python3"))
                result = subprocess.run(
                    ["sh", str(ROOT / "scripts/sdk-registry-smoke.sh"), language,
                     "0.15.1", "linux-x64-gnu", str(smoke)],
                    env=env, cwd=ROOT, check=True, text=True, capture_output=True)
                commands = log.read_text()
                self.assertIn("Guest boot NOT witnessed", result.stdout)
                if language == "python":
                    self.assertIn("--index-url https://pypi.org/simple", commands)
                    self.assertIn("--only-binary=:all: mvm==0.15.1", commands)
                    self.assertIn("smoke_installed.py", commands)
                else:
                    self.assertIn("--registry=https://registry.npmjs.org --include=optional", commands)
                    self.assertIn("--save-exact @runmvm/mvm@0.15.1", commands)
                    self.assertIn("smoke-installed.mjs linux-x64-gnu", commands)


if __name__ == "__main__":
    unittest.main()
