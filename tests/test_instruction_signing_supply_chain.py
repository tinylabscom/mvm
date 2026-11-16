"""Source-binding and refusal tests; no real OIDC or signing operations."""

import hashlib
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "instruction_signing",
    ROOT / ".github/actions/sign-instructions/instruction-signing.py",
)
SIGNING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIGNING)
REAL_RUN = subprocess.run


class TransferTests(unittest.TestCase):
    @contextmanager
    def external_commands(self, effect=None):
        command = Mock(side_effect=effect)

        def run(args, **kwargs):
            if args[0] == "git":
                return REAL_RUN(args, **kwargs)
            return command(args, **kwargs)

        with patch.object(SIGNING.subprocess, "run", side_effect=run):
            yield command

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        Path("CLAUDE.md").write_bytes(b"original instructions\n")
        Path(".claude").mkdir()
        Path(".claude/hidden.md").write_bytes(b"hidden instructions\n")
        Path("linked.md").symlink_to("CLAUDE.md")
        self.git("add", ".")
        self.git("commit", "-qm", "Fixture")
        sha = self.git("rev-parse", "HEAD").strip()
        env = {
            "GITHUB_SHA": sha, "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/sign.yml@refs/heads/main",
            "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1",
        }
        self.env = patch.dict(os.environ, env)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.request = self.root / "request.json"
        self.files = {
            name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
            for name in ["CLAUDE.md", ".claude/hidden.md"]
        }
        self.write_request()

    def git(self, *args):
        return subprocess.check_output(
            ["git", *args], text=True,
            env={**os.environ, "GIT_EDITOR": "true", "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_CONFIG_GLOBAL": "/dev/null"},
        )

    def write_request(self, **changes):
        data = {"context": SIGNING.context(), "files": self.files}
        data.update(changes)
        self.request.write_text(json.dumps(data))

    def test_sign_uses_original_git_bytes_not_modified_worktree(self):
        Path("CLAUDE.md").write_bytes(b"producer replacement\n")
        signed = []

        def cosign(args, **kwargs):
            self.assertEqual(args[:2], ["cosign", "sign-blob"])
            signed.append(Path(args[-1]).read_bytes())
            Path(args[args.index("--bundle") + 1]).write_bytes(b"fixture bundle")

        with self.external_commands(cosign):
            SIGNING.sign(self.request, self.root / "candidate")
        self.assertIn(b"original instructions\n", signed)
        self.assertNotIn(b"producer replacement\n", signed)
        self.assertTrue(Path("candidate/.claude/hidden.md.sigstore.json").is_file())

    def test_all_request_entries_validated_before_any_signature(self):
        self.files["missing.md"] = "0" * 64
        self.write_request()
        with self.external_commands() as signer:
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                SIGNING.sign(self.request, self.root / "candidate")
            signer.assert_not_called()

    def test_wrong_context_is_refused(self):
        for key in SIGNING.CONTEXT_KEYS:
            with self.subTest(key=key):
                ctx = SIGNING.context()
                ctx[key] += "-other"
                self.write_request(context=ctx)
                with self.assertRaises(ValueError):
                    SIGNING.read_request(self.request)

    def test_wrong_hash_untracked_file_and_symlink_are_refused(self):
        Path("untracked.md").write_bytes(b"not in commit")
        for name in ["CLAUDE.md", "untracked.md", "linked.md"]:
            with self.subTest(name=name):
                self.write_request(files={name: "0" * 64})
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    SIGNING.read_request(self.request)

    def test_traversal_aliases_and_sidecars_are_refused(self):
        for name in ["../CLAUDE.md", "/CLAUDE.md", "./CLAUDE.md",
                     "a/../CLAUDE.md", "a//b", ".git/config",
                     "CLAUDE.md.sigstore.json", "a\nb", "a\\b", ""]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                SIGNING.relative_path(name)

    def test_oversized_request_and_instruction_are_refused(self):
        self.request.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            SIGNING.read_request(self.request)
        self.write_request()
        with patch.object(SIGNING, "MAX_FILE", 1), self.assertRaises(ValueError):
            SIGNING.read_request(self.request)

    def test_empty_request_is_refused(self):
        self.write_request(files={})
        with self.assertRaises(ValueError):
            SIGNING.read_request(self.request)

    def test_legacy_mode_and_misplaced_oidc_authority_are_refused(self):
        action = (ROOT / ".github/actions/sign-instructions/action.yml").read_text()
        body = action.split("      run: |\n", 1)[1].split("\n    - name:", 1)[0]
        script = "\n".join(line[8:] for line in body.splitlines() if line)
        for phase, token in [("", ""), ("combined", ""), ("prepare", "token"),
                             ("verify", "token"), ("sign", "")]:
            with self.subTest(phase=phase):
                result = REAL_RUN(
                    ["bash", "-c", script], capture_output=True, text=True,
                    env={**os.environ, "PHASE": phase,
                         "ACTIONS_ID_TOKEN_REQUEST_TOKEN": token},
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def candidates(self):
        directory = self.root / "candidate"
        for name in self.files:
            path = directory / (name + ".sigstore.json")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"candidate")
        return directory

    def test_verification_publishes_only_after_success(self):
        candidates = self.candidates()
        output = self.root / "verified"
        with patch.object(SIGNING, "discover", return_value=sorted(self.files)):
            with self.external_commands(subprocess.CalledProcessError(1, "verifier")):
                with self.assertRaises(subprocess.CalledProcessError):
                    SIGNING.verify("mvmctl", self.request, candidates, output)
            self.assertFalse(output.exists())
            with self.external_commands() as verifier:
                SIGNING.verify("mvmctl", self.request, candidates, output)
                self.assertEqual(verifier.call_args.args[0][:4],
                                 ["mvmctl", "trust", "instructions", "verify"])
        self.assertEqual((output / "CLAUDE.md.sigstore.json").read_bytes(), b"candidate")

    def test_incomplete_policy_selection_is_refused(self):
        candidates = self.candidates()
        with patch.object(SIGNING, "discover", return_value=["CLAUDE.md"]):
            with self.assertRaises(ValueError):
                SIGNING.verify("mvmctl", self.request, candidates, self.root / "verified")

    def test_extra_missing_and_symlink_bundles_are_refused(self):
        candidates = self.candidates()
        bad = candidates / "extra"
        with patch.object(SIGNING, "discover", return_value=sorted(self.files)):
            for kind in ["extra", "symlink", "missing"]:
                with self.subTest(kind=kind):
                    if kind == "extra":
                        bad.write_bytes(b"extra")
                    elif kind == "symlink":
                        bad.symlink_to("CLAUDE.md.sigstore.json")
                    else:
                        (candidates / "CLAUDE.md.sigstore.json").unlink()
                    with self.assertRaises(ValueError):
                        SIGNING.verify("mvmctl", self.request, candidates, self.root / "verified")
                    if kind != "missing":
                        bad.unlink()

    def test_modified_verifier_checkout_is_refused(self):
        candidates = self.candidates()
        Path("CLAUDE.md").write_bytes(b"modified")
        with patch.object(SIGNING, "discover", return_value=sorted(self.files)):
            with self.assertRaises(ValueError):
                SIGNING.verify("mvmctl", self.request, candidates, self.root / "verified")


if __name__ == "__main__":
    unittest.main()
