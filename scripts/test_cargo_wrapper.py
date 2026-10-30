#!/usr/bin/env python3
"""Exercise compiler selection, target isolation and argv forwarding without building."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class CargoWrapper(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="mvm-cargo-", dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in ["cargo.sh", "cargo-target-dir-guard.sh"]:
            shutil.copyfile(ROOT / "scripts" / name, scripts / name)
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.97.1"\n')
        self.tools = self.root / "tools"
        self.tools.mkdir()
        rustup = self.tools / "rustup"
        rustup.write_text(
            '#!/bin/sh\n'
            '[ "$1" = which ] && [ "$2" = --toolchain ] && [ "$3" = 1.97.1 ] || exit 17\n'
            'printf "%s/%s\\n" "$TEST_TOOLS" "$4"\n'
        )
        rustup.chmod(0o755)
        for name in ["cargo", "cargo-zigbuild"]:
            tool = self.tools / name
            tool.write_text(
                '#!/usr/bin/env python3\n'
                'import json, os, sys\n'
                'print(json.dumps({"argv": sys.argv[1:], "rust": os.environ["RUSTC"], '
                '"toolchain": os.environ["RUSTUP_TOOLCHAIN"], '
                '"target": os.environ.get("CARGO_TARGET_DIR")}))\n'
                'sys.exit(int(os.environ.get("TEST_STATUS", "0")))\n'
            )
            tool.chmod(0o755)

    def run_wrapper(self, *args, **overrides):
        env = {
            **os.environ,
            "PATH": f"{self.tools}:{os.environ['PATH']}",
            "TEST_TOOLS": str(self.tools),
            "RUSTUP_TOOLCHAIN": "unwanted-nightly",
            "RUSTC": "/unwanted/rustc",
        }
        for name in ["CARGO_TARGET_DIR", "MVM_DEV_ENV_KEEP_INHERITED", "TEST_STATUS"]:
            env.pop(name, None)
        return subprocess.run(
            ["bash", str(self.root / "scripts/cargo.sh"), *args],
            cwd=self.root, env={**env, **overrides}, capture_output=True, text=True,
        )

    def test_build_test_and_lint_share_the_pin_and_target(self):
        target = str(self.root / "target with spaces")
        for command in ["build", "test", "clippy"]:
            result = self.run_wrapper(command, "--locked", CARGO_TARGET_DIR=target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {
                "argv": [command, "--locked"],
                "rust": str(self.tools / "rustc"),
                "toolchain": "1.97.1",
                "target": target,
            })

    def test_default_target_is_not_redirected_to_a_second_build_tree(self):
        result = self.run_wrapper("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(json.loads(result.stdout)["target"])

    def test_foreign_target_is_reclaimed_unless_explicitly_kept(self):
        for keep, expected in [("", str(self.root / "target")), ("1", "/foreign/target")]:
            result = self.run_wrapper(
                "check", CARGO_TARGET_DIR="/foreign/target", MVM_DEV_ENV_KEEP_INHERITED=keep,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["target"], expected)

    def test_direct_tool_preserves_arguments_and_failure_status(self):
        result = self.run_wrapper(
            "--direct", "cargo-zigbuild", "check", "name with spaces;not-a-command",
            TEST_STATUS="9",
        )
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertEqual(json.loads(result.stdout)["argv"],
                         ["check", "name with spaces;not-a-command"])

    def test_missing_toolchain_fails_before_cargo_runs(self):
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "missing"\n')
        result = self.run_wrapper("build")
        self.assertEqual(result.returncode, 17)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
