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


class ToolchainPolicy(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="mvm-toolchain-policy-", dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        paths = [
            "rust-toolchain.toml", "Cargo.toml", "flake.nix", "Justfile",
            ".cargo/config.toml", ".githooks/pre-commit",
            "scripts/check-cargo-toolchain.sh", "scripts/cargo.sh",
            "nix/packages/embedded-rust-toolchain.nix",
            "nix/packages/rust-platform.nix",
            "crates/mvm-build/src/guest_agent_build.rs",
            "crates/mvm-conformance/tests/steps/cli.rs",
            "crates/mvm-hostd/ebpf/rust-toolchain.toml",
        ]
        paths += [str(p.relative_to(ROOT)) for p in (ROOT / "nix/packages").glob("*.nix")]
        for extension in ("yml", "yaml"):
            paths += [
                str(p.relative_to(ROOT))
                for p in (ROOT / ".github/workflows").glob(f"*.{extension}")
            ]
            paths += [
                str(p.relative_to(ROOT))
                for p in (ROOT / ".github/actions").rglob(f"action.{extension}")
            ]
        for name in paths:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)

    def check(self):
        return subprocess.run(
            ["bash", str(self.root / "scripts/check-cargo-toolchain.sh")],
            capture_output=True, text=True, timeout=15,
        )

    def test_current_pins_pass(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unlisted_workflow_cannot_select_another_compiler(self):
        workflow = self.root / ".github/workflows/new-build.yml"
        for channel in ["stable", "1.99.0", "nightly", "nightly-2026-06-11"]:
            workflow.write_text(f"jobs:\n  build:\n    with:\n      toolchain: {channel}\n")
            result = self.check()
            self.assertNotEqual(result.returncode, 0, channel)
            self.assertIn("new-build.yml", result.stderr)

    def test_yaml_workflow_overrides_cannot_bypass_the_pin(self):
        workflow = self.root / ".github/workflows/override.yaml"
        for selection in [
            'toolchain: "stable"',
            "RUSTUP_TOOLCHAIN: nightly",
            "run: RUSTUP_TOOLCHAIN=nightly cargo check",
            "run: cargo +1.99.0 check",
            "run: rustc +nightly -V",
            "run: rustup default stable",
            "run: rustup toolchain install 1.99.0",
        ]:
            workflow.write_text(f"jobs:\n  build:\n    {selection}\n")
            result = self.check()
            self.assertNotEqual(result.returncode, 0, selection)
            self.assertIn("override.yaml", result.stderr)

    def test_nightly_exception_is_not_shared_with_other_jobs(self):
        workflow = self.root / ".github/workflows/security.yml"
        workflow.write_text(
            workflow.read_text()
            + "\n  unrelated:\n    with:\n      toolchain: nightly-2026-06-11\n"
        )
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("(unrelated)", result.stderr)

    def test_new_nix_recipe_cannot_bypass_the_pinned_compiler(self):
        recipe = self.root / "nix/packages/mvm-new.nix"
        for decoy in ["", "# import ./rust-platform.nix\n"]:
            recipe.write_text(
                decoy + "{ pkgs, mvmSrc }: pkgs.rustPlatform.buildRustPackage { src = mvmSrc; }\n"
            )
            result = self.check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mvm-new.nix", result.stderr)

    def test_recipe_inventory_cannot_silently_shrink(self):
        for path in (self.root / "nix/packages").glob("mvm-*.nix"):
            path.unlink()
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected at least 10", result.stderr)

    def test_embedded_metadata_cannot_drift_from_root(self):
        manifest = self.root / "Cargo.toml"
        pin = next(
            line.split('"')[1]
            for line in (self.root / "rust-toolchain.toml").read_text().splitlines()
            if line.startswith("channel = ")
        )
        manifest.write_text(manifest.read_text().replace(f'rust = "{pin}"', 'rust = "1.99.0"'))
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("embedded compiler must match", result.stderr)


if __name__ == "__main__":
    unittest.main()
