#!/usr/bin/env python3
"""Exercise the development wrapper without compiling or booting a VM."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class BinDevTest(unittest.TestCase):
    def test_builds_cli_and_host_helpers_without_eager_embed(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryDirectory() as state_dir,
        ):
            root = Path(temporary)
            (root / "bin").mkdir()
            (root / "scripts").mkdir()
            wrapper = root / "bin" / "dev"
            shutil.copy2(ROOT / "bin" / "dev", wrapper)
            cargo = root / "scripts" / "cargo.sh"
            cargo.write_text(
                "#!/bin/sh\n"
                'if [ -n "${TEST_BUILD_EXIT:-}" ]; then exit "$TEST_BUILD_EXIT"; fi\n'
                'printf "%s\\n" "$*" > "$MVM_HOME/build-args"\n'
                'mkdir -p "$CARGO_TARGET_DIR/debug"\n'
                'printf \'#!/bin/sh\\nprintf "ran:%%s\\\\n" "$*"\\n\' '
                '> "$CARGO_TARGET_DIR/debug/mvmctl"\n'
                'chmod +x "$CARGO_TARGET_DIR/debug/mvmctl"\n'
            )
            cargo.chmod(0o755)
            state = Path(state_dir) / "state"
            env = {**os.environ, "MVM_PAIRS_DIR": str(state), "MVM_IMAGES_DIR": ""}
            env.pop("TEST_BUILD_EXIT", None)
            result = subprocess.run(
                [str(wrapper), "doctor"],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "ran:doctor\n")
            homes = list(state.glob("*/home"))
            self.assertEqual(len(homes), 1)
            self.assertEqual(
                (homes[0] / "build-args").read_text(),
                "build -p mvmctl -p mvm-hostd -p mvm-gpu --bins --features mvmctl/dev\n",
            )
            self.assertTrue(next(root.glob("target/pair-*/debug/mvmctl")).is_file())

            failed = subprocess.run(
                [str(wrapper), "doctor"],
                env={**env, "TEST_BUILD_EXIT": "23"},
                capture_output=True,
                text=True,
            )
            self.assertEqual(failed.returncode, 23, failed.stderr)
            self.assertEqual(
                failed.stdout, "", "must not run the old CLI after build failure"
            )


if __name__ == "__main__":
    unittest.main()
