"""Exercise the contributor toolchain recipe without installing anything."""

import os
import pathlib
import subprocess
import sys
import sysconfig
import tempfile
import textwrap
import tomllib
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


class PayloadToolchainTests(unittest.TestCase):
    def test_recipe_installs_pinned_zig_into_an_isolated_target(self):
        pins = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["metadata"]["mvm"][
            "toolchain"
        ]
        recipe = (ROOT / "just/payload/mod.just").read_text().split("\ntoolchain:\n", 1)[1]
        script = textwrap.dedent(recipe.split("\n# Build the per-VM", 1)[0])
        with tempfile.TemporaryDirectory() as temp:
            home = pathlib.Path(temp)
            tools = home / "tools"
            tools.mkdir()
            (tools / "python3").write_text(
                "#!/bin/sh\n"
                'if [ "$1" = -c ]; then exec "$TEST_PYTHON" "$@"; fi\n'
                'if [ "$1" = -m ] && [ "$2" = pip ] && [ "$3" = install ]; then\n'
                '  shift 3\n'
                '  printf "%s\\n" "$@" > "$HOME/pip-args"\n'
                '  exit 0\n'
                "fi\n"
                'echo "system Python pip was used without an isolated install" >&2\n'
                "exit 99\n"
            )
            (tools / "rustup").write_text("#!/bin/sh\nexit 0\n")
            (tools / "cargo-zigbuild").write_text(
                f'#!/bin/sh\nprintf "cargo-zigbuild {pins["cargo-zigbuild"]}\\n"\n'
            )
            (tools / "cargo").write_text("#!/bin/sh\nexit 99\n")
            for tool in tools.iterdir():
                tool.chmod(0o755)

            result = subprocess.run(
                ["bash", "-c", script],
                cwd=ROOT,
                env={
                    **os.environ,
                    "HOME": temp,
                    "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
                    "TEST_PYTHON": sys.executable,
                },
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            target = home / ".local/share/mvm/toolchains/zig" / pins["zig"]
            self.assertEqual(
                (home / "pip-args").read_text().splitlines(),
                ["--quiet", "--upgrade", "--target", str(target), f"ziglang=={pins['zig']}"],
            )

    @unittest.skipUnless(
        os.environ.get("MVM_EXPECT_PEP668") == "1", "requires system Python with PEP 668"
    )
    def test_real_pip_can_install_into_target_with_externally_managed_python(self):
        marker = pathlib.Path(sysconfig.get_path("stdlib")) / "EXTERNALLY-MANAGED"
        self.assertTrue(marker.is_file(), f"not an externally managed Python: {marker}")
        with tempfile.TemporaryDirectory() as temp:
            wheel = pathlib.Path(temp) / "ziglang-0.13.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("ziglang/__init__.py", "")
                archive.writestr("ziglang/zig", "test binary")
                archive.writestr(
                    "ziglang-0.13.0.dist-info/METADATA",
                    "Metadata-Version: 2.1\nName: ziglang\nVersion: 0.13.0\n",
                )
                archive.writestr(
                    "ziglang-0.13.0.dist-info/WHEEL",
                    "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                )
                archive.writestr("ziglang-0.13.0.dist-info/RECORD", "")

            pip_env = {**os.environ, "PIP_CONFIG_FILE": os.devnull}
            pip_env.pop("PIP_BREAK_SYSTEM_PACKAGES", None)
            refusal = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--dry-run", "--no-index", str(wheel)],
                env=pip_env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(refusal.returncode, 0, refusal.stdout)
            self.assertIn("externally-managed-environment", refusal.stderr)

            target = pathlib.Path(temp) / "toolchain"
            result = subprocess.run(
                [
                    sys.executable, "-m", "pip", "install", "--no-index",
                    "--target", str(target), str(wheel),
                ],
                env=pip_env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((target / "ziglang/zig").read_text(), "test binary")


if __name__ == "__main__":
    unittest.main()
