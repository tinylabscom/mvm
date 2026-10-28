"""Run the real Zig action step with fake tools; no network or installation."""

import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/install-zigbuild/action.yml"
PINS = {
    ("Linux", "x86_64"): ("linux-x86_64", "d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea"),
    ("Linux", "aarch64"): ("linux-aarch64", "041ac42323837eb5624068acd8b00cd5777dac4cf91179e8dad7a7e90dd0c556"),
    ("Darwin", "x86_64"): ("macos-x86_64", "8b06ed1091b2269b700b3b07f8e3be3b833000841bae5aa6a09b1a8b4773effd"),
    ("Darwin", "arm64"): ("macos-aarch64", "46fae219656545dfaf4dce12fb4e8685cec5b51d721beee9389ab4194d43394c"),
}
TOOLS = r"""
set -euo pipefail
name=${0##*/}
root=$TEST_ROOT
stdin=
if [[ $name == shasum || $name == sha256sum ]]; then
    IFS= read -r stdin
    stdin+=$'\n'
fi
printf '%s\0' "$name" "$#" "$@" "$stdin" >> "$root/events"
case "$name" in
    uname)
        if [[ $1 == -s ]]; then printf '%s\n' "$TEST_OS"
        else printf '%s\n' "$TEST_ARCH"; fi ;;
    zig)
        if [[ $TEST_FAST == 1 || -f $root/linked ]]; then echo 0.13.0
        else echo 0.12.0; fi ;;
    mktemp)
        [[ $# == 1 && $1 == -d ]]
        /bin/mkdir "$root/work"
        printf '%s\n' "$root/work" ;;
    rm)
        [[ $# == 2 && $1 == -rf && $2 == "$root/work" ]]
        /bin/rm -rf "$root/work" ;;
    curl)
        while [[ $# -gt 0 && $1 != -o ]]; do shift; done
        [[ $# -ge 2 && $2 == "$root/work/"* && $2 != *..* ]]
        printf 'mock archive' > "$2"
        if [[ $TEST_FAILURE == download ]]; then exit 7; fi ;;
    shasum|sha256sum)
        if [[ $name == shasum ]]; then [[ "$*" == '-a 256 -c -' ]]
        else [[ "$*" == '-c -' ]]; fi
        archive=${stdin#*  }
        archive=${archive%$'\n'}
        [[ $archive == "$root/work/"* && $archive != *..* ]]
        [[ $(< "$archive") == 'mock archive' ]]
        if [[ $TEST_FAILURE == checksum ]]; then exit 1; fi ;;
    sudo)
        # Never execute privileged commands, even if the action regresses.
        case "$1" in
            mkdir|tar) ;;
            ln) printf linked > "$root/linked" ;;
            *) exit 99 ;;
        esac ;;
    *) echo "unexpected tool: $name" >&2; exit 99 ;;
esac
"""


class ZigBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Extract only the literal run block, without adding a YAML dependency.
        step = ACTION.read_text().split("    - name: Install zig\n", 1)[1]
        block = step.split("      run: |\n", 1)[1].split("\n    - name:", 1)[0]
        cls.script = textwrap.dedent(block)
        cls.bash = shutil.which("bash")
        assert cls.bash, "bash is required to run the composite action"

    def run_step(self, system="Linux", arch="x86_64", failure="", fast=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            tools = root / "bin"
            tools.mkdir()
            for name in ("uname", "zig", "mktemp", "rm", "curl", "shasum",
                         "sha256sum", "sudo", "tar", "ln", "mkdir"):
                tool = tools / name
                tool.write_text(f"#!{self.bash}\n" + TOOLS)
                tool.chmod(0o755)
            env = {
                "PATH": str(tools),
                "TEST_ROOT": tmp,
                "TEST_OS": system,
                "TEST_ARCH": arch,
                "TEST_FAILURE": failure,
                "TEST_FAST": "1" if fast else "0",
            }
            result = subprocess.run(
                [self.bash, "--noprofile", "--norc", "-c", self.script],
                env=env, capture_output=True, text=True, timeout=10,
            )
            fields = iter((root / "events").read_text().split("\0")[:-1])
            events = []
            for name in fields:
                args = [next(fields) for _ in range(int(next(fields)))]
                events.append([name, args, next(fields)])
            self.assertFalse((root / "work").exists(), result.stderr)
            return result, events

    def test_platform_pins_and_verify_before_extract(self):
        for (system, arch), (target, pin) in PINS.items():
            with self.subTest(system=system, arch=arch):
                result, events = self.run_step(system, arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                names = [event[0] for event in events]
                curl = next(event[1] for event in events if event[0] == "curl")
                archive = f"zig-{target}-0.13.0.tar.xz"
                self.assertEqual(curl[-1], f"https://ziglang.org/download/0.13.0/{archive}")
                for flag, value in (
                    ("--retry", "3"), ("--retry-delay", "2"),
                    ("--connect-timeout", "10"), ("--max-time", "120"),
                    ("--retry-max-time", "300"),
                ):
                    self.assertEqual(curl[curl.index(flag) + 1], value)
                self.assertIn("-fL", curl)
                self.assertIn("--retry-all-errors", curl)
                self.assertNotIn("-k", curl)
                checksum = "shasum" if system == "Darwin" else "sha256sum"
                verified = next(event for event in events if event[0] == checksum)
                self.assertEqual(verified[2], f"{pin}  {curl[curl.index('-o') + 1]}\n")
                self.assertLess(names.index("curl"), names.index(checksum))
                self.assertLess(names.index(checksum), names.index("sudo"))
                privileged = [event[1] for event in events if event[0] == "sudo"]
                self.assertEqual(privileged, [
                    ["mkdir", "-p", "/opt"],
                    ["tar", "-xJf", curl[curl.index("-o") + 1], "-C", "/opt"],
                    ["ln", "-sf", f"/opt/zig-{target}-0.13.0/zig", "/usr/local/bin/zig"],
                ])

    def test_download_and_checksum_failures_never_install(self):
        for system, arch in PINS:
            for failure in ("download", "checksum"):
                with self.subTest(system=system, failure=failure):
                    result, events = self.run_step(system, arch, failure)
                    self.assertNotEqual(result.returncode, 0)
                    names = [event[0] for event in events]
                    for forbidden in ("sudo", "tar", "ln", "mkdir"):
                        self.assertNotIn(forbidden, names)
                    if failure == "download":
                        self.assertEqual(result.returncode, 7)
                        self.assertNotIn("shasum", names)
                        self.assertNotIn("sha256sum", names)

    def test_installed_pin_needs_no_sudo_or_network(self):
        result, events = self.run_step(fast=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([event[0] for event in events], ["zig"])

    def test_unsupported_platforms_fail_explicitly(self):
        for system, arch in (("FreeBSD", "x86_64"), ("Linux", "riscv64")):
            with self.subTest(system=system, arch=arch):
                result, events = self.run_step(system, arch)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"no pinned zig binary for {system}/{arch}", result.stderr)
                self.assertEqual([event[0] for event in events], ["zig", "uname", "uname"])


if __name__ == "__main__":
    unittest.main()
