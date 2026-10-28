"""Hermetic orchestration checks, not evidence of a live microVM run."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "smoke_local_demo", Path(__file__).with_name("smoke-local-demo.py")
)
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)
PIN = "registry.example/demo/alpine@sha256:" + "a" * 64


class FakeCLI:
    def __init__(self):
        self.calls = []
        self.names = []
        self.inspect_output = PIN + "\n"
        self.inspect_code = 0
        self.run_code = None
        self.missing_output = False
        self.leak = None
        self.inventory_output = None
        self.inventory_code = 0
        self.run_error = None

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        code, stdout = 0, ""
        if command[1:3] == ["image", "inspect"]:
            code, stdout = self.inspect_code, self.inspect_output
        elif command[1:3] == ["machine", "ps"]:
            records = [{"name": "unrelated", "state": "running"}]
            if self.leak and self.names:
                records.append({"name": self.names[-1], "state": self.leak})
            stdout = json.dumps(records)
            if self.inventory_output is not None:
                stdout = self.inventory_output
            code = self.inventory_code
        else:
            self.names.append(command[command.index("--name") + 1])
            if self.run_error:
                raise self.run_error
            marker = re.search(r"'(guest-[0-9a-f]+)'", command[-1])[1]
            stdout = "" if self.missing_output else f"{marker}\nLinux\n"
            code = 7 if command[-1].endswith("exit 7") else 0
            if self.run_code is not None:
                code = self.run_code
        return subprocess.CompletedProcess(command, code, stdout, "")


class SmokeTests(unittest.TestCase):
    def run_fake(self, fake):
        SMOKE.smoke(PIN, "test-mvmctl", runner=fake, output=lambda message: None)

    def test_happy_path_commands_and_environment(self):
        fake = FakeCLI()
        with patch.dict(os.environ, {"MVM_HOME": "/prepared/cache"}):
            self.run_fake(fake)
            self.assertEqual(os.environ["MVM_HOME"], "/prepared/cache")
        self.assertEqual(len(fake.names), 2)
        self.assertEqual(len(set(fake.names)), 2)
        for name in fake.names:
            self.assertLessEqual(len(name), 63)
            self.assertRegex(name, r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
        self.assertEqual(len(fake.calls), 7)
        for command, kwargs in fake.calls:
            self.assertNotIn("env", kwargs)
            self.assertNotIn("shell", kwargs)
            self.assertLessEqual(kwargs["timeout"], 180)
            self.assertEqual(command[0], "test-mvmctl")
            for forbidden in (
                "mvmd", "--mount", "--volume", "--network", "--secret",
                "--detach", "--insecure", "--allow-unsigned", "stop",
                "bootstrap", "pull", "build", "install",
            ):
                self.assertNotIn(forbidden, command)
            self.assertNotIn("unrelated", command)
            if command[1:3] == ["machine", "run"]:
                for flag, value in (
                    ("--profile", "dev"), ("--cpus", "1"),
                    ("--memory", "256M"), ("--timeout", "120"), ("--image", PIN),
                ):
                    self.assertEqual(command[command.index(flag) + 1], value)
                self.assertGreater(kwargs["timeout"], 120)

    def test_unexpected_exit_and_missing_output(self):
        for code, missing in ((7, False), (0, False), (1, False), (None, True)):
            with self.subTest(code=code, missing=missing):
                fake = FakeCLI()
                fake.run_code, fake.missing_output = code, missing
                with self.assertRaises(SMOKE.SmokeError):
                    self.run_fake(fake)
                self.assertEqual(fake.calls[-1][0][1:3], ["machine", "ps"])

    def test_leaks_fail_even_when_stopped(self):
        for state in ("running", "stopped", "expired"):
            fake = FakeCLI()
            fake.leak = state
            with self.assertRaisesRegex(SMOKE.SmokeError, "leaked"):
                self.run_fake(fake)

    def test_invalid_inventory_fails_before_boot(self):
        for text in ("{", "{}", "[{}]", '[{"name": 2}]', "[null]", '[{"name": ""}]'):
            fake = FakeCLI()
            fake.inventory_output = text
            with self.assertRaises(SMOKE.SmokeError):
                self.run_fake(fake)
            self.assertEqual(fake.names, [])
        fake = FakeCLI()
        fake.inventory_code = 1
        with self.assertRaisesRegex(SMOKE.SmokeError, "inventory failed"):
            self.run_fake(fake)

    def test_cache_missing_or_pin_drift_prevents_boot(self):
        for code, pin in ((1, PIN), (0, PIN.replace("a" * 64, "b" * 64))):
            fake = FakeCLI()
            fake.inspect_code, fake.inspect_output = code, pin
            with self.assertRaises(SMOKE.SmokeError):
                self.run_fake(fake)
            self.assertEqual(len(fake.calls), 1)

    def test_mutable_input_rejected_without_invocation(self):
        for image in ("alpine", "alpine:latest", "alpine@sha256:abc", ""):
            fake = FakeCLI()
            with self.assertRaises(SMOKE.SmokeError):
                SMOKE.smoke(image, runner=fake)
            self.assertEqual(fake.calls, [])

    def test_missing_binary_and_preflight_timeout(self):
        for error in (FileNotFoundError("no CLI"), subprocess.TimeoutExpired("CLI", 30)):
            with self.assertRaises(SMOKE.SmokeError):
                self.run_fake(Mock(side_effect=error))

    def test_run_timeout_still_checks_teardown_and_reports_both_failures(self):
        fake = FakeCLI()
        fake.run_error = subprocess.TimeoutExpired("CLI", 180)
        fake.leak = "running"
        with self.assertRaisesRegex(SMOKE.SmokeError, "failed:.*leaked"):
            self.run_fake(fake)
        self.assertEqual(fake.calls[-1][0][1:3], ["machine", "ps"])

    def test_teardown_inventory_error_is_not_swallowed(self):
        fake = FakeCLI()

        def runner(command, **kwargs):
            result = fake(command, **kwargs)
            if fake.names and command[1:3] == ["machine", "ps"]:
                return subprocess.CompletedProcess(command, 1, "", "inventory unavailable")
            return result

        with self.assertRaisesRegex(SMOKE.SmokeError, "teardown verification failed"):
            self.run_fake(runner)


if __name__ == "__main__":
    unittest.main()
