"""CPU-only checks; never start an endpoint or inspect GPU hardware."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/native-gpu-witness.py"
SPEC = importlib.util.spec_from_file_location("witness", RUNNER)
witness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(witness)


class NativeWitnessTests(unittest.TestCase):
    def test_identity_policy(self):
        good = "0, GPU-abc, Example, 555, Disabled\n"
        self.assertEqual(witness.host_identity(good)[0][1], "GPU-abc")
        for bad in ("", good + good, good.replace("Disabled", "Enabled"),
                    good.replace("GPU-abc", "MIG-abc"),
                    good.replace("Disabled", "Unknown")):
            with self.assertRaises(RuntimeError):
                witness.host_identity(bad)
        for key in ("CUDA_VISIBLE_DEVICES", "CUDA_DEVICE_ORDER",
                    "NVIDIA_VISIBLE_DEVICES"):
            with self.assertRaises(RuntimeError):
                witness.check_environment({key: ""})

    def test_command_diagnostics(self):
        for error in (
            subprocess.CalledProcessError(1, ["probe"], stderr="driver refused"),
            subprocess.TimeoutExpired(["probe"], 1, stderr=b"driver refused"),
        ):
            with patch.object(witness.subprocess, "run", side_effect=error):
                with self.assertRaisesRegex(RuntimeError, "driver refused"):
                    witness.run_checked(["probe"], {}, 1)
        self.assertEqual(len(witness.diagnostic(b"x" * 100000)), 65536)

    def test_drain_and_cleanup_budget(self):
        retained = bytearray()
        witness.drain_stderr(io.BytesIO(b"x" * 100000 + b"last"), retained)
        self.assertEqual(len(retained), 65536)
        self.assertTrue(retained.endswith(b"last"))
        child = Mock(pid=123)
        child.poll.return_value = None
        witness.cleanup(child)
        child.kill.assert_called_once()
        child.wait.assert_called_once_with(timeout=5)
        child.wait.side_effect = subprocess.TimeoutExpired("endpoint", 5)
        with self.assertRaisesRegex(RuntimeError, "PID 123: cleanup uncertain"):
            witness.cleanup(child)

    def orchestrate(self, startup=b"listening on", ready=True,
                    probe="12000\t1\t555\tExample\t142\n", clock=None,
                    connect_error=None):
        argv = ["witness"]
        for option in ("endpoint", "probe", "cuda-shim", "nvml-shim"):
            argv.extend(["--" + option, str(RUNNER)])
        child = Mock(pid=321)
        child.poll.return_value = None
        child.stderr = Mock()
        child.stderr.fileno.return_value = 99
        child.stderr.read.return_value = b""
        selector = Mock()
        selector.select.return_value = [True] if ready else []
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.connect.side_effect = connect_error
        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            for target, kwargs in (
                ("sys.argv", {"new": argv}),
                ("os.environ", {"new": {}}),
                ("platform.system", {"return_value": "Linux"}),
                ("platform.platform", {"return_value": "mock-linux"}),
                ("signal.signal", {}),
                ("subprocess.Popen", {"return_value": child}),
                ("selectors.DefaultSelector", {"return_value": selector}),
                ("socket.socket", {"return_value": connection}),
                ("os.read", {"return_value": startup}),
                ("run_checked", {"side_effect": [
                    Mock(stdout="0, GPU-abc, Example, 555, Disabled\n"),
                    Mock(stdout=probe)]}),
            ):
                if "." in target:
                    owner, name = target.split(".")
                    stack.enter_context(patch.object(getattr(witness, owner),
                                                     name, **kwargs))
                else:
                    stack.enter_context(patch.object(witness, target, **kwargs))
            if clock:
                stack.enter_context(patch.object(witness.time, "monotonic",
                                                side_effect=clock))
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            witness.main()
        return json.loads(output.getvalue()), child

    def test_success_evidence(self):
        evidence, child = self.orchestrate()
        self.assertTrue(evidence["passed"])
        self.assertEqual(evidence["kernel_actual"], 142)
        self.assertEqual(evidence["nvidia_smi"][0][1], "GPU-abc")
        child.wait.assert_called_once_with(timeout=5)

    def test_readiness_deadlines_and_mismatch(self):
        for kwargs, message in (
            ({"startup": b""}, "refused startup"),
            ({"ready": False}, "startup deadline"),
            ({"connect_error": ConnectionRefusedError()}, "never accepted"),
            ({"clock": [0, 61]}, "deadline exceeded"),
            ({"probe": "12000\t2\t555\tExample\t142\n"}, "mismatch"),
            ({"probe": "12000\t1\t555\tOther\t142\n"}, "mismatch"),
            ({"probe": "12000\t1\t555\tExample\t105\n"}, "mismatch"),
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex((RuntimeError, TimeoutError), message):
                    self.orchestrate(**kwargs)

    def test_arguments_fail_before_execution(self):
        artifacts = ["--endpoint", str(RUNNER), "--probe", str(RUNNER),
                     "--cuda-shim", str(RUNNER), "--nvml-shim", str(RUNNER)]
        for args in ([], ["--timeout", "0"], ["--timeout", "301"],
                     ["--timeout", "invalid"]):
            result = subprocess.run([sys.executable, str(RUNNER),
                                     *(artifacts if args else []), *args],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)

    def test_compile_and_transport_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory) / "probe"
            command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                       "-Werror", str(ROOT / "crates/mvm-gpu/tests/native_witness.c"),
                       "-o", str(probe)]
            if sys.platform != "darwin":
                command.append("-ldl")
            subprocess.run(command, check=True, timeout=30)
            for rpc in ("", "tcp:localhost:5256", "unix:relative", "unix:/"):
                result = subprocess.run([str(probe), "/missing/cuda", "/missing/nvml"],
                                        env=dict(os.environ, MVM_GPU_RPC=rpc),
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 64)
            result = subprocess.run([str(probe), "/missing/cuda", "/missing/nvml"],
                                    env=dict(os.environ, MVM_GPU_RPC="unix:/missing"),
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
