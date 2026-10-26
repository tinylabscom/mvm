#!/usr/bin/env python3
"""Manually run the built shims against an owned, explicit native endpoint."""
import argparse
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


LOG_LIMIT = 65536
TEARDOWN_SECONDS = 5


def diagnostic(value):
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    return (value or "")[-LOG_LIMIT:]


def run_checked(command, env, timeout):
    try:
        return subprocess.run(command, env=env, text=True, capture_output=True,
                              check=True, timeout=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"{command[0]}: {error}; stderr: "
                           f"{diagnostic(error.stderr)}") from error


def check_environment(env):
    for key in ("CUDA_VISIBLE_DEVICES", "CUDA_DEVICE_ORDER",
                "NVIDIA_VISIBLE_DEVICES"):
        if key in env:
            raise RuntimeError(f"unsupported visibility/order override: {key}")


def host_identity(stdout):
    rows = [[field.strip() for field in row.split(",")]
            for row in stdout.strip().splitlines()]
    if (len(rows) != 1 or len(rows[0]) != 5 or rows[0][0] != "0"
            or not rows[0][1].startswith("GPU-")
            or rows[0][4] not in ("Disabled", "N/A", "[N/A]")):
        raise RuntimeError("requires exactly one physical GPU with MIG disabled")
    return rows


def cleanup(child):
    if child.poll() is None:
        child.kill()
    try:
        child.wait(timeout=TEARDOWN_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"endpoint PID {child.pid}: cleanup uncertain after "
                           f"{TEARDOWN_SECONDS}s teardown budget") from error


def drain_stderr(stream, retained):
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            retained.extend(chunk)
            del retained[:-LOG_LIMIT]
    finally:
        stream.close()


def positive_seconds(value):
    seconds = int(value)
    if not 1 <= seconds <= 300:
        raise argparse.ArgumentTypeError("deadline must be between 1 and 300 seconds")
    return seconds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--cuda-shim", required=True, type=Path)
    parser.add_argument("--nvml-shim", required=True, type=Path)
    parser.add_argument("--timeout", type=positive_seconds, default=60)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    paths = [args.endpoint, args.probe, args.cuda_shim, args.nvml_shim]
    if any(not p.is_absolute() or not p.is_file() for p in paths):
        parser.error("all artifact paths must be absolute existing files")
    if platform.system() != "Linux":
        parser.error("native hardware execution requires an authorized Linux host")
    deadline = time.monotonic() + args.timeout

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("native witness deadline exceeded")
        return seconds

    with tempfile.TemporaryDirectory(prefix="mvm-native-") as directory:
        rpc = "unix:" + directory + "/gpu.sock"
        env = dict(os.environ, MVM_GPU_RPC=rpc)
        # Never let the endpoint resolve the guest shims as host driver libraries.
        env.pop("LD_LIBRARY_PATH", None)
        env.pop("LD_PRELOAD", None)
        check_environment(env)
        host = run_checked(
            ["nvidia-smi", "--query-gpu=index,uuid,name,driver_version,mig.mode.current",
             "--format=csv,noheader"], env, remaining())
        rows = host_identity(host.stdout)
        command = [str(args.endpoint), "--listen", rpc, "--backend", "native"]
        with tempfile.TemporaryFile(mode="w+") as log:
            child = subprocess.Popen(command, env=env, stdout=log,
                                     stderr=subprocess.PIPE)
            retained = bytearray()
            reader = None
            try:
                # Observe the endpoint's startup event, not socket-file polling.
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stderr, selectors.EVENT_READ)
                    startup = b""
                    while b"listening on" not in startup:
                        if not selector.select(remaining()):
                            raise TimeoutError("endpoint startup deadline exceeded")
                        chunk = os.read(child.stderr.fileno(), 4096)
                        retained.extend(chunk)
                        del retained[:-LOG_LIMIT]
                        if not chunk:
                            raise RuntimeError("native endpoint refused startup: "
                                               + startup.decode(errors="replace"))
                        startup += chunk
                        if len(startup) > 65536:
                            raise RuntimeError("endpoint startup log exceeded limit")
                    # The existing startup line precedes bind/listen. Until the
                    # endpoint exports a post-listen event, use a bounded
                    # compatibility reconciliation, still observing child EOF.
                    for attempt in range(5):
                        try:
                            with socket.socket(socket.AF_UNIX) as connection:
                                connection.settimeout(remaining())
                                connection.connect(rpc.removeprefix("unix:"))
                            break
                        except (FileNotFoundError, ConnectionRefusedError):
                            if attempt == 4:
                                raise RuntimeError("endpoint never accepted a connection")
                            if selector.select(min(0.05 * 2**attempt, remaining())):
                                chunk = os.read(child.stderr.fileno(), 4096)
                                retained.extend(chunk)
                                del retained[:-LOG_LIMIT]
                                if not chunk:
                                    raise RuntimeError("endpoint exited before listen")
                reader = threading.Thread(target=drain_stderr,
                                          args=(child.stderr, retained), daemon=True)
                reader.start()
                probe = run_checked(
                    [str(args.probe), str(args.cuda_shim), str(args.nvml_shim)],
                    env, remaining())
                version, count, driver, name, result = probe.stdout.strip().split("\t")
                if (int(count) != 1
                        or rows[0][2:4] != [name, driver] or int(result) != 142):
                    raise RuntimeError("NVML/host comparison or kernel result mismatch")
                if child.poll() is not None:
                    raise RuntimeError("native endpoint exited during witness")
                evidence = {
                    "schema": 1, "backend": "native", "transport": "unix",
                    "platform": platform.platform(), "artifacts": list(map(str, paths)),
                    "cuda_driver_api_version": int(version),
                    "nvml": {"count": int(count), "driver": driver, "gpu0_name": name},
                    "nvidia_smi": rows, "kernel_expected": 142,
                    "kernel_actual": int(result), "passed": True,
                    "identity_policy": "single-physical-gpu-no-remapping-no-mig",
                }
            finally:
                try:
                    cleanup(child)
                finally:
                    if reader is not None:
                        reader.join(timeout=0.2)
                    else:
                        child.stderr.close()
                    if retained:
                        print("endpoint stderr: " + diagnostic(bytes(retained)),
                              file=sys.stderr)
            print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"native witness failed: {error}", file=sys.stderr)
        sys.exit(1)
