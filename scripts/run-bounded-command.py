#!/usr/bin/env python3
"""Run a command with streamed output and a deadline for its process tree."""

from __future__ import annotations

import argparse
import errno
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--grace", type=float, default=5.0)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    if args.timeout <= 0 or args.grace < 0:
        parser.error("--timeout must be positive and --grace must be non-negative")
    return args


def stream_output(pipe: object, log_path: Path) -> None:
    with log_path.open("wb") as log:
        while chunk := pipe.read(64 * 1024):
            log.write(chunk)
            log.flush()
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()


def signal_group(process_group: int, sig: int) -> bool:
    try:
        os.killpg(process_group, sig)
        return True
    except ProcessLookupError:
        return False
    except OSError as error:
        if error.errno == errno.ESRCH:
            return False
        raise


def group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
    except OSError as error:
        if error.errno in (errno.ESRCH, errno.EPERM):
            return False
        raise


def terminate_group(process: subprocess.Popen[bytes], grace: float) -> None:
    process_group = process.pid
    signal_group(process_group, signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        process.poll()
        if not group_exists(process_group):
            break
        time.sleep(min(0.05, deadline - time.monotonic()))
    try:
        signal_group(process_group, signal.SIGKILL)
    except PermissionError:
        # macOS can reparent the last dying group member between the existence
        # probe and this fallback. TERM already reached the private group; an
        # EPERM at this point is equivalent to the group no longer being ours.
        pass
    process.wait()


def normalized_exit_code(return_code: int) -> int:
    return return_code if return_code >= 0 else 128 - return_code


def main() -> int:
    args = parse_args()
    args.log.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        args.command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    if process.stdout is None:
        raise RuntimeError("subprocess stdout pipe was not created")
    reader = threading.Thread(target=stream_output, args=(process.stdout, args.log))
    reader.start()

    try:
        return_code = process.wait(timeout=args.timeout)
        # A command can exit after spawning a background helper that still has
        # the output pipe open. The wrapper owns the whole session, so clean up
        # any such descendants before joining the output thread.
        terminate_group(process, args.grace)
    except subprocess.TimeoutExpired:
        print(
            f"bounded command exceeded {args.timeout:g}s; terminating process group",
            file=sys.stderr,
        )
        terminate_group(process, args.grace)
        return_code = 124
    except KeyboardInterrupt:
        terminate_group(process, args.grace)
        return_code = 130
    finally:
        reader.join()

    return normalized_exit_code(return_code)


if __name__ == "__main__":
    raise SystemExit(main())
