"""Capped + timed subprocess helper for the host SDK transport (plan-0005).

The SDK shells out to ``mvmctl`` for invoke / session start / session stop.
The substrate may hang, return gigabytes, or otherwise misbehave — defense
in depth says the SDK reads bounded output, kills on timeout, and never
buffers the full stream into RAM if the cap is exceeded.

This module exposes :func:`run_capped` which mirrors the slice of
:func:`subprocess.run` we use, with two extra guarantees:

- Hard cap on stdout and stderr bytes (each independently).
- Hard wall-clock timeout. On expiry, the child is ``SIGKILL``'d and the
  function raises ``TransportTimeout``.
- On stdout cap exceeded, the child is killed and ``TransportOutputOverflow``
  is raised. Whatever we already read is discarded — we don't return a
  partial result that pretends to be valid.
"""

from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import dataclass


DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024  # 16 MiB
DEFAULT_INVOKE_TIMEOUT_SEC = 60.0
DEFAULT_SESSION_START_TIMEOUT_SEC = 60.0
DEFAULT_SESSION_STOP_TIMEOUT_SEC = 30.0


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class TransportTimeout(RuntimeError):
    """Subprocess didn't exit within the wall-clock budget."""


class TransportOutputOverflow(RuntimeError):
    """Subprocess emitted more bytes than the configured cap."""


@dataclass
class CappedResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def run_capped(
    argv: list[str],
    *,
    input_bytes: bytes | None,
    timeout: float,
    max_output_bytes: int,
) -> CappedResult:
    """Run ``argv`` with capped output and wall-clock timeout.

    ``input_bytes`` is written to the child's stdin then the pipe closes.
    Each of stdout and stderr is independently capped at ``max_output_bytes``.
    Exceeding either cap kills the child and raises
    :class:`TransportOutputOverflow`.

    Returns ``CappedResult`` (no merging — stdout / stderr stay separate).
    """
    # Start the child in its own process group so we can kill the whole
    # tree on timeout / overflow. Otherwise a child like `bash` that
    # spawned its own subprocess (e.g. `sleep`) would have those orphans
    # keep our pipes open after we kill the bash parent.
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    def kill_process_group() -> None:
        try:
            os.killpg(proc.pid, 9)  # SIGKILL the whole group
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    overflow: list[str] = []  # Stream name(s) that exceeded the cap.
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    def reader(stream, chunks: list[bytes], name: str) -> None:
        total = 0
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                total += len(chunk)
                if total > max_output_bytes:
                    overflow.append(name)
                    kill_process_group()
                    return
                chunks.append(chunk)
        finally:
            try:
                stream.close()
            except OSError:
                pass

    t_out = threading.Thread(target=reader, args=(proc.stdout, stdout_chunks, "stdout"))
    t_err = threading.Thread(target=reader, args=(proc.stderr, stderr_chunks, "stderr"))
    t_out.start()
    t_err.start()

    # Feed stdin then close. BrokenPipeError can happen if the child died
    # before reading; that's a normal failure mode.
    if input_bytes is not None and proc.stdin is not None:
        try:
            proc.stdin.write(input_bytes)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_process_group()
        # Drain the reader threads so we don't leak. Bounded by a short
        # post-kill wait — once the group is dead, the pipes EOF promptly.
        t_out.join(2.0)
        t_err.join(2.0)
        raise TransportTimeout(
            f"{argv[0] if argv else 'subprocess'} did not exit within {timeout}s"
        )

    t_out.join(2.0)
    t_err.join(2.0)

    if overflow:
        streams = ", ".join(sorted(set(overflow)))
        raise TransportOutputOverflow(
            f"{argv[0] if argv else 'subprocess'} exceeded {max_output_bytes} bytes on {streams}"
        )

    return CappedResult(
        returncode=proc.returncode,
        stdout=b"".join(stdout_chunks),
        stderr=b"".join(stderr_chunks),
    )
