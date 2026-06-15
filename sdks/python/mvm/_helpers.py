"""Typed `Sandbox` presets (Plan 125 Phase C).

Thin, opinionated helpers built entirely over the imperative `Sandbox`
surface (`exec` / `copy_in`) — no new transport or mechanism. `CodeSandbox`
is the code-runner preset; `BrowserSandbox` (image + CDP-port preset) lands
alongside in C2.
"""

from __future__ import annotations

import os
from typing import Any

from mvm._sandbox import Sandbox

__all__ = ["CodeError", "CodeSandbox"]


class CodeError(RuntimeError):
    """A `CodeSandbox.run` / `run_script` / `install_package` exited non-zero.

    Carries the captured `exit_code` / `stdout` / `stderr` so callers can
    inspect the failure without re-running."""

    def __init__(self, message: str, *, exit_code: int, stdout: str, stderr: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


# Per-language runner: (interpreter, inline-eval flag, package-install argv).
_RUNNERS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "python": ("python", "-c", ("pip", "install")),
    "node": ("node", "-e", ("npm", "install")),
}


def _runner_for(image: str) -> str:
    """Pick the language runner from an image string. `node*` → node;
    everything else defaults to python (the common code-runner case)."""
    return "node" if "node" in image.lower() else "python"


class CodeSandbox:
    """A `Sandbox` preset for running code snippets in a language-runner
    image. Live-tier (the underlying `Sandbox.exec` is dev-only).

    Example::

        with mvm.CodeSandbox(image="python:slim") as cs:
            assert cs.run("print(2 + 2)").strip() == "4"
    """

    def __init__(
        self,
        image: str = "python:slim",
        *,
        workload_id: str | None = None,
        **create_kwargs: Any,
    ) -> None:
        self._lang = _runner_for(image)
        self._sandbox = Sandbox.create(
            image=image, workload_id=workload_id, **create_kwargs
        )

    @property
    def sandbox(self) -> Sandbox:
        """The underlying `Sandbox` for direct access (`copy_in`, `forward`, …)."""
        return self._sandbox

    def run(self, code: str) -> str:
        """Run `code` inline (`<interp> -c/-e <code>`) and return its stdout.
        Raises :class:`CodeError` on a non-zero exit."""
        interp, flag, _ = _RUNNERS[self._lang]
        return self._checked(self._sandbox.exec(interp, flag, code))

    def run_script(self, host_path: str) -> str:
        """Copy a host script into the sandbox and run it with the language
        interpreter; returns its stdout. Raises :class:`CodeError` on a
        non-zero exit."""
        interp, _, _ = _RUNNERS[self._lang]
        guest_path = f"/tmp/{os.path.basename(host_path)}"
        self._sandbox.copy_in(host_path, guest_path)
        return self._checked(self._sandbox.exec(interp, guest_path))

    def install_package(self, package: str) -> None:
        """Install a package with the language's package manager
        (`pip install` / `npm install`). Raises :class:`CodeError` on
        failure."""
        cmd = _RUNNERS[self._lang][2]
        self._checked(self._sandbox.exec(*cmd, package))

    def kill(self) -> None:
        self._sandbox.kill()

    def __enter__(self) -> "CodeSandbox":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.kill()

    @staticmethod
    def _checked(result: Any) -> str:
        if result.exit_code != 0:
            raise CodeError(
                f"code runner exited {result.exit_code}",
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        return result.stdout
