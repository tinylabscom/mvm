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

__all__ = ["BrowserSandbox", "CodeError", "CodeSandbox"]


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


# Browser → (image, default CDP/remote-debugging port). Chromium-family
# browsers expose the Chrome DevTools Protocol on 9222.
_BROWSERS: dict[str, tuple[str, int]] = {
    "chromium": ("chromium", 9222),
    "chrome": ("chrome", 9222),
}


class BrowserSandbox:
    """A `Sandbox` preset for a headless browser: a baked browser image with
    its CDP port forwarded to the host. Image + port preset only — no new
    mechanism (the forward is `Sandbox.forward`, the protocol is the
    browser's own CDP).

    `endpoint()` returns the host-side CDP HTTP base; pass it to a CDP client
    (Playwright/Puppeteer `connectOverCDP` / `browserURL`), which discovers
    the per-session WebSocket URL from `/json/version`.

    Example::

        with mvm.BrowserSandbox("chromium") as bs:
            page = await playwright.chromium.connect_over_cdp(bs.endpoint())
    """

    def __init__(
        self,
        browser: str = "chromium",
        *,
        host_port: int | None = None,
        workload_id: str | None = None,
        **create_kwargs: Any,
    ) -> None:
        if browser not in _BROWSERS:
            raise ValueError(
                f"unknown browser {browser!r}; supported: {sorted(_BROWSERS)}"
            )
        image, cdp_port = _BROWSERS[browser]
        self._cdp_port = cdp_port
        self._host_port = host_port if host_port is not None else cdp_port
        self._sandbox = Sandbox.create(
            image=image, workload_id=workload_id, **create_kwargs
        )
        self._sandbox.forward(self._host_port, cdp_port)

    @property
    def sandbox(self) -> Sandbox:
        """The underlying `Sandbox` for direct access."""
        return self._sandbox

    def endpoint(self) -> str:
        """Host-side CDP HTTP endpoint (e.g. ``http://localhost:9222``)."""
        return f"http://localhost:{self._host_port}"

    def kill(self) -> None:
        self._sandbox.kill()

    def __enter__(self) -> "BrowserSandbox":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.kill()
