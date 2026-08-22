"""Typed `Sandbox` presets (Plan 125 Phase C).

Thin, opinionated helpers built entirely over the imperative `Sandbox`
surface (`exec` / `copy_in`) — no new transport or mechanism. `CodeSandbox`
is the code-runner preset; `BrowserSandbox` (image + CDP-port preset) lands
alongside in C2.
"""

from __future__ import annotations

import os
import json
import time
import urllib.request
from dataclasses import dataclass
from typing import Any

from mvm._sandbox import Sandbox, _encode_network

__all__ = [
    "BrowserReadyError",
    "BrowserSandbox",
    "CodeError",
    "CodeSandbox",
    "OBSCURA_IMAGE",
]


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


OBSCURA_IMAGE = (
    "docker.io/h4ckf0r0day/obscura@"
    "sha256:78c99ac89d010d444d96d85c183a2db912c41f807b7807d697df98ab7e4bd3c2"
)
_MVM_EGRESS_PROXY = "http://127.0.0.1:1080"


class BrowserReadyError(RuntimeError):
    """The browser did not expose a valid CDP version endpoint in time."""


@dataclass(frozen=True)
class _BrowserPreset:
    source_kind: str
    source: str
    cdp_port: int
    command: tuple[str, ...] = ()


_BROWSERS: dict[str, _BrowserPreset] = {
    "chromium": _BrowserPreset("manifest", "chromium", 9222),
    "chrome": _BrowserPreset("manifest", "chrome", 9222),
    "obscura": _BrowserPreset(
        "image",
        OBSCURA_IMAGE,
        9222,
        (
            "/obscura",
            "--proxy",
            _MVM_EGRESS_PROXY,
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "9222",
        ),
    ),
}


class BrowserSandbox:
    """A `Sandbox` preset for a headless browser: a baked browser image with
    its CDP port declared as signed ingress before boot. Image + port preset
    only — no new mechanism (the protocol is the browser's own CDP).

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
        preset = _BROWSERS[browser]
        caller_command = create_kwargs.pop("command", None)
        if preset.command and caller_command is not None:
            raise ValueError("the obscura provider does not allow command overrides")
        command = list(preset.command) if preset.command else caller_command
        self._cdp_port = preset.cdp_port
        self._host_port = host_port if host_port is not None else preset.cdp_port
        source_kwargs = (
            {"template": preset.source}
            if preset.source_kind == "manifest"
            else {"image": preset.source}
        )
        network = _encode_network(create_kwargs.pop("network", None)) or {
            "mode": "none",
            "ports": [],
        }
        ports = list(network.get("ports", []))
        mapping_id = max(
            (int(port["mapping_id"]) for port in ports),
            default=0,
        ) + 1
        ports.append(
            {
                "mapping_id": mapping_id,
                "proto": "tcp",
                "host_addr": "127.0.0.1",
                "host": self._host_port,
                "guest_addr": "127.0.0.1",
                "guest": preset.cdp_port,
                "transform": "opaque",
            }
        )
        network["ports"] = ports
        self._sandbox = Sandbox.create(
            workload_id=workload_id,
            command=command,
            network=network,
            **source_kwargs,
            **create_kwargs,
        )

    @property
    def sandbox(self) -> Sandbox:
        """The underlying `Sandbox` for direct access."""
        return self._sandbox

    def endpoint(self) -> str:
        """Host-side CDP HTTP endpoint (e.g. ``http://localhost:9222``)."""
        return f"http://localhost:{self._host_port}"

    def wait_until_ready(
        self, *, timeout: float = 10.0, retry_interval: float = 0.1
    ) -> str:
        """Wait for a bounded CDP `/json/version` response and return its
        WebSocket debugger URL. Failure tears down the sandbox and forwarder."""
        if timeout <= 0 or retry_interval <= 0:
            raise ValueError("timeout and retry_interval must be positive")
        endpoint = f"http://127.0.0.1:{self._host_port}/json/version"
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                remaining = max(deadline - time.monotonic(), 0.001)
                with urllib.request.urlopen(endpoint, timeout=min(remaining, 1.0)) as response:
                    payload = response.read(65537)
                if len(payload) > 65536:
                    raise ValueError("CDP version response exceeds 64 KiB")
                parsed = json.loads(payload)
                websocket = parsed.get("webSocketDebuggerUrl") if isinstance(parsed, dict) else None
                if not isinstance(websocket, str) or not websocket:
                    raise ValueError("CDP response lacks webSocketDebuggerUrl")
                return websocket
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(retry_interval, remaining))
        self.kill()
        raise BrowserReadyError(
            f"browser CDP endpoint {endpoint} was not ready within {timeout:g}s"
        ) from last_error

    def kill(self) -> None:
        self._sandbox.kill()

    def __enter__(self) -> "BrowserSandbox":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.kill()
