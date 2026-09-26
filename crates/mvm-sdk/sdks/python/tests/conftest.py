"""Shared fixtures: a stand-in for the host library's C call.

`mvm._hostlib._invoke(method, request_json) -> (status, body)` is the one
place the SDK touches the library. Replacing it drives every facade through
its real request marshalling and reply parsing, with no library, no VM, and
no process.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any

import pytest

from mvm import _hostlib

# Methods whose success reply carries nothing a facade reads, so a test need
# not script them to exercise a path that calls them.
_DEFAULT_REPLIES: dict[str, Any] = {
    "machine.stop": {},
    "machine.rm": {},
    "guest.proc.signal": {},
    "guest.proc.kill": {},
    "guest.proc.stdin": {"accepted": 0},
    "guest.proc.stream.close": {},
    "guest.fs.write": {"bytes_written": 0},
    "guest.fs.mkdir": {},
    "guest.fs.remove": {"entries_removed": 1},
    "guest.fs.rename": {},
    "guest.cp": {},
}


class HostlibRecorder:
    """Records each call and answers from a per-method script.

    ``reply`` queues a success body; ``fail`` queues an error body shaped the
    way the library writes one. A method with nothing queued falls back to
    its default above, and a method with no default fails the test, so an
    unexpected call cannot pass silently.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self._queued: dict[str, deque[tuple[int, bytes]]] = defaultdict(deque)

    def reply(self, method: str, body: Any) -> "HostlibRecorder":
        self._queued[method].append((0, json.dumps(body).encode()))
        return self

    def fail(
        self, method: str, code: str, message: str = "refused", *, retryable: bool = False
    ) -> "HostlibRecorder":
        body = {"code": code, "message": message, "retryable": retryable}
        self._queued[method].append((1, json.dumps(body).encode()))
        return self

    def __call__(self, method: str, request_json: bytes) -> tuple[int, bytes]:
        request = json.loads(request_json) if request_json else None
        self.calls.append((method, request))
        if self._queued[method]:
            return self._queued[method].popleft()
        if method in _DEFAULT_REPLIES:
            return 0, json.dumps(_DEFAULT_REPLIES[method]).encode()
        raise AssertionError(f"unscripted host library call {method} {request!r}")

    @property
    def methods(self) -> list[str]:
        return [method for method, _ in self.calls]

    def requests(self, method: str) -> list[Any]:
        return [request for name, request in self.calls if name == method]

    def request(self, method: str) -> Any:
        """The one request made to ``method``; fails if there were more."""
        found = self.requests(method)
        assert len(found) == 1, f"expected one {method} call, got {found}"
        return found[0]


@pytest.fixture
def hostlib(monkeypatch: pytest.MonkeyPatch) -> HostlibRecorder:
    recorder = HostlibRecorder()
    monkeypatch.setattr(_hostlib, "_invoke", recorder)
    return recorder
