"""Thin in-guest transport to the host-services broker over vsock.

This is the one hand-written piece of the host-services SDK — the codegen
emits the wire *types* (``mvm._broker.services``), never a client, so the
socket + framing glue lives here. A workload running inside the microVM calls
``mvm.audit`` / ``mvm.host``, which build a ``ServiceCall`` and hand it to
[`call`]; that opens an ``AF_VSOCK`` stream to the host broker
(``HOST_CID``:``BROKER_PORT``), writes a 4-byte-big-endian-length-prefixed JSON
frame, and reads the framed ``ServiceResponse`` back — the exact wire the Rust
``mvm-guest::broker_client`` speaks.

Advisory only, like the Rust client: it holds no key and the call carries a bare
``ServiceCall``; the host derives identity from the connection and enforces the
``ExecutionPlan.services`` binding. ``AF_VSOCK`` exists only inside a Linux
guest, so it's resolved lazily — host-side imports never touch it, and tests
inject a socket pair via ``connect``.
"""

from __future__ import annotations

import json
import socket
import struct
from itertools import count
from typing import Any, Callable, Optional

# `connect_host_vsock` in the Rust guest: AF_VSOCK to the host.
BROKER_PORT = 5300
HOST_CID = 2  # VMADDR_CID_HOST
# Mirror the guest read cap so a bogus length prefix can't force a huge alloc.
_MAX_FRAME_BYTES = 256 * 1024
_DEFAULT_TIMEOUT_SECS = 5.0

# A connection factory the caller can override in tests (returns a connected
# stream socket speaking the framed protocol). Default opens the real vsock.
Connect = Callable[[], socket.socket]

_corr = count()


class BrokerError(Exception):
    """Base for any host-services broker failure."""


class BrokerServiceError(BrokerError):
    """The host answered ``ServiceResponse::Err`` — a typed broker refusal.

    ``code`` is the stable wire vocabulary (``not_bound``, ``rate_limit_exceeded``,
    …) the caller branches on; ``message`` is host-authored.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"broker service error [{code}]: {message}")


class BrokerTransportError(BrokerError):
    """Connect, framing, or (de)serialization failure on the vsock path."""


def _connect_vsock(timeout_secs: float) -> socket.socket:
    af_vsock = getattr(socket, "AF_VSOCK", None)
    if af_vsock is None:
        raise BrokerTransportError(
            "AF_VSOCK is unavailable — the host-services SDK runs inside a "
            "microVM guest (Linux); there is no host broker to dial here"
        )
    sock = socket.socket(af_vsock, socket.SOCK_STREAM)
    sock.settimeout(timeout_secs)
    try:
        sock.connect((HOST_CID, BROKER_PORT))
    except OSError as e:
        sock.close()
        raise BrokerTransportError(f"vsock connect to broker failed: {e}") from e
    return sock


def _send_frame(sock: socket.socket, obj: Any) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(body)) + body)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise BrokerTransportError("broker closed the connection mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def _recv_frame(sock: socket.socket) -> Any:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > _MAX_FRAME_BYTES:
        raise BrokerTransportError(
            f"broker frame {length} bytes exceeds cap {_MAX_FRAME_BYTES}"
        )
    try:
        return json.loads(_recv_exact(sock, length))
    except json.JSONDecodeError as e:
        raise BrokerTransportError(f"malformed broker response: {e}") from e


def call(
    service: str,
    verb: str,
    payload: Any,
    *,
    timeout_secs: float = _DEFAULT_TIMEOUT_SECS,
    connect: Optional[Connect] = None,
) -> Any:
    """Exchange one ``ServiceCall`` with the broker and return the ``Ok`` payload.

    Raises :class:`BrokerServiceError` on a typed ``Err`` reply and
    :class:`BrokerTransportError` on any socket/framing failure. ``connect``
    overrides the default vsock dialer (tests inject a socket pair).
    """
    opener = connect or (lambda: _connect_vsock(timeout_secs))
    sock = opener()
    try:
        # `correlation_id` is a guest-side placeholder; the supervisor reassigns
        # the authoritative id at ingress, so a monotonic counter suffices.
        _send_frame(
            sock,
            {
                "service": service,
                "verb": verb,
                "correlation_id": f"wl-{next(_corr)}",
                "payload": payload,
            },
        )
        resp = _recv_frame(sock)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not isinstance(resp, dict):
        raise BrokerTransportError(f"broker response was not an object: {resp!r}")
    kind = resp.get("kind")
    if kind == "ok":
        return resp.get("payload")
    if kind == "err":
        raise BrokerServiceError(str(resp.get("code")), str(resp.get("message")))
    raise BrokerTransportError(f"broker response missing kind: {resp!r}")
