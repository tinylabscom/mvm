"""In-guest witness for `host.cell.v1`.

Runs inside a booted workload. Neither the SDK nor the host-services library
exports the cell service, so this speaks the broker's own framing: a 4-byte
big-endian length and a JSON `ServiceCall`, over AF_VSOCK to the host on the
broker port, one call per connection. That is the path the library takes, so
the witness covers guest -> vsock -> broker -> epoch gate -> cell store.

`writer`: write the next version and read it back, see a repeated version
refused, then keep writing higher versions until the host fences this epoch.
Prints `CELL-WRITER-FENCED last=<version>`.

`reader`: read the value the writer left, see a write refused because this
unit only reads the cell. Prints `CELL-READER-OK version=<version>`.

Any unexpected answer raises, so the run exits nonzero with the reason.
"""

import base64
import json
import socket
import struct
import sys
import time

HOST_CID = 2
BROKER_PORT = 5300
CELL = "setpoint"
FENCE_DEADLINE_SECS = 120


class Refused(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("broker closed the connection")
        data += chunk
    return data


def call(verb, payload):
    body = json.dumps({
        "service": "host.cell.v1",
        "verb": verb,
        "correlation_id": "cell-probe",
        "payload": payload,
    }).encode()
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((HOST_CID, BROKER_PORT))
        sock.sendall(struct.pack(">I", len(body)) + body)
        (length,) = struct.unpack(">I", recv_exact(sock, 4))
        reply = json.loads(recv_exact(sock, length))
    finally:
        sock.close()
    if reply["kind"] == "err":
        raise Refused(reply["code"], reply["message"])
    return reply["payload"]


def value_of(version):
    return f"v{version}".encode()


def write(version):
    payload = {"cell": CELL, "version": version,
               "value": base64.b64encode(value_of(version)).decode()}
    return call("write", payload)


def read():
    got = call("read", {"cell": CELL})
    return got["version"], base64.b64decode(got["value"])


def expect_refused(code, op):
    try:
        op()
    except Refused as refused:
        if refused.code != code:
            raise
        return
    raise AssertionError(f"expected a {code} refusal")


def writer():
    # A cell outlives every epoch, so start above whatever an earlier run left.
    version = read()[0] + 1
    assert write(version) == {"version": version}
    assert read() == (version, value_of(version)), read()
    expect_refused("bad_request", lambda: write(version))

    deadline = time.monotonic() + FENCE_DEADLINE_SECS
    while time.monotonic() < deadline:
        try:
            write(version + 1)
        except Refused as refused:
            if refused.code != "session_revoked":
                raise
            # A fenced epoch is refused for reads as well.
            expect_refused("session_revoked", read)
            print(f"CELL-WRITER-FENCED last={version}", flush=True)
            return 0
        version += 1
        print(f"CELL-WRITER-WROTE version={version}", flush=True)
        time.sleep(0.2)
    raise AssertionError(f"still writing at version {version}: the epoch was never fenced")


def reader():
    version, value = read()
    assert version >= 2, f"the reader sees version {version}, not the writer's writes"
    assert value == value_of(version), (version, value)
    expect_refused("capability_denied", lambda: write(version + 1))
    print(f"CELL-READER-OK version={version}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit({"writer": writer, "reader": reader}[sys.argv[1]]())
