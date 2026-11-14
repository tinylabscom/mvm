"""Baked guest entrypoint for the Firecracker local-durable mailbox witness."""

import base64
import json
import os
import socket
import struct
import sys
import time


def wait_for(action, description, seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = action()
            if result is not None:
                return result
        except (FileNotFoundError, ConnectionRefusedError, TimeoutError, OSError):
            pass
        time.sleep(0.5)
    raise RuntimeError(f"timed out waiting for {description}")


def request(operation):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(15)
        stream.connect("/run/mvm/mailbox/receive.sock")
        body = b"MVMR\x01" + json.dumps(
            {"version": 1, "value": operation}, separators=(",", ":")
        ).encode()
        stream.sendall(struct.pack(">I", len(body)) + body)
        length = struct.unpack(">I", read_exact(stream, 4))[0]
        if not 5 <= length <= 65536:
            raise RuntimeError("invalid reader reply size")
        reply = read_exact(stream, length)
        if not reply.startswith(b"MVMR\x01"):
            raise RuntimeError("invalid reader reply discriminator")
        frame = json.loads(reply[5:])
        if frame["version"] != 1:
            raise RuntimeError("invalid reader reply version")
        return frame["value"]


def read_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise RuntimeError("reader closed before a complete reply")
        result.extend(chunk)
    return bytes(result)


def main():
    outbox = "/run/mvm/mailbox/outbox-local"
    message_id = bytes.fromhex("01" * 32)
    payload = b"booted-local-durable-witness"

    def stage():
        directory = os.path.dirname(outbox)
        if not os.path.isdir(directory):
            return None
        temporary = os.path.join(directory, f".local-witness-{os.getpid()}")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(bytes(32) + message_id + payload)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, outbox)
        return True

    wait_for(stage, "guest mailbox outbox")
    print("mailbox-local-pending", flush=True)
    try:
        wait_for(
            lambda: True if not os.path.exists(outbox) else None,
            "signed V2 receipt",
            seconds=45,
        )
    except RuntimeError:
        with open("/proc/cmdline", encoding="utf-8") as cmdline:
            asserted = cmdline.read().split().count("mvm.mailbox=1") == 1
        print(
            f"mailbox-local-diagnostic: token={asserted} "
            f"reader_socket={os.path.exists('/run/mvm/mailbox/receive.sock')} "
            f"pending={os.path.exists(outbox)}",
            file=sys.stderr,
        )
        raise
    print("mailbox-local-receipt-verified", flush=True)

    def receive():
        result = request({"operation": "receive"})
        if result["outcome"] == "empty":
            return None
        if result["outcome"] == "refused" and result["reason"] == "Unavailable":
            return None
        if result["outcome"] != "delivery":
            raise RuntimeError(f"reader refused delivery: {result}")
        if base64.b64decode(result["payload"], validate=True) != payload:
            raise RuntimeError("reader delivered the wrong plaintext")
        return result["lease"]

    lease = wait_for(receive, "boot-bound delivery")
    reply = request({"operation": "ack", "lease": lease})
    if reply["outcome"] != "acknowledged" or reply["ack"]["ack"]["lease"] != lease:
        raise RuntimeError("signed ACK was not committed for the leased message")
    print("mailbox-local-ack-committed", flush=True)
    if request({"operation": "receive"})["outcome"] != "empty":
        raise RuntimeError("acknowledged delivery was replayed")


if __name__ == "__main__":
    main()
