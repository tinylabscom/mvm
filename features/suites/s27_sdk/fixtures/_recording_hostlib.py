"""In-process stand-in for the host library, shared by the Python fixtures.

Replaces `mvm._hostlib._invoke`, the SDK's one C call, with a recorder: each
call is appended to `$MVM_BDD_CALL_LOG` as a `[method, request]` JSON line and
answered from `REPLIES`. The TypeScript twin, `_recording_hostlib.mjs`,
answers identically, so the two languages' traces can be compared. A method
with no scripted reply is answered with an `INVALID_INPUT` error, so an
unexpected call fails the fixture rather than passing quietly.

`$MVM_BDD_BUILD_MODE` (`dev` or `prod`) is the posture the machine reports.
"""

import base64
import json
import os

from mvm import _hostlib

VM_ID = "sdk-bdd-vm"
BUILD_MODE = os.environ.get("MVM_BDD_BUILD_MODE", "dev")


def _b64(text: str) -> str:
    return base64.standard_b64encode(text.encode()).decode("ascii")


REPLIES = {
    "machine.run": {
        "machine": {"id": VM_ID, "name": VM_ID, "status": "running"},
        "plan_id": "plan-bdd",
        "build_mode": BUILD_MODE,
    },
    "machine.inventory": [{"name": VM_ID, "build_mode": BUILD_MODE}],
    "machine.stop": {},
    "guest.proc.start": {"token": "ptok-bdd"},
    "guest.proc.stream.open": {"stream": 1},
    "guest.proc.stream.next": {
        "events": [{"stream": "stdout", "data_b64": _b64("ok\n")}],
        "done": True,
        "outcome": {"kind": "exited", "code": 0},
    },
    "guest.proc.stream.close": {},
    "guest.fs.write": {"bytes_written": 5},
    "guest.fs.read": {"data_b64": _b64("hello")},
    "guest.fs.list": {
        "entries": [{"name": "hello.txt", "kind": "file", "size": 5}],
        "truncated": False,
    },
}


def _record(method, request_json):
    request = json.loads(request_json) if request_json else None
    with open(os.environ["MVM_BDD_CALL_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps([method, request], sort_keys=True) + "\n")
    if method in REPLIES:
        return 0, json.dumps(REPLIES[method]).encode()
    body = {"code": "INVALID_INPUT", "message": f"unscripted method {method}", "retryable": False}
    return 8, json.dumps(body).encode()


_hostlib._invoke = _record
