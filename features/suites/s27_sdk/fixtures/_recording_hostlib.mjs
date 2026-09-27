// In-process stand-in for the host library, shared by the TypeScript fixtures.
//
// Twin of `_recording_hostlib.py`: replaces the SDK's one C call with a
// recorder through the package's test seam. Each call is appended to
// `$MVM_BDD_CALL_LOG` as a `[method, request]` JSON line and answered from
// REPLIES, identically to the Python twin, so the two languages' traces can be
// compared. A method with no scripted reply gets an `INVALID_INPUT` error, so
// an unexpected call fails the fixture rather than passing quietly.
//
// `$MVM_BDD_BUILD_MODE` (`dev` or `prod`) is the posture the machine reports.
import { appendFileSync } from "node:fs";

import { setInvokeForTesting } from "../../../../crates/mvm-sdk/sdks/typescript/dist/_hostlib.js";

const VM_ID = "sdk-bdd-vm";
const BUILD_MODE = process.env.MVM_BDD_BUILD_MODE ?? "dev";
const b64 = (text) => Buffer.from(text, "utf8").toString("base64");

const REPLIES = {
  "machine.run": {
    machine: { id: VM_ID, name: VM_ID, status: "running" },
    plan_id: "plan-bdd",
    build_mode: BUILD_MODE,
  },
  "machine.inventory": [{ name: VM_ID, build_mode: BUILD_MODE }],
  "machine.stop": {},
  "guest.proc.start": { token: "ptok-bdd" },
  "guest.proc.stream.open": { stream: 1 },
  "guest.proc.stream.next": {
    events: [{ stream: "stdout", data_b64: b64("ok\n") }],
    done: true,
    outcome: { kind: "exited", code: 0 },
  },
  "guest.proc.stream.close": {},
  "guest.fs.write": { bytes_written: 5 },
  "guest.fs.read": { data_b64: b64("hello") },
  "guest.fs.list": {
    entries: [{ name: "hello.txt", kind: "file", size: 5 }],
    truncated: false,
  },
};

setInvokeForTesting((method, requestJson) => {
  const request = requestJson.length > 0 ? JSON.parse(requestJson.toString("utf8")) : null;
  appendFileSync(process.env.MVM_BDD_CALL_LOG, JSON.stringify([method, request]) + "\n");
  if (Object.hasOwn(REPLIES, method)) {
    return [0, Buffer.from(JSON.stringify(REPLIES[method]), "utf8")];
  }
  const body = { code: "INVALID_INPUT", message: `unscripted method ${method}`, retryable: false };
  return [8, Buffer.from(JSON.stringify(body), "utf8")];
});
