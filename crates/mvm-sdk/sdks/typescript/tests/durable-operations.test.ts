import { afterEach, expect, it } from "vitest";
import { agentSessions, checkpoints, replay } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";
import { MachineBackendError } from "../src/_errors/types.js";

afterEach(() => setInvokeForTesting(null));
const execute = (request: Record<string, unknown>) => ({ intent: "execute", request });
const cases = [
  { operation: () => agentSessions.list(), method: "agent_sessions.list", request: {} },
  { operation: () => agentSessions.show("s"), method: "agent_sessions.show", request: { session_id: "s" } },
  { operation: () => agentSessions.open("s", { intent: "execute" }), method: "agent_sessions.open",
    request: execute({ session_id: "s", members: [], resume_point: null }) },
  { operation: () => agentSessions.park("s", { intent: "execute", reason: "operator", journalCursor: 7 }),
    method: "agent_sessions.park", request: execute({ session_id: "s", reason: "operator", journal_cursor: 7,
      approval_head: null, retain_for: null, expected_generation: null }) },
  { operation: () => agentSessions.renew("s", { intent: "execute", extendFor: "1h" }), method: "agent_sessions.renew",
    request: execute({ session_id: "s", extend_for: "1h", expected_deadline: null, expected_generation: null }) },
  { operation: () => agentSessions.resume("s", { intent: "execute", backend: "mock", image: "test",
    imageSha256: "digest", cpus: 1, memMib: 128, boot: false }), method: "agent_sessions.resume",
    request: execute({ session_id: "s", backend: "mock", image: "test", image_sha256: "digest", cpus: 1,
      mem_mib: 128, boot: false, kernel_sha256: null, kernel: null, approval_head: null, expected_generation: null }) },
  { operation: () => checkpoints.list(), method: "checkpoints.list", request: {} },
  { operation: () => checkpoints.info("c"), method: "checkpoints.info", request: { id: "c" } },
  { operation: () => checkpoints.diff("a", "b"), method: "checkpoints.diff", request: { a: "a", b: "b" } },
  { operation: () => checkpoints.verify("c"), method: "checkpoints.verify", request: { id: "c" } },
  { operation: () => checkpoints.timeline("c"), method: "checkpoints.timeline", request: { target: "c", kind: null } },
  { operation: () => checkpoints.remove("c", { intent: "execute" }), method: "checkpoints.remove", request: execute({ id: "c" }) },
  { operation: () => checkpoints.capture("vm", { intent: "execute", class: "fs_quick" }), method: "checkpoints.capture",
    request: execute({ name: "vm", class: "fs_quick", tag: null }) },
  { operation: () => checkpoints.restore("c", { intent: "execute", tenant: "t" }), method: "checkpoints.restore",
    request: execute({ id: "c", tenant: "t" }) },
  { operation: () => checkpoints.forkCheckpoint("c", { intent: "execute", tenant: "t", boot: false }), method: "checkpoints.fork",
    request: execute({ id: "c", tenant: "t", boot: false, new_id: null, hypervisor: "", cpus: null, memory: null }) },
  { operation: () => replay.runSession("s", { tenant: "t", timeoutSecs: 30 }), method: "replay.run_session",
    request: { selection: { session_id: "s", from: null, as_name: null }, tenant: "t", timeout_secs: 30, dry_run: true } },
  { operation: () => replay.runSession("s", { tenant: "t", timeoutSecs: 30, dryRun: false, fromCheckpoint: "c", asName: "child" }),
    method: "replay.run_session",
    request: { selection: { session_id: "s", from: "c", as_name: "child" }, tenant: "t", timeout_secs: 30, dry_run: false } },
];

it.each(cases)("marshals $method and preserves reports", ({ operation, method, request }) => {
  const report = { generation: 3, replayed: true, warnings: ["audit unavailable"],
    summary: { checkpoint: "c" }, execution: null, future: [null, true] };
  setInvokeForTesting((name, body) => {
    expect(name).toBe(method);
    expect(JSON.parse(body.toString("utf8"))).toEqual(request);
    return [0, Buffer.from(JSON.stringify(report))];
  });
  expect(operation()).toEqual(report);
});
it.each(cases)("preserves $method client errors", ({ operation }) => {
  setInvokeForTesting(() => [3, Buffer.from(JSON.stringify({
    code: "BACKEND_ERROR", message: "outer operation: tenant refused", retryable: false,
  }))]);
  expect(operation).toThrow(MachineBackendError);
  expect(operation).toThrow("outer operation: tenant refused");
});
it("does not expose privileged roots or incomplete time travel", () => {
  expect("at" in agentSessions).toBe(false);
  for (const name of ["revert", "rewind", "advance"]) expect(name in checkpoints).toBe(false);
});
