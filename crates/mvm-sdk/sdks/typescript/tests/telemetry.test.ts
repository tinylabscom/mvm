import { afterEach, expect, it, vi } from "vitest";
import childProcess from "node:child_process";
import { telemetry } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";
import { MachineNotFoundError, MachineSpecError } from "../src/_errors/types.js";

afterEach(() => { setInvokeForTesting(null); vi.restoreAllMocks(); });

it.each([
  { collection: "not_provisioned" },
  ...[{ kind: "connecting" }, { kind: "collecting", generation: 7 },
    { kind: "stopped" }, { kind: "degraded", code: "writer_failed" }].map((state) => ({
    collection: "provisioned", vm_name: "selected", state, shed: 0, records_bytes: 42,
  })),
  { collection: "provisioned", vm_name: "selected", state: { kind: "degraded", code: "writer_failed" },
    shed: 3, records_bytes: 1234, snapshot_age_ms: 42,
    losses: { queue_full: 1, cap_reached: 0, write_failed: 2, secret_withheld: 0 } },
])("preserves status without inferring health: $collection", (reply) => {
  setInvokeForTesting((method, body) => {
    expect(method).toBe("telemetry.status");
    expect(JSON.parse(body.toString("utf8"))).toEqual({ id: "selected" });
    return [0, Buffer.from(JSON.stringify(reply))];
  });
  expect(telemetry.status("selected")).toEqual(reply);
});

it("pages only on explicit calls, preserving identity, cursor and opaque records", () => {
  const first = { records: [{ received_at_ms: 123, record: { sequence: 1, future: [1] } }],
    next_cursor: { offset: 300 }, undecodable: 2, exhausted: false };
  const last = { records: [{ record: { sequence: 2 } }], next_cursor: { offset: 500 }, undecodable: 0, exhausted: true };
  const empty = { ...last, records: [] };
  const replies = [first, last, empty];
  const calls: unknown[] = [];
  setInvokeForTesting((method, body) => {
    calls.push([method, JSON.parse(body.toString("utf8"))]);
    return [0, Buffer.from(JSON.stringify(replies.shift()))];
  });
  expect(telemetry.records("selected", { limit: 0 })).toEqual(first);
  expect(telemetry.records("selected", { cursor: first.next_cursor, limit: 4096 })).toEqual(last);
  expect(telemetry.records("selected", { cursor: last.next_cursor })).toEqual(empty);
  expect(calls).toEqual([
    ["telemetry.records", { id: "selected", limit: 0 }],
    ["telemetry.records", { id: "selected", cursor: { offset: 300 }, limit: 4096 }],
    ["telemetry.records", { id: "selected", cursor: { offset: 500 } }],
  ]);
});

it("leaves default cursor and limit to the host", () => {
  setInvokeForTesting((method, body) => {
    expect(method).toBe("telemetry.records");
    expect(JSON.parse(body.toString("utf8"))).toEqual({ id: "selected" });
    return [0, Buffer.from('{"records":[],"next_cursor":{"offset":0},"undecodable":0,"exhausted":true}')];
  });
  expect(telemetry.records("selected").exhausted).toBe(true);
});

it.each([
  { method: "status" as const, code: "NOT_FOUND", errorType: MachineNotFoundError },
  { method: "records" as const, code: "INVALID_SPEC", errorType: MachineSpecError },
])("preserves $code without retry", ({ method, code, errorType }) => {
  let calls = 0;
  setInvokeForTesting(() => {
    calls++;
    return [1, Buffer.from(JSON.stringify({ code, message: "refused", retryable: false }))];
  });
  expect(() => telemetry[method]("selected")).toThrow(errorType);
  expect(calls).toBe(1);
});

it.each(["", null, 1, true])("refuses invalid identity %s", (id) => {
  setInvokeForTesting(() => { throw new Error("unexpected transport"); });
  expect(() => telemetry.status(id as string)).toThrow(/id/);
  expect(() => telemetry.records(id as string)).toThrow(/id/);
});

it.each([{}, { offset: -1 }, { offset: true }, { offset: 1.5 },
  { offset: Number.MAX_SAFE_INTEGER + 1 }, { offset: 0, generation: 1 }, "0",
])("refuses malformed or imprecise outgoing cursor", (cursor) => {
  setInvokeForTesting(() => { throw new Error("unexpected transport"); });
  expect(() => telemetry.records("selected", { cursor: cursor as telemetry.TelemetryCursor })).toThrow(/cursor/);
});

it.each([-1, true, 1.5, "2", Number.MAX_SAFE_INTEGER + 1])("refuses invalid limit %s", (limit) => {
  setInvokeForTesting(() => { throw new Error("unexpected transport"); });
  expect(() => telemetry.records("selected", { limit: limit as number })).toThrow(/limit/);
});

it.each(["null", "[]", "{}", '{"records":[]}',
  '{"records":[],"next_cursor":{"offset":9007199254740993},"undecodable":0,"exhausted":true}',
])("refuses malformed or unsafe received cursors before exposing a page", (reply) => {
  setInvokeForTesting(() => [0, Buffer.from(reply)]);
  expect(() => telemetry.records("selected")).toThrow(telemetry.TelemetryError);
});

it.each([
  {}, [], { collection: "unknown" },
  { collection: "provisioned", vm_name: "selected", state: { kind: "collecting" }, shed: 0, records_bytes: 0 },
  { collection: "provisioned", vm_name: "selected", state: { kind: "stopped" }, shed: true, records_bytes: 0 },
  { collection: "provisioned", vm_name: "selected", state: { kind: "stopped" }, shed: 0, records_bytes: 0, snapshot_age_ms: null },
])("refuses malformed status without reflecting its payload", (reply) => {
  setInvokeForTesting(() => [0, Buffer.from(JSON.stringify(reply))]);
  expect(() => telemetry.status("selected")).toThrow(
    "telemetry.status returned an invalid or unsafe status envelope",
  );
});

it("uses only the host transport without spawning a CLI", () => {
  for (const method of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"] as const) {
    vi.spyOn(childProcess, method).mockImplementation(() => { throw new Error("unexpected subprocess"); });
  }
  const calls: string[] = [];
  setInvokeForTesting((method) => {
    calls.push(method);
    const reply = method === "telemetry.status" ? { collection: "not_provisioned" }
      : { records: [], next_cursor: { offset: 0 }, undecodable: 0, exhausted: true };
    return [0, Buffer.from(JSON.stringify(reply))];
  });
  telemetry.status("selected");
  telemetry.records("selected");
  expect(calls).toEqual(["telemetry.status", "telemetry.records"]);
});

it("preserves additive reply fields without interpreting them", () => {
  const status = { collection: "not_provisioned", future: { enabled: false } };
  const page = { records: [{ record: { future: 1 }, extra: "retained" }],
    next_cursor: { offset: 0 }, undecodable: 0, exhausted: true, future: [1, 2] };
  setInvokeForTesting((method) => [
    0, Buffer.from(JSON.stringify(method === "telemetry.status" ? status : page)),
  ]);
  expect(telemetry.status("selected")).toEqual(status);
  expect(telemetry.records("selected")).toEqual(page);
});
