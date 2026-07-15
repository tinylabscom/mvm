/**
 * In-guest host-services veneer (`mvm.audit` / `mvm.host`).
 *
 * Exercises the marshalling + status→error mapping over an injected C-call seam
 * (`opts.invoke`), so no real `.so` or vsock broker is needed — mirroring the
 * Rust `dispatch_on` socket-pair tests one layer down. The actual koffi load +
 * broker dial is the live-VM E2E (b4).
 */

import { describe, expect, it } from "vitest";

import * as audit from "../src/audit.js";
import * as host from "../src/host.js";
import {
  BadRequestError,
  HostServiceError,
  type InvokeFn,
  NotBoundError,
  RateLimitedError,
  ServiceError,
  TransportError,
  UnavailableError,
  VerbNotImplementedError,
} from "../src/_hostsvc.js";

/** A fake C-call: records each call and returns a settable `[status, body]`. */
function fakeInvoke(status: number, body: unknown) {
  const calls: Array<{ method: string; request: unknown; timeoutSecs: number }> = [];
  const invoke: InvokeFn = (method, requestJson, timeoutSecs) => {
    calls.push({ method, request: JSON.parse(requestJson.toString("utf8")), timeoutSecs });
    return [status, Buffer.from(JSON.stringify(body), "utf8")];
  };
  return { invoke, calls };
}

describe("mvm.audit.emit", () => {
  it("sends host.audit.emit with the record and returns the chain head", () => {
    const { invoke, calls } = fakeInvoke(0, { chain_head: "head-001" });
    const head = audit.emit({ action: "login", user: "alice" }, "2026-06-16T00:00:00Z", {
      invoke,
    });
    expect(head).toBe("head-001");
    expect(calls[0].method).toBe("host.audit.emit");
    expect(calls[0].request).toEqual({
      ts: "2026-06-16T00:00:00Z",
      fields: { action: "login", user: "alice" },
    });
    // Claim 8: the workload can never express a category.
    expect((calls[0].request as Record<string, unknown>).category).toBeUndefined();
  });

  it("defaults ts to an RFC 3339 Z string", () => {
    const { invoke, calls } = fakeInvoke(0, { chain_head: "h" });
    audit.emit({ x: 1 }, undefined, { invoke });
    const ts = (calls[0].request as { ts: string }).ts;
    expect(ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });

  it("maps a bad-request status onto a typed error", () => {
    const { invoke } = fakeInvoke(1, {
      code: "bad_request",
      message: "record 5121 bytes exceeds cap 4096",
    });
    expect(() => audit.emit({ x: 1 }, undefined, { invoke })).toThrow(BadRequestError);
    try {
      audit.emit({ x: 1 }, undefined, { invoke });
    } catch (e) {
      expect(e).toBeInstanceOf(HostServiceError);
      expect((e as Error).message).toContain("exceeds cap");
    }
  });

  it("maps a rate-limit status onto a typed error", () => {
    const { invoke } = fakeInvoke(2, { code: "rate_limited", message: "rate" });
    expect(() => audit.emit({ x: 1 }, undefined, { invoke })).toThrow(RateLimitedError);
  });
});

describe("mvm.audit.emitBatch", () => {
  it("sends host.audit.emit_batch with stamped entries", () => {
    const { invoke, calls } = fakeInvoke(0, { chain_head: "hb", statuses: [] });
    const head = audit.emitBatch([{ a: 1 }, { b: 2 }], { invoke });
    expect(head).toBe("hb");
    expect(calls[0].method).toBe("host.audit.emit_batch");
    const req = calls[0].request as { entries: Array<{ ts: string; fields: unknown }> };
    expect(req.entries).toHaveLength(2);
    expect(req.entries[0].fields).toEqual({ a: 1 });
    expect(req.entries.every((e) => typeof e.ts === "string")).toBe(true);
  });
});

describe("mvm.host.time", () => {
  it("returns wall_ms over host.time.now with an empty body", () => {
    const { invoke, calls } = fakeInvoke(0, { wall_ms: 1_717_000_000_000 });
    expect(host.time({ invoke })).toBe(1_717_000_000_000);
    expect(calls[0].method).toBe("host.time.now");
    expect(calls[0].request).toEqual({});
  });

  it("maps not-bound onto a typed error", () => {
    const { invoke } = fakeInvoke(4, { code: "not_bound", message: "nb" });
    expect(() => host.time({ invoke })).toThrow(NotBoundError);
  });
});

describe("mvm.host.cost", () => {
  it("routes workload and tenant to distinct verbs", () => {
    const { invoke, calls } = fakeInvoke(0, { spent_micros_usd: 4_200_000 });
    expect(host.cost("workload", { invoke })).toBe(4_200_000);
    expect(calls[0].method).toBe("host.cost.workload");
    expect(host.cost("tenant", { invoke })).toBe(4_200_000);
    expect(calls[1].method).toBe("host.cost.tenant");
  });

  it("rejects an unknown scope before calling", () => {
    const { invoke, calls } = fakeInvoke(0, {});
    // @ts-expect-error — exercising the runtime guard on a bad scope.
    expect(() => host.cost("nope", { invoke })).toThrow(RangeError);
    expect(calls).toHaveLength(0);
  });

  it("maps tenant not-implemented onto a typed error", () => {
    const { invoke } = fakeInvoke(5, { code: "not_implemented", message: "ni" });
    expect(() => host.cost("tenant", { invoke })).toThrow(VerbNotImplementedError);
  });
});

describe("status mapping", () => {
  it("maps unavailable / service / transport onto typed errors", () => {
    for (const [status, ctor] of [
      [3, UnavailableError],
      [6, ServiceError],
      [7, TransportError],
    ] as const) {
      const { invoke } = fakeInvoke(status, { code: "x", message: "m" });
      expect(() => host.time({ invoke })).toThrow(ctor);
    }
  });
});
