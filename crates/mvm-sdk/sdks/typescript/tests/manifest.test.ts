import { afterEach, describe, expect, it } from "vitest";

import { manifest } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";
import { HostLibraryError, MachineBackendError } from "../src/_errors/types.js";

afterEach(() => setInvokeForTesting(null));

describe("manifest inspection", () => {
  const verified = { slot_hash: "abc", manifest_path: "/build/manifest.json" };
  const cases = [
    {
      operation: () => manifest.list(),
      method: "manifest.list",
      request: { orphans: false, tags: [] },
      reply: [],
    },
    {
      operation: () => manifest.list({ orphans: true, tags: ["prod", "web"] }),
      method: "manifest.list",
      request: { orphans: true, tags: ["prod", "web"] },
      reply: [{ ...verified, name: null, updated_at: "2026-01-01T00:00:00Z",
        orphan: true, tags: ["prod", "web"] }],
    },
    {
      operation: () => manifest.info(),
      method: "manifest.info",
      request: { path: null },
      reply: { slot_hash: "abc", persisted: { future: [null, { x: 1 }] }, snapshot: null },
    },
    {
      operation: () => manifest.info("/build/manifest.json"),
      method: "manifest.info",
      request: { path: "/build/manifest.json" },
      reply: { slot_hash: "abc", persisted: { version: 2 },
        snapshot: { unknown: { nested: [true, 4] } } },
    },
    {
      operation: () => manifest.verify(),
      method: "manifest.verify",
      request: { path: null, revision: null, check_signature: false },
      reply: verified,
    },
    {
      operation: () => manifest.verify("/build/manifest.json", {
        revision: "rev", checkSignature: true,
      }),
      method: "manifest.verify",
      request: { path: "/build/manifest.json", revision: "rev", check_signature: true },
      reply: verified,
    },
  ];

  it.each(cases)("marshals $method and preserves its reply", ({ operation, method, request, reply }) => {
    const calls: unknown[] = [];
    setInvokeForTesting((name, body) => {
      calls.push({ method: name, request: JSON.parse(body.toString("utf8")) });
      return [0, Buffer.from(JSON.stringify(reply))];
    });
    expect(operation()).toEqual(reply);
    expect(calls).toEqual([{ method, request }]);
  });

  it.each([
    {
      operation: () => manifest.verify(null, { checkSignature: true }),
      message: "manifest signature checking is unsupported",
    },
    {
      operation: () => manifest.info("invalid.json"),
      message: "invalid manifest: missing slot_hash",
    },
    {
      operation: () => manifest.list(),
      message: "invalid manifest: malformed JSON",
    },
  ])("preserves backend failure: $message", ({ operation, message }) => {
    setInvokeForTesting(() => [1, Buffer.from(JSON.stringify({
      code: "BACKEND_ERROR", message, retryable: false,
    }))]);
    let failure: unknown;
    try {
      operation();
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(HostLibraryError);
    expect(failure).toBeInstanceOf(MachineBackendError);
    expect((failure as Error).message).toBe(message);
  });
});
