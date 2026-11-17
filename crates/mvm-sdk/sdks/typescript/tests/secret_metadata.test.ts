import { afterEach, expect, it } from "vitest";
import { secrets } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";
import { MachineBackendError } from "../src/_errors/types.js";

afterEach(() => setInvokeForTesting(null));

it("returns metadata or null through the in-process host call", () => {
  const oldPath = process.env.PATH;
  process.env.PATH = "";
  try {
    const calls: unknown[] = [];
    const replies = [
      { tenant: "local", name: "sample", binding: null, referenced_by: ["machine"] },
      null,
    ];
    setInvokeForTesting((method, body) => {
      calls.push([method, JSON.parse(body.toString("utf8"))]);
      return [0, Buffer.from(JSON.stringify(replies.shift()))];
    });
    expect(secrets.get("sample")).toMatchObject({ name: "sample", referenced_by: ["machine"] });
    expect(secrets.get("missing", "other")).toBeNull();
    expect(calls).toEqual([
      ["secret.get", { tenant: "local", name: "sample" }],
      ["secret.get", { tenant: "other", name: "missing" }],
    ]);
  } finally {
    if (oldPath === undefined) delete process.env.PATH;
    else process.env.PATH = oldPath;
  }
});

it("keeps storage errors distinct from absence", () => {
  setInvokeForTesting(() => [3, Buffer.from(JSON.stringify({
    code: "BACKEND_ERROR", message: "host-local operation failed", retryable: false,
  }))]);
  expect(() => secrets.get("sample")).toThrow(MachineBackendError);
});
