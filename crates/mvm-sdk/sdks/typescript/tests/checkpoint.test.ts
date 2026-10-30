import { afterEach, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import { checkpoint } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";
import { MachineBackendError, MachineConflictError, MachineSpecError } from "../src/_errors/types.js";

afterEach(() => setInvokeForTesting(null));

const catalog: unknown = JSON.parse(readFileSync(
  new URL("../../../../../tests/fixtures/checkpoint/catalog.json", import.meta.url), "utf8",
));

it.each([[], catalog].map((reply) => ({ reply })))("preserves complete and legacy catalog metadata", ({ reply }) => {
  const calls: unknown[] = [];
  setInvokeForTesting((method, body) => {
    calls.push([method, JSON.parse(body.toString("utf8"))]);
    return [0, Buffer.from(JSON.stringify(reply))];
  });
  expect(checkpoint.list()).toEqual(reply);
  expect(calls).toEqual([["checkpoint.list", {}]]);
});

it("preserves a nonretryable host refusal", () => {
  setInvokeForTesting(() => [1, Buffer.from(JSON.stringify({
    code: "BACKEND_ERROR", message: "host-local operation failed", retryable: false,
  }))]);
  expect(() => checkpoint.list()).toThrow(MachineBackendError);
});

it("removes only through the host-local closed operation", () => {
  const calls: unknown[] = [];
  setInvokeForTesting((method, body) => {
    calls.push([method, JSON.parse(body.toString("utf8"))]);
    return [0, Buffer.from("{}")];
  });
  expect(checkpoint.remove("ckpt-local")).toBeUndefined();
  expect(calls).toEqual([["checkpoint.remove", { id: "ckpt-local" }]]);
});

it.each([
  { code: "INVALID_SPEC", errorType: MachineSpecError },
  { code: "CONFLICT", errorType: MachineConflictError },
  { code: "BACKEND_ERROR", errorType: MachineBackendError },
])("preserves nonretryable removal refusal $code", ({ code, errorType }) => {
  setInvokeForTesting(() => [1, Buffer.from(JSON.stringify({
    code, message: "checkpoint removal refused", retryable: false,
  }))]);
  let failure: unknown;
  try {
    checkpoint.remove("ckpt-local");
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(errorType);
  expect(failure).toMatchObject({ code, retryable: false, message: "checkpoint removal refused" });
});
