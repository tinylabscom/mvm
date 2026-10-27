import { afterEach, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import { checkpoint } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";
import { MachineBackendError } from "../src/_errors/types.js";

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
