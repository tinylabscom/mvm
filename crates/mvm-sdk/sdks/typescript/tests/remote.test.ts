/**
 * Function dispatch: local under MVM_NO_VM=1, refused otherwise.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import * as mvm from "../src/index.js";
import { MAX_RESULT_NESTING_DEPTH, REMOTE_DISPATCH_UNAVAILABLE } from "../src/_remote.js";
import { HostRecorder, uninstallRecorder } from "./_recorder.js";

let host: HostRecorder;

beforeEach(() => {
  // Dispatch never reaches the host library in either mode.
  host = new HostRecorder().install();
});

afterEach(() => {
  uninstallRecorder();
  delete process.env.MVM_NO_VM;
  delete process.env.MVM_EMITTING;
  delete process.env.MVM_MAX_PAYLOAD_BYTES;
  expect(host.calls).toEqual([]);
});

const add = mvm.func("adder", (a: unknown, b: unknown) => (a as number) + (b as number));

describe("without MVM_NO_VM", () => {
  it("refuses a function call, naming the escape hatch", () => {
    let ran = false;
    const fn = mvm.func("wl", () => {
      ran = true;
    });
    expect(() => fn.sync()).toThrow(mvm.MvmTransportError);
    expect(() => fn.sync()).toThrow(REMOTE_DISPATCH_UNAVAILABLE);
    expect(REMOTE_DISPATCH_UNAVAILABLE).toContain("MVM_NO_VM=1");
    expect(ran).toBe(false);
  });

  it("refuses a workload_ref call", () => {
    const ref = mvm.workload_ref("other");
    expect(ref.id).toBe("other");
    expect(ref.format).toBe("json");
    expect(() => (ref.fn as () => unknown)()).toThrow(REMOTE_DISPATCH_UNAVAILABLE);
  });

  it("keeps the emit-context guard ahead of everything", () => {
    process.env.MVM_EMITTING = "1";
    expect(() => add.sync(1, 2)).toThrow(mvm.EmittingContextError);
    expect(() => (mvm.workload_ref("other").fn as () => unknown)()).toThrow(mvm.EmittingContextError);
  });

  it("rejects a malformed workload id", () => {
    expect(() => mvm.workload_ref("-x")).toThrow(mvm.MvmTransportError);
    expect(() => mvm.func("", () => 1).sync()).toThrow(/must be a non-empty string/);
  });
});

describe("under MVM_NO_VM=1", () => {
  beforeEach(() => {
    process.env.MVM_NO_VM = "1";
  });

  it("runs the function in-process with round-tripped arguments", () => {
    expect(add.sync(2, 3)).toBe(5);
  });

  it("hands the function decoded copies, not the caller's objects", () => {
    const input = { items: [1, 2], at: new Date(0) };
    let received: unknown;
    const fn = mvm.func("wl", (value: unknown) => {
      received = value;
      return value;
    });
    const result = fn.sync(input);
    expect(received).not.toBe(input);
    // A Date crosses the wire as its ISO string, exactly as it would into a guest.
    expect(received).toEqual({ items: [1, 2], at: "1970-01-01T00:00:00.000Z" });
    expect(result).toEqual(received);
  });

  it("returns null for a function with no return value", () => {
    expect(mvm.func("wl", () => undefined).sync()).toBeNull();
  });

  it("awaits a promise-returning function and round-trips its result", async () => {
    const fn = mvm.func("wl", async (n: unknown) => ({ doubled: (n as number) * 2 }));
    const pending = fn.sync(21);
    expect(pending).toBeInstanceOf(Promise);
    expect(await pending).toEqual({ doubled: 42 });
  });

  it("re-raises the function's own error, sync and async", async () => {
    class Boom extends Error {}
    expect(() =>
      mvm.func("wl", () => {
        throw new Boom("sync");
      }).sync(),
    ).toThrow(Boom);
    await expect(
      mvm.func("wl", async () => {
        throw new Boom("async");
      }).sync() as Promise<unknown>,
    ).rejects.toBeInstanceOf(Boom);
  });

  it("holds the payload to MVM_MAX_PAYLOAD_BYTES before calling", () => {
    process.env.MVM_MAX_PAYLOAD_BYTES = "16";
    let ran = false;
    const fn = mvm.func("wl", () => {
      ran = true;
    });
    expect(() => fn.sync("x".repeat(64))).toThrow(mvm.PayloadTooLarge);
    expect(ran).toBe(false);
  });

  it("refuses a non-finite number in the arguments or the result", () => {
    expect(() => add.sync(Number.NaN, 1)).toThrow(/non-finite/);
    expect(() => mvm.func("wl", () => ({ v: Infinity })).sync()).toThrow(mvm.MvmTransportError);
  });

  it("refuses a result nested deeper than the decoder allows", () => {
    const deep = mvm.func("wl", () => {
      let value: unknown = 0;
      for (let i = 0; i <= MAX_RESULT_NESTING_DEPTH; i += 1) value = [value];
      return value;
    });
    expect(() => deep.sync()).toThrow(/nesting depth/);
  });

  it("refuses msgpack and unknown formats", () => {
    expect(() => mvm.func("wl", () => 1, "msgpack").sync()).toThrow(mvm.MsgpackUnavailable);
    expect(() => mvm.func("wl", () => 1, "yaml").sync()).toThrow(/unknown serialization format/);
  });

  it("refuses a workload_ref call: there is no local function to run", () => {
    expect(() => (mvm.workload_ref("other").fn as () => unknown)()).toThrow(mvm.NoVmIntrospectionError);
  });
});
