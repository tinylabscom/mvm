/**
 * Function dispatch: local under MVM_NO_VM=1, through the host library
 * otherwise.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import * as mvm from "../src/index.js";
import { MAX_RESULT_NESTING_DEPTH } from "../src/_remote.js";
import { HostRecorder, failure, uninstallRecorder } from "./_recorder.js";

let host: HostRecorder;

beforeEach(() => {
  host = new HostRecorder().install();
});

afterEach(() => {
  uninstallRecorder();
  delete process.env.MVM_NO_VM;
  delete process.env.MVM_EMITTING;
  delete process.env.MVM_MAX_PAYLOAD_BYTES;
  delete process.env.MVM_MAX_OUTPUT_BYTES;
});

const add = mvm.func("adder", (a: unknown, b: unknown) => (a as number) + (b as number));

const b64 = (text: string): string => Buffer.from(text, "utf8").toString("base64");

function reply(exitCode: number, stdout = "", stderr = "", extra: Record<string, unknown> = {}) {
  return {
    exit_code: exitCode,
    stdout_b64: b64(stdout),
    stderr_b64: b64(stderr),
    output_truncated: false,
    ...extra,
  };
}

describe("without MVM_NO_VM", () => {
  it("dispatches into the workload and decodes the result", () => {
    let ran = false;
    const fn = mvm.func("adder", () => {
      ran = true;
    });
    host.on("entrypoint.call", reply(0, "5"));
    expect(fn.sync(2, 3)).toBe(5);
    expect(host.requests("entrypoint.call")).toEqual([
      { workload: "adder", payload_b64: b64("[[2,3],{}]") },
    ]);
    expect(ran).toBe(false);
  });

  it("turns a raised exception into RemoteError", () => {
    host.on(
      "entrypoint.call",
      reply(1, "", "MVM_ENVELOPE: {...}\n", {
        error: { kind: "ValueError", error_id: "0123456789abcdef", message: "bad" },
      }),
    );
    let caught: unknown;
    try {
      add.sync(1, 2);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(mvm.RemoteError);
    const remote = caught as mvm.RemoteError;
    expect([remote.kind, remote.error_id]).toEqual(["ValueError", "0123456789abcdef"]);
    expect(remote.message).toContain("bad");
  });

  it("reports a failure without an envelope with its status and stderr tail", () => {
    host.on("entrypoint.call", reply(3, "", "x".repeat(5000) + "segfault"));
    let message = "";
    try {
      add.sync(1, 2);
    } catch (err) {
      expect(err).toBeInstanceOf(mvm.MvmTransportError);
      message = (err as Error).message;
    }
    expect(message).toContain("status 3");
    expect(message).toContain("segfault");
    expect(message).not.toContain("x".repeat(2100));
  });

  it("says why when the agent ended the call", () => {
    host.on("entrypoint.call", reply(124, "", "", { agent_error: { kind: "Timeout", message: "exceeded 30s" } }));
    expect(() => add.sync(1, 2)).toThrow(/Timeout: exceeded 30s/);
  });

  it("holds a host result to the output cap", () => {
    process.env.MVM_MAX_OUTPUT_BYTES = "4";
    host.on("entrypoint.call", reply(0, "123456"));
    expect(() => add.sync(1, 2)).toThrow(/output cap/);
    delete process.env.MVM_MAX_OUTPUT_BYTES;
    host.on("entrypoint.call", reply(0, "1", "", { output_truncated: true }));
    expect(() => add.sync(1, 2)).toThrow(/output cap/);
  });

  it("refuses a reply without an exit status", () => {
    host.on("entrypoint.call", { stdout_b64: "" });
    expect(() => add.sync(1, 2)).toThrow(/no exit status/);
  });

  it("passes a library refusal through typed", () => {
    host.on("entrypoint.call", failure("INVALID_SPEC", 'no built image named "adder"', { status: 2 }));
    expect(() => add.sync(1, 2)).toThrow(/no built image/);
  });

  it("dispatches a workload_ref call to its workload", () => {
    const ref = mvm.workload_ref("other");
    expect(ref.id).toBe("other");
    expect(ref.format).toBe("json");
    host.on("entrypoint.call", reply(0, "3"));
    expect((ref.add as (...a: unknown[]) => unknown)(1, 2)).toBe(3);
    expect(host.requests("entrypoint.call")).toEqual([
      { workload: "other", payload_b64: b64("[[1,2],{}]") },
    ]);
  });

  it("keeps the emit-context guard ahead of everything", () => {
    process.env.MVM_EMITTING = "1";
    expect(() => add.sync(1, 2)).toThrow(mvm.EmittingContextError);
    expect(() => (mvm.workload_ref("other").fn as () => unknown)()).toThrow(mvm.EmittingContextError);
    expect(host.calls).toEqual([]);
  });

  it("runs the payload cap before reaching the library", () => {
    process.env.MVM_MAX_PAYLOAD_BYTES = "16";
    expect(() => add.sync("x".repeat(64), 1)).toThrow(mvm.PayloadTooLarge);
    expect(host.calls).toEqual([]);
  });

  it("rejects a malformed workload id", () => {
    expect(() => mvm.workload_ref("-x")).toThrow(mvm.MvmTransportError);
    expect(() => mvm.func("", () => 1).sync()).toThrow(/must be a non-empty string/);
    expect(host.calls).toEqual([]);
  });
});

describe("under MVM_NO_VM=1", () => {
  beforeEach(() => {
    process.env.MVM_NO_VM = "1";
  });

  afterEach(() => {
    // A local call never reaches the host library.
    expect(host.calls).toEqual([]);
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
