import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { func } from "../src/_remote.js";
import { Session, currentSessionId, session } from "../src/_session.js";
import { HostRecorder, failure, uninstallRecorder } from "./_recorder.js";
import { NativeContext, OwnedContextFailure } from "../src/_hostlib.js";

let host: HostRecorder;
let previousNoVm: string | undefined;

beforeEach(() => {
  host = new HostRecorder().install();
  previousNoVm = process.env.MVM_NO_VM;
  delete process.env.MVM_NO_VM;
});

afterEach(() => {
  vi.restoreAllMocks();
  uninstallRecorder();
  if (previousNoVm === undefined) delete process.env.MVM_NO_VM;
  else process.env.MVM_NO_VM = previousNoVm;
});

const SID = "abcdefghijklmnopqrstuvwx";

it("unknown start recovery closes the same C slot without Stop and retains failed free", () => {
  host.on("session.start", failure("REJECTED", "local fixture", { status: 6 }));
  let caught: unknown;
  try { session("fixture", () => { throw new Error("body must not run"); }); }
  catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(OwnedContextFailure);
  const first = caught as OwnedContextFailure;
  const owner = first.session as Session;
  const context = first.recovery;
  const slot: unknown[] = [{}];
  const cleanup = new Error("close fixture");
  let closeOk = false;
  let freeOk = false;
  const calls: string[] = [];
  // C outcome adapter only; actual provenance construction is tested in Rust.
  Object.assign(context, {
    slot,
    shared: { free: () => {}, koffi: { decode: () => [] } },
    functions: {
      close: () => { calls.push("close"); if (!closeOk) throw cleanup; return 0; },
      free: () => { calls.push("free"); if (!freeOk) return 5; slot[0] = null; return 0; },
    },
  });
  for (const allowed of [false, true]) {
    closeOk = allowed;
    let retry: unknown;
    try { owner.retry_stop(); } catch (error) { retry = error; }
    expect(retry).toBeInstanceOf(OwnedContextFailure);
    expect((retry as OwnedContextFailure).primary_error).toBe(first.primary_error);
    expect((retry as OwnedContextFailure).session).toBe(owner);
    expect((retry as OwnedContextFailure).recovery).toBe(context);
    expect(String(retry)).not.toContain("local fixture");
    expect(slot[0]).not.toBeNull();
  }
  const state = owner as unknown as { cleanupErrors: unknown[]; stopPhase: string };
  expect(state.cleanupErrors).toHaveLength(2);
  const history = [...state.cleanupErrors];
  freeOk = true;
  owner.retry_stop();
  expect(state.stopPhase).toBe("closed");
  expect(slot[0]).toBeNull();
  expect(state.cleanupErrors).toEqual(history);
  const finishedCalls = [...calls];
  owner.retry_stop();
  expect(calls).toEqual(finishedCalls);
  expect(host.methods()).toEqual(["session.start"]);
});

it("retains body plus cleanup errors and does not stop again after an acknowledged stop", () => {
  host.on("session.start", { session_id: SID, vm_name: "fixture" });
  host.on("session.stop", {});
  const primary = new Error("body fixture");
  const cleanup = new Error("close fixture");
  vi.spyOn(NativeContext.prototype, "close").mockImplementationOnce(() => { throw cleanup; });
  let caught: unknown;
  try { session("fixture", () => { throw primary; }); } catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(OwnedContextFailure);
  const retained = caught as OwnedContextFailure;
  expect(retained.primary_error).toBe(primary);
  expect(retained.cleanup_error).toBe(cleanup);
  const original = retained.session as Session;
  expect(original.context).toBe(retained.recovery);
  original.retry_stop();
  expect(host.requests("session.stop")).toHaveLength(1);
});

function callReply(stdout: string): Record<string, unknown> {
  return {
    exit_code: 0,
    stdout_b64: Buffer.from(stdout, "utf8").toString("base64"),
    stderr_b64: "",
    output_truncated: false,
  };
}

describe("session without MVM_NO_VM", () => {
  beforeEach(() => {
    host.on("session.start", { session_id: SID, vm_name: "session-vm" });
    host.on("session.stop", {});
  });

  it("boots before the body, calls into the session, and stops after", () => {
    const add = func("adder", (a: unknown, b: unknown) => (a as number) + (b as number));
    host.on("session.call", callReply("5"));
    const seen = session("adder", (s) => {
      expect(s).toBeInstanceOf(Session);
      expect(s.id).toBe(SID);
      expect(s.host).toBe(true);
      expect(s.vm_name).toBe("session-vm");
      expect(currentSessionId()).toBe(SID);
      return add.sync(2, 3);
    });
    expect(seen).toBe(5);
    expect(currentSessionId()).toBeNull();
    expect(host.methods()).toEqual(["session.start", "session.call", "session.stop"]);
    expect(host.requests("session.start")).toEqual([{ workload: "adder" }]);
    expect(host.requests("session.call")).toEqual([
      { session_id: SID, payload_b64: Buffer.from("[[2,3],{}]").toString("base64") },
    ]);
    expect(host.requests("session.stop")).toEqual([{ session_id: SID }]);
  });

  it("stops only once an async body settles", async () => {
    const add = func("adder", () => 0);
    host.on("session.call", callReply("9"));
    const pending = session(
      "adder",
      async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        return add.sync(4, 5);
      },
      { idle_timeout_secs: 60 },
    );
    expect(host.methods()).toEqual(["session.start"]);
    expect(await pending).toBe(9);
    expect(host.methods()).toEqual(["session.start", "session.call", "session.stop"]);
    expect(host.requests("session.start")).toEqual([{ workload: "adder", idle_timeout_secs: 60 }]);
  });

  it("sends a call to another workload to a VM of its own", () => {
    const other = func("other", () => null);
    host.on("entrypoint.call", callReply("null"));
    session("adder", () => other.sync());
    expect(host.requests("entrypoint.call")[0].workload).toBe("other");
    expect(host.methods()).not.toContain("session.call");
  });

  it("retains both original errors and the owned session when sync or async stop fails", async () => {
    // Ordinary host sessions now share the caller-owned context lifetime.
    // The installed recorder makes this a no-child consumer regression.
    host.on("session.stop", failure("BACKEND_ERROR", "teardown failed"));
    const originalCall = NativeContext.prototype.call;
    const stopErrors: unknown[] = [];
    vi.spyOn(NativeContext.prototype, "call").mockImplementation(function (
      this: NativeContext, method: string, request?: unknown,
    ) {
      try {
        return originalCall.call(this, method, request);
      } catch (error) {
        if (method === "session.stop") stopErrors.push(error);
        throw error;
      }
    });
    const bodies = [new Error("body fixture"), new Error("async body fixture")];
    const failures: OwnedContextFailure[] = [];
    for (const [index, primary] of bodies.entries()) {
      let original: Session | undefined;
      let caught: unknown;
      try {
        await session("adder", (handle) => {
          original = handle;
          if (index === 0) throw primary;
          return Promise.reject(primary);
        });
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(OwnedContextFailure);
      const retained = caught as OwnedContextFailure;
      expect(retained.primary_error).toBe(primary);
      expect(retained.cleanup_error).toBe(stopErrors[index]);
      expect(retained.session).toBe(original);
      expect(retained.recovery).toBe(original!.context);
      expect(String(retained)).not.toContain(primary.message);
      expect(String(retained)).not.toContain("teardown failed");
      failures.push(retained);
    }
    expect(host.methods().filter((m) => m === "session.stop")).toHaveLength(2);
    host.on("session.stop", {});
    for (const retained of failures) (retained.session as Session).retry_stop();
    expect(host.methods().filter((m) => m === "session.stop")).toHaveLength(4);
  });

  it("retains the original session on sync and async success-body cleanup failure", async () => {
    const cleanup = new Error("stop fixture");
    const originalCall = NativeContext.prototype.call;
    for (const asynchronous of [false, true]) {
      vi.spyOn(NativeContext.prototype, "call").mockImplementation(function (
        this: NativeContext, method: string, request?: unknown,
      ) {
        if (method === "session.stop") throw cleanup;
        return originalCall.call(this, method, request);
      });
      let original: Session | undefined;
      let caught: unknown;
      try {
        await session("adder", (handle) => {
          original = handle;
          return asynchronous ? Promise.resolve(1) : 1;
        });
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(OwnedContextFailure);
      const retained = caught as OwnedContextFailure;
      expect(retained.primary_error).toBeUndefined();
      expect(retained.cleanup_error).toBe(cleanup);
      expect(retained.session).toBe(original);
      expect(retained.recovery).toBe(original!.context);
      expect(String(retained)).not.toContain(cleanup.message);
      vi.restoreAllMocks();
      original!.retry_stop();
      original!.retry_stop();
    }
    expect(host.requests("session.stop")).toHaveLength(2);
  });

  it("retains original body and all errors through explicit failed retry and held success", () => {
    host.on("session.stop",
      failure("BACKEND_ERROR", "first fixture stop"),
      failure("BACKEND_ERROR", "second fixture stop"), {});
    const primary = new Error("private body fixture");
    const originalCall = NativeContext.prototype.call;
    const errors: unknown[] = [];
    vi.spyOn(NativeContext.prototype, "call").mockImplementation(function (
      this: NativeContext, method: string, request?: unknown,
    ) {
      try { return originalCall.call(this, method, request); }
      catch (error) { errors.push(error); throw error; }
    });
    let first: OwnedContextFailure | undefined;
    try { session("adder", () => { throw primary; }); }
    catch (error) { first = error as OwnedContextFailure; }
    expect(first).toBeInstanceOf(OwnedContextFailure);
    let second: OwnedContextFailure | undefined;
    try { (first!.session as Session).retry_stop(); }
    catch (error) { second = error as OwnedContextFailure; }
    expect(second).toBeInstanceOf(OwnedContextFailure);
    const owner = second!.session as Session;
    expect(second!.primary_error).toBe(primary);
    expect(second!.cleanup_error).toBe(errors[1]);
    expect(owner).toBe(first!.session);
    expect(owner.context).toBe(first!.recovery);
    expect(second!.recovery).toBe(first!.recovery);
    const retained = owner as unknown as {
      primaryError: { value: unknown }; cleanupErrors: unknown[];
    };
    expect(retained.primaryError.value).toBe(primary);
    expect(retained.cleanupErrors).toHaveLength(2);
    expect(retained.cleanupErrors[0]).toBe(errors[0]);
    expect(retained.cleanupErrors[1]).toBe(errors[1]);
    expect(String(second)).not.toContain(primary.message);
    expect(String(second)).not.toContain("fixture stop");
    owner.retry_stop();
    owner.retry_stop();
    expect(host.requests("session.stop")).toHaveLength(3);
    expect(retained.primaryError.value).toBe(primary);
    expect(retained.cleanupErrors[0]).toBe(errors[0]);
  });

  it("refuses a retry before effects when its finite cleanup history is full", () => {
    host.on("session.stop", failure("BACKEND_ERROR", "bounded fixture"));
    let owner: Session | undefined;
    try { session("adder", (handle) => { owner = handle; }); }
    catch (error) { expect((error as OwnedContextFailure).session).toBe(owner); }
    for (let i = 1; i < 16; i++) expect(() => owner!.retry_stop()).toThrow(OwnedContextFailure);
    const history = (owner as unknown as { cleanupErrors: unknown[] }).cleanupErrors;
    expect(history).toHaveLength(16);
    const original = [...history];
    const before = host.requests("session.stop").length;
    let refused: OwnedContextFailure | undefined;
    try { owner!.retry_stop(); } catch (error) { refused = error as OwnedContextFailure; }
    expect(refused!.session).toBe(owner);
    expect(refused!.recovery).toBe(owner!.context);
    expect(host.requests("session.stop")).toHaveLength(before);
    expect(history).toHaveLength(16);
    history.forEach((error, index) => expect(error).toBe(original[index]));
    // No C/native owner was constructed by the installed recorder.
  });

  it.each([
    {}, { session_id: null }, { session_id: 7 },
    { session_id: "NOT-BASE32" }, { session_id: SID + "\n" },
  ])("retains the original receiver on malformed start: %j", (reply) => {
    host.on("session.start", reply);
    const originalCall = NativeContext.prototype.call;
    const errors: unknown[] = [];
    vi.spyOn(NativeContext.prototype, "call").mockImplementation(function (
      this: NativeContext, method: string, request?: unknown,
    ) {
      try { return originalCall.call(this, method, request); }
      catch (error) { errors.push(error); throw error; }
    });
    let ran = false;
    let caught: unknown;
    try {
      session("adder", () => {
        ran = true;
      });
    } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(OwnedContextFailure);
    const retained = caught as OwnedContextFailure;
    const owner = retained.session as Session;
    expect(retained.primary_error).toBe(errors[0]);
    expect(owner.context).toBe(retained.recovery);
    expect(() => owner.id).toThrow(OwnedContextFailure);
    for (const cleanup of [
      () => owner.retry_stop(), () => retained.recovery.retry_stop(),
      () => retained.recovery.close(), () => retained.recovery.free(),
    ]) expect(cleanup).toThrow();
    expect(() => retained.recovery.call("session.start", { workload: "second" })).toThrow();
    expect(ran).toBe(false);
    expect(host.methods()).toEqual(["session.start"]);
    expect(currentSessionId()).toBeNull();
  });

  it("rejects a malformed workload id or idle timeout before booting", () => {
    expect(() => session("-rf", () => undefined)).toThrow(/must be a non-empty string/);
    expect(() => session("wl", () => undefined, { idle_timeout_secs: 0 })).toThrow(/idle_timeout_secs/);
    expect(host.calls).toEqual([]);
  });
});

describe("session under MVM_NO_VM=1", () => {
  beforeEach(() => {
    process.env.MVM_NO_VM = "1";
  });

  afterEach(() => {
    // A local session makes no host call.
    expect(host.calls).toEqual([]);
  });

  it("exposes a local id inside the body and nothing outside it", () => {
    expect(currentSessionId()).toBeNull();
    const seen = session("wl-a", (s) => {
      expect(s).toBeInstanceOf(Session);
      expect(s.workload_id).toBe("wl-a");
      expect(String(s)).toBe(s.id);
      return currentSessionId();
    });
    expect(seen).toMatch(/^local-[0-9a-f]{16}$/);
    expect(currentSessionId()).toBeNull();
    expect(host.calls).toEqual([]);
  });

  it("returns the body's value and re-raises its error", () => {
    expect(session("wl", () => 42)).toBe(42);
    expect(() =>
      session("wl", () => {
        throw new Error("body failed");
      }),
    ).toThrow("body failed");
    expect(currentSessionId()).toBeNull();
  });

  it("mints a fresh id per session", () => {
    const first = session("wl", () => currentSessionId());
    const second = session("wl", () => currentSessionId());
    expect(first).not.toBe(second);
  });

  it("keeps concurrent sessions from seeing each other", async () => {
    // The property the callback shape was chosen for: a module-level
    // variable would let whichever body started last win for both.
    const observe = (workload: string, delayMs: number) =>
      session(workload, async (s) => {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        return [s.id, currentSessionId()];
      });
    const [first, second] = await Promise.all([observe("wl-1", 20), observe("wl-2", 5)]);
    expect(first[1]).toBe(first[0]);
    expect(second[1]).toBe(second[0]);
    expect(first[0]).not.toBe(second[0]);
    expect(currentSessionId()).toBeNull();
  });

  it("stays visible across an await in an async body", async () => {
    let inside: string | null = null;
    const id = await session("wl-async", async (s) => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      inside = currentSessionId();
      return s.id;
    });
    expect(inside).toBe(id);
  });
});
