import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { MvmTransportError } from "../src/_errors/types.js";
import { func } from "../src/_remote.js";
import { Session, currentSessionId, session } from "../src/_session.js";
import { HostRecorder, failure, uninstallRecorder } from "./_recorder.js";

let host: HostRecorder;

beforeEach(() => {
  host = new HostRecorder().install();
});

afterEach(() => {
  uninstallRecorder();
  delete process.env.MVM_NO_VM;
});

const SID = "abcdefghijklmnopqrstuvwx";

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

  it("stops the session when the body throws, and keeps the body's error", async () => {
    host.on("session.stop", failure("BACKEND_ERROR", "teardown failed"));
    expect(() =>
      session("adder", () => {
        throw new Error("body failed");
      }),
    ).toThrow("body failed");
    await expect(
      session("adder", async () => {
        throw new Error("async body failed");
      }),
    ).rejects.toThrow("async body failed");
    expect(host.methods().filter((m) => m === "session.stop")).toHaveLength(2);
  });

  it("reports a stop failure when the body succeeded", () => {
    host.on("session.stop", failure("BACKEND_ERROR", "teardown failed"));
    expect(() => session("adder", () => 1)).toThrow(/teardown failed/);
  });

  it("refuses a start without a usable id before the body runs", () => {
    host.on("session.start", { session_id: "NOT-BASE32", vm_name: "x" });
    let ran = false;
    expect(() =>
      session("adder", () => {
        ran = true;
      }),
    ).toThrow(MvmTransportError);
    expect(ran).toBe(false);
    expect(host.methods()).toEqual(["session.start"]);
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
