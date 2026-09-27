import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { MvmTransportError } from "../src/_errors/types.js";
import { SESSION_UNAVAILABLE, Session, currentSessionId, session } from "../src/_session.js";
import { HostRecorder, uninstallRecorder } from "./_recorder.js";

let host: HostRecorder;

beforeEach(() => {
  // A session makes no host call in either mode; the recorder proves it.
  host = new HostRecorder().install();
});

afterEach(() => {
  uninstallRecorder();
  delete process.env.MVM_NO_VM;
});

describe("session without MVM_NO_VM", () => {
  it("refuses before the body runs", () => {
    let ran = false;
    expect(() =>
      session("wl-a", () => {
        ran = true;
      }),
    ).toThrow(MvmTransportError);
    expect(ran).toBe(false);
    expect(() => session("wl-a", () => undefined)).toThrow(SESSION_UNAVAILABLE);
    expect(host.calls).toEqual([]);
  });

  it("rejects a malformed workload id first", () => {
    expect(() => session("-rf", () => undefined)).toThrow(/must be a non-empty string/);
  });
});

describe("session under MVM_NO_VM=1", () => {
  beforeEach(() => {
    process.env.MVM_NO_VM = "1";
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
