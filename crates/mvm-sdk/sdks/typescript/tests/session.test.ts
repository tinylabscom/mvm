import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Session, currentSessionId, session } from "../src/_session.js";

/**
 * A stand-in `mvmctl` that answers the two session verbs.
 *
 * `session start` prints a fresh id derived from the workload, so a test
 * can tell two concurrent sessions apart; `session stop` records the
 * teardown so a test can assert it happened.
 */
let tmp: string;
let fakeCli: string;
let stopLog: string;

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mvm-session-test-"));
  stopLog = path.join(tmp, "stops.log");
  fakeCli = path.join(tmp, "mvmctl");
  fs.writeFileSync(
    fakeCli,
    `#!/bin/bash
if [ "$1" = "session" ] && [ "$2" = "start" ]; then
  # argv: session start -- <workload_id>
  echo "sid-$4"
  exit 0
fi
if [ "$1" = "session" ] && [ "$2" = "stop" ]; then
  echo "$3" >> "${stopLog}"
  exit 0
fi
exit 64
`,
    { mode: 0o755 },
  );
  process.env.MVM_CLI_BIN = fakeCli;
});

afterAll(() => {
  delete process.env.MVM_CLI_BIN;
  fs.rmSync(tmp, { recursive: true, force: true });
});

function stops(): string[] {
  if (!fs.existsSync(stopLog)) return [];
  return fs.readFileSync(stopLog, "utf-8").trim().split("\n").filter(Boolean);
}

describe("session", () => {
  it("exposes the started id inside the body and nothing outside it", () => {
    expect(currentSessionId()).toBeNull();
    const seen = session("wl-a", (s) => {
      expect(s).toBeInstanceOf(Session);
      expect(s.workload_id).toBe("wl-a");
      return currentSessionId();
    });
    expect(seen).toBe("sid-wl-a");
    expect(currentSessionId()).toBeNull();
  });

  it("stops the session when the body returns", () => {
    const before = stops().length;
    session("wl-stop", () => undefined);
    expect(stops().slice(before)).toContain("sid-wl-stop");
  });

  it("stops the session when the body throws, and re-raises", () => {
    const before = stops().length;
    expect(() => {
      session("wl-throw", () => {
        throw new Error("body failed");
      });
    }).toThrow("body failed");
    // Teardown must not mask the body's failure, and must still happen.
    expect(stops().slice(before)).toContain("sid-wl-throw");
  });

  it("keeps concurrent sessions from seeing each other", async () => {
    // This is the property the callback shape was chosen for. A
    // module-level variable with `using` would fail here: whichever body
    // started last would win, and both would observe the same id.
    const observe = async (workload: string, delayMs: number) =>
      session(workload, async () => {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        return currentSessionId();
      });

    const [first, second] = await Promise.all([observe("wl-1", 20), observe("wl-2", 5)]);
    expect(first).toBe("sid-wl-1");
    expect(second).toBe("sid-wl-2");
    expect(currentSessionId()).toBeNull();
  });

  it("waits for an async body before stopping", async () => {
    const before = stops().length;
    let finished = false;
    await session("wl-async", async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      // The session must still be live here; a teardown that did not
      // await the promise would already have stopped it.
      expect(currentSessionId()).toBe("sid-wl-async");
      finished = true;
    });
    expect(finished).toBe(true);
    expect(stops().slice(before)).toContain("sid-wl-async");
  });
});
