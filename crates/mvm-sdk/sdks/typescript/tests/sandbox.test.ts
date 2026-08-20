/**
 * Tests for the Sandbox record-mode SDK. SDK port Phase 7c.
 * Mirrors `sdks/python/tests/test_sandbox.py`.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as mvm from "../src/index.js";
import { currentRecording, flushRecordingToOutPath } from "../src/_sandbox.js";

beforeEach(() => {
  mvm.resetRecording();
  delete process.env.MVM_SDK_MODE;
});

afterEach(() => {
  mvm.resetRecording();
  delete process.env.MVM_SDK_MODE;
});

// ── basic recording shape ────────────────────────────────────────────

describe("Sandbox.create", () => {
  it("records the template and default TTL", () => {
    mvm.Sandbox.create("python-3.12");
    const rec = currentRecording()!;
    expect(rec.create.template).toBe("python-3.12");
    expect(rec.create.ttl_seconds).toBe(mvm.DEFAULT_TTL_SECONDS);
    expect(rec.ops).toEqual([]);
  });

  it("records a pinned image and explicit command", () => {
    mvm.Sandbox.create(
      { image: `docker.io/example/browser@sha256:${"a".repeat(64)}` },
      { command: ["/browser", "serve"] },
    );
    const rec = currentRecording()!;
    expect(rec.create.template).toBeUndefined();
    expect(rec.create.image).toMatch(/a{64}$/);
    expect(rec.ops).toEqual([
      { kind: "command_start", argv: ["/browser", "serve"], env: {} },
    ]);
  });

  it("defaults workloadId to template", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    expect(sb.workloadId).toBe("python-3.12");
  });

  it("respects workloadId override", () => {
    const sb = mvm.Sandbox.create("python-3.12", { workloadId: "etl-job" });
    expect(sb.workloadId).toBe("etl-job");
    expect(currentRecording()!.workload_id).toBe("etl-job");
  });

  it("rejects empty template", () => {
    expect(() => mvm.Sandbox.create("")).toThrow(TypeError);
  });

  it("enforces one-sandbox-per-script", () => {
    mvm.Sandbox.create("python-3.12");
    expect(() => mvm.Sandbox.create("node-22")).toThrow(/already active/);
  });
});

// ── commands.start ──────────────────────────────────────────────────

describe("Sandbox.commands.start", () => {
  it("appends a command_start op", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    sb.commands.start(["python", "run.py"]);
    expect(currentRecording()!.ops).toEqual([
      { kind: "command_start", argv: ["python", "run.py"], env: {} },
    ]);
  });

  it("encodes env with secret refs", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    sb.commands.start(["python", "run.py"], {
      env: {
        MODE: "prod",
        API_KEY: mvm.secret("api-key", { type: "bearer", hosts: ["api.example.com"] }),
      },
    });
    const op = currentRecording()!.ops[0] as Extract<
      mvm.RecordedOpWire,
      { kind: "command_start" }
    >;
    expect(op.env.MODE).toEqual({ kind: "literal", value: "prod" });
    expect(op.env.API_KEY).toMatchObject({ kind: "secret_ref" });
  });

  it("rejects non-array argv", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    expect(() => sb.commands.start("python run.py" as never)).toThrow(TypeError);
  });

  it("rejects empty argv", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    expect(() => sb.commands.start([])).toThrow(RangeError);
  });
});

// ── files.write ────────────────────────────────────────────────────

describe("Sandbox.files.write", () => {
  it("base64-encodes bytes", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    sb.files.write("/app/config.json", new TextEncoder().encode('{"x":1}'));
    const op = currentRecording()!.ops[0] as Extract<
      mvm.RecordedOpWire,
      { kind: "files_write" }
    >;
    expect(op.path).toBe("/app/config.json");
    expect(Buffer.from(op.bytes_b64, "base64").toString("utf-8")).toBe('{"x":1}');
  });

  it("utf-8 encodes string content", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    sb.files.write("/app/note.txt", "héllo");
    const op = currentRecording()!.ops[0] as Extract<
      mvm.RecordedOpWire,
      { kind: "files_write" }
    >;
    expect(Buffer.from(op.bytes_b64, "base64").toString("utf-8")).toBe("héllo");
  });

  it("rejects non-bytes non-str content", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    expect(() => sb.files.write("/app/x", 123 as never)).toThrow(TypeError);
  });

  it("rejects empty path", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    expect(() => sb.files.write("", new Uint8Array())).toThrow(TypeError);
  });
});

// ── kill / dispose ───────────────────────────────────────────────────

describe("Sandbox.kill / dispose", () => {
  it("kill appends a kill op", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    sb.kill();
    expect(currentRecording()!.ops).toEqual([{ kind: "kill" }]);
  });

  it("Symbol.dispose appends a kill op", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    sb[Symbol.dispose]();
    expect(currentRecording()!.ops).toEqual([{ kind: "kill" }]);
  });
});

// ── modes ────────────────────────────────────────────────────────────

describe("MVM_SDK_MODE", () => {
  it("live mode without the host CLI throws", () => {
    process.env.MVM_SDK_MODE = "live";
    delete process.env.MVM_CLI_BIN;
    process.env.PATH = "";
    expect(() => mvm.Sandbox.create("python-3.12")).toThrow(/mvmctl/);
  });

  it("plan mode redirects to mvmctl run --mode plan", () => {
    process.env.MVM_SDK_MODE = "plan";
    expect(() => mvm.Sandbox.create("python-3.12")).toThrow(/mvmctl run --mode plan/);
  });

  it("invalid mode throws with actionable message", () => {
    process.env.MVM_SDK_MODE = "garbage";
    expect(() => mvm.Sandbox.create("python-3.12")).toThrow(/invalid/);
  });
});

// ── TTL parsing ──────────────────────────────────────────────────────

describe("ttl parsing", () => {
  it("accepts integer seconds", () => {
    mvm.Sandbox.create("python-3.12", { ttl: 120 });
    expect(currentRecording()!.create.ttl_seconds).toBe(120);
  });

  it("accepts 30m", () => {
    mvm.Sandbox.create("python-3.12", { ttl: "30m" });
    expect(currentRecording()!.create.ttl_seconds).toBe(1800);
  });

  it("accepts 1h", () => {
    mvm.Sandbox.create("python-3.12", { ttl: "1h" });
    expect(currentRecording()!.create.ttl_seconds).toBe(3600);
  });

  it("accepts bare integer string", () => {
    mvm.Sandbox.create("python-3.12", { ttl: "3600" });
    expect(currentRecording()!.create.ttl_seconds).toBe(3600);
  });

  it("rejects unparseable", () => {
    expect(() => mvm.Sandbox.create("python-3.12", { ttl: "forever" })).toThrow(/unrecognized/);
  });

  it("rejects zero", () => {
    expect(() => mvm.Sandbox.create("python-3.12", { ttl: 0 })).toThrow(RangeError);
  });
});

// ── flow-through ─────────────────────────────────────────────────────

describe("create kwargs", () => {
  it("resources flow through", () => {
    mvm.Sandbox.create("python-3.12", {
      resources: mvm.resources({ cpu_cores: 2, memory_mb: 512, rootfs_size_mb: 1024 }),
    });
    const rsr = currentRecording()!.create.resources!;
    expect(rsr.cpu_cores).toBe(2);
    expect(rsr.memory_mb).toBe(512);
    expect(rsr.rootfs_size_mb).toBe(1024);
  });

  it("includes flow through", () => {
    mvm.Sandbox.create("python-3.12", { include: ["src", "lib"] });
    expect(currentRecording()!.create.include).toEqual(["src", "lib"]);
  });
});

// ── emit + reset ─────────────────────────────────────────────────────

describe("emitRecordingJson", () => {
  it("produces a wire-compatible document", () => {
    const sb = mvm.Sandbox.create("python-3.12", { include: ["src"] });
    sb.commands.start(["python", "run.py"], { env: { X: "1" } });
    sb.files.write("/app/cfg", new TextEncoder().encode("data"));
    const parsed = JSON.parse(mvm.emitRecordingJson());
    expect(Object.keys(parsed).sort()).toEqual(["create", "ops", "workload_id"]);
    expect(parsed.ops.map((o: { kind: string }) => o.kind)).toEqual([
      "command_start",
      "files_write",
    ]);
  });

  it("throws when inactive", () => {
    expect(() => mvm.emitRecordingJson()).toThrow(mvm.RecordingNotActiveError);
  });

  it("resetRecording clears state", () => {
    mvm.Sandbox.create("python-3.12");
    expect(currentRecording()).not.toBeNull();
    mvm.resetRecording();
    expect(currentRecording()).toBeNull();
  });
});

// ── Phase 7f — MVM_SDK_OUT_PATH exit flusher ─────────────────────────

describe("flushRecordingToOutPath", () => {
  // Use os.tmpdir + a random name; vitest doesn't ship a per-test
  // tmpdir helper out of the box. Cleanup runs in afterEach.
  const tmpFiles: string[] = [];
  const tmpFile = (): string => {
    const os = require("node:os");
    const path = require("node:path");
    const p = path.join(os.tmpdir(), `mvm-rec-${Date.now()}-${Math.random()}.json`);
    tmpFiles.push(p);
    return p;
  };

  afterEach(() => {
    const fs = require("node:fs");
    for (const p of tmpFiles) {
      try {
        fs.rmSync(p, { force: true });
      } catch {
        // ignore
      }
    }
    tmpFiles.length = 0;
    delete process.env.MVM_SDK_OUT_PATH;
  });

  it("writes the recording to MVM_SDK_OUT_PATH on flush", () => {
    const out = tmpFile();
    process.env.MVM_SDK_OUT_PATH = out;
    const sb = mvm.Sandbox.create("python-3.12");
    sb.commands.start(["python", "run.py"]);
    flushRecordingToOutPath();
    const fs = require("node:fs");
    expect(fs.existsSync(out)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(out, "utf-8"));
    expect(parsed.workload_id).toBe("python-3.12");
    expect(parsed.ops[0].kind).toBe("command_start");
  });

  it("is a no-op when MVM_SDK_OUT_PATH is unset", () => {
    const out = tmpFile();
    // Don't set the env var.
    mvm.Sandbox.create("python-3.12");
    flushRecordingToOutPath();
    const fs = require("node:fs");
    expect(fs.existsSync(out)).toBe(false);
  });

  it("is a no-op when no Sandbox was created", () => {
    const out = tmpFile();
    process.env.MVM_SDK_OUT_PATH = out;
    // Don't call Sandbox.create — the CLI's existence check uses
    // file-missing as the "no Sandbox" signal.
    flushRecordingToOutPath();
    const fs = require("node:fs");
    expect(fs.existsSync(out)).toBe(false);
  });
});
