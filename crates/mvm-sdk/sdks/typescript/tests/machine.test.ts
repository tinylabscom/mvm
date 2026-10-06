/**
 * `Machine` over the host library.
 *
 * The library is replaced by a recorder, so each test pins the exact request
 * a facade method sends and how the reply comes back.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import * as mvm from "../src/index.js";
import { parseAllowHost } from "../src/_machine.js";
import { HostRecorder, batch, failure, runReply, uninstallRecorder } from "./_recorder.js";

let host: HostRecorder;

beforeEach(() => {
  host = new HostRecorder().install();
});

afterEach(() => {
  uninstallRecorder();
});

const STATE = { id: "id-devbox", name: "devbox", status: "stopped" };

describe("Machine.run", () => {
  it("boots, runs the command, returns its output, and stops the machine", () => {
    host
      .on("machine.run", runReply("run-1", "dev", "tok-1"))
      .on("guest.proc.stream.open", { stream: 4 })
      .on("guest.proc.stream.next", batch([["stdout", "Linux\n"]], { kind: "exited", code: 0 }))
      .on("machine.stop", {})
      .on("machine.rm", {});
    const result = mvm.Machine.run("alpine:latest", ["uname"], {
      env: { LANG: "C" },
      cwd: "/",
      cpus: 2,
      memoryMib: 512,
      allowHosts: ["example.com:443"],
      timeout: 30,
    });
    expect(result).toEqual({ exitCode: 0, stdout: "Linux\n", stderr: "" });
    const [request] = host.requests("machine.run");
    expect(request.name).toMatch(/^sdk-run-[0-9a-f]{8}$/);
    delete request.name;
    expect([request]).toEqual([
      {
        image: "alpine:latest",
        mode: "persistent",
        command: ["uname"],
        env: { LANG: "C" },
        cwd: "/",
        cpus: 2,
        memory_mib: 512,
        egress: [{ host: "example.com", port: 443 }],
      },
    ]);
    expect(host.requests("guest.proc.stream.open")).toEqual([{ id: "run-1", token: "tok-1", timeout_secs: 30 }]);
    expect(host.methods().slice(-2)).toEqual(["machine.stop", "machine.rm"]);
    expect(host.requests("machine.stop")).toEqual([{ id: "run-1" }]);
    expect(host.requests("machine.rm")).toEqual([{ id: "run-1" }]);
  });

  it("stops and removes the machine when the wait fails", () => {
    host
      .on("machine.run", runReply("run-2", "dev", "tok"))
      .on("guest.proc.stream.open", failure("BACKEND_ERROR", "the agent went away"))
      .on("machine.stop", {})
      .on("machine.rm", {});
    expect(() => mvm.Machine.run("alpine:latest", ["true"])).toThrow(mvm.MachineBackendError);
    expect(host.requests("machine.stop")).toEqual([{ id: "run-2" }]);
    expect(host.requests("machine.rm")).toEqual([{ id: "run-2" }]);
  });

  it("reports rather than throws a failed teardown", () => {
    host
      .on("machine.run", runReply("run-3", "dev", "tok"))
      .on("guest.proc.stream.open", { stream: 1 })
      .on("guest.proc.stream.next", batch([], { kind: "exited", code: 0 }))
      .on("machine.stop", failure("NOT_FOUND", "already reaped"));
    const written: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((line: unknown) => {
      written.push(String(line));
    });
    try {
      expect(mvm.Machine.run("alpine:latest", ["true"]).exitCode).toBe(0);
    } finally {
      spy.mockRestore();
    }
    expect(written.join("")).toContain("stopping run-3 failed: already reaped");
    expect(host.methods()).not.toContain("machine.rm");
  });

  it("needs a command", () => {
    expect(() => mvm.Machine.run("alpine:latest", [])).toThrow(RangeError);
    expect(host.calls).toEqual([]);
  });

  it("raises the library's refusal of a denied variable, and boots nothing to stop", () => {
    host.on("machine.run", failure("INVALID_SPEC", "variable LD_PRELOAD is denied"));
    expect(() => mvm.Machine.run("alpine:latest", ["true"], { env: { LD_PRELOAD: "/x.so" } })).toThrow(
      mvm.MachineSpecError,
    );
    expect(host.methods()).toEqual(["machine.run"]);
  });
});

describe("Machine.launch", () => {
  it("sends the minimal request with a generated name and returns a handle", () => {
    host.on("machine.run", runReply("gen-1", "dev"));
    const machine = mvm.Machine.launch({ image: "alpine:latest" });
    expect(machine).toBeInstanceOf(mvm.Machine);
    expect([machine.name, machine.buildMode, machine.planId, machine.process]).toEqual([
      "gen-1",
      "dev",
      "plan-0",
      undefined,
    ]);
    const [request] = host.requests("machine.run");
    expect(request.name).toMatch(/^sdk-machine-[0-9a-f]{8}$/);
    delete request.name;
    expect(request).toEqual({ image: "alpine:latest", mode: "persistent" });
  });

  it("sends every option under the library's field names", () => {
    host.on("machine.run", runReply("web", "prod"));
    mvm.Machine.launch({
      image: "alpine:latest",
      name: "web",
      cpus: 2,
      memoryMib: 512,
      profile: "dev",
      allowHosts: ["example.com:443", "[2001:db8::1]:8443"],
      ports: ["8080:80"],
      ttlSeconds: 600,
    });
    expect(host.requests("machine.run")).toEqual([
      {
        image: "alpine:latest",
        mode: "persistent",
        name: "web",
        cpus: 2,
        memory_mib: 512,
        profile: "dev",
        ports: ["8080:80"],
        egress: [
          { host: "example.com", port: 443 },
          { host: "2001:db8::1", port: 8443 },
        ],
        ttl_seconds: 600,
      },
    ]);
  });

  it("leaves empty collections out", () => {
    host.on("machine.run", runReply("x", "dev"));
    mvm.Machine.launch({ image: "alpine:latest", name: "x", env: {}, allowHosts: [], ports: [] });
    expect(host.requests("machine.run")).toEqual([{ image: "alpine:latest", mode: "persistent", name: "x" }]);
  });

  it("keeps a started command's process to wait on", () => {
    host
      .on("machine.run", runReply("svc", "dev", "tok-9"))
      .on("guest.proc.stream.open", { stream: 1 })
      .on("guest.proc.stream.next", batch([["stderr", "bad"]], { kind: "exited", code: 3 }));
    const machine = mvm.Machine.launch({ image: "alpine:latest", command: ["serve"], name: "svc" });
    expect(machine.process).toBe("tok-9");
    expect(machine.wait()).toEqual({ exitCode: 3, stdout: "", stderr: "bad" });
  });

  it("reports a started command with no process as MachineError", () => {
    host.on("machine.run", runReply("svc", "dev"));
    expect(() => mvm.Machine.launch({ image: "alpine:latest", command: ["serve"] })).toThrow(/named no process/);
  });

  it("refuses to wait without a command", () => {
    expect(() => new mvm.Machine("idle").wait()).toThrow(mvm.MachineError);
    expect(host.calls).toEqual([]);
  });

  it.each(["template", "manifest"] as const)("boots a %s by its field", (field) => {
    host.on("machine.run", runReply("b", "dev"));
    mvm.Machine.launch({ [field]: "chromium", name: "b" });
    expect(host.requests("machine.run")).toEqual([{ [field]: "chromium", mode: "persistent", name: "b" }]);
  });

  it.each([{}, { image: "alpine", template: "chromium" }, { template: "a", manifest: "b" }])(
    "names exactly one source: %j",
    (source) => {
      expect(() => mvm.Machine.launch(source)).toThrow(/exactly one/);
      expect(host.calls).toEqual([]);
    },
  );

  it("refuses bad arguments before any call", () => {
    expect(() => mvm.Machine.launch({ image: "" })).toThrow(TypeError);
    expect(() => mvm.Machine.launch({ image: "img", cpus: 0 })).toThrow(RangeError);
    expect(() => mvm.Machine.launch({ image: "img", cwd: "" })).toThrow(TypeError);
    expect(() => mvm.Machine.launch({ image: "img", command: [] })).toThrow(RangeError);
    expect(() => mvm.Machine.launch({ image: "img", allowHosts: ["example.com"] })).toThrow(mvm.MachineError);
    expect(host.calls).toEqual([]);
  });

  it("reports a reply with no machine name as MachineError", () => {
    host.on("machine.run", { machine: {}, build_mode: "dev" });
    expect(() => mvm.Machine.launch({ image: "img" })).toThrow(mvm.MachineError);
  });
});

describe("parseAllowHost", () => {
  it("parses host:port and bracketed IPv6", () => {
    expect(parseAllowHost("api.example.com:443")).toEqual({ host: "api.example.com", port: 443 });
    expect(parseAllowHost("10.0.0.1:80")).toEqual({ host: "10.0.0.1", port: 80 });
    expect(parseAllowHost("[::1]:8080")).toEqual({ host: "::1", port: 8080 });
  });

  it.each(["example.com", "example.com:", ":443", "::1:443", "[::1]", "[::1]443", "h:0", "h:65536", "h:4x3"])(
    "refuses %j",
    (entry) => {
      expect(() => parseAllowHost(entry)).toThrow(mvm.MachineError);
    },
  );
});

describe("Machine.create", () => {
  it("persists a definition and returns a handle", () => {
    host.on("machine.create", STATE);
    const machine = mvm.Machine.create("devbox", "alpine:latest", {
      cpus: 1,
      memoryMib: 256,
      profile: "dev",
      allowHosts: ["example.com:443"],
      force: true,
    });
    expect(machine.name).toBe("devbox");
    expect(host.requests("machine.create")).toEqual([
      {
        name: "devbox",
        image: "alpine:latest",
        cpus: 1,
        memory_mib: 256,
        profile: "dev",
        egress: [{ host: "example.com", port: 443 }],
        force: true,
      },
    ]);
  });

  it("omits force unless set", () => {
    host.on("machine.create", STATE);
    mvm.Machine.create("devbox", "alpine:latest");
    expect(host.requests("machine.create")).toEqual([{ name: "devbox", image: "alpine:latest" }]);
  });

  it("persists a definition from a manifest", () => {
    host.on("machine.create", STATE);
    mvm.Machine.create("tmpl", { manifest: "./mvm.toml" });
    expect(host.requests("machine.create")).toEqual([{ name: "tmpl", manifest: "./mvm.toml" }]);
  });
});

describe("Machine.ls", () => {
  it("returns the inventory records", () => {
    const records = [{ name: "a", build_mode: "dev", status: "running", kind: "transient", source: "oci" }];
    host.on("machine.inventory", records);
    expect(mvm.Machine.ls()).toEqual(records);
    expect(host.calls).toEqual([{ method: "machine.inventory", request: undefined }]);
  });

  it("refuses a non-array reply", () => {
    host.on("machine.inventory", {});
    expect(() => mvm.Machine.ls()).toThrow(mvm.MachineError);
  });
});

describe("Machine lifecycle", () => {
  it("start, inspect, stop, and rm address the machine by name", () => {
    host
      .on("machine.start", { ...STATE, status: "running" })
      .on("machine.inspect", STATE)
      .on("machine.stop", {})
      .on("machine.rm", {});
    const machine = new mvm.Machine("devbox");
    expect(machine.start().status).toBe("running");
    expect(machine.inspect()).toEqual(STATE);
    expect(machine.stop()).toBeUndefined();
    expect(machine.rm()).toBeUndefined();
    expect(host.calls).toEqual([
      { method: "machine.start", request: { id: "devbox" } },
      { method: "machine.inspect", request: { id: "devbox" } },
      { method: "machine.stop", request: { id: "devbox" } },
      { method: "machine.rm", request: { id: "devbox" } },
    ]);
  });

  it("follows logs as they arrive, decoding a character split across chunks", () => {
    const snowman = Buffer.from("\u2603", "utf8");
    const chunk = (stream: string, bytes: Buffer) => ({ stream, data_b64: bytes.toString("base64") });
    host
      .on("machine.logs.stream.open", { stream: 8 })
      .on(
        "machine.logs.stream.next",
        { events: [chunk("stdout", Buffer.concat([Buffer.from("boot "), snowman.subarray(0, 1)]))], done: false },
        { events: [], done: false },
        { events: [chunk("stderr", Buffer.concat([snowman.subarray(1), Buffer.from(" up")]))], done: true },
      );
    const chunks = new mvm.Machine("web").logs({ lines: 5, follow: true });
    expect(host.calls).toEqual([]);
    expect([...chunks].join("")).toBe("boot \u2603 up");
    expect(host.requests("machine.logs.stream.open")).toEqual([
      { id: "web", follow: true, streams: ["stdout", "stderr"], tail_lines: 5 },
    ]);
    expect(host.requests("machine.logs.stream.next")[0]).toEqual({ stream: 8, wait_ms: 5000 });
    expect(host.methods()).not.toContain("machine.logs.stream.close");
  });

  it("closes a followed log stream when iteration stops early", () => {
    host
      .on("machine.logs.stream.open", { stream: 2 })
      .on("machine.logs.stream.next", { events: [{ stream: "stdout", data_b64: Buffer.from("line\n").toString("base64") }], done: false })
      .on("machine.logs.stream.close", {});
    for (const text of new mvm.Machine("web").logs({ follow: true })) {
      expect(text).toBe("line\n");
      break;
    }
    expect(host.requests("machine.logs.stream.close")).toEqual([{ stream: 2 }]);
  });

  it("logs decodes the console and forwards the line limit", () => {
    host.on("machine.logs", { data_b64: Buffer.from("booted\n").toString("base64") });
    const machine = new mvm.Machine("devbox");
    expect(machine.logs()).toBe("booted\n");
    machine.logs({ lines: 20 });
    expect(host.requests("machine.logs")).toEqual([{ id: "devbox" }, { id: "devbox", tail_lines: 20 }]);
  });

  it("propagates typed errors with their flags", () => {
    host.on("machine.rm", failure("CONFLICT", "stop it first", { status: 5 }));
    try {
      new mvm.Machine("devbox").rm();
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(mvm.MachineConflictError);
      const f = err as mvm.HostLibraryFailure;
      expect([f.code, f.retryable, f.status, f.message]).toEqual(["CONFLICT", false, 5, "stop it first"]);
    }
  });

  it("rejects an empty name without a call", () => {
    expect(() => new mvm.Machine("")).toThrow(TypeError);
    expect(host.calls).toEqual([]);
  });

  it("pause and resume send only what was asked", () => {
    const sealed = { epoch: 3, vmstate_len: 12, mem_len: 8 };
    host
      .on("machine.pause", sealed, sealed)
      .on("machine.resume", { ...sealed, reseed: "ok" }, { epoch: 0, vmstate_len: 0, mem_len: 0, reseed: "ok" });
    const machine = new mvm.Machine("devbox");
    expect(machine.pause()).toEqual(sealed);
    expect(machine.pause({ primedBarrier: true, primedTimeout: 30 }).epoch).toBe(3);
    expect(machine.resume().reseed).toBe("ok");
    expect(machine.resume({ warm: true }).epoch).toBe(0);
    expect(host.calls).toEqual([
      { method: "machine.pause", request: { id: "devbox" } },
      { method: "machine.pause", request: { id: "devbox", primed_barrier: true, primed_timeout_secs: 30 } },
      { method: "machine.resume", request: { id: "devbox" } },
      { method: "machine.resume", request: { id: "devbox", warm: true } },
    ]);
  });

  it("propagates a refused resume as the library's typed error", () => {
    host.on("machine.resume", failure("BACKEND_ERROR", "snapshot epoch 2 is older than 3", { status: 3 }));
    expect(() => new mvm.Machine("devbox").resume()).toThrow(mvm.MachineBackendError);
  });

  it("reconfigure sends only the fields it changes", () => {
    host.on("machine.reconfigure", { ...STATE, status: "running" }, STATE);
    const machine = new mvm.Machine("devbox");
    expect(machine.reconfigure({ cpus: 2 }).status).toBe("running");
    expect(machine.reconfigure({ cpus: 4, memoryMib: 1024 }).status).toBe("stopped");
    expect(host.requests("machine.reconfigure")).toEqual([
      { id: "devbox", cpus: 2 },
      { id: "devbox", cpus: 4, memory_mib: 1024 },
    ]);
  });

  it("setTtl sets and clears the expiry", () => {
    host.on("machine.set_ttl", {}, {});
    const machine = new mvm.Machine("devbox");
    expect(machine.setTtl("2030-01-02T03:04:05Z")).toBeUndefined();
    expect(machine.setTtl(null)).toBeUndefined();
    expect(host.requests("machine.set_ttl")).toEqual([
      { id: "devbox", expires_at: "2030-01-02T03:04:05Z" },
      { id: "devbox", expires_at: null },
    ]);
  });

  it("refuses bad lifecycle arguments before any call", () => {
    const machine = new mvm.Machine("devbox");
    expect(() => machine.pause({ primedTimeout: 0 })).toThrow(RangeError);
    expect(() => machine.pause({ primedBarrier: "yes" as unknown as boolean })).toThrow(TypeError);
    expect(() => machine.resume({ warm: 1 as unknown as boolean })).toThrow(TypeError);
    expect(() => machine.reconfigure({})).toThrow(TypeError);
    expect(() => machine.reconfigure({ cpus: 0 })).toThrow(RangeError);
    expect(() => machine.reconfigure({ memoryMib: -1 })).toThrow(RangeError);
    expect(() => machine.setTtl("")).toThrow(TypeError);
    expect(host.calls).toEqual([]);
  });
});

describe("Machine.exec", () => {
  it("starts through guest.proc.start and collects through the stream", () => {
    host
      .on("guest.proc.start", { token: "t1" })
      .on("guest.proc.stream.open", { stream: 3 })
      .on("guest.proc.stream.next", batch([["stdout", "hel"]]), batch([["stdout", "lo"], ["stderr", "!"]], { kind: "exited", code: 1 }));
    const result = new mvm.Machine("devbox").exec(["echo", "hello"], { cwd: "/w", env: { K: "v" }, timeout: 5 });
    expect(result).toEqual({ exitCode: 1, stdout: "hello", stderr: "!" });
    expect(host.calls).toEqual([
      { method: "guest.proc.start", request: { id: "devbox", argv: ["echo", "hello"], env: { K: "v" }, cwd: "/w" } },
      { method: "guest.proc.stream.open", request: { id: "devbox", token: "t1", timeout_secs: 5 } },
      { method: "guest.proc.stream.next", request: { stream: 3 } },
      { method: "guest.proc.stream.next", request: { stream: 3 } },
    ]);
  });

  it("surfaces a production machine's refusal as MachineBackendError", () => {
    host.on("guest.proc.start", failure("BACKEND_ERROR", "DevOnly verbs are refused on a sealed machine"));
    expect(() => new mvm.Machine("sealed").exec(["id"])).toThrow(mvm.MachineBackendError);
  });

  it("refuses an empty command without a call", () => {
    expect(() => new mvm.Machine("devbox").exec([])).toThrow(RangeError);
    expect(host.calls).toEqual([]);
  });
});
