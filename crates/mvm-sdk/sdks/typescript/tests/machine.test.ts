/**
 * `Machine` over the host library.
 *
 * The library is replaced by a recorder, so each test pins the exact request
 * a facade method sends and how the reply comes back.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

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
  it("sends the minimal transient request and returns a handle", () => {
    host.on("machine.run", runReply("gen-1", "dev"));
    const machine = mvm.Machine.run("alpine:latest");
    expect(machine).toBeInstanceOf(mvm.Machine);
    expect(machine.name).toBe("gen-1");
    expect(host.calls).toEqual([
      { method: "machine.run", request: { image: "alpine:latest", mode: "transient" } },
    ]);
  });

  it("sends every option under the library's field names", () => {
    host.on("machine.run", runReply("web", "prod"));
    mvm.Machine.run("alpine:latest", {
      name: "web",
      command: ["uname", "-a"],
      env: { A: "1" },
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
        mode: "transient",
        name: "web",
        command: ["uname", "-a"],
        env: { A: "1" },
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
    mvm.Machine.run("alpine:latest", { command: [], env: {}, allowHosts: [], ports: [] });
    expect(host.requests("machine.run")).toEqual([{ image: "alpine:latest", mode: "transient" }]);
  });

  it("passes a command through so the library's refusal is the one raised", () => {
    host.on("machine.run", failure("INVALID_SPEC", "command overrides are not supported yet"));
    try {
      mvm.Machine.run("alpine:latest", { command: ["true"] });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(mvm.MachineSpecError);
      expect((err as mvm.HostLibraryFailure).code).toBe("INVALID_SPEC");
    }
    expect(host.requests("machine.run")[0].command).toEqual(["true"]);
  });

  it("refuses bad arguments before any call", () => {
    expect(() => mvm.Machine.run("")).toThrow(TypeError);
    expect(() => mvm.Machine.run("img", { cpus: 0 })).toThrow(RangeError);
    expect(() => mvm.Machine.run("img", { allowHosts: ["example.com"] })).toThrow(mvm.MachineError);
    expect(host.calls).toEqual([]);
  });

  it("reports a reply with no machine name as MachineError", () => {
    host.on("machine.run", { machine: {}, build_mode: "dev" });
    expect(() => mvm.Machine.run("img")).toThrow(mvm.MachineError);
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
