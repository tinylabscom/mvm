/**
 * Live-mode Sandbox tests.
 *
 * Mirrors `sdks/python/tests/test_sandbox_live.py`. The host library is
 * replaced through `setInvokeForTesting` by a recorder that answers from
 * canned replies, so each test asserts the exact `(method, request)` sequence
 * the SDK sends. Nothing loads a library and no microVM boots.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";

import * as mvm from "../src/index.js";
import { deriveAttachedBuildMode, parseRunReply } from "../src/_sandbox.js";
import { HostRecorder, batch, failure, runReply, uninstallRecorder } from "./_recorder.js";

const IMAGE = "docker.io/library/python:3.12-slim";

let tmpDir: string;
let host: HostRecorder;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvm-sdk-live-"));
  mvm.resetRecording();
  delete process.env.MVM_SDK_MODE;
  delete process.env.MVM_SDK_RUN_PROFILE;
  host = new HostRecorder().install();
});

afterEach(() => {
  uninstallRecorder();
  mvm.resetRecording();
  delete process.env.MVM_SDK_MODE;
  delete process.env.MVM_SDK_RUN_PROFILE;
  vi.restoreAllMocks();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

/** Boot a live sandbox against a canned `machine.run` reply. */
function boot(buildMode: "dev" | "prod", name = "sb-vm", options: mvm.SandboxCreateOptions = {}): mvm.Sandbox {
  process.env.MVM_SDK_MODE = "live";
  host.on("machine.run", runReply(name, buildMode)).on("machine.stop", {});
  return mvm.Sandbox.create({ image: IMAGE }, { workloadId: "testwid", ...options });
}

/** Answer a started process's stream with `batches`. */
function streamReplies(...batches: Array<Record<string, unknown> | ReturnType<typeof failure>>): void {
  host
    .on("guest.proc.start", { token: "tok-1" })
    .on("guest.proc.stream.open", { stream: 7 })
    .on("guest.proc.stream.next", ...batches)
    .on("guest.proc.stream.close", {});
}

const guestCalls = () => host.methods().filter((m) => m.startsWith("guest."));

// ── reply parsing ────────────────────────────────────────────────────

describe("parseRunReply", () => {
  it("reads the machine name and build mode", () => {
    expect(parseRunReply(runReply("sb-xyz", "dev"))).toEqual({ vmId: "sb-xyz", buildMode: "dev" });
  });

  it("rejects a reply with no machine name", () => {
    expect(() => parseRunReply({ machine: {}, build_mode: "dev" })).toThrow(mvm.SandboxLiveError);
  });

  it("rejects an unknown build_mode", () => {
    expect(() => parseRunReply({ machine: { name: "x" }, build_mode: "staging" })).toThrow(/build_mode/);
  });

  it("rejects a non-object reply", () => {
    expect(() => parseRunReply(null)).toThrow(/no reply object/);
  });
});

describe("deriveAttachedBuildMode", () => {
  it("matches on name and returns the record's build_mode", () => {
    const records = [
      { name: "a", build_mode: "prod", status: "running" },
      { name: "b", build_mode: "dev", status: "running" },
    ];
    expect(deriveAttachedBuildMode(records, "b")).toBe("dev");
    expect(deriveAttachedBuildMode(records, "a")).toBe("prod");
  });

  it("fails closed on a missing or unknown build_mode", () => {
    expect(deriveAttachedBuildMode([{ name: "a" }], "a")).toBe("prod");
    expect(deriveAttachedBuildMode([{ name: "a", build_mode: "staging" }], "a")).toBe("prod");
  });

  it("throws when the machine is absent", () => {
    expect(() => deriveAttachedBuildMode([{ name: "other", build_mode: "dev" }], "ghost")).toThrow(
      /no machine named "ghost"/,
    );
  });

  it("throws on a non-array inventory", () => {
    expect(() => deriveAttachedBuildMode({}, "a")).toThrow(/must return an array/);
  });
});

// ── connect ──────────────────────────────────────────────────────────

describe("Sandbox.connect (attach; inherits the dev-only guard)", () => {
  it("attaches to a dev machine through machine.inventory and allows exec", () => {
    host.on("machine.inventory", [
      { name: "web-1", build_mode: "dev", status: "running" },
      { name: "other", build_mode: "prod", status: "running" },
    ]);
    streamReplies(batch([["stdout", "hi"]], { kind: "exited", code: 0 }));

    const sb = mvm.Sandbox.connect("web-1");
    expect(sb.info()).toEqual({ id: "web-1", workloadId: "web-1", buildMode: "dev", live: true });
    expect(sb.exec(["echo", "hi"]).stdout).toBe("hi");
    expect(host.calls[0]).toEqual({ method: "machine.inventory", request: undefined });
    expect(host.requests("guest.proc.start")).toEqual([{ id: "web-1", argv: ["echo", "hi"] }]);
  });

  it("refuses exec on a prod machine before any guest call", () => {
    host.on("machine.inventory", [{ name: "sealed", build_mode: "prod" }]);
    const sb = mvm.Sandbox.connect("sealed");
    expect(() => sb.exec(["id"])).toThrow(mvm.SandboxDevOnly);
    expect(host.methods()).toEqual(["machine.inventory"]);
  });

  it("treats a missing build_mode as prod", () => {
    host.on("machine.inventory", [{ name: "m" }]);
    expect(() => mvm.Sandbox.connect("m").commands.start(["id"])).toThrow(mvm.SandboxDevOnly);
    expect(guestCalls()).toEqual([]);
  });

  it("throws SandboxLiveError when the machine is not listed", () => {
    host.on("machine.inventory", []);
    expect(() => mvm.Sandbox.connect("ghost")).toThrow(mvm.SandboxLiveError);
  });

  it("propagates a typed inventory failure", () => {
    host.on("machine.inventory", failure("UNAVAILABLE", "backend busy", { retryable: true }));
    try {
      mvm.Sandbox.connect("m");
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(mvm.MachineUnavailableError);
      expect((err as mvm.HostLibraryFailure).code).toBe("UNAVAILABLE");
      expect((err as mvm.HostLibraryFailure).retryable).toBe(true);
    }
  });

  it("refuses a second concurrent session", () => {
    host.on("machine.inventory", [{ name: "a", build_mode: "dev" }]);
    mvm.Sandbox.connect("a");
    expect(() => mvm.Sandbox.connect("a")).toThrow(/already active/);
  });

  it("rejects an empty id", () => {
    expect(() => mvm.Sandbox.connect("")).toThrow(TypeError);
    expect(host.calls).toEqual([]);
  });
});

// ── create ───────────────────────────────────────────────────────────

describe("Sandbox.create (live mode)", () => {
  it("sends one machine.run and records the reply's name and build mode", () => {
    const sb = boot("dev", "sb-test-vm");
    expect(sb._live!.vmId).toBe("sb-test-vm");
    expect(sb._live!.buildMode).toBe("dev");
    expect(host.methods()).toEqual(["machine.run"]);
    const request = host.requests("machine.run")[0];
    expect(Object.keys(request).sort()).toEqual(["image", "mode", "name", "ttl_seconds"]);
    expect(request.image).toBe(IMAGE);
    expect(request.mode).toBe("transient");
    expect(request.ttl_seconds).toBe(mvm.DEFAULT_TTL_SECONDS);
    expect(request.name).toMatch(/^sdk-testwid-[0-9a-f]{8}$/);
  });

  it("slugs the workload id into the generated name", () => {
    process.env.MVM_SDK_MODE = "live";
    host.on("machine.run", runReply("x", "dev"));
    mvm.Sandbox.create({ image: IMAGE });
    expect(host.requests("machine.run")[0].name).toMatch(/^sdk-docker-io-library-python-[0-9a-f]{8}$/);
  });

  it("carries an explicit ttl", () => {
    boot("dev", "vm", { ttl: "5m" });
    expect(host.requests("machine.run")[0].ttl_seconds).toBe(300);
  });

  it("propagates an explicit dev profile", () => {
    process.env[mvm.MVM_SDK_RUN_PROFILE_ENV] = " Dev ";
    boot("dev");
    expect(host.requests("machine.run")[0].profile).toBe("dev");
  });

  it("rejects an unknown profile before any call", () => {
    process.env[mvm.MVM_SDK_RUN_PROFILE_ENV] = "unknown";
    expect(() => boot("dev")).toThrow(/MVM_SDK_RUN_PROFILE/);
    expect(host.calls).toEqual([]);
  });

  it("lowers the egress allowlist and boot command", () => {
    boot("dev", "browser", {
      network: {
        mode: "none",
        egress: { allowlist: [{ host: "example.com", port: 443 }, { host: "[2001:db8::1]", port: 8443 }] },
      },
      command: ["/obscura", "serve"],
    });
    const request = host.requests("machine.run")[0];
    expect(request.egress).toEqual([
      { host: "example.com", port: 443 },
      { host: "2001:db8::1", port: 8443 },
    ]);
    expect(request.command).toEqual(["/obscura", "serve"]);
  });

  it("refuses a wildcard or out-of-range egress entry before any call", () => {
    process.env.MVM_SDK_MODE = "live";
    for (const entry of [{ host: "*", port: 443 }, { host: "example.com", port: 0 }]) {
      expect(() =>
        mvm.Sandbox.create({ image: IMAGE }, { network: { mode: "none", egress: { allowlist: [entry] } } as never }),
      ).toThrow(mvm.SandboxModeError);
    }
    expect(host.calls).toEqual([]);
  });

  it("refuses a template source before any call", () => {
    process.env.MVM_SDK_MODE = "live";
    expect(() => mvm.Sandbox.create("python-3.12")).toThrow(mvm.SandboxModeError);
    expect(() => mvm.Sandbox.create({ manifest: "python-3.12" })).toThrow(/pass .*image/i);
    expect(host.calls).toEqual([]);
  });

  it("refuses env and unrepresentable options before any call", () => {
    process.env.MVM_SDK_MODE = "live";
    expect(() => mvm.Sandbox.create({ image: IMAGE }, { env: { MODE: "safe" } })).toThrow(
      /Sandbox\.commands\.start/,
    );
    expect(() =>
      mvm.Sandbox.create({ image: IMAGE }, { resources: { cpu_cores: 1, memory_mb: 256, rootfs_size_mb: 512 } }),
    ).toThrow(/resources/);
    expect(() =>
      mvm.Sandbox.create({ image: IMAGE }, { network: { raw_ip_stack: true } as never }),
    ).toThrow(/unknown fields/);
    expect(() => mvm.Sandbox.create({ image: IMAGE }, { include: ["src"] })).toThrow(/include/);
    expect(() => mvm.Sandbox.create({ image: IMAGE }, { tags: { a: "b" } })).toThrow(/tags/);
    expect(host.calls).toEqual([]);
  });

  it("propagates the library's typed refusal", () => {
    process.env.MVM_SDK_MODE = "live";
    host.on("machine.run", failure("INVALID_SPEC", "a command override is not supported", { status: 3 }));
    try {
      mvm.Sandbox.create({ image: IMAGE }, { command: ["true"] });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(mvm.MachineSpecError);
      expect(err).toBeInstanceOf(mvm.HostLibraryError);
      const f = err as mvm.HostLibraryFailure;
      expect([f.code, f.retryable, f.status]).toEqual(["INVALID_SPEC", false, 3]);
      expect(f.message).toBe("a command override is not supported");
    }
  });

  it("reports a malformed reply as SandboxLiveError", () => {
    process.env.MVM_SDK_MODE = "live";
    host.on("machine.run", { plan_id: "p" });
    expect(() => mvm.Sandbox.create({ image: IMAGE })).toThrow(mvm.SandboxLiveError);
  });

  it("enforces one sandbox per process", () => {
    boot("dev");
    expect(() => mvm.Sandbox.create({ image: IMAGE })).toThrow(/already active/);
    expect(host.methods()).toEqual(["machine.run"]);
  });
});

// ── processes ────────────────────────────────────────────────────────

describe("Sandbox.commands.start (live mode)", () => {
  it("sends guest.proc.start with literal env and returns the token's handle", () => {
    const sb = boot("dev", "sb-dev-vm");
    host.on("guest.proc.start", { token: "tok-9" });
    const handle = sb.commands.start(["python", "-c", "print(1)"], {
      env: { A: "1", B: mvm.literal("2") },
    });
    expect(handle!.token).toBe("tok-9");
    expect(host.requests("guest.proc.start")).toEqual([
      { id: "sb-dev-vm", argv: ["python", "-c", "print(1)"], env: { A: "1", B: "2" } },
    ]);
  });

  it("omits env when none is given", () => {
    const sb = boot("dev", "vm");
    host.on("guest.proc.start", { token: "t" });
    sb.commands.start(["true"]);
    expect(host.requests("guest.proc.start")).toEqual([{ id: "vm", argv: ["true"] }]);
  });

  it("refuses a secret env value before any guest call", () => {
    const sb = boot("dev");
    const secret = mvm.secret("api-key", { type: "bearer", hosts: ["api.example.com"] });
    expect(() => sb.commands.start(["true"], { env: { KEY: secret } })).toThrow(/non-literal/);
    expect(guestCalls()).toEqual([]);
  });

  it("raises SandboxDevOnly against a prod machine with zero guest calls", () => {
    const sb = boot("prod");
    try {
      sb.commands.start(["id"]);
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(mvm.SandboxDevOnly);
      expect(err).toBeInstanceOf(mvm.SandboxLiveError);
      expect((err as mvm.SandboxLiveError).code).toBe("DEV_ONLY");
    }
    expect(guestCalls()).toEqual([]);
  });

  it("returns undefined and records the op in record mode", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    expect(sb.commands.start(["true"])).toBeUndefined();
    expect(host.calls).toEqual([]);
  });
});

describe("ProcessHandle", () => {
  it("streams output across batches, in order, and maps the exit code", async () => {
    const sb = boot("dev", "vm");
    streamReplies(
      batch([["stdout", "a"], ["stderr", "x"]]),
      batch([]),
      batch([["stdout", "b"]], { kind: "exited", code: 3 }),
    );
    const events: string[] = [];
    const handle = sb.commands.start(["job"])!;
    const result = await handle.wait({
      timeout: 9.7,
      onEvent: (e) => events.push(`${e.stream}:${new TextDecoder().decode(e.data)}`),
    });
    expect(events).toEqual(["stdout:a", "stderr:x", "stdout:b"]);
    expect(result.exitCode).toBe(3);
    expect(new TextDecoder().decode(result.stdout)).toBe("ab");
    expect(new TextDecoder().decode(result.stderr)).toBe("x");
    expect(host.requests("guest.proc.stream.open")).toEqual([{ id: "vm", token: "tok-1", timeout_secs: 9 }]);
    expect(host.requests("guest.proc.stream.next")).toEqual([{ stream: 7 }, { stream: 7 }, { stream: 7 }]);
    // A stream that reported done is gone on the library's side.
    expect(host.requests("guest.proc.stream.close")).toEqual([]);
  });

  it("omits timeout_secs when no timeout is given", async () => {
    const sb = boot("dev", "vm");
    streamReplies(batch([], { kind: "exited", code: 0 }));
    await sb.commands.start(["job"])!.wait();
    expect(host.requests("guest.proc.stream.open")).toEqual([{ id: "vm", token: "tok-1" }]);
  });

  it.each([
    [{ kind: "exited", code: 0 } as const, 0],
    [{ kind: "exited", code: 2 } as const, 2],
    [{ kind: "killed", signal: 9 } as const, 137],
    [{ kind: "timed_out" } as const, 124],
  ])("maps outcome %j to exit code %i", async (outcome, code) => {
    const sb = boot("dev");
    streamReplies(batch([], outcome));
    expect((await sb.commands.start(["job"])!.wait()).exitCode).toBe(code);
  });

  it("closes the stream when onEvent throws, and rejects with that error", async () => {
    const sb = boot("dev");
    streamReplies(batch([["stdout", "a"]]), batch([], { kind: "exited", code: 0 }));
    const handle = sb.commands.start(["job"])!;
    await expect(
      handle.wait({
        onEvent: () => {
          throw new Error("consumer failed");
        },
      }),
    ).rejects.toThrow("consumer failed");
    expect(host.requests("guest.proc.stream.close")).toEqual([{ stream: 7 }]);
  });

  it("delivers output before a failed wait, then rejects with the typed error and closes", async () => {
    const sb = boot("dev");
    streamReplies(batch([["stdout", "partial"]]), failure("BACKEND_ERROR", "the guest agent went away"));
    const seen: string[] = [];
    const handle = sb.commands.start(["job"])!;
    await expect(
      handle.wait({ onEvent: (e) => seen.push(new TextDecoder().decode(e.data)) }),
    ).rejects.toBeInstanceOf(mvm.MachineBackendError);
    expect(seen).toEqual(["partial"]);
    expect(host.requests("guest.proc.stream.close")).toEqual([{ stream: 7 }]);
  });

  it("closes the stream on a malformed batch", async () => {
    const sb = boot("dev");
    streamReplies({ done: false });
    await expect(sb.commands.start(["job"])!.wait()).rejects.toBeInstanceOf(mvm.SandboxLiveError);
    expect(host.requests("guest.proc.stream.close")).toEqual([{ stream: 7 }]);
  });

  it("rejects an outcome it does not understand", async () => {
    const sb = boot("dev");
    streamReplies({ events: [], done: true, outcome: { kind: "vanished" } });
    await expect(sb.commands.start(["job"])!.wait()).rejects.toThrow(/does not understand/);
  });

  it("sends stdin, signal, and kill for the handle's token", () => {
    const sb = boot("dev", "vm");
    host
      .on("guest.proc.start", { token: "tok-1" })
      .on("guest.proc.stdin", { accepted: 5 })
      .on("guest.proc.signal", {})
      .on("guest.proc.kill", {});
    const handle = sb.commands.start(["cat"])!;
    handle.sendStdin("hello");
    handle.sendStdin(new Uint8Array([0, 255]));
    handle.signal(15);
    handle.kill();
    expect(host.requests("guest.proc.stdin")).toEqual([
      { id: "vm", token: "tok-1", data_b64: Buffer.from("hello").toString("base64") },
      { id: "vm", token: "tok-1", data_b64: "AP8=" },
    ]);
    expect(host.requests("guest.proc.signal")).toEqual([{ id: "vm", token: "tok-1", signum: 15 }]);
    expect(host.requests("guest.proc.kill")).toEqual([{ id: "vm", token: "tok-1" }]);
    expect(() => handle.signal(0)).toThrow(RangeError);
  });
});

// ── exec ─────────────────────────────────────────────────────────────

describe("Sandbox.exec (live mode)", () => {
  it("starts with cwd and env, then collects through the stream", () => {
    const sb = boot("dev", "vm");
    streamReplies(batch([["stdout", "out\n"], ["stderr", "err\n"]], { kind: "exited", code: 0 }));
    const result = sb.exec(["sh", "-c", "run"], { cwd: "/work", env: { K: "v" }, timeout: 30 });
    expect(result).toEqual({ exitCode: 0, stdout: "out\n", stderr: "err\n" });
    expect(host.methods()).toEqual([
      "machine.run",
      "guest.proc.start",
      "guest.proc.stream.open",
      "guest.proc.stream.next",
    ]);
    expect(host.requests("guest.proc.start")).toEqual([
      { id: "vm", argv: ["sh", "-c", "run"], env: { K: "v" }, cwd: "/work" },
    ]);
    expect(host.requests("guest.proc.stream.open")).toEqual([{ id: "vm", token: "tok-1", timeout_secs: 30 }]);
  });

  it("surfaces a non-zero exit code", () => {
    const sb = boot("dev");
    streamReplies(batch([], { kind: "exited", code: 3 }));
    expect(sb.exec(["false"]).exitCode).toBe(3);
  });

  it("decodes invalid UTF-8 with replacement", () => {
    const sb = boot("dev");
    streamReplies({
      events: [{ stream: "stdout", data_b64: Buffer.from([0x61, 0xff, 0x62]).toString("base64") }],
      done: true,
      outcome: { kind: "exited", code: 0 },
    });
    expect(sb.exec(["cat"]).stdout).toBe("a�b");
  });

  it("shell runs /bin/sh -lc", () => {
    const sb = boot("dev");
    streamReplies(batch([], { kind: "exited", code: 0 }));
    sb.shell("echo $HOME");
    expect(host.requests("guest.proc.start")[0].argv).toEqual(["/bin/sh", "-lc", "echo $HOME"]);
  });

  it("raises SandboxDevOnly against a prod machine with zero guest calls", () => {
    const sb = boot("prod");
    expect(() => sb.exec(["id"])).toThrow(mvm.SandboxDevOnly);
    expect(guestCalls()).toEqual([]);
  });

  it("is refused in record mode", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    expect(() => sb.exec(["id"])).toThrow(mvm.SandboxModeError);
  });
});

// ── files ────────────────────────────────────────────────────────────

describe("Sandbox.files (live mode)", () => {
  it("sends each guest.fs request", () => {
    const sb = boot("dev", "vm");
    host
      .on("guest.fs.write", { bytes_written: 2 })
      .on("guest.fs.read", { data_b64: Buffer.from("hi").toString("base64") })
      .on("guest.fs.list", { entries: [{ name: "a", kind: "file", size: 1 }], truncated: false })
      .on("guest.fs.stat", { canonical_path: "/a", kind: "file", size: 1, mode: 420, mtime: null })
      .on("guest.fs.mkdir", {})
      .on("guest.fs.remove", { entries_removed: 1 })
      .on("guest.fs.rename", {});

    sb.files.write("/a", "hi");
    sb.files.write("/b", new Uint8Array([1]), { mode: 0o600, createParents: true, followSymlinks: true });
    expect(new TextDecoder().decode(sb.files.read("/a"))).toBe("hi");
    sb.files.read("/a", 4, 8);
    expect(sb.files.list("/")).toEqual([{ name: "a", kind: "file", size: 1 }]);
    expect(sb.files.stat("/a").canonical_path).toBe("/a");
    sb.files.stat("/link", false);
    sb.files.mkdir("/d");
    sb.files.mkdir("/d/e", true, 0o700);
    sb.files.remove("/a");
    sb.files.remove("/d", true);
    sb.files.move("/x", "/y");

    expect(host.calls.slice(1)).toEqual([
      {
        method: "guest.fs.write",
        request: { id: "vm", path: "/a", data_b64: "aGk=", mode: 0o644, create_parents: false, follow_symlinks: false },
      },
      {
        method: "guest.fs.write",
        request: { id: "vm", path: "/b", data_b64: "AQ==", mode: 0o600, create_parents: true, follow_symlinks: true },
      },
      { method: "guest.fs.read", request: { id: "vm", path: "/a", offset: 0, length: 16 * 1024 * 1024 } },
      { method: "guest.fs.read", request: { id: "vm", path: "/a", offset: 4, length: 8 } },
      { method: "guest.fs.list", request: { id: "vm", path: "/" } },
      { method: "guest.fs.stat", request: { id: "vm", path: "/a", follow_symlinks: true } },
      { method: "guest.fs.stat", request: { id: "vm", path: "/link", follow_symlinks: false } },
      { method: "guest.fs.mkdir", request: { id: "vm", path: "/d", mode: 0o755, parents: false } },
      { method: "guest.fs.mkdir", request: { id: "vm", path: "/d/e", mode: 0o700, parents: true } },
      { method: "guest.fs.remove", request: { id: "vm", path: "/a", recursive: false } },
      { method: "guest.fs.remove", request: { id: "vm", path: "/d", recursive: true } },
      { method: "guest.fs.rename", request: { id: "vm", from: "/x", to: "/y" } },
    ]);
  });

  it("propagates a typed guest refusal unchanged", () => {
    const sb = boot("dev");
    host.on("guest.fs.read", failure("NOT_FOUND", "no such file"));
    expect(() => sb.files.read("/missing")).toThrow(mvm.MachineNotFoundError);
  });

  it("refuses every development-only verb on prod with zero guest calls", () => {
    const sb = boot("prod");
    const operations: Array<() => unknown> = [
      () => sb.files.write("/a", "x"),
      () => sb.files.read("/a"),
      () => sb.files.list("/"),
      () => sb.files.stat("/a"),
      () => sb.files.mkdir("/d"),
      () => sb.files.remove("/a"),
      () => sb.files.move("/a", "/b"),
      () => sb.copyIn(path.join(tmpDir, "f"), "/f"),
      () => sb.copyOut("/f", path.join(tmpDir, "f")),
      () => sb.commands.start(["id"]),
      () => sb.exec(["id"]),
      () => sb.shell("id"),
    ];
    for (const operation of operations) {
      expect(operation).toThrow(mvm.SandboxDevOnly);
    }
    expect(guestCalls()).toEqual([]);
  });

  it("refuses reads and mutations in record mode", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    expect(() => sb.files.read("/a")).toThrow(mvm.SandboxModeError);
    expect(() => sb.files.list("/")).toThrow(mvm.SandboxModeError);
    expect(() => sb.files.move("/a", "/b")).toThrow(mvm.SandboxModeError);
    expect(host.calls).toEqual([]);
  });
});

describe("Sandbox.copyIn / copyOut (live mode)", () => {
  it("sends guest.cp in each direction", () => {
    const sb = boot("dev", "vm");
    host.on("guest.cp", {});
    sb.copyIn("/host/in.txt", "/guest/in.txt");
    sb.copyOut("/guest/out.txt", "/host/out.txt");
    expect(host.requests("guest.cp")).toEqual([
      { id: "vm", direction: "host_to_guest", host_path: "/host/in.txt", guest_path: "/guest/in.txt" },
      { id: "vm", direction: "guest_to_host", host_path: "/host/out.txt", guest_path: "/guest/out.txt" },
    ]);
  });

  it("propagates a typed copy failure", () => {
    const sb = boot("dev");
    host.on("guest.cp", failure("BACKEND_ERROR", "copy failed"));
    expect(() => sb.copyIn("/h", "/g")).toThrow(mvm.MachineBackendError);
  });

  it("is refused in record mode", () => {
    const sb = mvm.Sandbox.create("python-3.12");
    expect(() => sb.copyIn("/h", "/g")).toThrow(mvm.SandboxModeError);
    expect(() => sb.copyOut("/g", "/h")).toThrow(mvm.SandboxModeError);
  });
});

// ── kill ─────────────────────────────────────────────────────────────

describe("Sandbox.kill (live mode)", () => {
  it("sends machine.stop once, however often it is called", () => {
    const sb = boot("dev", "vm");
    sb.kill();
    sb._live!.kill();
    expect(host.requests("machine.stop")).toEqual([{ id: "vm" }]);
  });

  it("writes a stop failure to stderr instead of throwing", () => {
    const sb = boot("dev", "vm");
    host.on("machine.stop", failure("BACKEND_ERROR", "already gone"));
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect(() => sb.kill()).not.toThrow();
    expect(errors).toHaveBeenCalledWith(expect.stringContaining("already gone"));
  });

  it("frees the process slot so another sandbox can start", () => {
    const sb = boot("dev", "vm");
    sb.kill();
    mvm.Sandbox.create({ image: IMAGE });
    expect(host.requests("machine.run")).toHaveLength(2);
  });

  it("[Symbol.dispose] and [Symbol.asyncDispose] stop the machine", async () => {
    const first = boot("dev", "one");
    first[Symbol.dispose]();
    const second = mvm.Sandbox.create({ image: IMAGE });
    await second[Symbol.asyncDispose]();
    expect(host.requests("machine.stop")).toEqual([{ id: "one" }, { id: "one" }]);
  });
});

// ── forward / ports ──────────────────────────────────────────────────

describe("ingress", () => {
  it("refuses dynamic forwarding", () => {
    const sb = boot("dev");
    expect(() => sb.forward(8080, 80)).toThrow(/declare ingress/);
    expect(() => sb.forward(0, 80)).toThrow(RangeError);
  });

  it("passes declared opaque TCP ingress to machine.run", () => {
    boot("dev", "vm", {
      network: {
        mode: "none",
        ports: [
          {
            mapping_id: 1,
            proto: "tcp",
            host_addr: "127.0.0.1",
            host: 18080,
            guest_addr: "127.0.0.1",
            guest: 8080,
            transform: "opaque",
          },
        ],
      },
    });
    expect(host.requests("machine.run")[0].ports).toEqual(["18080:8080"]);
  });

  it("refuses ingress that is not opaque loopback TCP", () => {
    process.env.MVM_SDK_MODE = "live";
    expect(() =>
      mvm.Sandbox.create(
        { image: IMAGE },
        {
          network: {
            mode: "none",
            ports: [
              { mapping_id: 1, proto: "tcp", host_addr: "0.0.0.0", host: 1, guest_addr: "127.0.0.1", guest: 1, transform: "opaque" },
            ],
          },
        },
      ),
    ).toThrow(/127\.0\.0\.1/);
    expect(host.calls).toEqual([]);
  });
});

// ── surface ──────────────────────────────────────────────────────────

describe("Sandbox id + info", () => {
  it("is the machine name when live", () => {
    const sb = boot("prod", "sb-info");
    expect(sb.id).toBe("sb-info");
    expect(sb.info()).toEqual({ id: "sb-info", workloadId: "testwid", buildMode: "prod", live: true });
  });

  it("is the workload id in record mode", () => {
    const sb = mvm.Sandbox.create("python-3.12", { workloadId: "wid" });
    expect(sb.info()).toEqual({ id: "wid", workloadId: "wid", buildMode: null, live: false });
  });

  it("await sb.exec(...) passes the synchronous result through", async () => {
    const sb = boot("dev");
    streamReplies(batch([["stdout", "ok"]], { kind: "exited", code: 0 }));
    expect((await sb.exec(["true"])).stdout).toBe("ok");
  });
});

describe("SandboxLiveError", () => {
  it("carries its message and an optional code", () => {
    expect(new mvm.SandboxLiveError("plain refusal").message).toBe("plain refusal");
    expect(new mvm.SandboxLiveError("plain refusal").code).toBeUndefined();
    expect(new mvm.SandboxLiveError("gone", { code: "NOT_FOUND" }).code).toBe("NOT_FOUND");
  });
});

// ── typed helpers ────────────────────────────────────────────────────

describe("CodeSandbox", () => {
  function codeSandbox(image: string, stdout = "", code = 0): mvm.CodeSandbox {
    process.env.MVM_SDK_MODE = "live";
    host.on("machine.run", runReply("sb-cs-vm", "dev")).on("machine.stop", {}).on("guest.cp", {});
    streamReplies(batch(stdout ? [["stdout", stdout]] : [], { kind: "exited", code }));
    return new mvm.CodeSandbox(image);
  }

  it("run() returns stdout via python -c", () => {
    const cs = codeSandbox("python:slim", "4");
    try {
      expect(cs.run("print(2 + 2)")).toBe("4");
      expect(host.requests("machine.run")[0].image).toBe("python:slim");
      expect(host.requests("guest.proc.start")[0]).toEqual({
        id: "sb-cs-vm",
        argv: ["python", "-c", "print(2 + 2)"],
      });
    } finally {
      cs.kill();
    }
  });

  it("run() throws CodeError on a non-zero exit", () => {
    const cs = codeSandbox("python:slim", "", 1);
    try {
      expect(() => cs.run("import sys; sys.exit(1)")).toThrow(mvm.CodeError);
    } finally {
      cs.kill();
    }
  });

  it("installPackage() runs the package manager", () => {
    const cs = codeSandbox("python:slim");
    try {
      cs.installPackage("requests");
      expect(host.requests("guest.proc.start")[0].argv).toEqual(["pip", "install", "requests"]);
    } finally {
      cs.kill();
    }
  });

  it("runScript() copies then runs the script", () => {
    const cs = codeSandbox("python:slim", "ok");
    const script = path.join(tmpDir, "job.py");
    fs.writeFileSync(script, "print('ok')");
    try {
      expect(cs.runScript(script)).toBe("ok");
      expect(host.requests("guest.cp")).toEqual([
        { id: "sb-cs-vm", direction: "host_to_guest", host_path: script, guest_path: "/tmp/job.py" },
      ]);
      expect(host.requests("guest.proc.start")[0].argv).toEqual(["python", "/tmp/job.py"]);
    } finally {
      cs.kill();
    }
  });

  it("a node image uses the node runner", () => {
    const cs = codeSandbox("node:22", "4");
    try {
      cs.run("console.log(2 + 2)");
      expect(host.requests("guest.proc.start")[0].argv).toEqual(["node", "-e", "console.log(2 + 2)"]);
    } finally {
      cs.kill();
    }
  });
});

describe("BrowserSandbox", () => {
  function liveBrowser(): void {
    process.env.MVM_SDK_MODE = "live";
    host.on("machine.run", runReply("browser", "dev")).on("machine.stop", {});
  }

  it("uses the pinned image, fixed proxy/loopback command, and allowlist", () => {
    liveBrowser();
    const bs = new mvm.BrowserSandbox("obscura", {
      network: { mode: "none", egress: { allowlist: [{ host: "example.com", port: 443 }] } },
    });
    try {
      const request = host.requests("machine.run")[0];
      expect(request.image).toBe(mvm.OBSCURA_IMAGE);
      expect(request.egress).toEqual([{ host: "example.com", port: 443 }]);
      expect(request.command).toEqual([
        "/obscura", "--proxy", "http://127.0.0.1:1080", "serve", "--host", "127.0.0.1", "--port", "9222",
      ]);
      expect(request.ports).toEqual(["9222:9222"]);
    } finally {
      bs.kill();
    }
  });

  it("refuses a command override before any call", () => {
    liveBrowser();
    expect(() => new mvm.BrowserSandbox("obscura", { command: ["/bin/sh"] })).toThrow(
      /does not allow command overrides/,
    );
    expect(host.calls).toEqual([]);
  });

  it("refuses the template-backed browsers in live mode before any call", () => {
    liveBrowser();
    expect(() => new mvm.BrowserSandbox("chromium")).toThrow(mvm.SandboxModeError);
    expect(host.calls).toEqual([]);
  });

  it("validates CDP readiness and cleans up after timeout", async () => {
    const server = http.createServer((_request, response) => {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ webSocketDebuggerUrl: "ws://127.0.0.1/devtools/browser/test" }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("expected TCP address");
    liveBrowser();
    const bs = new mvm.BrowserSandbox("obscura", { hostPort: address.port });
    expect(await bs.waitUntilReady({ timeoutMs: 1000 })).toBe("ws://127.0.0.1/devtools/browser/test");
    bs.kill();
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));

    const failing = new mvm.BrowserSandbox("obscura", { hostPort: address.port });
    await expect(failing.waitUntilReady({ timeoutMs: 20, retryMs: 2 })).rejects.toBeInstanceOf(
      mvm.BrowserReadyError,
    );
    expect(host.requests("machine.stop")).toEqual([{ id: "browser" }, { id: "browser" }]);
  });

  it("honours a custom host port", () => {
    liveBrowser();
    const bs = new mvm.BrowserSandbox("obscura", { hostPort: 18222 });
    try {
      expect(bs.endpoint()).toBe("http://localhost:18222");
      expect(host.requests("machine.run")[0].ports).toEqual(["18222:9222"]);
    } finally {
      bs.kill();
    }
  });

  it("throws on an unknown browser", () => {
    expect(() => new mvm.BrowserSandbox("safari")).toThrow(/unknown browser/);
  });
});
