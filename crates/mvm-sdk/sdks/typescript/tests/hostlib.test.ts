/**
 * Host-library binding (`src/_hostlib.ts`).
 *
 * Resolution and marshalling are tested without the library: path lookup
 * takes its environment, `which`, `exists`, and `realpath` as seams, and
 * `call` takes the C-call seam. The live test at the end loads a real
 * library when `MVM_HOSTLIB_PATH` names one, and is skipped otherwise —
 * mirroring `tests/test_hostlib.py`.
 */

import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
  approvalCallbackResult,
  call,
  candidatePaths,
  HostLibraryError,
  LIB_PATH_ENV,
  libraryFileName,
  packagedLibraryPath,
  platformPackageLibraryPath,
  resolveLibraryPath,
  setApprovalCallback,
  setInvokeForTesting,
  NativeContext,
  type InvokeFn,
} from "../src/_hostlib.js";
import { MVM_HOSTLIB_PATH_ENV } from "../src/_env/vars.js";
import { CODE_ERRORS, MachineRecoveryRequiredError } from "../src/_errors/types.js";
import type { HostLibraryFailure } from "../src/_hostlib.js";

describe("caller-owned context transport boundary", () => {
  afterEach(() => setInvokeForTesting(null));
  it("only clears unknown start after same-slot C close, retaining errors on failure", () => {
    setInvokeForTesting(() => [6, Buffer.from(JSON.stringify({
      code: "REJECTED", message: "preparation fixture", retryable: false,
    }))]);
    const context = new NativeContext();
    const slot: unknown[] = [{}];
    const cleanup = new Error("private cleanup fixture");
    let release = false;
    let closes = 0;
    let frees = 0;
    // In-process C transport fixture only; real provenance is tested in Rust.
    const shared = { free: () => {}, koffi: { decode: () => [] } };
    Object.assign(context, {
      slot, shared,
      functions: {
        close: () => { closes++; if (!release) throw cleanup; return 0; },
        free: () => { frees++; slot[0] = null; return 0; },
      },
    });
    let original: unknown;
    try { context.call("session.start", {}); } catch (error) { original = error; }
    const state = context as unknown as { sessionPhase: string; sessionError: unknown };
    expect(state.sessionPhase).toBe("unknown");
    expect(() => context.close()).toThrow(cleanup);
    expect(state.sessionPhase).toBe("unknown");
    expect(state.sessionError).toBe(original);
    expect(() => context.free()).toThrow();
    expect(frees).toBe(0);
    release = true;
    context.close();
    context.free();
    expect(state.sessionPhase).toBe("finished");
    expect(state.sessionError).toBe(original);
    expect(slot[0]).toBeNull();
    expect(closes).toBe(2);
    expect(frees).toBe(1);
  });

  it("retains the actual context on a transport failure and cannot serialize it", () => {
    setInvokeForTesting(() => [5, Buffer.from(JSON.stringify({
      code: "CONFLICT", message: "local fixture", retryable: false,
    }))]);
    const context = new NativeContext();
    let caught: unknown;
    try { context.call("transport.fixture", {}); } catch (error) { caught = error; }
    expect((caught as HostLibraryFailure).recovery).toBe(context);
    expect(() => JSON.stringify(context)).toThrow(TypeError);
    expect(() => context.inspect(5)).toThrow(RangeError);
    // No C allocation or native owner exists under this transport seam.
    context.close();
    context.free();
    expect(() => context.call("transport.fixture")).toThrow("closed");
  });

  it("refuses a second session start and foreign stop before transport", () => {
    const sid = "abcdefghijklmnopqrstuvwx";
    const methods: string[] = [];
    setInvokeForTesting((method) => {
      methods.push(method);
      return [0, Buffer.from(JSON.stringify(method === "session.start" ? { session_id: sid } : {}))];
    });
    const context = new NativeContext();
    context.call("session.start", { workload: "fixture" });
    expect(() => context.call("session.start", { workload: "second" })).toThrow();
    expect(() => context.call("session.stop", { session_id: "zyxwvutsrqponmlkjihgfedc" })).toThrow();
    for (const cleanup of [
      () => context.retry_stop(), () => context.close(), () => context.free(),
    ]) expect(cleanup).toThrow();
    expect(methods).toEqual(["session.start"]);
    context.call("session.stop", { session_id: sid });
    expect(() => context.call("session.start", { workload: "second" })).toThrow();
    expect(methods).toEqual(["session.start", "session.stop"]);
    context.close();
    context.free();
  });

  it.each([
    "{}", '{"session_id":7}', '{"session_id":null}', '{"session_id":"NOT-BASE32"}',
    '{"session_id":"abcdefghijklmnopqrstuvwx\\n"}',
    '{"session_id":"abcdefghijklmnopqrstuvwx","session_id":"abcdefghijklmnopqrstuvwx"}',
    '{"session_id":"abcdefghijklmnopqrstuvwx","session_\\u0069d":"abcdefghijklmnopqrstuvwx"}',
    '{"private_marker":"must-not-render"}', "not-json",
  ])("retains malformed original start and refuses false cleanup: %s", (raw) => {
    const methods: string[] = [];
    setInvokeForTesting((method) => { methods.push(method); return [0, Buffer.from(raw)]; });
    const context = new NativeContext();
    let original: unknown;
    try { context.call("session.start", { workload: "fixture" }); } catch (error) { original = error; }
    expect(original).toBeInstanceOf(Error);
    expect((original as HostLibraryFailure).recovery).toBe(context);
    const retained = context as unknown as { sessionError: unknown; sessionReplyBytes: Buffer };
    expect(retained.sessionError).toBe(original);
    expect(retained.sessionReplyBytes.toString("utf8")).toBe(raw);
    for (const cleanup of [
      () => context.retry_stop(), () => context.close(), () => context.free(), () => context.inspect(),
    ]) {
      expect(cleanup).toThrow();
      try { cleanup(); } catch (error) { expect(String(error)).not.toContain("must-not-render"); }
    }
    expect(() => context.call("session.start", { workload: "second" })).toThrow();
    expect(retained.sessionError).toBe(original);
    expect(retained.sessionReplyBytes.toString("utf8")).toBe(raw);
    expect(methods).toEqual(["session.start"]);
    // Actual SDK consumer state under a no-C-allocation recorder, not a VM.
  });
});

describe("typed recovery error decoding", () => {
  const details = { machine_id: "machine", plan_id: "plan", reason: "recover" };
  function failure(status: number, value: unknown): HostLibraryFailure {
    try {
      call("machine.inspect", {}, { invoke: () => [status, Buffer.from(JSON.stringify(value))] });
    } catch (error) {
      return error as HostLibraryFailure;
    }
    throw new Error("nonzero status was not refused");
  }
  it("uses the normal generated constructor and a frozen typed details value", () => {
    const error = failure(12, { code: "RECOVERY_REQUIRED", message: "context", retryable: false, details });
    expect(error).toBeInstanceOf(MachineRecoveryRequiredError);
    expect(error.message).toBe("context");
    expect(error.retryable).toBe(false);
    expect(error.details).toEqual(details);
    expect(Object.isFrozen(error.details)).toBe(true);
    expect(Reflect.set(error.details!, "machine_id", "replacement")).toBe(false);
    expect(Reflect.set(error, "details", {})).toBe(false);
  });
  it.each([null, [], "private-marker", {}, { machine_id: "m" },
    { ...details, reason: 7 }, { ...details, extra: "private-marker" }].map(value => ({ value })))(
    "refuses malformed details without retaining payloads: $value", ({ value }) => {
      const error = failure(12, { code: "RECOVERY_REQUIRED", message: "private-marker", retryable: false, details: value });
      expect(error).toBeInstanceOf(HostLibraryError);
      expect(error).not.toBeInstanceOf(MachineRecoveryRequiredError);
      expect(error.retryable).toBe(false);
      expect(error.details).toBeUndefined();
      expect(String(error)).not.toContain("private-marker");
      expect(JSON.stringify(error)).not.toContain("private-marker");
    },
  );
  it.each([
    [12, "UNAVAILABLE", true], [7, "RECOVERY_REQUIRED", false],
    [12, "RECOVERY_REQUIRED", true], [12, "RECOVERY_REQUIRED", "false"],
  ])("rejects status/code/retryability contradictions", (status, code, retryable) => {
    const error = failure(status as number, { code, message: "private-marker", retryable, details });
    expect(error.retryable).toBe(false);
    expect(error.details).toBeUndefined();
    expect(String(error)).not.toContain("private-marker");
  });
  it("the older generic fallback does not invent details or retry", () => {
    const oldCodes: Record<string, new (message: string) => Error> = { ...CODE_ERRORS };
    delete oldCodes.RECOVERY_REQUIRED;
    const Ctor = oldCodes.RECOVERY_REQUIRED ?? HostLibraryError;
    const error = new Ctor("recover") as HostLibraryFailure;
    error.retryable = false;
    expect(error.constructor).toBe(HostLibraryError);
    expect(error.retryable).toBe(false);
    expect(error.details).toBeUndefined();
  });
});
import {
  MachineNotFoundError,
  MachineSpecError,
  MvmTransportError,
} from "../src/_errors/types.js";
import {
  ABI_MAJOR,
  ABI_MINOR,
  MACHINE_INVENTORY,
  MACHINE_LIST,
  MACHINE_RUN,
  METHODS,
} from "../src/hostabi/methods.js";

const PKG = "/pkg/mvm";

describe("library file resolution", () => {
  it("follows the platform for the file name", () => {
    expect(libraryFileName("darwin")).toBe("libmvm_hostlib.dylib");
    expect(libraryFileName("linux")).toBe("libmvm_hostlib.so");
    expect(libraryFileName("win32")).toBe("mvm_hostlib.dll");
  });

  it("takes the variable's name from the registry", () => {
    expect(LIB_PATH_ENV).toBe(MVM_HOSTLIB_PATH_ENV);
    expect(LIB_PATH_ENV).toBe("MVM_HOSTLIB_PATH");
  });

  it("treats an explicit path as the only candidate", () => {
    expect(
      candidatePaths({
        environ: { [LIB_PATH_ENV]: "/opt/lib/libmvm_hostlib.so" },
        which: () => "/usr/bin/mvmctl",
      }),
    ).toEqual(["/opt/lib/libmvm_hostlib.so"]);
  });

  it("looks in the package, then beside mvmctl, then beside its real file", () => {
    const paths = candidatePaths({
      environ: {},
      which: () => "/usr/local/bin/mvmctl",
      realpath: () => "/cellar/mvm-1/bin/mvmctl",
      platform: "linux",
      packageRoot: PKG,
    });
    expect(paths).toEqual([
      "/pkg/mvm/native/libmvm_hostlib.so",
      "/usr/local/bin/libmvm_hostlib.so",
      "/cellar/mvm-1/bin/libmvm_hostlib.so",
    ]);
  });

  it("deduplicates when the binary is not a symlink", () => {
    const paths = candidatePaths({
      environ: {},
      which: () => "/usr/bin/mvmctl",
      realpath: (p) => p,
      platform: "linux",
      packageRoot: PKG,
    });
    expect(paths).toEqual(["/pkg/mvm/native/libmvm_hostlib.so", "/usr/bin/libmvm_hostlib.so"]);
  });

  it("still looks beside a dangling mvmctl link", () => {
    const paths = candidatePaths({
      environ: {},
      which: () => "/usr/bin/mvmctl",
      realpath: () => {
        throw new Error("ENOENT");
      },
      platform: "linux",
      packageRoot: PKG,
    });
    expect(paths).toEqual(["/pkg/mvm/native/libmvm_hostlib.so", "/usr/bin/libmvm_hostlib.so"]);
  });

  it("looks only in the package without the env var or mvmctl on PATH", () => {
    expect(
      candidatePaths({ environ: {}, which: () => null, platform: "darwin", packageRoot: PKG }),
    ).toEqual(["/pkg/mvm/native/libmvm_hostlib.dylib"]);
  });

  it("looks in this host's platform package after native/ and before mvmctl", () => {
    const asked: string[] = [];
    const paths = candidatePaths({
      environ: {},
      which: () => "/usr/bin/mvmctl",
      realpath: (p) => p,
      platform: "linux",
      arch: "arm64",
      libc: "musl",
      resolvePackage: (name) => {
        asked.push(name);
        return `/nm/${name}`;
      },
      packageRoot: PKG,
    });
    expect(asked).toEqual(["@runmvm/mvm-linux-arm64-musl"]);
    expect(paths).toEqual([
      "/pkg/mvm/native/libmvm_hostlib.so",
      "/nm/@runmvm/mvm-linux-arm64-musl/libmvm_hostlib.so",
      "/usr/bin/libmvm_hostlib.so",
    ]);
  });

  it("picks the glibc package on a glibc host and the macOS one on darwin", () => {
    const resolvePackage = (name: string) => `/nm/${name}`;
    expect(
      platformPackageLibraryPath({ platform: "linux", arch: "x64", libc: "glibc", resolvePackage }),
    ).toBe("/nm/@runmvm/mvm-linux-x64-gnu/libmvm_hostlib.so");
    expect(platformPackageLibraryPath({ platform: "darwin", arch: "arm64", resolvePackage })).toBe(
      "/nm/@runmvm/mvm-darwin-arm64/libmvm_hostlib.dylib",
    );
  });

  it("skips the platform package when it is not installed", () => {
    expect(
      platformPackageLibraryPath({
        platform: "linux",
        arch: "x64",
        libc: "glibc",
        resolvePackage: () => null,
      }),
    ).toBeNull();
  });

  it("asks for no package on a host nothing is published for", () => {
    const asked: string[] = [];
    const resolvePackage = (name: string) => {
      asked.push(name);
      return `/nm/${name}`;
    };
    expect(platformPackageLibraryPath({ platform: "darwin", arch: "x64", resolvePackage })).toBeNull();
    expect(platformPackageLibraryPath({ platform: "win32", arch: "x64", resolvePackage })).toBeNull();
    expect(asked).toEqual([]);
  });

  it("prefers native/ over the platform package", () => {
    expect(
      resolveLibraryPath({
        environ: {},
        which: () => null,
        exists: () => true,
        platform: "linux",
        arch: "x64",
        libc: "glibc",
        resolvePackage: (name) => `/nm/${name}`,
        packageRoot: PKG,
      }),
    ).toBe("/pkg/mvm/native/libmvm_hostlib.so");
  });

  it("loads from the platform package when native/ is empty", () => {
    expect(
      resolveLibraryPath({
        environ: {},
        which: () => "/usr/bin/mvmctl",
        realpath: (p) => p,
        exists: (p) => !p.startsWith("/pkg/"),
        platform: "linux",
        arch: "x64",
        libc: "glibc",
        resolvePackage: (name) => `/nm/${name}`,
        packageRoot: PKG,
      }),
    ).toBe("/nm/@runmvm/mvm-linux-x64-gnu/libmvm_hostlib.so");
  });

  it("defaults the package root to the directory above this module's", () => {
    // Source layout: src/_hostlib.ts -> <package>/native; the published
    // dist/_hostlib.js resolves the same way.
    const pkg = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    expect(packagedLibraryPath({ platform: "linux" })).toBe(
      path.join(pkg, "native", "libmvm_hostlib.so"),
    );
  });

  it("prefers the packaged library over the one beside mvmctl", () => {
    expect(
      resolveLibraryPath({
        environ: {},
        which: () => "/usr/bin/mvmctl",
        realpath: (p) => p,
        exists: () => true,
        platform: "linux",
        packageRoot: PKG,
      }),
    ).toBe("/pkg/mvm/native/libmvm_hostlib.so");
  });

  it("resolves the first candidate that exists", () => {
    expect(
      resolveLibraryPath({
        environ: {},
        which: () => "/usr/local/bin/mvmctl",
        realpath: () => "/cellar/bin/mvmctl",
        exists: (p) => p === "/cellar/bin/libmvm_hostlib.so",
        platform: "linux",
        packageRoot: PKG,
      }),
    ).toBe("/cellar/bin/libmvm_hostlib.so");
  });

  it("refuses an explicit path that does not exist, naming it, without falling through", () => {
    expect(() =>
      resolveLibraryPath({
        environ: { [LIB_PATH_ENV]: "/nope/libmvm_hostlib.so" },
        which: () => "/usr/bin/mvmctl",
        exists: (p) => p !== "/nope/libmvm_hostlib.so",
        packageRoot: PKG,
      }),
    ).toThrow(/MVM_HOSTLIB_PATH names \/nope\/libmvm_hostlib\.so, which does not exist/);
  });

  it("names all three ways out when nothing is found", () => {
    try {
      resolveLibraryPath({ environ: {}, which: () => null, exists: () => false, packageRoot: PKG });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(MvmTransportError);
      const message = (err as Error).message;
      expect(message).toContain("MVM_HOSTLIB_PATH");
      expect(message).toContain("native/");
      expect(message).toContain("beside mvmctl");
      expect(message).toContain("/pkg/mvm/native/");
    }
  });
});

describe("call marshalling", () => {
  it("sends an empty body for a missing request and parses the reply", () => {
    const seen: Array<{ method: string; body: Buffer }> = [];
    const invoke: InvokeFn = (method, requestJson) => {
      seen.push({ method, body: requestJson });
      return [0, Buffer.from(JSON.stringify([{ id: "m1" }]), "utf8")];
    };
    const reply = call(MACHINE_LIST, undefined, { invoke });
    expect(seen).toEqual([{ method: "machine.list", body: Buffer.alloc(0) }]);
    expect(reply).toEqual([{ id: "m1" }]);
  });

  it("serializes a request as compact JSON", () => {
    const seen: Buffer[] = [];
    const invoke: InvokeFn = (_method, requestJson) => {
      seen.push(requestJson);
      return [0, Buffer.alloc(0)];
    };
    call(MACHINE_LIST, { name: "web" }, { invoke });
    expect(seen[0].toString("utf8")).toBe('{"name":"web"}');
  });

  it("raises the typed error a known code names, with its flags", () => {
    const invoke: InvokeFn = () => [
      2,
      Buffer.from(JSON.stringify({ code: "NOT_FOUND", message: "no such machine", retryable: false }), "utf8"),
    ];
    try {
      call("machine.inspect", { id: "nope" }, { invoke });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(MachineNotFoundError);
      expect(err).toBeInstanceOf(HostLibraryError);
      const failure = err as HostLibraryError & { code?: string; retryable?: boolean; status?: number };
      expect(failure.code).toBe("NOT_FOUND");
      expect(failure.retryable).toBe(false);
      expect(failure.status).toBe(2);
      expect((err as Error).message).toBe("no such machine");
    }
  });

  it("falls back to the base class for an unknown code", () => {
    const invoke: InvokeFn = () => [
      7,
      Buffer.from(JSON.stringify({ code: "SOMEDAY", message: "future" }), "utf8"),
    ];
    expect(() => call(MACHINE_LIST, undefined, { invoke })).toThrow(HostLibraryError);
  });
});

describe("setInvokeForTesting", () => {
  afterEach(() => setInvokeForTesting(null));

  it("routes calls without a per-call seam, and a per-call seam still wins", () => {
    const seen: string[] = [];
    setInvokeForTesting((method) => {
      seen.push(`global:${method}`);
      return [0, Buffer.from("[]", "utf8")];
    });
    expect(call(MACHINE_LIST)).toEqual([]);
    call(MACHINE_LIST, undefined, {
      invoke: (method) => {
        seen.push(`local:${method}`);
        return [0, Buffer.alloc(0)];
      },
    });
    expect(seen).toEqual(["global:machine.list", "local:machine.list"]);
  });

  it("restores the real library when cleared", () => {
    setInvokeForTesting(() => [0, Buffer.from("1", "utf8")]);
    expect(call(MACHINE_LIST)).toBe(1);
    setInvokeForTesting(null);
    // With the seam gone the call reaches for the real library; pointing
    // the lookup at a file that is not there proves it without loading one.
    const previous = process.env[LIB_PATH_ENV];
    if (previous === undefined) {
      process.env[LIB_PATH_ENV] = "/nonexistent/libmvm_hostlib.so";
      try {
        expect(() => call(MACHINE_LIST)).toThrow(MvmTransportError);
      } finally {
        delete process.env[LIB_PATH_ENV];
      }
    }
  });
});

describe("approval callback", () => {
  const prompt = Buffer.from(
    JSON.stringify({
      request_id: "approval-1",
      subject: { kind: "tool_call", tool: "shell" },
      expires_in_ms: 1000,
    }),
    "utf8",
  );

  it("maps the bounded decisions and hands the parsed prompt to the application", () => {
    const seen: unknown[] = [];
    expect(approvalCallbackResult((value) => { seen.push(value); return "session"; }, prompt)).toBe(2);
    expect(seen).toEqual([
      {
        request_id: "approval-1",
        subject: { kind: "tool_call", tool: "shell" },
        expires_in_ms: 1000,
      },
    ]);
    expect(approvalCallbackResult(() => "once", prompt)).toBe(1);
    expect(approvalCallbackResult(() => "deny", prompt)).toBe(0);
  });

  it("denies malformed JSON and callback exceptions", () => {
    expect(approvalCallbackResult(() => "once", Buffer.from("not json"))).toBe(0);
    expect(
      approvalCallbackResult(() => {
        throw new Error("application failure");
      }, prompt),
    ).toBe(0);
  });
});

describe("generated method table", () => {
  it("carries the ABI version the binding negotiates with", () => {
    expect(typeof ABI_MAJOR).toBe("number");
    expect(typeof ABI_MINOR).toBe("number");
    expect(METHODS["machine.list"]?.key).toBe("machine_list");
    expect(METHODS["guest.proc.start"]?.classification).toBe("dev_only");
    expect(METHODS["machine.list"]?.classification).toBe("prod_safe");
  });
});

describe("live library", () => {
  const live = it.skipIf(!process.env[LIB_PATH_ENV]);

  live("loads, negotiates, and answers backend.capabilities", () => {
    const report = call("backend.capabilities", undefined);
    expect(report).toBeTypeOf("object");
  });

  live("answers machine.inventory with a list", () => {
    expect(Array.isArray(call(MACHINE_INVENTORY))).toBe(true);
  });

  live("registers and clears an approval callback", () => {
    setApprovalCallback(() => "once");
    setApprovalCallback(null);
  });

  live("refuses a machine.run command override with MachineSpecError", () => {
    // Proves the launch path end to end without booting: the in-process
    // launcher refuses a command override before it admits anything.
    try {
      call(MACHINE_RUN, { image: "docker.io/library/alpine:3.20", command: ["true"] });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(MachineSpecError);
      expect((err as HostLibraryError & { code?: string }).code).toBe("INVALID_SPEC");
    }
  });
});
