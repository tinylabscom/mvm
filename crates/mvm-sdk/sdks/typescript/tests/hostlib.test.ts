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
  call,
  candidatePaths,
  HostLibraryError,
  LIB_PATH_ENV,
  libraryFileName,
  packagedLibraryPath,
  resolveLibraryPath,
  setInvokeForTesting,
  type InvokeFn,
} from "../src/_hostlib.js";
import { MVM_HOSTLIB_PATH_ENV } from "../src/_env/vars.js";
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
