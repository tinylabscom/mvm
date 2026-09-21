/**
 * Host-library binding (`src/_hostlib.ts`).
 *
 * Resolution and marshalling are tested without the library: path lookup
 * takes its environment, `which`, `exists`, and `realpath` as seams, and
 * `call` takes the C-call seam. The live test at the end loads a real
 * library when `MVM_HOSTLIB_PATH` names one, and is skipped otherwise —
 * mirroring `tests/test_hostlib.py`.
 */

import { describe, expect, it } from "vitest";

import {
  call,
  candidatePaths,
  HostLibraryError,
  LIB_PATH_ENV,
  libraryFileName,
  resolveLibraryPath,
  type InvokeFn,
} from "../src/_hostlib.js";
import { MachineNotFoundError, MvmTransportError } from "../src/_errors/types.js";
import { ABI_MAJOR, ABI_MINOR, MACHINE_LIST, METHODS } from "../src/hostabi/methods.js";

describe("library file resolution", () => {
  it("follows the platform for the file name", () => {
    expect(libraryFileName("darwin")).toBe("libmvm_hostlib.dylib");
    expect(libraryFileName("linux")).toBe("libmvm_hostlib.so");
    expect(libraryFileName("win32")).toBe("mvm_hostlib.dll");
  });

  it("treats an explicit path as the only candidate", () => {
    expect(
      candidatePaths({
        environ: { [LIB_PATH_ENV]: "/opt/lib/libmvm_hostlib.so" },
        which: () => "/usr/bin/mvmctl",
      }),
    ).toEqual(["/opt/lib/libmvm_hostlib.so"]);
  });

  it("looks beside mvmctl, including beside the real file", () => {
    const paths = candidatePaths({
      environ: {},
      which: () => "/usr/local/bin/mvmctl",
      realpath: () => "/cellar/mvm-1/bin/mvmctl",
      platform: "linux",
    });
    expect(paths).toEqual([
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
    });
    expect(paths).toEqual(["/usr/bin/libmvm_hostlib.so"]);
  });

  it("returns no candidates without the env var or mvmctl on PATH", () => {
    expect(candidatePaths({ environ: {}, which: () => null })).toEqual([]);
  });

  it("resolves the first candidate that exists", () => {
    expect(
      resolveLibraryPath({
        environ: {},
        which: () => "/usr/bin/mvmctl",
        realpath: () => "/usr/bin/mvmctl",
        exists: (p) => p === "/usr/bin/libmvm_hostlib.so",
        platform: "linux",
      }),
    ).toBe("/usr/bin/libmvm_hostlib.so");
  });

  it("refuses an explicit path that does not exist, naming it", () => {
    expect(() =>
      resolveLibraryPath({
        environ: { [LIB_PATH_ENV]: "/nope/libmvm_hostlib.so" },
        exists: () => false,
      }),
    ).toThrow(/MVM_HOSTLIB_PATH names \/nope\/libmvm_hostlib\.so, which does not exist/);
  });

  it("names both ways out when nothing is found", () => {
    try {
      resolveLibraryPath({ environ: {}, which: () => null });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(MvmTransportError);
      expect((err as Error).message).toContain("MVM_HOSTLIB_PATH");
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
  it.skipIf(!process.env[LIB_PATH_ENV])(
    "loads, negotiates, and answers backend.capabilities",
    () => {
      const report = call("backend.capabilities", undefined);
      expect(report).toBeTypeOf("object");
    },
  );
});
