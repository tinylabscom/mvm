/**
 * Host-side transport: the host library, loaded in-process.
 *
 * The SDK drives machines by calling `libmvm_hostlib` through its C ABI —
 * JSON in, JSON out, an `int32` status, a paired free — exactly what
 * `mvm/_hostlib.py` is on Python. No process is spawned: not `mvmctl`, and
 * not a helper standing in for it.
 *
 * Resolution order for the library file:
 *
 * 1. `MVM_HOSTLIB_PATH`, the library file itself. Set and missing is an
 *    error, never a reason to keep looking: an explicit path that silently
 *    falls through would load some other build than the one named.
 * 2. Packaged with the SDK, in `native/` under the package root (the
 *    directory above the one holding this compiled module, so `dist/../native`
 *    for the published layout and `src/../native` for a source checkout).
 * 3. Beside `mvmctl` on `PATH` (the release ships them side by side; the
 *    binary is located, never run), including beside the real file after
 *    resolving symlinks.
 * 4. Otherwise {@link MvmTransportError}, naming all three.
 *
 * Before the first call the binding tells the library which ABI it was built
 * for, and the library refuses every call until that succeeds, so a binding
 * and library that disagree about the buffer layout cannot exchange one. The
 * ABI constants come from the generated method table, never restated here.
 */

import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { MVM_HOSTLIB_PATH_ENV } from "./_env/vars.js";
import {
  CODE_ERRORS,
  HostLibraryAbiError,
  HostLibraryError,
  MvmTransportError,
  STATUS_OK as OK,
} from "./_errors/types.js";
import { ABI_MAJOR, ABI_MINOR } from "./hostabi/methods.js";

/** Environment variable naming the library file; the registry owns the name. */
export const LIB_PATH_ENV = MVM_HOSTLIB_PATH_ENV;

export { HostLibraryError } from "./_errors/types.js";

/** The library's file name on `platform`. */
export function libraryFileName(platform: string = process.platform): string {
  if (platform === "darwin") return "libmvm_hostlib.dylib";
  if (platform === "win32") return "mvm_hostlib.dll";
  return "libmvm_hostlib.so";
}

/** The seams path resolution takes, so tests need no real files or PATH. */
export interface PathSeams {
  /** Environment map; defaults to `process.env`. */
  environ?: Record<string, string | undefined>;
  /** Locate a binary on PATH; defaults to a filesystem search. */
  which?: (bin: string) => string | null;
  /** Whether a path exists; defaults to `fs.existsSync`. */
  exists?: (p: string) => boolean;
  /** Resolve symlinks; defaults to `fs.realpathSync`. */
  realpath?: (p: string) => string;
  platform?: string;
  /** The package root holding `native/`; defaults to this module's. */
  packageRoot?: string;
}

/** The directory above the one holding this module: the package root. */
function defaultPackageRoot(): string {
  return path.dirname(path.dirname(fileURLToPath(import.meta.url)));
}

/** Where a package that ships the library puts it. */
export function packagedLibraryPath(seams: PathSeams = {}): string {
  const root = seams.packageRoot ?? defaultPackageRoot();
  return path.join(root, "native", libraryFileName(seams.platform ?? process.platform));
}

function defaultWhich(bin: string): string | null {
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    if (dir.length === 0) continue;
    const candidate = path.join(dir, bin);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Where to look for the library, in order. Pure with respect to the seams:
 * it names paths and reads no files beyond what `which`/`exists` do.
 */
export function candidatePaths(seams: PathSeams = {}): string[] {
  const env = seams.environ ?? process.env;
  const which = seams.which ?? defaultWhich;
  const platform = seams.platform ?? process.platform;
  const explicit = env[LIB_PATH_ENV];
  if (explicit) return [explicit];
  const paths = [packagedLibraryPath(seams)];
  const found = which("mvmctl");
  if (!found) return paths;
  const name = libraryFileName(platform);
  const besideLink = path.join(path.dirname(found), name);
  paths.push(besideLink);
  // A package manager usually links `mvmctl` into its bin directory; the
  // library sits beside the real file. A dangling link has no real file, so
  // there is nothing more to look beside.
  const realpath = seams.realpath ?? ((p: string) => fs.realpathSync(p));
  let real: string | null = null;
  try {
    real = realpath(found);
  } catch {
    real = null;
  }
  if (real !== null) {
    const besideReal = path.join(path.dirname(real), name);
    if (besideReal !== besideLink) paths.push(besideReal);
  }
  return paths;
}

/** The first candidate that exists, or {@link MvmTransportError}. */
export function resolveLibraryPath(seams: PathSeams = {}): string {
  const env = seams.environ ?? process.env;
  const exists = seams.exists ?? ((p: string) => fs.existsSync(p));
  const candidates = candidatePaths(seams);
  if (env[LIB_PATH_ENV]) {
    const named = candidates[0];
    if (named !== undefined && exists(named)) return named;
    throw new MvmTransportError(
      `${LIB_PATH_ENV} names ${named}, which does not exist`,
    );
  }
  for (const candidate of candidates) {
    if (exists(candidate)) return candidate;
  }
  throw new MvmTransportError(
    `the host library ${libraryFileName(seams.platform ?? process.platform)} was not found: ` +
      `set ${LIB_PATH_ENV} to its path, ship it in the SDK package's native/ directory, ` +
      `or install it beside mvmctl on PATH (looked in: ${candidates.join(", ")})`,
  );
}

/** An error the host library reported: `code`, `retryable`, and the status. */
export interface HostLibraryFailure extends Error {
  code?: string;
  retryable?: boolean;
  status?: number;
}

/** The C-call seam: `(method, requestJson) -> [status, body]`. */
export type InvokeFn = (method: string, requestJson: Buffer) => [number, Buffer];

export interface CallOptions {
  /** Override the C-call seam for this call only. */
  invoke?: InvokeFn;
}

let invokeOverride: InvokeFn | null = null;

/**
 * Route every {@link call} that names no `opts.invoke` through `fn`, so a
 * test can drive the whole SDK against canned replies without a library.
 * `null` restores the real library.
 */
export function setInvokeForTesting(fn: InvokeFn | null): void {
  invokeOverride = fn;
}

interface LoadedLib {
  call: (...args: unknown[]) => number;
  free: (buf: unknown) => void;
  koffi: { decode: (ptr: unknown, type: string, len: number) => Uint8Array };
}

let lib: LoadedLib | null = null;

/** Load and memoize the library, declaring the C ABI signatures. */
function loadLib(): LoadedLib {
  if (lib === null) {
    // Lazy `require` so importing this package never pulls koffi on a host
    // that only authors workloads — only a host-side call touches it.
    const require = createRequire(import.meta.url);
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const koffi = require("koffi");
    const handle = koffi.load(resolveLibraryPath());
    koffi.struct("MvmHostlibBuf", { data: "uint8_t*", len: "size_t" });
    const abiVersion = handle.func("uint32_t mvm_hostlib_abi_version(void)");
    const abiCompatible = handle.func(
      "int32_t mvm_hostlib_abi_is_compatible(uint16_t major, uint16_t minor)",
    );
    const call = handle.func(
      "int32_t mvm_hostlib_call(const uint8_t*, size_t, const uint8_t*, size_t, _Out_ MvmHostlibBuf*)",
    );
    const free = handle.func("void mvm_hostlib_free(MvmHostlibBuf)");
    if (abiCompatible(ABI_MAJOR, ABI_MINOR) !== 1) {
      const version: number = abiVersion();
      throw new HostLibraryAbiError(
        `the host library implements ABI ${version >> 16}.${version & 0xffff}, and ` +
          `this SDK needs ${ABI_MAJOR}.${ABI_MINOR}; install matching versions`,
      );
    }
    lib = { call, free, koffi };
  }
  return lib;
}

/** Call the C ABI once and return `[status, body]`. */
function realInvoke(method: string, requestJson: Buffer): [number, Buffer] {
  const handle = loadLib();
  const out: { data: unknown; len: number } = { data: null, len: 0 };
  // The ABI takes the method as bytes plus a length, not a C string, so koffi
  // needs a buffer here; it refuses a JS string for `const uint8_t*`.
  const methodBytes = Buffer.from(method, "utf8");
  const status = handle.call(
    methodBytes,
    methodBytes.length,
    requestJson,
    requestJson.length,
    out,
  );
  let body = Buffer.alloc(0);
  try {
    if (out.len > 0) {
      body = Buffer.from(handle.koffi.decode(out.data, "uint8_t", out.len));
    }
  } finally {
    handle.free(out);
  }
  return [status, body];
}

/**
 * Marshal `request` to JSON, call `method`, and return the parsed reply.
 * Throws the {@link HostLibraryError} subclass the error body's `code`
 * names, carrying `code`, `retryable`, and the library status.
 */
export function call(method: string, request?: unknown, opts: CallOptions = {}): any {
  const invoke = opts.invoke ?? invokeOverride ?? realInvoke;
  const requestJson =
    request === undefined || request === null
      ? Buffer.alloc(0)
      : Buffer.from(JSON.stringify(request), "utf8");
  const [status, body] = invoke(method, requestJson);
  const parsed: unknown = body.length > 0 ? JSON.parse(body.toString("utf8")) : null;
  if (status === OK) {
    return parsed;
  }
  const fields = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  const message =
    typeof fields.message === "string"
      ? fields.message
      : `host library call \`${method}\` failed (status ${status})`;
  const Ctor = CODE_ERRORS[typeof fields.code === "string" ? fields.code : ""] ?? HostLibraryError;
  const err = new Ctor(message) as HostLibraryFailure;
  err.code = typeof fields.code === "string" ? fields.code : undefined;
  err.retryable = fields.retryable === true;
  err.status = status;
  throw err;
}
