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
 * 2. In `native/` under the package root (the directory above the one
 *    holding this compiled module, so `dist/../native` or `src/../native`).
 *    The published package does not use it; it is where a source checkout
 *    or a hand-assembled package puts the library.
 * 3. The platform package for this host, `@runmvm/mvm-<os>-<cpu>[-<libc>]`
 *    (see `_platform.ts`), which npm installs as an optional dependency of
 *    the published package.
 * 4. Beside `mvmctl` on `PATH` (the release ships them side by side; the
 *    binary is located, never run), including beside the real file after
 *    resolving symlinks.
 * 5. Otherwise {@link MvmTransportError}, naming all of them.
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
  HostLibraryInternalError,
  MvmTransportError,
  STATUS_OK as OK,
} from "./_errors/types.js";
import { ABI_MAJOR, ABI_MINOR } from "./hostabi/methods.js";
import { detectLibc, type Libc, platformPackageFor, platformPackageName } from "./_platform.js";

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
  /** CPU architecture, as `process.arch` names it; defaults to this host's. */
  arch?: string;
  /** The C library on Linux; defaults to the one this process runs on. */
  libc?: Libc;
  /**
   * The directory of an installed package, or `null` when it is not
   * installed; defaults to Node's resolution from this module.
   */
  resolvePackage?: (name: string) => string | null;
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

function defaultResolvePackage(name: string): string | null {
  try {
    const require = createRequire(import.meta.url);
    return path.dirname(require.resolve(`${name}/package.json`));
  } catch {
    return null;
  }
}

/**
 * The library inside this host's installed platform package, or `null` when
 * no package is published for the host or none is installed.
 */
export function platformPackageLibraryPath(seams: PathSeams = {}): string | null {
  const platform = seams.platform ?? process.platform;
  const pkg = platformPackageFor(
    platform,
    seams.arch ?? process.arch,
    seams.libc ?? detectLibc(platform),
  );
  if (pkg === undefined) return null;
  const dir = (seams.resolvePackage ?? defaultResolvePackage)(platformPackageName(pkg));
  return dir === null ? null : path.join(dir, libraryFileName(platform));
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
  const fromPlatformPackage = platformPackageLibraryPath(seams);
  if (fromPlatformPackage !== null) paths.push(fromPlatformPackage);
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
      `install the platform package for this host, ` +
      `or install it beside mvmctl on PATH (looked in: ${candidates.join(", ")})`,
  );
}

/** An error the host library reported: `code`, `retryable`, and the status. */
export interface HostLibraryFailure extends Error {
  code?: string;
  retryable?: boolean;
  status?: number;
  readonly details?: RecoveryRequiredDetails;
  readonly recovery?: NativeContext;
}

/** Validated metadata, not a recovery operation or authority. */
export interface RecoveryRequiredDetails {
  readonly machine_id: string;
  readonly plan_id: string;
  readonly reason: string;
}

function protocolError(status: number): HostLibraryFailure {
  const error = new HostLibraryInternalError("malformed host library error response") as HostLibraryFailure;
  error.code = "INTERNAL";
  error.retryable = false;
  error.status = status;
  return error;
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
  library: { func: (signature: string) => (...args: unknown[]) => number };
  abiVersion: () => number;
  abiCompatible: (major: number, minor: number) => number;
  call: (...args: unknown[]) => number;
  free: (buf: unknown) => void;
  setApprovalCallback: (callback: unknown) => number;
  approvalCallbackType: unknown;
  koffi: {
    decode: (ptr: unknown, type: string, len: number) => Uint8Array;
    pointer: (type: unknown) => unknown;
    register: (
      callback: (pointer: unknown, length: number) => number,
      type: unknown,
    ) => unknown;
    unregister: (callback: unknown) => void;
  };
}

let lib: LoadedLib | null = null;
let legacyNegotiatedFor: LoadedLib | null = null;
let activeApprovalCallback: unknown | null = null;
let approvalCleanupRegistered = false;

/** The only decisions an SDK callback can return. */
export type ApprovalDecision = "deny" | "once" | "session";
/** What the paused flow is asking to do. */
export type ApprovalSubject =
  | {
      kind: "egress";
      route_id: string;
      rule: string;
      destination: string;
      method: string;
      path: string;
    }
  | { kind: "secret_use"; secret: string; destination: string }
  | { kind: "tool_call"; tool: string };
/** The supervisor's bounded JSON question. */
export interface ApprovalPrompt {
  request_id: string;
  subject: ApprovalSubject;
  expires_in_ms: number;
}
/** An application callback for runtime `ask` decisions. */
export type ApprovalCallback = (prompt: ApprovalPrompt) => ApprovalDecision;

/** Load and memoize the library, declaring the C ABI signatures. */
function loadLib(negotiate = true): LoadedLib {
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
    const approvalCallbackType = koffi.proto(
      "MvmHostlibApprovalCallback",
      "int32_t",
      ["const uint8_t *", "size_t"],
    );
    const setApprovalCallback = handle.func(
      "int32_t mvm_hostlib_set_approval_callback(void *callback)",
    );
    lib = { library: handle, abiVersion, abiCompatible, call, free, setApprovalCallback, approvalCallbackType, koffi };
  }
  if (negotiate && legacyNegotiatedFor !== lib) {
    if (lib.abiCompatible(ABI_MAJOR, ABI_MINOR) !== 1) {
      const version: number = lib.abiVersion();
      throw new HostLibraryAbiError(
        `the host library implements ABI ${version >> 16}.${version & 0xffff}, and ` +
          `this SDK needs ${ABI_MAJOR}.${ABI_MINOR}; install matching versions`,
      );
    }
    legacyNegotiatedFor = lib;
  }
  return lib;
}

/** Map one callback answer to the host ABI's bounded decision enum. */
export function approvalCallbackResult(
  callback: ApprovalCallback,
  encoded: Buffer,
): number {
  try {
    const parsed: unknown = JSON.parse(encoded.toString("utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return 0;
    const decision = callback(parsed as unknown as ApprovalPrompt);
    return decision === "once" ? 1 : decision === "session" ? 2 : 0;
  } catch {
    return 0;
  }
}

/**
 * Set the process-wide callback for runtime `ask` decisions.
 *
 * Register it before launching or starting a machine. Machines launched or
 * started through this SDK retain a private broker until stop/remove. Clearing
 * with `null` makes existing brokers deny; no decision is written to a profile.
 * Exceptions and unknown answers deny.
 */
export function setApprovalCallback(callback: ApprovalCallback | null): void {
  const handle = loadLib();
  let registered: unknown = null;
  if (callback !== null) {
    registered = handle.koffi.register(
      (pointer: unknown, length: number): number => {
        try {
          const bytes = Buffer.from(handle.koffi.decode(pointer, "uint8_t", length));
          return approvalCallbackResult(callback, bytes);
        } catch {
          return 0;
        }
      },
      handle.koffi.pointer(handle.approvalCallbackType),
    );
    if (!approvalCleanupRegistered) {
      process.once("exit", () => {
        handle.setApprovalCallback(null);
        if (activeApprovalCallback !== null) {
          handle.koffi.unregister(activeApprovalCallback);
          activeApprovalCallback = null;
        }
      });
      approvalCleanupRegistered = true;
    }
  }
  const status = handle.setApprovalCallback(registered);
  if (status !== OK) {
    if (registered !== null) handle.koffi.unregister(registered);
    throw new HostLibraryError(
      `host library refused the approval callback (status ${status})`,
    );
  }
  const previous = activeApprovalCallback;
  activeApprovalCallback = registered;
  if (previous !== null) handle.koffi.unregister(previous);
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

type ContextFn = (...args: unknown[]) => number;
interface ContextFunctions {
  create: ContextFn;
  call: ContextFn;
  inspect: ContextFn;
  retryStop: ContextFn;
  close: ContextFn;
  free: ContextFn;
}

/** Both original errors and the same held context, never their rendered data. */
export class OwnedContextFailure extends MvmTransportError {
  readonly primary_error: unknown;
  readonly cleanup_error: unknown;
  readonly recovery: NativeContext;
  readonly session?: unknown;
  constructor(primary: unknown, cleanup: unknown, recovery: NativeContext, session?: unknown) {
    super("cleanup is unresolved; original errors and context remain retained");
    this.primary_error = primary;
    this.cleanup_error = cleanup;
    this.recovery = recovery;
    this.session = session;
  }
}

/** Shared validation of the host's original binding, never normalization. */
export function sessionIdFromReply(reply: unknown): string {
  const id = reply !== null && typeof reply === "object" && !Array.isArray(reply)
    ? (reply as Record<string, unknown>).session_id : undefined;
  if (typeof id !== "string" || id.length < 16 || id.length > 64 || /[^a-z2-7]/.test(id)) {
    throw new MvmTransportError("session.start returned no usable session id; original reply retained");
  }
  return id;
}

function sessionIdFromWire(body: Buffer): string {
  const text = body.toString("utf8");
  const reply: unknown = JSON.parse(text);
  // JSON.parse collapses duplicate keys. Count only real top-level binding
  // keys, skipping complete escaped strings and nested objects/arrays.
  let depth = 0;
  let bindings = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '"') {
      const start = i++;
      while (i < text.length && text[i] !== '"') {
        i += text[i] === "\\" ? 2 : 1;
      }
      let next = i + 1;
      while (/\s/.test(text[next] ?? "") && next < text.length) next++;
      if (depth === 1 && text[next] === ":"
        && JSON.parse(text.slice(start, i + 1)) === "session_id") bindings++;
    } else if (text[i] === "{" || text[i] === "[") {
      depth++;
    } else if (text[i] === "}" || text[i] === "]") {
      depth--;
    }
  }
  if (bindings !== 1) throw new MvmTransportError("session start has no unique object binding");
  return sessionIdFromReply(reply);
}

/** Caller-owned C lifetime. No destructor or finalizer performs a stop. */
export class NativeContext {
  private readonly slot: [unknown] = [null];
  private shared: LoadedLib | null = null;
  private functions: ContextFunctions | null = null;
  private closed = false;
  private freed = false;
  private busy = false;
  private sessionPhase: "empty" | "starting" | "active" | "unknown" | "finished" = "empty";
  private sessionId: string | null = null;
  private sessionReplyBytes: Buffer | null = null;
  private sessionError: unknown;

  toJSON(): never {
    throw new TypeError("owning contexts are not serializable");
  }

  private bufferCall(fn: ContextFn, ...args: unknown[]): [number, Buffer] {
    const shared = this.shared;
    if (shared === null) throw new MvmTransportError("context has no held library");
    const out: { data: unknown; len: number } = { data: null, len: 0 };
    const status = fn(...args, out);
    try {
      return [status, out.len > 0
        ? Buffer.from(shared.koffi.decode(out.data, "uint8_t", out.len))
        : Buffer.alloc(0)];
    } finally {
      shared.free(out);
    }
  }

  private allocate(): ContextFunctions {
    if (this.freed) throw new MvmTransportError("context was already freed");
    if (this.functions === null) {
      const shared = loadLib(false);
      const functions = {
        create: shared.library.func("int32_t mvm_hostlib_context_create(uint16_t, uint16_t, _Out_ void **, _Out_ MvmHostlibBuf *)"),
        call: shared.library.func("int32_t mvm_hostlib_context_call(void *, const uint8_t *, size_t, const uint8_t *, size_t, _Out_ MvmHostlibBuf *)"),
        inspect: shared.library.func("int32_t mvm_hostlib_context_inspect(void *, uint32_t, _Out_ MvmHostlibBuf *)"),
        retryStop: shared.library.func("int32_t mvm_hostlib_context_retry_stop(void *, _Out_ MvmHostlibBuf *)"),
        close: shared.library.func("int32_t mvm_hostlib_context_close(void *, _Out_ MvmHostlibBuf *)"),
        free: shared.library.func("int32_t mvm_hostlib_context_checked_free(_Inout_ void **)"),
      };
      this.shared = shared; // includes the actual strong library handle
      this.functions = functions;
    }
    if (this.slot[0] === null) {
      const [status] = this.bufferCall(this.functions.create, ABI_MAJOR, ABI_MINOR, this.slot);
      if (status !== OK || this.slot[0] === null) {
        throw new HostLibraryAbiError("the library refused independent context ABI negotiation");
      }
    }
    return this.functions;
  }

  private invoke: InvokeFn = (method, request) => {
    if (this.closed) throw new MvmTransportError("context is closed");
    const functions = this.allocate();
    const encoded = Buffer.from(method, "utf8");
    return this.bufferCall(functions.call, this.slot[0], encoded, encoded.length, request, request.length);
  };

  call(method: string, request?: unknown): any {
    if (this.closed || this.freed) throw new MvmTransportError("context is closed");
    if (this.busy) throw new OwnedContextFailure(undefined,
      new MvmTransportError("context is busy"), this);
    this.busy = true;
    const starting = method === "session.start";
    try {
      if (this.sessionPhase === "unknown") {
        throw new MvmTransportError("original session start remains unconfirmed");
      }
      if (starting) {
        if (this.sessionPhase !== "empty") {
          throw new MvmTransportError("context already attempted its one session start");
        }
        this.sessionPhase = "starting";
      } else if (method === "session.stop" || method === "session.call") {
        if (this.sessionPhase !== "active" || request === null || typeof request !== "object"
          || (request as Record<string, unknown>).session_id !== this.sessionId) {
          throw new MvmTransportError("session request has no original context binding");
        }
      }
      const invoke = invokeOverride ?? this.invoke;
      const reply = call(method, request, { invoke: (name, encoded) => {
        const [status, body] = invoke(name, encoded);
        if (starting) {
          this.sessionReplyBytes = body;
          if (status === OK) sessionIdFromWire(this.sessionReplyBytes);
        }
        return [status, body];
      } });
      if (starting) {
        this.sessionId = sessionIdFromReply(reply);
        this.sessionPhase = "active";
      } else if (method === "session.stop") {
        this.sessionPhase = "finished";
      }
      return reply;
    } catch (error) {
      if (starting && this.sessionPhase === "starting") {
        this.sessionPhase = "unknown";
        this.sessionError = error;
      }
      if (error instanceof Error) Object.assign(error, { recovery: this });
      throw error;
    } finally {
      this.busy = false;
    }
  }

  private requireSessionQuiescent(): void {
    if (this.busy || this.sessionPhase === "starting" || this.sessionPhase === "active"
      || this.sessionPhase === "unknown") {
      throw new OwnedContextFailure(this.sessionError,
        new MvmTransportError("original session start or stop remains unconfirmed"), this);
    }
  }

  private control(operation: "inspect" | "retryStop" | "close", part?: number): any {
    if (this.freed) throw new MvmTransportError("context was already freed");
    if (this.slot[0] === null) return undefined; // no C resource was created
    if (this.functions === null) throw new MvmTransportError("context functions unavailable");
    const fn = this.functions[operation];
    const args = part === undefined ? [this.slot[0]] : [this.slot[0], part];
    try {
      return call(`context.${operation}`, undefined, {
        invoke: () => this.bufferCall(fn, ...args),
      });
    } catch (error) {
      if (error instanceof Error) Object.assign(error, { recovery: this });
      throw error;
    }
  }

  inspect(part = 0): any {
    if (!Number.isInteger(part) || part < 0 || part > 4) {
      throw new RangeError("context inspection selector must be in 0..=4");
    }
    if (part === 0 && (this.sessionPhase === "starting" || this.sessionPhase === "unknown")) {
      throw new OwnedContextFailure(this.sessionError,
        new MvmTransportError("original session start response remains private"), this);
    }
    return this.control("inspect", part);
  }
  retry_stop(): void { this.requireSessionQuiescent(); this.control("retryStop"); }
  close(): void {
    if (this.sessionPhase === "unknown" && this.slot[0] !== null && !this.busy) {
      // No recorder/DTO can release unknown custody: consult the actual slot.
      this.control("close");
      this.sessionPhase = "finished";
      this.closed = true;
      return;
    }
    this.requireSessionQuiescent();
    this.control("close");
    this.closed = true;
  }
  free(): void {
    if (this.freed) return;
    this.requireSessionQuiescent();
    if (this.slot[0] !== null) {
      if (this.functions === null) throw new MvmTransportError("context functions unavailable");
      if (this.functions.free(this.slot) !== OK) {
        throw new OwnedContextFailure(undefined,
          new MvmTransportError("context still owns resources; close and retain it"), this);
      }
      if (this.slot[0] !== null) {
        throw new HostLibraryInternalError("checked context free did not clear its pointer");
      }
    }
    this.freed = true;
  }
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
  if (status === OK) {
    return body.length > 0 ? JSON.parse(body.toString("utf8")) : null;
  }
  let parsed: unknown;
  try {
    parsed = body.length > 0 ? JSON.parse(body.toString("utf8")) : null;
  } catch {
    throw protocolError(status);
  }
  const fields = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  let recoveryDetails: Readonly<RecoveryRequiredDetails> | undefined;
  if (status === 12 || fields.code === "RECOVERY_REQUIRED") {
    const details = fields.details;
    if (
      status !== 12 || fields.code !== "RECOVERY_REQUIRED" || fields.retryable !== false ||
      typeof fields.message !== "string" || details === null ||
      typeof details !== "object" || Array.isArray(details)
    ) {
      throw protocolError(status);
    }
    const value = details as Record<string, unknown>;
    const keys = Object.keys(value).sort();
    if (
      keys.join(",") !== "machine_id,plan_id,reason" ||
      typeof value.machine_id !== "string" || typeof value.plan_id !== "string" ||
      typeof value.reason !== "string"
    ) {
      throw protocolError(status);
    }
    recoveryDetails = Object.freeze({
      machine_id: value.machine_id, plan_id: value.plan_id, reason: value.reason,
    });
  }
  const message =
    typeof fields.message === "string"
      ? fields.message
      : `host library call \`${method}\` failed (status ${status})`;
  const Ctor = CODE_ERRORS[typeof fields.code === "string" ? fields.code : ""] ?? HostLibraryError;
  const err = new Ctor(message) as HostLibraryFailure;
  err.code = typeof fields.code === "string" ? fields.code : undefined;
  err.retryable = fields.retryable === true;
  err.status = status;
  if (recoveryDetails !== undefined) {
    Object.defineProperty(err, "details", { value: recoveryDetails, enumerable: true });
  }
  throw err;
}
