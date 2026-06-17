/**
 * In-guest host-services transport — a thin `koffi` shim over the one
 * `libmvm_host_services.so` C ABI.
 *
 * A workload running *inside* the microVM calls `mvm.audit` / `mvm.host`, which
 * build the verb's typed request and hand it to {@link call}. This module is the
 * only hand-written transport piece: it loads the shared object, marshals the
 * request as JSON across the C ABI (`mvm_hsvc_call` — JSON in, JSON out, an
 * `int32` status, paired `mvm_hsvc_free`), and maps the status onto a typed
 * error. Every other language SDK is the same shim over the same `.so`, so the
 * wire + framing live once, in Rust — and Node needs no native AF_VSOCK: the
 * `.so` owns the vsock dial.
 *
 * Holds no key and is not a security boundary: it runs in the untrusted guest
 * over the advisory broker transport. The host derives identity from the
 * connection and enforces the `ExecutionPlan.services` binding, the
 * category-forcing and size/rate caps, and the correlation-id assignment.
 */

import { createRequire } from "node:module";

/** Where mkGuest bakes the shared object inside the runtime overlay. */
const LIB_PATH_ENV = "MVM_HOST_SERVICES_LIB";
const DEFAULT_LIB_PATH = "/mvm/runtime/lib/libmvm_host_services.so";

const DEFAULT_TIMEOUT_SECS = 5;

// Must match the MVM_HSVC_* status codes in the Rust cdylib.
const OK = 0;
const BAD_REQUEST = 1;
const RATE_LIMITED = 2;
const UNAVAILABLE = 3;
const NOT_BOUND = 4;
const NOT_IMPLEMENTED = 5;
const SERVICE = 6;
const TRANSPORT = 7;
const INVALID_INPUT = 8;

/** Base of every typed host-services failure. */
export class HostServiceError extends Error {}
/** The host rejected the record shape or size (e.g. the 4 KiB audit cap). */
export class BadRequestError extends HostServiceError {}
/** The per-workload audit emit rate limit is exhausted. */
export class RateLimitedError extends HostServiceError {}
/** The host could not answer (handler down, broker not ready). */
export class UnavailableError extends HostServiceError {}
/** The workload's `ExecutionPlan.services` did not bind the service. */
export class NotBoundError extends HostServiceError {}
/** The verb is not implemented in this build (e.g. `host.cost.tenant`). */
export class VerbNotImplementedError extends HostServiceError {}
/** Any other typed broker error code. */
export class ServiceError extends HostServiceError {}
/** Connect, framing, or (de)serialization failure on the vsock path. */
export class TransportError extends HostServiceError {}
/** The request was malformed: unknown method or a body the verb rejects. */
export class InvalidInputError extends HostServiceError {}

const STATUS_ERRORS: Record<number, new (msg: string) => HostServiceError> = {
  [BAD_REQUEST]: BadRequestError,
  [RATE_LIMITED]: RateLimitedError,
  [UNAVAILABLE]: UnavailableError,
  [NOT_BOUND]: NotBoundError,
  [NOT_IMPLEMENTED]: VerbNotImplementedError,
  [SERVICE]: ServiceError,
  [TRANSPORT]: TransportError,
  [INVALID_INPUT]: InvalidInputError,
};

/** The C-call seam: `(method, requestJson, timeoutSecs) -> [status, body]`. */
export type InvokeFn = (
  method: string,
  requestJson: Buffer,
  timeoutSecs: number,
) => [number, Buffer];

interface CallOptions {
  timeoutSecs?: number;
  /** Override the C-call seam (used by tests; defaults to the koffi loader). */
  invoke?: InvokeFn;
}

let lib: { call: (...args: unknown[]) => number; free: (buf: unknown) => void } | null = null;

/** Load and memoize the shared object, declaring the C ABI signatures. */
function loadLib() {
  if (lib === null) {
    // Lazy `require` so importing this package never pulls koffi or the `.so`
    // on a host (authoring) machine — only an in-guest call touches it.
    const require = createRequire(import.meta.url);
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const koffi = require("koffi");
    const path = process.env[LIB_PATH_ENV] ?? DEFAULT_LIB_PATH;
    const handle = koffi.load(path);
    koffi.struct("MvmHsvcBuf", { data: "uint8_t*", len: "size_t" });
    const call = handle.func(
      "int32_t mvm_hsvc_call(const char*, size_t, const char*, size_t, uint64_t, _Out_ MvmHsvcBuf*)",
    );
    const free = handle.func("void mvm_hsvc_free(MvmHsvcBuf)");
    lib = {
      call: (...args: unknown[]) => call(...args),
      free: (buf: unknown) => free(buf),
    };
    (lib as Record<string, unknown>).koffi = koffi;
  }
  return lib;
}

/**
 * Call the C ABI once and return `[status, responseBytes]`. The single test
 * seam: pass `opts.invoke` to drive the marshalling layer without a real `.so`
 * or broker.
 */
function realInvoke(method: string, requestJson: Buffer, timeoutSecs: number): [number, Buffer] {
  const handle = loadLib() as Record<string, unknown> & {
    call: (...a: unknown[]) => number;
    free: (b: unknown) => void;
  };
  const koffi = (handle as Record<string, unknown>).koffi as {
    decode: (ptr: unknown, type: string, len: number) => Uint8Array;
  };
  const out: { data: unknown; len: number } = { data: null, len: 0 };
  const status = handle.call(
    method,
    Buffer.byteLength(method, "utf8"),
    requestJson,
    requestJson.length,
    BigInt(Math.trunc(timeoutSecs)),
    out,
  );
  let body = Buffer.alloc(0);
  try {
    if (out.len > 0) {
      body = Buffer.from(koffi.decode(out.data, "uint8_t", out.len));
    }
  } finally {
    handle.free(out);
  }
  return [status, body];
}

/**
 * Marshal `request` to JSON, call `method`, and return the parsed reply. Throws
 * a typed {@link HostServiceError} subclass when the host refuses.
 */
export function call(method: string, request: unknown, opts: CallOptions = {}): any {
  const invoke = opts.invoke ?? realInvoke;
  const requestJson = Buffer.from(JSON.stringify(request), "utf8");
  const [status, body] = invoke(method, requestJson, opts.timeoutSecs ?? DEFAULT_TIMEOUT_SECS);
  const parsed = body.length > 0 ? JSON.parse(body.toString("utf8")) : {};
  if (status === OK) {
    return parsed;
  }
  const message: string =
    parsed && typeof parsed === "object" && typeof parsed.message === "string"
      ? parsed.message
      : "";
  const Ctor = STATUS_ERRORS[status] ?? ServiceError;
  throw new Ctor(message || `host service call \`${method}\` failed (status ${status})`);
}
