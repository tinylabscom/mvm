/**
 * Remote invocation — the TypeScript half of function dispatch.
 *
 * A function marked with {@link func} runs inside a workload's microVM. The
 * SDK reaches the host only through the in-process host library, never by
 * starting a process, and the two modes are:
 *
 * * **`MVM_NO_VM=1` — local dispatch.** The call runs the wrapped function in
 *   this process, but through the same wire discipline a microVM call would
 *   use: `[args, kwargs]` is encoded with the declared format and checked
 *   against the payload cap, decoded back, handed to the function, and its
 *   result is encoded and decoded again. A function that only works because
 *   it received a live object, or returned something the wire cannot carry,
 *   fails here rather than on its first real deployment.
 * * **Otherwise — in the workload's microVM**, through the host library's
 *   `entrypoint.call` (or `session.call` inside an open {@link session} for
 *   the same workload). The library boots the built image under a signed,
 *   audited plan, exactly as `mvmctl machine run --entrypoint` does. The
 *   encoded `[args, kwargs]` is the call's stdin and the function's encoded
 *   return value its stdout; an exception the function raised comes back as
 *   {@link RemoteError}, and a failure without that envelope as
 *   {@link MvmTransportError} carrying the exit status and stderr tail.
 *
 * {@link workload_ref} handles name a function in another workload: they
 * dispatch through the host library too, and under `MVM_NO_VM=1` they are
 * refused, having no local function to run.
 *
 * The host runs a workload's *primary* entrypoint: the guest wire has no
 * function selector yet.
 *
 * The error types come from the Rust registry via `_errors/types.js`.
 */

import {
  EmittingContextError,
  MsgpackUnavailable,
  MvmTransportError,
  NoVmIntrospectionError,
  PayloadTooLarge,
  RemoteError,
} from "./_errors/types.js";
import { call as hostCall } from "./_hostlib.js";
import { hostSessionFor } from "./_session.js";
import { ENTRYPOINT_CALL, SESSION_CALL } from "./hostabi/methods.js";

const DEFAULT_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024;

/** How much of a failed call's stderr a transport error quotes. */
export const STDERR_TAIL_BYTES = 2048;

/** Deepest nesting a decoded value may have; matches the Python SDK and the
 *  guest-side function wrappers, so a local run refuses what a real one would. */
export const MAX_RESULT_NESTING_DEPTH = 64;

/** Read a positive number from the environment, falling back on anything unparseable. */
function envNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number(raw);
  // Python's `env_float` / `env_int` silently fall back on a malformed
  // value; match that rather than inventing a new failure mode.
  return Number.isFinite(parsed) ? parsed : fallback;
}

function noVm(): boolean {
  return process.env.MVM_NO_VM === "1";
}

function checkEmittingContext(callSite: string): void {
  if (process.env.MVM_EMITTING === "1") {
    throw new EmittingContextError(
      `${callSite} is unreachable during \`mvm emit\` (MVM_EMITTING=1 is set). ` +
        "Layer-3 calls require a live microVM and only run in dev iteration.",
    );
  }
}

function checkId(label: string, value: string): void {
  if (!value || value.startsWith("-")) {
    throw new MvmTransportError(`${label} must be a non-empty string that does not start with '-'`);
  }
}

function checkFormat(format: string): void {
  if (format === "msgpack") {
    // Python raises this when msgpack is declared but not installed. The
    // TypeScript SDK ships no msgpack codec at all, so it is unconditional.
    throw new MsgpackUnavailable(
      "the TypeScript SDK has no msgpack codec; declare `format: \"json\"` on the entrypoint",
    );
  }
  if (format !== "json") {
    throw new RangeError(`unknown serialization format: ${JSON.stringify(format)}`);
  }
}

/**
 * Refuse a value JSON cannot carry faithfully. `JSON.stringify` quietly
 * turns `NaN` and `Infinity` into `null`; Python's encoder writes them and
 * its decoder refuses them. Refusing at encode time is the same outcome.
 */
function checkFinite(value: unknown, seen: Set<object> = new Set()): void {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new MvmTransportError(`value contains a non-finite number (${String(value)})`);
    }
    return;
  }
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  for (const child of Object.values(value as Record<string, unknown>)) checkFinite(child, seen);
}

function encodeJson(value: unknown): Buffer {
  checkFinite(value);
  let text: string | undefined;
  try {
    text = JSON.stringify(value);
  } catch (err) {
    throw new MvmTransportError(`failed to encode value as JSON: ${(err as Error).message}`);
  }
  // A bare `undefined` (a function with no return) has no JSON form; the
  // Python side sends `None`, which is `null`.
  return Buffer.from(text ?? "null", "utf-8");
}

function checkDepth(value: unknown, depth = 0): void {
  if (depth > MAX_RESULT_NESTING_DEPTH) {
    throw new MvmTransportError(`decoded value exceeds max nesting depth ${MAX_RESULT_NESTING_DEPTH}`);
  }
  if (value === null || typeof value !== "object") return;
  for (const child of Object.values(value as Record<string, unknown>)) checkDepth(child, depth + 1);
}

/**
 * Decode a JSON payload the way a result from a guest is decoded: bounded
 * nesting, and a parse failure reported as a transport fault. `JSON.parse`
 * already refuses the non-finite literals Python's decoder guards against.
 * Duplicate keys are not checked: this module only decodes what its own
 * encoder produced, and `JSON.stringify` cannot emit one.
 */
function decodeJson(data: Buffer): unknown {
  if (data.length === 0) return null;
  let value: unknown;
  try {
    value = JSON.parse(data.toString("utf-8"));
  } catch (err) {
    throw new MvmTransportError(`failed to decode JSON: ${(err as Error).message}`);
  }
  checkDepth(value);
  return value;
}

/** Encode `[args, kwargs]` and hold it to `MVM_MAX_PAYLOAD_BYTES`. */
function encodePayload(workloadId: string, args: unknown[], kwargs: Record<string, unknown>): Buffer {
  const payload = encodeJson([args, kwargs]);
  const cap = envNumber("MVM_MAX_PAYLOAD_BYTES", DEFAULT_MAX_PAYLOAD_BYTES);
  if (payload.byteLength > cap) {
    throw new PayloadTooLarge(
      `encoded payload for ${workloadId} is ${payload.byteLength} bytes, exceeding ` +
        `MVM_MAX_PAYLOAD_BYTES=${cap}. Hint: pass large blobs via a mounted ` +
        "volume rather than function args.",
    );
  }
  return payload;
}

function roundTrip(value: unknown): unknown {
  return decodeJson(encodeJson(value));
}

/**
 * Run `local` in this process as if it had been dispatched into
 * `workloadId`. An error `local` throws propagates unchanged. When `local`
 * returns a promise, so does this, settling with the round-tripped result.
 */
function dispatchLocal(
  workloadId: string,
  format: string,
  local: (...args: unknown[]) => unknown,
  args: unknown[],
): unknown {
  checkFormat(format);
  const decoded = decodeJson(encodePayload(workloadId, args, {})) as [unknown[], Record<string, unknown>];
  const result = local(...decoded[0]);
  if (result instanceof Promise) {
    return result.then(roundTrip);
  }
  return roundTrip(result);
}

/**
 * The host-library method and request for one call: into the open session
 * for this workload when there is one, otherwise a transient VM. Python and
 * TypeScript send the same shapes.
 */
export function hostRequest(workloadId: string, payload: Buffer): [string, Record<string, unknown>] {
  const payloadB64 = payload.toString("base64");
  const sessionId = hostSessionFor(workloadId);
  if (sessionId !== null) {
    return [SESSION_CALL, { session_id: sessionId, payload_b64: payloadB64 }];
  }
  return [ENTRYPOINT_CALL, { workload: workloadId, payload_b64: payloadB64 }];
}

function b64Field(reply: Record<string, unknown>, field: string): Buffer {
  const raw = reply[field] ?? "";
  if (typeof raw !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(raw)) {
    throw new MvmTransportError(`the host library's ${field} is not base64`);
  }
  return Buffer.from(raw, "base64");
}

/** Turn a call reply into the function's return value, or its failure. */
export function resultFromReply(workloadId: string, reply: unknown): unknown {
  if (reply === null || typeof reply !== "object" || !Number.isInteger((reply as { exit_code?: unknown }).exit_code)) {
    throw new MvmTransportError(`the call into ${workloadId} returned no exit status`);
  }
  const fields = reply as Record<string, unknown>;
  const stdout = b64Field(fields, "stdout_b64");
  const stderr = b64Field(fields, "stderr_b64");
  const exitCode = fields.exit_code as number;
  if (exitCode === 0) {
    const cap = envNumber("MVM_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES);
    if (fields.output_truncated === true || stdout.byteLength > cap) {
      throw new MvmTransportError(`the result of ${workloadId} exceeded the ${cap}-byte output cap`);
    }
    return decodeJson(stdout);
  }
  const error = fields.error;
  if (error !== null && typeof error === "object") {
    const e = error as Record<string, unknown>;
    throw new RemoteError({
      kind: String(e.kind ?? ""),
      error_id: String(e.error_id ?? ""),
      message: String(e.message ?? ""),
    });
  }
  const tail = stderr.subarray(Math.max(0, stderr.byteLength - STDERR_TAIL_BYTES)).toString("utf-8");
  const agent = fields.agent_error;
  if (agent !== null && typeof agent === "object") {
    const a = agent as Record<string, unknown>;
    throw new MvmTransportError(
      `the call into ${workloadId} was ended by the guest agent (${String(a.kind)}: ` +
        `${String(a.message)}), exit status ${exitCode}; stderr tail: ${JSON.stringify(tail)}`,
    );
  }
  throw new MvmTransportError(
    `the call into ${workloadId} exited with status ${exitCode} and no error envelope; ` +
      `stderr tail: ${JSON.stringify(tail)}`,
  );
}

/** Run one call in the workload's microVM through the host library. */
function dispatchHost(workloadId: string, format: string, args: unknown[]): unknown {
  checkFormat(format);
  const [method, request] = hostRequest(workloadId, encodePayload(workloadId, args, {}));
  return resultFromReply(workloadId, hostCall(method, request));
}

/** A function that runs inside a workload. */
export class RemoteFunction {
  readonly workload_id: string;
  readonly format: string;
  /** The wrapped local function, returned unchanged for local calls. */
  readonly local: (...args: unknown[]) => unknown;

  constructor(
    workloadId: string,
    local: (...args: unknown[]) => unknown,
    format: string = "json",
  ) {
    this.workload_id = workloadId;
    this.format = format;
    this.local = local;
  }

  /**
   * Call the function as its workload would receive it.
   *
   * Under `MVM_NO_VM=1` this runs {@link local} in-process through the wire
   * encoding; a promise-returning function yields a promise. Otherwise it
   * dispatches into the workload's microVM through the host library and
   * returns the decoded result.
   */
  sync(...args: unknown[]): unknown {
    checkEmittingContext("RemoteFunction.sync(...)");
    checkId("workload_id", this.workload_id);
    if (!noVm()) return dispatchHost(this.workload_id, this.format, args);
    return dispatchLocal(this.workload_id, this.format, this.local, args);
  }
}

/**
 * Mark a local function as running inside `workloadId`.
 *
 * Python's `@mvm.func` also derives a call schema from type hints;
 * TypeScript erases those before the program runs, so pass
 * `args_schema` / `return_schema` to `entrypoint_function` instead.
 */
export function func(
  workloadId: string,
  local: (...args: unknown[]) => unknown,
  format: string = "json",
): RemoteFunction {
  return new RemoteFunction(workloadId, local, format);
}

/**
 * A handle onto another workload, dispatching by attribute name.
 *
 * `ref.some_function(...)` names `some_function` in that workload. Python
 * does this with `__getattr__`; the equivalent here is a `Proxy`.
 */
export interface WorkloadRef {
  readonly id: string;
  readonly format: string;
  [callable: string]: unknown;
}

/**
 * Build a {@link WorkloadRef} for `workloadId`.
 *
 * A call through it dispatches into that workload's microVM through the
 * host library. Under `MVM_NO_VM=1` it is refused with
 * {@link NoVmIntrospectionError}: there is no local function to run in its
 * place.
 */
export function workload_ref(workloadId: string, format: string = "json"): WorkloadRef {
  checkId("workload_id", workloadId);
  const own: Record<string, unknown> = { id: workloadId, format };
  return new Proxy(own, {
    get(target, property) {
      if (typeof property !== "string" || property in target) {
        return target[property as string];
      }
      return (...args: unknown[]) => {
        checkEmittingContext(`workload_ref(${workloadId}).${property}(...)`);
        if (noVm()) {
          throw new NoVmIntrospectionError(
            `workload_ref(${workloadId}).${property} names a function in another workload; ` +
              "MVM_NO_VM=1 runs only functions defined in this process, and there is no " +
              "local function to run in its place",
          );
        }
        return dispatchHost(workloadId, format, args);
      };
    },
  }) as WorkloadRef;
}
