/**
 * Remote invocation — the TypeScript half of Tier C.
 *
 * A **declared subset** of the Python surface, not a full port. The
 * sizing pass found one half of Python's dispatch that has no TypeScript
 * form at all, so this module implements what is portable and refuses
 * what is not, rather than pretending:
 *
 * * **Real-VM invocation** — implemented. Encodes `[args, kwargs]`, feeds
 *   it to `mvmctl invoke` over stdin, and decodes stdout.
 * * **`MVM_NO_VM=1` local dispatch — not implemented, permanently.**
 *   Python derives the wrapper's argv from the function object itself
 *   (`__module__`, `__name__`, `inspect.getfile`). JavaScript cannot ask
 *   a function which module defined it, `fn.name` does not survive
 *   minification, and a source path is only recoverable by parsing a
 *   stack trace — which fails for any function received rather than
 *   defined locally. Setting `MVM_NO_VM=1` here raises
 *   `NoVmIntrospectionError` rather than silently doing something else.
 * * **Sessions** — not in this increment; an active session is simply
 *   not consulted yet.
 *
 * The error types come from the Rust registry via `_errors/types.js`;
 * this module is what raises them, which is why they are emitted into
 * TypeScript at all.
 */

import * as child from "node:child_process";

import { resolveCliBin } from "./_cli.js";
import {
  EmittingContextError,
  MsgpackUnavailable,
  MvmTransportError,
  NoVmIntrospectionError,
  PayloadTooLarge,
  RemoteError,
} from "./_errors/types.js";

const ENVELOPE_MARKER = "MVM_ENVELOPE: ";
const DEFAULT_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const DEFAULT_INVOKE_TIMEOUT_SEC = 60;

/** Read a positive number from the environment, falling back on anything unparseable. */
function envNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const parsed = Number(raw);
  // Python's `env_float` / `env_int` silently fall back on a malformed
  // value; match that rather than inventing a new failure mode.
  return Number.isFinite(parsed) ? parsed : fallback;
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

function encode(format: string, args: unknown[], kwargs: Record<string, unknown>): Buffer {
  if (format === "msgpack") {
    // Python's SDK raises this when msgpack is declared but absent. The
    // TypeScript SDK ships no msgpack codec at all, so the condition is
    // unconditional rather than an import probe.
    throw new MsgpackUnavailable(
      "the TypeScript SDK has no msgpack codec; declare `format: \"json\"` on the entrypoint",
    );
  }
  return Buffer.from(JSON.stringify([args, kwargs]), "utf-8");
}

function decodeEnvelope(body: string): RemoteError | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const env = parsed as Record<string, unknown>;
  const { kind, error_id, message } = env;
  if (typeof kind !== "string" || typeof error_id !== "string" || typeof message !== "string") {
    return null;
  }
  return new RemoteError({ kind, error_id, message });
}

/** Find a structured envelope in the wrapper's stderr, mirroring the Python scan. */
function parseErrorEnvelope(stderr: string): RemoteError | null {
  for (const line of stderr.split("\n")) {
    const idx = line.indexOf(ENVELOPE_MARKER);
    if (idx < 0) continue;
    const found = decodeEnvelope(line.slice(idx + ENVELOPE_MARKER.length).trim());
    if (found !== null) return found;
  }
  const stripped = stderr.trim();
  if (!stripped) return null;
  const last = stripped.split("\n").at(-1)?.trim() ?? "";
  if (last.startsWith("{") && last.endsWith("}")) return decodeEnvelope(last);
  return null;
}

interface InvokeOptions {
  callSite: string;
  fnSelector?: string;
}

/** Invoke `functionName` in `workloadId` and return its decoded result. */
export function invokeSync(
  workloadId: string,
  format: string,
  args: unknown[],
  kwargs: Record<string, unknown>,
  options: InvokeOptions,
): unknown {
  checkEmittingContext(options.callSite);
  checkId("workload_id", workloadId);

  if (process.env.MVM_NO_VM === "1") {
    // The unportable half. Refused explicitly so the mode fails loudly
    // rather than appearing to work against a real VM.
    throw new NoVmIntrospectionError(
      "MVM_NO_VM=1 has no TypeScript implementation: it dispatches by introspecting " +
        "the local function's module and source path, which JavaScript cannot recover " +
        "from a function value. Run against a real microVM instead.",
    );
  }

  const payload = encode(format, args, kwargs);
  const payloadCap = envNumber("MVM_MAX_PAYLOAD_BYTES", DEFAULT_MAX_PAYLOAD_BYTES);
  if (payload.byteLength > payloadCap) {
    throw new PayloadTooLarge(
      `encoded payload for ${workloadId} is ${payload.byteLength} bytes, exceeding ` +
        `MVM_MAX_PAYLOAD_BYTES=${payloadCap}. Hint: pass large blobs via a mounted ` +
        "volume rather than function args.",
    );
  }

  const bin = resolveCliBin("remote invocation");
  const argv = ["invoke"];
  if (options.fnSelector !== undefined) argv.push("--fn", options.fnSelector);
  argv.push("--stdin", "-", "--", workloadId);

  const timeoutMs = envNumber("MVM_INVOKE_TIMEOUT_SEC", DEFAULT_INVOKE_TIMEOUT_SEC) * 1000;
  const maxBuffer = envNumber("MVM_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES);

  const result = child.spawnSync(bin, argv, {
    input: payload,
    timeout: timeoutMs,
    maxBuffer,
  });

  if (result.error !== undefined) {
    const code = (result.error as NodeJS.ErrnoException).code;
    if (code === "ETIMEDOUT") {
      throw new MvmTransportError(`mvmctl invoke ${workloadId} timed out after ${timeoutMs / 1000}s`);
    }
    if (code === "ENOBUFS") {
      throw new MvmTransportError(
        `mvmctl invoke ${workloadId} exceeded ${maxBuffer}-byte output cap`,
      );
    }
    throw new MvmTransportError(`failed to spawn mvmctl: ${result.error.message}`);
  }

  const stderr = (result.stderr ?? Buffer.alloc(0)).toString("utf-8");
  if (result.status !== 0) {
    const envelope = parseErrorEnvelope(stderr);
    if (envelope !== null) throw envelope;
    throw new MvmTransportError(
      `mvmctl invoke ${workloadId} exited ${result.status}: ${stderr.trim() || "(no stderr)"}`,
    );
  }

  const stdout = (result.stdout ?? Buffer.alloc(0)).toString("utf-8");
  try {
    return JSON.parse(stdout);
  } catch (err) {
    throw new MvmTransportError(
      `mvmctl invoke ${workloadId} returned undecodable output: ${(err as Error).message}`,
    );
  }
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

  /** Invoke inside the microVM and return the decoded result. */
  sync(...args: unknown[]): unknown {
    return invokeSync(this.workload_id, this.format, args, {}, {
      callSite: "RemoteFunction.sync(...)",
      fnSelector: this.local.name || undefined,
    });
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
 * `ref.some_function(...)` invokes `some_function` in that workload.
 * Python does this with `__getattr__`; the equivalent here is a `Proxy`.
 */
export interface WorkloadRef {
  readonly id: string;
  readonly format: string;
  [callable: string]: unknown;
}

/** Build a {@link WorkloadRef} for `workloadId`. */
export function workload_ref(workloadId: string, format: string = "json"): WorkloadRef {
  checkId("workload_id", workloadId);
  const own: Record<string, unknown> = { id: workloadId, format };
  return new Proxy(own, {
    get(target, property) {
      if (typeof property !== "string" || property in target) {
        return target[property as string];
      }
      return (...args: unknown[]) =>
        invokeSync(workloadId, format, args, {}, {
          callSite: `workload_ref(${workloadId}).${property}(...)`,
          fnSelector: property,
        });
    },
  }) as WorkloadRef;
}
