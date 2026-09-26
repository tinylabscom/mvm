/**
 * Guest process plumbing shared by `Sandbox` and `Machine`.
 *
 * Both facades start a process with `guest.proc.start` and collect it through
 * the stream methods, so the request shapes and the outcome-to-exit-code
 * mapping live here once. A caller passes `fail` to decide which error type a
 * malformed reply becomes; errors the library itself reports propagate as the
 * typed `HostLibraryError` subclass `call` raised, untouched.
 */

import { call } from "./_hostlib.js";
import {
  GUEST_PROC_START,
  GUEST_PROC_STREAM_CLOSE,
  GUEST_PROC_STREAM_NEXT,
  GUEST_PROC_STREAM_OPEN,
} from "./hostabi/methods.js";

/** Builds the error a malformed reply is reported as. */
export type ReplyFailure = (message: string) => Error;

/** One chunk of process output, as the stream delivered it. */
export interface GuestStreamEvent {
  stream: string;
  data: Uint8Array;
}

/** A finished process: its exit code and everything it wrote. */
export interface GuestProcessResult {
  exitCode: number;
  stdout: Uint8Array;
  stderr: Uint8Array;
}

/** Exit status a shell reports for a command stopped by its time limit. */
const TIMED_OUT_EXIT_CODE = 124;

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");
}

export function fromBase64(value: unknown, what: string, fail: ReplyFailure): Uint8Array {
  if (typeof value !== "string") {
    throw fail(`${what} is missing from the host library's reply`);
  }
  return new Uint8Array(Buffer.from(value, "base64"));
}

/** `timeout` in seconds as the whole-second `timeout_secs` the library takes. */
export function timeoutSecs(timeout: number | undefined): number | undefined {
  if (timeout === undefined) return undefined;
  if (!Number.isFinite(timeout) || timeout < 0) {
    throw new RangeError("timeout must be a non-negative number of seconds");
  }
  return Math.trunc(timeout);
}

/** Start `argv` in machine `id` and return the process token. */
export function startGuestProcess(
  id: string,
  argv: string[],
  options: { env?: Record<string, string>; cwd?: string },
  fail: ReplyFailure,
): string {
  const request: Record<string, unknown> = { id, argv };
  if (options.env !== undefined && Object.keys(options.env).length > 0) {
    request.env = options.env;
  }
  if (options.cwd !== undefined) request.cwd = options.cwd;
  const reply = call(GUEST_PROC_START, request);
  const token = reply?.token;
  if (typeof token !== "string" || token.length === 0) {
    throw fail("guest.proc.start returned no process token");
  }
  return token;
}

/** Map a stream's final `outcome` to the exit code a shell would report. */
export function exitCodeOf(outcome: unknown, fail: ReplyFailure): number {
  const o = outcome as { kind?: unknown; code?: unknown; signal?: unknown } | null | undefined;
  switch (o?.kind) {
    case "exited":
      if (Number.isInteger(o.code)) return o.code as number;
      break;
    case "killed":
      if (Number.isInteger(o.signal)) return 128 + (o.signal as number);
      break;
    case "timed_out":
      return TIMED_OUT_EXIT_CODE;
  }
  throw fail(`the process ended with an outcome this SDK does not understand: ${JSON.stringify(outcome)}`);
}

/**
 * Collect a started process through its output stream.
 *
 * Every chunk reaches `onEvent` in the order the stream delivered it. A
 * stream that reports `done` is already gone on the library's side; any
 * other exit from the loop — a thrown `onEvent`, a failed wait reported by
 * `next`, a malformed reply — closes it, so an abandoned stream never holds
 * one of the library's bounded slots.
 */
export function waitGuestProcess(
  id: string,
  token: string,
  options: { timeout?: number; onEvent?: (event: GuestStreamEvent) => void },
  fail: ReplyFailure,
): GuestProcessResult {
  const openRequest: Record<string, unknown> = { id, token };
  const secs = timeoutSecs(options.timeout);
  if (secs !== undefined) openRequest.timeout_secs = secs;
  const opened = call(GUEST_PROC_STREAM_OPEN, openRequest);
  const stream = opened?.stream;
  if (!Number.isInteger(stream)) {
    throw fail("guest.proc.stream.open returned no stream id");
  }
  const stdout: Uint8Array[] = [];
  const stderr: Uint8Array[] = [];
  let done = false;
  let outcome: unknown;
  try {
    while (!done) {
      const batch = call(GUEST_PROC_STREAM_NEXT, { stream });
      if (batch === null || typeof batch !== "object" || !Array.isArray(batch.events)) {
        throw fail("guest.proc.stream.next returned a malformed batch");
      }
      // Only a `done` batch ends the loop; a reply that says so is final
      // even if a later step fails, and the stream is then gone.
      done = batch.done === true;
      outcome = batch.outcome;
      for (const event of batch.events as Array<{ stream?: unknown; data_b64?: unknown }>) {
        const name = event?.stream;
        if (name !== "stdout" && name !== "stderr") {
          throw fail(`guest.proc.stream.next delivered output on unknown stream ${JSON.stringify(name)}`);
        }
        const data = fromBase64(event.data_b64, "an output chunk's data_b64", fail);
        (name === "stdout" ? stdout : stderr).push(data);
        options.onEvent?.({ stream: name, data });
      }
    }
  } finally {
    if (!done) {
      try {
        call(GUEST_PROC_STREAM_CLOSE, { stream });
      } catch {
        // Already failing; the close is cleanup, and its error would mask
        // the one that says what went wrong.
      }
    }
  }
  return {
    exitCode: exitCodeOf(outcome, fail),
    stdout: Buffer.concat(stdout),
    stderr: Buffer.concat(stderr),
  };
}
