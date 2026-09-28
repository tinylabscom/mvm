/**
 * Sessions — a scope in which function calls share one warm workload.
 *
 * * Under `MVM_NO_VM=1`, `session(...)` is a local scope. It mints a
 *   `local-<hex>` id, makes it visible through {@link currentSessionId} for
 *   the body's dynamic extent, and has nothing to tear down: the functions
 *   it scopes run in this process.
 * * Otherwise `session(...)` boots the workload's microVM through the host
 *   library (`session.start`) before the body runs, dispatches every call to
 *   that workload inside the body into it (`session.call`), and stops it
 *   (`session.stop`) once the body — or the promise it returns — settles.
 *   The VM is admitted and audited exactly as `mvmctl machine session start`
 *   admits one. A warm VM is not a warm interpreter: each call still runs
 *   the function's wrapper afresh.
 *
 * Python holds the active session in a `contextvars.ContextVar` and resets
 * its `Token` in `__exit__`. `AsyncLocalStorage` scopes a value to a
 * *callback* instead, with no token to hand back later, so the shape here is
 * `session(id, body)`. The session is visible for exactly the dynamic extent
 * of `body`, including across `await`, and two concurrent sessions in
 * different async tasks cannot see each other's. The alternative — `using
 * s = session(id)` over a module-level variable — would let concurrent
 * sessions clobber one another, which is a correctness bug rather than an
 * ergonomic one.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import * as crypto from "node:crypto";

import { MvmTransportError } from "./_errors/types.js";
import { call as hostCall } from "./_hostlib.js";
import { SESSION_START, SESSION_STOP } from "./hostabi/methods.js";

/** What the host mints as a session id: base32, lower case. */
const HOST_SESSION_ID = /^[a-z2-7]{16,64}$/;

/** Holds the active session for the dynamic extent of a `session()` body. */
const active = new AsyncLocalStorage<Session>();

function checkId(label: string, value: string): void {
  if (!value || value.startsWith("-")) {
    throw new MvmTransportError(
      `${label} must be a non-empty string that does not start with '-'`,
    );
  }
}

/** Options for {@link session}. */
export interface SessionOptions {
  /**
   * How long the host keeps an idle session VM, in seconds; the host's
   * default when omitted. Ignored for a local session.
   */
  idle_timeout_secs?: number;
}

/** A session against one workload. */
export class Session {
  /** Session id; `local-<hex>` for a local session. */
  readonly id: string;
  /** Workload the session is bound to. */
  readonly workload_id: string;
  /** Whether a microVM on the host backs this session. */
  readonly host: boolean;
  /** The session VM's name, for a host session. */
  readonly vm_name: string | null;

  constructor(workloadId: string, id: string, opts: { host?: boolean; vmName?: string | null } = {}) {
    this.workload_id = workloadId;
    this.id = id;
    this.host = opts.host ?? false;
    this.vm_name = opts.vmName ?? null;
  }

  toString(): string {
    return this.id;
  }
}

/** The session active in the current async context, or `null`. */
export function currentSessionId(): string | null {
  return active.getStore()?.id ?? null;
}

/**
 * The host session a call to `workloadId` goes into, if one is open in this
 * context. A call to another workload inside a session runs in a VM of its
 * own.
 */
export function hostSessionFor(workloadId: string): string | null {
  const current = active.getStore();
  if (current === undefined || !current.host || current.workload_id !== workloadId) {
    return null;
  }
  return current.id;
}

function startHostSession(workloadId: string, opts: SessionOptions): Session {
  const request: Record<string, unknown> = { workload: workloadId };
  if (opts.idle_timeout_secs !== undefined) {
    if (!Number.isInteger(opts.idle_timeout_secs) || opts.idle_timeout_secs <= 0) {
      throw new RangeError("idle_timeout_secs must be a positive integer");
    }
    request.idle_timeout_secs = opts.idle_timeout_secs;
  }
  const reply = hostCall(SESSION_START, request) as Record<string, unknown> | null;
  const id = reply?.session_id;
  if (typeof id !== "string" || !HOST_SESSION_ID.test(id)) {
    throw new MvmTransportError(`session.start returned no usable session id: ${JSON.stringify(reply)}`);
  }
  const vmName = typeof reply?.vm_name === "string" ? reply.vm_name : null;
  return new Session(workloadId, id, { host: true, vmName });
}

function stopHostSession(handle: Session): void {
  hostCall(SESSION_STOP, { session_id: handle.id });
}

/** Stop a session whose body failed; the body's error is the one that counts. */
function stopQuietly(handle: Session): void {
  try {
    stopHostSession(handle);
  } catch {
    // The body's own failure is what the caller needs to see.
  }
}

/**
 * Run `body` inside a session against `workloadId`, returning what it
 * returns (a promise, if it is async).
 *
 * Under `MVM_NO_VM=1` the session is local. Otherwise the workload's
 * microVM boots before `body` runs and stops once `body` — or the promise it
 * returns — settles, whether it succeeded or not.
 */
export function session<T>(
  workloadId: string,
  body: (session: Session) => T,
  opts: SessionOptions = {},
): T {
  checkId("workload_id", workloadId);
  if (process.env.MVM_NO_VM === "1") {
    const handle = new Session(workloadId, `local-${crypto.randomBytes(8).toString("hex")}`);
    return active.run(handle, () => body(handle));
  }
  const handle = startHostSession(workloadId, opts);
  let result: T;
  try {
    result = active.run(handle, () => body(handle));
  } catch (err) {
    stopQuietly(handle);
    throw err;
  }
  if (result instanceof Promise) {
    return result.then(
      (value) => {
        stopHostSession(handle);
        return value;
      },
      (err: unknown) => {
        stopQuietly(handle);
        throw err;
      },
    ) as T;
  }
  stopHostSession(handle);
  return result;
}
