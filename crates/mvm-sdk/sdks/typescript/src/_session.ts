/**
 * Sessions — a scope in which function calls share one warm workload.
 *
 * A real session keeps a microVM warm across calls, and the in-process host
 * library cannot dispatch function calls into a microVM yet. So:
 *
 * * Under `MVM_NO_VM=1`, `session(...)` is a local scope. It mints a
 *   `local-<hex>` id, makes it visible through {@link currentSessionId} for
 *   the body's dynamic extent, and has nothing to tear down: the functions
 *   it scopes run in this process.
 * * Otherwise entering a session throws {@link MvmTransportError} before the
 *   body runs, for the same reason a function call does.
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

/** Why a session cannot be opened without `MVM_NO_VM=1`. */
export const SESSION_UNAVAILABLE =
  "a session keeps a microVM warm for function calls, and dispatching a function call " +
  "into a microVM from a host process is not available through the in-process host " +
  "library yet; set MVM_NO_VM=1 for a local session";

/** Holds the active session id for the dynamic extent of a `session()` body. */
const active = new AsyncLocalStorage<string>();

function checkId(label: string, value: string): void {
  if (!value || value.startsWith("-")) {
    throw new MvmTransportError(
      `${label} must be a non-empty string that does not start with '-'`,
    );
  }
}

/** A session against one workload. */
export class Session {
  /** Session id; `local-<hex>` for a local session. */
  readonly id: string;
  /** Workload the session is bound to. */
  readonly workload_id: string;

  constructor(workloadId: string, id: string) {
    this.workload_id = workloadId;
    this.id = id;
  }

  toString(): string {
    return this.id;
  }
}

/** The session active in the current async context, or `null`. */
export function currentSessionId(): string | null {
  return active.getStore() ?? null;
}

/**
 * Run `body` inside a session against `workloadId`, returning what it
 * returns (a promise, if it is async).
 *
 * Only a local session exists today (`MVM_NO_VM=1`); without it this throws
 * {@link MvmTransportError} and `body` never runs.
 */
export function session<T>(workloadId: string, body: (session: Session) => T): T {
  checkId("workload_id", workloadId);
  if (process.env.MVM_NO_VM !== "1") {
    throw new MvmTransportError(SESSION_UNAVAILABLE);
  }
  const handle = new Session(workloadId, `local-${crypto.randomBytes(8).toString("hex")}`);
  return active.run(handle.id, () => body(handle));
}
