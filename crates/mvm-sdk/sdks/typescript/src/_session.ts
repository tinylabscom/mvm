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
import { NativeContext, OwnedContextFailure, sessionIdFromReply } from "./_hostlib.js";
import { SESSION_START, SESSION_STOP } from "./hostabi/methods.js";

/** Holds the active session for the dynamic extent of a `session()` body. */
const active = new AsyncLocalStorage<Session>();
const MAX_CLEANUP_FAILURES = 16;
// Module-private error bookkeeping hook, not an ownership or transport token.
const rememberBodyFailure = Symbol("session body failure");

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
  private binding: string | null;
  /** Workload the session is bound to. */
  readonly workload_id: string;
  /** Whether a microVM on the host backs this session. */
  readonly host: boolean;
  /** The session VM's name, for a host session. */
  private vmName: string | null;
  readonly context: NativeContext | null;
  private stopPhase: "starting" | "unknown" | "running" | "closing" | "closed";
  private startError: unknown;
  private primaryError: { value: unknown } | null = null;
  private readonly cleanupErrors: unknown[] = [];
  private cleanupBusy = false;

  constructor(workloadId: string, id: string | null, opts: { host?: boolean; vmName?: string | null; context?: NativeContext } = {}) {
    this.workload_id = workloadId;
    this.binding = id;
    this.host = opts.host ?? false;
    this.vmName = opts.vmName ?? null;
    this.context = opts.context ?? null;
    this.stopPhase = id === null ? "starting" : "running";
  }

  get id(): string {
    if (this.binding === null) {
      throw this.startFailure(new MvmTransportError("original session binding remains unknown"));
    }
    return this.binding;
  }

  get vm_name(): string | null { return this.vmName; }

  /** Allocate the receiver before its one ordinary host start operation. */
  static startHost(workloadId: string, request: Record<string, unknown>): Session {
    const context = new NativeContext();
    const handle = new Session(workloadId, null, { host: true, context });
    try {
      const reply: unknown = context.call(SESSION_START, request);
      handle.completeStart(reply);
      return handle;
    } catch (error) {
      throw handle.startFailure(error);
    }
  }

  private completeStart(reply: unknown): void {
    this.binding = sessionIdFromReply(reply);
    const value = reply as Record<string, unknown>;
    this.vmName = typeof value.vm_name === "string" ? value.vm_name : null;
    this.stopPhase = "running";
  }

  private startFailure(error: unknown): unknown {
    if (this.stopPhase === "starting") {
      this.startError = error;
      this.stopPhase = "unknown";
    }
    return this.context === null ? error : new OwnedContextFailure(
      this.startError, error, this.context, this,
    );
  }

  toString(): string {
    return this.id;
  }

  [rememberBodyFailure](error: unknown): void {
    if (this.primaryError === null) this.primaryError = { value: error };
  }

  private cleanupPrimary(): unknown {
    return this.primaryError === null ? this.startError : this.primaryError.value;
  }

  retry_stop(): void {
    if (!this.host || this.stopPhase === "closed") return;
    if (this.context === null) throw new MvmTransportError("session has no original owning context");
    if (this.cleanupBusy || this.cleanupErrors.length >= MAX_CLEANUP_FAILURES) {
      throw new OwnedContextFailure(this.cleanupPrimary(),
        new MvmTransportError("cleanup is busy or its error retention budget is exhausted; no operation dispatched"),
        this.context, this);
    }
    this.cleanupBusy = true;
    try {
      if (this.stopPhase === "unknown") {
        // Let the same C allocation decide pre-dispatch release. Neither
        // the start error nor its wire status authorizes SDK cleanup.
        this.context.close();
        this.context.free();
        this.stopPhase = "closed";
        return;
      }
      if (this.stopPhase === "starting") {
        throw this.startFailure(new MvmTransportError("original session start is not ready for cleanup"));
      }
      if (this.stopPhase === "running") {
        this.context.call(SESSION_STOP, { session_id: this.id });
        this.stopPhase = "closing";
      }
      this.context.close();
      this.context.free();
      this.stopPhase = "closed";
    } catch (error) {
      this.cleanupErrors.push(error);
      if (error instanceof OwnedContextFailure && error.session === this) throw error;
      throw new OwnedContextFailure(this.cleanupPrimary(), error, this.context, this);
    } finally {
      this.cleanupBusy = false;
    }
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

export function hostContextFor(workloadId: string): NativeContext | null {
  const current = active.getStore();
  return hostSessionFor(workloadId) === null ? null : current?.context ?? null;
}

function startHostSession(workloadId: string, opts: SessionOptions): Session {
  const request: Record<string, unknown> = { workload: workloadId };
  if (opts.idle_timeout_secs !== undefined) {
    if (!Number.isInteger(opts.idle_timeout_secs) || opts.idle_timeout_secs <= 0) {
      throw new RangeError("idle_timeout_secs must be a positive integer");
    }
    request.idle_timeout_secs = opts.idle_timeout_secs;
  }
  return Session.startHost(workloadId, request);
}

function stopHostSession(handle: Session): void {
  handle.retry_stop();
}

/** Neither the body error nor cleanup uncertainty may replace the other. */
function stopAfterFailure(handle: Session, primary: unknown): never {
  handle[rememberBodyFailure](primary);
  stopHostSession(handle);
  throw primary;
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
    return stopAfterFailure(handle, err);
  }
  if (result instanceof Promise) {
    return result.then(
      (value) => {
        stopHostSession(handle);
        return value;
      },
      (err: unknown) => {
        return stopAfterFailure(handle, err);
      },
    ) as T;
  }
  stopHostSession(handle);
  return result;
}
