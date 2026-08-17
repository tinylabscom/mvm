/**
 * Sessions — the last piece of Tier C.
 *
 * Python holds the active session in a `contextvars.ContextVar` and
 * resets its `Token` in `__exit__`. `AsyncLocalStorage` does not work
 * that way: it scopes a value to a *callback*, with no token to hand
 * back later. The two available shapes are not equivalent, so the choice
 * is recorded rather than papered over:
 *
 *   * `session(id, body)` — what this module implements. The session is
 *     visible for exactly the dynamic extent of `body`, including across
 *     `await`, and two concurrent sessions in different async tasks
 *     cannot see each other's.
 *   * `using s = session(id)` over a module-level variable — closer to
 *     Python's call shape, but concurrent sessions clobber one another.
 *
 * The first was chosen because the failure mode of the second is one
 * session's context leaking into another, which is a correctness bug
 * rather than an ergonomic one.
 *
 * The abandonment net is also weaker than Python's, and deliberately so
 * rather than by oversight. Python registers a `weakref.finalize` that
 * best-effort stops a session the caller never closed. JavaScript's
 * `FinalizationRegistry` may never run and is not run at exit, so a
 * `try/finally` around the callback is the stronger guard available —
 * which is another reason to scope by callback rather than by disposal.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import * as child from "node:child_process";

import { resolveCliBin } from "./_cli.js";
import { MvmTransportError } from "./_errors/types.js";

const DEFAULT_SESSION_START_TIMEOUT_SEC = 60;
const DEFAULT_SESSION_STOP_TIMEOUT_SEC = 30;
const DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024;

/** Holds the active session id for the dynamic extent of a `session()` body. */
const active = new AsyncLocalStorage<string>();

function envNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number(raw);
  // Matches Python's `env_float` / `env_int`, which fall back silently
  // on anything unparseable rather than raising.
  return Number.isFinite(parsed) ? parsed : fallback;
}

function checkId(label: string, value: string): void {
  if (!value || value.startsWith("-")) {
    throw new MvmTransportError(
      `${label} must be a non-empty string that does not start with '-'`,
    );
  }
}

function runSessionVerb(argv: string[], timeoutSec: number, label: string): string {
  const bin = resolveCliBin("session management");
  const result = child.spawnSync(bin, argv, {
    timeout: timeoutSec * 1000,
    maxBuffer: envNumber("MVM_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES),
  });

  if (result.error !== undefined) {
    const code = (result.error as NodeJS.ErrnoException).code;
    if (code === "ETIMEDOUT") {
      throw new MvmTransportError(`${label} timed out after ${timeoutSec}s`);
    }
    if (code === "ENOBUFS") {
      throw new MvmTransportError(`${label} exceeded its output cap`);
    }
    throw new MvmTransportError(`failed to spawn mvmctl: ${result.error.message}`);
  }

  const stderr = (result.stderr ?? Buffer.alloc(0)).toString("utf-8").trim();
  if (result.status !== 0) {
    throw new MvmTransportError(
      `${label} exited ${result.status}: ${stderr || "(no stderr)"}`,
    );
  }
  return (result.stdout ?? Buffer.alloc(0)).toString("utf-8").trim();
}

function startSession(workloadId: string): string {
  const timeout = envNumber("MVM_SESSION_START_TIMEOUT_SEC", DEFAULT_SESSION_START_TIMEOUT_SEC);
  const id = runSessionVerb(
    ["session", "start", "--", workloadId],
    timeout,
    `mvmctl session start ${workloadId}`,
  );
  if (!id) {
    throw new MvmTransportError(
      `mvmctl session start ${workloadId} returned an empty session id`,
    );
  }
  return id;
}

function stopSession(sessionId: string): void {
  const timeout = envNumber("MVM_SESSION_STOP_TIMEOUT_SEC", DEFAULT_SESSION_STOP_TIMEOUT_SEC);
  runSessionVerb(["session", "stop", sessionId], timeout, `mvmctl session stop ${sessionId}`);
}

/** A warm session against one workload. */
export class Session {
  /** Substrate-assigned session id. */
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
 * Run `body` with a warm session against `workloadId`.
 *
 * The session is stopped when `body` returns or throws. If `body`
 * returns a promise, the session is stopped once it settles — so an
 * async body is awaited rather than torn down underneath.
 */
export function session<T>(workloadId: string, body: (session: Session) => T): T {
  checkId("workload_id", workloadId);
  const handle = new Session(workloadId, startSession(workloadId));

  // Teardown must not mask a body failure: the substrate's session
  // reaper collects the VM regardless, so a failed stop is swallowed the
  // way Python's `_teardown` swallows it.
  const teardown = () => {
    try {
      stopSession(handle.id);
    } catch {
      /* best effort, matching Python */
    }
  };

  let result: T;
  try {
    result = active.run(handle.id, () => body(handle));
  } catch (err) {
    teardown();
    throw err;
  }

  if (result instanceof Promise) {
    return result.then(
      (value) => {
        teardown();
        return value;
      },
      (err) => {
        teardown();
        throw err;
      },
    ) as T;
  }

  teardown();
  return result;
}
