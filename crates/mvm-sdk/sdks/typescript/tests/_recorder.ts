/**
 * A stand-in host library for tests.
 *
 * Installed through `setInvokeForTesting`, it records every `(method,
 * request)` pair the SDK sends and answers from canned replies, so a test
 * asserts the exact request sequence without loading a library or booting
 * anything.
 */

import { setInvokeForTesting, type InvokeFn } from "../src/_hostlib.js";

/** A canned library failure: the status and error body `call` turns into a typed error. */
export interface CannedFailure {
  readonly failure: { status: number; code: string; message: string; retryable: boolean };
}

export function failure(code: string, message: string, opts: { retryable?: boolean; status?: number } = {}): CannedFailure {
  return { failure: { status: opts.status ?? 1, code, message, retryable: opts.retryable ?? false } };
}

/** A reply, or a function of the request that produces one. */
export type Reply = unknown | ((request: any) => unknown);

export interface RecordedCall {
  method: string;
  request: any;
}

export class HostRecorder {
  readonly calls: RecordedCall[] = [];
  private readonly replies = new Map<string, Reply[]>();

  /**
   * Answer `method` with `replies`, in order. The last one keeps answering
   * once the others are used up, so a single reply serves every call.
   */
  on(method: string, ...replies: Reply[]): this {
    this.replies.set(method, [...replies]);
    return this;
  }

  /** Methods called, in order. */
  methods(): string[] {
    return this.calls.map((c) => c.method);
  }

  /** Requests sent to `method`, in order. */
  requests(method: string): any[] {
    return this.calls.filter((c) => c.method === method).map((c) => c.request);
  }

  readonly invoke: InvokeFn = (method, requestJson) => {
    const request = requestJson.length > 0 ? JSON.parse(requestJson.toString("utf8")) : undefined;
    this.calls.push({ method, request });
    const queue = this.replies.get(method);
    if (queue === undefined || queue.length === 0) {
      throw new Error(`test recorder has no reply for ${method}`);
    }
    const next = queue.length > 1 ? queue.shift() : queue[0];
    const reply = typeof next === "function" ? (next as (r: unknown) => unknown)(request) : next;
    if (reply !== null && typeof reply === "object" && "failure" in (reply as object)) {
      const f = (reply as CannedFailure).failure;
      return [f.status, Buffer.from(JSON.stringify({ code: f.code, message: f.message, retryable: f.retryable }), "utf8")];
    }
    return [0, reply === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(reply), "utf8")];
  };

  install(): this {
    setInvokeForTesting(this.invoke);
    return this;
  }
}

export function uninstallRecorder(): void {
  setInvokeForTesting(null);
}

/** One stream batch carrying `chunks` of output. */
export function batch(
  chunks: Array<[stream: "stdout" | "stderr", text: string]>,
  end?: { kind: "exited"; code: number } | { kind: "killed"; signal: number } | { kind: "timed_out" },
): Record<string, unknown> {
  const reply: Record<string, unknown> = {
    events: chunks.map(([stream, text]) => ({ stream, data_b64: Buffer.from(text, "utf8").toString("base64") })),
    done: end !== undefined,
  };
  if (end !== undefined) reply.outcome = end;
  return reply;
}

/** The `machine.run` reply for a booted machine. */
export function runReply(name: string, buildMode: "dev" | "prod"): Record<string, unknown> {
  return {
    machine: { id: `id-${name}`, name, status: "running" },
    plan_id: "plan-0",
    build_mode: buildMode,
  };
}
