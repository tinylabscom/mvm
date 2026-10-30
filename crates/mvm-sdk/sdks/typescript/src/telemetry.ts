/** One-page host-local reads; no polling, file access or health inference.
 * Known fields follow mvm-core protocol/telemetry/served.rs. Additive fields and
 * opaque record bodies are preserved, not fully Rust-validated; cursors stay closed.
 */
import { call } from "./_hostlib.js";
import { TELEMETRY_RECORDS, TELEMETRY_STATUS } from "./hostabi/methods.js";
import type { TelemetryCursor, TelemetryRecordsRequest } from "./hostabi/host_abi.js";
export type { TelemetryCursor } from "./hostabi/host_abi.js";

export class TelemetryError extends Error {
  override name = "TelemetryError";
}

export type CollectorState =
  | { kind: "connecting" | "stopped" }
  | { kind: "collecting"; generation: number }
  | { kind: "degraded"; code: string };
export interface HostLosses {
  queue_full: number;
  cap_reached: number;
  write_failed: number;
  secret_withheld: number;
}
export type TelemetryStatus =
  | { collection: "not_provisioned" }
  | {
    collection: "provisioned"; vm_name: string; state: CollectorState;
    shed: number; records_bytes: number; losses?: HostLosses; snapshot_age_ms?: number;
  };
export interface ReceivedRecord {
  received_at_ms?: number;
  record: Record<string, unknown>;
}
export interface TelemetryPage {
  records: ReceivedRecord[];
  next_cursor: TelemetryCursor;
  undecodable: number;
  exhausted: boolean;
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function uint(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
function validCursor(value: unknown): value is TelemetryCursor {
  return object(value) && Object.keys(value).length === 1 && uint(value.offset);
}
function identity(id: string): void {
  if (typeof id !== "string" || id.length === 0) throw new TypeError("id must be a non-empty string");
}

/** Read status. Unsafe envelope integers refuse rather than silently round. */
export function status(id: string): TelemetryStatus {
  identity(id);
  const reply: unknown = call(TELEMETRY_STATUS, { id });
  if (object(reply) && reply.collection === "not_provisioned") return reply as TelemetryStatus;
  if (object(reply) && reply.collection === "provisioned") {
    const state = reply.state;
    let valid = typeof reply.vm_name === "string" && uint(reply.shed) && uint(reply.records_bytes)
      && object(state) && (
        state.kind === "connecting" || state.kind === "stopped"
        || state.kind === "collecting" && uint(state.generation)
        || state.kind === "degraded" && typeof state.code === "string"
      );
    if ("snapshot_age_ms" in reply) valid = valid && uint(reply.snapshot_age_ms);
    if ("losses" in reply) {
      const losses = reply.losses;
      valid = valid && object(losses) && ["queue_full", "cap_reached", "write_failed", "secret_withheld"]
        .every((field) => uint(losses[field]));
    }
    if (valid) return reply as unknown as TelemetryStatus;
  }
  throw new TelemetryError("telemetry.status returned an invalid or unsafe status envelope");
}

/** Read once; the host defaults to 256 and clamps supplied limits (including 0)
 * to 1..1024. Reuse a cursor only for the same machine/file. No automatic retry.
 * Unsafe received cursor offsets refuse before exposure; JS cannot represent all u64.
 */
export function records(
  id: string, opts: { cursor?: TelemetryCursor | null; limit?: number | null } = {},
): TelemetryPage {
  identity(id);
  if (!object(opts)) throw new TypeError("records options must be an object");
  const request: TelemetryRecordsRequest = { id };
  if (opts.cursor != null) {
    if (!validCursor(opts.cursor)) throw new RangeError("cursor must contain only a non-negative safe integer offset");
    request.cursor = { offset: opts.cursor.offset };
  }
  if (opts.limit != null) {
    if (!uint(opts.limit)) throw new RangeError("limit must be a non-negative safe integer");
    request.limit = opts.limit;
  }
  const reply: unknown = call(TELEMETRY_RECORDS, request);
  if (!object(reply) || !Array.isArray(reply.records) || !validCursor(reply.next_cursor)
      || !uint(reply.undecodable) || typeof reply.exhausted !== "boolean"
      || !reply.records.every((item: unknown) => object(item) && object(item.record)
        && (!("received_at_ms" in item) || uint(item.received_at_ms)))) {
    throw new TelemetryError("telemetry.records returned an invalid or unsafe page envelope");
  }
  return reply as unknown as TelemetryPage;
}
