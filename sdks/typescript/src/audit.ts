/**
 * `mvm.audit` — workload-emitted audit entries (the `host.audit.v1` service),
 * callable from inside a booted workload.
 *
 * `emit` / `emitBatch` append to the chain-signed per-VM workload audit log over
 * the host-services broker. The request carries no `category`: the host handler
 * forces `workload_audit` and stamps the host-authoritative IDs, so a workload
 * can never write a host-category entry (claim 8). The 4 KiB per-record cap and
 * the rate limit are host-enforced and surface here as typed
 * {@link BadRequestError} / {@link RateLimitedError}.
 */

import { call, type InvokeFn } from "./_hostsvc.js";

export const HOST_AUDIT_SERVICE = "host.audit.v1";

interface EmitOptions {
  timeoutSecs?: number;
  invoke?: InvokeFn;
}

function nowRfc3339(): string {
  // 2026-06-16T00:00:00Z — second precision, UTC.
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Append one audit entry. `fields` is opaque workload JSON; `ts` is an RFC 3339
 * timestamp (defaults to now). Returns the new chain head.
 */
export function emit(fields: unknown, ts?: string, opts: EmitOptions = {}): string {
  const record = { ts: ts ?? nowRfc3339(), fields };
  return call("host.audit.emit", record, opts).chain_head as string;
}

/**
 * Append a batch of audit entries in one call. Each item is opaque workload JSON
 * (the record `fields`), stamped with the current time. Returns the final chain
 * head.
 */
export function emitBatch(entries: unknown[], opts: EmitOptions = {}): string {
  const now = nowRfc3339();
  const batch = { entries: entries.map((fields) => ({ ts: now, fields })) };
  return call("host.audit.emit_batch", batch, opts).chain_head as string;
}
