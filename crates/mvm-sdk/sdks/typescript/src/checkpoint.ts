/** Host-local checkpoint operations through the client-owned host service. */
import { call } from "./_hostlib.js";
import { CHECKPOINT_LIST, CHECKPOINT_REMOVE, CHECKPOINT_VERIFY_LINEAGE } from "./hostabi/methods.js";
import type { CheckpointListReply } from "./hostabi/host_abi.js";

export type CheckpointMeta = CheckpointListReply[number];

/**
 * Complete metadata in ID order, preserving omitted legacy fields.
 * Catalog data is not authenticated lineage or permission to restore.
 * A missing catalog is empty; unsafe or malformed metadata throws a host error.
 */
export function list(): CheckpointListReply {
  return call(CHECKPOINT_LIST, {});
}

/**
 * Remove a host-local checkpoint after metadata, pin and descendant checks.
 * Missing directories are already removed; incomplete metadata or failed guard
 * reads refuse deletion. These preflight checks do not serialize concurrent
 * pin, lineage or path changes, or grant guest/remote deletion authority.
 */
export function remove(id: string): void {
  call(CHECKPOINT_REMOVE, { id });
}

/**
 * Verify metadata ancestry against this host's signed audit chains.
 * Refuses missing, changed or unaudited ancestry. Does not hash snapshot blobs,
 * establish runtime compatibility or authorize a restore. Loading the existing
 * host anchor may initialize its identity when an audit directory exists.
 */
export function verifyLineage(id: string): void {
  call(CHECKPOINT_VERIFY_LINEAGE, { id });
}
