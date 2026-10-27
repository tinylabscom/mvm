/** Read-only checkpoint catalog access through the client-owned host service. */
import { call } from "./_hostlib.js";
import { CHECKPOINT_LIST } from "./hostabi/methods.js";
import type { CheckpointMeta } from "./hostabi/host_abi.js";

export type { CheckpointMeta } from "./hostabi/host_abi.js";

/**
 * Complete metadata in ID order, preserving omitted legacy fields.
 * Catalog data is not authenticated lineage or permission to restore.
 * A missing catalog is empty; unsafe or malformed metadata throws a host error.
 */
export function list(): CheckpointMeta[] {
  return call(CHECKPOINT_LIST, {});
}
