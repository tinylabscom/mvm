/** Read-only checkpoint catalog access through the client-owned host service. */
import { call } from "./_hostlib.js";
import { CHECKPOINT_LIST } from "./hostabi/methods.js";
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
