/** Complete checkpoint metadata; inspection is not verification or restore authority. */
import { call } from "./_hostlib.js";
import { CHECKPOINT_LIST } from "./hostabi/methods.js";
import type { CheckpointListReply } from "./hostabi/host_abi.js";

export type { CheckpointListReply } from "./hostabi/host_abi.js";

/**
 * List complete records in host-provided lexicographic ID order.
 * Preserve digests, nulls, and omitted defaults without projecting metadata.
 */
export function list(): CheckpointListReply {
  return call(CHECKPOINT_LIST, {});
}
