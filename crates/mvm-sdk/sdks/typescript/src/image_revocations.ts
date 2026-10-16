/** Canonical offline administration; no acquisition or trust-policy override. */
import { call } from "./_hostlib.js";
import { IMAGE_REVOCATIONS_STATUS, IMAGE_REVOCATIONS_UPDATE } from "./hostabi/methods.js";

export interface CheckpointReport { publication: number; issued_at: string; sha256: string }
export interface StatusReport extends CheckpointReport {
  signer_identity: string;
  not_after: string;
  entries: number;
}

/** Refusal can initialize private infrastructure, but does not establish applied state. */
export function update(documentPath: string, bundlePath: string): CheckpointReport {
  return call(IMAGE_REVOCATIONS_UPDATE, { document_path: documentPath, bundle_path: bundlePath });
}
/** Missing state can initialize the private store root/lock. */
export function status(): StatusReport { return call(IMAGE_REVOCATIONS_STATUS, {}); }
