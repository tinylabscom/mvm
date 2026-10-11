/** Host-local maintenance through the client-backed host library. */
import { call } from "./_hostlib.js";
import { MAINTENANCE_RECONCILE } from "./hostabi/methods.js";

/**
 * Preview registry drift, or repair it with explicit `apply: true`.
 * Non-fatal repair errors remain in the report's `errors` array.
 * This operates on the host registry, not a guest or a remote gateway.
 */
export function reconcile(
  opts: { apply?: boolean } = {},
): Record<string, string[]> {
  return call(MAINTENANCE_RECONCILE, { apply: opts.apply ?? false });
}
