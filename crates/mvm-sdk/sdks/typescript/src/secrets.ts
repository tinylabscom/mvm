/** Host-local secret metadata, never stored secret values. */
import { call } from "./_hostlib.js";
import { SECRET_GET } from "./hostabi/methods.js";
import type { SecretGet } from "./hostabi/host_abi.js";

/** Return metadata for a local secret, or null when absent.
 * Storage faults throw a host-library error rather than looking like absence.
 */
export function get(name: string, tenant = "local"): SecretGet["reply"] {
  return call(SECRET_GET, { tenant, name });
}
