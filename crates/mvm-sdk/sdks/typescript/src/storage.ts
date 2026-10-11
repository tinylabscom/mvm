/** Host-local thin-pool inspection and explicit garbage collection. */
import { call } from "./_hostlib.js";
import { STORAGE_GC, STORAGE_INFO } from "./hostabi/methods.js";

export function info(opts: { mock?: boolean } = {}): Record<string, unknown> {
  return call(STORAGE_INFO, { mock: opts.mock ?? false });
}

/** Preview by default. keepPrefix retains matching volume names. */
export function gc(
  opts: { apply?: boolean; mock?: boolean; keepPrefix?: string[] } = {},
): Record<string, unknown> {
  return call(STORAGE_GC, {
    apply: opts.apply ?? false, mock: opts.mock ?? false, keep_prefix: opts.keepPrefix ?? [],
  });
}
