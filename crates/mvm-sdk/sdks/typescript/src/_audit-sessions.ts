/** Configured-host verified queries, distinct from in-guest audit emission. */
import { call } from "./_hostlib.js";
import { AUDIT_SESSIONS_LIST, AUDIT_SESSIONS_SHOW, AUDIT_SESSIONS_VERIFY } from "./hostabi/methods.js";

export interface SessionOptions { tenant?: string; since?: string; until?: string }
export function list(opts: SessionOptions = {}): Record<string, unknown> {
  return call(AUDIT_SESSIONS_LIST, { tenant: opts.tenant ?? "local", range: { since: opts.since ?? null, until: opts.until ?? null } });
}
export function show(selector: string, opts: SessionOptions & { kind?: string } = {}): Record<string, unknown> {
  return call(AUDIT_SESSIONS_SHOW, {
    tenant: opts.tenant ?? "local", selector,
    filter: { kind: opts.kind ?? null, range: { since: opts.since ?? null, until: opts.until ?? null } },
  });
}
export function verify(selector: string, opts: { tenant?: string } = {}): Record<string, unknown> {
  return call(AUDIT_SESSIONS_VERIFY, { tenant: opts.tenant ?? "local", selector });
}
