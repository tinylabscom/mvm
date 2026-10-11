/** Host volume lifecycle. Recovery, key custody and admission stay client-owned. */
import { call } from "./_hostlib.js";
import {
  VOLUME_ATTACHMENTS, VOLUME_CREATE, VOLUME_DETACH, VOLUME_INSPECT, VOLUME_LIST,
  VOLUME_LOCK, VOLUME_MOUNT, VOLUME_RESTORE, VOLUME_SNAPSHOT, VOLUME_UNLOCK,
} from "./hostabi/methods.js";

export function list(): Record<string, unknown>[] { return call(VOLUME_LIST, {}); }
export function inspect(name: string): Record<string, unknown> { return call(VOLUME_INSPECT, { name }); }
export function create(name: string, capacityMib: number, opts: { root?: string } = {}): Record<string, unknown> {
  return call(VOLUME_CREATE, { name, capacity_mib: capacityMib, root: opts.root ?? null });
}
export function unlock(name: string): Record<string, unknown> { return call(VOLUME_UNLOCK, { name }); }
export function lock(name: string): Record<string, unknown> { return call(VOLUME_LOCK, { name }); }
export function mount(
  vm: string, volume: string, guestPath: string,
  opts: { host?: string; access?: "read-only" | "read-write" } = {},
): Record<string, unknown> {
  return call(VOLUME_MOUNT, { vm, volume, guest_path: guestPath, host: opts.host ?? null, access: opts.access ?? "read-only" });
}
export function detach(vm: string, guestPath: string): Record<string, unknown> {
  return call(VOLUME_DETACH, { vm, guest_path: guestPath });
}
export function attachments(vm: string): Record<string, unknown>[] { return call(VOLUME_ATTACHMENTS, { vm }); }
export function snapshot(name: string, snapshot: string): Record<string, unknown> { return call(VOLUME_SNAPSHOT, { name, snapshot }); }
export function restore(name: string, snapshot: string): Record<string, unknown> { return call(VOLUME_RESTORE, { name, snapshot }); }
