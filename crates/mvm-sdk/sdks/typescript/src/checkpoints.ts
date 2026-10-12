/** Local checkpoints. Image-revert launch handoffs and revert/rewind/advance are unavailable. */
import { call } from "./_hostlib.js";
import {
  CHECKPOINTS_LIST, CHECKPOINTS_INFO, CHECKPOINTS_DIFF, CHECKPOINTS_VERIFY,
  CHECKPOINTS_TIMELINE, CHECKPOINTS_REMOVE, CHECKPOINTS_CAPTURE, CHECKPOINTS_RESTORE, CHECKPOINTS_FORK,
} from "./hostabi/methods.js";

type Execute = { intent: "execute" };
type Report = Record<string, unknown>;
export function list(): Report[] { return call(CHECKPOINTS_LIST, {}); }
export function info(id: string): Report { return call(CHECKPOINTS_INFO, { id }); }
export function diff(a: string, b: string): Report { return call(CHECKPOINTS_DIFF, { a, b }); }
export function verify(id: string): Report { return call(CHECKPOINTS_VERIFY, { id }); }
export function timeline(target: string, opts: { kind?: "checkpoint" | "image" } = {}): Report {
  return call(CHECKPOINTS_TIMELINE, { target, kind: opts.kind ?? null });
}
export function remove(id: string, opts: Execute): Report {
  return call(CHECKPOINTS_REMOVE, { intent: opts.intent, request: { id } });
}
export function capture(name: string, opts: Execute & { class: "fs_quick" | "vm_full"; tag?: string }): Report {
  return call(CHECKPOINTS_CAPTURE, { intent: opts.intent, request: { name, class: opts.class, tag: opts.tag ?? null } });
}
export function restore(id: string, opts: Execute & { tenant: string }): Report {
  return call(CHECKPOINTS_RESTORE, { intent: opts.intent, request: { id, tenant: opts.tenant } });
}
/** A vm_full fork boots even with boot=false. Secret rebinding is not exposed. */
export function forkCheckpoint(id: string, opts: Execute & {
  tenant: string; boot: boolean; newId?: string; hypervisor?: string; cpus?: number; memory?: string;
}): Report {
  return call(CHECKPOINTS_FORK, { intent: opts.intent, request: {
    id, tenant: opts.tenant, boot: opts.boot, new_id: opts.newId ?? null, hypervisor: opts.hypervisor ?? "",
    cpus: opts.cpus ?? null, memory: opts.memory ?? null,
  } });
}
