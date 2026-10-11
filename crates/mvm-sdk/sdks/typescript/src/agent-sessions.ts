/** Durable local sessions, independent of short-lived session authoring. */
import { call } from "./_hostlib.js";
import {
  AGENT_SESSIONS_LIST, AGENT_SESSIONS_SHOW, AGENT_SESSIONS_OPEN,
  AGENT_SESSIONS_PARK, AGENT_SESSIONS_RENEW, AGENT_SESSIONS_RESUME,
} from "./hostabi/methods.js";

type Execute = { intent: "execute" };
type Report = Record<string, unknown>;

export function list(): Report[] {
  return call(AGENT_SESSIONS_LIST, {});
}
export function show(sessionId: string): Report {
  return call(AGENT_SESSIONS_SHOW, { session_id: sessionId });
}
export function open(sessionId: string, opts: Execute & { members?: string[]; resumePoint?: string }): Report {
  return call(AGENT_SESSIONS_OPEN, { intent: opts.intent, request: {
    session_id: sessionId, members: opts.members ?? [], resume_point: opts.resumePoint ?? null,
  } });
}
export function park(sessionId: string, opts: Execute & {
  reason: string; journalCursor: number; approvalHead?: string; retainFor?: string; expectedGeneration?: number;
}): Report {
  return call(AGENT_SESSIONS_PARK, { intent: opts.intent, request: {
    session_id: sessionId, reason: opts.reason, journal_cursor: opts.journalCursor,
    approval_head: opts.approvalHead ?? null, retain_for: opts.retainFor ?? null,
    expected_generation: opts.expectedGeneration ?? null,
  } });
}
export function renew(sessionId: string, opts: Execute & {
  extendFor: string; expectedDeadline?: number; expectedGeneration?: number;
}): Report {
  return call(AGENT_SESSIONS_RENEW, { intent: opts.intent, request: {
    session_id: sessionId, extend_for: opts.extendFor, expected_deadline: opts.expectedDeadline ?? null,
    expected_generation: opts.expectedGeneration ?? null,
  } });
}
/** boot=false still re-admits and mutates the durable session; it is not a preview. */
export function resume(sessionId: string, opts: Execute & {
  backend: string; image: string; imageSha256: string; cpus: number; memMib: number; boot: boolean;
  kernelSha256?: string; approvalHead?: string; kernel?: string; expectedGeneration?: number;
}): Report {
  return call(AGENT_SESSIONS_RESUME, { intent: opts.intent, request: {
    session_id: sessionId, backend: opts.backend, image: opts.image, image_sha256: opts.imageSha256,
    kernel_sha256: opts.kernelSha256 ?? null, cpus: opts.cpus, mem_mib: opts.memMib,
    approval_head: opts.approvalHead ?? null, boot: opts.boot, kernel: opts.kernel ?? null,
    expected_generation: opts.expectedGeneration ?? null,
  } });
}
