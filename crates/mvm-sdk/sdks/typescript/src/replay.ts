/** Verified prompt replay defaults to preview; plaintext inputs and guest output are not returned. */
import { call } from "./_hostlib.js";
import { REPLAY_RUN_SESSION } from "./hostabi/methods.js";

export function runSession(sessionId: string, opts: {
  tenant: string; timeoutSecs: number; dryRun?: boolean; fromCheckpoint?: string; asName?: string;
}): Record<string, unknown> {
  return call(REPLAY_RUN_SESSION, {
    selection: { session_id: sessionId, from: opts.fromCheckpoint ?? null, as_name: opts.asName ?? null },
    dry_run: opts.dryRun ?? true, timeout_secs: opts.timeoutSecs, tenant: opts.tenant,
  });
}
