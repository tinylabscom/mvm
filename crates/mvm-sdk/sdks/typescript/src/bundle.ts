/** Host-signed exports. No private keys cross the ABI. */
import { call } from "./_hostlib.js";
import { BUNDLE_EXPORT } from "./hostabi/methods.js";
import type { ExportPosture } from "./hostabi/host_abi.js";

/** Wire-shaped posture is validated by the client, including unknown fields. */
export type { ExportPosture } from "./hostabi/host_abi.js";

/** cmdline names a host file; the result preserves every client report field. */
function exportBundle(
  template: string,
  out: string,
  opts: { label?: string | null; cmdline?: string | null; posture?: ExportPosture | null } = {},
): Record<string, unknown> {
  return call(BUNDLE_EXPORT, {
    template, out, label: opts.label ?? null, cmdline: opts.cmdline ?? null,
    posture: opts.posture ?? null,
  });
}

export { exportBundle as export };
