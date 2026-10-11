/** Inspect only the configured host context, never arbitrary roots or trust keys. */
import { call } from "./_hostlib.js";
import { POSTURE_INSPECT } from "./hostabi/methods.js";

export function inspect(): Record<string, unknown> { return call(POSTURE_INSPECT, {}); }
