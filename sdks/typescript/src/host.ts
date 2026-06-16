/**
 * `mvm.host` — host-services clock + cost (`host.time.v1` / `host.cost.v1`),
 * callable from inside a booted workload.
 *
 * Both ride the same broker transport as `mvm.audit` and carry an empty body —
 * the scope is the verb, so a workload cannot ask for another scope's clock or
 * spend. Host refusals surface as typed {@link HostServiceError} subclasses
 * (e.g. {@link NotBoundError} when the service is unbound).
 */

import { call, type InvokeFn } from "./_hostsvc.js";

export const HOST_TIME_SERVICE = "host.time.v1";
export const HOST_COST_SERVICE = "host.cost.v1";

interface HostOptions {
  timeoutSecs?: number;
  invoke?: InvokeFn;
}

export type CostScope = "workload" | "tenant";

/** Host wall-clock in milliseconds since the Unix epoch. */
export function time(opts: HostOptions = {}): number {
  return call("host.time.now", {}, opts).wall_ms as number;
}

/**
 * Accumulated spend for `scope` (`"workload"` or `"tenant"`), in micro-USD
 * (1e-6 USD).
 */
export function cost(scope: CostScope = "workload", opts: HostOptions = {}): number {
  if (scope !== "workload" && scope !== "tenant") {
    throw new RangeError(`cost scope must be 'workload' or 'tenant', got ${String(scope)}`);
  }
  return call(`host.cost.${scope}`, {}, opts).spent_micros_usd as number;
}
