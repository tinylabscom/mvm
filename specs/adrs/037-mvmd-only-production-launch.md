# ADR-037 — `mvmd` is the only production launch authority

**Status: Accepted**
**Date: 2026-08-04**
**Note on the number.** Until 2026-09-04 two ADRs held 037: this one and the
userspace socket datapath, now [ADR-052](052-userspace-socket-datapath.md).
This one kept the number because it is `Accepted` and cited as current
authority. A citation of "ADR-037" that predates that date and discusses
networking means ADR-052; one that discusses launch authority means this ADR.

## Context

`mvm` has both development and production security postures. A production
workload is sealed, admitted, and launched under the fleet control plane;
development workloads retain the local iteration and interactive surfaces.
Without an explicit launch-authority rule, a local CLI, SDK, test harness, or
future embedding could accidentally be treated as a production launcher merely
because it supplied a production-looking artifact or flag.

## Decision

The **only** path that may launch a workload in production is a launch kicked
off by the authenticated `mvmd` control plane. `mvmd` owns production
placement, admission, and launch authority; `mvm` executes the resulting
admitted request.

Every launch that is not initiated by `mvmd` is **development mode**, without
exception. This includes local `mvmctl` and SDK launches, direct library or
host-daemon invocations, test and benchmark harnesses, and developer tooling.
Those paths must use the development posture and must never be inferred to be
production from an artifact profile, environment variable, or operator flag.

This decision governs **launch**, not artifact preparation. Local tooling may
still build, inspect, or validate a sealed/production-shaped artifact for
development and deployment preparation; that activity does not itself launch
production.

## Consequences

- Production launch authority is identified by authenticated `mvmd` origin,
  not by caller convention or a local boolean.
- Local execution is always a dev-tier operation, even when it exercises the
  same runtime code used by the fleet.
- The `mvm`/`mvmd` boundary must preserve the origin and admission evidence
  needed for `mvm` to reject any attempt to use the production posture outside
  the `mvmd`-initiated path.
- Documentation and APIs must describe local `--prod`-shaped operations as
  artifact preparation or validation unless they are part of an `mvmd`
  launch.
