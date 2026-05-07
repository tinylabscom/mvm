# 0013 - Local Drift Primitives for `mvm`

## Status

Proposed

## Date

2026-05-06

## Context

`mvm` is the local microVM runtime and CLI. It builds, launches, inspects, and manages individual microVM instances and their host-side runtime resources.

Fleet-level reconciliation belongs in `mvmd`, but `mvmd` cannot reliably detect or repair drift unless `mvm` exposes deterministic local primitives.

This ADR defines the `mvm` side of drift management.

`mvm` must not become the global control plane. It must not own fleet placement, rolling updates, scheduling, node health policy, or cross-host reconciliation. Those concerns belong to `mvmd`.

Instead, `mvm` must provide the local truth needed by `mvmd-agent` and operators:

- what was requested locally;
- what artifacts were built;
- what was launched;
- what currently exists on the host;
- what differs from the local declaration;
- which local repairs are safe;
- which local conditions must be reported or quarantined by a higher-level controller.

## Decision

`mvm` will implement local drift primitives but not fleet-level drift policy.

`mvm` will support:

1. deterministic desired-state input for a single VM or local VM group;
2. structured actual-state inspection;
3. local desired-vs-actual diffing;
4. typed local drift reports;
5. conservative local repair operations;
6. quarantine recommendations for unsafe drift;
7. machine-readable state export for `mvmd-agent`;
8. audit-friendly command output.

`mvmd` remains responsible for global desired state, reconciliation policy, tenant placement, rolling updates, wake/sleep distribution, host management, and fleet-level quarantine decisions.

## Scope

### In Scope for `mvm`

`mvm` owns local correctness for:

- VM configuration files;
- kernel, initrd, rootfs, and image digests;
- Firecracker, Lima, Incus, containerd, or other local backend launch configuration;
- VM process lifecycle;
- guest CID and vsock configuration;
- TAP device creation and validation;
- bridge attachment validation;
- local IP/MAC assignment validation when provided by a controller;
- cgroup configuration;
- jailer configuration;
- runtime directories;
- mounted volumes;
- local snapshot files;
- local artifact cache entries;
- local logs and audit events;
- local health checks.

### Out of Scope for `mvm`

`mvm` does not own:

- fleet scheduling;
- tenant placement across nodes;
- global desired-state signing policy;
- global reconciliation loops;
- cross-node wake/sleep distribution;
- rolling update orchestration;
- release waves;
- global node drain decisions;
- cross-node quota management;
- long-term drift event storage;
- policy decisions about whether a drifted workload should be rescheduled.

Those belong to `mvmd`.

## Definitions

### Local Desired State

Local desired state is the complete declaration needed for `mvm` to construct and run one VM or a bounded local set of VMs.

Examples:

- backend type;
- VM ID;
- tenant ID;
- kernel path and digest;
- rootfs path and digest;
- initrd path and digest;
- CPU count;
- memory size;
- guest CID;
- TAP device name;
- expected bridge;
- expected MAC/IP;
- cgroup limits;
- jailer settings;
- volume mounts;
- snapshot source;
- runtime directory;
- expected release version.

### Local Actual State

Local actual state is what `mvm` observes directly on the host.

Examples:

- VM process exists or does not exist;
- process PID;
- backend runtime status;
- TAP device existence;
- bridge membership;
- cgroup files and limits;
- jail directory contents;
- artifact file digests;
- volume mount status;
- snapshot file presence and digest;
- vsock availability;
- runtime directory contents;
- local log status.

### Local Drift

Local drift is any mismatch between local desired state and local actual state.

Local drift does not imply global policy. It is an observation and classification that can be consumed by `mvmd-agent` or a human operator.

## Required Commands

`mvm` must expose a small set of commands that can be used by both humans and automation.

### `mvm inspect`

Inspect actual local state.

Example:

```sh
mvm inspect <instance-id> --output json
```

Must report:

- instance identity;
- tenant identity if known;
- backend;
- lifecycle state;
- process status;
- artifact digests;
- network state;
- cgroup state;
- jailer state;
- volume state;
- snapshot state;
- health status;
- detected local warnings.

### `mvm state export`

Export actual local state in a stable machine-readable schema.

Example:

```sh
mvm state export --output json
```

This command is intended for `mvmd-agent`.

It must avoid unstable human-only formatting.

### `mvm diff`

Compare a local desired-state declaration with actual local state.

Example:

```sh
mvm diff --desired ./instance.json --output json
```

Must report typed drift categories and recommended local action.

### `mvm doctor`

Run local host checks.

Example:

```sh
mvm doctor --output json
```

Must check whether the host can safely run declared microVM workloads.

Checks may include:

- required binaries;
- backend availability;
- KVM availability where applicable;
- networking prerequisites;
- cgroup support;
- jailer support;
- filesystem permissions;
- artifact cache readability;
- snapshot directory health;
- log directory health.

### `mvm repair`

Perform explicitly requested local repair operations.

Example:

```sh
mvm repair <instance-id> --repair missing-runtime-dir
```

Repair must be conservative and idempotent.

`mvm repair` must not silently update desired state to match actual state.

### `mvm quarantine-local`

Put a local instance into a safe stopped or isolated state when instructed by an operator or controller.

Example:

```sh
mvm quarantine-local <instance-id> --reason image-digest-mismatch
```

This is a local action. Global quarantine policy still belongs to `mvmd`.

## Local Drift Categories

`mvm diff` must classify drift into typed categories.

### Missing Local Resource

A declared local resource is missing.

Examples:

- runtime directory missing;
- TAP device missing;
- cgroup missing;
- jail directory missing;
- VM process missing;
- snapshot file missing.

Possible recommendation: repair, restart, rebuild, or report.

### Unexpected Local Resource

A resource exists locally but is not declared.

Examples:

- unknown VM process;
- unexpected TAP device;
- orphaned jail directory;
- untracked rootfs;
- unknown runtime directory;
- unexpected mounted volume.

Possible recommendation: report, quarantine, or require operator review.

### Local Configuration Mismatch

A resource exists but does not match local desired state.

Examples:

- wrong CPU count;
- wrong memory size;
- wrong guest CID;
- wrong backend;
- wrong kernel args;
- wrong cgroup limit;
- wrong jailer setting.

Possible recommendation: restart or recreate.

### Local Artifact Mismatch

An artifact digest does not match desired state.

Examples:

- wrong kernel digest;
- wrong initrd digest;
- wrong rootfs digest;
- wrong snapshot digest;
- wrong bundled workflow digest.

Possible recommendation: quarantine.

Artifact mismatch is security-sensitive.

### Local Network Mismatch

Host networking does not match declared local state.

Examples:

- missing TAP device;
- TAP device attached to wrong bridge;
- wrong MAC address;
- wrong IP address;
- duplicate detected assignment;
- missing expected bridge membership.

Possible recommendation: repair when local and safe; quarantine or report when tenant isolation may be affected.

### Local Lifecycle Mismatch

The instance lifecycle does not match declared local state.

Examples:

- desired running, actual stopped;
- desired stopped, actual running;
- desired asleep, actual running;
- desired draining, actual accepting local start operations.

Possible recommendation: start, stop, sleep, wake, or report.

## Local Repair Policy

`mvm` may repair only local drift that is safe, explicit, and idempotent.

Safe examples:

- recreate an empty runtime directory under the declared runtime path;
- recreate a missing TAP device with the declared name and ownership;
- restore a declared cgroup limit;
- remove an empty temporary directory created by a failed `mvm` operation;
- restart a VM when the desired state explicitly allows restart.

Unsafe examples:

- accept an unknown image as desired;
- accept an unknown snapshot as desired;
- attach a VM to a different bridge than declared;
- modify tenant assignment;
- weaken seccomp, jailer, or cgroup settings;
- infer missing desired state from actual state;
- delete unknown resources without operator or controller instruction.

`mvm` must never repair drift by mutating desired state.

## Local Quarantine Recommendations

`mvm` must recommend quarantine when local drift may indicate compromise or tenant isolation failure.

Examples:

- artifact digest mismatch;
- unknown VM process using an `mvm` runtime path;
- VM attached to an undeclared bridge;
- snapshot tenant mismatch;
- jailer configuration missing or weakened;
- cgroup isolation missing;
- unexpected listening socket associated with a VM process;
- runtime directory owned by an unexpected UID/GID.

`mvm` may perform local quarantine only when explicitly invoked by an operator or `mvmd-agent`.

## Output Schema Requirements

Machine-readable output must be stable and versioned.

Example shape:

```json
{
  "schema_version": "mvm.local_state.v1",
  "node_id": "local-dev-node",
  "observed_at": "2026-05-06T00:00:00Z",
  "instances": [
    {
      "instance_id": "vm_123",
      "tenant_id": "tenant_abc",
      "backend": "firecracker",
      "desired_ref": "sha256:...",
      "actual": {
        "lifecycle": "running",
        "pid": 12345,
        "guest_cid": 42
      },
      "drift": [
        {
          "category": "local_artifact_mismatch",
          "severity": "critical",
          "resource": "rootfs",
          "desired": "sha256:expected",
          "actual": "sha256:actual",
          "recommended_action": "quarantine"
        }
      ]
    }
  ]
}
```

The schema must avoid leaking secrets.

Secret values must be redacted or represented as opaque handles.

## Audit Requirements

`mvm` must emit local audit events for drift-relevant operations.

Events include:

- inspect started;
- diff computed;
- drift detected;
- repair attempted;
- repair completed;
- repair failed;
- local quarantine requested;
- local quarantine completed;
- local quarantine failed.

Audit records must include:

- timestamp;
- instance ID;
- tenant ID if known;
- local host ID if known;
- command;
- resource type;
- drift category;
- action;
- result;
- error if any;
- actor if known;
- `mvm` version;
- backend.

## Security Invariants

The following invariants are mandatory:

1. `mvm` never treats actual state as the source of truth.
2. `mvm` never accepts unknown artifacts automatically.
3. `mvm` never weakens local security settings as a repair action.
4. `mvm` never hides manual host mutation.
5. `mvm` never leaks secrets in inspect, diff, state export, or audit output.
6. `mvm` never crosses tenant boundaries during local repair.
7. `mvm` never performs destructive cleanup unless the resource is proven safe or explicitly instructed.
8. `mvm` exposes enough structured state for `mvmd-agent` to reconcile safely.
9. `mvm` commands used by automation must support JSON output.
10. `mvm` local repair operations must be idempotent.

## Development Mode

Local development may run without signed desired state.

However, development mode must still expose drift explicitly.

Development convenience must not teach unsafe production behavior.

Dev shells and setup scripts must not silently mutate host networking, cgroups, system services, permissions, or runtime directories outside declared paths.

If privileged host setup is required, it must be explicit and documented.

## Production Mode

In production, `mvm` should normally be invoked by `mvmd-agent` rather than directly by humans.

Production desired state should be authenticated before `mvm` launches or repairs resources.

Direct operator usage should be audited.

Production repairs should generally be initiated by `mvmd-agent`, even when executed through `mvm` local primitives.

## Consequences

### Positive

- Keeps `mvm` focused on local deterministic runtime behavior.
- Gives `mvmd-agent` reliable primitives for reconciliation.
- Avoids duplicating fleet policy inside `mvm`.
- Makes manual local mutation visible.
- Improves security and auditability.
- Supports local debugging without requiring the full control plane.

### Negative

- Requires stable JSON schemas.
- Requires careful host inspection code.
- Adds command surface area to `mvm`.
- Requires test coverage for local drift categories.
- Requires discipline to avoid turning `mvm` into a scheduler.

### Neutral

- Some local repairs are supported.
- Some drift only produces recommendations.
- `mvmd` remains responsible for global policy.
- Development mode may be less strict than production mode, but must remain explicit.

## Implementation Plan

Recommended first implementation:

1. Define `LocalDesiredState`.
2. Define `LocalActualState`.
3. Define `LocalDrift` and `LocalDriftCategory`.
4. Add `mvm inspect <instance-id> --output json`.
5. Add `mvm state export --output json`.
6. Add `mvm diff --desired <file> --output json`.
7. Add digest validation for kernel/rootfs/initrd/snapshots.
8. Add network inspection for TAP and bridge membership.
9. Add cgroup and jailer inspection.
10. Add conservative `mvm repair` for missing runtime directories only.
11. Add local audit events.
12. Add tests for drift classification.
13. Add fixture-based tests for JSON schema stability.

Do not begin with broad automatic repair.

Detection and reporting must come first.

## Relationship to `mvmd`

This ADR is intentionally narrower than the `mvmd` drift ADR.

`mvm` answers:

> What exists on this host for this VM, and how does it differ from the local declaration?

`mvmd` answers:

> What should exist across the fleet, which nodes are out of convergence, and what global action should be taken?

The `mvmd` ADR should be considered the canonical source for fleet-level drift detection and reconciliation policy.

This `mvm` ADR defines the local primitives that make that policy enforceable.

## Open Questions

- What is the exact `LocalDesiredState` schema?
- Should `mvm diff` accept only files, or also stdin?
- Should `mvm inspect` support all backends equally in v1?
- Which backend-specific fields belong in the stable schema?
- How should local host identity be determined?
- Should `mvm repair` require an explicit repair type every time?
- Should destructive cleanup require a separate `--confirm-resource-id` flag?
- How should local audit events be stored before `mvmd-agent` exists?
- Should `mvm doctor` include performance/capacity checks or only correctness checks?
- Should development mode allow unsigned desired state by default?

## Related ADRs

- `mvmd` drift detection and reconciliation
- Runtime isolation and microVM backend selection
- Tenant networking and TAP allocation
- Snapshot lifecycle and integrity
- Jailer, cgroup, and host security model
- Local state export and inspection
- Audit logging and event model
