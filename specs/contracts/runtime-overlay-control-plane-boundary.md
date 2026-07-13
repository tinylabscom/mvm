# Contract: runtime-overlay control-plane boundary

## Status

**Proposed.** This document tightens the architectural boundary for the
readonly runtime overlay that ships under
`~/.cache/mvm/runtime-overlay/<version>/<arch>/`.

The overlay is an mvm-owned **guest runtime control-plane** artifact. It is
not a generic executable layer for workloads, and it is not a second
application filesystem.

## Goal

The runtime overlay exists for one reason:

- provide the guest-side substrate that lets a microVM talk to the host,
  receive mvm control-plane commands, and reach explicitly mediated outward
  paths

Everything else belongs somewhere else.

## Boundary

### The overlay owns

Only mvm-owned guest-side binaries whose primary purpose is one of:

- guest-to-host control-plane communication over vsock
- guest-side bootstrap required to establish the control plane
- guest-side mediation for host-authorized outbound paths
- guest-side enforcement shims that mvm requires before workload code runs

### The overlay does not own

- workload executables
- workload language runtimes, frameworks, or libraries
- workload entrypoint wrappers whose purpose is to run tenant code
- developer convenience shells or debug tools
- guest binaries that must execute before the overlay can be mounted

The practical rule is simple:

- if the binary exists to let the **platform** manage the VM, it can belong in
  the overlay
- if the binary exists to let the **workload** run, it belongs in the workload
  rootfs or image

## Mount contract

- The runtime overlay is mounted read-only at `/mvm/runtime`.
- The host must verify the cached overlay artifact against its recorded
  SHA-256 manifest before attach.
- The guest must mount only the verified dm-verity mapping, never the raw
  `overlay.ext4` block device directly.
- Workloads must not depend on `/mvm/runtime` as an application search path.
- The workload rootfs remains the source of truth for workload binaries and
  workload libraries.
- The overlay may be consumed by mvm-owned bootstrap and supervisor logic, but
  not treated as a general-purpose runtime pack for tenant code.

## Decision rules for classifying a binary

A binary belongs in the overlay only if **all** of the following are true:

1. It is shipped and versioned by mvm.
2. It runs inside the guest.
3. Its primary job is platform control-plane bootstrap, host communication, or
   host-mediated egress.
4. A workload author should not need to know it exists.
5. Removing it from the workload rootfs does not change the workload's own
   runtime contract except through mvm-managed control-plane behavior.

A binary does **not** belong in the overlay if **any** of the following are
true:

1. The workload executes it directly.
2. It is part of the workload's application ABI or language/runtime ABI.
3. It is a dev shell, debug helper, or interactive convenience tool.
4. It must run before the overlay itself can be mounted and trusted.
5. Its main job is launching tenant code rather than connecting the guest to
   mvm control-plane services.

## Current inventory audit

This table classifies the current shipped/runtime-related guest binaries against
the target boundary.

| Binary | Current shape | Target classification | Rationale |
|---|---|---|---|
| `mvm-guest-agent` | overlay | keep in overlay | primary guest control-plane agent |
| `mvm-guest-netinit` | overlay | keep in overlay | guest bootstrap needed before workload networking/control-plane is usable |
| `mvm-seccomp-apply` | overlay | keep in overlay | platform enforcement shim before workload execution |
| `mvm-egress-client` | overlay | keep in overlay | guest-side bridge for host-mediated outward traffic |
| `mvm-guest-netd` | rootfs / injected path today | candidate for overlay if it remains mvm-owned tunnel plumbing | control-plane/tunnel substrate, not workload payload |
| `mvm-oci-init` | baked into rootfs | keep out of overlay | must exist before overlay-mounted userspace is available |
| `mvm-verity-init` | initramfs / also present in overlay inventory today | keep out of overlay | executes before the overlay can be mounted; bootstraps trust for the overlay itself |
| `mvm-oci-entrypoint` | baked into rootfs | keep out of overlay by default | workload launch helper, not host communication substrate |
| `mvm-runner` | overlay | move out of overlay | launches tenant/workload code; this is workload execution surface, not control-plane transport |
| `mvm-guest-agent` dev-shell variant | overlay | move out of overlay | interactive/dev behavior, not production control-plane substrate |

## Current mismatches to resolve

Based on the shipped implementation, these are the architectural mismatches
against the stricter boundary:

1. The overlay currently carries `runner`, which is workload-execution
   machinery rather than host-communication substrate.
2. The overlay currently carries an `agent-dev-shell` variant, which is
   developer tooling surface rather than production control-plane substrate.
3. The overlay inventory currently includes `verity-init`, even though the
   actual boot chain requires it before the overlay can be mounted.
4. Some launch shapes still bake guest helpers into the rootfs for
   `RootfsOnly` execution, so the product currently has more than one guest
   runtime ownership model.

## Required invariants after cleanup

- `/mvm/runtime` contains only mvm-owned control-plane substrate.
- No workload binary or workload-facing runtime helper is required from
  `/mvm/runtime`.
- No binary needed before overlay mount is classified as an overlay payload.
- The overlay remains readonly on every admitted backend.
- A runtime overlay cache entry with missing or mismatched checksums is refused
  before boot.
- The rootfs/image remains the only owner of workload execution semantics.

## Code-audit checklist

Use this checklist before moving any binary into or out of the overlay:

1. Identify who directly executes the binary first: initramfs, mvm bootstrap,
   supervisor, or workload code.
2. Verify whether the binary must run before `/mvm/runtime` is mounted.
3. Verify whether the workload ABI or entrypoint contract changes if the binary
   moves.
4. Verify whether the binary's only external interactions are mvm control
   plane, vsock, or host-mediated egress.
5. Verify whether the binary is referenced by workload docs, workload examples,
   or user authordata. If yes, it is probably not overlay-owned.
6. Verify whether the binary is dev-only or debug-only. If yes, keep it out of
   the production overlay.
7. Verify every backend mount path still proves readonly behavior after the
   inventory change.
8. Verify `RootfsOnly` and overlay-backed launch shapes do not silently diverge
   in workload ABI.

## Review questions for future changes

Before approving a PR that touches runtime-overlay contents, ask:

1. Is this binary part of host communication / outward mediation, or is it part
   of workload execution?
2. Would a workload author notice or depend on this binary directly?
3. Could the workload still run if this binary stayed in the rootfs instead of
   the overlay?
4. Does placing it in the overlay reduce rebuild/update cost without expanding
   the workload-visible runtime surface?
5. Are we accidentally turning `/mvm/runtime` into a second application
   filesystem?

If the answer to question 5 is "yes" or "maybe", the change should not ship as
an overlay addition without a new explicit decision record.
