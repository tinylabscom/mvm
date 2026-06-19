# ADR-089 — Builder VM resident control plane

**Status:** Proposed
**Date:** 2026-06-19
**Relates to:** [ADR-013](013-libkrun-microvm-nix-pivot.md),
[ADR-046](046-builder-vm-via-libkrun.md),
[ADR-057](057-symmetric-builder-vm.md),
[ADR-071](071-stage0-bootstrap-trust-model.md),
[ADR-079](079-app-builder-product-surface.md),
[Plan 199](../plans/199-host-runtime-packaging-and-crate-boundaries.md),
[Plan 200](../plans/200-machine-ux-dx-layer.md), and
[Plan 204](../plans/204-builder-vm-resident-control-plane.md)

## Context

mvm has two different execution surfaces that are easy to confuse:

- the host-facing product surface, currently `mvmctl`;
- the Linux builder environment, which owns Nix builds/evals and Linux-only
  microVM tooling.

Plan 199 intentionally made `mvmctl` installable as a host package without
changing the guest image API. That raised a design question: should the builder
VM be a passive target launched by the host CLI, or should it be a resident
service with its own control socket that receives build/eval commands?

The product goal is a simple local UX: users install one host binary, ask it to
run/build/manage machines, and do not need host Nix for normal use. At the same
time, the trust-boundary goal is that Nix and Linux-specific work stay inside
the project builder VM, not on the macOS host and not in an unrelated VM.

Today the builder path is closer to controlled job execution: the host CLI
starts or reuses a builder VM, bind-mounts source/output directories, and runs
bounded shell/Nix jobs inside it. That is workable, but it leaves too much of the
long-term contract implicit:

- the transport is not a first-class protocol;
- shell snippets are easier to widen accidentally than typed operations;
- progress, cancellation, provenance, and cache keys are harder to make uniform;
- users and contributors can infer that host Nix is part of the runtime model.

## Decision

mvm keeps `mvmctl` as the host-facing control plane, but moves builder execution
toward a resident builder VM service exposed over a typed vsock protocol.

The target architecture is:

```text
host
  mvmctl
    validates CLI / SDK input
    performs admission and local state bookkeeping
    starts or connects to the builder VM
    sends typed BuilderRequest messages over vsock

builder VM
  mvm-builderd
    owns Nix and the builder Nix store
    owns Linux-only build/eval/syscall work
    executes allowlisted operations
    streams structured progress and returns provenance/artifacts
```

The host does not need Nix for normal use. Host Nix remains an optional
expert-facing install frontend only, for example `nix build .#mvmctl` from a
source checkout. Normal runtime and build flows use host `mvmctl` plus the
builder VM.

`mvm-builderd` is an internal execution plane, not a new user-facing CLI.
Operators and SDKs continue to use `mvmctl`; the vsock protocol is the private
transport between the host control plane and the builder execution plane.

## Protocol boundary

The long-term builder protocol is typed and allowlisted. Examples:

- `Handshake`
- `Probe`
- `FlakeCheck`
- `BuildGuestImage`
- `BuildHostTool`
- `PrefetchSource`
- `QueryStorePath`
- `CancelJob`

Each request carries explicit inputs:

- workspace/source snapshot reference;
- operation kind and schema version;
- declared environment;
- expected output kind;
- cache key or fingerprint inputs when relevant;
- admission/provenance context when the result feeds a runtime path.

Responses are structured:

- progress events;
- log chunks with redaction posture;
- final store paths or copied artifact paths;
- provenance records;
- failure category and retryability;
- resource usage when available.

Generic "run this shell command in the builder VM" is not the stable API. A raw
shell escape may exist only as a gated development/debug fallback with explicit
audit/logging and no product dependency.

## Security and trust boundary

This ADR does not weaken the existing builder boundary:

- Nix builds/evals and Linux-only microVM operations stay inside the builder VM.
- The host does not gain a normal-use Nix dependency.
- The builder service executes an allowlist of operation types, not arbitrary
  caller-provided shell.
- Source snapshots and output paths are explicit inputs/outputs, so cache keys
  and provenance stay reviewable.
- The builder service does not become a guest image dependency. MicroVM guests do
  not install `mvmctl` or `mvm-builderd`.

The host `mvmctl` remains in the TCB as the local control plane. It validates
operator intent, owns local state, and mediates builder requests. The builder VM
is the Linux execution boundary for Nix and Linux-only tooling.

## Consequences

Positive:

- Simple UX: one host binary drives the system.
- Host Nix stays optional.
- Builder jobs become explicit, cancellable, observable operations.
- Progress reporting, provenance, cache behavior, and failure categories become
  uniform.
- The implementation can retire ad hoc shell snippets gradually without changing
  user commands.

Negative:

- Requires a new daemon binary, protocol, lifecycle management, and versioning.
- The resident builder service has a wider uptime/crash-recovery surface than
  one-shot shell jobs.
- Migration must preserve existing builder behavior while replacing internals in
  slices.

## Alternatives Considered

### Require host Nix

Rejected. It makes source-based usage convenient for Nix users, but it is the
wrong default product contract. Normal users should not need to install Nix on
the host to build or run mvm workloads.

### Make the builder VM the user-facing CLI surface

Rejected. It pushes users toward thinking about the builder VM as the product.
The product surface should stay one host command. The builder VM is an internal
execution boundary.

### Keep controlled shell jobs forever

Rejected as the final state. Controlled shell jobs are useful for bootstrapping,
but they are too broad as the permanent protocol. Typed operations make the
security boundary and user-facing behavior easier to test.

### Expose a generic remote shell over vsock

Rejected as the stable API. It would be flexible, but it would blur the boundary
between product operations and arbitrary builder mutation. Debug-only escape
hatches must stay gated, logged, and out of the normal UX.

## Migration

Plan 204 owns the migration. The intended sequence is:

1. Define the builder protocol and daemon lifecycle.
2. Implement `mvm-builderd` with health/probe and one low-risk build/eval
   operation.
3. Route existing builder jobs through a compatibility adapter.
4. Move Nix flake check, guest image build, and host-tool build operations to
   typed requests.
5. Retire normal-path raw shell execution.

No user command rename is required.

