# Plan 298 — Resident warm-claim service and sub-300ms machine launch

**Status:** In progress.

## Objective

Make a warmed `machine run` claim complete in strictly less than 300ms from
admission completion to authenticated guest readiness on Apple Silicon and
Linux KVM, without using Virtualization.framework/VZ and without silently
falling back to a cold launch.

The existing sub-300ms contract remains defined by Plan 297. This plan turns
that contract into an executable architecture: a resident host service owns
prewarmed golden VMs, claims create copy-on-write children, and read-only
directory mounts bind at child materialization time rather than becoming
snapshot state.

## Current evidence and constraints

The reported run spends approximately 430 seconds before backend start in the
drive/image phase, approximately 1.2 seconds in backend start, and only a few
milliseconds waiting for the guest agent. The `pip install` command is
workload time and is measured separately from launch readiness.

The current pool path rejects all volume-bearing launches, the HVF backend does
not advertise standby-pool support, and the child-fork request has no share
binding field. These are intentional fail-closed boundaries until the backend
can bind a host directory before the restored child resumes.

## Architecture

```text
CLI
  -> local Claim RPC
  -> resident warm-launch service
       -> compatibility-keyed golden VM pool
       -> child CoW materialization
       -> fresh identity, authority, and host channels
       -> fixed virtio-fs share-slot binding
       -> restore/resume
       -> authenticated guest readiness
```

The hot path contains no image resolution, artifact download, Nix/build
operation, ext4 generation, host-directory copy, VMM process spawn, or
synchronous cleanup.

The pool key contains image/kernel/initramfs identity, backend version, guest
agent protocol, CPU/memory shape, runtime overlay, network-policy shape,
device layout, and share-slot shape. It never contains a host path or host
directory contents.

Every warmed VM has a fixed share-slot topology. A claim supplies an opened
read-only host directory binding to the child before vCPUs resume. If the
backend cannot provide this operation, the claim is refused as cold-only.

## Issue sequence

1. [x] [#2192](https://github.com/tinylabscom/mvm/issues/2192) — Define the
   resident warm-launch service contract and explicit warm/cold lifecycle.
2. [~] [#2193](https://github.com/tinylabscom/mvm/issues/2193) — Move image,
   kernel, initramfs, and runtime-overlay preparation into an asynchronous
   content-addressed prewarm pipeline.
3. [ ] [#2194](https://github.com/tinylabscom/mvm/issues/2194) — Implement the
   Apple Silicon libkrun/HVF in-process golden VM pool and child restore path.
   Virtualization.framework/VZ is excluded.
4. [ ] [#2195](https://github.com/tinylabscom/mvm/issues/2195) — Implement fixed
   virtio-fs share slots and claim-time read-only host binding.
5. [~] [#2196](https://github.com/tinylabscom/mvm/issues/2196) — Complete and
   validate the Linux KVM/Firecracker warm-pool backend. The direct
   Firecracker/KVM witness is green; production standby admission remains.
6. [ ] [#2197](https://github.com/tinylabscom/mvm/issues/2197) — Harden the VMM
   and share-control processes with least privilege and platform-specific
   defense in depth.
7. [ ] [#2198](https://github.com/tinylabscom/mvm/issues/2198) — Finish timing,
   refusal reasons, warm-required semantics, and command-line behavior.
8. [~] [#2199](https://github.com/tinylabscom/mvm/issues/2199) — Add the
   1,000-claim benchmark matrix and CI enforcement. The live Apple Silicon
   matrix passes; CI enforcement and the remaining backend dimensions remain.

## Dependency graph

```text
service contract
    ├── artifact prewarm
    ├── macOS libkrun/HVF pool
    │     └── share slots
    ├── Linux Firecracker pool
    ├── host hardening
    └── SLO/fallback semantics
          └── benchmark and CI gates
```

## Required API seams

The runtime must gain typed representations for:

- a warm compatibility shape;
- a fixed guest share slot;
- a claim-time share binding;
- warm claim refusal reasons;
- pool and claim timing marks;
- a claim lease whose drop path safely returns or quarantines capacity.

The VMM driver seam must receive share bindings as part of child creation and
must not resume a child until all required host channels and share slots are
armed. The role layer remains responsible for admission, authority, identity
reseeding, and policy validation.

## Current implementation progress

- [x] Added `WarmLaunchMode` with explicit optional, required, and cold modes.
- [x] Added typed warm refusal reasons and a backend-neutral warm outcome.
- [x] Added mode-aware claim glue; required claims refuse instead of cold-booting.
- [x] Kept healthy parent capacity under the runner-owned `WarmClaimLease`;
  orchestration no longer deletes a parent after a lease-managed failure.
- [x] Added the resident local Claim/Release/Prewarm service boundary and
  service-owned active lease registry.
- [x] Added end-to-end required-mode lease behavior and refusal reporting.
- [x] Added lease-origin reporting so optional cold fallback is explicit, and
  failed release keeps the active lease owned for retry.
- [x] Added a content-addressed warm-artifact key, immutable manifest, verified
  lookup, atomic publication, and path-constrained staged inputs.
- [x] Added durable prewarm job states with retry and restart recovery; the
  worker seam receives expensive preparation work outside the claim path.
- [x] Enforced canonical artifact identities and manifest-listed path access;
  malformed keys and staged/published symlinks fail closed.
- [x] Added worker-side preparation for resolved rootfs and kernel inputs,
  reused the existing universal-initramfs and runtime-overlay resolvers, and
  staged canonical boot inputs with compatibility-key digest checks.
- [x] Added the resident worker adapter that resolves a source plan per queued
  job and records source-resolution failures as retryable durable states.
- [x] Added validated, host-path-free OCI/template source descriptors to the
  prewarm protocol and persisted them with durable jobs for restart-safe
  resolution.
- [x] Added a mandatory golden-VM readiness-verifier seam to the worker; a
  verifier failure leaves the job retryable and prevents artifact publication.
- [x] Connected the CLI source boundary to concrete OCI/template resolution and
  a runtime worker factory without re-entering the foreground launch path.
- [x] Wired the worker factory into the resident service; prewarm requests
  enqueue typed artifact identities and a resident worker tick processes them
  outside claims.
- [x] Added the shared authenticated golden-VM verifier: it boots through a
  backend factory, performs an authenticated `ReadinessStatus` exchange,
  requires a sealed-production ready control plane, and tears down the probe
  VM on both success and failure.
- [x] Added the process-local resident parent registry: verified parents must
  carry a captured checkpoint, compatibility selection and reservation are
  atomic, dropped leases return capacity, and successful or unhealthy parents
  are explicitly consumed or quarantined.
- [x] Wired the existing HVF supervisor pause loop through both backend
  surfaces with live-pid checks; HVF advertises pause/resume only, while
  memory, device-state, and vCPU-state snapshot capabilities remain disabled.
- [x] Added bounded snapshot-frame encoding plus fixed-width HVF AArch64 vCPU
  capture/restore and exact-size guest-RAM section codecs. These are tested
  state primitives only; the live pause/serialize/restore loop and device
  serializer still gate capability admission.
- [x] Added a bounded, versioned device-state section and deterministic control
  codecs for PL011, virtio-blk, virtio-fs, and virtio-rng. Restore requires an
  exact device topology and rejects malformed queue control state; console
  transcripts, entropy bytes, backing handles, and active vsock sessions are
  not serialized. The vsock codec now preserves only idle transport control
  state and fails closed on bound host endpoints, host-I/O descriptors,
  receive-credit sessions, pending packets, lifecycle transcripts, and exited
  workloads.
- [x] Added the strict HVF snapshot-bundle seam: capture combines guest RAM,
  AArch64 vCPU state, device state, and artifact metadata; parse validates
  architecture, backend identity, required sections, duplicate sections, and
  exact RAM size before restore; restore keeps the target paused and leaves
  host-channel rebind and live backend capability admission to the owner.
- [x] Added an acknowledged HVF pause boundary: the supervisor publishes a
  pause marker only after the run loop has entered its vCPU hold, clears it on
  observed resume, and both backend surfaces wait for the acknowledgement.
- [x] Added the child-memory and host-channel restore primitives: guest RAM can
  be remapped privately from an exact-size snapshot file with kernel COW, and
  restored vsock devices accept fresh caller-authorized host bindings without
  serializing paths or socket ownership.
- [x] Wired the HVF parent-capture and child-restore orchestration through the
  existing warm-claim seam: paused supervisors publish fixed state-directory
  RAM/frame files, the driver persists the launch config into the checkpoint,
  child supervisors privately map the copied RAM, restore vCPU/device state,
  rebind the claim-derived channels before execution, and the existing
  authenticated post-restore identity handshake gates admission.
- [x] Replaced the unsupported cross-process HVF restore assumption with a
  signed, same-process paused-parent handoff. The parent supervisor remains the
  HVF owner; a pinned host identity authorizes the child name, parent PID, and
  channel mask over a private Unix socket; the parent retargets only the
  claim-derived channels, links child state to the live owner, and resumes as
  the child. The handoff listener polls during the paused vCPU hold, so no new
  HVF VM or interrupt controller is created. Endpoint derivation is internal
  and state-root constrained; focused protocol, path-safety, and channel
  rebind tests pass.
- [x] Added the host-only Apple Silicon acceptance harness
  (`scripts/check-hvf-warm-restore.sh` and `just hvf-warm-restore`). It builds
  isolated binaries, records host and launch evidence, bootstraps through the
  normal replenish path, requires every measured claim to report
  `launch_mode=warm`, completes a post-restore guest timer, virtio-filesystem,
  and vsock continuity probe, and fails on any warm-SLO or cold-fallback result.
  The harness never enables the backend capability itself.
- [x] Added the typed trusted-snapshot backend contract. The claim path now has
  an explicit seam for a kernel-backed immutable publication, while the
  unsupported implementation performs no filesystem mutation and keeps the
  fast path fail-closed. The existing reflink/filesystem store remains on the
  full verification path until a platform adapter proves sealing, mount,
  cleanup, and tamper behavior on real hardware.
- [x] Added an opt-in Apple APFS backend implementation behind the trusted
  snapshot contract. It stages through the existing store, seals into a
  read-only APFS snapshot, mounts only that read view for materialization, and
  removes the mutable staging tree after sealing. Claim validation mounts the
  sealed view and verifies the host-authenticated manifest digest and signer in
  O(1), before the no-rehash materialization path. The default build does not
  enable this backend.
- [~] Run the privileged Apple Silicon APFS live witness: publish a large
  snapshot, mutate or remove the staging path, materialize from the sealed
  view, verify byte equality, exercise cleanup, and record the privilege
  failure mode. The witness reached the real seal call and received
  `EPERM`; the adapter now normalizes that to `Unsupported` and the warm
  capability remains disabled. Do not enable it until the privilege path is
  available and the full witness passes.
- [x] Added the service-owned trusted-snapshot publication registry. It issues
  opaque handles only after stage and seal succeed, accepts no source path at
  claim time, rejects handles from another service, and removes publications
  only through the owning service.
- [x] Wired trusted publication into the real warm-pool capture and claim path.
  Captures sign the manifest before stage/seal, trusted IDs select the platform
  backend only after lineage plus sealed-manifest validation, and ordinary
  filesystem snapshots retain full blob verification for saved-state restores.
  Resident HVF claims use the signed ordinary snapshot manifest as their
  user-owned publication witness and do not require privileged APFS support.
  HVF capability admission now requires only the live-validation feature and
  explicit warm-handoff opt-in.
- [x] Implemented the rootless resident HVF claim path. A claim verifies the
  host signature over the staged manifest as its O(1) publication witness,
  creates only the fresh child state directory, validates the parent launch
  source with the normal overlay gate, and transfers the paused parent
  supervisor directly to the child identity. It does not use mutable
  checkpoint bytes as the child's rootfs and does not materialize or hash the
  large bundle on the hot path. Saved-state drivers retain the existing full
  content and lineage verification path.
- [x] Removed the secret-free deny-all endpoint process and guest egress channel
  from resident claims, and deferred the broad orphan-state maintenance sweep
  until after the guest command. The deny-all posture remains explicit and
  fail-closed; the fresh release-built 1,000-claim Apple Silicon matrix
  measured p50=17.9ms, p95=22.1ms, p99=27.4ms, and max=33.3ms.
- [~] Live-validate the same-process handoff on real Apple Silicon and complete
  the full 1,000-claim continuity witness. Darwin arm64 validation now proves
  the signed rootless handoff with the Hypervisor.framework entitlement, with
  1,000/1,000 successful warm claims below the strict 300ms ceiling and inside
  the p50≤30ms and p99≤50ms aggregate targets. A real Linux x86_64
  Firecracker/KVM direct-driver matrix also passes 30/30 claims at p50=39ms,
  p95=39ms, and max=40ms. Production standby capability admission, Linux
  libkrun, and the remaining backend/share-shape matrices remain open. The
  resident path defers reclamation of consumed parent payloads until after the
  measured handoff, keeping checkpoint and snapshot state bounded.
- [x] Removed the process-wide `MVM_HOME` mutation from the UDS-channel test
  harness. Parallel host tests now use explicit isolated socket roots; the
  complete `mvm-hostd` package suite passes without the prior macOS hang.
- [x] Choose and implement the same-process paused-parent design: the parent
  remains the HVF owner, signed handoff metadata authorizes the child identity
  and channel mask, and all host endpoints are derived from the child state
  root before the parent resumes. The remaining work is live proof of timer
  wake, restored virtio-filesystem access, fresh host-vsock traffic, and the
  strict launch window on a real Linux guest.
- [ ] Connect the Apple Silicon and Linux backend factories to the verifier so
  each platform can boot its disposable golden VM from staged inputs.
- [x] Implement the Apple Silicon immutable snapshot adapter behind the
  trusted-snapshot contract. It uses an OS read-only snapshot view, not
  reflinks, mode bits, or a mutable sidecar as the publication proof; claim
  validation checks the host-signed manifest without hashing the payload.
- [~] Keep the privileged Apple snapshot adapter optional and off the resident
  claim path. The root-only helper remains available for deployments that want
  immutable APFS publication for background bundles, but rootless HVF warm
  claims use ordinary user-owned signed bundles and same-process handoff. The
  live witness still needs real Apple Silicon timing and continuity evidence;
  unsupported APFS operations must continue to normalize to `Unsupported`.

## Security invariants

- A factory VM contains no tenant authority, secrets, workload grant, or
  user-specific host path.
- A share binding is opened and validated before the child is resumed.
- A read-only share cannot become writable through a warm claim.
- A failed claim stops or quarantines the child and returns no usable partial
  VM to the pool.
- The VMM/share processes run with only the host permissions required for
  their assigned slot; Linux uses seccomp, Landlock, namespaces/cgroups, and
  dropped capabilities where available.
- macOS relies on the VM boundary, process separation, restrictive
  entitlements, and handle-scoped share access; Linux-only controls are not
  presented as portable guarantees.

## Acceptance gates

- Warm-required launches never silently cold-boot.
- A warmed no-share claim and a warmed read-only `--mount` claim both report
  `launch_mode=warm` only after a real claim.
- The warm window is strictly below 300ms for every successful claim in the
  benchmark matrix; p50 is at most 30ms and p99 at most 50ms.
- The 1,000-claim matrix records p50, p95, p99, maximum, refusal rate, and
  cold comparison without discarding outliers.
- The launch benchmark excludes command execution; a separate workload
  benchmark covers dependency installation and network behavior.
- Workspace tests, all-target Clippy, formatting, security tests, and the
  supported live backend smoke tests pass before the sprint item closes.

## Issue ownership boundaries

Each issue owns its implementation, focused tests, and documentation updates.
Cross-issue changes are limited to the typed seams explicitly listed in the
issue body. No issue may enable a backend capability flag without its live
acceptance test.
