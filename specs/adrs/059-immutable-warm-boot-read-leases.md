# ADR-059: Immutable read leases for warm boot inputs

Backing: preview
Validation: none — this is an accepted design direction, not a shipped warm read lease

## Status

Accepted direction. The owner approved one typed publication/claim API with
bounded sealed memfds, inode-pinned fs-verity where supported, and fail-closed
warm claims. A resident service can publish and claim a canonical signed
kernel in a sealed, explicitly budgeted Linux memfd. Its claim exposes no
descriptor and is not a complete boot closure or a VMM-lifetime lease. No
backend or launch path consumes it; enabling warm claims still requires an
owner/descriptor API review and live witnesses.

## Context

ADR-001 trusts the host, not a compromised guest or another local process.
ADR-025 permits fresh children of a clean, authority-free parent but refuses
reuse of a dirty guest. The composable-pack contract requires fresh admission
and <300 ms cold / <50 ms warm launch including admission. Today
`TrustedSnapshotBackend::materialize` returns a writable destination, the
named path disables its warm pool, and PR runtime and kernel descriptor
custody refuse standby. None is an immutable VMM read lease.

On a Raspberry Pi 4 Linux/KVM host, a test-only direct Firecracker probe
sealed an 8.5 MB kernel and 71.3 MB ext4 rootfs in memfds. A write after
`F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL` failed; inherited
`/proc/self/fd/N` paths were accepted by pinned Firecracker, and the guest
mounted the root ext4 read-only and ran `/bin/sh` as init. The probe had no
admission, scoped launcher, runtime overlay or parent claim. The Pi kernel
does not advertise fs-verity. The ordinary named start on that host still
took 53 s, including fresh admission; the probe is not evidence for a speed target.

## Decision

Extend the existing `TrustedSnapshotBackend` and `TrustedSnapshotService`.
The owner accepts an authenticated, exact boot closure (selected kernel,
rootfs, full runtime, parent device shape and publisher/revocation evidence),
reserves its memory and descriptor budget, then publishes and seals its bytes.
A successful publication issues a generation-bound, nonserializable handle;
a claim yields an **owned read lease**, never an arbitrary source path or a
writable materialization. A handle or cache hit grants no plan authority.

On Linux, sealed memfds serve small boot inputs and explicitly budgeted
resident parents. A separately validated fs-verity provider may pin open
inodes for large rootfs files; its measured verity identity must be bound
to the authenticated byte digest at publication. No permission bit, reflink
or sidecar signature stands in for kernel-backed immutability. A requested
warm guarantee refuses before execution when the selected provider lacks
support, sealing fails, or the byte/FD/parent budget is exhausted. A normal
cold start can proceed through its own full verification and admission, but
must not be reported as a warm claim. The provider is fixed at publication;
claim does not silently switch mechanisms.

The lease owns its descriptors and publication generation through the actual
VMM's last child, not only until a copy or launch call returns. Reuse the
Firecracker launcher descriptor handoff and verify the VMM's opened objects,
not the diagnostic pathname. The scoped launcher, device layout, guest
no-NIC/vsock-only network path and host budget remain mandatory. APFS must
provide an independently witnessed read-only mount lease before enabling
this claim on macOS; unsupported platforms refuse it.

A parent is clean: no tenant plan, secret, writable volume, egress destination
or previous child's guest memory. Each child gets fresh signed-plan,
revocation, policy, grant and one-use admission before any admitted effect or
readiness claim. A changed closure, stale handle, lost owner or expired proof
refuses a claim. Owner restart loses memfds and must rebuild from newly
authenticated inputs; no persisted filename recovers a lease. A VMM that
retains its own original descriptors cannot become a new parent after owner
loss; existing children remain subject to their original admitted bounds
or are stopped when those bounds cannot be enforced.

The owner moves an ID through reserved, sealed, leased, removing and
quarantined states. Failed staging or cleanup keeps it unclaimable. Removal
waits for every active child and VMM descriptor; cancellation and process
death release reservations without reassigning stale generations. Claim-time
checks inspect sealed objects and current authority, not payload hashes.

## Alternatives

- Unlimited memfds are simple and work on the Pi, but one copy per distinct
  parent shape can exhaust RAM or swap; no 1,000-workload capacity claim
  follows without sharing and an enforced host budget.
- fs-verity-only storage avoids the shmem copy but is unavailable on the Pi
  and some hosts. It still needs an inode-pinned descriptor and a signed
  identity binding rather than trusting a replaceable path.
- Reflinks, read-only modes and host-signed cache sidecars do not seal the
  bytes a VMM opens. They cannot satisfy a warm read lease.

## Evidence required before enabling

Exercise seal/mutate refusal, manifest/signer mismatch, stale generations,
concurrent publish/claim/remove, memory and FD exhaustion, cancellation,
owner crash/restart, pathname replacement and actual VMM descriptor identity.
Run normal scoped Firecracker launches on Linux x86_64 and arm64 with fresh
admission, verified guest output and no guest NIC. Witness APFS mount custody
separately. Measure first-use publication apart from cold and warm readiness;
the latter include admission and must meet the stated thresholds on named
hosts. Tests or a direct-VMM probe cannot substitute for those live claims.
