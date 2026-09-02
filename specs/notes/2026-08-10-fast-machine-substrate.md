# Fast machine substrate

**Status:** Contract defined; implementation remains in Plans 298, 299, 265,
270, and 292.

This note joins the cold-launch, warm-claim, guest-boot, and artifact-storage
work without introducing another cache or snapshot graph. The performance
target is a property of the complete prepared machine substrate, not of the
kernel file in isolation.

## Design decision

Every launchable machine is derived from a prepared, content-addressed
template. A template describes the immutable inputs and the execution shape
that determine whether an artifact or warm parent is reusable:

```text
kernel
initramfs
rootfs lower artifacts
verity metadata
runtime overlay
backend and VMM version
guest-agent protocol
CPU and memory shape
block-device and share topology
network-policy shape
warmup profile and readiness probe
```

The template identity excludes tenant authority, workload grants, host paths,
host-directory contents, live vsock sessions, mutable writable state, and
secrets. A warm claim creates a fresh child identity from a clean parent; it
never makes a dirty workload reusable.

The existing content-addressed artifact and checkpoint stores remain the
storage primitives. A template identity composes their digests and policy
inputs; it does not create a second store, manifest format, or snapshot
lineage.

## Lifecycle contract

The measured lifecycle has these ordered phases:

1. **Prepared:** all required artifacts are present, digest-verified, and
   compatible with the requested execution shape.
2. **Kernel entry:** the guest has begun executing the selected kernel.
3. **Agent ready:** the universal initramfs agent is listening on the expected
   authenticated control path.
4. **Activated:** the host has delivered the signed activation for this fresh
   machine identity.
5. **Environment ready:** rootfs, runtime overlay, privileges, and policy have
   been applied successfully.
6. **First useful RPC:** the first workload operation has crossed the
   authenticated channel. `/bin/true` remains a launch probe; it is not a
   substitute for this end-to-end measure.
7. **Reaped:** the guest and host resources have been cleaned up or handed to
   an ownership-safe lifecycle reaper.

Cold launch, mount-cache hit, mount miss, artifact miss, and warm claim are
separate benchmark lanes. A lane never hides preparation, network, image
materialization, or cleanup work inside another lane's SLO.

## Cross-plan ownership

| Concern | Owner | Boundary |
|---|---|---|
| Prepared cold path, artifact lookup, launch spans, backend cold latency | Plan 299 | New VMM and fresh guest identity |
| Resident parent pool, claim leases, CoW child, warm admission | Plan 298 | Clean parent and fresh child only |
| Restore sequencing, page-cache policy, density, warm SLO | Plan 265 | Restore correctness and measured working set |
| Universal initramfs, signed activation, guest readiness, PID 1 lifecycle | Plan 270 | Guest boot and activation state machine |
| Local/remote artifact tiers and rehydration | Plan 292 | Remote storage stays off the hot path |

The typed seams between these owners are the template identity, the prepared
artifact manifest, the readiness event, and the fresh-child handoff. Changes
that cross those seams update this note and the owning plan in the same change.

## Kernel and boot-substrate budget

Kernel sizing is evaluated together with the initramfs, rootfs, VMM mapping,
guest working set, and restore behavior. Each supported kernel variant records:

- raw and compressed kernel size;
- initramfs and immutable rootfs artifact sizes;
- built-in drivers, modules, and boot probes;
- time to kernel entry and authenticated readiness;
- resident pages after warmup;
- cold launch and warm-restore fault cost;
- compatibility and security witnesses.

The smallest artifact wins only when it improves or preserves the launch,
resident-memory, restore, and security measurements. Removing a driver or boot
probe without a guest-readiness witness is not an optimization.

Warm launch samples now provide the end-to-end process witness needed for this
comparison. The workload backend resolves the VMM/supervisor PID through the
shared running-VM trait, then samples the same process after authenticated
readiness and immediately after the first guest command. Linux records RSS from
`/proc/<pid>/statm` and
minor/major page-fault deltas; macOS records physical footprint and marks those
Linux-specific counters unavailable. Firecracker, libkrun, and HVF use the same
schema and lane gate, which rejects missing warm evidence. Results remain
comparable only within a matching host, backend, artifact, and sizing context.

The report consumer adds the publication gate shared by all native backends:
20 measured samples after exactly two warm-ups, per-sample contamination and
capability validation, the prepared-cold 200/250/300 ms percentile diagnostics,
and the stricter requirement that every prepared boot dispatch stays under
200 ms.
Warm claims retain the independent 30/50 ms p50/p99 target. The report now
summarizes ready resident memory, first-command resident-memory growth/reclaim, and
fault deltas without turning an unavailable platform counter into a zero.
These are enforcement rules; they do not turn a synthetic or degraded local
run into native matrix evidence.
## Filesystem evaluation

The current block-backed rootfs, overlay, dm-verity, and host-directory image
paths remain the baseline. A candidate guest-local immutable lower-layer
layout may be evaluated if it preserves content addressing, verification,
xattrs/whiteouts, clean writable CoW state, read-only enforcement, and tenant
isolation. The candidate must be compared using the same lifecycle lanes and
must report preparation time, first-file access, snapshot working set, and
multi-claim density.

The external research is a hypothesis for deleting host/guest filesystem work,
not a performance number to copy. The result is an explicit adopt or decline
decision in issue #2281 and Plan 299; no parallel filesystem or cache stack is
allowed.

The current baseline is now measurable without a VM: `cargo xtask perf
filesystem --root <DIR> --json` drives
`mvm_fs::rootfs::measure_ext4_pure`, which reports the source content digest,
effective node composition, source file bytes, emitted ext4 size/digest,
materializer format version, and separate hash/walk/build timings. Candidate
filesystem paths must use the same fixture identity and report equivalent
preparation, first-file access, working-set, and density evidence before the
existing ext4 path can be replaced. Cold-launch samples now also carry the
tier-selected `virtiofs_root` or `block_ext4` strategy, so those measurements
remain comparable only within the same security and capability tier. The
benchmark gate requires the field and rejects a report that changes strategy
between warmup or measured samples.

## Security and resource invariants

- Prepared artifacts are published atomically and verified before use.
- Warm-required claims refuse when the required capability is unavailable;
  they never silently cold-start.
- A factory parent contains no tenant authority, secrets, host path, or live
  channel.
- Every child receives fresh identity, authority, and host-channel state before
  it resumes.
- Read-only host directories are opened and validated before resume.
- Pool admission accounts for resident working set, concurrency, and
  backpressure rather than only template count.
- Default reuse is clean-fork reuse. Any page-cache-hot mode must be explicit,
  bounded, and workload-authorized.

## Issue sequence

- [~] [#2280](https://github.com/tinylabscom/mvm/issues/2280) — measure the
  kernel and boot-substrate budget. The bounded libkrun resident host-process
  capture is landed, and HVF guest-RAM now exposes an allocation-level
  demand-fault witness plus private restore-mapping duration. The live libkrun
  density report also records guest-agent RSS after readiness. Backend-neutral
  warm samples now capture whole-VMM ready/first-command working set and Linux
  fault deltas. The report-level 20-sample/two-warm-up gate and canonical
  budget enforcement are landed; the real-host Firecracker/HVF matrix and
  measured result remain.
- [~] [#2281](https://github.com/tinylabscom/mvm/issues/2281) — baseline the
  current pure-Rust ext4 path and evaluate the guest-local immutable
  filesystem path against it.
- [ ] [#2194](https://github.com/tinylabscom/mvm/issues/2194),
  [#2195](https://github.com/tinylabscom/mvm/issues/2195), and
  [#2196](https://github.com/tinylabscom/mvm/issues/2196) — complete the
  backend-specific warm pool and share acceptance work already owned by Plan
  298.
- [ ] [#2199](https://github.com/tinylabscom/mvm/issues/2199) — complete the
  1,000-claim matrix and regression evidence.
