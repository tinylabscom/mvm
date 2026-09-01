# Stage C — the persistent HVF builder moves off virtio-fs

Plan: `specs/plans/2026-08-31-remove-virtio-fs.md`, Stage C.
Follows the guest half (PR #3056), which was inert until this flip.

## What landed

The persistent HVF builder exchanges jobs and artifacts over two raw block
devices instead of four virtio-fs shares. `persistent_builder_spec` declares no
shares at all, so `check-no-virtio-fs` dropped `builder_runner/spec.rs` from its
pinned table — the signal Stage C names for itself. The gate now ratchets 22
sites across 10 files, none of them a builder spec.

The two builder cmdlines collapsed into one. A persistent builder now boots the
same contract as a one-shot — `vda` rootfs, `vdb` nix-store, `vdc` input, `vdd`
output, optional `vde` overlay — so `PERSISTENT_BUILDER_CMDLINE` and its
separate runtime-overlay device constant went away with the shares rather than
being maintained as a second copy of the same string.

Per-dispatch lifetime lives in a new `persistent_builder_transport` module:
`SessionDiskTransport`, `guest_artifact_dir`, `repack_dispatch_input`,
`read_dispatch_artifacts`. Both dispatch clients use it —
`PersistentBuilderVm::run_build` (what `mvmctl build` routes through) and the
`persistent-builder submit` verb. The session record carries
`disk_transport: Option<…>`, which is a real two-state distinction rather than
backcompat padding: the libkrun persistent builder still uses shares.

## Three things that were not in the plan

**Readiness could not be connect-polling.** The plan called for it, and it does
not work here. The backend binds the host UDS during VM setup, before the guest
boots, so `connect` succeeds against a guest whose vsock driver is not up. The
bridge only closes that connection when the guest kernel answers `OP_RST`, so
early in boot a probe neither connects-and-fails nor gets refused — it hangs
open and reads as ready, which is the same silent hang the plan was trying to
remove. Readiness is a round trip instead: `submit_workload_status` for the nil
UUID. Any well-formed reply proves the loop is accepting and framing. Existing
request, no side effect, no protocol change.

**A fifth coordinated change, and the one that would have shipped broken.** The
guest tars `/out` — and only `/out` — onto the output disk. Both host stagers
rendered a `cmd.sh` writing to `/job/<job_id>/out`, which under the disk
transport is the guest's own input stage on the nix-store disk, never read back.
The four planned changes alone would have produced a build that reported success
and emitted nothing. The guest-visible artifact dir is now chosen per transport,
and the host reads the output disk into the same `artifact_dir_for` path a
share-backed session writes to, so everything downstream is transport-blind.

**The install arm has the same shape and no host-side fix.** The guest hardcodes
`/job/<job_id>/out` for install jobs. Rather than lose a claim-11 sealed
volume's SBOM and CVE sidecars silently, an install dispatch on a disk-backed
session is refused with a message naming the missing half. Fixing it needs a
guest change and an image rebuild; it is tracked in the plan.

## Smaller notes

- Transport disk sizes moved into `builder_disk_transport` so the one-shot and
  persistent paths size from one source instead of two copies of the number.
- The Nix diagnostic log moved from `$JOB_DIR` to `$OUT_DIR`, which is
  host-readable on *both* transports; the output disk is now read back whether
  or not the dispatch succeeded, since a failed build is when its log matters.
- `mvm-build/src/persistent_builder.rs` crossed the 1500-line production cap, so
  the transport helpers became their own module rather than an `#[allow]`.

## Verification

`just check-gated`, `cargo nextest run --workspace` (12853 passed),
`cargo test --workspace --doc`, `cargo clippy --workspace --all-targets -D
warnings`, `cargo fmt --all --check`, and `cargo run -p xtask -- check-all`
(63/63) are all clean.

**Not yet verified live.** No CI lane boots a builder — every guest-booting lane
skips on hosted runners — so this needs a real `mvmctl build` on macOS 26+ Apple
Silicon against a **rebuilt** builder image. `mvm-host-vm-init` is
cross-compiled and baked into the rootfs; a stale baked guest against this host
hangs the dispatch loop with no useful error. Do not merge without it.
