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

## Live validation on macOS 26.5.2 / Apple Silicon

Run against a rebuilt builder image (the image cache key includes the
`mvm-host-vm-init` hash, so the guest change rotates it automatically — but
`MVM_EMBED_NO_CACHE=1` is needed first, or `build.rs` reuses a stale baked
guest and warns about it).

**Proven end to end:**

- The input disk packs and attaches as `vdc`, the output disk as `vdd`, and the
  guest boots the disk transport off them (`mvm.builder_transport=disk` with
  both device tokens on the observed cmdline).
- The guest binds `/job`, `/work` and `/mvm-bins` from the input disk — Nix
  evaluated a flake at `path:/work`, which is only possible if the workspace
  crossed on that disk.
- **The new readiness path works.** `start` returns when the dispatch loop
  answers, with no `dispatch.ready` file anywhere the host can see.
- **The per-dispatch repack works.** Two dispatches into one live session: the
  host rewrote the input disk, the guest re-staged `/job/<job_id>` off it and
  ran that dispatch's `cmd.sh`, streaming stderr back over the channel.
- The session record carries the transport, and `stop` tears the session down
  cleanly.

**Not proven: a completed build, and therefore `read_dispatch_artifacts`
against a real output disk** (it is unit-tested only). The blocker is not the
transport — it is that the host-side `mvm-network-endpoint` this session spawns
dies with the command that spawned it, so the guest's egress client loses its
only route to the network mid-build (`FlowMux reconnect exhausted`). The
one-shot builder never hits this because its endpoint's lifetime *is* the VM's
lifetime; a persistent session inverts that. Fixing it means spawning the
endpoint detached and reaping it on `stop`, which is lifecycle design in a
claim-10 component and is deliberately not in this change.

## Pre-existing gaps this uncovered

The persistent HVF builder had never booted. Getting far enough to exercise
Stage C at all required fixing three things that have nothing to do with
virtio-fs, each by calling the helper the one-shot builder already calls:

- No runtime overlay was ever resolved, so the guest refused to boot
  (`require_runtime_overlay_ext4`).
- No FlowMux identity drive was ever minted, so the egress client could not
  authenticate and the guest refused to boot (`mint_from_host_signer`).
- No network endpoint was ever spawned, so the egress client could not bind
  (`spawn_network_endpoint`). This one is wired but, as above, does not yet
  survive its spawning command.

A fourth was mine: the input pack must use `stage_filtered_work_input`, as the
one-shot pack does. Packing the raw workspace put 45 GB of `target/` on the
input disk, filled the 64 GiB store image mid-extraction, and left every later
boot failing at `setup_nix_store` for an unrelated-looking reason
(`mvmctl cache repair --store-only` recovers).
