# Delete virtiofsd

The host-side `virtiofsd` spawn/supervise module is gone, and with it the
`--sandbox none` flag that started `specs/plans/2026-08-31-remove-virtio-fs.md`.

Two consumers had to go first. The QEMU *builder* moved to the disk transport in
the previous change. The QEMU *workload* driver is this one.

## The workload driver refuses rather than ignores

`spec_map.rs` has set `shares: Vec::new()` for every workload since a granted
directory became a materialized block image, and the only non-empty producer of
`VmmSpec.shares` left in the tree is the HVF persistent builder. So the QEMU
driver's share-mapping arm was unreachable and deleting it changes no behaviour.

It was replaced with a refusal rather than simply removed. `QemuDriver::boot`
now bails on a non-empty `spec.shares`, mirroring Firecracker's long-standing
`boot_rejects_virtio_fs_shares`. A driver that silently drops a share it was
asked to serve hands the guest a VM missing a filesystem it expected — the
failure would surface inside the guest, far from the cause. Two tests: the
refusal itself, and `argv_carries_no_virtio_fs_or_shared_memory_backend`, which
pins the absence of the `-object memory-backend-memfd` / `-numa` pair. That pair
existed only because vhost-user-fs requires a shared memory backend whose size
equals `-m`, so it had no reason to outlive the shares.

## What else came out

`mvm-vmm`'s `which` dependency. The manifest comment above it said "binary
lookup for host-side helpers (virtiofsd)", and once the module went it had no
other user in the crate — only prose matches for the word.

## Corrections to the plan

The plan said to remove "the `virtiofsd` host dependency in the Linux install
docs". There is no such dependency in any doc — nothing under `public/` or
`README.md` mentions virtiofsd. That instruction described a document that does
not exist, and is recorded as such rather than silently dropped.

The plan also predicted this step would make `check-no-virtio-fs` "drop to
FFI-only rows and the ratchet become an absolute rather than a ceiling". It does
not. The persistent HVF builder and libkrun's seeded closure still attach
shares, so the gate went from **54 sites across 15 files to 44 across 14**. The
absolute is still two pieces of work away.

## Superseded

`specs/plans/2026-08-31-virtiofsd-sandbox-parity.md` hardens the confinement of
a daemon this repo no longer spawns. It is marked SUPERSEDED in place —
implementing it now would mean re-adding the deleted file. The concern it
addressed is resolved by removal instead of by configuration. The two Stopgap
boxes in the removal plan are struck for the same reason.

## Verification

`cargo fmt --all --check`, `just check-gated`, `cargo clippy --workspace
--all-targets -D warnings`, `cargo nextest run --workspace` (12,882 passed),
`cargo test --workspace --doc`, `cargo run -p xtask -- check-all` (63 gates) —
all clean.

No live validation needed: this deletes unreachable code and a module with no
remaining callers. The behaviour that *did* need a live boot — the QEMU builder
on the disk transport — was validated in the previous change.

One note on the suite: the first full run failed
`the_controller_reads_the_clock_once_per_period` and
`daemon_crash_mid_flight_loses_at_most_one_call_and_preserves_chain`. Both pass
in isolation and both pass on a full re-run; neither touches virtio-fs, QEMU, or
anything in this diff. That is the known nextest parallel-execution flake, not a
regression.
