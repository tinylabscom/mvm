# The libkrun seeded closure rides the input disk

Stage C of `specs/plans/2026-08-31-remove-virtio-fs.md`, libkrun half. Both
one-shot libkrun transport paths (`run_shell_script`, `run_build`) now pass the
seeded Nix store closure to `prepare_builder_transport_disks` instead of
attaching it as a separate virtio-fs share.

This closes a box the plan had marked done and wasn't. The plan's `[x]` on
"`work`, `job`, `mvm-bins`, closure seed — Done for the one-shot builder via the
disk transport" was false for the closure: `prepare_builder_transport_disks`
passed a hardcoded `None` while both call sites attached the NAR over virtio-fs
a few lines later. The QEMU migration gave the helper a real `closure_nar`
parameter; this uses it.

## What stays

This was true when this delivery landed, but the follow-up completed the seam.
`run_stage0_impl` now materializes its `RootDir` seed into `root.ext4`, passes
the optional closure NAR through the raw-tar input disk, and attaches no
virtio-fs share. `closure_seed_share` and its staging tests are deleted.

## Live validation

`mvmctl machine build --builder libkrun` on macOS 26.5.2 / arm64 against
`examples/sleeper`, warm builder-image cache:

    [mvm] Step 2/2: Build complete
    [mvm]   Slot: 2ab4f258887f2a9aed72961b42675a68993c5e841fd6e51188daff7ea364e65f

The proof is in the supervisor config the run wrote, not just the exit status:

    virtio_fs_mounts = []
    extra_disks = [nix-store, input, output, runtime-overlay, …]

The libkrun one-shot builder now boots with **zero** virtio-fs devices, and no
`closure-seed/` staging directory was created under the VM state dir.

**What this run does not prove, stated rather than glossed.** This host's
builder-image cache carries no `nix-closure.nar`, so `closure_nar_for_host_arch()`
returns `None` — with no closure to carry, old and new code produce identical
bytes and the live run is a regression check on the surrounding transport path
rather than a test of the closure moving onto the disk.

That arm is covered by
`prepare_transport_disks_lands_the_closure_under_its_fixed_name`, which packs a
deliberately misnamed source NAR and asserts it lands at
`closure-seed/nix-closure.nar`. The rename is the part worth pinning: the guest
imports a fixed path, so a differently-named source landing under its own name
would make `import_seeded_closure` a silent no-op rather than an error.

Planting a synthetic NAR to force the live path was considered and rejected —
`import_seeded_closure` returns `Err` when `nix-store --import` fails, so a
bogus file would fail the build for an artificial reason and say nothing about
the transport.

## Gate

`check-no-virtio-fs`: 54 sites across 15 files → **52 across 15**, and
`libkrun_builder.rs`'s pin reason is now accurate — its remaining 11 sites are
the Stage 0 RootDir path, not the transport paths.

## Verification

`cargo fmt --all --check`, `just check-gated`, `cargo clippy --workspace
--all-targets -D warnings`, `cargo nextest run --workspace` (12,890 passed),
`cargo test --workspace --doc`, `cargo run -p xtask -- check-all` (63 gates) —
all clean.
