# Bounded Stage 0 Nix store and a targeted prune

Issue #3360, parts 1 and 3. Part 2 (virtio-blk discard and host hole-punching)
landed separately in #3440; the Firecracker half of it waits on #3433.

The Stage 0 store (`nix-store-stage0-<arch>.img`) was never garbage-collected,
so every bootstrap's intermediates stayed until the image hit its 64 GiB
ceiling; a long-lived contributor home measured 53 GB against a 12 GB clean
closure. Nothing could remove it without also deleting the builder image it
produced.

## What changed

- **Collection.** After a successful build, `stage0-init` measures the store
  filesystem and, past the cap, collects it. The seed's own paths were never in
  the Nix database, and Nix both ignores a root pointing at an unregistered path
  and deletes unregistered paths, so the seed is first registered from its
  `.reginfo` (copied to `/run` before the persistent store is bound over `/nix`)
  and its `nix` and CA bundle are rooted. Each output mode's last build is
  rooted too, so an unchanged next bootstrap is still a cache hit. If the seed
  is nonetheless gone afterwards, the store marker is dropped and the next run
  reseeds. Every decision logs one line.
- **The cap** is the steady-state builder's (`MVM_BUILDER_STORE_GC_GIB`,
  default 24 GiB), carried to the guest as `mvm.store_gc_kib=<KiB>` on the
  Stage 0 kernel cmdline. It does not ride `stage0-build.conf`, because the
  ordinary builder-image bootstrap writes no conf.
- **Trim.** After collecting, the store is trimmed with `FITRIM`; a disk
  without discard answers `EOPNOTSUPP`, which is logged and ignored.
- **Console drain.** `power_off()` drains stdout and stderr before
  `reboot(2)`; the halt was truncating the `stage0-init: done; halting` marker.
- **Prune.** `mvmctl cache prune --stage0-store` (implied by `--deep`) removes
  only the Stage 0 store image. An explicit request refuses during an in-flight
  bootstrap; `--deep` skips it with a warning. Freed space is reported as
  allocated blocks, not the sparse 64 GiB length — `cache repair --store-only`
  now reports the same way.

The guest code lives in `stage0-init/store_gc.rs` (pure policy plus the
Linux-only `collect` module) and `stage0-init/seed.rs` (seed lookups, moved out
unchanged), which keeps `stage0-init.rs` under the file-size cap.

## Live evidence

Hetzner KVM box, x86_64, Firecracker 1.14.1, cold `MVM_HOME`,
`MVM_BUILDER_STORE_GC_GIB=1`, built with `MVM_EMBED_NO_CACHE=1` and the new log
strings confirmed in the embedded `stage0/root/init`:

- Run 1: `Nix store 9307936 KiB -> 2157480 KiB after garbage collection`;
  `the store disk does not support discard` (Firecracker 1.14.1 has no block
  discard); done marker intact; exit 0.
- Run 2, builder image deleted and store kept: the store was reused, 0
  derivations built, collected again (2620968 -> 2156280 KiB), exit 0.
- `cache prune --stage0-store` dry run, then real: removed only the Stage 0
  store, 11.2G freed.

That run preceded the final change, which moves the collection code into
modules and adds a compile-time layout contract to `FstrimRange`; neither
changes behaviour, so it was not rerun.

## Not done

- The trim returns host disk only where the store disk honours discard: the
  in-house device model (HVF) since #3440. Firecracker gains block discard in
  1.17 and is pinned at 1.14.1 (#3433), so on Linux collection stops growth but
  the image file does not shrink.
- Whether the Stage 0 store should persist by default at all is undecided; it
  stays, bounded, and `--stage0-store` is the reclaim.

## Validation

`cargo fmt --all -- --check`; `RUSTFLAGS="-D warnings" just check-gated` (the
only local build that compiles `stage0-init` for Linux); Linux-target clippy on
`mvm-build`; workspace clippy; `cargo nextest run -p mvm-build -p mvm-cli -p
mvm-runtime -p mvm-backends`; `cargo test --workspace --doc`; `xtask check-all`;
and the `test-support` library lane.
