# `cache prune` stops deleting live caches, and stops overstating by 8x

A dry run against a real 152 GiB `~/.mvm` produced two wrong answers at once.
`--orphan-dirs` listed eight live caches — `guest-agent-build`,
`runtime-overlay-bins`, `runtime-overlay`, `sdk-sidecar`, `verity-initrd`,
`audit-verify`, `initramfs`, `builder-health` — as "unrecognized cache entry",
which is the wording for something safe to delete. And it offered to free
367 GiB from a tree that holds 152 GiB.

## The sweep deleted whatever it did not recognise

`RECOGNIZED_CACHE_ENTRIES` was an allow-list of live cache dirs, and
`--orphan-dirs` removed every top-level entry missing from it. That inverts
the safe direction: the list has to be extended every time any subsystem
anywhere in the workspace grows a cache, and the price of forgetting is a
deletion, not a leak. It had drifted behind eleven live entries — the eight
above plus `packs` (the attested pack cache `cache status` reads),
`warm-artifacts`, and `local-run`. `--deep` implies `--orphan-dirs`, so the
documented "reclaim regenerable caches" command reached all of it.

The list is now `RETIRED_CACHE_ENTRIES`, a deny-list naming the two entries a
removed subsystem left behind (`docker-nix-store`, `builder-nix-store`).
Nothing else is ever a candidate. Forgetting to retire a dead name now leaks
disk an operator can see, instead of deleting a cache they were using.

The guard test went the same way. `recognized_cache_entries_cover_known_dirs`
asserted eight hand-picked names were on the allow-list — every one of which
happened to be there, which is why it stayed green through the whole drift.
It is replaced by an assertion that every live cache dir the workspace writes
is *not* a candidate, and by an end-to-end sweep test that requires both
halves: the live dirs survive and the retired one is gone. Deleting nothing
fails it as surely as deleting everything.

## The estimate followed symlinks

`dir_size` walked with `Path::is_dir()` and stat'd with `Path::metadata()`,
both of which resolve symlinks. A materialized OCI rootfs is roughly 70,000
symlinks: every symlinked directory got its whole subtree re-walked, and every
symlinked file was charged its target's blocks. Measuring `~/.mvm/cache/oci`
that way visits 1,352,922 files where 487,613 exist and reports 355.4 GiB
where `du` reports 46.4 GiB — the 355.4 GiB the tool printed, to the tenth of
a gigabyte. Hardlinks were the other suspect and were not the cause: charging
each link separately moves that tree by under 0.05 GiB.

Five hand-rolled tree-walkers existed across the CLI and `mvm-build`, with
three different notions of size between them (apparent length in three,
allocated blocks in one, allocated-blocks-through-symlinks in the one this
bug was in). They are now one function, `mvm_core::disk_usage::tree_bytes`:
allocated blocks, symlinks charged as themselves and never traversed, each
inode charged once. It answers the question `du` answers, so an operator can
check the tool against `du -sh` and get the same number.

The walker fix is not only cosmetic. `cache prune`'s temp-file sweep deletes
what that walker yields, so following a link let a `foo.tmp` symlink inside
the cache reach files outside it — and removal chose `remove_dir_all` from a
symlink-following `is_dir()`, which would have emptied the target rather than
unlinking the link. Both paths now decide from `symlink_metadata`.

## One list of live-VM markers

The reaper `cache prune` runs by default kept its own copy of the workload
supervisor markers, holding three of the five the shared liveness probe reads.
`qemu.pid` and the generic `pid` were missing, so a live QEMU guest whose
supervisor had been reparented to launchd read as having no owner and its
helpers were reaped. `hvf.pid` had already been added to that copy once by a
previous fix — the second occurrence of the same drift is the argument for
not keeping a copy. `WORKLOAD_SIDECARS` is now
`mvm_vmm::host::process_liveness::PID_FILE_NAMES` itself.

The same file also carried its own `pid_is_alive`, a bare
`kill(pid, 0) == 0` in an `unsafe` block with no safety note. `EPERM` is a
positive existence result — it means the process is there and belongs to
someone else, which is what a root-owned Firecracker under the jailer looks
like — and that check read it as absent. The shared probe, which handles
`EPERM` and macOS zombies, replaces it, along with the marker parser beside it.
