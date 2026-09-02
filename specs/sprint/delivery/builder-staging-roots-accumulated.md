# The builder guest's staging roots were never emptied

`mvm-host-vm-init::stage_disk_transport_input` staged the builder input tar into
`/nix-store/builder-input` and backed `/out` with `/nix-store/out`. Both live on
the persistent nix-store disk — deliberately, since a tmpfs overflows on a large
work tree — and both were created with `create_dir_all`, which is a no-op when
the directory is already there. `tar x` only adds.

So on every disk-transport builder run (hvf, and the rootfs-backed libkrun
path), `/work` was the union of every tree ever staged on that host, and `/out`
the union of every artifact ever produced there.

## What it broke

**A source file deleted upstream kept being compiled.**
`crates/mvm-core/src/policy/audit.rs` was removed in `a71564173e` when it became
`audit/`. It stayed in the stage dir, so the guest build failed `E0761`
(ambiguous module) while every checkout on the host was clean —
`crates/mvm-core/src/policy/` has held only the directory since that commit.

**A successful job failed on the way out.** `/out` had accumulated 69 entries,
among them `result-*` symlinks into `/nix/store` paths that exist only inside
the guest. Those dangle on the host, so `copy_tree` mirroring the job's
artifacts failed `ENOENT` *after* the build had already reported exit 0.

The loud failures are the lucky ones. A stale source that still compiles makes
the build succeed against sources that are not the checkout's, and nothing
reports it.

## Why it was misdiagnosed

The `E0761` was read as `/work` being "a mutable, possibly stale staged tree",
which pointed at `MVM_WORKSPACE_PATH` as the culprit and suggested making the
flake read an immutable store copy instead. That change landed separately and is
correct on its own merits, but it did not fix this: the failure reproduced
identically through the immutable `path:...?dir=` copy, because both routes read
the same polluted `/work`. Ruling the mutable path out is what isolated the
staging dir.

Two details cost time and are worth writing down. The host surfaces only a 4 KiB
**tail** of the guest's stderr, which cuts the two paths `rustc` names in an
`E0761` — read the code path rather than trying to widen the tail. And the host
staging is genuinely fresh (`stage_filtered_work_input` builds a new `TempDir`
per job), so every check on the host side says "clean"; only the guest side
accumulates.

## Fix

`reset_stage_dir` — `remove_dir_all`, tolerate `NotFound`, recreate — applied to
both roots before use. Two tests: one seeds a previous build's tree and asserts
a file the new archive omits does not survive, one covers the first-boot case
where there is nothing to clear.

The tests live in the `cfg(target_os = "linux")` module with the code they
cover, so they run in the Linux lanes rather than in a macOS workspace run.
