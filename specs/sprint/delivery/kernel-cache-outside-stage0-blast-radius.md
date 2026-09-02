# Move the kernel cache out of the Stage 0 blast radius

`just e2e-launch` failed on 2026-08-31 with a cold workload-kernel build that
blew the builder VM's 1800-second wall-clock cap — thirty minutes in, after the
expensive part. A second run six minutes later, same host and same `~/.mvm`,
passed 23/23. Nothing about the tree had changed between them.

The kernel was not corrupt and had not failed verification. It was gone, and
mvm had deleted it.

## The mechanism

`cached_kernel_path` put the workload kernel at

    <cache>/builder-vm/<arch>/kernels/<variant>/vmlinux

which is inside the directory `promote_builder_vm_stage0_cache` calls
`remove_dir_all` on whenever the builder-VM source fingerprint changes:

    if final_dir.exists() { ... std::fs::remove_dir_all(final_dir)?; }
    std::fs::rename(staging_dir, final_dir)?;

`final_dir` is `<cache>/builder-vm/<arch>`. So promoting a new builder image
destroyed, as collateral, an unrelated artifact that costs half an hour of nix
to rebuild. Nothing in `stage0_cache.rs` or `cache_install.rs` so much as
mentions `kernels` — there was no preservation step to have gone wrong, and the
promotion was doing exactly what it was written to do.

The failure needs a fingerprint change to fire, which is why it looked
intermittent. Two source trees sharing one `~/.mvm` wipe each other's kernel on
every alternation, and that is precisely what happened: the run before this one
was from a different worktree.

## Filesystem evidence

The mtimes told the whole story once read correctly:

- `builder-vm/aarch64/` — `rootfs.ext4`, `vmlinux`, `manifest.json`,
  `.mvm-source.sha256` all stamped 14:03, the artifact set replaced at run 1's
  start.
- `builder-vm/aarch64/kernels/` stamped 14:37, meaning `workload/` was created
  inside it by run *2*. The directory sat empty from 14:03 onward.

## What changed

Kernel entries now live at `<cache>/kernels/<arch>/<variant>/`, a sibling of
`builder-vm/` rather than a child. Nothing about a kernel's identity depends on
which builder image compiled it, so it does not belong in a directory whose
contract is "atomically replaceable". Preserving `kernels/` across the promotion
was the alternative; it keeps the artifact inside the bomb and re-creates the
bug the next time someone adds a cache there.

`resolve_kernel` — the one gate every read passes through — adopts an entry left
at the old path by renaming the directory. The digest sidecar and the
size+mtime-keyed digest cache move with the bytes they describe, so an adopted
entry stays verified and no one pays for a rebuild. Adoption only ever moves
into an absent destination, so a newer entry is never clobbered.

## The layout was hand-rebuilt at nine sites

Relocating a path this simple should have been a one-line change. It was not:
the layout was reconstructed independently at nine call sites, including the
*writer*, which built it as a format string. They now all route through
`kernel_cache_dir` / `cached_kernel_path`.

One straggler survived the first sweep and failed the gate — a shell `find` in
`e2e-launch-modes.sh` looking for the kernel under `cache/builder-vm`. A grep
scoped to `*.rs` cannot see it. The script failed loudly rather than skipping the
seam quietly, which is the only reason it was caught; that guard was added
deliberately and earned its keep here.

## The cap, separately

`e2e-launch-modes.sh` now exports `MVM_BUILDER_VM_TIMEOUT_SECS=7200`, respecting
an operator override. The 1800-second default is not enough for a cold
workload-kernel build on a loaded host — run 1 was at load 11-14 on 16 cores —
so the gate failed on a slow build rather than a broken one. `ci-full.yml`
already runs its builder lane at 7200; the two no longer disagree about how long
a build may take.

This is the second-order fix. On its own it would have left a gate that pays a
half-hour rebuild on every fingerprint change and merely tolerates it.

## Verification

Unit and workspace: 12,819 tests pass, clippy clean at `-D warnings`, doctests,
`just check-gated`, and the xtask gates including `check-doc-claims`,
`check-single-home`, `check-single-network-path` and `check-cli-help-matches-docs`.

Three new tests: an entry is not stored under `builder-vm/`, an entry at the old
path is adopted rather than rebuilt, and adoption never clobbers a newer entry.
The reproduction landed red first and asserts its own precondition — that the
planted kernel resolves as `KernelResolution::Cached` — so it proves destruction
rather than absence.

Live on macOS 26 / Apple Silicon against the real `~/.mvm`, which still held a
kernel at the old path:

- The migration fired and was a rename, not a rebuild: all four files kept their
  original 14:37 mtimes, only the new parent directory was newly created.
- The adopted kernel still verifies — computed SHA-256 equals the recorded
  sidecar.
- `just e2e-launch` passed end to end, booting on the adopted kernel with no
  kernel build at all, including the in-process `mvm-client` seam
  (`transient_and_persistent_lifecycle_over_hvf`).

CI cannot exercise this: no hosted macOS runner boots a guest.

## Note for whoever reads the ledger

`check-claim-catalog` and its siblings cannot catch this class. Every gate here
was green while the cache was being destroyed, because nothing asserts that one
cache's lifetime is independent of another's. The new
`a_kernel_entry_is_not_stored_under_the_builder_vm_cache_directory` test is a
narrow guard against exactly one recurrence, not against the general shape.
