# OCI image publication and removal durability (#3538)

Backing: shipped-source
Validation: focused host tests, package check and Clippy, repository gates

## Durable rootfs publication

`publish_rootfs_build` already flushed every staged file and renamed the guest
sidecar last, but the containing directory was not synced. The final rename is
now followed by a directory sync, and a sync failure is returned to the caller.
The regression injects that failure after the renames and proves publication
does not report success without the durability boundary.

## One cache mutation protocol

OCI index writers now use an advisory lock on `index.json`, reload while the
lock is held, and replace the index through the durable atomic-write helper.
`image rm` first snapshots the entry, then acquires its unpacked-tree lock and
all materialized-rootfs output locks in sorted order before taking the index
lock. It reloads and verifies that both the entry and resource set still match;
if they changed, it drops the locks and retries from a fresh snapshot.

Pull and rematerialization register a completed image in the same resource →
index order. They re-acquire the tree and output locks, verify that the unpacked
tree has its ownership/deferred state and that the published rootfs is complete,
then lock, reload and update the index. A forced interleaving holds removal at
the resource boundary while an upsert queues behind it; after removal commits
and deletes the files, the upsert refuses the missing tree and leaves the index
empty instead of resurrecting a broken entry.

The index removal is committed before file reclamation. A process or power loss
can therefore leave unreachable cache bytes, which a later maintenance sweep
may reclaim, but cannot leave a live index entry whose files were already
deleted.

## Last-reference cleanup

When another cache entry names the same resolved digest, the unpacked tree,
ownership sidecar and deferred-node sidecar remain. Removing the last reference
deletes all three while holding the digest's tree lock, alongside the existing
rootfs, metadata and unshared-layer cleanup. Tests cover both halves of that
shared-reference transition and prove removal waits for a live tree reader.

## Validation status

The 24 `mvm-build` run-image tests, 28 cache tests, and all 121 host-side image
module tests pass. The cache race tests observe actual resource- or index-lock
contention before releasing the held lock, with bounded channel waits used only
as deadlock guards. Package check and all-target Clippy pass, as do the exact
single-threaded full workspace suite, workspace all-target Clippy, gated-target
compilation, formatting, and all 74 repository gates.

An earlier full-workspace run hit the unrelated timer-sensitive
`quota::controller::tests::the_controller_reads_the_clock_once_per_period`;
its isolated exact rerun passed, and the final exact workspace rerun passed in
full. The first sandboxed gated-target invocation could not write Zig's user
cache; the same command passed outside the filesystem sandbox.
