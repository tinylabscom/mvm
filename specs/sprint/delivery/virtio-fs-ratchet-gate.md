# A ratchet on the virtio-fs surface

`xtask check-no-virtio-fs` pins every site that attaches a virtio-fs device or
constructs a share, with a reason per file and what would retire it. A new site
fails as growth. A *removed* site also fails, as a stale pin — so the table can
only shrink, and cannot rot into a ceiling nobody maintains.

23 sites across 11 files, all of them builder-VM plumbing or the libkrun C FFI.
No workload tier reaches virtio-fs at all.

## Landed before the removal finished, not after

The plan put this gate last, after Stage C. That ordering leaves the removal
unprotected for exactly as long as the removal takes — and the remaining work
needs hardware validation, so "as long as it takes" is open-ended. A ratchet
does not need the surface to be zero to be useful; it needs it to be *known*.

## Counting code, not the word

The plan's original design failed on `virtio_fs` / `VirtioFs` / `virtiofsd`
anywhere outside the FFI bindings. That would have fired on ~70 files, nearly
all of which only *discuss* virtio-fs — including several explaining why we are
removing it. Worse, a word-matching gate is satisfied by rewording a comment.

So the pattern matches the forms that actually attach a device — `add_virtiofs*`,
`VirtioFs::new`/`with_tag`, `VirtioFsShare {`, `HvfVirtioFsShare {`,
`krun_add_virtiofs` — over source with comments and strings blanked first. A
test pins each of those forms, because a pattern that silently stops matching
one turns a whole class of attach site invisible.

Four rows in the first draft turned out to be doc comments rather than code. The
gate caught them on its first run, which is the behaviour worth having.

## What the inventory turned up

Two findings that change the remaining plan, both recorded there:

**`out` was never the blocker.** The plan said Stage C could not start until we
chose between a host-side ext4 reader and vsock streaming.
`mvm_build::builder_disk_transport` already resolves it and has for some time: a
raw tar written straight onto a disk image with no filesystem, so both sides only
run `tar` and the host needs no ext4 reader. That is precisely why it exists —
HVF's host is macOS, which can neither format nor read an ext4.

**The one-shot builder already migrated.** `libkrun_builder.rs` packs the input
disk and reads the output disk; `builder_spec` lays out four disks and asks for
no shares. The only share-based path left is the *persistent* HVF builder, which
is persistent — many dispatches against one live VM — so a disk packed once at
boot does not substitute. It already has a `BuilderDispatch` vsock channel, so
that migration extends an existing protocol rather than inventing a transport.

## Verification

Both failure directions were exercised against the real tree before landing: a
new attach site in an unpinned file is reported as new surface, and an extra site
in a pinned file is reported as growth. Four unit tests ship with the gate,
including one asserting the pattern still matches every real attach form.

`check-all` — 63 gates clean. The gate runs on every PR through `ci.yml`.
