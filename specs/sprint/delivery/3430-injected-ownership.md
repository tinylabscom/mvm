# Delivery: injected image files stay root-owned (#3430)

A container image layer could take ownership of the files mvm injects into
the built rootfs. The layer owner table was applied after injection, so a
layer that declared `etc/passwd` as uid 1000 produced an image whose
`/etc/passwd` belonged to uid 1000. Claim 2 depends on the account databases
being root-owned.

- `OwnerTable::apply` now takes a `RootOwnedPaths` set and forces root on
  every node the set claims. It sets root instead of skipping those nodes,
  because a deferred node arrives carrying its layer's owner even when the
  table doesn't name the path. `mvm_build::oci_runtime_inject::injected_root_owned_paths`
  builds the set from the tables the injection already walks (`INJECT_DESTS`,
  `INJECT_DIRS`) and the directories leading to each entry, plus the trees
  mvm owns (`/etc/mvm`, `/mvm`, `/usr/lib/mvm`). The in-process materializer
  claims that set on every tree it builds.
- The injection no longer writes through whatever the image left at a path.
  An image that ships an injected path, a directory on the way to one, or
  anything under an mvm-only tree as a symbolic link is refused: the
  unpacker keeps link targets as written, absolute ones included, so the
  host-side write used to land outside the rootfs, and a link inside it
  would have moved the file to a path the image's own owners govern. A
  non-regular file where a regular one is written is refused too. Every
  injected file is created as a fresh inode, so a hard link an image file
  shares with `/etc/passwd`, the layer's mode, and the layer's extended
  attributes (an ACL, for example) do not survive. The account databases
  are moved onto a fresh inode before the workload identity is appended.
- A deferred layer node (one the host tree could not hold) at an injected
  path is refused before injection. The image writer lays deferred nodes
  over the walked tree, so a deferred symlink at `/etc/passwd` would have
  replaced the runtime's file with the layer's.
- The builder-VM writer copies the host tree with the ids the input
  transport carried, which are the host account's. Its script now sets every
  claimed path back to root after the copy.
- `INJECT_SEMANTICS_VERSION` is bumped, so a rootfs cached before the fix is
  rebuilt rather than reused.
- The adversarial tests cover `/etc/passwd`, `/etc/group`,
  `/etc/mvm/verb-trust.json` and the entrypoint wrapper: through the
  production materializer options, through the independent ext4 oracle, and
  through stacked layers with a whiteout, an opaque directory and a hard
  link. Each also checks that a path mvm does not inject keeps the owner its
  layer declared.
- A builder-VM refusal now states the actual cause. When
  `MVM_MATERIALIZE_BUILDER_VM` selected the builder VM, the refusal tells the
  operator to unset it. On the automatic fallback, it names the in-process
  failure that caused the fallback.
- The owner and deferred-node sidecars are now written atomically. A corrupt
  or truncated sidecar makes the cached unpack unusable, so the layers get
  unpacked again. It no longer returns a hard error that blocks the image
  until someone deletes the file by hand. A corrupt deferred-node sidecar is
  treated as unknown, not as an empty list.

Not fixed here, found while checking the builder-VM path: the work-input
staging (`copy_dir_filtered`) copies a symbolic link's host-resolved target
instead of the link, and the input tar records host uids for every file, so
an image materialized through the builder VM carries the host account's ids
everywhere mvm does not claim. On macOS the unpacker's hard-link fallback
removes the link *source* when an earlier layer wrote it.
