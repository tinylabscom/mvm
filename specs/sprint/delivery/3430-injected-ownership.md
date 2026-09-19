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
- The injection no longer writes through paths the image shaped. It refuses
  an image in which an injected path, or a directory on the way to one, is a
  symbolic link. The unpacker keeps link targets as written, absolute ones
  included, so the host-side write used to land outside the rootfs, and a
  link inside the rootfs would have moved the file to a path the image's own
  owners govern.
- On a host filesystem that folds names (the macOS default folds case and
  some non-ASCII letters, such as `ſ` to `s`), every component must be
  listed by its directory under exactly mvm's spelling. An image shipping
  `etc/Mvm/` used to receive `/etc/mvm/verb-trust.json` in its own directory,
  owned by the layer's uid, and the guest saw no trust policy at all.
- After injection the tree is checked the way the image writer reads it, by
  listing each directory. Every always-written path must be present under
  its exact spelling.
- A non-regular file where mvm writes a regular one is refused.
- `/etc/mvm`, `/mvm` and `/usr/lib/mvm` are emptied of everything the image
  shipped there before injection, then recreated with mode 0755. The only
  content left in them is what mvm writes.
- The files the injection writes, including the provenance mark, are
  created as fresh inodes. A hard link an image file shares with one of them
  does not carry over, and neither do the layer's mode or extended
  attributes. `/etc/passwd` and `/etc/group` keep the image's entries: they
  are moved onto a fresh inode before the workload identity is appended, and
  set to 0644.
- A deferred layer node (one the host tree could not hold) at an injected
  path is refused before injection. The path is compared in normalized form.
  The image writer lays deferred nodes over the walked tree, so a deferred
  symlink at `/etc/passwd` would have replaced the runtime's file.
- Builder-VM writer:
  - Its input staging and input archive carry symbolic links as links. They
    used to follow them, so an image link such as
    `srv/k -> ../../../.ssh/id_ed25519` copied a host file into the guest
    image.
  - The copy keeps the ids the transport carried, which are the host
    account's. The script now sets the image root and every claimed path
    back to 0:0.
  - Its refusal no longer counts non-root owners on paths mvm claims.
- `INJECT_SEMANTICS_VERSION` is bumped, and the injection layout digest now
  covers the mvm-only trees. A rootfs cached before this change is rebuilt
  rather than reused.
- A builder-VM refusal now states the actual cause. When
  `MVM_MATERIALIZE_BUILDER_VM` selected the builder VM, the refusal tells the
  operator to unset it. On the automatic fallback, it names the in-process
  failure that caused the fallback.
- The owner and deferred-node sidecars are now written atomically. A corrupt
  or truncated sidecar makes the cached unpack unusable, so the layers are
  unpacked again. A corrupt deferred-node sidecar is treated as unknown, not
  as an empty list.

Compatibility: images that ship `/data`, `/work`, `/mnt`, `/home`, `/tmp` or
`/dev/shm` (or any other injected path) as a symbolic link are now refused.

`/etc/nsswitch.conf` is named in claim 2 but is neither injected nor
claimed. The image's own file keeps the owner its layer declared. No code in
the tree bind-mounts it, or `/etc/passwd` and `/etc/group`, read-only; the
`fs_rpc` module doc says it does. What protects all three in the guest is
the read-only workload root.

Still open (plan W3.8):
- On the builder-VM path, paths mvm does not claim are owned by the host
  account's uid.
- On macOS, the unpacker's hard-link fallback removes the link *source* when
  an earlier layer wrote it.
