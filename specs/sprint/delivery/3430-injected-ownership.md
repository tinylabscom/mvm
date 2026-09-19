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
  - The tree now reaches the builder as one archive the host writes itself
    (`mvm-rootfs.tar`) and the guest extracts into the new filesystem. The
    generic work-input staging, built for source checkouts, dropped
    `node_modules`, `target`, `dist`, `.git` and `result*` at any depth, so a
    node image lost `/usr/local/lib/node_modules`. It also copied symbolic
    links by reading their host targets (an image link such as
    `srv/k -> ../../../.ssh/id_ed25519` copied a host file into the guest
    image), and read special files, so a FIFO hung the copy. The archive
    stores links as links and every entry owned 0:0. It keeps modes,
    including setuid. Devices, FIFOs and sockets are omitted, as the
    in-process writer omits them.
  - The staging and the input archive also carry links as links for every
    other builder job.
  - After extraction, the script sets the image root and every claimed path
    to 0:0. `chown -h` and `chown -Rh` do not follow the final component or
    links met while recursing. An intermediate component could still resolve
    through a link; that is safe only because the host refused any tree with
    a link on the way to a claimed path.
  - Its refusal no longer counts non-root owners on paths mvm claims. It now
    also refuses a tree carrying a guest-semantic extended attribute (a file
    capability, an ACL, a `user.`/`trusted.` attribute). The archive carries
    none, and the builder's busybox `tar` could not restore them.
  - Files are streamed into the archive, never read into memory whole.
- A `--prod` run is always sealed. Before this change the cached rootfs path
  did not record the variant, so a dev image and a sealed image of one image
  shared a file, and the first one written was kept. A `--prod` pull on a cold
  cache also materialized the dev variant, and the boot then quietly picked
  the dev agent profile. Now:
  - The rootfs path carries its variant (`…-sealed/` or `…-dev/`), so the
    two variants never share a file, a sidecar or an output lock.
  - A cached image is reused only at this variant's path, and only when its
    sidecar records `sealed` exactly when the run is `--prod`. Anything else
    is rebuilt.
  - A fresh `--prod` pull is sealed and carries its provenance mark.
  - A `--prod` resolve refuses an image whose sidecar is not sealed, rather
    than hand it to a boot that would choose the dev profile.
  - The cosign trust check runs before anything is materialized or signed
    for a cached image, so a refused image leaves no sealed, signed rootfs
    behind.
- Concurrency. Two runs of one image share its unpacked tree, which is
  injected in place. Without a lock, one run could clear `/etc/mvm` and
  rewrite `variant` and `/etc/passwd` between another run's post-injection
  check and its image walk. Now:
  - Every path that removes, unpacks, injects into or copies from a tree
    holds its per-tree lock (`mvm_build::run_image::lock_unpacked_tree`).
  - Materialization runs under a `HeldTreeLocks` proof covering the tree and
    the rootfs output, passed by reference to the work, so both locks are
    held until the seal and sidecar are written.
  - The overlay-lean staging tree is private to each run.
  - The prepared rootfs-only tree is built in a scratch directory and renamed
    into place under its own lock, so a failure never leaves a partial tree.
  - `copy_tree` skips devices, FIFOs and sockets instead of reading them.
- A deferred-node sidecar that exists but cannot be read is an error. Only
  an absent one means nothing was deferred.
- The alias defence is layered. Clearing the mvm-only trees and writing
  fresh inodes re-spell mvm's names even without the pre-check. The
  post-injection check catches an alias of a parent directory, which those
  two cannot.
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

Still open (plan W3.8): on macOS the unpacker's hard-link fallback removes
the link *source* when an earlier layer wrote it.
