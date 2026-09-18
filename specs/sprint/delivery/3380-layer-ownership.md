# #3380 — container layer file ownership survives into the rootfs image

**Delivered:** 2026-09-16
**Plan:** `specs/plans/2026-09-16-sandbox-review-upgrades.md`, W3

## The bug

A rootfs built from container image layers booted with every file owned by
root. The layer unpacker writes into a host directory as an unprivileged user,
so it cannot `chown`; the walk that feeds the ext4 writer saw only the host
user's ids and threw them away; and the writer had nowhere to put an owner
anyway — `Node` had no owner and every inode was written uid 0, gid 0. A layer
that ships `/var/lib/<service>` owned by its service account booted with that
directory owned by root, and the service failed once it dropped privileges.

## What changed

- **The writer.** Every `Node` variant carries an `Owner`. The inode gets the
  low halves at `i_uid` (0x02) and `i_gid` (0x18) and the high halves in
  `osd2.linux2` at `l_i_uid_high` (0x78) and `l_i_gid_high` (0x7A) — after
  `l_i_blocks_high` and `l_i_file_acl_high`, not at 0x74/0x76. The independent
  test-oracle reader agrees on those offsets. Root writes zeros into bytes that
  were already zero, so an image with no owners is byte-identical to before;
  a pinned digest, taken before the writer changed, proves it.
- **The unpacker.** Each materialized entry's owner is read from its tar header,
  with a pax `uid`/`gid` record taking precedence. An id past 32 bits, or a pax
  value that is not a decimal number, refuses the entry as malformed rather than
  truncating it into someone else's id. The owners go into a per-layer
  `LayerOwnership` record alongside the whiteouts the layer applied.
- **Stacking layers.** `mvm_fs::ownership::OwnerTable` folds each layer's record
  in manifest order: a later entry wins, a whiteout drops the owners of
  everything it removed, an opaque marker drops the lower contents' owners and
  keeps the directory's, and a file replacing a directory drops the directory's
  children. A hardlink gives both names the link header's owner, since they are
  one inode. A parent directory the stream implied but never listed stays root.
- **The materializer.** `MaterializeOptions::owners` is applied to the walked
  nodes. A host-directory walk (`--mount`, flake images) never reads host ids,
  so it stays root-owned unless a caller supplies a table.
- **Cache identity.** `fingerprint_ext4_nodes` folds a non-root owner into the
  node's kind byte, so a tree that differs only in ownership gets a different
  identity while root-owned identities are unchanged (also pinned). The image
  cache's runtime tag gains `unpack-2`, so an image cached before this change is
  rebuilt; the owners are persisted beside the unpacked tree, and a tree with no
  owner record is unpacked again rather than rebuilt root-owned.
- **The builder-VM fallback** copies the host tree, so it cannot place owners.
  It refuses an image whose layers assign a non-root owner, the same way it
  already refused deferred nodes.

## Not covered

- The dev-only rootfs-only tree served as a host directory share still presents
  host ids; it is a host directory, not an image.
- The live boot of an image whose service data directory is owned by a non-root
  account (W3.6) was not run.
