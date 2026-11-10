# am-fs-ext4 0.4.0 patch

This directory contains the source of the MIT-licensed
`am-fs-ext4` 0.4.0 package published on crates.io, used only as the independent
ext4 reader for `mvm-fs` tests.

MVM carries one source change: the C ABI (`capi`), the `mkfs`, `fsck` and
`verify` modules, the `fs_core_bridge`, `acl`, `casefold`, `ea_inode` and
`htree_mut` modules and the `mkfs_ext4` binary are removed, because the tests
only use the reader and the in-place write paths, and the dependencies those
modules alone needed are dropped with them. No remaining file is edited.

Upstream: <https://github.com/christhomas/rust-fs-ext4>

Remove this patch and the root `[patch.crates-io]` entry after an upstream
release containing the equivalent fix is adopted.
