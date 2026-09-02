# am-fs-ext4 0.4.0 patch

This directory contains the source of the MIT-licensed
`am-fs-ext4` 0.4.0 package published on crates.io, used only as the independent
ext4 reader for `mvm-fs` tests.

MVM carries one source change in `src/capi.rs`: initialize the directory-entry
name buffer as `[c_char; 256]` instead of `[i8; 256]`. The published form does
not compile on platforms where C `char` is unsigned, including aarch64 Linux.
The change preserves the declared C ABI and the behavior on signed-`char`
targets.

Upstream: <https://github.com/christhomas/rust-fs-ext4>

Remove this patch and the root `[patch.crates-io]` entry after an upstream
release containing the equivalent fix is adopted.
