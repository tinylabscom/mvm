//! `mvm-builder-init` — tiny in-guest init for the libkrun-backed
//! builder VM. Plan 71 W3.
//!
//! The binary at `src/main.rs` is Linux-only (it issues `mount(2)`,
//! `reboot(2)`, etc. via `libc`). The pure-Rust helpers in this lib
//! crate compile and test cross-platform so contributors on macOS
//! can run `cargo test -p mvm-builder-init` and exercise the
//! result-file format, kernel-cmdline parsing, and stderr-tail
//! truncation.
//!
//! ## Boot order the binary will execute (W3-real PR)
//!
//! 1. Mount essentials: `/proc`, `/sys`, `/dev`, `/tmp`.
//! 2. fsck + mount the persistent `/nix` store from `/dev/vdb`. On a
//!    fresh disk, format ext4, copy the seed `/nix/store` from the
//!    rootfs, then bind-mount over `/nix`.
//! 3. Bring up `eth0` via `udhcpc -i eth0 -n -q`.
//! 4. Exec `/bin/sh -eu /job/cmd.sh`; capture exit code + stderr tail.
//! 5. Write [`JobResult`] to `/job/result` as one JSON object on one
//!    line.
//! 6. `reboot(LINUX_REBOOT_CMD_POWER_OFF)`.
//!
//! Every step has a typed error path that lands in
//! `/job/result` rather than panicking. The builder VM never owns
//! "did anything go wrong" — the host reads the result file after
//! the VM powers off, and uses the host-side timeout as the only
//! catastrophic guard rail. Mirrors `mvmctl run`'s own model.

pub mod cmdline;
pub mod result;

pub use cmdline::BuilderCmdline;
pub use result::{JobResult, STDERR_TAIL_MAX_BYTES};
