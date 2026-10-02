//! The on-disk name of the guest sidecar manifest.
//!
//! The sidecar is written beside a built rootfs and travels with it: the
//! builder emits it, the runtime refuses to boot a rootfs without it, and a
//! bundle has to carry it for the rootfs inside to be bootable on arrival.
//! Those three live in crates that do not depend on each other, so the name
//! is defined once here instead of once per crate.

/// Filename of the sidecar manifest written next to a built rootfs.
pub const SIDECAR_FILENAME: &str = "mvm-meta.json";
