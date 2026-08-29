//! Which C library a guest rootfs is built against.
//!
//! The type lives here rather than beside the code that detects it, because
//! two crates that cannot see each other both need it: `mvm-build` observes it
//! while the unpacked tree is still a directory, and `mvm-fs` keys the SDK
//! sidecar cache on it so a guest is offered the variant it can load. Those are
//! siblings, so the shared vocabulary has to sit underneath both.
//!
//! Detection stays in `mvm-build` — it reads a filesystem, which this `no_std`
//! crate cannot.

use serde::{Deserialize, Serialize};

/// The C library a guest rootfs is built against.
///
/// [`GuestLibc::Unknown`] is not a neutral default. It means the tree carried
/// no loader the detector recognises, or carried more than one, and a caller
/// gating on it must treat that as *unknown*, never as safe — the same
/// convention the image sidecar's `entrypoint_argv` follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestLibc {
    /// GNU libc. Loader is `ld-linux-<arch>.so.<n>`; its libc soname is
    /// `libc.so.6`.
    Glibc,
    /// musl libc, as used by Alpine. Loader is `ld-musl-<arch>.so.1`; its libc
    /// soname is `libc.so`.
    Musl,
    /// No recognised loader, or more than one.
    #[default]
    Unknown,
}

impl GuestLibc {
    /// The value as it appears in the image sidecar, in cache paths, and in
    /// operator-facing text.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Glibc => "glibc",
            Self::Musl => "musl",
            Self::Unknown => "unknown",
        }
    }
}

impl core::fmt::Display for GuestLibc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_the_default() {
        assert_eq!(GuestLibc::default(), GuestLibc::Unknown);
    }

    #[test]
    fn the_wire_form_is_lowercase() {
        assert_eq!(serde_json::to_string(&GuestLibc::Musl).unwrap(), "\"musl\"");
        assert_eq!(
            serde_json::from_str::<GuestLibc>("\"glibc\"").unwrap(),
            GuestLibc::Glibc
        );
    }

    /// The cache keys a directory segment on this, so it has to match the wire
    /// form exactly — a divergence would put the artifact somewhere the
    /// resolver does not look.
    #[test]
    fn the_display_form_matches_the_wire_form() {
        for libc in [GuestLibc::Glibc, GuestLibc::Musl, GuestLibc::Unknown] {
            let wire = serde_json::to_string(&libc).unwrap();
            assert_eq!(format!("\"{libc}\""), wire);
        }
    }
}
