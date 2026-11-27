//! What the running Firecracker can be asked for.
//!
//! The pinned version is what `install` fetches on a host with no Firecracker.
//! It is not what a host runs: `install` leaves an existing binary alone, so a
//! host provisioned before a pin moved keeps its older Firecracker. Anything a
//! newer version added has to be gated on the process actually serving the
//! API socket, because Firecracker rejects a config field it does not know.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// The first Firecracker with block discard (opt-in, writable `Sync` drives).
const BLOCK_DISCARD_SINCE: (u32, u32, u32) = (1, 17, 0);

/// Optional device features the running Firecracker supports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FcCapabilities {
    /// Writable drives can offer the guest discard, so a trim punches holes in
    /// the host image file.
    pub block_discard: bool,
}

impl FcCapabilities {
    /// Capabilities of a Firecracker reporting `version` (`1.17.0`,
    /// `v1.17.0`). An unparseable version gets none: sending a field an older
    /// Firecracker rejects fails the whole boot, and not offering one only
    /// costs the feature.
    pub fn for_version(version: &str) -> Self {
        let Some(version) = parse_version(version) else {
            return Self::default();
        };
        Self {
            block_discard: version >= BLOCK_DISCARD_SINCE,
        }
    }

    /// Ask the Firecracker serving `socket` which version it is. A failed or
    /// malformed answer is reported, not guessed at.
    pub fn probe(socket: &Path) -> Result<Self> {
        Ok(Self::for_version(&running_version(socket)?))
    }
}

/// The version the Firecracker serving `socket` reports, e.g. `1.17.0`.
pub fn running_version(socket: &Path) -> Result<String> {
    let body = crate::fc::call(socket, "GET", "/version", None)
        .context("GET /version from Firecracker")?;
    let reported: VersionResponse =
        serde_json::from_str(&body).context("parsing Firecracker's /version response")?;
    Ok(reported.firecracker_version)
}

/// `GET /version`'s body.
#[derive(Deserialize)]
struct VersionResponse {
    firecracker_version: String,
}

/// `1.17.0` / `v1.17.0` / `1.17.0-dev` → `(1, 17, 0)`.
fn parse_version(raw: &str) -> Option<(u32, u32, u32)> {
    let raw = raw.trim().trim_start_matches('v');
    let core = raw.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|part| part.parse::<u32>().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discard_starts_at_1_17() {
        for supported in ["1.17.0", "v1.17.0", "1.17.1", "1.18.0", "2.0.0"] {
            assert!(
                FcCapabilities::for_version(supported).block_discard,
                "{supported}"
            );
        }
        for older in ["1.14.1", "v1.16.2", "1.9.20", "0.25.0"] {
            assert!(!FcCapabilities::for_version(older).block_discard, "{older}");
        }
    }

    #[test]
    fn a_prerelease_suffix_does_not_hide_the_version() {
        assert!(FcCapabilities::for_version("1.17.0-dev").block_discard);
    }

    #[test]
    fn an_unreadable_version_offers_nothing() {
        for bad in ["", "1.17", "one.seventeen.zero", "1.17.0.1", "1..0"] {
            assert_eq!(
                FcCapabilities::for_version(bad),
                FcCapabilities::default(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_version_response_is_read_by_its_documented_field() {
        let reported: VersionResponse =
            serde_json::from_str(r#"{"firecracker_version": "1.17.0"}"#).unwrap();
        assert!(FcCapabilities::for_version(&reported.firecracker_version).block_discard);
    }
}
