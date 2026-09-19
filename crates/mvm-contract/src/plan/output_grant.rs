//! Output grants: which guest directories a transient workload may hand back
//! to the host, where they land, and the bounds the collection enforces.

use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::plan::types::{HostShareGrant, ShareKind, deserialize_abs_path};

/// A grant for a transient workload to hand files back to the host.
///
/// The guest writes under `guest_path`, which is backed by a fresh, writable
/// disk image the plan also names in `shares`. After the workload exits and
/// its filesystem has been flushed, the host reads that image — no protocol
/// is spoken with the guest — and copies what it finds into `host_path`,
/// refusing the whole collection rather than truncating it when either bound
/// is exceeded. Both bounds are fixed here, before boot, so the admitted plan
/// says how much a workload may return, not only where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputGrant {
    /// Absolute guest mount point the workload writes its results under.
    #[serde(deserialize_with = "deserialize_abs_path")]
    pub guest_path: String,
    /// Resolved host directory the collected files are written to. It must be
    /// absent or empty when the collection runs; nothing in it is overwritten.
    #[serde(deserialize_with = "deserialize_abs_path")]
    pub host_path: String,
    /// Refuse the collection when the files sum to more bytes than this.
    pub max_bytes: u64,
    /// Refuse the collection when it holds more files and directories than this.
    pub max_entries: u64,
}

/// Why a plan's output grants are inadmissible.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutputGrantError {
    #[error("output grant for {guest_path} declares a zero {bound} bound")]
    ZeroBound {
        guest_path: String,
        bound: &'static str,
    },
    #[error("output grant for {guest_path} is declared more than once")]
    DuplicateGuestPath { guest_path: String },
    #[error(
        "output grant for {guest_path} has no writable disk share at that guest path, so the \
         workload would have nowhere to write it"
    )]
    NoWritableDisk { guest_path: String },
}

/// Validate a plan's output grants against its host-fs grants.
pub fn validate_output_grants(
    outputs: &[OutputGrant],
    shares: &[HostShareGrant],
) -> Result<(), OutputGrantError> {
    for (index, grant) in outputs.iter().enumerate() {
        for (value, bound) in [(grant.max_bytes, "byte"), (grant.max_entries, "entry")] {
            if value == 0 {
                return Err(OutputGrantError::ZeroBound {
                    guest_path: grant.guest_path.clone(),
                    bound,
                });
            }
        }
        if outputs[..index]
            .iter()
            .any(|earlier| earlier.guest_path == grant.guest_path)
        {
            return Err(OutputGrantError::DuplicateGuestPath {
                guest_path: grant.guest_path.clone(),
            });
        }
        let backed = shares.iter().any(|share| {
            share.kind == ShareKind::Disk
                && !share.read_only
                && share.guest_path == grant.guest_path
        });
        if !backed {
            return Err(OutputGrantError::NoWritableDisk {
                guest_path: grant.guest_path.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn grant(guest: &str) -> OutputGrant {
        OutputGrant {
            guest_path: guest.into(),
            host_path: "/host/results".into(),
            max_bytes: 1 << 20,
            max_entries: 100,
        }
    }

    fn disk(guest: &str, read_only: bool) -> HostShareGrant {
        HostShareGrant {
            tag: "uvol0".into(),
            host_path: "/state/output.img".into(),
            guest_path: guest.into(),
            kind: ShareKind::Disk,
            read_only,
            encrypted: false,
            content_sha256: None,
        }
    }

    #[test]
    fn roundtrips_through_json_and_refuses_unknown_fields() {
        let g = grant("/data/out");
        let json = serde_json::to_string(&g).unwrap();
        assert_eq!(serde_json::from_str::<OutputGrant>(&json).unwrap(), g);
        let extra = json.replace('}', r#","bogus":1}"#);
        assert!(serde_json::from_str::<OutputGrant>(&extra).is_err());
    }

    #[test]
    fn rejects_relative_paths_on_either_side() {
        for json in [
            r#"{"guest_path":"data","host_path":"/h","max_bytes":1,"max_entries":1}"#,
            r#"{"guest_path":"/data","host_path":"h","max_bytes":1,"max_entries":1}"#,
        ] {
            assert!(serde_json::from_str::<OutputGrant>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn a_grant_backed_by_a_writable_disk_is_admissible() {
        assert_eq!(
            validate_output_grants(&[grant("/data/out")], &[disk("/data/out", false)]),
            Ok(())
        );
    }

    #[test]
    fn a_grant_without_a_writable_disk_at_its_guest_path_is_refused() {
        for shares in [
            vec![],
            vec![disk("/data/out", true)],
            vec![disk("/data/other", false)],
        ] {
            assert!(matches!(
                validate_output_grants(&[grant("/data/out")], &shares),
                Err(OutputGrantError::NoWritableDisk { .. })
            ));
        }
    }

    #[test]
    fn zero_bounds_and_duplicates_are_refused() {
        let shares = [disk("/data/out", false)];
        let mut zero_bytes = grant("/data/out");
        zero_bytes.max_bytes = 0;
        assert!(matches!(
            validate_output_grants(&[zero_bytes], &shares),
            Err(OutputGrantError::ZeroBound { bound: "byte", .. })
        ));
        let mut zero_entries = grant("/data/out");
        zero_entries.max_entries = 0;
        assert!(matches!(
            validate_output_grants(&[zero_entries], &shares),
            Err(OutputGrantError::ZeroBound { bound: "entry", .. })
        ));
        assert!(matches!(
            validate_output_grants(&[grant("/data/out"), grant("/data/out")], &shares),
            Err(OutputGrantError::DuplicateGuestPath { .. })
        ));
    }
}
