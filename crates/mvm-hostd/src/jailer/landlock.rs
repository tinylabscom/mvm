//! ADR-064 — Landlock filesystem ruleset (ABI v2, Linux 5.19+).
//!
//! ABI v2 is the floor because it's the first to expose the
//! file-execute permission split, which the `mvm-firecracker-bridge`
//! sidecar relies on to read its passt binary (exec) without granting
//! exec on the audit-log directory. Earlier ABIs collapse the two.

use crate::jailer::{ConfinementSpec, JailerError};
use landlock::{
    ABI, Access, AccessFs, BitFlags, PathBeneath, PathFd, RestrictionStatus, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetError, RulesetStatus,
};

/// Minimal `AccessFs` bit-set granted on `read_write_paths` for the
/// bridge sidecar. Landlock is supposed to be the *smallest* grant
/// that lets the bridge function, so we explicitly enumerate:
///
/// - `ReadFile` / `ReadDir`: read the existing audit chain head to
///   verify before appending (chain-signing requires the previous
///   entry's signature).
/// - `WriteFile`: append the new entry.
/// - `MakeReg`: create the `tmp` file used for atomic write-then-rename.
/// - `Refer`: rename across the same parent directory (atomicity).
/// - `RemoveFile`: clean up stale `tmp` files left by a crashed writer.
///
/// Notably absent: `Execute` (no exec inside audit dir), `MakeChar`
/// / `MakeBlock` / `MakeSock` / `MakeFifo` / `MakeSym` (device-style
/// nodes have no place in an audit-log directory). `from_all(V2)`
/// would grant all of these; we refuse.
fn rw_bridge_access() -> BitFlags<AccessFs> {
    AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::MakeReg
        | AccessFs::Refer
        | AccessFs::RemoveFile
}

pub fn apply(spec: &ConfinementSpec) -> Result<(), JailerError> {
    let abi = ABI::V2;
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| match e {
            RulesetError::CreateRuleset(_) => JailerError::LandlockUnavailable,
            other => JailerError::LandlockApply(format!("{other:?}")),
        })?
        .create()
        .map_err(|e| JailerError::LandlockApply(format!("{e:?}")))?;

    let rw_access = rw_bridge_access();
    for p in &spec.readable_paths {
        let fd = PathFd::new(p).map_err(|e| path_open_error(p, e))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))
            .map_err(|e| JailerError::LandlockApply(format!("{e:?}")))?;
    }
    for p in &spec.read_write_paths {
        let fd = PathFd::new(p).map_err(|e| path_open_error(p, e))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, rw_access))
            .map_err(|e| JailerError::LandlockApply(format!("{e:?}")))?;
    }
    let status: RestrictionStatus = ruleset
        .restrict_self()
        .map_err(|e| JailerError::LandlockApply(format!("{e:?}")))?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced | RulesetStatus::NotEnforced => {
            Err(JailerError::LandlockApply(format!(
                "ruleset status {:?}; refusing partial confinement",
                status.ruleset
            )))
        }
    }
}

/// Convert a `landlock::PathFdError` into our `PathNotFound` variant so
/// the operator sees which path failed. The `landlock` crate's only
/// `PathFdError` variant today is `OpenCall { source, path, .. }`
/// (both the enum and the variant carry `#[non_exhaustive]`, so future
/// landlock releases may add fields or variants). When we can extract
/// the source `io::Error`, we surface it; otherwise we synthesize a
/// generic error from the spec path so the caller still gets a useful
/// message instead of a panic.
fn path_open_error(spec_path: &std::path::Path, err: landlock::PathFdError) -> JailerError {
    match err {
        landlock::PathFdError::OpenCall { source, path, .. } => {
            // Prefer the path the landlock crate reports (it's the one
            // it actually tried to open). If for any reason it's empty,
            // fall back to the path from the spec.
            let chosen = if path.as_os_str().is_empty() {
                spec_path.to_path_buf()
            } else {
                path
            };
            JailerError::PathNotFound {
                path: chosen,
                source,
            }
        }
        // Future landlock variant: synthesize a generic error keyed to
        // the spec path so the operator at least sees which path was
        // being installed.
        other => JailerError::PathNotFound {
            path: spec_path.to_path_buf(),
            source: std::io::Error::other(format!("landlock PathFd open failed: {other:?}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Defense-in-depth: a future contributor swapping the minimal
    /// grant back to `AccessFs::from_all(ABI::V2)` (or otherwise
    /// granting Execute / Make{Char,Block,Sock,Fifo,Sym}) trips this
    /// test before the change reaches CI. The bridge's audit-dir use
    /// case never needs any of these bits — see `rw_bridge_access`
    /// doc for the rationale.
    #[test]
    fn rw_bridge_access_does_not_include_dangerous_bits() {
        let access = rw_bridge_access();
        assert!(!access.contains(AccessFs::Execute), "Execute granted");
        assert!(!access.contains(AccessFs::MakeChar), "MakeChar granted");
        assert!(!access.contains(AccessFs::MakeBlock), "MakeBlock granted");
        assert!(!access.contains(AccessFs::MakeSock), "MakeSock granted");
        assert!(!access.contains(AccessFs::MakeFifo), "MakeFifo granted");
        assert!(!access.contains(AccessFs::MakeSym), "MakeSym granted");
        assert!(!access.contains(AccessFs::MakeDir), "MakeDir granted");
    }

    #[test]
    fn rw_bridge_access_includes_required_bits() {
        let access = rw_bridge_access();
        assert!(access.contains(AccessFs::ReadFile));
        assert!(access.contains(AccessFs::ReadDir));
        assert!(access.contains(AccessFs::WriteFile));
        assert!(access.contains(AccessFs::MakeReg));
        assert!(access.contains(AccessFs::Refer));
        assert!(access.contains(AccessFs::RemoveFile));
    }
}
