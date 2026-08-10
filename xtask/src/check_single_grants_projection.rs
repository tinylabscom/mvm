//! `xtask check-single-grants-projection`
//!
//! Egress policy must be derivable from grants in exactly one place. A second
//! derivation is a second policy decision point, and two decision points can
//! disagree — at which point the enforced policy is whichever one the
//! enforcement path happened to read. This is the same discipline
//! `check-uniform-vsock-egress` applies to the egress gate itself.

use anyhow::{Result, bail};
use std::path::Path;

/// The sole file permitted to construct a `NetworkPolicy` from `Grants`.
const PROJECTION_FILE: &str = "crates/mvm-contract/src/grants/projection.rs";

/// Signatures that would constitute a second projection. A *call* to the
/// projection (`network_policy_from_grants(&grants)`) never matches these —
/// only a function signature carries the `-> NetworkPolicy` return type next
/// to a `grants` parameter — so legitimate call sites in tests elsewhere are
/// not offenders.
const FORBIDDEN_MARKERS: [&str; 2] = [
    "grants) -> NetworkPolicy",
    "grants: &Grants) -> NetworkPolicy",
];

pub fn run(workspace: &Path) -> Result<()> {
    let projection = workspace.join(PROJECTION_FILE);
    if !projection.is_file() {
        bail!("the grants projection is missing at {PROJECTION_FILE}");
    }

    let mut offenders = Vec::new();
    crate::fs_walk::for_each_file(&workspace.join("crates"), Some("rs"), &mut |path, body| {
        let rel = path
            .strip_prefix(workspace)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel == PROJECTION_FILE {
            return;
        }
        // Test modules legitimately call the one projection; only a second
        // *definition* is a violation.
        if FORBIDDEN_MARKERS
            .iter()
            .any(|marker| body.contains(marker) && body.contains("pub fn"))
        {
            offenders.push(rel);
        }
    })?;

    if !offenders.is_empty() {
        bail!(
            "a second Grants -> NetworkPolicy projection exists in:\n  {}\n\
             Egress policy must be derived only in {PROJECTION_FILE}.",
            offenders.join("\n  ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_on_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        run(&workspace).expect("the real tree carries exactly one grants projection");
    }

    #[test]
    fn missing_projection_file_fails_closed() {
        let tmp = std::env::temp_dir().join(format!(
            "xtask-single-grants-projection-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains(PROJECTION_FILE));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_second_definition_elsewhere_is_rejected() {
        let tmp = std::env::temp_dir().join(format!(
            "xtask-single-grants-projection-second-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let projection_dir = tmp.join("crates/mvm-contract/src/grants");
        std::fs::create_dir_all(&projection_dir).unwrap();
        std::fs::write(
            projection_dir.join("projection.rs"),
            "pub fn network_policy_from_grants(grants: &Grants) -> NetworkPolicy { todo!() }",
        )
        .unwrap();

        let offender_dir = tmp.join("crates/mvm-core/src");
        std::fs::create_dir_all(&offender_dir).unwrap();
        std::fs::write(
            offender_dir.join("lib.rs"),
            "pub fn sneaky(grants: &Grants) -> NetworkPolicy { unimplemented!() }",
        )
        .unwrap();

        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("crates/mvm-core/src/lib.rs"));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
