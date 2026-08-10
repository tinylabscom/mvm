//! `xtask check-single-grants-projection`
//!
//! Egress policy must be derivable from grants in exactly one place. A second
//! derivation is a second policy decision point, and two decision points can
//! disagree — at which point the enforced policy is whichever one the
//! enforcement path happened to read. This is the same discipline
//! `check-uniform-vsock-egress` applies to the egress gate itself.
//!
//! The rule: outside the projection file, no function signature may both
//! take a `Grants` and return a `NetworkPolicy`. Keying on the signature
//! shape rather than on fixed marker strings is what makes the gate survive
//! the refactors that would otherwise slip past it — a renamed parameter, a
//! by-value `Grants`, or a `Result`/`Option`-wrapped return are all still the
//! same second decision point.
//!
//! Visibility is deliberately not part of the rule. Even a private
//! delegating wrapper is a second name for the one decision, and it belongs
//! in the projection file — testing visibility file-wide (rather than per
//! declaration) is also what would make a gate like this fire on unrelated
//! code that merely happens to share a file with a real definition.
//!
//! Known and accepted limit: a method on a struct that holds `Grants` (`fn
//! policy(&self) -> NetworkPolicy`) names neither type in its signature and
//! is not detectable by a text gate. That shape has to be caught in review,
//! not here.

use anyhow::{Result, bail};
use std::path::Path;

/// The sole file permitted to construct a `NetworkPolicy` from `Grants`.
const PROJECTION_FILE: &str = "crates/mvm-contract/src/grants/projection.rs";

/// Roots to scan for a second projection. Root `src/` is the facade that
/// re-exports the libraries and root `tests/` holds workspace-level
/// integration tests — both could host a second projection just as easily as
/// a crate under `crates/`.
const ROOTS: [&str; 3] = ["crates", "src", "tests"];

pub fn run(workspace: &Path) -> Result<()> {
    let projection = workspace.join(PROJECTION_FILE);
    if !projection.is_file() {
        bail!("the grants projection is missing at {PROJECTION_FILE}");
    }

    let mut offenders = Vec::new();
    for root in ROOTS {
        let dir = workspace.join(root);
        if !dir.is_dir() {
            continue;
        }
        crate::fs_walk::for_each_file(&dir, Some("rs"), &mut |path, body| {
            let rel = path
                .strip_prefix(workspace)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if rel == PROJECTION_FILE {
                return;
            }
            for line in body.lines() {
                let Some((before, after)) = line.split_once("->") else {
                    continue;
                };
                if before.contains("fn ")
                    && before.contains("Grants")
                    && after.contains("NetworkPolicy")
                {
                    offenders.push(format!("{rel}: {}", line.trim()));
                    break;
                }
            }
        })?;
    }

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
    fn a_renamed_parameter_is_still_caught() {
        let tmp = fixture_with_offender(
            "renamed-param",
            "pub fn policy_for(g: &Grants) -> NetworkPolicy { unimplemented!() }",
        );
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("crates/mvm-core/src/lib.rs"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_by_value_grants_parameter_is_still_caught() {
        let tmp = fixture_with_offender(
            "by-value",
            "pub fn derive(grants: Grants) -> NetworkPolicy { unimplemented!() }",
        );
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("crates/mvm-core/src/lib.rs"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_result_wrapped_return_is_still_caught() {
        let tmp = fixture_with_offender(
            "result-wrapped",
            "pub fn try_policy(grants: &Grants) -> Result<NetworkPolicy, ()> { unimplemented!() }",
        );
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("crates/mvm-core/src/lib.rs"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_private_wrapper_is_still_caught() {
        let tmp = fixture_with_offender(
            "private-wrapper",
            "fn private_wrapper(grants: &Grants) -> NetworkPolicy { unimplemented!() }",
        );
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("crates/mvm-core/src/lib.rs"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_second_definition_reports_the_offending_line() {
        let tmp = fixture_with_offender(
            "line-reported",
            "pub fn sneaky(grants: &Grants) -> NetworkPolicy { unimplemented!() }",
        );
        let err = run(&tmp).unwrap_err();
        assert!(
            err.to_string()
                .contains("pub fn sneaky(grants: &Grants) -> NetworkPolicy")
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn fixture_with_offender(label: &str, offender_line: &str) -> std::path::PathBuf {
        let tmp = std::env::temp_dir().join(format!(
            "xtask-single-grants-projection-{label}-{}",
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
        std::fs::write(offender_dir.join("lib.rs"), offender_line).unwrap();
        tmp
    }
}
