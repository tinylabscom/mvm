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
//!
//! Signatures are matched whole, not line-by-line: rustfmt wraps any
//! signature past its width limit, which puts the parameters and the return
//! type on different lines — the single most likely shape a real second
//! projection would actually take, and invisible to a line-based check.
//! Comments are stripped first so prose quoting a signature is not mistaken
//! for one.

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
            // The return-type arrow is matched with `rsplit_once` (last
            // occurrence, not first): a parameter of type `impl Fn() -> T`
            // carries its own `->` before the real one, and taking the first
            // occurrence would split there instead of at the signature's
            // actual return type.
            for signature in fn_signatures(&strip_line_comments(body)) {
                let Some((params, ret)) = signature.rsplit_once("->") else {
                    continue;
                };
                if params.contains("Grants") && ret.contains("NetworkPolicy") {
                    offenders.push(format!("{rel}: {}", signature.trim()));
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

/// Drop `//`-style comments so prose quoting a signature is not read as one.
/// Block comments are left alone: a `/* */` containing a full signature is
/// rare enough that the false positive is cheaper than a comment parser.
fn strip_line_comments(body: &str) -> String {
    body.lines()
        .map(|line| match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every function signature in `body`, each flattened to one line.
///
/// A signature runs from `fn ` to the `{` opening its body (or the `;`
/// ending a trait method), so a rustfmt-wrapped signature is returned whole
/// rather than in fragments.
fn fn_signatures(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("fn ") {
        rest = &rest[start..];
        let end = rest
            .find('{')
            .into_iter()
            .chain(rest.find(';'))
            .min()
            .unwrap_or(rest.len());
        out.push(rest[..end].split_whitespace().collect::<Vec<_>>().join(" "));
        rest = &rest[end.min(rest.len())..];
        if rest.is_empty() {
            break;
        }
        rest = &rest[1.min(rest.len())..];
    }
    out
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
        // The reported text starts at `fn ` (visibility is not part of the
        // matched signature); the file and the rest of the signature must
        // still be present so the failure is actionable.
        assert!(
            err.to_string().contains(
                "crates/mvm-core/src/lib.rs: fn sneaky(grants: &Grants) -> NetworkPolicy"
            )
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_rustfmt_wrapped_signature_is_still_caught() {
        // Written exactly as rustfmt would emit a signature past its width
        // limit: parameters and return type on separate lines. This is the
        // shape a line-based check misses.
        let tmp = fixture_with_offender(
            "rustfmt-wrapped",
            "pub fn policy_for(\n    g: &Grants,\n) -> NetworkPolicy {\n    unimplemented!()\n}\n",
        );
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("crates/mvm-core/src/lib.rs"));
        assert!(
            err.to_string()
                .contains("fn policy_for( g: &Grants, ) -> NetworkPolicy")
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_doc_comment_quoting_a_signature_is_not_flagged() {
        // A `///` line quoting the projection's own signature must not be
        // mistaken for a second definition.
        let tmp = fixture_with_offender(
            "doc-comment",
            "/// Calls `fn helper(grants: &Grants) -> NetworkPolicy` internally.\npub fn helper() {}\n",
        );
        run(&tmp).expect("a doc comment quoting a signature is not a second projection");
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
