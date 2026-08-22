//! `xtask check-single-grants-projection`
//!
//! Egress policy must be derivable from grants in exactly one place. A second
//! derivation is a second policy decision point, and two decision points can
//! disagree — at which point the enforced policy is whichever one the
//! enforcement path happened to read. This is the same discipline
//! `check-single-network-path` applies to the endpoint and egress gate.
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
//! Comments *and string literals* are blanked first, by the shared
//! [`crate::rust_source`] scanner, so neither prose quoting a signature nor a
//! signature embedded in a `"…"` (a test fixture, an error message, a codegen
//! template) is mistaken for a declaration.
//!
//! A trailing `where` clause is moved back onto the parameter side before the
//! signature is split on its return arrow. rustfmt routinely relocates bounds
//! there, and `fn f<T>(t: T) -> NetworkPolicy where T: Into<Grants>` puts the
//! `Grants` to the *right* of the last `->` — a real second projection that a
//! naive split waves through. Re-attaching rather than discarding is what
//! makes it catchable: a bound is part of what the function takes, so
//! dropping the clause would hide the same signature for the opposite reason.

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
            for signature in fn_signatures(&crate::rust_source::blank_comments_and_strings(body)) {
                let Some(Split { inputs, ret }) = split_at_return_arrow(&signature) else {
                    continue;
                };
                if inputs.contains("Grants") && ret.contains("NetworkPolicy") {
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

/// A signature cut into what it takes and what it returns.
struct Split<'a> {
    /// Everything the function accepts: its parameter list *and* its `where`
    /// clause, which is where a bound-spelled parameter type lives.
    inputs: String,
    /// The return type alone.
    ret: &'a str,
}

/// Cut a flattened signature at its return arrow.
///
/// Two things make this more than a `rsplit_once("->")`.
///
/// The arrow is matched at its *last* occurrence, not its first: a parameter
/// of type `impl Fn() -> T` carries its own `->` ahead of the real one.
///
/// And the `where` clause is moved back onto the input side rather than left
/// where it sits. A bound is part of what a function accepts, but it is
/// written after the return type, so `fn f<T>(t: T) -> NetworkPolicy where T:
/// Into<Grants>` puts its `Grants` to the right of the last arrow. Dropping
/// the clause instead of re-attaching it would be just as wrong in the other
/// direction — the mention would vanish and the projection would go unseen.
fn split_at_return_arrow(signature: &str) -> Option<Split<'_>> {
    let (head, where_clause) = match where_clause_start(signature) {
        Some(i) => (&signature[..i], &signature[i..]),
        None => (signature, ""),
    };
    let (params, ret) = head.rsplit_once("->")?;
    Some(Split {
        inputs: format!("{params} {where_clause}"),
        ret,
    })
}

/// The byte offset of a signature's trailing `where` clause, if it has one.
///
/// The keyword is only recognised as a whole word at bracket depth zero, so
/// an identifier that merely contains the letters (`somewhere`) never splits
/// a signature in the wrong place.
fn where_clause_start(signature: &str) -> Option<usize> {
    let bytes = signature.as_bytes();
    let mut depth = 0i32;
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'w' if depth == 0 && is_where_keyword_at(signature, i) => return Some(i),
            _ => {}
        }
    }
    None
}

/// Whether the `where` keyword starts at byte `i`, bounded by non-identifier
/// bytes on both sides.
fn is_where_keyword_at(signature: &str, i: usize) -> bool {
    if !signature[i..].starts_with("where") {
        return false;
    }
    let bytes = signature.as_bytes();
    let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
    let after_ok = bytes
        .get(i + "where".len())
        .is_none_or(|b| !is_ident_byte(*b));
    before_ok && after_ok
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
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

    #[test]
    fn a_where_clause_after_the_return_type_is_still_caught() {
        // rustfmt puts bounds after the return type, which moves `Grants` to
        // the right of the last `->`. Splitting the raw signature there reads
        // this as "returns NetworkPolicy, takes no Grants" and passes it.
        let tmp = fixture_with_offender(
            "where-clause",
            "pub fn policy_for<T>(t: T) -> NetworkPolicy\nwhere\n    T: Into<Grants>,\n{\n    unimplemented!()\n}\n",
        );
        let err = run(&tmp).unwrap_err();
        assert!(
            err.to_string().contains("crates/mvm-core/src/lib.rs"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_where_clause_on_one_line_is_still_caught() {
        let tmp = fixture_with_offender(
            "where-clause-inline",
            "pub fn policy_for<T>(t: T) -> NetworkPolicy where T: Into<Grants> { unimplemented!() }",
        );
        let err = run(&tmp).unwrap_err();
        assert!(
            err.to_string().contains("crates/mvm-core/src/lib.rs"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn an_identifier_containing_where_does_not_truncate_a_signature() {
        // `somewhere` must not be read as the `where` keyword: truncating
        // there would drop the return type and silently stop flagging.
        let tmp = fixture_with_offender(
            "somewhere-param",
            "pub fn policy_for(somewhere: &Grants) -> NetworkPolicy { unimplemented!() }",
        );
        let err = run(&tmp).unwrap_err();
        assert!(
            err.to_string().contains("crates/mvm-core/src/lib.rs"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_signature_inside_a_string_literal_is_not_flagged() {
        // A fixture, an error message, or a codegen template quoting the
        // projection's signature is not a second projection.
        let tmp = fixture_with_offender(
            "string-literal",
            "pub const FIXTURE: &str = \"pub fn policy_for(g: &Grants) -> NetworkPolicy { todo!() }\";\n",
        );
        run(&tmp).expect("a signature inside a string literal is not a second projection");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_signature_inside_a_raw_string_literal_is_not_flagged() {
        let tmp = fixture_with_offender(
            "raw-string-literal",
            "pub const FIXTURE: &str = r#\"fn policy_for(g: &Grants) -> NetworkPolicy {}\"#;\n",
        );
        run(&tmp).expect("a signature inside a raw string literal is not a second projection");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_signature_inside_a_block_comment_is_not_flagged() {
        let tmp = fixture_with_offender(
            "block-comment",
            "/* fn policy_for(g: &Grants) -> NetworkPolicy {} */\npub fn helper() {}\n",
        );
        run(&tmp).expect("a signature inside a block comment is not a second projection");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_lifetime_before_a_real_offender_does_not_hide_it() {
        // A `'a` misread as an unterminated char literal would blank the rest
        // of the file, and every offender after it would vanish.
        let tmp = fixture_with_offender(
            "lifetime-then-offender",
            "pub fn first<'a>(s: &'a str) -> &'a str { s }\npub fn second(g: &Grants) -> NetworkPolicy { unimplemented!() }\n",
        );
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("fn second"), "{err}");
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
