//! `xtask check-pq-claims`
//!
//! The mission demo's presenter notes tell an audience that no post-quantum
//! cryptography is implemented. That sentence is true today and stops being true
//! the day someone adds an implementation, at which point the notes would be
//! telling a customer something false. This ties the two together: while the
//! notes carry the "not implemented" sentence, the lockfile must hold no
//! post-quantum implementation crate, and when a crate appears the build fails
//! until the notes are rewritten to match.
//!
//! The other direction is held too: dropping the sentence without an
//! implementation behind it is a claim someone should make on purpose.
//!
//! A crate in the lockfile is the signal because an implementation needs one:
//! ML-KEM and ML-DSA are not written by hand here. It is not a proof: a
//! vendored or renamed implementation passes unnoticed, which is why the notes
//! also say what is proposed, not just what is absent.

use anyhow::{Result, bail};
use std::path::Path;

/// The notes whose "not implemented" sentence this holds to the lockfile.
const NOTES: &str = "scripts/mission-demo-presenter-notes.md";

/// The sentence in the notes that says no post-quantum extension exists.
const NOT_IMPLEMENTED: &str = "These post-quantum extensions are not implemented today.";

/// Lockfile package names that implement ML-KEM, ML-DSA, SLH-DSA or the
/// pre-standard schemes they came from, by exact name or prefix. TLS stacks and
/// general crypto crates (aws-lc, ring, rustls) are deliberately absent: they
/// are not an implementation of this project's own signing or key exchange.
const EXACT: &[&str] = &[
    "ml-dsa",
    "ml-kem",
    "slh-dsa",
    "fips203",
    "fips204",
    "fips205",
    "kyber",
    "dilithium",
    "liboqs",
    "oqs",
    "oqs-sys",
    "pqc_kyber",
    "safe_pqc_kyber",
    "crystals-dilithium",
];
const PREFIXES: &[&str] = &["pqcrypto", "libcrux-ml-", "libcrux-kem", "pqc-", "oqs-"];

/// Names in `lock` that implement a post-quantum scheme.
fn post_quantum_packages(lock: &str) -> Vec<String> {
    let mut found: Vec<String> = lock
        .lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .filter(|name| EXACT.contains(name) || PREFIXES.iter().any(|p| name.starts_with(p)))
        .map(str::to_owned)
        .collect();
    found.sort();
    found.dedup();
    found
}

/// What the lockfile and the notes together say.
fn evaluate(lock: &str, notes: &str) -> Result<String> {
    let packages = post_quantum_packages(lock);
    let says_none = notes.contains(NOT_IMPLEMENTED);
    match (packages.is_empty(), says_none) {
        (true, true) => Ok("no post-quantum implementation crate in Cargo.lock, and the presenter notes say none is implemented".to_string()),
        (false, true) => bail!(
            "Cargo.lock now holds post-quantum crate(s) {packages:?}, but {NOTES} still says \"{NOT_IMPLEMENTED}\". Rewrite the notes to say what is implemented, what the demo shows and what is still proposed, then remove or change that sentence."
        ),
        (true, false) => bail!(
            "{NOTES} no longer says \"{NOT_IMPLEMENTED}\" but Cargo.lock holds no post-quantum implementation crate. Restore the sentence, or add the implementation the notes now describe."
        ),
        (false, false) => Ok(format!(
            "post-quantum crate(s) {packages:?} are in Cargo.lock and the presenter notes no longer claim none is implemented"
        )),
    }
}

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let lock = std::fs::read_to_string(workspace.join("Cargo.lock"))?;
    let notes = std::fs::read_to_string(workspace.join(NOTES))?;
    let verdict = evaluate(&lock, &notes)?;
    println!("check-pq-claims: {verdict}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(names: &[&str]) -> String {
        names
            .iter()
            .map(|n| format!("[[package]]\nname = \"{n}\"\nversion = \"1.0.0\"\n"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_tree_with_no_post_quantum_crate_and_notes_that_say_so_passes() {
        let notes = format!("text. {NOT_IMPLEMENTED} more.");
        assert!(evaluate(&lock(&["ring", "rustls", "ed25519-dalek"]), &notes).is_ok());
    }

    #[test]
    fn a_post_quantum_crate_makes_the_not_implemented_sentence_fail() {
        let notes = NOT_IMPLEMENTED;
        for name in [
            "ml-dsa",
            "ml-kem",
            "pqcrypto-dilithium",
            "libcrux-ml-kem",
            "oqs-sys",
        ] {
            let error = evaluate(&lock(&["ring", name]), notes)
                .unwrap_err()
                .to_string();
            assert!(error.contains(name), "{name}: {error}");
            assert!(error.contains("presenter-notes"), "{error}");
        }
    }

    #[test]
    fn dropping_the_sentence_without_an_implementation_fails() {
        assert!(evaluate(&lock(&["ring"]), "the notes were rewritten").is_err());
    }

    #[test]
    fn rewritten_notes_with_an_implementation_behind_them_pass() {
        assert!(evaluate(&lock(&["ml-dsa"]), "now implemented").is_ok());
    }

    #[test]
    fn general_crypto_and_tls_crates_are_not_post_quantum_implementations() {
        for name in [
            "aws-lc-rs",
            "aws-lc-sys",
            "ring",
            "rustls",
            "x25519-dalek",
            "kyber-unrelated-name",
        ] {
            // `kyber-unrelated-name` is not an exact or prefix match either.
            assert!(post_quantum_packages(&lock(&[name])).is_empty(), "{name}");
        }
    }

    #[test]
    fn the_real_workspace_holds_the_notes_to_the_lockfile() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        run(workspace).unwrap();
    }
}
