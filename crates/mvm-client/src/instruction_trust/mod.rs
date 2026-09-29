//! Provenance for agent instruction files.
//!
//! An agent treats `CLAUDE.md`, `AGENTS.md`, a `SKILL.md` or a rules file as
//! instructions, which makes a poisoned one a prompt-injection vector with no
//! code in it at all. This module decides, before a workload boots, whether
//! the instruction files that are about to be copied into the guest were
//! signed by a publisher the operator trusts.
//!
//! The pieces:
//!
//! - [`policy`] — the TOML trust policy (which files count, which publishers
//!   are trusted, a digest blocklist, and `deny`/`warn`/`audit` enforcement),
//!   and the merge that lets a project policy tighten the user's policy but
//!   never loosen it.
//! - [`scan`] — finding the instruction files under a set of roots.
//! - [`verify`] — the per-file verdict: verified, unsigned, or refused for a
//!   named reason.
//! - [`sign`] — writing a keyed signature beside a file.
//! - [`gate`] — the admission gate: which roots a boot copies into the guest,
//!   and what each enforcement mode does with the verdicts.
//!
//! Signatures live **beside** each file rather than in one bundle per
//! directory. A keyless signature is a standard Sigstore bundle at
//! `<file>.sigstore.json` (exactly what `cosign sign-blob --new-bundle-format
//! --bundle` writes), and a keyed one is an Ed25519 envelope at
//! `<file>.mvmsig.json`. Per-file sidecars travel with the file when it is
//! copied, moved, or mounted on its own; editing one file invalidates only its
//! own signature; and the verifier checks exactly the bytes an agent reads,
//! with no manifest in between whose coverage could drift from the directory.

pub mod gate;
mod identity;
pub mod policy;
pub mod scan;
pub mod sign;
pub mod templates;
pub mod verify;

/// Suffix of a keyless Sigstore bundle written beside an instruction file.
pub const KEYLESS_SIDECAR_SUFFIX: &str = ".sigstore.json";

/// Suffix of a keyed Ed25519 signature envelope written beside a file.
pub const KEYED_SIDECAR_SUFFIX: &str = ".mvmsig.json";

/// The sidecar path for `file` with `suffix` appended to its full name.
pub(crate) fn sidecar_path(file: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut name = file.as_os_str().to_os_string();
    name.push(suffix);
    std::path::PathBuf::from(name)
}

/// Whether `name` is a signature sidecar rather than an instruction file.
///
/// A rules directory is matched with a `**` glob, which would otherwise
/// sweep up the signatures beside the files it holds and demand a signature
/// for the signature.
pub(crate) fn is_sidecar_name(name: &str) -> bool {
    name.ends_with(KEYLESS_SIDECAR_SUFFIX) || name.ends_with(KEYED_SIDECAR_SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sidecar_is_named_after_the_whole_file_name() {
        let file = std::path::Path::new("/w/.claude/commands/review.md");
        assert_eq!(
            sidecar_path(file, KEYLESS_SIDECAR_SUFFIX),
            std::path::Path::new("/w/.claude/commands/review.md.sigstore.json")
        );
        assert_eq!(
            sidecar_path(file, KEYED_SIDECAR_SUFFIX),
            std::path::Path::new("/w/.claude/commands/review.md.mvmsig.json")
        );
    }

    #[test]
    fn sidecars_are_recognised_and_instruction_files_are_not() {
        assert!(is_sidecar_name("CLAUDE.md.sigstore.json"));
        assert!(is_sidecar_name("style.mdc.mvmsig.json"));
        assert!(!is_sidecar_name("CLAUDE.md"));
        assert!(!is_sidecar_name("sigstore.json.md"));
    }
}
