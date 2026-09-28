//! What of the paired mvm checkout a locally built image is keyed on.
//!
//! By default, the whole checkout: its commit and working-tree state, so any
//! edit anywhere in the tree builds the image again. For a role whose image
//! reads a known, derived part of the mvm tree, the key names a digest of
//! exactly that part instead, and an edit elsewhere leaves it alone.
//!
//! The builder image is the one such role today. Its evaluation reads the Nix
//! sources in [`BUILDER_FLAKE_NIX_INPUTS`], compiles `mvm-setpriv` from source,
//! and, while the image checkout bakes them, installs host binaries compiled
//! from the `mvm-build` package. Those three are its consumed inputs.
//!
//! A narrow key is only as good as its agreement with what the image really
//! reads; one narrower than the reads serves a stale image. So the image
//! checkout's own builder source is scanned at key time for every place it
//! reads the mvm tree, and a read outside the known inputs — or no recognisable
//! read at all, which means the scan has stopped seeing them — falls back to
//! the whole-checkout identity. The fallback is always safe: it is the key
//! every role had before.

use std::fmt;
use std::path::Path;

use mvm_core::image_set::RepoIdentity;
use mvm_core::packs::Sha256Hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::key::{ImageBuildRole, ImageBuildTarget};
use crate::builder_image_inputs::BUILDER_FLAKE_NIX_INPUTS;
use crate::image_source::LocalImageCheckout;
use crate::image_source::build::contract_for;
use crate::source_closure::{SETPRIV_PACKAGE, fold_package_source_identity};
use crate::workspace_graph::{hash_file, hash_tree};

/// Domain tag for the consumed-input digest, so it can equal no other digest.
const CONSUMED_DOMAIN: &[u8] = b"mvm consumed inputs v1\n";

/// The package the image checkout's `scripts/build-host-binaries.sh` compiles
/// the builder's host binaries from.
const HOST_BINARY_PACKAGE: &str = "mvm-build";

/// Cargo configuration the host-binary build reads from the checkout, beside
/// the manifests: target flags and linker settings change the bytes.
const CARGO_CONFIG: &str = ".cargo/config.toml";

/// The names the image checkout's Nix gives the mvm source tree. A path read
/// through anything else is not recognised as an mvm read.
const MVM_SOURCE_NAMES: &[&str] = &["workspaceRoot", "mvm-src"];

/// What of the mvm checkout a key names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MvmSourceIdentity {
    /// The whole checkout, by commit and working-tree state.
    Checkout(RepoIdentity),
    /// A digest of exactly the mvm sources the target's image reads. The
    /// commit a set records is then provenance, not part of the key.
    ConsumedInputs(Sha256Hex),
}

impl fmt::Display for MvmSourceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Checkout(identity) => write!(f, "checkout {identity}"),
            Self::ConsumedInputs(digest) => {
                write!(f, "consumed inputs {}", &digest.as_str()[..16])
            }
        }
    }
}

/// The identity to key `target` on, given the mvm checkout at `mvm_root` whose
/// whole identity is `checkout`.
pub(super) fn mvm_source_identity(
    images: &LocalImageCheckout,
    mvm_root: &Path,
    target: &ImageBuildTarget,
    checkout: RepoIdentity,
) -> MvmSourceIdentity {
    match consumed_inputs(images.root(), mvm_root, target) {
        Ok(Some(digest)) => MvmSourceIdentity::ConsumedInputs(digest),
        Ok(None) => MvmSourceIdentity::Checkout(checkout),
        Err(reason) => {
            tracing::warn!(
                "keying {target} on the whole mvm checkout, not the sources it reads: {reason}"
            );
            MvmSourceIdentity::Checkout(checkout)
        }
    }
}

/// The digest of the mvm sources `target`'s image reads, `None` for a role
/// with no derived input set, or why the set could not be trusted.
fn consumed_inputs(
    images_root: &Path,
    mvm_root: &Path,
    target: &ImageBuildTarget,
) -> Result<Option<Sha256Hex>, String> {
    let ImageBuildRole::BuilderVm = target.role else {
        return Ok(None);
    };
    let Ok(contract) = contract_for(target) else {
        return Ok(None);
    };
    let image_source = images_root
        .join("images")
        .join(target.role.name())
        .join("image.nix");
    let text = std::fs::read_to_string(&image_source)
        .map_err(|e| format!("reading {}: {e}", image_source.display()))?;
    check_reads_are_listed(&mvm_source_reads(&text), BUILDER_FLAKE_NIX_INPUTS)
        .map_err(|reason| format!("{}: {reason}", image_source.display()))?;

    let mut hasher = Sha256::new();
    hasher.update(CONSUMED_DOMAIN);
    fold_nix_inputs(&mut hasher, mvm_root, BUILDER_FLAKE_NIX_INPUTS);
    fold_package_source_identity(&mut hasher, mvm_root, SETPRIV_PACKAGE)
        .map_err(|e| format!("{e:#}"))?;
    if contract.needs_host_binaries {
        fold_package_source_identity(&mut hasher, mvm_root, HOST_BINARY_PACKAGE)
            .map_err(|e| format!("{e:#}"))?;
        fold_listed(
            &mut hasher,
            CARGO_CONFIG,
            hash_file(&mvm_root.join(CARGO_CONFIG)),
        );
    }
    Ok(Some(Sha256Hex::from_bytes(&hasher.finalize())))
}

/// Every mvm-relative path `nix` reads through one of [`MVM_SOURCE_NAMES`]:
/// `name + "/path"` and `"${name}/path"`.
fn mvm_source_reads(nix: &str) -> Vec<String> {
    let mut reads = Vec::new();
    for name in MVM_SOURCE_NAMES {
        for form in [format!("{name} + \"/"), format!("${{{name}}}/")] {
            let mut rest = nix;
            while let Some(at) = rest.find(&form) {
                let after = &rest[at + form.len()..];
                let end = after
                    .find(|c: char| c == '"' || c == '$' || c.is_whitespace())
                    .unwrap_or(after.len());
                reads.push(after[..end].to_string());
                rest = &after[end..];
            }
        }
    }
    reads.sort();
    reads.dedup();
    reads
}

/// Refuse unless there is at least one read and every read is a listed input
/// or lies under one.
fn check_reads_are_listed(reads: &[String], listed: &[&str]) -> Result<(), String> {
    if reads.is_empty() {
        return Err(
            "no read of the mvm source was recognised, so the reads cannot be checked".to_string(),
        );
    }
    match reads.iter().find(|read| {
        !listed
            .iter()
            .any(|input| read.as_str() == *input || read.starts_with(&format!("{input}/")))
    }) {
        Some(unlisted) => Err(format!(
            "reads `{unlisted}` from the mvm source, which is not among the builder image's \
             listed inputs"
        )),
        None => Ok(()),
    }
}

/// Fold every listed input under `root`: each file of a directory, by path and
/// content hash, a file by its hash, and an absent input as absent.
fn fold_nix_inputs(hasher: &mut Sha256, root: &Path, inputs: &[&str]) {
    for input in inputs {
        let path = root.join(input);
        if path.is_dir() {
            for (file, sha) in hash_tree(root, &path) {
                fold_listed(hasher, &file, sha);
            }
        } else {
            fold_listed(hasher, input, hash_file(&path));
        }
    }
}

/// One `(path, sha)` pair, length-prefixed so no two lists fold alike. An
/// unreadable or absent file hashes to the empty string.
fn fold_listed(hasher: &mut Sha256, path: &str, sha: String) {
    for part in [path, sha.as_str()] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_read_forms_are_found_and_other_paths_are_not() {
        let nix = r#"
          workspace = import (workspaceRoot + "/nix/lib/workspace-filter.nix");
          mvm = (import (workspaceRoot + "/nix/flake.nix")).outputs { };
          script = "${mvm-src}/nix/packages/x.nix";
          bins = hostBinDir + "/${name}";
        "#;
        assert_eq!(
            mvm_source_reads(nix),
            vec![
                "nix/flake.nix".to_string(),
                "nix/lib/workspace-filter.nix".to_string(),
                "nix/packages/x.nix".to_string(),
            ]
        );
    }

    #[test]
    fn a_read_outside_the_listed_inputs_is_refused_by_name() {
        let reads = vec!["nix/flake.nix".to_string(), "crates/x/y.rs".to_string()];
        let err = check_reads_are_listed(&reads, BUILDER_FLAKE_NIX_INPUTS).unwrap_err();
        assert!(err.contains("crates/x/y.rs"), "{err}");
    }

    #[test]
    fn a_source_with_no_recognisable_read_is_refused() {
        let err = check_reads_are_listed(&[], BUILDER_FLAKE_NIX_INPUTS).unwrap_err();
        assert!(err.contains("no read"), "{err}");
    }

    #[test]
    fn a_listed_prefix_does_not_admit_a_sibling_with_the_same_stem() {
        let reads = vec!["nix/libextra/x.nix".to_string()];
        assert!(check_reads_are_listed(&reads, BUILDER_FLAKE_NIX_INPUTS).is_err());
    }

    /// The shipped tree resolves to a consumed-input digest, so a builder image
    /// built against it is keyed narrowly. A resolution failure would fall
    /// back to the whole checkout without failing anything, which is why this
    /// is asserted rather than left to be noticed.
    #[test]
    fn the_shipped_tree_resolves_to_a_consumed_input_digest() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root");
        let images = tempfile::tempdir().expect("tempdir");
        let source = images.path().join("images/builder-vm/image.nix");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(
            &source,
            r#"workspace = import (workspaceRoot + "/nix/lib/workspace-filter.nix");
               mvm = (import (workspaceRoot + "/nix/flake.nix")).outputs { };"#,
        )
        .unwrap();
        let target = ImageBuildTarget {
            role: ImageBuildRole::BuilderVm,
            attr: crate::image_source::FlakeAttr::new("default").unwrap(),
        };

        let digest = consumed_inputs(images.path(), &workspace, &target);

        assert!(matches!(digest, Ok(Some(_))), "{digest:?}");
    }

    /// The builder evaluation reaches the mvm tree through `nix/flake.nix`, so
    /// every path that file names relative to itself has to be a listed input
    /// too. The shipped flake is scanned, not a copy of it. `nix/profiles` is
    /// the one exception: it feeds only the flake's NixOS test configurations,
    /// which no image evaluation forces.
    #[test]
    fn every_path_the_shipped_nix_flake_names_is_a_listed_input() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root");
        let flake = std::fs::read_to_string(workspace.join("nix/flake.nix")).expect("read flake");
        let mut named = Vec::new();
        let mut rest = flake.as_str();
        while let Some(at) = rest.find("./") {
            let before = rest[..at].chars().last();
            let after = &rest[at + 2..];
            let end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/')))
                .unwrap_or(after.len());
            if before != Some('.') && end > 0 {
                named.push(format!("nix/{}", after[..end].trim_end_matches('/')));
            }
            rest = &after[end..];
        }
        assert!(!named.is_empty(), "the scan found nothing to check");
        let unlisted: Vec<&String> = named
            .iter()
            .filter(|path| {
                !path.starts_with("nix/profiles")
                    && check_reads_are_listed(std::slice::from_ref(path), BUILDER_FLAKE_NIX_INPUTS)
                        .is_err()
            })
            .collect();
        assert!(
            unlisted.is_empty(),
            "nix/flake.nix names paths the builder image key does not hash: {unlisted:?}"
        );
    }
}
