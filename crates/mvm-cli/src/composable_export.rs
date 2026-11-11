//! Production composition candidate export for a separately held publisher signer.
//!
//! This writes an unpublished archive. Its signature is not an official
//! publisher claim until the signed registry descriptor, fresh revocations,
//! and the exact-file health and installed boots have been independently checked.

use std::path::{Path, PathBuf};

use anyhow::Result;
use mvm_client::bundle::BundleSigner;

/// Freeze and seal a v8 production candidate without loading the local host signer.
///
/// The caller supplies a protected publisher signer. The destination must be new;
/// no archive is published to a registry by this function.
///
/// # Errors
///
/// Refuses missing production intent, changed inputs, invalid signatures, and
/// any destination that already exists or cannot be safely inspected.
pub fn build_candidate(
    spec: &Path,
    destination: &Path,
    signer: &dyn BundleSigner,
) -> Result<PathBuf> {
    crate::commands::vm::exec::composition::export_production(spec, destination, signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    struct RefusingSigner;

    impl BundleSigner for RefusingSigner {
        fn publisher_id(&self) -> String {
            panic!("invalid input must never contact the publisher signer")
        }

        fn verifying_key(&self) -> VerifyingKey {
            SigningKey::from_bytes(&[7; 32]).verifying_key()
        }

        fn sign(&self, _: &[u8]) -> Result<[u8; 64]> {
            anyhow::bail!("invalid input must never contact the publisher signer")
        }
    }

    #[test]
    fn production_intent_is_required_before_signing_or_creating_an_archive() {
        let project = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(project.path().join("home"));
        let recipe = project.path().join("pack.toml");
        let archive = project.path().join("candidate.mvmpkg");
        let arch = format!("{}-linux", mvm_core::arch::GuestArch::host());
        std::fs::write(
            &recipe,
            format!(
                "schema = \"mvm.pack-spec/v2\"\ntarget = \"{arch}\"\n\
                 runtimes = []\ncopy = []\nentrypoint = [\"/usr/bin/python3\"]\n\
                 [identity]\nname = \"agent/example\"\nversion = \"1.0.0\"\n\
                 [source]\nkind = \"local\"\npath = \".\"\n\
                 [resources]\ncpu_cores = 1\nmemory_mb = 256\n"
            ),
        )
        .unwrap();
        let error = build_candidate(&recipe, &archive, &RefusingSigner).unwrap_err();
        assert!(
            error.to_string().contains("explicit [production]"),
            "{error:#}"
        );
        assert!(!archive.exists());
        assert!(
            !project
                .path()
                .join("home/keys/host-signer.ed25519")
                .exists()
        );
        std::fs::write(
            &recipe,
            format!(
                "{}\n[production]\n",
                std::fs::read_to_string(&recipe).unwrap()
            ),
        )
        .unwrap();
        std::fs::write(&archive, b"existing archive").unwrap();
        let error = build_candidate(&recipe, &archive, &RefusingSigner).unwrap_err();
        assert!(
            error.to_string().contains("destination already exists"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(&archive).unwrap(), b"existing archive");
    }
}
