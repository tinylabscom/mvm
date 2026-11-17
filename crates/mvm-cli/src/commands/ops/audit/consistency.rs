//! Signed-root append-only consistency commands.

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use mvm_client::audit::chain::emitter::default_audit_dir;
use mvm_contract::merkle::SignedAuditRoot;

use super::load_verifying_key;
use crate::ui;

pub(in crate::commands) fn prove_consistency(roots: &ConsistencyRoots) -> Result<()> {
    let (old, new, vk) = roots.load()?;
    let proof = prove_consistency_in(&default_audit_dir()?, &old, &new, &vk, &roots.tenant)?;
    println!("{}", serde_json::to_string_pretty(&proof)?);
    Ok(())
}

pub(in crate::commands) fn verify_consistency(args: &VerifyConsistencyArgs) -> Result<()> {
    ui::success(&verify_consistency_files(&args.proof, &args.roots)?);
    Ok(())
}

/// Offline consistency proof and the signed roots it binds.
#[derive(Debug, Clone, clap::Args)]
pub(in crate::commands) struct VerifyConsistencyArgs {
    /// Path to the consistency-proof JSON.
    #[arg(long)]
    proof: std::path::PathBuf,
    #[command(flatten)]
    roots: ConsistencyRoots,
}

/// Explicit saved and candidate roots with caller-controlled trust.
#[derive(Debug, Clone, clap::Args)]
pub(in crate::commands) struct ConsistencyRoots {
    /// Previously verified signed-root JSON retained independently of the host.
    #[arg(long)]
    old_root: std::path::PathBuf,
    /// Candidate signed-root JSON.
    #[arg(long)]
    new_root: std::path::PathBuf,
    /// Trusted public key file (raw, hex, or base64); defaults to host-signer.pub.
    /// The default must already exist; this command never initializes keys.
    #[arg(long)]
    pubkey: Option<std::path::PathBuf>,
    /// Tenant both signed roots must name.
    #[arg(long, default_value = "local")]
    tenant: String,
}

impl ConsistencyRoots {
    fn load(&self) -> Result<(SignedAuditRoot, SignedAuditRoot, VerifyingKey)> {
        let load = |path: &std::path::Path| -> Result<SignedAuditRoot> {
            serde_json::from_slice(
                &std::fs::read(path)
                    .with_context(|| format!("reading signed root {}", path.display()))?,
            )
            .with_context(|| format!("decoding signed root {}", path.display()))
        };
        let old = load(&self.old_root)?;
        let new = load(&self.new_root)?;
        let default_key = mvm_core::config::mvm_keys_dir().join("host-signer.pub");
        let vk = load_verifying_key(self.pubkey.as_deref().unwrap_or(&default_key))?;
        Ok((old, new, vk))
    }
}

fn verify_consistency_files(
    proof_path: &std::path::Path,
    roots: &ConsistencyRoots,
) -> Result<String> {
    let (old, new, vk) = roots.load()?;
    let proof: mvm_contract::merkle::ConsistencyProof = serde_json::from_slice(
        &std::fs::read(proof_path)
            .with_context(|| format!("reading consistency proof {}", proof_path.display()))?,
    )
    .context("decoding consistency-proof JSON")?;
    mvm_contract::merkle::verify_append_only(&proof, &old, &new, &vk, &roots.tenant)?;
    Ok(format!(
        "verified: signed-root append-only consistency ({} -> {} leaves); not a freshness or complete execution-history claim",
        old.tree_size, new.tree_size
    ))
}

fn prove_consistency_in(
    audit_dir: &std::path::Path,
    old: &SignedAuditRoot,
    new: &SignedAuditRoot,
    vk: &VerifyingKey,
    tenant: &str,
) -> Result<mvm_contract::merkle::ConsistencyProof> {
    // Authenticate before using untrusted sizes or reading the live chain.
    for root in [old, new] {
        mvm_contract::merkle::verify_signed_root(root, vk)?;
        anyhow::ensure!(root.tenant == tenant, "signed-root tenant mismatch");
    }
    let proof = mvm_client::audit::chain::merkle::build_consistency_in(
        audit_dir,
        tenant,
        vk,
        usize::try_from(old.tree_size).context("old tree size cannot be indexed")?,
        usize::try_from(new.tree_size).context("new tree size cannot be indexed")?,
    )?;
    mvm_contract::merkle::verify_append_only(&proof, old, new, vk, tenant)?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::super::merkle_verb_tests::{fresh_key, seed_leaves_with_key, sign_root};
    use super::*;

    #[test]
    fn consistency_generated_proof_verifies_offline_and_refuses_mutations() {
        let key = fresh_key();
        let (dir, leaves) = seed_leaves_with_key(&["a", "b", "c", "d"], key.clone());
        let old = sign_root(&key, "local", &leaves[..2]);
        let new = sign_root(&key, "local", &leaves);
        let proof = prove_consistency_in(
            &dir.path().join("audit"),
            &old,
            &new,
            &key.verifying_key(),
            "local",
        )
        .unwrap();
        let roots = ConsistencyRoots {
            old_root: dir.path().join("old.json"),
            new_root: dir.path().join("new.json"),
            pubkey: Some(dir.path().join("trusted.pub")),
            tenant: "local".into(),
        };
        let write_root = |path: &std::path::Path, root: &SignedAuditRoot| {
            std::fs::write(path, serde_json::to_vec(root).unwrap()).unwrap();
        };
        write_root(&roots.old_root, &old);
        write_root(&roots.new_root, &new);
        std::fs::write(
            roots.pubkey.as_ref().unwrap(),
            key.verifying_key().as_bytes(),
        )
        .unwrap();
        let proof_path = dir.path().join("proof.json");
        let original = serde_json::to_vec(&proof).unwrap();
        std::fs::write(&proof_path, &original).unwrap();
        // No live leaves or signing secret remain available to the verifier.
        std::fs::remove_dir_all(dir.path().join("audit")).unwrap();
        assert!(
            verify_consistency_files(&proof_path, &roots)
                .unwrap()
                .contains("2 -> 4")
        );
        let mut missing_key = roots.clone();
        let missing_path = dir.path().join("absent-keys").join("host-signer.pub");
        missing_key.pubkey = Some(missing_path.clone());
        assert!(verify_consistency_files(&proof_path, &missing_key).is_err());
        assert!(!missing_path.parent().unwrap().exists());
        let mut wrong_tenant = roots.clone();
        wrong_tenant.tenant = "elsewhere".into();
        assert!(verify_consistency_files(&proof_path, &wrong_tenant).is_err());
        std::fs::write(
            roots.pubkey.as_ref().unwrap(),
            fresh_key().verifying_key().as_bytes(),
        )
        .unwrap();
        assert!(verify_consistency_files(&proof_path, &roots).is_err());
        std::fs::write(
            roots.pubkey.as_ref().unwrap(),
            key.verifying_key().as_bytes(),
        )
        .unwrap();
        let mut altered = proof.clone();
        altered.new_size += 1;
        std::fs::write(&proof_path, serde_json::to_vec(&altered).unwrap()).unwrap();
        assert!(verify_consistency_files(&proof_path, &roots).is_err());
        std::fs::write(&proof_path, original).unwrap();
        let mut tampered = new.clone();
        tampered.timestamp.push('x');
        write_root(&roots.new_root, &tampered);
        assert!(verify_consistency_files(&proof_path, &roots).is_err());
        write_root(&roots.new_root, &old);
        write_root(&roots.old_root, &new);
        let mut shrink = proof;
        std::mem::swap(&mut shrink.old_size, &mut shrink.new_size);
        std::mem::swap(&mut shrink.old_root, &mut shrink.new_root);
        std::fs::write(&proof_path, serde_json::to_vec(&shrink).unwrap()).unwrap();
        assert!(verify_consistency_files(&proof_path, &roots).is_err());
        assert!(
            prove_consistency_in(
                &dir.path().join("missing"),
                &old,
                &tampered,
                &key.verifying_key(),
                "local",
            )
            .unwrap_err()
            .to_string()
            .contains("signature")
        );
    }
}
