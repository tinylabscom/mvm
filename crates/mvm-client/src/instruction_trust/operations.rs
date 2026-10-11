//! Host-local instruction trust operations. Private signing keys never leave
//! this module; callers receive only paths, public key identities and reports.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use secrecy::zeroize;
use serde::Serialize;

use super::gate::{
    PolicyLocations, ScanReport, default_trust_store, load_effective_policy, scan_roots,
};
use super::policy::{EffectivePolicy, Enforcement, PolicySummary};
use super::scan::{RootKind, ScanRoot, find_instruction_files};
use super::{sign as signatures, templates};

#[derive(Debug, Clone)]
pub struct InitRequest {
    pub project: Option<PathBuf>,
    pub enforcement: Enforcement,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InitOutcome {
    pub path: PathBuf,
    pub enforcement: Enforcement,
    pub project: bool,
}

#[derive(Debug, Clone)]
pub struct SignRequest {
    pub paths: Vec<PathBuf>,
    /// Raw 32-byte seed file; absent means the authoritative hostd host key.
    pub key: Option<PathBuf>,
    pub dry_run: bool,
    pub policy: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedFile {
    pub path: PathBuf,
    pub sidecar: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignOutcome {
    pub selected: Vec<PathBuf>,
    pub signed: Vec<SignedFile>,
    pub key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifyRequest {
    pub path: PathBuf,
    pub policy: Option<PathBuf>,
}

pub fn init(request: &InitRequest) -> Result<InitOutcome> {
    let (path, body) = match &request.project {
        Some(dir) => (
            mvm_core::config::project_instruction_trust_policy_path(dir),
            templates::project_policy(request.enforcement),
        ),
        None => {
            let signer = mvm_hostd::audit::host_keypair::load_or_init()
                .context("loading this host's signing key for the starter policy")?;
            (
                mvm_core::config::instruction_trust_policy_path(),
                templates::user_policy(
                    request.enforcement,
                    &hex::encode(signer.verifying.to_bytes()),
                ),
            )
        }
    };
    if path.exists() && !request.force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite it",
            path.display()
        );
    }
    let parent = path
        .parent()
        .context("a policy path always has a parent directory")?;
    if request.project.is_some() {
        std::fs::create_dir_all(parent)
    } else {
        mvm_core::config::create_private_dir(parent)
    }
    .with_context(|| format!("creating {}", parent.display()))?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    mvm_core::audit_emit!(
        TrustInstructionsInit,
        "path={},enforcement={}",
        path.display(),
        request.enforcement.as_str()
    );
    Ok(InitOutcome {
        path,
        enforcement: request.enforcement,
        project: request.project.is_some(),
    })
}

fn policy_for(root: &Path, user: Option<&Path>) -> Result<EffectivePolicy> {
    let locations = PolicyLocations {
        user: user.map(Path::to_path_buf),
        project_root: root.is_dir().then(|| root.to_path_buf()),
    };
    Ok(load_effective_policy(&locations, &default_trust_store()?)?)
}

fn files_to_sign(request: &SignRequest) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in &request.paths {
        if path.is_dir() {
            let policy = policy_for(path, request.policy.as_deref())?;
            let found = find_instruction_files(&ScanRoot::new(path, RootKind::Explicit), &policy)
                .with_context(|| format!("scanning {}", path.display()))?;
            files.extend(found.into_iter().map(|f| f.path));
        } else if path.is_file() {
            files.push(path.clone());
        } else {
            anyhow::bail!("{} is not a file or directory", path.display());
        }
    }
    Ok(files)
}

fn load_signing_key(path: Option<&Path>) -> Result<SigningKey> {
    let Some(path) = path else {
        return Ok(mvm_hostd::audit::host_keypair::load_or_init()
            .context("loading this host's signing key")?
            .signing);
    };
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(path).with_context(|| format!("reading key {}", path.display()))?,
    );
    let seed: zeroize::Zeroizing<[u8; 32]> =
        zeroize::Zeroizing::new(bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "key {} is {} bytes; expected a raw 32-byte Ed25519 secret key",
                path.display(),
                bytes.len()
            )
        })?);
    Ok(SigningKey::from_bytes(&seed))
}

pub fn sign(request: &SignRequest) -> Result<SignOutcome> {
    let selected = files_to_sign(request)?;
    let mut outcome = SignOutcome {
        selected,
        signed: Vec::new(),
        key_id: None,
    };
    if request.dry_run || outcome.selected.is_empty() {
        return Ok(outcome);
    }
    let key = load_signing_key(request.key.as_deref())?;
    let key_id = mvm_core::plan::bundle::key_id_from_pubkey(&key.verifying_key());
    for file in &outcome.selected {
        let sidecar = signatures::sign_file(file, &key)?;
        let sha256 = mvm_core::crypto::image_verify::sha256_file(file)
            .with_context(|| format!("hashing {}", file.display()))?;
        mvm_core::audit_emit!(
            TrustInstructionsSign,
            "path={},sha256={},key_id={}",
            file.display(),
            sha256,
            key_id.0
        );
        outcome.signed.push(SignedFile {
            path: file.clone(),
            sidecar,
        });
    }
    outcome.key_id = Some(key_id.0);
    Ok(outcome)
}

/// Return the full report, including refusals, so a caller can render it before
/// applying `ScanReport::decision`. Admission uses the same gate unchanged.
pub fn verify(request: &VerifyRequest) -> Result<ScanReport> {
    let policy = policy_for(&request.path, request.policy.as_deref())?;
    Ok(scan_roots(
        &[ScanRoot::new(&request.path, RootKind::Explicit)],
        &policy,
    )?)
}

pub fn policy(locations: &PolicyLocations) -> Result<PolicySummary> {
    Ok(load_effective_policy(locations, &default_trust_store()?)?.summary())
}

#[cfg(test)]
mod tests;
