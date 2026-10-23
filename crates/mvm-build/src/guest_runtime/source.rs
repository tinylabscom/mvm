//! Checked, explicitly unsigned contributor runtime integrity.
//!
//! The local checkout, compiler and source cache are developer-trusted inputs.
//! These checks bind selected bytes to deterministic assembly of that cache;
//! they do not authenticate a release or prove compiled guest semantics. Private
//! snapshots do not defend against a malicious process running as the same UID.

use super::GuestRuntimeError;
use super::evidence::{
    RuntimeArtifactSelection, VerifiedRuntimeArtifacts, snapshot_declared_artifacts,
};
use crate::guest_bins::assembly::RuntimeAssembly;
use mvm_core::arch::GuestArch;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

/// Constructible only by the compiled-channel-gated source cache verifier.
#[derive(Debug)]
pub struct CheckedSourceRuntime {
    digest: String,
    declaration: RuntimeAssembly,
}

impl CheckedSourceRuntime {
    pub fn archive_sha256(&self) -> &str {
        &self.digest
    }

    pub fn declaration(&self, arch: GuestArch) -> Result<&RuntimeAssembly, GuestRuntimeError> {
        if arch != self.declaration.arch {
            return Err(GuestRuntimeError::Cache(
                "source runtime evidence architecture mismatch".into(),
            ));
        }
        Ok(&self.declaration)
    }

    pub fn snapshot_artifacts(
        &self,
        selection: &RuntimeArtifactSelection<'_>,
    ) -> Result<VerifiedRuntimeArtifacts, GuestRuntimeError> {
        snapshot_declared_artifacts(
            &self.digest,
            self.declaration(selection.arch)?,
            selection,
            None,
        )
    }

    pub fn snapshot_artifacts_in(
        &self,
        selection: &RuntimeArtifactSelection<'_>,
        private_parent: &Path,
    ) -> Result<VerifiedRuntimeArtifacts, GuestRuntimeError> {
        snapshot_declared_artifacts(
            &self.digest,
            self.declaration(selection.arch)?,
            selection,
            Some(private_parent),
        )
    }
}

// Process-local only: the assembly recipe and protocol constants cannot change
// during this process. Every lookup still validates the source cache first.
static DECLARATIONS: LazyLock<Mutex<BTreeMap<(String, GuestArch), RuntimeAssembly>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Never builds guest binaries, takes a caller channel, or falls back from a
/// failed release proof. Callers must dispatch an existing release proof to the
/// release verifier, even when this executable permits source builds.
#[tracing::instrument(skip_all)]
pub fn check_source_runtime(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<CheckedSourceRuntime, GuestRuntimeError> {
    if !crate::artifact_acquisition::compiled_channel().permits_automatic_builds() {
        return Err(GuestRuntimeError::Cache(
            "compiled release channel refuses unsigned source runtime evidence".into(),
        ));
    }
    let workspace = crate::image_source::guest_runtime_source_checkout().ok_or_else(|| {
        GuestRuntimeError::Cache("source runtime requires an available developer checkout".into())
    })?;
    let runtime = super::cached_source_guest_runtime(cache_root, version, arch, &workspace)?
        .ok_or_else(|| {
            GuestRuntimeError::Cache("no source runtime matching this checkout, version and architecture; prepare the contributor runtime first".into())
        })?;
    crate::guest_bins::assembly::verify_protocol_source(&workspace)?;
    let key = (runtime.digest.clone(), arch);
    let mut declarations = DECLARATIONS
        .lock()
        .map_err(|_| GuestRuntimeError::Cache("source declaration cache poisoned".into()))?;
    let declaration = if let Some(declaration) = declarations.get(&key) {
        declaration.clone()
    } else {
        // A fresh private assembly cache cannot adopt attacker-selected outputs.
        // Schema 1 has no declaration: derive it, never bless supplied hashes.
        // A declaration this host already derived and signed for this archive
        // and this build is read back instead; any doubt about it derives again.
        let declaration = match super::declaration_cache::load(cache_root, &runtime.digest, arch) {
            Some(declaration) => declaration,
            None => {
                let cache = tempfile::tempdir()?;
                let derived = crate::guest_bins::assembly::derive_runtime_assembly(
                    &runtime,
                    arch,
                    cache.path(),
                )?;
                super::declaration_cache::store(cache_root, &runtime.digest, arch, &derived);
                derived
            }
        };
        if let Some(claimed) = runtime.manifest.assemblies.get(&arch)
            && claimed != &declaration
        {
            return Err(GuestRuntimeError::Cache(
                "unsigned source assembly declaration differs from archive members".into(),
            ));
        }
        declarations.insert(key, declaration.clone());
        declaration
    };
    Ok(CheckedSourceRuntime {
        digest: runtime.digest,
        declaration,
    })
}
