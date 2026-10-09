//! Bounded discovery of sealed managed generations. Legacy captures outside
//! this tree are never enrolled or removed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_core::transcript::secure_cleanup::CaptureDirectory;
use mvm_core::transcript::{GenerationBudget, TranscriptManifest, verify_sealed_root};

use crate::audit::emitter::AuditEmitter;
use crate::audit::transcript_retirement::{GenerationReservation, authenticated_retirement};

#[derive(Clone)]
pub(super) struct Generation {
    pub relative: PathBuf,
    pub manifest: TranscriptManifest,
    pub retired: bool,
    pub retry: bool,
}

pub(super) struct Inventory {
    pub generations: Vec<Generation>,
    pub usage: GenerationReservation,
}

impl Inventory {
    pub fn load(root: &Path, vm: &str, tenant: &str, emitter: &AuditEmitter) -> Result<Self> {
        let mut generations = Vec::new();
        let mut usage = GenerationReservation {
            plaintext_bytes: 0,
            chunks: 0,
        };
        let mut visited = 0usize;
        let family = root.join(mvm_core::stream_client::protected::GENERATIONS_DIRECTORY);
        for run in directories(&family)? {
            for generation in directories(&run)? {
                ensure!(
                    visited < 4096,
                    "managed generation inventory bound exceeded"
                );
                visited += 1;
                let relative = generation.strip_prefix(root)?.to_path_buf();
                let capture = CaptureDirectory::open(root, &relative)
                    .context("managed generation is active or untrusted")?;
                let manifest = capture
                    .read_manifest()
                    .context("managed generation needs recovery before admission")?;
                verify_sealed_root(&manifest)?;
                // Time policy alone does not enroll a legacy/forensic capture
                // into the independently authenticated workload-output budget.
                if manifest.generation_budget.is_none() {
                    continue;
                }
                ensure!(
                    manifest.binding.tenant_id == tenant
                        && manifest.binding.vm_name == vm
                        && manifest.generation_budget == Some(GenerationBudget::default()),
                    "managed generation identity or budget mismatch"
                );
                ensure!(
                    manifest.sealed_unix_secs.is_some(),
                    "managed generation is not terminal"
                );
                let retired = authenticated_retirement(
                    emitter.audit_dir(),
                    &emitter.verifying_key(),
                    &manifest,
                )?;
                capture.prepare_payload(&manifest, retired)?;
                check_declared_segments(&generation, &manifest)?;
                if manifest.chunks.is_empty() {
                    continue;
                }
                // A signed retirement whose unlink was interrupted still costs
                // capacity until cleanup finishes. Charge conservatively for
                // the entire generation while any declared segment remains.
                let payload_present = !retired
                    || manifest.chunks.iter().try_fold(
                        false,
                        |present, chunk| -> std::io::Result<bool> {
                            Ok(present || generation.join(&chunk.file).try_exists()?)
                        },
                    )?;
                if retired && !payload_present {
                    continue;
                }
                if payload_present {
                    usage.plaintext_bytes = usage
                        .plaintext_bytes
                        .checked_add(manifest.retained_plaintext_bytes()?)
                        .context("managed byte accounting overflow")?;
                    usage.chunks = usage
                        .chunks
                        .checked_add(manifest.chunks.len() as u64)
                        .context("managed chunk accounting overflow")?;
                }
                generations.push(Generation {
                    relative,
                    manifest,
                    retired,
                    retry: false,
                });
            }
        }
        generations.sort_by(|left, right| {
            (left.manifest.created_unix_secs, &left.manifest.capture_id)
                .cmp(&(right.manifest.created_unix_secs, &right.manifest.capture_id))
        });
        Ok(Self { generations, usage })
    }

    pub fn track(&mut self, relative: PathBuf, manifest: TranscriptManifest) -> Result<()> {
        if manifest.chunks.is_empty() {
            return Ok(());
        }
        self.usage.plaintext_bytes = self
            .usage
            .plaintext_bytes
            .checked_add(manifest.retained_plaintext_bytes()?)
            .context("managed byte overflow")?;
        self.usage.chunks = self
            .usage
            .chunks
            .checked_add(manifest.chunks.len() as u64)
            .context("managed chunk overflow")?;
        self.generations.push(Generation {
            relative,
            manifest,
            retired: false,
            retry: false,
        });
        self.generations.sort_by(|left, right| {
            (left.manifest.created_unix_secs, &left.manifest.capture_id)
                .cmp(&(right.manifest.created_unix_secs, &right.manifest.capture_id))
        });
        Ok(())
    }

    pub fn remove(&mut self, index: usize) -> Result<GenerationReservation> {
        let removed = self.generations.remove(index);
        let usage = GenerationReservation {
            plaintext_bytes: removed.manifest.retained_plaintext_bytes()?,
            chunks: removed.manifest.chunks.len() as u64,
        };
        self.usage.plaintext_bytes = self
            .usage
            .plaintext_bytes
            .checked_sub(usage.plaintext_bytes)
            .context("managed byte underflow")?;
        self.usage.chunks = self
            .usage
            .chunks
            .checked_sub(usage.chunks)
            .context("managed chunk underflow")?;
        Ok(usage)
    }
}

pub(super) fn check_declared_segments(dir: &Path, manifest: &TranscriptManifest) -> Result<()> {
    let declared: std::collections::BTreeSet<_> = manifest
        .chunks
        .iter()
        .map(|chunk| chunk.file.as_str())
        .collect();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".seg") {
            ensure!(
                name.to_str().is_some_and(|name| declared.contains(name)),
                "unaccounted ciphertext segment requires recovery"
            );
        }
    }
    Ok(())
}

fn directories(root: &Path) -> Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_dir(),
            "managed generation path is not a directory"
        );
        ensure!(
            paths.len() < 4096,
            "managed generation directory bound exceeded"
        );
        paths.push(entry.path());
    }
    paths.sort();
    Ok(paths)
}
