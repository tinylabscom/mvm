//! Recovery is possible only under the supervisor family lease and an
//! exclusive generation lease. Signed opening evidence is attribution, not
//! evidence that a still-running producer has stopped.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use mvm_core::transcript::evidence::{authenticate_opening, authenticated_seal};
use mvm_core::transcript::secure_cleanup::CaptureDirectory;
use mvm_core::transcript::{self, MANIFEST_FILENAME, TranscriptManifest};
use mvm_core::util::atomic_io::atomic_write;

use super::journal;
use super::protected_inventory::check_declared_segments;
use crate::audit::emitter::AuditEmitter;

/// Caller holds the family owner. The nonblocking capture lease is positive
/// quiescence evidence: every enrolled writer retains this lease until drop.
pub(super) fn recover(
    dir: &Path,
    capture: &CaptureDirectory,
    emitter: &AuditEmitter,
    tenant: &str,
    vm: &str,
) -> Result<TranscriptManifest> {
    let manifest_path = dir.join(MANIFEST_FILENAME);
    let existing = if manifest_path.try_exists()? {
        Some(capture.read_manifest()?)
    } else {
        None
    };
    if let Some(manifest) = &existing {
        ensure!(
            manifest.binding.tenant_id == tenant && manifest.binding.vm_name == vm,
            "protected recovery instance mismatch"
        );
        transcript::verify_sealed_root(manifest)?;
        if authenticated_seal(emitter.audit_dir(), &emitter.verifying_key(), manifest)?.is_some() {
            return Ok(manifest.clone());
        }
    }

    let seed: TranscriptManifest = serde_json::from_slice(&read_private(
        &dir.join(journal::SEED_FILENAME),
        1024 * 1024,
    )?)
    .context("invalid protected capture seed")?;
    ensure!(
        seed.binding.tenant_id == tenant && seed.binding.vm_name == vm,
        "protected recovery opening instance mismatch"
    );
    authenticate_opening(emitter.audit_dir(), &emitter.verifying_key(), &seed)?;
    let mut recovered = if let Some(manifest) = existing {
        // Preserve the already-staged terminal clock across every retry.
        ensure!(
            manifest.sealed_unix_secs.is_some(),
            "staged capture is not terminal"
        );
        manifest
    } else if dir.join(journal::JOURNAL_FILENAME).try_exists()? {
        // Validate bounded, private no-follow input before the legacy journal
        // parser. Neither an absent header nor malformed identity is a seed.
        read_private(&dir.join(journal::JOURNAL_FILENAME), 64 * 1024 * 1024)?;
        let replayed = journal::replay(dir).context("protected journal cannot be recovered")?;
        ensure!(
            replayed.seed == seed,
            "protected journal opening differs from signed seed"
        );
        replayed.manifest
    } else {
        seed.clone()
    };
    if recovered.sealed_unix_secs.is_none() {
        transcript::recover_abandoned_at(&mut recovered, transcript::retention_now()?)?;
    } else {
        recovered.adopted = true;
        recovered.sealed_root_hex = transcript::sealed_root_hex(&recovered)?;
    }
    // Reject unexpected ciphertext rather than sign or discard an unaccounted
    // append tail. This preserves the artifact for explicit offline recovery.
    check_declared_segments(dir, &recovered)?;
    capture.prepare_payload(&recovered, false)?;
    transcript::evidence::recovered_seal_entry(
        emitter.audit_dir(),
        &emitter.verifying_key(),
        &seed,
        &recovered,
    )?;
    stage(dir, &recovered)?;
    emitter.emit_recovered_transcript_sealed(&seed, &recovered)?;
    journal::CaptureJournal::discard(&dir.join(journal::JOURNAL_FILENAME));
    Ok(recovered)
}

/// Atomic file replacement plus directory sync precedes any signed seal.
pub(super) fn stage(dir: &Path, manifest: &TranscriptManifest) -> Result<()> {
    #[cfg(test)]
    stage_fault(StageFault::Write)?;
    atomic_write(
        &dir.join(MANIFEST_FILENAME),
        &serde_json::to_vec_pretty(manifest)?,
    )?;
    #[cfg(test)]
    stage_fault(StageFault::DirectorySync)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum StageFault {
    Write,
    DirectorySync,
}

#[cfg(test)]
thread_local! {
    static STAGE_FAULT: std::cell::Cell<Option<StageFault>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn stage_fault(boundary: StageFault) -> std::io::Result<()> {
    if STAGE_FAULT.with(|fault| {
        if fault.get() == Some(boundary) {
            fault.set(None);
            true
        } else {
            false
        }
    }) {
        Err(std::io::Error::other(
            "injected protected staging I/O failure",
        ))
    } else {
        Ok(())
    }
}

fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o077 == 0,
        "protected recovery metadata is not private"
    );
    ensure!(
        metadata.len() <= limit,
        "protected recovery metadata exceeds bound"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "protected recovery metadata exceeds bound"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::transcript_retirement::BudgetOwner;
    use mvm_core::transcript::{AtRestRetention, Direction, GenerationBudget};
    use mvm_core::{config, plan::test_support::PlanFixture, util::test_env::TestEnv};

    #[test]
    fn recovery_requires_quiescence_and_original_opening_without_current_plan() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let plan = PlanFixture::new().tenant("recovery-tenant").build();
        let vm = "recovery-instance";
        let root = config::vm_stream_transcript_dir(vm);
        config::create_private_dir(&root).unwrap();
        let emitter = AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&[31; 32]),
            &config::mvm_audit_dir(),
        )
        .unwrap();
        let _family =
            BudgetOwner::acquire(&root, &plan.tenant.0, vm, GenerationBudget::default()).unwrap();
        let relative = Path::new("generations/1-1/00000000000000000000");
        let dir = root.join(relative);
        let mut writer = super::super::plane::build_writer_with_policy(
            vm,
            &dir,
            Some(AtRestRetention::default()),
            &plan.tenant.0,
            &config::mvm_keys_dir(),
        )
        .unwrap();
        let seed = writer.sealed_manifest();
        super::super::protected::record_opening(&plan, &emitter, &seed).unwrap();
        assert!(
            CaptureDirectory::open(&root, relative).is_err(),
            "live writer must exclude recovery"
        );
        let mut journal = journal::CaptureJournal::new(&dir, seed.clone());
        writer
            .push(Direction::Stdout, b"recovered-private-marker")
            .unwrap();
        let snapshot = writer.sealed_manifest();
        journal.record(snapshot.chunks.last().unwrap(), Default::default());
        drop(journal);
        drop(writer);
        let tenant = plan.tenant.0.clone();
        drop(plan);
        let lease = CaptureDirectory::open(&root, relative).unwrap();
        assert!(recover(&dir, &lease, &emitter, &tenant, "wrong-instance").is_err());
        assert!(!dir.join(MANIFEST_FILENAME).exists());
        let recovered = recover(&dir, &lease, &emitter, &tenant, vm).unwrap();
        assert!(recovered.adopted);
        assert_eq!(recovered.chunks.len(), 1);
        assert_eq!(recovered.created_unix_secs, seed.created_unix_secs);
        let again = recover(&dir, &lease, &emitter, &tenant, vm).unwrap();
        assert_eq!(
            again, recovered,
            "retry must not reset the terminal clock or root"
        );
        assert!(
            !std::fs::read(dir.join(MANIFEST_FILENAME))
                .unwrap()
                .windows(b"recovered-private-marker".len())
                .any(|b| b == b"recovered-private-marker")
        );
    }

    #[test]
    fn staged_candidate_is_reused_and_unsigned_opening_refuses() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let plan = PlanFixture::new().tenant("staged-tenant").build();
        let vm = "staged-instance";
        let root = config::vm_stream_transcript_dir(vm);
        config::create_private_dir(&root).unwrap();
        let emitter = AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&[32; 32]),
            &config::mvm_audit_dir(),
        )
        .unwrap();
        let _family =
            BudgetOwner::acquire(&root, &plan.tenant.0, vm, GenerationBudget::default()).unwrap();
        let relative = Path::new("generations/2-1/00000000000000000000");
        let dir = root.join(relative);
        let writer = super::super::plane::build_writer_with_policy(
            vm,
            &dir,
            Some(AtRestRetention::default()),
            &plan.tenant.0,
            &config::mvm_keys_dir(),
        )
        .unwrap();
        let seed = writer.sealed_manifest();
        drop(writer);
        let lease = CaptureDirectory::open(&root, relative).unwrap();
        assert!(recover(&dir, &lease, &emitter, &plan.tenant.0, vm).is_err());
        assert!(!dir.join(MANIFEST_FILENAME).exists());
        super::super::protected::record_opening(&plan, &emitter, &seed).unwrap();
        let mut tampered = seed.clone();
        tampered.created_unix_secs += 1;
        tampered.sealed_root_hex = transcript::sealed_root_hex(&tampered).unwrap();
        atomic_write(
            &dir.join(journal::SEED_FILENAME),
            &serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap();
        assert!(recover(&dir, &lease, &emitter, &plan.tenant.0, vm).is_err());
        assert!(!dir.join(MANIFEST_FILENAME).exists());
        atomic_write(
            &dir.join(journal::SEED_FILENAME),
            &serde_json::to_vec(&seed).unwrap(),
        )
        .unwrap();
        STAGE_FAULT.with(|fault| fault.set(Some(StageFault::Write)));
        assert!(recover(&dir, &lease, &emitter, &plan.tenant.0, vm).is_err());
        assert!(!dir.join(MANIFEST_FILENAME).exists());
        let mut candidate = seed.clone();
        transcript::recover_abandoned_at(&mut candidate, seed.created_unix_secs).unwrap();
        assert!(
            authenticated_seal(emitter.audit_dir(), &emitter.verifying_key(), &candidate)
                .unwrap()
                .is_none()
        );
        STAGE_FAULT.with(|fault| fault.set(Some(StageFault::DirectorySync)));
        assert!(recover(&dir, &lease, &emitter, &plan.tenant.0, vm).is_err());
        let staged = capture_manifest(&dir);
        assert!(
            authenticated_seal(emitter.audit_dir(), &emitter.verifying_key(), &staged)
                .unwrap()
                .is_none(),
            "atomic rename without durable directory sync cannot publish a terminal seal"
        );
        let unavailable = home.path().join("unavailable-audit");
        std::fs::rename(emitter.audit_dir(), &unavailable).unwrap();
        assert!(
            recover(&dir, &lease, &emitter, &plan.tenant.0, vm).is_err(),
            "an unavailable original authority must not be replaced with a standalone signature"
        );
        assert_eq!(capture_manifest(&dir), staged);
        std::fs::rename(&unavailable, emitter.audit_dir()).unwrap();
        let recovered = recover(&dir, &lease, &emitter, &plan.tenant.0, vm).unwrap();
        assert_eq!(
            recovered, staged,
            "crash after staging must preserve exact candidate"
        );
        assert!(recovered.adopted);
        assert!(recovered.chunks.is_empty());
    }

    fn capture_manifest(dir: &Path) -> TranscriptManifest {
        serde_json::from_slice(&std::fs::read(dir.join(MANIFEST_FILENAME)).unwrap()).unwrap()
    }
}
