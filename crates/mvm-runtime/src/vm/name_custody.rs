//! A short-lived, per-name exclusive lock for launch and cleanup transitions.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::instance_snapshot::MachineLifecycleLock;
use super::name_registry::{VmNameRegistry, acquire_registry_lock, registry_path};
use crate::standby_pool::SupervisorStandbyPool;

/// Compatibility custody for older callers; shares the canonical machine lifecycle lock.
pub struct NameCustody {
    lifecycle: MachineLifecycleLock,
}

impl NameCustody {
    /// Serialize a transition using the canonical per-machine lifecycle lock.
    pub fn acquire(name: &str) -> Result<Self> {
        let lifecycle = MachineLifecycleLock::try_acquire(name)?
            .ok_or_else(|| anyhow::anyhow!("machine {name:?} is owned by another transition"))?;
        mvm_core::config::create_private_dir(
            PathBuf::from(mvm_core::config::mvm_share_dir()).join("launch-locks"),
        )?;
        Ok(Self { lifecycle })
    }

    /// The validated VM identity this lease excludes competing transitions for.
    #[must_use]
    pub fn name(&self) -> &str {
        self.lifecycle.name()
    }

    /// Refuse a warm reservation or an unregistered preloaded child before
    /// touching a name's runtime state. The registry lock covers only this
    /// inspection, never backend start or filesystem cleanup.
    pub fn require_cold_state(name: &str) -> Result<()> {
        let state = mvm_core::config::vm_state_dir(name);
        // Older preloads have no explicit marker; only their saved-runtime
        // evidence needs the slower pool-record lookup.
        let pooled_child = if occupied(&state.join("runtime-artifacts.json"))?
            && !occupied(&state.join("plan.json"))?
        {
            SupervisorStandbyPool::open()?
                .list()?
                .iter()
                .any(|handle| handle.preloaded_child_vm_name.as_deref() == Some(name))
        } else {
            false
        };
        let registry_path = registry_path();
        let _registry_lock = acquire_registry_lock(&registry_path)?;
        VmNameRegistry::load(&registry_path)?;
        if occupied(&stopped_path(name))?
            || occupied(&state.join(".warm-claim-reservation"))?
            || occupied(&state.join(".warm-claim-committed"))?
            || occupied(&state.join(crate::standby_pool::PRELOADED_CHILD_RESERVATION_FILE))?
            || pooled_child
        {
            bail!(
                "machine {name:?} has a warm claim or preloaded child; state is not owned by this cold launch"
            );
        }
        Ok(())
    }

    /// Recognize a completed warm child for explicit persistent lifecycle
    /// actions. A pending reservation or a mismatched plan is never ownership.
    /// Call only while holding this name's lease; cold boot still uses the
    /// stricter [`Self::require_cold_state`] rule.
    pub fn require_persistent_lifecycle(name: &str) -> Result<()> {
        anyhow::ensure!(
            !confirmed_stop_exists(name)?,
            "machine {name:?} has unfinished confirmed-stop cleanup"
        );
        if authenticated_warm_marker(name, ".warm-claim-committed")? {
            return Ok(());
        }
        Self::require_cold_state(name)
    }

    /// A pending claim may have crashed after starting a child but before
    /// publishing the committed marker. Permit only an explicit stop/recovery
    /// attempt under the name lease, never a readiness or cold-boot claim.
    pub fn require_stop_lifecycle(name: &str) -> Result<()> {
        if confirmed_stop_exists(name)? {
            return Ok(());
        }
        if authenticated_warm_marker(name, ".warm-claim-committed")?
            || authenticated_warm_marker(name, ".warm-claim-reservation")?
        {
            return Ok(());
        }
        Self::require_cold_state(name)
    }

    /// A pending marker alone permits a stop attempt, not deletion. A
    /// partially reaped child needs the independent confirmed-stop record.
    pub fn require_removal_lifecycle(name: &str) -> Result<()> {
        if confirmed_stop_exists(name)? {
            return Ok(());
        }
        Self::require_persistent_lifecycle(name)
    }

    /// Whether this name carries a completed warm claim rather than ordinary
    /// cold state. A caller must authenticate it with
    /// [`Self::require_persistent_lifecycle`] before using this answer to act.
    pub fn has_committed_warm(name: &str) -> Result<bool> {
        occupied(&mvm_core::config::vm_state_dir(name).join(".warm-claim-committed"))
    }

    /// An in-flight or interrupted warm child has not proved readiness.
    pub fn has_pending_warm(name: &str) -> Result<bool> {
        occupied(&mvm_core::config::vm_state_dir(name).join(".warm-claim-reservation"))
    }

    /// A previous transition already confirmed stop and retained durable
    /// cleanup authority; do not rediscover the backend from partially reaped
    /// runtime metadata. Call only while holding the name's lease.
    pub fn has_confirmed_stop(name: &str) -> Result<bool> {
        confirmed_stop_exists(name)
    }

    /// After a backend confirms stop under the name lease, transition an
    /// authenticated pending marker so ordinary persistent removal can finish.
    /// This never claims that an unverified child was ready.
    pub fn settle_pending_after_stop(name: &str) -> Result<()> {
        if confirmed_stop_exists(name)? {
            return Ok(());
        }
        if authenticated_warm_marker(name, ".warm-claim-reservation")? {
            let state = mvm_core::config::vm_state_dir(name);
            std::fs::rename(
                state.join(".warm-claim-reservation"),
                state.join(".warm-claim-committed"),
            )
            .with_context(|| format!("settling stopped warm child {name:?}"))?;
        }
        Ok(())
    }

    /// Persist recovery authority outside the directory about to be reaped.
    /// Only a confirmed backend stop under this name's lease may call this;
    /// a pending child must first prove its plan and registry ownership.
    pub fn mark_confirmed_stop(name: &str) -> Result<()> {
        if confirmed_stop_exists(name)? {
            return Ok(());
        }
        mvm_core::config::create_private_dir(
            PathBuf::from(mvm_core::config::mvm_share_dir()).join("launch-locks"),
        )?;
        for marker in [".warm-claim-committed", ".warm-claim-reservation"] {
            if authenticated_warm_marker(name, marker)? {
                let digest =
                    std::fs::read_to_string(mvm_core::config::vm_state_dir(name).join(marker))?;
                let path = stopped_path(name);
                mvm_core::atomic_io::write_private(&path, digest.as_bytes())
                    .with_context(|| format!("record confirmed stop of {name:?}"))?;
                return Ok(());
            }
        }
        Self::require_cold_state(name)
    }

    /// Clear recovery authority only after runtime state has been removed.
    pub fn clear_confirmed_stop(name: &str) -> Result<()> {
        anyhow::ensure!(
            !occupied(&mvm_core::config::vm_state_dir(name))?,
            "cannot clear confirmed stop while {name:?} retains runtime state"
        );
        let path = stopped_path(name);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("clear confirmed stop of {name:?}")),
        }
    }
}

fn stopped_path(name: &str) -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_share_dir())
        .join("launch-locks")
        .join(format!("{name}.stopped"))
}

fn confirmed_stop_exists(name: &str) -> Result<bool> {
    let path = stopped_path(name);
    match std::fs::read_to_string(&path) {
        Ok(digest) => {
            anyhow::ensure!(
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid confirmed-stop record for {name:?}"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn authenticated_warm_marker(name: &str, marker: &str) -> Result<bool> {
    let state = mvm_core::config::vm_state_dir(name);
    let path = state.join(marker);
    let digest = match std::fs::read_to_string(&path) {
        Ok(digest) => digest,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", path.display()));
        }
    };
    use sha2::Digest;
    let plan = std::fs::read(state.join("plan.json"))
        .with_context(|| format!("read warm plan of {name:?}"))?;
    anyhow::ensure!(
        digest == hex::encode(sha2::Sha256::digest(&plan)),
        "warm child {name:?} has a different signed plan"
    );
    let registry_path = registry_path();
    let _registry_lock = acquire_registry_lock(&registry_path)?;
    let registry = VmNameRegistry::load(&registry_path)?;
    anyhow::ensure!(
        registry
            .lookup(name)
            .is_some_and(|entry| Path::new(&entry.vm_dir) == state),
        "warm child {name:?} has no matching registry owner"
    );
    Ok(true)
}

fn occupied(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn cold_first_excludes_warm_until_release() {
        let _serial = crate::vm::DATA_DIR_TEST_LOCK.lock().expect("test env lock");
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let cold = NameCustody::acquire("child").expect("cold reserves name");
        assert!(
            NameCustody::acquire("child").is_err(),
            "warm cannot take cold's name"
        );
        drop(cold);
        NameCustody::acquire("child").expect("released name is reusable");
    }

    #[test]
    fn warm_and_preloaded_reservations_refuse_cold_cleanup() {
        let _serial = crate::vm::DATA_DIR_TEST_LOCK.lock().expect("test env lock");
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let state = mvm_core::config::vm_state_dir("child");
        std::fs::create_dir_all(&state).expect("state");
        let warm = NameCustody::acquire("child").expect("warm reserves name");
        std::fs::write(state.join(".warm-claim-reservation"), b"digest").expect("warm marker");
        assert!(
            NameCustody::acquire("child").is_err(),
            "cold cannot enter warm transition"
        );
        drop(warm);
        let _cold = NameCustody::acquire("child").expect("transition ended");
        assert!(
            NameCustody::require_cold_state("child").is_err(),
            "completed warm claim is still foreign to cold cleanup"
        );
        std::fs::remove_file(state.join(".warm-claim-reservation")).expect("remove warm marker");
        std::fs::write(state.join(".preloaded-child-reservation"), b"parent")
            .expect("preload marker");
        assert!(
            NameCustody::require_cold_state("child").is_err(),
            "preloaded child cannot be deleted by a cold launch"
        );
    }

    #[test]
    fn unowned_stale_state_is_reusable() {
        let _serial = crate::vm::DATA_DIR_TEST_LOCK.lock().expect("test env lock");
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let state = mvm_core::config::vm_state_dir("stale");
        std::fs::create_dir_all(&state).expect("state");
        std::fs::write(state.join("plan.json"), b"old plan").expect("old plan");
        std::fs::write(state.join("runtime-artifacts.json"), b"old runtime").expect("old runtime");
        let _cold = NameCustody::acquire("stale").expect("name");
        NameCustody::require_cold_state("stale").expect("old cold state is recoverable");
        std::fs::remove_file(state.join("plan.json")).expect("remove old plan");
        NameCustody::require_cold_state("stale")
            .expect("unclaimed runtime metadata alone does not own the name");
    }

    #[test]
    fn committed_warm_child_is_lifecycle_owned_but_not_cold_bootable() {
        use sha2::Digest;

        let _serial = crate::vm::DATA_DIR_TEST_LOCK.lock().expect("test env lock");
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let name = "persisted-warm-child";
        let custody = MachineLifecycleLock::acquire(name).expect("hold child's lifecycle");
        let state = mvm_core::config::vm_state_dir(name);
        std::fs::create_dir_all(&state).expect("state");
        std::fs::write(state.join("plan.json"), b"signed plan").expect("plan");
        let digest = hex::encode(sha2::Sha256::digest(b"signed plan"));
        std::fs::write(state.join(".warm-claim-committed"), digest).expect("commit marker");
        assert!(
            custody.require_persistent_lifecycle().is_err(),
            "a matching plan and marker without a registry owner cannot authorize lifecycle"
        );
        assert!(
            custody.require_cold_state().is_err(),
            "an unregistered committed marker still reserves its name against cold boot"
        );
        let mut registry = VmNameRegistry::default();
        let vm_dir = state.to_string_lossy();
        registry
            .register(super::super::name_registry::RegisterParams::minimal(
                name, &vm_dir, "default",
            ))
            .expect("registered child");
        registry.save(&registry_path()).expect("save registry");

        assert!(custody.require_cold_state().is_err());
        custody
            .require_persistent_lifecycle()
            .expect("same registered child");
        std::fs::write(state.join("plan.json"), b"another plan").expect("tamper plan");
        assert!(custody.require_persistent_lifecycle().is_err());
        std::fs::write(state.join("plan.json"), b"signed plan").expect("restore plan");
        std::fs::rename(
            state.join(".warm-claim-committed"),
            state.join(".warm-claim-reservation"),
        )
        .expect("model crash before publication");
        assert!(custody.require_persistent_lifecycle().is_err());
        custody
            .require_stop_lifecycle()
            .expect("authenticated pending child may be stopped, not declared ready");
        assert!(
            custody.require_removal_lifecycle().is_err(),
            "a pending marker is not confirmation that deletion is safe"
        );
        custody
            .settle_pending_after_stop()
            .expect("caller confirmed stop before settling marker");
        custody
            .require_persistent_lifecycle()
            .expect("settled marker permits cleanup after stop");
        custody.mark_confirmed_stop().expect("persist stop proof");
        assert!(custody.has_confirmed_stop().expect("read stop proof"));
        assert!(
            custody.clear_confirmed_stop().is_err(),
            "retained state must keep confirmed-stop recovery authority"
        );
        std::fs::remove_dir_all(&state).expect("reap confirmed stopped child");
        custody
            .clear_confirmed_stop()
            .expect("clear stop after reaping");
        assert!(!custody.has_confirmed_stop().expect("stop proof cleared"));
    }
}
