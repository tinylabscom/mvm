//! Validation state for optional extension executables mounted at activation.

use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use crate::entrypoint::{CancellationToken, EntrypointPolicy, ValidatedEntrypoint};
use crate::vsock::{ExtensionCancellation, ExtensionConfig};

/// A fixed executable whose artifact and identity were admitted by the host.
#[derive(Debug)]
pub struct ValidatedExtension {
    pub config: ExtensionConfig,
    pub entrypoint: ValidatedEntrypoint,
    pub call_lock: Mutex<()>,
    pub cancellation: ExtensionCancellationState,
}

/// Identity-bound cancellation state for one extension's concurrency slot.
#[derive(Debug, Default)]
pub struct ExtensionCancellationState {
    inner: Mutex<ExtensionCallState>,
    finished: Condvar,
}

#[derive(Debug, Default)]
struct ExtensionCallState {
    active: Option<ActiveExtensionCall>,
    pending: Option<ExtensionCancellation>,
    last_completed: Option<ExtensionCancellation>,
    last_canceled: Option<ExtensionCancellation>,
}

#[derive(Debug)]
struct ActiveExtensionCall {
    identity: ExtensionCancellation,
    token: CancellationToken,
}

/// RAII registration for one cancellable extension call.
pub struct ActiveExtensionCallGuard<'a> {
    state: &'a ExtensionCancellationState,
    token: CancellationToken,
}

impl ActiveExtensionCallGuard<'_> {
    /// Token polled by the child-process pump.
    #[must_use]
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

impl Drop for ActiveExtensionCallGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.inner.lock()
            && let Some(active) = state.active.take()
        {
            state.last_completed = Some(active.identity.clone());
            if active.token.is_requested() {
                state.last_canceled = Some(active.identity);
            }
        }
        self.state.finished.notify_all();
    }
}

impl ExtensionCancellationState {
    /// Register the exact identity before any child process is created.
    pub fn begin(
        &self,
        identity: ExtensionCancellation,
    ) -> Result<ActiveExtensionCallGuard<'_>, String> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| "extension cancellation state is unavailable".to_string())?;
        if state.active.is_some() {
            return Err("an extension call is already active".to_string());
        }
        let token = CancellationToken::default();
        if state.pending.as_ref() == Some(&identity) {
            token.request();
            state.pending = None;
        } else if state.pending.is_some() {
            return Err("pending extension cancellation identity mismatch".to_string());
        }
        state.last_canceled = None;
        state.last_completed = None;
        state.active = Some(ActiveExtensionCall {
            identity,
            token: token.clone(),
        });
        Ok(ActiveExtensionCallGuard { state: self, token })
    }

    /// Request cancellation only when every admitted identity matches.
    pub fn request(&self, identity: &ExtensionCancellation) -> Result<(), String> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| "extension cancellation state is unavailable".to_string())?;
        if let Some(active) = state.active.as_ref()
            && &active.identity == identity
        {
            active.token.request();
            return Ok(());
        }
        if state.last_canceled.as_ref() == Some(identity) {
            return Ok(());
        }
        if state.active.is_none() {
            if state.last_completed.is_some() {
                return Err("extension cancellation did not match an active call".to_string());
            }
            match state.pending.as_ref() {
                Some(pending) if pending != identity => {
                    return Err("extension cancellation identity mismatch".to_string());
                }
                Some(_) => return Ok(()),
                None => {
                    state.pending = Some(identity.clone());
                    return Ok(());
                }
            }
        }
        Err("extension cancellation did not match an active call".to_string())
    }

    /// Request cancellation and wait until an active child has actually
    /// stopped. A request that wins the race before dispatch is remembered so
    /// the matching call is canceled before child creation.
    pub fn request_and_wait(
        &self,
        identity: &ExtensionCancellation,
        timeout: Duration,
    ) -> Result<(), String> {
        self.request(identity)?;
        let state = self
            .inner
            .lock()
            .map_err(|_| "extension cancellation state is unavailable".to_string())?;
        if state.pending.as_ref() == Some(identity)
            || state.last_canceled.as_ref() == Some(identity)
        {
            return Ok(());
        }
        let (state, wait) = self
            .finished
            .wait_timeout_while(state, timeout, |state| {
                state
                    .active
                    .as_ref()
                    .is_some_and(|active| &active.identity == identity)
            })
            .map_err(|_| "extension cancellation state is unavailable".to_string())?;
        if state.last_canceled.as_ref() == Some(identity) {
            return Ok(());
        }
        if wait.timed_out() {
            return Err("extension call did not stop within the cancellation deadline".to_string());
        }
        Err("extension cancellation did not match the completed call".to_string())
    }
}

/// Validate every mounted extension once, holding its executable inode open.
pub fn validate_extensions(
    configs: &[ExtensionConfig],
    marker_root: &Path,
) -> Result<Vec<ValidatedExtension>, String> {
    std::fs::create_dir_all(marker_root)
        .map_err(|error| format!("create extension marker directory: {error}"))?;
    configs
        .iter()
        .map(|config| validate_extension(config, marker_root))
        .collect()
}

fn validate_extension(
    config: &ExtensionConfig,
    marker_root: &Path,
) -> Result<ValidatedExtension, String> {
    config
        .binding
        .validate()
        .map_err(|error| format!("invalid extension binding: {error}"))?;
    let digest: String = config
        .binding
        .pack_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let expected_mountpoint = PathBuf::from(format!("/run/mvm/extensions/{digest}"));
    let mountpoint = PathBuf::from(&config.mountpoint);
    if mountpoint != expected_mountpoint || config.device.is_empty() {
        return Err("extension activation identity does not match its mount".to_string());
    }
    let entrypoint = mountpoint.join(&config.binding.entrypoint);
    let marker = marker_root.join(&digest);
    std::fs::write(&marker, format!("{}\n", entrypoint.display()))
        .map_err(|error| format!("write extension marker: {error}"))?;
    let validated = EntrypointPolicy {
        marker_path: marker,
        allowed_prefix: mountpoint.clone(),
        same_fs_as: Some(mountpoint),
        required_mode: 0o555,
        required_uid: 0,
        required_gid: 0,
        allow_shell_shebang: false,
    }
    .validate()
    .map_err(|error| format!("validate extension entrypoint: {error}"))?;
    Ok(ValidatedExtension {
        config: config.clone(),
        entrypoint: validated,
        call_lock: Mutex::new(()),
        cancellation: ExtensionCancellationState::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::assurance::AssuranceId;
    use mvm_contract::protocol::extension_pack::{
        ExtensionBudgets, ExtensionId, ExtensionPlacement, ExtensionPlanBinding, ExtensionVersion,
    };

    fn config(mountpoint: &str) -> ExtensionConfig {
        ExtensionConfig {
            binding: ExtensionPlanBinding {
                extension_id: ExtensionId::parse("org.example.extension").expect("id"),
                version: ExtensionVersion::parse("1.0.0").expect("version"),
                pack_digest: [1; 32],
                contract_digest: [2; 32],
                placement: ExtensionPlacement::GuestWorkload,
                artifact: "extension.ext4".to_string(),
                entrypoint: "bin/extension".to_string(),
                capabilities: Vec::new(),
                budgets: ExtensionBudgets {
                    cpu_millis: 100,
                    memory_bytes: 1024,
                    duration_ms: 1000,
                    max_steps: 1,
                    max_concurrency: 1,
                    max_payload_bytes: 1024,
                    max_output_bytes: 1024,
                    max_artifact_bytes: 1024,
                },
            },
            plan_id: AssuranceId::parse(format!("sha256-{}", "a".repeat(64))).expect("plan id"),
            mountpoint: mountpoint.to_string(),
            device: "/dev/vde".to_string(),
        }
    }

    #[test]
    fn a_mountpoint_not_derived_from_the_pack_digest_is_refused() {
        let marker = tempfile::tempdir().expect("marker directory");
        let error = validate_extensions(&[config("/tmp/attacker")], marker.path())
            .expect_err("foreign mountpoint must fail");
        assert!(error.contains("identity does not match"), "{error}");
    }

    fn cancellation() -> ExtensionCancellation {
        let config = config(
            "/run/mvm/extensions/0101010101010101010101010101010101010101010101010101010101010101",
        );
        ExtensionCancellation {
            extension_id: config.binding.extension_id,
            pack_digest: config.binding.pack_digest,
            contract_digest: config.binding.contract_digest,
            request_id: AssuranceId::parse("request-1").expect("request"),
            session_id: AssuranceId::parse("session-1").expect("session"),
            campaign_id: AssuranceId::parse("campaign-1").expect("campaign"),
            trial_id: AssuranceId::parse("trial-1").expect("trial"),
            plan_id: config.plan_id,
            idempotency_key: AssuranceId::parse("trial-1").expect("key"),
            grant_digest: mvm_contract::assurance::Sha256Digest::parse(format!(
                "sha256:{}",
                "a".repeat(64)
            ))
            .expect("grant digest"),
            nonce: AssuranceId::parse("nonce-1").expect("nonce"),
        }
    }

    #[test]
    fn cancellation_requires_the_exact_active_identity_and_is_idempotent() {
        let state = ExtensionCancellationState::default();
        let identity = cancellation();
        let guard = state.begin(identity.clone()).expect("register call");
        let mut foreign = identity.clone();
        foreign.trial_id = AssuranceId::parse("trial-2").expect("foreign trial");

        assert!(state.request(&foreign).is_err());
        assert!(!guard.token().is_requested());
        state.request(&identity).expect("cancel");
        state.request(&identity).expect("repeat cancel");
        assert!(guard.token().is_requested());
        drop(guard);
        state
            .request(&identity)
            .expect("retry after completion remains idempotent");
        assert!(state.request(&foreign).is_err());
    }

    #[test]
    fn cancellation_before_dispatch_prevents_child_creation() {
        let state = ExtensionCancellationState::default();
        let identity = cancellation();
        state.request(&identity).expect("queue cancellation");
        state
            .request(&identity)
            .expect("repeat queued cancellation");
        let guard = state.begin(identity.clone()).expect("register call");
        assert!(guard.token().is_requested());
        drop(guard);
        state
            .request(&identity)
            .expect("completed cancellation remains idempotent");
    }

    #[test]
    fn cancellation_ack_waits_for_the_active_call_to_stop() {
        let state = ExtensionCancellationState::default();
        let identity = cancellation();
        let guard = state.begin(identity.clone()).expect("register call");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                sender
                    .send(state.request_and_wait(&identity, Duration::from_secs(1)))
                    .expect("send result");
            });
            assert!(
                receiver.recv_timeout(Duration::from_millis(20)).is_err(),
                "acknowledgement must wait while the child is active"
            );
            assert!(guard.token().is_requested());
            drop(guard);
            receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("cancellation finishes")
                .expect("cancellation succeeds");
        });
    }
}
