//! Authenticated readiness verification for asynchronously prepared warm VMs.
//!
//! Artifact publication is allowed only after a backend-specific factory has
//! booted the staged inputs and the guest agent has answered a readiness query
//! over its authenticated control channel. The factory is the only
//! platform-specific seam; the handshake and readiness policy are shared.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use mvm_agentd::vsock::{
    ComponentState, GUEST_AGENT_PORT, GuestRequest, GuestResponse, ReadinessReport,
    send_request_stream,
};
use mvm_core::security::AgentProfile;
use mvm_core::vm_backend::WarmPrewarmSource;

use crate::driver::RunningVm;
use crate::warm_artifact_builder::WarmGoldenVmReadinessVerifier;
use crate::warm_artifacts::WarmArtifactKey;

/// Backend-specific factory used to boot one disposable golden VM from the
/// worker's staged, content-addressed inputs.
pub type WarmGoldenVmFactory = Arc<
    dyn Fn(&WarmPrewarmSource, &WarmArtifactKey, &Path) -> Result<Box<dyn RunningVm>> + Send + Sync,
>;

/// Shared authenticated readiness verifier for all warm-pool backends.
pub struct AuthenticatedWarmGoldenVmVerifier {
    factory: WarmGoldenVmFactory,
}

impl AuthenticatedWarmGoldenVmVerifier {
    /// Create a verifier around a backend-specific disposable-VM factory.
    pub fn new(factory: WarmGoldenVmFactory) -> Self {
        Self { factory }
    }

    /// Convert this verifier into the worker callback used by the durable
    /// prewarm queue.
    pub fn callback(self: Arc<Self>) -> WarmGoldenVmReadinessVerifier {
        Arc::new(move |source, key, staging_root| self.verify(source, key, staging_root))
    }

    /// Boot, authenticate, query readiness, and tear down one golden VM.
    pub fn verify(
        &self,
        source: &WarmPrewarmSource,
        key: &WarmArtifactKey,
        staging_root: &Path,
    ) -> Result<()> {
        source
            .validate()
            .map_err(anyhow::Error::msg)
            .context("validate warm source before readiness probe")?;
        key.validate().map_err(anyhow::Error::new)?;
        let vm = (self.factory)(source, key, staging_root).context("boot golden VM")?;
        let readiness = verify_authenticated_readiness(&*vm);
        let teardown = vm.kill().context("tear down golden VM readiness probe");
        match (readiness, teardown) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(readiness), Err(teardown)) => {
                Err(readiness.context(format!("golden VM teardown also failed: {teardown}")))
            }
        }
    }
}

fn verify_authenticated_readiness(vm: &dyn RunningVm) -> Result<()> {
    let mut stream = vm
        .vsock_connect(GUEST_AGENT_PORT)
        .context("connect to golden VM guest agent")?;
    let response = send_request_stream(&mut stream, &GuestRequest::ReadinessStatus)
        .context("authenticated golden VM readiness request")?;
    let GuestResponse::ReadinessStatusReport(report) = response else {
        bail!("golden VM returned an unexpected readiness response")
    };
    validate_readiness_report(&report)
}

fn validate_readiness_report(report: &ReadinessReport) -> Result<()> {
    if report.control_plane != ComponentState::Ready {
        bail!(
            "golden VM control plane is not ready: {:?}",
            report.control_plane
        );
    }
    if report.profile != AgentProfile::SealedProd {
        bail!("golden VM guest agent is not sealed-production profile");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, Ordering};

    use ed25519_dalek::SigningKey;
    use mvm_agentd::vsock::{AuthenticatedSession, GuestRequest};
    use mvm_core::vm_backend::{VmExitStatus, VmId, VmStatus};

    struct TestVmState {
        stream: std::sync::Mutex<Option<UnixStream>>,
        killed: AtomicBool,
    }

    struct TestRunningVm {
        state: Arc<TestVmState>,
    }

    impl RunningVm for TestRunningVm {
        fn id(&self) -> &VmId {
            static ID: std::sync::OnceLock<VmId> = std::sync::OnceLock::new();
            ID.get_or_init(|| VmId("warm-readiness-test".into()))
        }

        fn wait(&self) -> Result<VmExitStatus> {
            Ok(VmExitStatus::SUCCESS)
        }

        fn kill(&self) -> Result<()> {
            self.state.killed.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn pause(&self) -> Result<()> {
            Ok(())
        }

        fn resume(&self) -> Result<()> {
            Ok(())
        }

        fn status(&self) -> Result<VmStatus> {
            Ok(VmStatus::Running)
        }

        fn vsock_connect(&self, _guest_port: u32) -> Result<Box<dyn crate::driver::DuplexStream>> {
            let stream = self
                .state
                .stream
                .lock()
                .map_err(|_| anyhow::anyhow!("test VM stream lock poisoned"))?
                .take()
                .ok_or_else(|| anyhow::anyhow!("test VM stream already consumed"))?;
            Ok(Box::new(stream))
        }
    }

    fn key() -> WarmArtifactKey {
        WarmArtifactKey {
            backend: "hvf".into(),
            backend_version: "v1".into(),
            guest_agent_sha256: "a".repeat(64),
            kernel_sha256: "b".repeat(64),
            initramfs_sha256: "c".repeat(64),
            rootfs_sha256: "d".repeat(64),
            runtime_overlay_sha256: Some("e".repeat(64)),
        }
    }

    fn ready_report() -> ReadinessReport {
        ReadinessReport {
            control_plane: ComponentState::Ready,
            profile: AgentProfile::SealedProd,
            ..ReadinessReport::default()
        }
    }

    #[test]
    fn sealed_ready_report_is_accepted() {
        validate_readiness_report(&ready_report()).expect("sealed ready report is valid");
    }

    #[test]
    fn starting_control_plane_is_rejected() {
        let report = ReadinessReport {
            control_plane: ComponentState::Starting,
            ..ready_report()
        };
        let error = validate_readiness_report(&report).expect_err("starting is not ready");
        assert!(error.to_string().contains("not ready"));
    }

    #[test]
    fn non_sealed_profile_is_rejected() {
        let report = ReadinessReport {
            profile: AgentProfile::Dev,
            ..ready_report()
        };
        let error = validate_readiness_report(&report).expect_err("dev profile is not admissible");
        assert!(error.to_string().contains("sealed-production"));
    }

    #[test]
    fn verifier_uses_authenticated_readiness_and_always_tears_down_probe_vm() {
        let home = tempfile::tempdir().expect("test home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let host_key = SigningKey::from_bytes(&[7; 32]);
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys).expect("create test keys");
        std::fs::write(keys.join("host-signer.ed25519"), host_key.to_bytes())
            .expect("write host signer");

        let (host, mut guest) = UnixStream::pair().expect("socket pair");
        let anchor = host_key.verifying_key();
        let guest_thread = std::thread::spawn(move || {
            let guest_key = SigningKey::from_bytes(&[9; 32]);
            let mut session = AuthenticatedSession::guest(&mut guest, guest_key, &anchor)
                .expect("guest authentication");
            let request: GuestRequest = session.read(&mut guest).expect("read readiness request");
            assert!(matches!(request, GuestRequest::ReadinessStatus));
            session
                .write(
                    &mut guest,
                    &GuestResponse::ReadinessStatusReport(ready_report()),
                )
                .expect("write readiness report");
        });

        let state = Arc::new(TestVmState {
            stream: std::sync::Mutex::new(Some(host)),
            killed: AtomicBool::new(false),
        });
        let factory_state = Arc::clone(&state);
        let factory: WarmGoldenVmFactory = Arc::new(move |_, _, _| {
            Ok(Box::new(TestRunningVm {
                state: Arc::clone(&factory_state),
            }))
        });
        let verifier = AuthenticatedWarmGoldenVmVerifier::new(factory);
        let staging = tempfile::tempdir().expect("staging root");
        verifier
            .verify(
                &WarmPrewarmSource::OciImage {
                    reference: "python:3.12".into(),
                },
                &key(),
                staging.path(),
            )
            .expect("authenticated readiness succeeds");
        guest_thread.join().expect("guest thread completes");
        assert!(state.killed.load(Ordering::SeqCst));
    }
}
