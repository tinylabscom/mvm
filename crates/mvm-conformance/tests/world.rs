//! Shared state cucumber threads through the steps of one scenario.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::process::Output;

use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use mvm_core::kernel_advisory::{KernelAdvisory, KernelPin};
use mvm_core::kernel_format::KernelFormat;
use mvm_core::vm_backend::StandbyHandle;
use mvm_fs::snapshot_store::{FsSnapshotStore, SnapshotId};
use mvm_runtime::checkpoint::CheckpointStore;
use mvm_runtime::standby_pool::SupervisorStandbyPool;

/// Points `MVM_HOME` at a scenario-local directory and restores the
/// previous value when the guard drops.
///
/// Warm-restore scenarios call in-process seal/verify helpers that read
/// `MVM_HOME` via [`mvm_core::config::mvm_home`], so they cannot pass a
/// home directory as an argument. This guard keeps the override active
/// across every step of a scenario while ensuring the override is undone
/// afterwards. The BDD runner executes scenarios sequentially, so the
/// process-global mutation is safe.
pub struct MvmHomeGuard {
    previous: Option<std::ffi::OsString>,
}

impl MvmHomeGuard {
    pub fn new(path: &std::path::Path) -> Self {
        let previous = std::env::var_os("MVM_HOME");
        // SAFETY: the BDD runner executes scenarios sequentially, so no other
        // thread observes the process environment while this guard is alive.
        unsafe { std::env::set_var("MVM_HOME", path) };
        Self { previous }
    }
}

impl Drop for MvmHomeGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(prev) => {
                // SAFETY: serial scenario execution; see `MvmHomeGuard::new`.
                unsafe { std::env::set_var("MVM_HOME", prev) };
            }
            None => {
                // SAFETY: serial scenario execution; see `MvmHomeGuard::new`.
                unsafe { std::env::remove_var("MVM_HOME") };
            }
        }
    }
}

/// Overrides a fixed set of process environment variables for the duration
/// of one scenario and restores each previous value when the guard drops.
///
/// This is the process-wide counterpart of the per-command `.env(...)` the
/// CLI steps use, for steps that drive in-process boot-policy code reading
/// the environment (`MVM_HOME`, `HOME`, acquire-mode selectors). The BDD
/// runner executes scenarios sequentially, so the process-global mutation is
/// safe.
pub struct ScenarioEnvGuard {
    previous: Vec<(std::ffi::OsString, Option<std::ffi::OsString>)>,
}

impl ScenarioEnvGuard {
    pub fn new(overrides: &[(&str, &std::ffi::OsStr)]) -> Self {
        let previous = overrides
            .iter()
            .map(|(key, value)| {
                let previous = std::env::var_os(key);
                // SAFETY: the BDD runner executes scenarios sequentially, so
                // no other thread observes the process environment while this
                // guard is alive.
                unsafe { std::env::set_var(key, value) };
                (std::ffi::OsString::from(key), previous)
            })
            .collect();
        Self { previous }
    }
}

impl Drop for ScenarioEnvGuard {
    fn drop(&mut self) {
        for (key, previous) in &self.previous {
            match previous {
                Some(prev) => {
                    // SAFETY: serial scenario execution; see `ScenarioEnvGuard::new`.
                    unsafe { std::env::set_var(key, prev) };
                }
                None => {
                    // SAFETY: serial scenario execution; see `ScenarioEnvGuard::new`.
                    unsafe { std::env::remove_var(key) };
                }
            }
        }
    }
}

/// One end-to-end launch's observable result: what the CLI said, and how long
/// the guest took to become dispatchable.
///
/// Lives here rather than beside its steps because `tests/world.rs` is also
/// auto-discovered as its own integration-test target, where `crate::steps`
/// does not exist.
#[derive(Debug, Default)]
pub struct LaunchRecord {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    /// `dispatch_window` from `MVM_PHASE_TIMING=1`, in milliseconds.
    pub dispatch_window_ms: Option<f64>,
    /// Wall-clock for the whole `mvmctl` invocation.
    pub wall: std::time::Duration,
}

impl LaunchRecord {
    /// stdout and stderr together — the guest's own output and the CLI's
    /// diagnostics arrive on different streams depending on the shape.
    pub fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

/// Constructed fresh for every scenario. Holds the result of the most
/// recent CLI invocation so later `Then` steps can assert on it, plus the
/// workload identities parsed from successful `build address` runs, keyed by
/// fixture name.
#[derive(cucumber::World, Default)]
pub struct CliWorld {
    pub last_run: Option<Output>,
    /// Artifact-warm `MVM_HOME` the end-to-end launch scenarios share.
    pub e2e_home: Option<PathBuf>,
    /// Result of the most recent end-to-end launch, including its measured
    /// dispatch window.
    pub last_launch: Option<LaunchRecord>,
    /// Name of the shared guest the documented machine-verb journey drives.
    pub journey_machine: Option<String>,
    /// Gate under test in the peer-addressing scenarios.
    pub peer_gate: Option<mvm_vmm::vsock_egress_bridge::egress_gate::EgressGate>,
    /// The most recent peer/egress decision.
    pub peer_decision: Option<mvm_vmm::vsock_egress_bridge::egress_gate::TargetDecision>,
    /// Broker registry under test in the key-value scenarios.
    pub broker_registry: Option<mvm_hostd::broker::registry::Registry>,
    /// Tempdir backing the key-value store, held so it outlives the scenario.
    pub kv_root: Option<tempfile::TempDir>,
    /// Read-only ext4 carrying the live service-plane fixture tree, held so it
    /// remains present while the microVM boots and mounts it.
    pub service_plane_fixture_disk: Option<tempfile::TempDir>,
    /// Outcome of the most recent broker dispatch.
    pub kv_result: Option<mvm_core::protocol::handler::ServiceDispatchResult>,
    /// Catalog under test in the declared-binding scenarios.
    pub runtime_catalog: Option<mvm_core::runtime_catalog::RuntimeCatalog>,
    /// Outcome of resolving a runtime by name, error rendered for assertion.
    pub runtime_resolution: Option<Result<mvm_core::runtime_catalog::Detection, String>>,
    /// Whether detection matched, or why it refused.
    pub runtime_detection: Option<Result<bool, String>>,
    /// Id of the conformance claim currently being exercised by a claim scenario.
    pub current_claim_id: Option<String>,
    /// Local file:// registry created by template-registry scenarios.
    pub template_registry_dir: Option<tempfile::TempDir>,
    /// Generated project directory guard created by template-registry scenarios.
    pub generated_project_dir_tmp: Option<tempfile::TempDir>,
    /// Path to the most recently generated project directory.
    pub generated_project_dir: Option<PathBuf>,
    /// Output from the SDK fixture or code-generation command used by the
    /// cross-language SDK scenarios.
    pub sdk_output: Option<Output>,
    /// SDK fixture surface most recently exercised (`decorator` or `runtime`).
    pub sdk_surface: Option<String>,
    /// `mvmctl` argv the recording double captured, one entry per invocation,
    /// keyed by the language whose fixture produced it.
    pub sdk_recorded_argv: BTreeMap<String, Vec<Vec<String>>>,

    /// Per-language JSON emitted by the Tier A constructor fixtures,
    /// keyed by language, for comparison against the golden document.
    pub sdk_ctor_docs: BTreeMap<String, String>,
    /// Scenario-local directory holding the recording double's argv logs.
    pub sdk_argv_log_dir: Option<tempfile::TempDir>,
    /// Result of exercising the signed-plan share gate with an attachment the
    /// plan did not authorize.
    pub volume_admission_result: Option<Result<(), String>>,
    /// `workload_address` per fixture name, populated on a zero-exit
    /// `build address` run.
    pub addresses: HashMap<String, String>,
    /// `ir_hash` per fixture name, from the same run as `addresses`.
    pub ir_hashes: HashMap<String, String>,
    /// Full sealed-workload cmdline assembled through a real VMM driver.
    pub workload_cmdline: Option<String>,
    /// Whether the sealed launch's production block mapping attached both
    /// read-only runtime-overlay devices under a complete verified triple.
    pub sealed_runtime_overlay_attached: Option<bool>,
    /// Kernel format mapped by the libkrun supervisor-config seam.
    pub libkrun_kernel_format: Option<KernelFormat>,
    /// An isolated `MVM_HOME` created by a `Given` step and reused by later
    /// steps that need to inspect the filesystem after a run.
    pub isolated_home: Option<tempfile::TempDir>,
    /// A throwaway working directory a documented command runs *inside*, so an
    /// example whose argument is a relative path (`./my-python-app`) can be
    /// spelled in the step exactly as the README prints it. Without it such a
    /// command writes into the repository working tree, which is banned, and
    /// the alternative — an argv assembled in Rust — is invisible to the
    /// structural check that reads commands out of quoted step text.
    pub scratch_dir: Option<tempfile::TempDir>,
    /// Host-side listener standing in for the workload a `--peer` route points
    /// at. Held for the scenario's lifetime: the accept loop runs on a clone
    /// and ends when this drops.
    pub peer_listener: Option<std::net::TcpListener>,
    /// Tempdir holding the file/directory trees the asset-identity
    /// scenarios hash; held so it outlives the scenario.
    pub asset_fixture_dir: Option<tempfile::TempDir>,
    /// Force workload-kernel reacquisition through a closed local endpoint so
    /// invalid-cache scenarios prove eviction without network or Stage 0.
    pub kernel_reacquisition_must_fail: bool,
    /// Process-wide `MVM_HOME` override held across the steps of one
    /// scenario (dropped — and the previous value restored — when the
    /// world is dropped at scenario end).
    pub mvm_home_guard: Option<MvmHomeGuard>,
    /// The typed artifact-missing triple (`what`, `path`, `hint`) captured
    /// from the apple-container backend's start failure.
    pub apple_container_error: Option<(String, String, String)>,
    /// The typed untrusted-artifact triple (`reason`, `path`, `hint`)
    /// captured from the apple-container backend's start failure when the
    /// cached kernel fails its digest attestation.
    pub apple_container_untrusted: Option<(String, String, String)>,
    /// The backend kind auto-select resolved to, as its `Debug` token.
    pub auto_selected_kind: Option<String>,
    /// The kernel path after the apple-container backend's substitution.
    pub overridden_kernel_path: Option<String>,
    /// The backend kind (`Debug` token) the admitted workload funnel
    /// returned for the apple-container selector.
    pub apple_container_workload_kind: Option<String>,
    /// Fixed stand-in guest-agent bytes an initramfs scenario builds from.
    pub initramfs_agent_bytes: Option<Vec<u8>>,
    /// The two deterministic cpio builds a determinism scenario compares.
    pub initramfs_cpio_a: Option<Vec<u8>>,
    /// Second deterministic cpio build (see `initramfs_cpio_a`).
    pub initramfs_cpio_b: Option<Vec<u8>>,
    /// Sidecar contents (`hash`, `size`, `VERSION`) read back after an
    /// initramfs artifact assembly + install.
    pub initramfs_sidecars: Option<(String, String, String)>,
    /// The resolved image path after installing the assembled initramfs.
    pub initramfs_resolved_image: Option<PathBuf>,
    /// Process-wide env overrides held across the steps of a sealed-OCI
    /// initrd scenario (dropped — and the previous values restored — when
    /// the world is dropped at scenario end).
    pub initramfs_boot_env: Option<ScenarioEnvGuard>,
    /// Outcome of the most recent persistent-OCI effective-initrd
    /// resolution: `Ok(Some(path))` for a resolved initrd, `Ok(None)` for
    /// "no initrd", `Err(rendered)` for the legacy ladder's terminal
    /// failure.
    pub initramfs_boot_initrd: Option<Result<Option<String>, String>>,
    /// Whether live CLI steps should keep one warm standby for the next run.
    pub warm_residency: bool,
    /// Home selected by the most recent live CLI step. This is the shared
    /// artifact-warm home when the live runner provides one.
    pub last_live_home: Option<PathBuf>,
    /// Transient request directories present before a live warm-claim journey.
    /// The final assertion compares against this baseline so unrelated stale
    /// state in a shared runner home cannot hide or falsely fail the cleanup.
    pub live_request_dirs_before: Option<HashSet<PathBuf>>,
    /// Content address of the bundle a `bundle install` step registered, so the
    /// boot step can name it as `machine run --manifest <sha>`.
    pub bundle_sha: Option<String>,
    /// Local kernel pins accumulated by the freshness-watcher scenarios.
    pub kernel_pins: Vec<KernelPin>,
    /// Latest upstream point release per `MAJOR.MINOR` series, as those same
    /// scenarios stage it before assessing.
    pub kernel_upstream: BTreeMap<String, String>,
    /// The verdict from the most recent freshness assessment.
    pub kernel_advisory: Option<KernelAdvisory>,
    /// Per-scenario SDK-sidecar cache root, so a developer's populated cache
    /// can never satisfy a scenario for the wrong reason.
    pub sdk_sidecar_cache: Option<tempfile::TempDir>,
    /// Per-scenario staged release directory the acquire scenarios fetch from,
    /// so the download path runs against local bytes and never the network.
    pub sdk_sidecar_release: Option<tempfile::TempDir>,
    /// Host-service bindings the scenario's plan carries.
    pub sdk_sidecar_services: Vec<mvm_contract::protocol::broker::ServiceId>,
    /// Ordinary workload mounts assembled beside the reserved SDK sidecar.
    /// Keeping these separate lets the sidecar scenarios prove the two guest
    /// activation channels cannot accidentally be conflated.
    pub sdk_sidecar_user_volumes: Vec<mvm_core::vm_backend::VmVolume>,
    /// The signed-plan fixture the sidecar scenarios gate against.
    pub sdk_sidecar_plan: Option<mvm_core::plan::ExecutionPlan>,
    /// Outcome of the most recent sidecar resolution: `Ok(None)` for "not
    /// needed", `Ok(Some(_))` for an attachment, `Err(rendered)` for a
    /// fail-closed refusal.
    pub sdk_sidecar_result:
        Option<Result<Option<mvm_runtime::sdk_sidecar::SdkSidecarAttachment>, String>>,
    /// Result of a framed `host.time.v1::now` request against the same bound
    /// broker registry the host-agent constructs for a workload.
    pub sdk_host_time_result: Option<Result<u64, String>>,
    /// Root directory for the OCI unpack scenarios.
    pub unpack_root: Option<tempfile::TempDir>,
    /// Paths written by prior layers when unpacking multiple layers.
    pub prior_layer_paths: HashSet<PathBuf>,
    /// The most recent OCI unpack report.
    pub last_unpack_report: Option<mvm_fs::oci::UnpackReport>,
    /// Scratch directory backing the HVF restore config-rewrite scenarios.
    pub hvf_restore_tmp: Option<tempfile::TempDir>,
    /// The captured parent launch config a restore scenario rewrites.
    pub hvf_parent_config: Option<mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig>,
    /// The rewritten child launch config under assertion.
    pub hvf_child_config: Option<mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig>,
    /// Scratch directory backing the HVF checkpoint-origin/lineage scenarios.
    pub hvf_ckpt_tmp: Option<tempfile::TempDir>,
    /// Checkpoint store seeded by an HVF checkpoint scenario.
    pub hvf_ckpt_store: Option<CheckpointStore>,
    /// The sealed record a scenario classifies or tries to restore.
    pub hvf_ckpt_meta: Option<CheckpointMeta>,
    /// The digest the scenario's signed-chain double reports, or `None` for a
    /// checkpoint no signed audit entry covers.
    pub hvf_anchor: Option<Option<mvm_core::checkpoint::CheckpointDigest>>,
    /// Scratch directory backing the warm-snapshot scenarios: holds the
    /// snapshot store root, the synthetic template rootfs artifact, and
    /// every materialized instance path.
    pub snapshot_tmp: Option<tempfile::TempDir>,
    /// The content-addressed snapshot store opened by a warm-snapshot
    /// `Given` step.
    pub snapshot_store: Option<FsSnapshotStore>,
    /// The id returned when the template rootfs artifact was stored.
    pub snapshot_id: Option<SnapshotId>,
    /// Path to the synthetic template rootfs artifact, kept so later steps
    /// can re-store it and assert dedup.
    pub snapshot_source_path: Option<PathBuf>,
    /// Bytes of the synthetic template rootfs artifact, for byte-equality
    /// assertions against materialized instances.
    pub snapshot_source_bytes: Option<Vec<u8>>,
    /// Path of the most recently materialized instance.
    pub snapshot_instance_path: Option<PathBuf>,
    /// Root tempdir backing the warm-claim scenario's checkpoint + snapshot
    /// stores and standby pool. Kept alive for the scenario's duration.
    pub warm_claim_store_root: Option<tempfile::TempDir>,
    /// Tempdir holding the seeded parent's source rootfs + overlay sidecar.
    pub warm_claim_src: Option<tempfile::TempDir>,
    /// Content-addressed checkpoint store the seeded parent lives in.
    pub warm_claim_checkpoints: Option<CheckpointStore>,
    /// Snapshot store backing the child's copy-on-write rootfs materialize.
    pub warm_claim_snapshots: Option<FsSnapshotStore>,
    /// The seeded parent's checkpoint id + captured, sealed metadata.
    pub warm_claim_parent_id: Option<CheckpointId>,
    pub warm_claim_parent_meta: Option<CheckpointMeta>,
    /// Whether the claim's `CheckpointChainAnchor` should report the seeded
    /// parent as carrying a signed audit-chain creation entry.
    pub warm_claim_parent_audited: bool,
    /// The standby pool the seeded parent is recorded in.
    pub warm_claim_pool: Option<SupervisorStandbyPool>,
    /// The seeded parent's idle standby handle.
    pub warm_claim_handle: Option<StandbyHandle>,
    /// VM-name registry path serializing the parent reserve + child mint.
    pub warm_claim_registry_path: Option<PathBuf>,
    /// The outcome of the most recent `claim_standby` call.
    pub warm_claim_outcome: Option<WarmClaimOutcome>,

    /// RAII guard that keeps a scenario-local `MVM_HOME` override active
    /// across the warm-restore steps. Dropping it restores the previous
    /// value so later scenarios see a clean environment.
    pub warm_restore_home_guard: Option<MvmHomeGuard>,

    /// Outcome of the most recent warm-restore guard step.
    pub warm_restore_result: Option<Result<String, String>>,
    /// Directory containing the sealed snapshot under test.
    pub warm_restore_dir: Option<PathBuf>,
    /// Which artifact file was tampered with (e.g. "vmstate.bin" or "mem.bin").
    pub warm_restore_tampered_file: Option<String>,
    /// Restored device model produced by the most recent restore probe.
    pub warm_restore_device_model: Option<mvm_runtime::microvm::RestoredDeviceModel>,

    /// The launch sample a prepared-cold lane scenario stages.
    pub cold_launch_sample: Option<mvm_cli::bench::cold_launch::LaunchSample>,
    /// The lane gate's verdict on it, with any refusal reduced to its
    /// rendered text so the scenario asserts what an operator would read.
    pub cold_launch_lane_result: Option<Result<(), String>>,

    /// Page-merge scopes staged for the most recent merge-decision step.
    pub warm_merge_scopes: Vec<(String, mvm_core::page_merge::PageMergeScope)>,
    /// The most recent page-merge decision.
    pub warm_merge_decision: Option<mvm_core::page_merge::MergeDecision>,
    /// Signer id that produced the plan under test.
    pub warm_restore_plan_signer: Option<String>,
    /// JSON of the most recently signed execution plan under test.
    pub warm_restore_plan_json: Option<String>,
    /// The isolated `MVM_HOME` backing the warm-restore guard scenarios;
    /// kept alive so the sealed snapshot files survive the `Given` step.
    pub warm_restore_home: Option<tempfile::TempDir>,

    /// Bytes of a sealed ext4 rootfs built by a verified-boot scenario.
    pub sealed_rootfs: Option<Vec<u8>>,
    /// dm-verity root hash recorded for `sealed_rootfs`.
    pub sealed_rootfs_roothash: Option<String>,
    /// Tempdir backing a secrets/PII scenario's isolated secret store.
    pub secret_tmp: Option<tempfile::TempDir>,
    /// Raw value stored for the current secret scenario.
    pub secret_value: Option<String>,
    /// Name of the secret stored in the current scenario.
    pub secret_name: Option<String>,
    /// Tenant of the secret stored in the current scenario.
    pub secret_tenant: Option<String>,
    /// JSON serialization of the metadata returned by SecretService.
    pub secret_metadata_json: Option<String>,
    /// Original outbound body for a PII-redaction scenario.
    pub pii_body: Option<String>,
    /// Body after the PII redactor processed it.
    pub pii_redacted: Option<String>,
    /// Rule names that fired during PII redaction.
    pub pii_fired_rules: Option<Vec<String>>,
    /// Outcome of the most recent runtime-overlay resolver probe.
    pub runtime_overlay_result: Option<Result<mvm_fs::overlay::RuntimeOverlayArtifact, String>>,

    /// Outcome of the most recent plan-verification step.
    pub warm_restore_verify_result: Option<Result<String, String>>,
    /// Checkpoint id captured by the most recent `machine vm checkpoint create`.
    pub warm_restore_checkpoint_id: Option<String>,
    /// Reference agent-session journal used by the durable contract BDD
    /// scenarios. The journal is pure protocol state, not a second store.
    pub agent_session_journal: Option<mvm_contract::protocol::agent_session::AgentSessionJournal>,
    /// Most recent agent command result.
    pub agent_session_outcome: Option<mvm_contract::protocol::agent_session::AgentCommandOutcome>,
    /// Most recent bounded history page.
    pub agent_session_history:
        Option<mvm_contract::protocol::agent_session::AgentSessionHistoryPage>,
    /// State reconstructed from durable history after a simulated adapter
    /// restart.
    pub agent_session_restarted_state:
        Option<mvm_contract::protocol::agent_session::AgentSessionState>,
    /// Most recent live-only event.
    pub agent_session_live:
        Option<mvm_contract::protocol::agent_session::AgentSessionEventEnvelope>,
    /// Sanitized serialized history captured by a security assertion.
    pub agent_session_history_json: Option<String>,
    /// Descriptor used by the typed capability BDD contract scenarios.
    pub capability_descriptor:
        Option<mvm_contract::protocol::agent_capability::CapabilityDescriptor>,
    /// Invocation metadata used by the typed capability BDD scenarios.
    pub capability_invocation:
        Option<mvm_contract::protocol::agent_capability::CapabilityInvocation>,
    /// Last typed capability validation outcome.
    pub capability_outcome:
        Option<Result<(), mvm_contract::protocol::agent_capability::CapabilityFailureCode>>,
    /// Serialized digest-only capability audit event.
    pub capability_audit_json: Option<String>,
    /// Typed policy evaluation used by the runtime-approval scenarios.
    pub approval_evaluation: Option<mvm_contract::policy::approval::PolicyEvaluation>,
    /// Durable approval ledger reconstructed from the agent-session journal.
    pub approval_ledger: Option<mvm_contract::policy::approval::ApprovalLedger>,
    /// Approval id used by the current runtime-approval scenario.
    pub approval_id: Option<mvm_contract::policy::approval::ApprovalRequestId>,
    /// Most recent approval operation failure, retained as a stable message.
    pub approval_error: Option<String>,
    /// Most recent approval lifecycle state.
    pub approval_state: Option<mvm_contract::policy::approval::ApprovalState>,
    /// Approval state reconstructed after a simulated restart.
    pub approval_restarted_state: Option<mvm_contract::policy::approval::ApprovalState>,
    /// Scratch dir for the one-transport scenarios' identity drives.
    pub one_transport_dir: Option<tempfile::TempDir>,
    /// Identity drives minted during a one-transport scenario, in order.
    pub one_transport_drives: Vec<std::path::PathBuf>,
    /// The material behind each of those drives.
    pub one_transport_material: Vec<mvm_vmm::host::flowmux_identity::FlowMuxIdentityMaterial>,
    /// Raw bytes of the drive the guest reader last inspected.
    pub one_transport_image: Option<Vec<u8>>,
    /// Raw bytes of the inheritable identity the host last persisted.
    pub one_transport_persisted: Option<Vec<u8>>,
    /// `(egress_mode, carries_guest_key)` for each endpoint config built.
    pub one_transport_modes: Vec<(String, bool)>,
    /// Per-VM state dir for the readiness scenarios.
    pub one_transport_state: Option<tempfile::TempDir>,
}

/// What a warm-claim `When` step observed from a `WorkloadRunner::claim_standby`
/// call — either the fresh child identity a guarded fork produced, or the
/// fail-closed refusal message, so `Then` steps assert on plain, `Send`
/// data rather than holding VM-runner types across step boundaries.
#[derive(Debug, Clone)]
pub enum WarmClaimOutcome {
    Claimed(WarmClaimWitness),
    Refused {
        message: String,
        /// Whether the driver's `fork_standby_child` ran before the refusal —
        /// must be `false` for every refusal: a fail-closed gate refuses
        /// before any clone or boot side effect.
        any_fork_occurred: bool,
    },
}

/// The observable, runner-owned facts a successful guarded fork produces:
/// a fresh child identity distinct from the parent, its cloned rootfs, and
/// the fresh generation token delivered with the fork.
#[derive(Debug, Clone)]
pub struct WarmClaimWitness {
    pub child_id: String,
    pub child_dir_has_sidecar: bool,
    pub child_dir_has_rootfs: bool,
    pub fork_genid_nonzero: bool,
    pub fork_genid_content_hash_matches_parent: bool,
    pub post_restore_grant_session_matches_child: bool,
    pub post_restore_grant_verbs: Vec<String>,
    pub post_restore_grant_verifies_under_host_key: bool,
}

impl fmt::Debug for CliWorld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliWorld")
            .field("last_run", &self.last_run)
            .field("sdk_output", &self.sdk_output)
            .field("sdk_surface", &self.sdk_surface)
            .field("addresses", &self.addresses)
            .field("ir_hashes", &self.ir_hashes)
            .field("workload_cmdline", &self.workload_cmdline)
            .field(
                "sealed_runtime_overlay_attached",
                &self.sealed_runtime_overlay_attached,
            )
            .field("libkrun_kernel_format", &self.libkrun_kernel_format)
            .field(
                "isolated_home",
                &self.isolated_home.as_ref().map(|t| t.path().to_path_buf()),
            )
            .field(
                "service_plane_fixture_disk",
                &self
                    .service_plane_fixture_disk
                    .as_ref()
                    .map(|t| t.path().to_path_buf()),
            )
            .field(
                "kernel_reacquisition_must_fail",
                &self.kernel_reacquisition_must_fail,
            )
            .field("warm_residency", &self.warm_residency)
            .field("kernel_pins", &self.kernel_pins)
            .field("kernel_upstream", &self.kernel_upstream)
            .field("kernel_advisory", &self.kernel_advisory)
            .finish()
    }
}

impl CliWorld {
    /// The `Output` of the most recent CLI invocation, or a failed
    /// assertion naming the step that forgot to run one first.
    pub fn last_output(&self) -> &Output {
        self.last_run
            .as_ref()
            .expect("no CLI invocation recorded yet — a prior `When` step must run one")
    }

    /// The stored workload address for `fixture`, or a failed assertion
    /// naming the fixture whose `When` step didn't run (or didn't succeed).
    pub fn address_of(&self, fixture: &str) -> &str {
        self.addresses.get(fixture).unwrap_or_else(|| {
            panic!(
                "no address recorded for {fixture:?} — its `When` step must run and succeed first"
            )
        })
    }

    /// The advisory from the most recent freshness assessment, or a failed
    /// assertion naming the missing `When` step.
    pub fn advisory(&self) -> &KernelAdvisory {
        self.kernel_advisory
            .as_ref()
            .expect("no advisory recorded yet — a prior `When` step must assess freshness")
    }
}
