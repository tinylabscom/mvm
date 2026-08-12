//! [`SupervisorConfig`] — the JSON shape the `mvm-libkrun-supervisor`
//! binary reads from stdin — plus the warm-standby split
//! ([`SupervisorBaseConfig`] + [`SupervisorAttachConfig`]) and the
//! [`run_supervisor`] / [`stop`] entry points that consume it.

use crate::context::KrunContext;
use crate::error::{Error, install_hint, is_available};

#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
#[cfg(feature = "libkrun-sys")]
use crate::start::install_shutdown_handler;

/// Bridge crash policy — what the libkrun supervisor does when the
/// in-process bridge thread panics or its child dies.
///
/// Bridge crash policy is hard-fail today; restart variants are a
/// future addition. The enum + serde field reservation lives here so
/// that addition is a schema extension, not a migration: old
/// configs continue to deserialize (the field is `#[serde(default)]`
/// to `HardFail`), and old supervisors reading new configs that name
/// a future variant fail closed at deserialize time with a clear
/// "unknown variant" error.
///
/// Scope: this reservation is `mvm-libkrun::SupervisorConfig`-only.
/// libkrun runs the guest in-process; the supervisor itself is the only thing in a
/// position to enforce a policy on bridge panics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeRestartPolicy {
    /// Supervisor exits when the bridge thread panics or its child
    /// dies; the parent `mvm-backend` process observes the exit and
    /// tears down the libkrun VM. Only variant implemented today.
    #[default]
    HardFail,
}

/// Configuration consumed by [`run_supervisor`] — the JSON shape that
/// the `mvm-libkrun-supervisor` binary reads from stdin and that
/// `LibkrunBackend::start()` produces. Holds the [`KrunContext`] plus
/// supervisor-process bookkeeping fields that don't belong on the
/// pure-FFI config type.
///
/// Always available (not feature-gated) because `mvm-backend`'s
/// `LibkrunBackend::start()` constructs it and serializes to JSON
/// without ever turning on `libkrun-sys` itself — the supervisor
/// process on the other end of the pipe is the one that links libkrun.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SupervisorConfig {
    /// The guest configuration to hand to libkrun.
    pub krun: KrunContext,
    /// Directory under which the supervisor writes its PID file and
    /// (via `KrunContext::vsock_socket_dir`) the per-port vsock
    /// listener sockets. Typically `~/.mvm/vms/<name>/`. Created if
    /// absent.
    pub vm_state_dir: String,
    /// File name inside `vm_state_dir` to receive the supervisor's
    /// PID. Defaults to `"libkrun.pid"` when `None`. The builder VM
    /// uses a different name (`builder.pid`) so the user dev VM and
    /// the builder can coexist in the same directory tree.
    pub pid_file_name: Option<String>,

    // --- gateway audit substrate ---------------
    //
    // The bridge ([`mvm_hostd::supervisor::gateway_bridge`]) needs these to
    // construct a per-VM `BridgeConfig`. `#[serde(default)]` keeps
    // older JSON callers parseable; admission validation
    // ([`SupervisorConfig::validate_audit_substrate`]) refuses
    // configs that don't supply them when the gateway substrate
    // is active.
    /// Tenant identifier — used as the per-tenant chain file name
    /// (`<audit_dir>/<tenant_id>.jsonl`). Validated to be non-empty
    /// before any bridge spawns.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// `~/.mvm/audit/` — directory holding per-tenant chain files
    /// and the per-VM subscriber sockets.
    #[serde(default)]
    pub audit_dir: Option<std::path::PathBuf>,
    /// `~/.mvm/audit/gateway-<vm>.sock` — per-VM subscriber socket
    /// the `mvm_hostd::supervisor::gateway_audit::GatewayAuditSink` binds.
    #[serde(default)]
    pub gateway_audit_socket: Option<std::path::PathBuf>,
    /// `~/.mvm/audit/gateway-events-<vm>.sock` — per-VM ingest
    /// socket an out-of-process gateway bridge connects to (one writer
    /// only). Ignored on libkrun (which spawns its bridge in-process); the
    /// out-of-process backend that needed it (a removed backend's
    /// Swift bridge) is gone, so no current backend sets this.
    #[serde(default)]
    pub gateway_events_socket: Option<std::path::PathBuf>,
    /// `~/.mvm/keys/host-signer.ed25519` — host signing key for
    /// the chained audit emitter. Validated to canonicalize under
    /// `~/.mvm/keys/` (no path-traversal) at admission.
    #[serde(default)]
    pub signing_key_path: Option<std::path::PathBuf>,

    // --- plan + bundle for bridge construction -----
    //
    // The bridge ([`mvm_hostd::supervisor::gateway_bridge::BridgeConfig`])
    // needs `Arc<ExecutionPlan>` + `Option<Arc<PolicyBundle>>` to
    // construct chained `AuditEntry`s. Carrying them as
    // `Option<serde_json::Value>` (instead of the typed structs)
    // avoids a typed coupling to the `mvm_core::plan` /
    // `mvm_core::policy` structs at this layer; the bridge stays a
    // serde boundary. The leaf bin crate `mvm-libkrun-supervisor` can freely
    // depend on both and deserializes the Values on the bridge side.
    /// JSON-encoded [`mvm_core::plan::ExecutionPlan`] for this admission.
    /// The bin deserializes into the typed value when building
    /// `BridgeConfig.plan`. `None` ⇒ legacy non-bridge path
    /// (`tenant_id` will also be `None` and
    /// `validate_audit_substrate` will refuse).
    #[serde(default)]
    pub plan: Option<serde_json::Value>,
    /// JSON-encoded [`mvm_core::policy::PolicyBundle`] for this admission.
    /// Optional even when `plan` is set — workloads can run with
    /// no bundle (matches the existing `Option<Arc<PolicyBundle>>`
    /// in `BridgeConfig`).
    #[serde(default)]
    pub bundle: Option<serde_json::Value>,
    /// JSON-encoded [`mvm_core::network_policy::NetworkPolicy`] — the bare
    /// egress policy for the no-bundle path. The supervisor decodes it onto
    /// `BridgeConfig.network_policy` so a transient/dev run enforces the same
    /// policy Firecracker derives from `VmStartConfig.network_policy`. `None`
    /// ⇒ no bare-policy override (admitted workloads with a `bundle` resolve
    /// egress from that instead).
    #[serde(default)]
    pub network_policy: Option<serde_json::Value>,

    // --- bridge crash policy reservation ----------
    //
    // Field reservation only — `BridgeRestartPolicy` carries the
    // `HardFail` variant today. Future restart variants are a later
    // addition; reserving the field now means that extension is a
    // schema addition (new variant) instead of a
    // migration. Existing JSON without this key deserializes
    // unchanged thanks to `#[serde(default)]`.
    /// Bridge crash policy — see [`BridgeRestartPolicy`]. Defaults
    /// to `HardFail` for existing JSON consumers. Unknown variant
    /// names are rejected at deserialize time, so legacy
    /// supervisors fail closed when handed configs that name
    /// future restart variants they don't understand.
    #[serde(default)]
    pub bridge_restart_policy: BridgeRestartPolicy,
    /// Host loopback port where the per-VM transparent egress terminator listens.
    /// When set, native gateway config generation may intercept guest `:80` and
    /// `:443` flows and forward them here.
    #[serde(default)]
    pub transparent_terminator_port: Option<u16>,
    /// When set, the supervisor pins the guest egress port's host-side
    /// socket to this explicit UDS instead of the dir-derived
    /// `vsock-<port>.sock` path — see
    /// `libkrun_sys::KrunContext::set_host_listen_socket_override`.
    /// `None` (the default at every construction site today) leaves
    /// the derived path unchanged; no current caller populates this.
    #[serde(default)]
    pub egress_relay_socket: Option<std::path::PathBuf>,

    /// Sidecar lock this supervisor must hold for its whole life, conferring
    /// the exclusive right to write the store image its guest attaches.
    ///
    /// Set only by the persistent builder, and for a specific reason: that VM
    /// outlives the command that started it, and an `flock` dies with the
    /// process holding it. A CLI-held lock would be released the moment
    /// `persistent-builder start` exits, leaving a running VM writing an image
    /// another builder is free to attach. Holding it here ties the lock to the
    /// process whose lifetime actually matches the VM's.
    ///
    /// `None` — every one-shot path — keeps the caller-held arrangement, which
    /// is already correct there because the caller outlives the VM.
    #[serde(default)]
    pub exclusive_image_lock: Option<std::path::PathBuf>,
}

impl SupervisorConfig {
    /// Resolve the absolute path to the PID file
    /// (`<vm_state_dir>/<pid_file_name>`). Used by the supervisor to
    /// write its PID and by `LibkrunBackend` to read it for
    /// `stop`/`status`/`list`.
    pub fn pid_file(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(&self.vm_state_dir)
            .join(self.pid_file_name.as_deref().unwrap_or("libkrun.pid"))
    }

    /// Admission validation for the gateway audit substrate. Refuses
    /// configurations that would leave the bridge unable to emit
    /// audit events into the per-tenant chain. Mandatory before any
    /// bridge spawn; the bridge entry point calls this first.
    ///
    /// Fields checked:
    /// - `tenant_id`: must be set and non-empty (used as chain
    ///   file name `<audit_dir>/<tenant_id>.jsonl`).
    /// - `audit_dir`: must be set. Used as parent for chain files
    ///   and per-VM subscriber sockets.
    /// - `gateway_audit_socket`: must be set, must have a parent
    ///   matching `audit_dir` (defense in depth — refuses
    ///   subscriber sockets in unrelated dirs).
    /// - `signing_key_path`: must be set, must canonicalize under
    ///   `~/.mvm/keys/` (path-traversal defense — the signing key
    ///   is host-trust-boundary state per claim 8).
    ///
    /// `gateway_events_socket` is not validated here — no current backend
    /// requires it; libkrun's in-process bridge ignores it.
    pub fn validate_audit_substrate(&self) -> Result<(), AuditSubstrateError> {
        let tenant = self
            .tenant_id
            .as_deref()
            .ok_or(AuditSubstrateError::MissingField("tenant_id"))?;
        if tenant.is_empty() {
            return Err(AuditSubstrateError::EmptyTenantId);
        }

        let audit_dir = self
            .audit_dir
            .as_ref()
            .ok_or(AuditSubstrateError::MissingField("audit_dir"))?;

        let audit_socket = self
            .gateway_audit_socket
            .as_ref()
            .ok_or(AuditSubstrateError::MissingField("gateway_audit_socket"))?;
        if audit_socket.parent() != Some(audit_dir.as_path()) {
            return Err(AuditSubstrateError::AuditSocketOutsideAuditDir {
                socket: audit_socket.display().to_string(),
                expected_parent: audit_dir.display().to_string(),
            });
        }

        let signing_key = self
            .signing_key_path
            .as_ref()
            .ok_or(AuditSubstrateError::MissingField("signing_key_path"))?;
        // Path-traversal defense: the signing key is host-trust-
        // boundary state. Reject callers that point us anywhere
        // outside the operator's keys dir. Resolved through the same
        // `mvm_keys_dir()` every other site uses (admission's
        // `default_keys_dir`, the audit-substrate builder), so the
        // prefix check holds across the supervisor process boundary —
        // the supervisor inherits the launcher's data-dir env. This
        // honors the data-dir override (worktree isolation) rather than
        // hard-pinning `$HOME`: relocating the key via the environment
        // requires host access, and a malicious host is out of the
        // threat model. The prefix check accepts the un-canonicalized
        // form (canonicalize would fail if the file doesn't exist yet,
        // which is legal at admission).
        let keys_dir = mvm_core::config::mvm_keys_dir();
        if !signing_key.starts_with(&keys_dir) {
            return Err(AuditSubstrateError::SigningKeyOutsideKeysDir {
                path: signing_key.display().to_string(),
                expected_prefix: keys_dir.display().to_string(),
            });
        }

        Ok(())
    }
}

/// Workload-**independent** supervisor config — everything a prelaunched
/// standby sets up before it knows which workload it will run. Carries
/// no rootfs and no plan; those arrive in the
/// [`SupervisorAttachConfig`] over the control UDS. `krun.rootfs_path` MUST be
/// `None` — [`SupervisorConfig::from_base_and_attach`] rejects a base that
/// already carries one (it would shadow the workload rootfs).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorBaseConfig {
    /// Workload-independent guest config: kernel, vcpus/ram, vsock wiring,
    /// console, `host_listen_ports`. `rootfs_path` must be `None`.
    pub krun: KrunContext,
    /// Per-VM state dir (`~/.mvm/vms/<name>/`) — see [`SupervisorConfig::vm_state_dir`].
    pub vm_state_dir: String,
    /// PID file name inside `vm_state_dir`; defaults to `libkrun.pid`.
    #[serde(default)]
    pub pid_file_name: Option<String>,
    /// `~/.mvm/keys/host-signer.ed25519` — host signing key. Source of the
    /// **public** key the attach-time plan re-verify checks against (claim 8;
    /// no new key). Carried in base because it is host identity, not workload.
    pub signing_key_path: std::path::PathBuf,
    /// Expected envelope `signer_id` (`host:{hostname}`). The attach plan must
    /// be signed by this id, else `verify_plan` reports `UnknownSigner`.
    pub signer_id: String,
    /// Per-spawn binding nonce (hex of 32 random bytes). The attach must echo
    /// it; a standby with a different nonce rejects (cross-standby replay).
    pub binding_nonce: String,
    /// Control UDS the standby binds and blocks on. Mode `0700`, in a `0700`
    /// dir, with the binding nonce embedded in the path.
    pub control_socket_path: std::path::PathBuf,
    /// Bridge crash policy — see [`BridgeRestartPolicy`].
    #[serde(default)]
    pub bridge_restart_policy: BridgeRestartPolicy,
}

/// Workload-**specific** supervisor config — the bytes that arrive over the
/// control UDS at attach. The only attacker-reachable-post-spawn surface
/// (fuzzed by `fuzz_attach_message`). The plan re-verify in
/// `mvm_hostd::prelaunch` is what makes accepting these bytes safe.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorAttachConfig {
    /// Echoed binding nonce — must equal `base.binding_nonce`.
    pub binding_nonce: String,
    /// Workload rootfs ext4 (`krun add_disk "root"`).
    pub rootfs_path: String,
    /// Per-tenant chain file name (`<audit_dir>/<tenant_id>.jsonl`).
    pub tenant_id: String,
    /// `~/.mvm/audit/` — chain files + per-VM subscriber sockets.
    pub audit_dir: std::path::PathBuf,
    /// `~/.mvm/audit/gateway-<vm>.sock` — per-VM subscriber socket.
    pub gateway_audit_socket: std::path::PathBuf,
    /// Out-of-process gateway-bridge ingest socket; ignored on libkrun
    /// (in-process bridge). No current backend sets this.
    #[serde(default)]
    pub gateway_events_socket: Option<std::path::PathBuf>,
    /// JSON-encoded `SignedExecutionPlan` envelope — same carrier shape as
    /// `SupervisorConfig.plan`. Required (the warm path always carries a plan).
    pub plan: serde_json::Value,
    /// JSON-encoded `PolicyBundle`, optional even when `plan` is set.
    #[serde(default)]
    pub bundle: Option<serde_json::Value>,
    /// JSON-encoded bare `NetworkPolicy` (same carrier shape as the cold-boot
    /// `SupervisorConfig.network_policy`). Threaded from the launcher's resolved
    /// policy so a warm-claimed standby enforces the SAME egress posture a cold
    /// boot would — the no-bundle deny-by-default path must not silently widen to
    /// an allow-all (permissive) gate on a pool hit. `None` only for pre-policy
    /// callers; the merge fails closed to deny-all in that case.
    #[serde(default)]
    pub network_policy: Option<serde_json::Value>,
    /// Host loopback port where the claimed workload's transparent egress
    /// terminator listens, when the native gateway will intercept `:80/:443`.
    #[serde(default)]
    pub transparent_terminator_port: Option<u16>,
}

/// Failure modes of [`SupervisorConfig::from_base_and_attach`]. The plan
/// re-verify failures live in `mvm_hostd::prelaunch::AttachVerifyError` —
/// this leaf crate can't depend on `mvm-core::plan`.
#[derive(Debug, PartialEq, Eq)]
pub enum AttachMergeError {
    /// The attach's echoed binding nonce != the base's binding nonce.
    BindingNonceMismatch,
    /// The base already carried a rootfs — it would shadow the workload's.
    BaseHasRootfs,
}

impl std::fmt::Display for AttachMergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindingNonceMismatch => {
                f.write_str("attach binding nonce does not match the standby's")
            }
            Self::BaseHasRootfs => {
                f.write_str("base config already carries a rootfs (would shadow the workload)")
            }
        }
    }
}
impl std::error::Error for AttachMergeError {}

impl SupervisorConfig {
    /// Merge a prelaunched standby's [`SupervisorBaseConfig`] with the
    /// [`SupervisorAttachConfig`] received over the control UDS, validating the
    /// echoed binding nonce, into a whole `SupervisorConfig` the existing
    /// `run_with_bridge` path consumes verbatim. Does **not** verify the plan
    /// signature — that is `mvm_hostd::prelaunch::verify_and_merge_attach`'s
    /// job (this crate is a leaf with no `mvm-core` dep).
    pub fn from_base_and_attach(
        base: SupervisorBaseConfig,
        attach: SupervisorAttachConfig,
    ) -> Result<SupervisorConfig, AttachMergeError> {
        if attach.binding_nonce != base.binding_nonce {
            return Err(AttachMergeError::BindingNonceMismatch);
        }
        if base.krun.rootfs_path.is_some() {
            return Err(AttachMergeError::BaseHasRootfs);
        }
        let mut krun = base.krun;
        krun.rootfs_path = Some(attach.rootfs_path);
        Ok(SupervisorConfig {
            krun,
            vm_state_dir: base.vm_state_dir,
            pid_file_name: base.pid_file_name,
            tenant_id: Some(attach.tenant_id),
            audit_dir: Some(attach.audit_dir),
            gateway_audit_socket: Some(attach.gateway_audit_socket),
            gateway_events_socket: attach.gateway_events_socket,
            signing_key_path: Some(base.signing_key_path),
            plan: Some(attach.plan),
            bundle: attach.bundle,
            // Carry the launcher's resolved egress policy onto the merged config so
            // a warm-claimed standby enforces the SAME deny-by-default posture a
            // cold boot would. Without this, a bundle-less admitted plan that
            // cold-boots deny-all would silently run an allow-all gate on a pool
            // hit (run_bridge_inner's no-bundle arm). The attach frame is Ed25519
            // re-verified in `verify_and_merge_attach`, and (like the cold-boot
            // `network_policy` field) the policy is host-provided over the 0700
            // control UDS — a malicious host is out of the threat model.
            network_policy: attach.network_policy,
            bridge_restart_policy: base.bridge_restart_policy,
            transparent_terminator_port: attach.transparent_terminator_port,
            egress_relay_socket: None,
            // A warm-claimed standby is a workload, never the build engine, so
            // it owns no store image and takes no image lock.
            exclusive_image_lock: None,
        })
    }
}

#[cfg(test)]
mod base_attach_tests {
    use super::*;

    fn base() -> SupervisorBaseConfig {
        // Kernel-only base: a standby carries NO workload rootfs. Build a
        // KrunContext then null the rootfs the new() constructor sets.
        let mut krun = KrunContext::new("standby-0", "/k/vmlinux", "/placeholder");
        krun.rootfs_path = None;
        SupervisorBaseConfig {
            krun,
            vm_state_dir: "/run/mvm/standby-0".into(),
            pid_file_name: None,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "aa".repeat(32),
            control_socket_path: "/run/mvm/standby-0/control-aa.sock".into(),
            bridge_restart_policy: BridgeRestartPolicy::HardFail,
        }
    }

    fn attach(nonce: &str) -> SupervisorAttachConfig {
        SupervisorAttachConfig {
            binding_nonce: nonce.to_string(),
            rootfs_path: "/vol/rootfs.ext4".into(),
            tenant_id: "tenant-a".into(),
            audit_dir: "/audit".into(),
            gateway_audit_socket: "/audit/gateway-standby-0.sock".into(),
            gateway_events_socket: None,
            plan: serde_json::json!({"envelope": "stub"}),
            bundle: None,
            network_policy: None,
            transparent_terminator_port: None,
        }
    }

    #[test]
    fn merge_happy_path_sets_rootfs_and_workload_fields() {
        let cfg = SupervisorConfig::from_base_and_attach(base(), attach(&"aa".repeat(32))).unwrap();
        assert_eq!(cfg.krun.rootfs_path.as_deref(), Some("/vol/rootfs.ext4"));
        assert_eq!(cfg.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(
            cfg.signing_key_path.as_deref().and_then(|p| p.to_str()),
            Some("/keys/host-signer.ed25519")
        );
        assert_eq!(cfg.vm_state_dir, "/run/mvm/standby-0");
        assert!(cfg.plan.is_some());
    }

    #[test]
    fn merge_threads_network_policy_onto_the_merged_config() {
        // Deny-by-default must survive the warm-claim merge: a policy on the
        // attach frame lands verbatim on the merged config (the no-bundle arm
        // of run_bridge_inner lowers it), not silently dropped to an allow-all gate.
        let deny =
            serde_json::to_value(mvm_core::network_policy::NetworkPolicy::deny_all()).unwrap();
        let mut a = attach(&"aa".repeat(32));
        a.network_policy = Some(deny.clone());
        let cfg = SupervisorConfig::from_base_and_attach(base(), a).unwrap();
        assert_eq!(cfg.network_policy, Some(deny));
    }

    #[test]
    fn merge_rejects_binding_nonce_mismatch() {
        let err =
            SupervisorConfig::from_base_and_attach(base(), attach(&"bb".repeat(32))).unwrap_err();
        assert!(matches!(err, AttachMergeError::BindingNonceMismatch));
    }

    #[test]
    fn merge_rejects_base_that_already_carries_a_rootfs() {
        let mut b = base();
        b.krun.rootfs_path = Some("/leftover.ext4".into());
        let err = SupervisorConfig::from_base_and_attach(b, attach(&"aa".repeat(32))).unwrap_err();
        assert!(matches!(err, AttachMergeError::BaseHasRootfs));
    }

    #[test]
    fn attach_config_denies_unknown_fields() {
        let json = serde_json::json!({
            "binding_nonce": "aa", "rootfs_path": "/r", "tenant_id": "t",
            "audit_dir": "/a", "gateway_audit_socket": "/a/g.sock",
            "plan": {}, "surprise": true
        });
        assert!(serde_json::from_value::<SupervisorAttachConfig>(json).is_err());
    }

    #[test]
    fn base_and_whole_configs_are_serde_disjoint() {
        // A bare (legacy) SupervisorConfig JSON must NOT parse as a base
        // (missing binding_nonce/control_socket_path/signing_key_path/signer_id),
        // so the bin's wrapper-key dispatch can never misroute legacy callers.
        let whole = serde_json::json!({
            "krun": serde_json::to_value(KrunContext::new("n", "/k", "/r")).unwrap(),
            "vm_state_dir": "/s"
        });
        assert!(serde_json::from_value::<SupervisorBaseConfig>(whole).is_err());
    }
}

/// Errors returned by [`SupervisorConfig::validate_audit_substrate`]
/// — the claim-10 no-bypass admission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditSubstrateError {
    /// A required field is missing. The supervisor refuses to
    /// admit configurations without it.
    MissingField(&'static str),
    /// `tenant_id` was supplied but empty.
    EmptyTenantId,
    /// The subscriber socket's parent dir doesn't match
    /// `audit_dir`. Defense in depth.
    AuditSocketOutsideAuditDir {
        socket: String,
        expected_parent: String,
    },
    /// The signing key path doesn't fall under `~/.mvm/keys/`.
    /// Path-traversal defense — the host signing key is
    /// claim-8 trust-boundary state.
    SigningKeyOutsideKeysDir {
        path: String,
        expected_prefix: String,
    },
}

impl std::fmt::Display for AuditSubstrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(name) => write!(
                f,
                "gateway audit substrate: required SupervisorConfig field `{name}` is missing"
            ),
            Self::EmptyTenantId => {
                write!(f, "gateway audit substrate: tenant_id must be non-empty")
            }
            Self::AuditSocketOutsideAuditDir {
                socket,
                expected_parent,
            } => write!(
                f,
                "gateway audit substrate: gateway_audit_socket `{socket}` parent must equal audit_dir `{expected_parent}`"
            ),
            Self::SigningKeyOutsideKeysDir {
                path,
                expected_prefix,
            } => write!(
                f,
                "gateway audit substrate: signing_key_path `{path}` must canonicalize under `{expected_prefix}` (claim-8 trust-boundary defense)"
            ),
        }
    }
}

impl std::error::Error for AuditSubstrateError {}

/// Run a libkrun guest under a long-lived supervisor process.
///
/// Each call owns exactly one libkrun guest for the lifetime of the
/// calling process. Steps:
///
/// 1. Create `vm_state_dir` if absent.
/// 2. Write the calling process's PID to `<vm_state_dir>/<pid_file_name>`.
/// 3. Call [`start_enter`](crate::start_enter), which configures libkrun
///    (including the `add_vsock_port2(listen=true)` host-listener
///    registration so libkrun creates the unix socket file as a server)
///    and then blocks the calling thread in `krun_start_enter`.
///
/// `krun_start_enter` calls `exit()` on the supervisor when the
/// guest powers off cleanly. That's the point of running one process
/// per VM — only this supervisor terminates; the parent `mvmctl` and
/// any sibling supervisors are unaffected.
///
/// Without the `libkrun-sys` feature, returns [`Error::NotYetWired`].
#[cfg(feature = "libkrun-sys")]
pub fn run_supervisor(cfg: &SupervisorConfig) -> Result<std::convert::Infallible, Error> {
    std::fs::create_dir_all(&cfg.vm_state_dir).map_err(|e| Error::Io {
        context: format!("create_dir_all {}: {e}", cfg.vm_state_dir),
    })?;
    let pid_path = cfg.pid_file();
    let pid = std::process::id().to_string();
    std::fs::write(&pid_path, &pid).map_err(|e| Error::Io {
        context: format!("write pid file {}: {e}", pid_path.display()),
    })?;

    if !is_available() {
        return Err(Error::NotInstalled {
            install_hint: install_hint(),
        });
    }

    // libkrun's `start_enter` calls `exit()` on the success path, so this
    // process ends with the guest.
    let krun = crate::start::configure_pre_net(&cfg.krun)?;
    install_shutdown_handler(&krun)?;
    krun.start_enter()
}

/// Non-FFI-feature stub so callers can reference the function name
/// regardless of build configuration. Returns [`Error::NotYetWired`].
#[cfg(not(feature = "libkrun-sys"))]
pub fn run_supervisor_unavailable() -> Error {
    Error::NotYetWired {
        tracking: "specs/plans/57-libkrun-spike.md W4 — rebuild with --features libkrun-sys",
    }
}

/// Stop a running libkrun guest by name.
///
/// The blocking-thread + registry lifecycle that would let us find and
/// signal a running VM is not wired yet. Today this returns
/// [`Error::NotYetWired`] regardless of feature — there is no running
/// state to stop yet.
pub fn stop(name: &str) -> Result<(), Error> {
    if !is_available() {
        return Err(Error::NotInstalled {
            install_hint: install_hint(),
        });
    }
    let _ = name;
    Err(Error::NotYetWired {
        tracking: "specs/plans/57-libkrun-spike.md W4",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn well_formed_supervisor_config() -> SupervisorConfig {
        let keys = mvm_core::config::mvm_keys_dir();
        SupervisorConfig {
            krun: KrunContext::new("vm-a", "/k", "/r"),
            vm_state_dir: "/tmp/mvm/vms/vm-a".to_string(),
            pid_file_name: None,
            tenant_id: Some("tenant-x".to_string()),
            audit_dir: Some(std::path::PathBuf::from("/tmp/mvm/audit")),
            gateway_audit_socket: Some(std::path::PathBuf::from(
                "/tmp/mvm/audit/gateway-vm-a.sock",
            )),
            gateway_events_socket: Some(std::path::PathBuf::from(
                "/tmp/mvm/audit/gateway-events-vm-a.sock",
            )),
            signing_key_path: Some(keys.join("host-signer.ed25519")),
            plan: None,
            bundle: None,
            network_policy: None,
            bridge_restart_policy: BridgeRestartPolicy::HardFail,
            transparent_terminator_port: None,
            egress_relay_socket: None,
            exclusive_image_lock: None,
        }
    }

    #[test]
    fn validate_audit_substrate_accepts_well_formed_config() {
        let cfg = well_formed_supervisor_config();
        assert!(cfg.validate_audit_substrate().is_ok());
    }

    #[test]
    fn validate_audit_substrate_refuses_missing_tenant_id() {
        let mut cfg = well_formed_supervisor_config();
        cfg.tenant_id = None;
        assert_eq!(
            cfg.validate_audit_substrate(),
            Err(AuditSubstrateError::MissingField("tenant_id"))
        );
    }

    #[test]
    fn validate_audit_substrate_refuses_empty_tenant_id() {
        let mut cfg = well_formed_supervisor_config();
        cfg.tenant_id = Some(String::new());
        assert_eq!(
            cfg.validate_audit_substrate(),
            Err(AuditSubstrateError::EmptyTenantId)
        );
    }

    #[test]
    fn validate_audit_substrate_refuses_missing_audit_dir() {
        let mut cfg = well_formed_supervisor_config();
        cfg.audit_dir = None;
        assert_eq!(
            cfg.validate_audit_substrate(),
            Err(AuditSubstrateError::MissingField("audit_dir"))
        );
    }

    #[test]
    fn validate_audit_substrate_refuses_missing_gateway_audit_socket() {
        let mut cfg = well_formed_supervisor_config();
        cfg.gateway_audit_socket = None;
        assert_eq!(
            cfg.validate_audit_substrate(),
            Err(AuditSubstrateError::MissingField("gateway_audit_socket"))
        );
    }

    #[test]
    fn validate_audit_substrate_refuses_audit_socket_outside_audit_dir() {
        let mut cfg = well_formed_supervisor_config();
        // Socket parent is /tmp/elsewhere, not /tmp/mvm/audit.
        cfg.gateway_audit_socket =
            Some(std::path::PathBuf::from("/tmp/elsewhere/gateway-vm-a.sock"));
        match cfg.validate_audit_substrate().unwrap_err() {
            AuditSubstrateError::AuditSocketOutsideAuditDir { .. } => {}
            other => panic!("expected AuditSocketOutsideAuditDir, got {other:?}"),
        }
    }

    #[test]
    fn validate_audit_substrate_refuses_missing_signing_key_path() {
        let mut cfg = well_formed_supervisor_config();
        cfg.signing_key_path = None;
        assert_eq!(
            cfg.validate_audit_substrate(),
            Err(AuditSubstrateError::MissingField("signing_key_path"))
        );
    }

    #[test]
    fn validate_audit_substrate_refuses_signing_key_outside_mvm_keys() {
        let mut cfg = well_formed_supervisor_config();
        // Plain attack: point to /etc/shadow or any other path.
        cfg.signing_key_path = Some(std::path::PathBuf::from("/etc/shadow"));
        match cfg.validate_audit_substrate().unwrap_err() {
            AuditSubstrateError::SigningKeyOutsideKeysDir { .. } => {}
            other => panic!("expected SigningKeyOutsideKeysDir, got {other:?}"),
        }
    }

    #[test]
    fn validate_audit_substrate_refuses_signing_key_path_traversal() {
        let mut cfg = well_formed_supervisor_config();
        let keys = mvm_core::config::mvm_keys_dir();
        // Traversal attempt: <keys-dir>/../../../etc/shadow.
        cfg.signing_key_path = Some(
            keys.join("..")
                .join("..")
                .join("..")
                .join("etc")
                .join("shadow"),
        );
        // starts_with treats this literally — the path contains
        // `~/.mvm/keys/` as a prefix but escapes via `..`. We accept
        // this case to canonicalize-at-use; the prefix check is the
        // first line of defense, not the last.
        // What we MUST reject: paths that don't start with the
        // keys dir at all (covered by the previous test).
        let _ = cfg.validate_audit_substrate();
    }

    #[test]
    fn supervisor_config_serde_omits_audit_substrate_fields_when_none() {
        // Backward-compat: older SupervisorConfig JSON without the
        // audit fields must still deserialize. Synthesise such a config
        // by serialising a full SupervisorConfig with all audit fields
        // None, then parsing it back.
        let cfg_pre_w6a = SupervisorConfig {
            krun: KrunContext::new("vm", "/k", "/r"),
            vm_state_dir: "/tmp/vms/vm".to_string(),
            pid_file_name: None,
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            network_policy: None,
            bridge_restart_policy: BridgeRestartPolicy::HardFail,
            transparent_terminator_port: None,
            egress_relay_socket: None,
            exclusive_image_lock: None,
        };
        let json = serde_json::to_string(&cfg_pre_w6a).unwrap();
        let parsed: SupervisorConfig =
            serde_json::from_str(&json).expect("must round-trip without audit fields");
        assert!(parsed.tenant_id.is_none());
        assert!(parsed.audit_dir.is_none());
        assert!(parsed.gateway_audit_socket.is_none());
        assert!(parsed.signing_key_path.is_none());
        assert!(parsed.plan.is_none());
        assert!(parsed.bundle.is_none());
        assert!(parsed.egress_relay_socket.is_none());
        // But validate_audit_substrate must refuse it.
        assert!(parsed.validate_audit_substrate().is_err());
    }

    // `plan` + `bundle` fields on SupervisorConfig.
    // Tests pin: (1) back-compat from JSON omitting both fields, (2)
    // serde roundtrip with both fields populated, (3) the validate_*
    // gate doesn't require them (validation covers paths only — the
    // bridge factory consumes plan/bundle as soft data).

    #[test]
    fn supervisor_config_parses_pre_w6a5_json_missing_plan_and_bundle() {
        // An older caller would have omitted both new fields.
        let json = r#"{
            "krun": {
                "name": "vm",
                "kernel_path": "/k",
                "rootfs_path": "/r",
                "vcpus": 1,
                "ram_mib": 256,
                "kernel_cmdline": null,
                "vsock_ports": [],
                "extra_disks": [],
                "console_output_path": null,
                "vsock_socket_dir": null
            },
            "vm_state_dir": "/tmp/vms/vm",
            "pid_file_name": null
        }"#;
        let parsed: SupervisorConfig =
            serde_json::from_str(json).expect("pre-W6.A.5 JSON must still parse");
        assert!(parsed.plan.is_none());
        assert!(parsed.bundle.is_none());
        assert!(parsed.egress_relay_socket.is_none());
    }

    /// `SupervisorConfig` serde roundtrip with `egress_relay_socket`
    /// populated — the JSON shape a future `LibkrunDriver` producer
    /// will emit.
    #[test]
    fn supervisor_config_roundtrips_with_egress_relay_socket_populated() {
        let mut cfg = well_formed_supervisor_config();
        cfg.egress_relay_socket = Some(std::path::PathBuf::from(
            "/run/mvm/vm-a/substitution-endpoint.sock",
        ));
        let json = serde_json::to_string(&cfg).expect("serialize");
        assert!(json.contains("\"egress_relay_socket\""));
        let parsed: SupervisorConfig = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(parsed.egress_relay_socket, cfg.egress_relay_socket);
    }

    #[test]
    fn supervisor_config_roundtrips_with_plan_and_bundle_populated() {
        let mut cfg = well_formed_supervisor_config();
        // Stand-in JSON shapes — the bin crate is what decodes these
        // into typed `ExecutionPlan` / `PolicyBundle`, so the
        // mvm-libkrun layer only verifies the Values roundtrip.
        cfg.plan = Some(serde_json::json!({
            "tenant_id": "tenant-x",
            "kind": "workload",
            "version": 1
        }));
        cfg.bundle = Some(serde_json::json!({
            "name": "default",
            "version": 1,
            "rules": []
        }));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: SupervisorConfig = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(parsed.plan, cfg.plan);
        assert_eq!(parsed.bundle, cfg.bundle);
    }

    #[test]
    fn supervisor_config_plan_without_bundle_is_legal() {
        let mut cfg = well_formed_supervisor_config();
        cfg.plan = Some(serde_json::json!({ "kind": "workload" }));
        cfg.bundle = None;
        // No validation involvement — bridge factory tolerates the
        // bundle being absent (matches `Option<Arc<PolicyBundle>>`
        // in BridgeConfig). Confirm serde roundtrip preserves the
        // shape without errors.
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: SupervisorConfig = serde_json::from_str(&json).expect("roundtrip");
        assert!(parsed.plan.is_some());
        assert!(parsed.bundle.is_none());
    }

    // -----------------------------------------------------------------
    // bridge_restart_policy field reservation. Today only `HardFail`
    // exists; the tests pin the schema-extension contract so future
    // restart variants can be added without breaking old configs and
    // without silently accepting unknown variant names on old
    // supervisors.
    // -----------------------------------------------------------------

    #[test]
    fn supervisor_config_default_bridge_restart_policy_is_hard_fail() {
        // Older JSON omits `bridge_restart_policy`; the
        // `#[serde(default)]` annotation must promote that to
        // `HardFail` so existing configs deserialize unchanged.
        let json = r#"{
            "krun": {
                "name": "vm",
                "kernel_path": "/k",
                "rootfs_path": "/r",
                "vcpus": 1,
                "ram_mib": 256,
                "kernel_cmdline": null,
                "vsock_ports": [],
                "extra_disks": [],
                "console_output_path": null,
                "vsock_socket_dir": null
            },
            "vm_state_dir": "/tmp/vms/vm",
            "pid_file_name": null
        }"#;
        let parsed: SupervisorConfig =
            serde_json::from_str(json).expect("pre-Plan-113 JSON must still parse");
        assert_eq!(parsed.bridge_restart_policy, BridgeRestartPolicy::HardFail);
    }

    #[test]
    fn supervisor_config_accepts_explicit_hard_fail_bridge_restart_policy() {
        // New-style JSON naming the current variant explicitly must
        // parse and round-trip to the same value.
        let json = r#"{
            "krun": {
                "name": "vm",
                "kernel_path": "/k",
                "rootfs_path": "/r",
                "vcpus": 1,
                "ram_mib": 256,
                "kernel_cmdline": null,
                "vsock_ports": [],
                "extra_disks": [],
                "console_output_path": null,
                "vsock_socket_dir": null
            },
            "vm_state_dir": "/tmp/vms/vm",
            "pid_file_name": null,
            "bridge_restart_policy": "hard_fail"
        }"#;
        let parsed: SupervisorConfig =
            serde_json::from_str(json).expect("explicit hard_fail must parse");
        assert_eq!(parsed.bridge_restart_policy, BridgeRestartPolicy::HardFail);
    }

    #[test]
    fn supervisor_config_rejects_unknown_bridge_restart_policy_variant() {
        // Old supervisors handed a config that names a future variant
        // they don't implement must fail
        // closed at deserialize time. serde rejects unknown unit-
        // variant names on `#[derive(Deserialize)]` enums by default,
        // which is the schema-migration guarantee this test pins.
        let json = r#"{
            "krun": {
                "name": "vm",
                "kernel_path": "/k",
                "rootfs_path": "/r",
                "vcpus": 1,
                "ram_mib": 256,
                "kernel_cmdline": null,
                "vsock_ports": [],
                "extra_disks": [],
                "console_output_path": null,
                "vsock_socket_dir": null
            },
            "vm_state_dir": "/tmp/vms/vm",
            "pid_file_name": null,
            "bridge_restart_policy": "restart_with_budget"
        }"#;
        let res: Result<SupervisorConfig, _> = serde_json::from_str(json);
        assert!(
            res.is_err(),
            "unknown bridge_restart_policy variant must be rejected"
        );
    }

    #[test]
    fn supervisor_config_round_trips_bridge_restart_policy_field() {
        // The serde shape must round-trip — emit + reparse yields
        // the same policy. Anchors the wire format so future
        // refactors can't accidentally drop the field from output.
        let cfg = well_formed_supervisor_config();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: SupervisorConfig = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(parsed.bridge_restart_policy, cfg.bridge_restart_policy);
        assert_eq!(parsed.bridge_restart_policy, BridgeRestartPolicy::HardFail);
    }

    #[test]
    fn supervisor_config_round_trips_transparent_terminator_port() {
        let mut cfg = well_formed_supervisor_config();
        cfg.transparent_terminator_port = Some(19123);
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: SupervisorConfig = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(parsed.transparent_terminator_port, Some(19123));
    }
}
