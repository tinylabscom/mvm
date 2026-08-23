//! Profile classification for `GuestRequest`: `RequestClass`, the
//! verb/response-contract projection, and the `SealedProd`/`Dev`
//! eligibility gate the dispatcher checks before running a handler.

use super::*;
use mvm_core::security::AgentProfile;

/// Coarse profile-eligibility class for each `GuestRequest` variant.
///
/// Wire types are compiled into every agent build; this classifier
/// is the dispatcher-side gate that rejects out-of-profile verbs
/// *before* the per-variant handler runs. DevOnly handlers are compiled into
/// the universal artifact, but remain unreachable until this gate and the
/// signed-grant check both authorize the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestClass {
    /// Allowed under `SealedProd` and `Dev` profiles. Includes the
    /// lifecycle, entrypoint-status, sleep/wake, mount-volume, and
    /// idle-timeout verbs. Sub-policies (mount path, idle timeout
    /// scope) are enforced inside the handler.
    ProdSafe,
    /// Allowed only under `Dev`. Process RPC, filesystem RPC, console,
    /// port forwarding, shell exec, code eval.
    DevOnly,
    /// Allowed only under `Builder`. No current `GuestRequest`
    /// variant is `BuilderOnly`; the variant is reserved for forward
    /// compatibility when builder-specific verbs land on the tenant
    /// wire.
    BuilderOnly,
}

impl GuestRequest {
    /// Stable string name for the verb, used in audit logs and the
    /// `UnsupportedInProfile` rejection response. Wire-stable —
    /// renaming a verb is a breaking change.
    pub fn verb_name(&self) -> &'static str {
        self.verb().name()
    }

    /// Typed projection of this request's verb. Exhaustive — adding a
    /// `GuestRequest` variant fails to compile until mapped here, keeping
    /// `Verb` in lockstep with the wire enum.
    pub fn verb(&self) -> Verb {
        match self {
            GuestRequest::ActivateEnvironment { .. } => Verb::ActivateEnvironment,
            GuestRequest::ProtocolHello { .. } => Verb::ProtocolHello,
            GuestRequest::WorkerStatus => Verb::WorkerStatus,
            GuestRequest::SleepPrep { .. } => Verb::SleepPrep,
            GuestRequest::Wake => Verb::Wake,
            GuestRequest::Ping => Verb::Ping,
            GuestRequest::ResourceUsage => Verb::ResourceUsage,
            GuestRequest::IntegrationStatus => Verb::IntegrationStatus,
            GuestRequest::CheckpointIntegrations { .. } => Verb::CheckpointIntegrations,
            GuestRequest::ProbeStatus => Verb::ProbeStatus,
            GuestRequest::PrimedStatus => Verb::PrimedStatus,
            GuestRequest::Exec { .. } => Verb::Exec,
            GuestRequest::ExecBatch { .. } => Verb::ExecBatch,
            GuestRequest::RunEntrypoint { .. } => Verb::RunEntrypoint,
            GuestRequest::RunExtension { .. } => Verb::RunExtension,
            GuestRequest::CancelExtension { .. } => Verb::CancelExtension,
            GuestRequest::RunDetached { .. } => Verb::RunDetached,
            GuestRequest::PostRestore { .. } => Verb::PostRestore,
            GuestRequest::FsDiff => Verb::FsDiff,
            GuestRequest::StartUnixSocketForward { .. } => Verb::StartUnixSocketForward,
            GuestRequest::ConsoleOpen { .. } => Verb::ConsoleOpen,
            GuestRequest::ConsoleClose { .. } => Verb::ConsoleClose,
            GuestRequest::ConsoleResize { .. } => Verb::ConsoleResize,
            GuestRequest::EntrypointStatus => Verb::EntrypointStatus,
            GuestRequest::ReadinessStatus => Verb::ReadinessStatus,
            GuestRequest::FsRead { .. } => Verb::FsRead,
            GuestRequest::FsWrite { .. } => Verb::FsWrite,
            GuestRequest::FsList { .. } => Verb::FsList,
            GuestRequest::FsStat { .. } => Verb::FsStat,
            GuestRequest::FsMkdir { .. } => Verb::FsMkdir,
            GuestRequest::FsRemove { .. } => Verb::FsRemove,
            GuestRequest::FsMove { .. } => Verb::FsMove,
            GuestRequest::ProcStart { .. } => Verb::ProcStart,
            GuestRequest::ProcList => Verb::ProcList,
            GuestRequest::ProcSignal { .. } => Verb::ProcSignal,
            GuestRequest::ProcSendInput { .. } => Verb::ProcSendInput,
            GuestRequest::ProcWait { .. } => Verb::ProcWait,
            GuestRequest::ProcKill { .. } => Verb::ProcKill,
            GuestRequest::MountVolume { .. } => Verb::MountVolume,
            GuestRequest::UnmountVolume { .. } => Verb::UnmountVolume,
            GuestRequest::UpdateIdleTimeout { .. } => Verb::UpdateIdleTimeout,
            GuestRequest::RunCode { .. } => Verb::RunCode,
            GuestRequest::StreamInput(_) => Verb::StreamInput,
            GuestRequest::CloseStreamInput(_) => Verb::CloseStreamInput,
        }
    }

    /// The declared response contract for this request — which
    /// `GuestResponse` variant(s) answer it, unary vs streamed. See
    /// [`Verb::response_contract`].
    pub fn response_contract(&self) -> ResponseContract {
        self.verb().response_contract()
    }

    /// Profile class of this request. Exhaustive match — adding a new
    /// `GuestRequest` variant fails to compile until it is classified.
    pub fn class(&self) -> RequestClass {
        match self {
            // ProdSafe: initramfs activation + compatibility negotiation + lifecycle
            // + status + entrypoint + sleep/wake + mount-volume + idle-timeout. Volume
            // mounts are additionally constrained by
            // `MountPathPolicy` inside the handler — the gate just
            // lets the verb reach it. `ProtocolHello` remains prod-safe for
            // compatibility. The authenticated session handshake already
            // runs before dispatch on production control connections.
            GuestRequest::ActivateEnvironment { .. }
            | GuestRequest::ProtocolHello { .. }
            | GuestRequest::WorkerStatus
            | GuestRequest::SleepPrep { .. }
            | GuestRequest::Wake
            | GuestRequest::Ping
            | GuestRequest::ResourceUsage
            | GuestRequest::IntegrationStatus
            | GuestRequest::CheckpointIntegrations { .. }
            | GuestRequest::ProbeStatus
            | GuestRequest::PrimedStatus
            | GuestRequest::RunEntrypoint { .. }
            | GuestRequest::RunExtension { .. }
            | GuestRequest::CancelExtension { .. }
            | GuestRequest::PostRestore { .. }
            | GuestRequest::EntrypointStatus
            | GuestRequest::ReadinessStatus
            | GuestRequest::MountVolume { .. }
            | GuestRequest::UnmountVolume { .. }
            | GuestRequest::UpdateIdleTimeout { .. }
            // The input plane is production surface by design: a sealed
            // workload's stdin is what the host's signed grant, single-writer
            // lease and secret scan exist to police. Refusing the verb in
            // SealedProd would make the whole gate unreachable exactly where
            // it matters, leaving the dev tier as the only place input works.
            | GuestRequest::StreamInput(_)
            | GuestRequest::CloseStreamInput(_) => RequestClass::ProdSafe,

            // DevOnly: shell exec, process RPC, filesystem RPC,
            // console, port forwarding, code eval, filesystem diff.
            // Filesystem reads look benign but can leak secrets and
            // mounted-volume contents, so the entire filesystem
            // RPC surface is DevOnly in v1.
            GuestRequest::Exec { .. }
            | GuestRequest::ExecBatch { .. }
            | GuestRequest::RunDetached { .. }
            | GuestRequest::FsDiff
            | GuestRequest::StartUnixSocketForward { .. }
            | GuestRequest::ConsoleOpen { .. }
            | GuestRequest::ConsoleClose { .. }
            | GuestRequest::ConsoleResize { .. }
            | GuestRequest::FsRead { .. }
            | GuestRequest::FsWrite { .. }
            | GuestRequest::FsList { .. }
            | GuestRequest::FsStat { .. }
            | GuestRequest::FsMkdir { .. }
            | GuestRequest::FsRemove { .. }
            | GuestRequest::FsMove { .. }
            | GuestRequest::ProcStart { .. }
            | GuestRequest::ProcList
            | GuestRequest::ProcSignal { .. }
            | GuestRequest::ProcSendInput { .. }
            | GuestRequest::ProcWait { .. }
            | GuestRequest::ProcKill { .. }
            | GuestRequest::RunCode { .. } => RequestClass::DevOnly,
        }
    }

    /// Whether this request is allowed under `profile`.
    ///
    /// Profile rules:
    /// - `SealedProd` allows only `ProdSafe`.
    /// - `Dev` allows `ProdSafe` and `DevOnly` (a superset).
    /// - `Builder` allows only `BuilderOnly` — today the builder
    ///   agent speaks `HostVmRequest`, so `GuestRequest` reaching
    ///   a `Builder`-profile agent is a configuration error.
    pub fn allowed_in(&self, profile: AgentProfile) -> bool {
        matches!(
            (self.class(), profile),
            (
                RequestClass::ProdSafe,
                AgentProfile::SealedProd | AgentProfile::Dev
            ) | (RequestClass::DevOnly, AgentProfile::Dev)
                | (RequestClass::BuilderOnly, AgentProfile::Builder)
        )
    }

    /// The kebab `kind_name()`s of every `ProdSafe` control verb —
    /// the candidate members of an `agent_verbs` grant. Single source
    /// of truth; the classification guard test keeps this in lockstep
    /// with `class()`.
    pub fn prod_safe_verb_names() -> &'static [&'static str] {
        &[
            "activate-environment",
            "protocol-hello",
            "ping",
            "resource-usage",
            "readiness-status",
            "worker-status",
            "sleep-prep",
            "wake",
            "integration-status",
            "checkpoint-integrations",
            "probe-status",
            "primed-status",
            "post-restore",
            "entrypoint-status",
            "run-entrypoint",
            "run-extension",
            "cancel-extension",
            "stream-input",
            "close-stream-input",
            "mount-volume",
            "unmount-volume",
            "update-idle-timeout",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::stream::input::{CloseInput, InputFrame};

    #[test]
    fn run_detached_classifies_dev_only() {
        let req = GuestRequest::RunDetached {
            argv: vec!["/bin/true".into()],
            env: vec![],
        };
        assert!(matches!(req.class(), RequestClass::DevOnly));
        assert_eq!(req.kind_name(), "run-detached");
        assert!(!req.allowed_in(AgentProfile::SealedProd));
        assert!(req.allowed_in(AgentProfile::Dev));
    }

    // ========================================================================
    // profile classifier
    // ========================================================================

    /// One representative value per `GuestRequest` variant. Both the
    /// classification test and the `prod_safe_verb_names` guard share
    /// this list — a single source of truth that must grow with the enum.
    fn every_guest_request_variant() -> Vec<GuestRequest> {
        vec![
            GuestRequest::ProtocolHello {
                host_protocol_version: 1,
                min_supported_version: 1,
                host_version: "test".into(),
                requested_capabilities: vec![],
            },
            GuestRequest::WorkerStatus,
            GuestRequest::SleepPrep {
                drain_timeout_secs: 0,
            },
            GuestRequest::Wake,
            GuestRequest::Ping,
            GuestRequest::ResourceUsage,
            GuestRequest::IntegrationStatus,
            GuestRequest::CheckpointIntegrations {
                integrations: vec![],
            },
            GuestRequest::ProbeStatus,
            GuestRequest::Exec {
                command: "x".into(),
                stdin: None,
                timeout_secs: None,
            },
            GuestRequest::RunEntrypoint {
                stdin: vec![],
                timeout_secs: 1,
                env: vec![],
                stream_input: false,
            },
            GuestRequest::StreamInput(InputFrame {
                seq: 0,
                payload: vec![b'x'],
            }),
            GuestRequest::CloseStreamInput(CloseInput::default()),
            GuestRequest::RunDetached {
                argv: vec!["/bin/sh".into(), "-lc".into(), "true".into()],
                env: vec![],
            },
            GuestRequest::PostRestore {
                token: [0u8; mvm_core::crypto::vmgenid::GENID_BYTES],
                hostname: None,
                host_epoch_secs: None,
                grant_envelope: None,
            },
            GuestRequest::FsDiff,
            GuestRequest::StartUnixSocketForward {
                guest_path: "/run/mvm/forward.sock".to_string(),
                host_vsock_port: BROKER_PORT,
                socket_mode: 0o600,
            },
            GuestRequest::ConsoleOpen {
                cols: 1,
                rows: 1,
                env: Vec::new(),
                argv: Vec::new(),
            },
            GuestRequest::ConsoleClose { session_id: 1 },
            GuestRequest::ConsoleResize {
                session_id: 1,
                cols: 1,
                rows: 1,
            },
            GuestRequest::EntrypointStatus,
            GuestRequest::ReadinessStatus,
            GuestRequest::FsRead {
                path: "/x".into(),
                offset: None,
                length: 1,
                follow_symlinks: true,
            },
            GuestRequest::FsWrite {
                path: "/x".into(),
                content: vec![],
                mode: 0,
                create_parents: false,
                follow_symlinks: false,
                offset: None,
                truncate: true,
            },
            GuestRequest::FsList {
                path: "/x".into(),
                follow_symlinks: true,
            },
            GuestRequest::FsStat {
                path: "/x".into(),
                follow_symlinks: true,
            },
            GuestRequest::FsMkdir {
                path: "/x".into(),
                mode: 0,
                parents: false,
            },
            GuestRequest::FsRemove {
                path: "/x".into(),
                recursive: false,
                follow_symlinks: false,
            },
            GuestRequest::FsMove {
                from: "/x".into(),
                to: "/y".into(),
                follow_symlinks: false,
            },
            GuestRequest::ProcStart {
                argv: vec!["/x".into()],
                env: Default::default(),
                cwd: None,
                stdin: vec![],
                timeout_secs: None,
            },
            GuestRequest::ProcList,
            GuestRequest::ProcSignal {
                pid_token: "t".into(),
                signum: 15,
            },
            GuestRequest::ProcSendInput {
                pid_token: "t".into(),
                bytes: vec![],
            },
            GuestRequest::ProcWait {
                pid_token: "t".into(),
                timeout_secs: None,
            },
            GuestRequest::ProcKill {
                pid_token: "t".into(),
            },
            GuestRequest::MountVolume {
                volume_name: "v".into(),
                guest_path: "/x".into(),
                read_only: true,
            },
            GuestRequest::UnmountVolume {
                guest_path: "/x".into(),
                force: false,
            },
            GuestRequest::UpdateIdleTimeout { secs: 0 },
            GuestRequest::RunCode {
                code: "x".into(),
                timeout_secs: Some(1),
            },
            GuestRequest::PrimedStatus,
            GuestRequest::ExecBatch {
                stages: vec![],
                commands: vec![],
                timeout_secs: None,
            },
        ]
    }

    /// Every `GuestRequest` variant must classify as either `ProdSafe`
    /// or `DevOnly` today. Compile-fail when a new variant is added
    /// without being classified — the exhaustive match inside
    /// `class()` guarantees that, and this test fails closed if the
    /// variant ever lands in an unexpected class.
    #[test]
    fn test_request_class_coverage_matches_sealed_prod_allowlist() {
        let prod_safe_verbs: &[&str] = &[
            "ProtocolHello",
            "WorkerStatus",
            "SleepPrep",
            "Wake",
            "Ping",
            "ResourceUsage",
            "IntegrationStatus",
            "CheckpointIntegrations",
            "ProbeStatus",
            "PrimedStatus",
            "RunEntrypoint",
            "StreamInput",
            "CloseStreamInput",
            "PostRestore",
            "EntrypointStatus",
            "ReadinessStatus",
            "MountVolume",
            "UnmountVolume",
            "UpdateIdleTimeout",
        ];

        let all = every_guest_request_variant();

        // Every variant has a stable verb_name; that name appears in
        // exactly one of the two classification buckets.
        for req in &all {
            let name = req.verb_name();
            let in_prod = prod_safe_verbs.contains(&name);
            match req.class() {
                RequestClass::ProdSafe => assert!(
                    in_prod,
                    "{name}: classified ProdSafe but missing from SealedProd allowlist"
                ),
                RequestClass::DevOnly => assert!(
                    !in_prod,
                    "{name}: classified DevOnly but present in SealedProd allowlist"
                ),
                RequestClass::BuilderOnly => {
                    panic!("{name}: no GuestRequest variant should be BuilderOnly yet")
                }
            }
        }

        // The allowlist itself stays anchored: every prod-safe verb
        // shows up in `all` above, so renaming a variant trips this
        // assertion too.
        let names: Vec<&'static str> = all.iter().map(|r| r.verb_name()).collect();
        for v in prod_safe_verbs {
            assert!(
                names.contains(v),
                "SealedProd verb {v} missing from coverage"
            );
        }
    }

    #[test]
    fn prod_safe_verb_names_matches_classification() {
        let listed: std::collections::BTreeSet<&str> = GuestRequest::prod_safe_verb_names()
            .iter()
            .copied()
            .collect();
        for req in every_guest_request_variant() {
            let name = req.kind_name();
            let is_prod = matches!(req.class(), RequestClass::ProdSafe);
            assert_eq!(
                listed.contains(name),
                is_prod,
                "{name}: listed={} but class ProdSafe={}",
                listed.contains(name),
                is_prod
            );
        }
        // No duplicates, all non-empty.
        assert_eq!(
            listed.len(),
            GuestRequest::prod_safe_verb_names().len(),
            "duplicate in prod_safe_verb_names"
        );
        assert!(
            GuestRequest::prod_safe_verb_names()
                .iter()
                .all(|n| !n.is_empty())
        );
    }

    #[test]
    fn test_sealed_prod_rejects_dev_only_verbs() {
        let dev_only_samples = [
            GuestRequest::Exec {
                command: "x".into(),
                stdin: None,
                timeout_secs: None,
            },
            GuestRequest::ConsoleOpen {
                cols: 80,
                rows: 24,
                env: Vec::new(),
                argv: Vec::new(),
            },
            GuestRequest::ProcStart {
                argv: vec!["/x".into()],
                env: Default::default(),
                cwd: None,
                stdin: vec![],
                timeout_secs: None,
            },
            GuestRequest::RunCode {
                code: "print(1)".into(),
                timeout_secs: Some(1),
            },
            GuestRequest::FsWrite {
                path: "/x".into(),
                content: vec![],
                mode: 0,
                create_parents: false,
                follow_symlinks: false,
                offset: None,
                truncate: true,
            },
            GuestRequest::FsRead {
                path: "/x".into(),
                offset: None,
                length: 1,
                follow_symlinks: true,
            },
        ];

        for req in &dev_only_samples {
            assert!(
                !req.allowed_in(AgentProfile::SealedProd),
                "{} should be rejected in SealedProd",
                req.verb_name()
            );
            assert!(
                req.allowed_in(AgentProfile::Dev),
                "{} should be allowed in Dev",
                req.verb_name()
            );
            assert!(
                !req.allowed_in(AgentProfile::Builder),
                "{} should not be allowed in Builder",
                req.verb_name()
            );
        }
    }

    #[test]
    fn test_sealed_prod_accepts_prod_safe_verbs() {
        let prod_safe_samples = [
            GuestRequest::Ping,
            GuestRequest::WorkerStatus,
            GuestRequest::EntrypointStatus,
            GuestRequest::RunEntrypoint {
                stdin: vec![],
                timeout_secs: 60,
                env: vec![],
                stream_input: false,
            },
            // A sealed workload's stdin is exactly what the host gate polices;
            // refusing the verb here would put the gate out of reach.
            GuestRequest::StreamInput(InputFrame {
                seq: 0,
                payload: vec![b'x'],
            }),
            GuestRequest::CloseStreamInput(CloseInput::default()),
            GuestRequest::SleepPrep {
                drain_timeout_secs: 5,
            },
            GuestRequest::Wake,
            GuestRequest::PostRestore {
                token: [0u8; mvm_core::crypto::vmgenid::GENID_BYTES],
                hostname: None,
                host_epoch_secs: None,
                grant_envelope: None,
            },
            GuestRequest::UpdateIdleTimeout { secs: 600 },
            GuestRequest::MountVolume {
                volume_name: "v".into(),
                guest_path: "/data".into(),
                read_only: true,
            },
            GuestRequest::UnmountVolume {
                guest_path: "/data".into(),
                force: false,
            },
        ];

        for req in &prod_safe_samples {
            assert!(
                req.allowed_in(AgentProfile::SealedProd),
                "{} should be allowed in SealedProd",
                req.verb_name()
            );
            assert!(
                req.allowed_in(AgentProfile::Dev),
                "{} should be allowed in Dev (Dev ⊃ SealedProd)",
                req.verb_name()
            );
        }
    }

    // ========================================================================
    // readiness model
    // ========================================================================

    #[test]
    fn test_readiness_status_classifies_prod_safe() {
        // `ReadinessStatus` must respond from sealed-prod images
        // even before entrypoint validation completes — that's the
        // whole point of the verb. If a future refactor downgrades
        // it to DevOnly, this test fails loud.
        let req = GuestRequest::ReadinessStatus;
        assert_eq!(req.class(), RequestClass::ProdSafe);
        assert!(req.allowed_in(AgentProfile::SealedProd));
        assert!(req.allowed_in(AgentProfile::Dev));
        assert!(!req.allowed_in(AgentProfile::Builder));
        assert_eq!(req.verb_name(), "ReadinessStatus");
    }

    #[test]
    fn exec_batch_request_roundtrips_and_classifies() {
        let req = GuestRequest::ExecBatch {
            stages: vec![StageFile {
                path: "/tmp/m.rs".to_string(),
                content: b"fn main(){}".to_vec(),
                mode: 0o644,
            }],
            commands: vec![vec!["rustc".to_string(), "/tmp/m.rs".to_string()]],
            timeout_secs: Some(30),
        };
        let back: GuestRequest =
            serde_json::from_slice(&serde_json::to_vec(&req).unwrap()).unwrap();
        assert!(matches!(
            back,
            GuestRequest::ExecBatch { ref stages, ref commands, timeout_secs: Some(30) }
                if stages.len() == 1 && commands == &[vec!["rustc".to_string(), "/tmp/m.rs".to_string()]]
        ));
        // Verb, name, dev-only class, and the unary ExecBatchResult contract.
        assert_eq!(req.verb(), Verb::ExecBatch);
        assert_eq!(req.kind_name(), "exec-batch");
        assert_eq!(req.class(), RequestClass::DevOnly);
        let contract = req.response_contract();
        assert_eq!(contract.kind, ResponseKind::Unary);
        assert_eq!(contract.responses, &[ResponseVariant::ExecBatchResult]);
    }

    #[test]
    fn verb_projection_matches_wire_verb_name() {
        let req = GuestRequest::Ping;
        assert_eq!(req.verb(), Verb::Ping);
        assert_eq!(req.verb().name(), req.verb_name());
    }

    #[test]
    fn activate_environment_is_prod_safe_and_control_plane() {
        use crate::vsock::{ActivateEnvironment, RootfsConfig, RuntimeOverlayConfig, VolumeConfig};
        let req = GuestRequest::ActivateEnvironment(ActivateEnvironment {
            rootfs: RootfsConfig {
                data_dev: "/dev/vda".to_string(),
                hash_dev: Some("/dev/vdb".to_string()),
                roothash: Some("a".repeat(64)),
                virtiofs_tag: None,
                in_place: false,
            },
            runtime: Some(RuntimeOverlayConfig {
                data_dev: "/dev/vdc".to_string(),
                hash_dev: "/dev/vdd".to_string(),
                roothash: "b".repeat(64),
            }),
            volumes: vec![VolumeConfig {
                tag: "vol".to_string(),
                mountpoint: "/mnt/vol".to_string(),
                read_only: false,
                kind: crate::vsock::VolumeConfigKind::VirtioFs,
                device: None,
            }],
            extensions: Vec::new(),
            verb_grant_envelope: None,
        });
        assert_eq!(req.verb(), Verb::ActivateEnvironment);
        assert_eq!(req.kind_name(), "activate-environment");
        assert_eq!(req.class(), RequestClass::ProdSafe);
        assert!(req.allowed_in(mvm_core::security::AgentProfile::SealedProd));
        assert_eq!(req.verb().traffic_plane(), TrafficPlane::Control);
    }
}
