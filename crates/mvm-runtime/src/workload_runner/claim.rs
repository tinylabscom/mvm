//! Warm-pool claim guards: the fail-closed refusal set and bind gate, plus
//! [`ClaimGuards`] — the runner-side, host-side steps (overlay-contract gate +
//! per-child substitution endpoint) a warm claim shares verbatim with a cold
//! boot so it can never be less-guarded.
//!
//! The refusal set is kept separate from the crate-wide `anyhow::Result`
//! convention: refusals are a closed set the caller must exhaustively handle
//! (audit, retry, or surface to the operator), not an open-ended error bag.

use std::path::{Path, PathBuf};

use anyhow::Result;

use mvm_core::checkpoint::CheckpointMeta;
use mvm_core::plan::SecretBinding;
use mvm_core::policy::RedactionPolicy;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::vm_backend::VmId;

use crate::network_endpoint_spawn::EndpointGuard;
use crate::workload_runner::runner::FlowMuxIdentitySource;
use crate::workload_runner::runner::{NetworkEndpointSpawnRequest, NetworkEndpointSpawner};

#[derive(Debug, thiserror::Error)]
pub enum ClaimRefusal {
    #[error("parent is not in a claimable state")]
    ParentNotClaimable,
    #[error("parent has no signed audit entry; refusing to fork an un-audited parent")]
    ParentUnaudited,
    /// Distinct from [`Self::ParentUnaudited`] on purpose: there the parent
    /// demonstrably has no creation entry, here the ledger cannot be read at
    /// all, so whether the parent was audited is unknown. Same refusal, but the
    /// operator's next move is to investigate a damaged chain rather than to
    /// re-capture a parent.
    #[error(
        "the signed audit chain is unverifiable, so the parent's audit status cannot be \
         determined; refusing to fork against a ledger that proves nothing"
    )]
    LedgerUnverifiable,
    #[error("parent record drifted from its sealed content; refusing a tampered parent")]
    ParentTampered,
    #[error("claim carries no admitted plan; refusing to fork without claim-8 authority")]
    PlanMissing,
    #[error("plan image digest {expected} does not match parent rootfs digest {got}")]
    PlanParentMismatch { expected: String, got: String },
    /// The claimed child asked for more than the parent it is restored from was
    /// sealed under. Same rule and same code path as a vm_full fork's — a warm
    /// claim restores a child out of a parent's memory just as a fork does, so
    /// it cannot be the one restore path that skips the comparison.
    #[error("{reason}")]
    GrantsExceedParent { reason: String },
    /// The claimed child asked for more than this host's operator-configured
    /// ceiling allows. Separate from [`Self::GrantsExceedParent`] because the
    /// two bound against different things and the operator's next move differs:
    /// a widening over the parent means the claim asked for more than the
    /// snapshot it restores from held, while this means the claim asked for
    /// more than the host permits anyone.
    #[error(
        "this host's grant ceiling bounds {dimension} at {ceiling}, and the claimed child's \
         admitted plan asks for {requested}; a warm pool parent deliberately carries no grant \
         of its own, so a claimed child is bound by the host-wide ceiling"
    )]
    GrantsExceedHostCeiling {
        dimension: &'static str,
        requested: u64,
        ceiling: u64,
    },
}

/// Refuse a claimed child whose admitted plan asks for more than this host's
/// configured grant ceiling.
///
/// This is the warm pool's whole CPU bound, and it is deliberately the weakest
/// one available. A standby parent is shared by every later claim, so it is
/// built carrying no grant at all — sealing one workload's grant onto it would
/// bind every unrelated later claim to a stranger's number. That leaves the
/// parent-subset comparison with nothing to bind against, so the bound falls
/// back to the host ceiling: a host-wide maximum every cold boot already
/// clears, *not* a pool-specific grant. A claim within the ceiling is admitted
/// regardless of what any other claim on the same pool asked for. This is
/// strictly better than the unbounded claim it replaces, and no tighter.
///
/// Checked after pool matching rather than folded into the compatibility key.
/// Folding it in would fragment the pool per distinct grant value — a
/// 1500-millicore claim could not reuse a parent warmed beside a 2000-millicore
/// one — and the hit rate is the point of the pool. The cost is that a claim
/// can match a parent and then be refused, which is why the refusal names both
/// the ceiling and the request.
///
/// Only the dimensions a grant can author are checked. The child's memory is
/// the parent's — fixed when the parent booted, part of the pool's own
/// compatibility key, and unchangeable at claim time — so a memory check here
/// has nothing to refuse that pool matching did not already settle.
pub fn ensure_child_grants_within_host_ceiling(
    child: Option<&mvm_contract::grants::Grants>,
    ceiling: &mvm_contract::grants::ceiling::GrantCeiling,
) -> Result<(), ClaimRefusal> {
    // An absent grant set means here what it means to the parent-subset
    // comparison: unbounded CPU and wall clock, deny-all egress. A ceiling
    // still has something to say about that — an operator who bounded wall
    // clock refuses an unbounded request rather than clamping it — so the
    // absent case goes through the same check rather than short-circuiting.
    let unbounded_cpu_deny_all_egress = mvm_contract::grants::Grants::default();
    ceiling
        .admits_grants(child.unwrap_or(&unbounded_cpu_deny_all_egress))
        .map_err(|violation| ClaimRefusal::GrantsExceedHostCeiling {
            dimension: violation.dimension,
            requested: violation.requested,
            ceiling: violation.ceiling,
        })
}

/// Name of the [`mvm_core::checkpoint::ContentBlob`] holding the parent's
/// sealed rootfs image. `verify_content` (run earlier in the claim) already
/// proved this blob's `sha256` equals the file on disk, so comparing a plan's
/// image digest against it transitively binds the plan to the exact bytes
/// that boot.
const ROOTFS_BLOB_NAME: &str = "rootfs.ext4";

/// The parent checkpoint's verified rootfs digest (bare 64-hex, no `sha256:`
/// prefix), or a refusal if the parent carries no `rootfs.ext4` blob.
pub fn parent_rootfs_digest(meta: &CheckpointMeta) -> Result<&str, ClaimRefusal> {
    meta.content
        .iter()
        .find(|b| b.name == ROOTFS_BLOB_NAME)
        .map(|b| b.sha256.as_str())
        .ok_or_else(|| ClaimRefusal::PlanParentMismatch {
            expected: String::new(),
            got: String::from("<parent carries no rootfs.ext4 blob>"),
        })
}

/// Binds an admitted plan's image digest to the verified parent's actual
/// rootfs so the audit-recorded plan always describes exactly what boots.
/// `plan_image_sha256` is `plan.image.sha256` — bare 64-hex, compared
/// directly against the parent's bare-hex blob digest.
pub fn bind_plan_to_parent(
    plan_image_sha256: &str,
    meta: &CheckpointMeta,
) -> Result<(), ClaimRefusal> {
    let parent = parent_rootfs_digest(meta)?;
    if parent == plan_image_sha256 {
        Ok(())
    } else {
        Err(ClaimRefusal::PlanParentMismatch {
            expected: plan_image_sha256.to_string(),
            got: parent.to_string(),
        })
    }
}

/// The per-VM substitution-endpoint spawn inputs a warm claim and a cold boot
/// both thread, minus the VM identity: the id is supplied to
/// [`ClaimGuards::spawn_endpoint`] separately so the socket is always keyed on
/// the child's own [`VmId`], never a sibling's. The identity source is passed
/// in rather than derived: a cold boot mints, a warm claim inherits, and only
/// the caller knows which it is.
pub struct EndpointSpawnInputs<'a> {
    pub state_dir: &'a Path,
    pub tenant: &'a str,
    pub secrets: &'a [SecretBinding],
    pub redaction: &'a RedactionPolicy,
    pub network_policy: &'a NetworkPolicy,
    /// Transport-neutral resource ceilings from the admitted plan.
    pub network_limits: mvm_core::plan::NetworkLimits,
    /// Exact signed ingress mappings owned by this endpoint.
    pub ingress: &'a [mvm_core::plan::IngressMapping],
    /// Where this boot's FlowMux identity comes from. A cold boot mints one; a
    /// warm claim inherits its parent's, because the restored child already
    /// holds the parent's signing key in memory.
    pub identity: FlowMuxIdentitySource<'a>,
}

/// A spawned per-VM substitution endpoint: the host UDS the guest's `EGRESS_PORT`
/// relays to (the sole gate off the box), plus the RAII reaper that tears the
/// endpoint down on an early return until the VM is fully up ([`Self::defuse`]).
/// A deny-all, secret-free workload has no egress channel at all and carries
/// `None`; the guest-side connect then fails closed without starting a process.
pub struct EndpointHandle {
    egress_uds: Option<PathBuf>,
    identity_drive: Option<PathBuf>,
    guard: EndpointGuard,
}

impl EndpointHandle {
    /// The host-side egress UDS, wired into the spec's `EGRESS_PORT` channel.
    /// `None` means the workload has no admitted egress capability.
    pub fn egress_uds(&self) -> Option<&Path> {
        self.egress_uds.as_deref()
    }

    /// The identity drive to attach to this guest, when this boot minted one.
    /// `None` for a warm claim, whose guest already holds its key.
    pub fn identity_drive(&self) -> Option<&Path> {
        self.identity_drive.as_deref()
    }

    /// Disarm the reaper: the VM is up and the `stop` path now owns teardown.
    pub fn defuse(&mut self) {
        self.guard.defuse();
    }
}

/// The runner-side, host-side steps a warm claim shares with a cold boot, in one
/// place so a claim can never run a weaker version than the cold path.
///
/// Admission (signed-plan re-verify), verity inherit, and per-service confinement
/// are enforced at their own layers — the CLI + supervisor, the CLI, and guest
/// init respectively — not here; a fork inherits confinement by construction from
/// a clean parent. This bundle owns only the two steps the runner itself performs
/// on the start path: the overlay-contract admission gate and the per-child
/// substitution endpoint. Both cold boot and the warm claim call it, so the two
/// cannot diverge to a weaker posture.
pub struct ClaimGuards<'a> {
    spawner: &'a dyn NetworkEndpointSpawner,
}

impl<'a> ClaimGuards<'a> {
    pub fn new(spawner: &'a dyn NetworkEndpointSpawner) -> Self {
        Self { spawner }
    }

    /// Refuse an image whose dir carries no overlay-aware sidecar (no
    /// `/mvm/runtime` mount point) before any endpoint spawn or boot — the same
    /// gate the raw backends run, so a claim admits exactly what a cold boot does.
    ///
    /// `image_rootfs` is the rootfs the claim was **admitted for**, not the
    /// copy-on-write clone the child boots from. The sidecar records how the
    /// image was built (`overlayAware`, `runtimeLean`), so it lives beside the
    /// image and travels with neither the snapshot capture nor the clone: a
    /// materialized child dir holds `rootfs.ext4` and the saved memory, and
    /// nothing else. Gating on the clone therefore refused every saved-state
    /// claim for a missing sidecar while the identical cold boot of the same
    /// image was admitted — the resident-handoff path already passed the image
    /// dir here for exactly this reason, and the two must not disagree.
    pub fn admit_overlay_contract(
        &self,
        image_rootfs: &Path,
        runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
    ) -> Result<()> {
        let rootfs_dir = image_rootfs.parent().unwrap_or_else(|| Path::new("."));
        mvm_vmm::host::runtime_meta::admit_runtime_overlay_contract(
            rootfs_dir,
            runtime_source_policy,
        )
    }

    /// Spawn the per-child substitution endpoint keyed on `vm`'s own id — 0700,
    /// never a sibling's socket — and return its egress UDS plus the reaper.
    /// A secret-free deny-all policy has no egress capability to mediate, so it
    /// omits the channel entirely and fails closed without process startup.
    pub fn spawn_endpoint(
        &self,
        vm: &VmId,
        inputs: &EndpointSpawnInputs<'_>,
    ) -> Result<EndpointHandle> {
        if inputs.secrets.is_empty()
            && !inputs.network_policy.allows_egress()
            && inputs.ingress.is_empty()
        {
            return Ok(EndpointHandle {
                egress_uds: None,
                identity_drive: None,
                guard: EndpointGuard::defused(),
            });
        }
        // No protocol choice is made here any more. Whether a workload carries
        // secrets decides what the endpoint *does* with a flow, not which
        // protocol the guest speaks: there is one authenticated session either
        // way. The old `raw_egress = secrets.is_empty()` fork is what let the
        // guest and the host disagree.
        let spawned = self.spawner.spawn(&NetworkEndpointSpawnRequest {
            vm_name: &vm.0,
            state_dir: inputs.state_dir,
            tenant: inputs.tenant,
            secrets: inputs.secrets,
            redaction: inputs.redaction,
            network_policy: inputs.network_policy,
            network_limits: inputs.network_limits,
            ingress: inputs.ingress,
            identity: inputs.identity,
        })?;
        Ok(EndpointHandle {
            egress_uds: Some(spawned.egress_uds),
            identity_drive: spawned.identity_drive,
            guard: EndpointGuard::new(&vm.0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, ContentBlob};
    use mvm_core::vm_backend::RuntimeSourcePolicy;

    fn fake_meta_with_rootfs(hex: String) -> CheckpointMeta {
        CheckpointMeta::builder(
            CheckpointId::new("cp-test"),
            CheckpointClass::FsQuick,
            "vm-test",
        )
        .content(vec![ContentBlob {
            name: ROOTFS_BLOB_NAME.to_string(),
            sha256: hex,
        }])
        .build()
    }

    fn fake_meta_without_rootfs() -> CheckpointMeta {
        CheckpointMeta::builder(
            CheckpointId::new("cp-test"),
            CheckpointClass::FsQuick,
            "vm-test",
        )
        .build()
    }

    #[test]
    fn bind_accepts_matching_and_rejects_mismatched_rootfs() {
        let meta = fake_meta_with_rootfs("aa".repeat(32));
        // matching
        assert!(bind_plan_to_parent(&"aa".repeat(32), &meta).is_ok());
        // mismatch -> PlanParentMismatch
        let err = bind_plan_to_parent(&"bb".repeat(32), &meta).unwrap_err();
        assert!(matches!(err, ClaimRefusal::PlanParentMismatch { .. }));
    }

    #[test]
    fn parent_without_rootfs_blob_refuses() {
        let meta = fake_meta_without_rootfs();
        assert!(matches!(
            bind_plan_to_parent(&"aa".repeat(32), &meta),
            Err(ClaimRefusal::PlanParentMismatch { .. })
        ));
    }

    #[test]
    fn refusal_reasons_are_distinct_and_described() {
        let m = ClaimRefusal::PlanParentMismatch {
            expected: "sha256:aa".into(),
            got: "sha256:bb".into(),
        };
        assert!(m.to_string().contains("sha256:aa"));
        assert!(m.to_string().contains("sha256:bb"));
        // Distinct variants must not compare equal.
        assert_ne!(
            ClaimRefusal::ParentUnaudited.to_string(),
            ClaimRefusal::ParentTampered.to_string()
        );
    }

    // ---- ClaimGuards: the runner-side shared host steps ----

    use crate::workload_runner::runner::SpawnedEndpoint;
    use crate::workload_runner::runner::{NetworkEndpointSpawnRequest, NetworkEndpointSpawner};
    use mvm_core::policy::RedactionPolicy;
    use mvm_core::policy::network_policy::NetworkPolicy;
    use std::sync::Mutex;

    /// An `NetworkEndpointSpawner` double: records the `vm_name` it was handed and,
    /// mirroring `RealNetworkEndpointSpawner`, returns the per-VM socket keyed on that
    /// name — so a test can prove `ClaimGuards` threads the child's own id
    /// through and never reuses a sibling's socket, with no real endpoint process.
    #[derive(Default)]
    struct FakeSpawner {
        seen_vm: Mutex<Option<String>>,
    }

    impl NetworkEndpointSpawner for FakeSpawner {
        fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> anyhow::Result<SpawnedEndpoint> {
            *self.seen_vm.lock().unwrap() = Some(req.vm_name.to_string());
            Ok(SpawnedEndpoint {
                egress_uds: PathBuf::from("fake-endpoints")
                    .join(req.vm_name)
                    .join("substitution-endpoint.sock"),
                identity_drive: None,
            })
        }
    }

    fn endpoint_inputs<'a>(
        state_dir: &'a std::path::Path,
        redaction: &'a RedactionPolicy,
        policy: &'a NetworkPolicy,
    ) -> EndpointSpawnInputs<'a> {
        EndpointSpawnInputs {
            identity: FlowMuxIdentitySource::Mint,
            state_dir,
            tenant: "tenant-x",
            secrets: &[],
            redaction,
            network_policy: policy,
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: &[],
        }
    }

    #[test]
    fn claim_guards_spawn_endpoint_keys_the_socket_on_the_given_vm() {
        let spawner = FakeSpawner::default();
        let guards = ClaimGuards::new(&spawner);
        let redaction = RedactionPolicy::default();
        let policy =
            NetworkPolicy::allow_list(vec![mvm_core::policy::network_policy::HostPort::new(
                "example.com",
                443,
            )]);
        let state = tempfile::tempdir().unwrap();
        let expected_child = PathBuf::from("fake-endpoints")
            .join("child-a")
            .join("substitution-endpoint.sock");
        let expected_sibling = PathBuf::from("fake-endpoints")
            .join("child-b")
            .join("substitution-endpoint.sock");

        let mut child = guards
            .spawn_endpoint(
                &VmId("child-a".into()),
                &endpoint_inputs(state.path(), &redaction, &policy),
            )
            .expect("spawn_endpoint succeeds against the fake spawner");

        // The endpoint socket is keyed on child-a's own id — private to it, and
        // provably not a sibling's socket (no cross-workload reuse).
        assert_eq!(child.egress_uds(), Some(expected_child.as_path()));
        assert_ne!(child.egress_uds(), Some(expected_sibling.as_path()));
        // The fresh id was threaded to the spawner, not a parent/shared name.
        assert_eq!(spawner.seen_vm.lock().unwrap().as_deref(), Some("child-a"));

        // Disarm the reaper so drop doesn't chase a nonexistent endpoint.
        child.defuse();
    }

    #[test]
    fn deny_all_secret_free_claims_omit_the_egress_process_and_channel() {
        let spawner = FakeSpawner::default();
        let guards = ClaimGuards::new(&spawner);
        let redaction = RedactionPolicy::default();
        let policy = NetworkPolicy::deny_all();
        let state = tempfile::tempdir().unwrap();

        let child = guards
            .spawn_endpoint(
                &VmId("child-deny-all".into()),
                &endpoint_inputs(state.path(), &redaction, &policy),
            )
            .expect("deny-all fast path succeeds");

        assert_eq!(child.egress_uds(), None);
        assert_eq!(spawner.seen_vm.lock().unwrap().as_deref(), None);
    }

    #[test]
    fn claim_guards_admit_overlay_contract_matches_cold_boot() {
        let spawner = FakeSpawner::default();
        let guards = ClaimGuards::new(&spawner);

        // A rootfs whose dir carries an overlay-aware sidecar is admitted —
        // exactly what the cold-boot start gate accepts.
        let ok_dir = tempfile::tempdir().unwrap();
        let ok_rootfs = ok_dir.path().join("rootfs.ext4");
        std::fs::write(&ok_rootfs, b"rootfs").unwrap();
        mvm_build::builder_vm::GuestSidecar::for_oci_run("cg-valid", false, true)
            .write_to_dir(ok_dir.path())
            .unwrap();
        assert!(
            guards
                .admit_overlay_contract(&ok_rootfs, RuntimeSourcePolicy::default())
                .is_ok()
        );

        // A rootfs whose dir carries no sidecar is refused — same message the
        // cold-boot gate emits.
        let bare_dir = tempfile::tempdir().unwrap();
        let bare_rootfs = bare_dir.path().join("rootfs.ext4");
        std::fs::write(&bare_rootfs, b"rootfs").unwrap();
        let err = guards
            .admit_overlay_contract(&bare_rootfs, RuntimeSourcePolicy::default())
            .expect_err("a rootfs with no overlay-aware sidecar must be refused");
        assert!(
            err.to_string().contains("mvm-meta.json"),
            "refusal must name the missing sidecar: {err}"
        );
    }

    /// A saved-state claim gates the image it was admitted for, not the
    /// copy-on-write clone the child boots. The clone carries `rootfs.ext4` and
    /// the saved memory and nothing else — the sidecar is not part of the
    /// capture — so gating the clone refused every such claim for a missing
    /// sidecar while the identical cold boot of the same image was admitted.
    #[test]
    fn admit_overlay_contract_gates_the_image_not_the_materialized_clone() {
        let spawner = FakeSpawner::default();
        let guards = ClaimGuards::new(&spawner);

        let image_dir = tempfile::tempdir().unwrap();
        let image_rootfs = image_dir.path().join("rootfs.ext4");
        std::fs::write(&image_rootfs, b"rootfs").unwrap();
        mvm_build::builder_vm::GuestSidecar::for_oci_run("cg-image", false, true)
            .write_to_dir(image_dir.path())
            .unwrap();

        // What a materialization actually produces: the blob and the memory
        // image, no sidecar.
        let clone_dir = tempfile::tempdir().unwrap();
        let clone_rootfs = clone_dir.path().join("rootfs.ext4");
        std::fs::write(&clone_rootfs, b"rootfs").unwrap();
        std::fs::write(clone_dir.path().join("memory.bin"), b"mem").unwrap();

        assert!(
            guards
                .admit_overlay_contract(&image_rootfs, RuntimeSourcePolicy::default())
                .is_ok(),
            "the admitted image carries the sidecar and must be admitted"
        );
        assert!(
            guards
                .admit_overlay_contract(&clone_rootfs, RuntimeSourcePolicy::default())
                .is_err(),
            "the clone has no sidecar — proving the gate must not be pointed at it"
        );
    }
}
