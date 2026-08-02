//! Local mvmctl audit-log DTOs (single-host operations) plus the
//! per-tenant fleet audit DTOs. Pure serde shapes only — the
//! `std::fs`-backed writer (`LocalAuditLog`), the `audit_emit!` macro,
//! the `event()`/`LocalAuditBuilder` composition helpers, `emit()`/
//! `emit_to()`, `default_audit_log()`, and the Stage 0 tail readers
//! stay in `mvm_core::policy::audit`, which re-exports these types at
//! their existing paths.
//!
//! `LocalAuditEvent::now()` (the `chrono::Utc::now()`-stamped
//! constructor) also stays in `mvm-core` as the free function
//! `now_event()` — the wall-clock read needs chrono's `clock` feature,
//! unavailable in this `no_std` crate.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::policy::security::{GateDecision, ThreatFinding};

// ============================================================================
// Local mvmctl audit log (single-host operations)
// ============================================================================

/// Categories of local mvmctl operations that are audit-logged.
///
/// Invariant: no unaudited control-plane mutation. Every
/// state-changing CLI verb emits one of these. Pure read-only verbs
/// (status / list / inspect / completions / shell-init) are not
/// audited; everything that mutates host state, registry state, the
/// data dir, the network, secrets, snapshots, signing keys, or the
/// audit log itself must be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAuditKind {
    VmStart,
    VmStop,
    KeyLookup,
    VolumeCreate,
    VolumeOpen,
    VolumeLock,
    VolumeSnapshot,
    VolumeRestore,
    UpdateInstall,
    Uninstall,
    // --- DX features ---
    NetworkCreate,
    NetworkRemove,
    ImageFetch,
    TemplateBuild,
    TemplatePush,
    TemplatePull,
    ConfigChange,
    ConsoleSessionStart,
    ConsoleSessionEnd,
    // --- Reserved future verbs ----------------------------------
    // These kinds are reserved here so the wire format is stable
    // before the corresponding CLI verbs ship. Each will be emitted
    // by its own command later. Reserving them now lets the egress
    // proxy and supervisor command work land their verbs without
    // re-bumping the audit schema each time.
    /// `mvmctl plan submit <signed-plan>` — admission of a signed
    /// `ExecutionPlan`. Distinct from the supervisor's per-state
    /// `plan.admitted` event: this is the local CLI verb that
    /// hands the plan to the supervisor.
    PlanSubmit,
    /// Policy bundle install or replacement. Public policy rollout
    /// is owned by mvmd; this keeps the local audit kind stable.
    PolicyApply,
    /// Policy bundle rollback. Public policy rollout is owned by mvmd;
    /// this keeps the local audit kind stable.
    PolicyRollback,
    /// `mvmctl host trust set` — add or remove a trusted signer key
    /// from the supervisor's trust store. Affects which signed plans
    /// the supervisor will admit.
    HostTrustSet,
    /// `mvmctl supervisor restart` — restart the trusted host-side
    /// supervisor process.
    SupervisorRestart,
    /// `mvmctl quarantine <workload>` — freeze a running workload.
    /// Distinct from `kill`: quarantined workloads can be resumed
    /// for forensics; killed workloads cannot.
    Quarantine,
    /// `mvmctl kill <workload>` — terminal teardown of a running
    /// workload.
    Kill,
    /// `mvmctl artifact fetch <plan_id>` — retrieve captured
    /// artifacts from the supervisor's artifact store.
    ArtifactFetch,
    /// `mvmctl wake <workload>` / `mvmctl sleep <workload>` —
    /// supervisor-driven snapshot suspend/resume.
    WorkloadWake,
    WorkloadSleep,
    // --- Egress L7 ---
    /// Host CA for hypervisor-level L7 egress interception was
    /// rotated. Rotation is explicit, not implicit; every rotation
    /// lands in the audit log with old + new fingerprints + the list
    /// of VMs whose per-VM leaves were re-signed.
    EgressCaRotated,
    // --- Lifecycle integrity events ---
    /// `mvmctl build` failed before producing a slot/revision. Paired
    /// with the existing `TemplateBuild` success kind so every build
    /// attempt — success or failure — leaves a single audit line.
    TemplateBuildError,
    /// Snapshot integrity verification failed at resume time. Covers
    /// HMAC tag mismatch (tampered bytes or rotated host key), version
    /// mismatch under strict mode, and lower-level I/O / encoding
    /// failures from `crate::crypto::snapshot_hmac::verify`. Refusing
    /// to resume a tampered snapshot is a security signal and must be
    /// auditable.
    SnapshotIntegrityFailed,
    /// Pre-flight verification of a downloaded dev image manifest
    /// failed: cosign signature invalid, manifest version pin off,
    /// `not_after` past, or the published version is on the signed
    /// revocation list. Every refusal is an auditable event so an
    /// operator can correlate "image rejected
    /// at 14:03" with their CDN logs.
    ImageVerifyFailed,
    // --- Registry / cache mutations (no-unaudited-mutation fillers) ---
    /// `mvmctl cache prune` removed temporary files / empty subdirs
    /// from the cache tree (`<mvm_home>/cache`). Pure read-only
    /// `cache info` is not audited; the prune verb is, because it
    /// deletes host bytes.
    CachePrune,
    /// `mvmctl pack rollback` / `pack download` / `pack update` changed
    /// the attested-pack cache: retargeted a key's active version, or
    /// fetched and (for `update`) activated a new one. Distinct from
    /// `CachePrune`, which only ever removes bytes; this kind covers
    /// additions and pointer swaps. Detail carries `op=<verb>` plus the
    /// pack key and version affected.
    PackCacheChange,
    /// `mvmctl cleanup` ran a host-side tier sweep
    /// (`--cache` / `--state` / `--nuclear`). The detail field carries
    /// the tier name, byte count freed, and number of top-level paths
    /// removed. The in-VM-only default invocation continues to emit
    /// `SlotPrune` for its `~/.mvm/dev/builds/` mutation; this kind is
    /// only emitted when a host-side tier flag is set.
    Cleanup,
    /// `mvmctl manifest rm` deleted a registry slot
    /// (`~/.mvm/templates/<slot_hash>/`). Optionally also deleted the
    /// source `mvm.toml` when `--manifest-file` is passed.
    SlotRemove,
    /// Orphan-slot sweep deleted one or more slots whose source
    /// `mvm.toml` no longer exists on disk. Emitted by both
    /// `mvmctl manifest prune --orphans` and
    /// `mvmctl cache prune --orphan-builds`. The detail field carries
    /// the count and (for small sweeps) the truncated slot hashes.
    SlotPrune,
    /// Reconcile-on-entry convergence healed registry/runtime drift:
    /// a dead-process record was torn down, a stale record dropped, or
    /// an orphan state dir reaped. One entry per
    /// healed item; the `detail` field carries `action=<classification>`.
    /// Emitted by `mvmctl reconcile` and the cheap convergence pass run at
    /// CLI entry for state-touching commands.
    RegistryReconcile,
    /// `mvmctl pool warm` pre-spawned supervisor standbys for the warm pool.
    /// State-changing infra verb (spawns detached
    /// supervisors + writes `~/.mvm/pool/`); the `detail` field carries
    /// `spawned=<n> target=<n>`.
    PoolWarm,
    /// `mvmctl checkpoint create` froze a VM's filesystem state into an
    /// immutable fs_quick checkpoint.
    CheckpointCreated,
    /// `mvmctl checkpoint fork` branched a new sandbox from a checkpoint.
    CheckpointForked,
    /// `mvmctl checkpoint restore` resumed a VM from a vm_full checkpoint.
    CheckpointRestored,
    // --- Sandbox SDK foundation (fs/proc/share/pause/TTL/tags) ---
    // The verbs below are state-changing CLI surfaces added by the
    // sandbox-SDK foundation work. Each kind names a single mutation
    // class; the per-call detail is carried in the audit event's
    // `target` and `detail` fields.
    /// `mvmctl manifest alias set` / unset — registry-level alias
    /// mutation that retargets a friendly name to a different slot.
    ManifestAliasSet,
    ManifestAliasRemove,
    /// `mvmctl manifest tag add` / `tag remove` — adds or removes a
    /// label on a manifest entry.
    ManifestTagAdd,
    ManifestTagRemove,
    /// `mvmctl vm fs <write|delete|mkdir|chmod|chown|...>` — any
    /// guest-filesystem mutation through the FsRpc surface. The
    /// `detail` field carries the operation kind and target path.
    VmFsMutate,
    /// `mvmctl cp <src> <dst>` copied a file across the host/guest
    /// boundary. Detail carries direction, guest path, and byte count;
    /// host paths and file contents are deliberately omitted.
    VmFileCopy,
    /// `mvmctl vm snapshot delete` — removes a saved snapshot from
    /// the host's snapshot store.
    SnapshotDelete,
    /// `mvmctl vm proc start` / `vm proc signal <pid> <sig>` /
    /// `vm proc stdin <pid>` — process control RPC mutations on a
    /// running guest.
    VmProcStart,
    VmProcSignal,
    VmProcStdin,
    /// `mvmctl vm set-ttl` — changes the TTL deadline on a running
    /// VM. The reaper picks up the new deadline on its next tick.
    VmTtlSet,
    /// `mvmctl vm rekernel` — relaunches a VM on a chosen/updated
    /// workload kernel (a stop + re-boot). Recorded as its own kind so
    /// a kernel swap is distinguishable in the audit trail from an
    /// ordinary restart; the underlying down/up legs still emit their
    /// own VmStop / plan.* + VmStart entries.
    VmRekernel,
    /// `mvmctl vm volume add` / `volume remove` — mounts or unmounts
    /// a virtio-fs volume into a running guest. (Renamed from the
    /// prior `VmShareAdd` / `VmShareRemove`; no compat shim, no
    /// behavioural change.)
    VmVolumeAdd,
    VmVolumeRemove,
    // --- metering API ---
    /// One per-minute metering bucket sealed and chained into the
    /// audit log. Auditing-grade resource attribution. The
    /// `detail` field carries a JSON-encoded `MeteringBucket`
    /// (`mvm_core::metering::MeteringBucket`) so a forensic pass can
    /// reconstruct per-tenant resource consumption end-to-end without
    /// trusting the per-tenant JSONL rollup file (which the audit
    /// chain authenticates by sealing each bucket here).
    MeteringEpoch,
    // --- bundle trust store mutations ---
    //
    // `~/.mvm/trusted-publishers/<key_id>.pub` is the host-trust-
    // boundary state for bundle admission (claim 9). Every add /
    // remove leaves an audit line so a forensics pass can answer
    // "which publishers were trusted at the moment of incident."
    /// `mvmctl trust add <pubkey>` — enrolled a publisher's Ed25519
    /// pubkey in the trust store. Detail: `key_id=<32hex>`.
    TrustAdd,
    /// `mvmctl trust remove <key_id>` — un-enrolled a publisher.
    /// Detail: `key_id=<32hex>`.
    TrustRemove,
    /// `mvmctl bundle install <source>` — verified + atomically
    /// extracted a `.mvmpkg` archive into `~/.mvm/bundles/<sha>/`.
    /// Detail: `bundle_sha256=<64hex>,key_id=<32hex>`. Emitted only
    /// on the success arm; verify failures don't reach the emit.
    BundleInstall,
    /// `mvmctl bundle gc <sha>` or `mvmctl bundle gc --all` —
    /// pruned one or more installed bundles from the registry.
    /// Detail: `removed=<count>,shas=<sha1>[,sha2,...]` (truncated
    /// to the first ~5 shas for sweeps).
    BundleGc,
    /// `mvmctl manifest export-oci <template> --out <path>` —
    /// copied a slot's OCI tarball (produced by `mkGuest`'s
    /// `dockerTools.streamLayeredImage`) to a user-supplied path
    /// so a non-KVM host can `docker load` it. Detail:
    /// `template=<slot>,revision=<rev>,bytes=<size>`.
    ImageExportOci,
    // --- dm-thin storage pool ops ---
    /// `mvmctl storage gc` removed one or more orphaned thin volumes
    /// from the pool. Detail carries the removed volume names (or a
    /// truncated count for large sweeps).
    StorageGc,
    /// `mvmctl sandbox gc --apply` removed stale VM name-registry
    /// records for expired or stopped sandboxes. Detail carries the
    /// removed count and, for small sweeps, the VM names.
    SandboxGc,
    /// Pool-full event surfaced from a clone/snapshot attempt. Detail
    /// carries used + capacity bytes. Operators correlate with their
    /// disk-pressure alerts.
    StoragePoolFull,
    // --- session lifecycle ---
    //
    // Dev sessions hold a long-lived microVM with PTY / shell-exec
    // surface available behind the session id. The session id IS the
    // capability: anyone with read access to
    // `<mvm_home>/run/sessions/<id>.json` can attach. Every
    // interactive entry point therefore lands in the audit log so a
    // forensics pass can reconstruct who-attached-when even after
    // the session record is reaped.
    /// `mvmctl session start <template>` registered a new session.
    /// Detail: `mode=prod|dev,template=<id>,session=<id>`.
    SessionStart,
    /// `mvmctl session attach <id>` dispatched a `RunEntrypoint`
    /// call into an existing session. Detail: `session=<id>`.
    SessionAttach,
    /// `mvmctl session exec <id> -- <argv>` ran an ad-hoc shell
    /// command in a dev session. Detail: `session=<id>` (argv is
    /// **not** logged — could contain user-typed secrets).
    SessionExec,
    /// `mvmctl session run-code <id> <code>` ran user-supplied code
    /// in a dev session. Detail: `session=<id>` (code is **not**
    /// logged — same secrecy concern as exec argv).
    SessionRunCode,
    /// `mvmctl session console <id>` opened an interactive PTY into
    /// a dev session. Pair with `ConsoleSessionEnd` (already
    /// emitted) for the close edge. Detail: `session=<id>`.
    SessionConsoleOpen,
    /// `mvmctl session kill <id>` terminated a session. Detail:
    /// `session=<id>`.
    SessionKill,
    /// `mvmctl session reap` (or the lazy host-side reaper running
    /// inside another session verb) tore down an idle session.
    /// Detail: `session=<id>,idle_timeout_secs=<n>`.
    SessionReap,
    // --- deps-volume audit verbs ---
    /// `mvmctl deps audit` re-ran the CVE scan against a cached deps
    /// volume and resealed it. Detail carries the prior + new volume
    /// hashes plus the count of high/critical CVE findings surfaced.
    /// Emitted once per volume processed (so `--all` produces N
    /// records, one per volume).
    DepsAudit,

    // --- Stage 0 builder VM bootstrap lifecycle ---
    //
    // Three events bracket the per-host Stage 0 lifecycle so a
    // contributor can answer "did the builder VM bootstrap actually run
    // Stage 0 last night, and how did it land?" after the fact. We emit into the
    // shared local audit log (rather than a separate
    // `~/.mvm/audit/stage0.jsonl`) because (a) every
    // other contributor-side event already lands there, (b) the
    // schema/macro/rotation already exists, and (c) operators filter
    // by `kind` not by file. The `kind` strings (`stage0_boot`,
    // `stage0_cache_promoted`, `stage0_failed`) are stable.
    //
    // Detail formats are space-separated key=value pairs to match
    // every other call site (the macro can't emit JSON without a
    // wider schema change). SHAs are intentionally omitted — hashing
    // a 700 MiB rootfs on every builder VM bootstrap is too expensive for an
    // audit event; the seed label + source fingerprint prefix are
    // enough to correlate against the build cache.
    //
    /// Stage 0 entered the bootstrap path: seed image located, lock
    /// acquired, build about to start. Detail format:
    ///   `seed=<label> fingerprint_prefix=<8-hex-prefix>`
    /// where `seed` is the find_local_fallback_image label
    /// (`current`, `prebuilt/v0.14.0`, `builds/<hash>`, ...) and
    /// `fingerprint_prefix` is the leading 8 hex chars of the
    /// SHA-256 of `nix/images/builder-vm/{flake.nix,flake.lock}`.
    Stage0Boot,
    /// Stage 0 finished cleanly: the staging dir validated, was
    /// renamed into the live cache, and `cache_ready` re-validates.
    /// Detail format:
    ///   `cache=<final_dir> fingerprint_prefix=<8-hex-prefix> duration_ms=<n>`
    Stage0CachePromoted,
    /// Stage 0 failed at any point after `Stage0Boot` was emitted.
    /// Detail format:
    ///   `stage=<build|validate|promote> duration_ms=<n> reason=<short-error-summary>`
    /// `reason` is the top-level anyhow message, truncated to a
    /// reasonable bound; the full chain is on stderr already. Pre-
    /// `Stage0Boot` failures (lock contention, no seed image) are
    /// not audited because they happen before the bootstrap really
    /// started.
    Stage0Failed,

    // --- programmable network policy enforcement events ---
    //
    // Five new kinds wired into the L3 iptables / L4 substrate / DNS
    // pin paths. Variants ship ahead of their emission sites without
    // re-bumping the audit schema each time. Wire format is stable
    // (snake_case strings) per the enum's `rename_all` attribute.
    //
    // Detail-format conventions across the five (so a future
    // dashboard parses uniformly):
    //   - `proto=<tcp|udp>` always first when L4 protocol applies.
    //   - `dst=<ip:port>` for the destination tuple, `ip` for an
    //     IP-only event.
    //   - additional key=value pairs comma-separated, no spaces.
    //
    /// L4 allow decision: a flow matched a policy rule and was
    /// permitted. Fired from `CanonicalEgress::permits` and from the
    /// iptables FORWARD accept path (when wired). Detail format:
    ///   `proto=<tcp|udp>,dst=<ip:port>,rule=<host:port-or-cidr>`
    NetworkPolicyAllow,
    /// L4 deny decision: no allow rule matched. Distinct from
    /// `NetworkMandatoryDeny` — that variant fires only for the
    /// unconditional deny set; this one captures "policy didn't
    /// permit" + "policy was empty" + similar negative outcomes.
    /// Detail format:
    ///   `proto=<tcp|udp>,dst=<ip:port>,reason=<no-allow|policy-empty>`
    NetworkPolicyDeny,
    /// Egress hit one of `MANDATORY_DENY_RANGES` (cloud metadata,
    /// link-local, CGNAT, host loopback) — the unconditional deny
    /// fired regardless of the user's allow-list. Surfaced as a
    /// distinct kind because IMDS-style exfil attempts deserve a
    /// dedicated alert channel separate from noisier policy
    /// denials. Detail format:
    ///   `proto=<tcp|udp>,dst=<ip:port>,category=<cloud-metadata|link-local|cgnat|loopback>`
    NetworkMandatoryDeny,
    /// Supervisor admission resolved a destination host to one or
    /// more IPs and pinned them for the lifetime of the workload.
    /// Fires once per `(workload, destination)`
    /// pair at admission, before the guest boots. Detail format:
    ///   `dest=<host>,ips=<ip[,ip...]>,ttl_s=<n>`
    DnsPinSet,
    /// A guest request resolved (via the egress proxy or supervisor
    /// resolver) to an IP that didn't match the admission-time pin.
    /// Distinct from `NetworkPolicyDeny`: this is a TOCTOU /
    /// rebinding signal, not a missing-allow signal. Detail format:
    ///   `dest=<host>,pinned_ips=<ip[,ip...]>,observed_ip=<ip>`
    DnsPinReject,

    // --- gateway-flow audit kinds (claim 10 leg 2) ---
    //
    // Four new kinds emitted by the native gateway (macOS) / passt (Linux)
    // control-socket wrapper. Variants ship ahead of their emission
    // sites without re-bumping the audit schema each time. Wire
    // format is stable (snake_case strings) per the enum's
    // `rename_all` attribute.
    //
    // Detail-format conventions (documented here so the names match
    // the intended payload the emission path populates):
    //   - `flow_id=<u64-hex>` is the join key across all four kinds
    //     for a single flow's lifecycle.
    //   - per-direction byte counters are `bytes_in` / `bytes_out` on
    //     terminal events, `bytes_in_delta` / `bytes_out_delta` on
    //     periodic `FlowBytes` aggregates.
    //   - durations / windows are milliseconds / seconds, named
    //     `*_ms` / `*_s` to match the rest of the audit log.
    //
    /// A new outbound flow opened through the native-gateway/passt path. Fired once
    /// at flow setup with the 5-tuple and assigned `flow_id`; the
    /// `flow_id` is the join key for subsequent `FlowBytes`,
    /// `FlowClosed`, and `FlowPolicyDecision` entries on the same
    /// flow. Detail format:
    ///   `proto=<tcp|udp>,src=<ip:port>,dst=<ip:port>,flow_id=<hex>`
    FlowOpened,
    /// Flow closed (FIN/RST, idle timeout, or guest-side teardown).
    /// Carries final per-direction byte counters and wall-clock
    /// duration. One per flow lifecycle; pairs with the opening
    /// `FlowOpened`. Detail format:
    ///   `flow_id=<hex>,bytes_in=<n>,bytes_out=<n>,duration_ms=<n>`
    FlowClosed,
    /// Periodic aggregated byte counters for a long-lived flow.
    /// Per-byte audit is too noisy; the emission policy defaults to
    /// every 30s for flows still open beyond the window. Counters
    /// are deltas since the previous
    /// `FlowBytes` / `FlowOpened` entry on the same `flow_id`.
    /// Detail format:
    ///   `flow_id=<hex>,bytes_in_delta=<n>,bytes_out_delta=<n>,window_s=<n>`
    FlowBytes,
    /// The gateway evaluated a per-flow policy decision and emitted
    /// the outcome. Distinct from `NetworkPolicyAllow` /
    /// `NetworkPolicyDeny`: those are *admission-time* decisions
    /// at flow setup; `FlowPolicyDecision` fires for runtime
    /// re-evaluations on an already-open flow (e.g. rate-limit
    /// trip, destination-pin recheck, L4 reauth). Detail format:
    ///   `flow_id=<hex>,decision=<allow|deny>,rule=<rule-id>`
    FlowPolicyDecision,

    // --- vendored-blob supply-chain fetch ---
    //
    // Emitted once per vendored bootstrap blob each time it is fetched
    // or revalidated from cache, so every hash trust decision in the
    // no-prebuilt-download supply chain is auditable. Today the only such
    // blob is the nix-tarball Stage 0 seed (SHA-256-pinned; the hash
    // is the binding integrity check); the kind is forward-compatible
    // with any future pinned asset. Lands in the shared
    // local audit log (not the chain-signed stream), matching the Stage 0
    // siblings above. Wire string is stable (`vendor_blob_fetched`) — log
    // shippers / `mvmctl audit` filter on it.
    //
    /// A vendored bootstrap blob was downloaded and verified, or
    /// re-verified on a cache hit. Detail format (space-separated
    /// `key=value`, matching the Stage 0 kinds):
    ///   `url=<url> sha256=<64hex> bytes=<n> outcome=<fetched|cache_revalidated>`
    VendorBlobFetched,

    // Forensic transcript capture lifecycle (opt-in, host-boundary). Detail is
    // a space-separated `key=value` list; raw payload bytes never appear here.
    /// A forensic transcript capture was armed for a tenant/VM/session.
    ///   `tenant=<t> vm=<v> capture=<id> max_bytes=<n> max_chunks=<n>`
    TranscriptArmed,
    /// A capture was sealed (disarmed) — no further bytes will be recorded.
    ///   `tenant=<t> vm=<v> capture=<id> chunks=<n>`
    TranscriptSealed,
    /// A sealed transcript was verified and exported (decrypted).
    ///   `tenant=<t> vm=<v> capture=<id> bytes=<n>`
    TranscriptExported,
    /// A transcript operation refused fail-closed (tamper, wrong key, bound).
    ///   `tenant=<t> vm=<v> capture=<id> reason=<msg>`
    TranscriptRefused,
}

/// A single local audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAuditEvent {
    pub timestamp: String,
    pub kind: LocalAuditKind,
    pub vm_name: Option<String>,
    pub detail: Option<String>,
}

/// Audit event types for per-tenant audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    // -- Instance lifecycle --
    InstanceCreated,
    InstanceStarted,
    InstanceStopped,
    InstanceWarmed,
    InstanceSlept,
    InstanceWoken,
    InstanceDestroyed,
    // -- Pool/Tenant --
    PoolCreated,
    PoolBuilt,
    PoolDestroyed,
    TenantCreated,
    TenantDestroyed,
    // -- Operational --
    QuotaExceeded,
    SecretsRotated,
    SnapshotCreated,
    SnapshotRestored,
    SnapshotDeleted,
    TransitionDeferred,
    MinRuntimeOverridden,
    // -- Vsock security --
    VsockSessionStarted,
    VsockSessionEnded,
    VsockFrameReceived,
    CommandBlocked,
    CommandApproved,
    CommandDenied,
    ThreatDetected,
    RateLimitExceeded,
    SessionRecycled,
}

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub tenant_id: String,
    pub pool_id: Option<String>,
    pub instance_id: Option<String>,
    pub action: AuditAction,
    pub detail: Option<String>,
    /// Threat findings from the classifier (empty for non-security events).
    #[serde(default)]
    pub threats: Vec<ThreatFinding>,
    /// Gate decision for command-gated events.
    #[serde(default)]
    pub gate_decision: Option<GateDecision>,
    /// Vsock frame sequence number.
    #[serde(default)]
    pub frame_sequence: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;

    /// Pure-shape constructor used in place of the removed
    /// `LocalAuditEvent::now()` (a `chrono::Utc::now()`-stamped
    /// constructor that stays in `mvm-core` as `now_event()`, since
    /// this crate carries no clock). Tests here only assert on
    /// `kind`/`vm_name`/`detail`/serde shape, never on the timestamp
    /// value, so a fixed stamp is equivalent coverage.
    fn stub_event(
        kind: LocalAuditKind,
        vm_name: Option<String>,
        detail: Option<String>,
    ) -> LocalAuditEvent {
        LocalAuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            kind,
            vm_name,
            detail,
        }
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            tenant_id: "acme".to_string(),
            pool_id: Some("workers".to_string()),
            instance_id: Some("i-abc123".to_string()),
            action: AuditAction::InstanceStarted,
            detail: Some("pid=12345".to_string()),
            threats: vec![],
            gate_decision: None,
            frame_sequence: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"tenant_id\":\"acme\""));
        assert!(json.contains("\"InstanceStarted\""));
    }

    #[test]
    fn test_audit_entry_no_optionals() {
        let entry = AuditEntry {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            tenant_id: "acme".to_string(),
            pool_id: None,
            instance_id: None,
            action: AuditAction::TenantCreated,
            detail: None,
            threats: vec![],
            gate_decision: None,
            frame_sequence: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"pool_id\":null"));
    }

    #[test]
    fn test_all_audit_actions_serialize() {
        let actions = vec![
            AuditAction::InstanceCreated,
            AuditAction::InstanceStarted,
            AuditAction::InstanceStopped,
            AuditAction::InstanceWarmed,
            AuditAction::InstanceSlept,
            AuditAction::InstanceWoken,
            AuditAction::InstanceDestroyed,
            AuditAction::PoolCreated,
            AuditAction::PoolBuilt,
            AuditAction::PoolDestroyed,
            AuditAction::TenantCreated,
            AuditAction::TenantDestroyed,
            AuditAction::QuotaExceeded,
            AuditAction::SecretsRotated,
            AuditAction::SnapshotCreated,
            AuditAction::SnapshotRestored,
            AuditAction::SnapshotDeleted,
            AuditAction::TransitionDeferred,
            AuditAction::MinRuntimeOverridden,
            AuditAction::VsockSessionStarted,
            AuditAction::VsockSessionEnded,
            AuditAction::VsockFrameReceived,
            AuditAction::CommandBlocked,
            AuditAction::CommandApproved,
            AuditAction::CommandDenied,
            AuditAction::ThreatDetected,
            AuditAction::RateLimitExceeded,
            AuditAction::SessionRecycled,
        ];

        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_audit_entry_backward_compat() {
        // Old-format JSON without new fields should still deserialize
        let json = r#"{
            "timestamp": "2025-01-01T00:00:00Z",
            "tenant_id": "acme",
            "pool_id": null,
            "instance_id": null,
            "action": "TenantCreated",
            "detail": null
        }"#;
        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.tenant_id, "acme");
        assert!(entry.threats.is_empty());
        assert!(entry.gate_decision.is_none());
        assert!(entry.frame_sequence.is_none());
    }

    #[test]
    fn test_audit_entry_with_security_fields() {
        use crate::policy::security::{GateDecision, Severity, ThreatCategory, ThreatFinding};

        let entry = AuditEntry {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            tenant_id: "acme".to_string(),
            pool_id: None,
            instance_id: Some("i-001".to_string()),
            action: AuditAction::ThreatDetected,
            detail: Some("classified vsock frame".to_string()),
            threats: vec![ThreatFinding {
                category: ThreatCategory::Destructive,
                pattern_id: "rm_rf_root".to_string(),
                severity: Severity::Critical,
                matched_text: "rm -rf /".to_string(),
                context: "literal match".to_string(),
            }],
            gate_decision: Some(GateDecision::Blocked {
                pattern: "rm -rf /".to_string(),
                reason: "destructive".to_string(),
            }),
            frame_sequence: Some(42),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.threats.len(), 1);
        assert_eq!(parsed.threats[0].category, ThreatCategory::Destructive);
        assert!(parsed.gate_decision.is_some());
        assert_eq!(parsed.frame_sequence, Some(42));
    }

    // -------------------------------------------------------------------------
    // LocalAuditEvent / LocalAuditKind shape tests
    // -------------------------------------------------------------------------

    #[test]
    fn b21_reserved_audit_kinds_serde_roundtrip() {
        // These reserved audit kinds keep the wire format stable
        // before each CLI verb ships. This test is the contract —
        // older builds must accept any of these snake_case variants
        // without rejecting them.
        let kinds = vec![
            LocalAuditKind::PlanSubmit,
            LocalAuditKind::PolicyApply,
            LocalAuditKind::PolicyRollback,
            LocalAuditKind::HostTrustSet,
            LocalAuditKind::SupervisorRestart,
            LocalAuditKind::Quarantine,
            LocalAuditKind::Kill,
            LocalAuditKind::ArtifactFetch,
            LocalAuditKind::WorkloadWake,
            LocalAuditKind::WorkloadSleep,
        ];
        for kind in kinds {
            let event = stub_event(kind.clone(), None, None);
            let json = serde_json::to_string(&event).unwrap();
            let parsed: LocalAuditEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.kind, kind, "kind round-trip diverged: {kind:?}");
        }
    }

    #[test]
    fn b21_audit_kinds_use_snake_case_on_the_wire() {
        // Pin the casing — we don't want a future rename to silently
        // break the audit-stream parser of an older mvmctl reading
        // a newer log.
        let kinds_and_strings = vec![
            (LocalAuditKind::PlanSubmit, "plan_submit"),
            (LocalAuditKind::PolicyApply, "policy_apply"),
            (LocalAuditKind::PolicyRollback, "policy_rollback"),
            (LocalAuditKind::HostTrustSet, "host_trust_set"),
            (LocalAuditKind::SupervisorRestart, "supervisor_restart"),
            (LocalAuditKind::Quarantine, "quarantine"),
            (LocalAuditKind::Kill, "kill"),
            (LocalAuditKind::ArtifactFetch, "artifact_fetch"),
            (LocalAuditKind::WorkloadWake, "workload_wake"),
            (LocalAuditKind::WorkloadSleep, "workload_sleep"),
        ];
        for (kind, expected) in kinds_and_strings {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
        }
    }

    // =====================================================================
    // network policy audit kinds
    // =====================================================================

    /// Same shape as `b21_reserved_audit_kinds_serde_roundtrip`:
    /// every new network-policy variant must serde-roundtrip cleanly
    /// so emission can land independently without re-bumping the audit
    /// schema each time.
    #[test]
    fn w2_network_audit_kinds_serde_roundtrip() {
        let kinds = vec![
            LocalAuditKind::NetworkPolicyAllow,
            LocalAuditKind::NetworkPolicyDeny,
            LocalAuditKind::NetworkMandatoryDeny,
            LocalAuditKind::DnsPinSet,
            LocalAuditKind::DnsPinReject,
        ];
        for kind in kinds {
            let event = stub_event(kind.clone(), None, None);
            let json = serde_json::to_string(&event).unwrap();
            let parsed: LocalAuditEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.kind, kind, "kind round-trip diverged: {kind:?}");
        }
    }

    /// Wire-format pin for the network-policy variants. Pinned so a
    /// future rename surfaces as a failing test and forces a conscious
    /// decision about old-log readability.
    #[test]
    fn w2_network_audit_kinds_use_snake_case_on_the_wire() {
        let kinds_and_strings = vec![
            (LocalAuditKind::NetworkPolicyAllow, "network_policy_allow"),
            (LocalAuditKind::NetworkPolicyDeny, "network_policy_deny"),
            (
                LocalAuditKind::NetworkMandatoryDeny,
                "network_mandatory_deny",
            ),
            (LocalAuditKind::DnsPinSet, "dns_pin_set"),
            (LocalAuditKind::DnsPinReject, "dns_pin_reject"),
        ];
        for (kind, expected) in kinds_and_strings {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(
                json,
                format!("\"{expected}\""),
                "W2 audit kind wire format drifted for {kind:?}"
            );
        }
    }

    /// The mandatory-deny variant is distinct from the
    /// policy-deny variant. A future maintainer who tries to
    /// collapse them into one kind fails this test and reads
    /// the doc comment explaining why they're separate.
    #[test]
    fn registry_reconcile_kind_serializes_snake_case() {
        // The convergence audit kind must serde-roundtrip (snake_case
        // per the enum attr) so emission + chain verification stay
        // stable.
        let json = serde_json::to_string(&LocalAuditKind::RegistryReconcile).unwrap();
        assert_eq!(json, "\"registry_reconcile\"");
        let parsed: LocalAuditKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, LocalAuditKind::RegistryReconcile);
    }

    #[test]
    fn w2_mandatory_deny_is_separate_from_policy_deny() {
        // PartialEq + serialize both establish identity.
        assert_ne!(
            LocalAuditKind::NetworkMandatoryDeny,
            LocalAuditKind::NetworkPolicyDeny
        );
        let mandatory = serde_json::to_string(&LocalAuditKind::NetworkMandatoryDeny).unwrap();
        let policy = serde_json::to_string(&LocalAuditKind::NetworkPolicyDeny).unwrap();
        assert_ne!(
            mandatory, policy,
            "mandatory and policy deny must serialize differently — IMDS-exfil \
             alerts need a dedicated channel separate from noisier policy denials"
        );
    }

    /// Each new variant must compose with the standard
    /// `LocalAuditEvent` constructor. Catches a future
    /// regression where a variant accidentally drops `Clone` or
    /// stops being usable with the existing event shape.
    #[test]
    fn w2_network_audit_kinds_compose_with_event_constructor() {
        let cases = [
            LocalAuditKind::NetworkPolicyAllow,
            LocalAuditKind::NetworkPolicyDeny,
            LocalAuditKind::NetworkMandatoryDeny,
            LocalAuditKind::DnsPinSet,
            LocalAuditKind::DnsPinReject,
        ];
        for kind in cases {
            let event = stub_event(
                kind.clone(),
                Some("vm-test".to_string()),
                Some("dst=1.2.3.4:443,proto=tcp".to_string()),
            );
            assert_eq!(event.kind, kind);
            assert_eq!(event.vm_name.as_deref(), Some("vm-test"));
            assert_eq!(event.detail.as_deref(), Some("dst=1.2.3.4:443,proto=tcp"));
        }
    }

    // =====================================================================
    // gateway-flow audit kinds
    // =====================================================================

    /// Mirrors the network-policy roundtrip pattern: every reserved
    /// gateway-flow variant must serde-roundtrip cleanly so emission
    /// lands independently without re-bumping the audit schema.
    #[test]
    fn w7_flow_audit_kinds_serde_roundtrip() {
        let kinds = vec![
            LocalAuditKind::FlowOpened,
            LocalAuditKind::FlowClosed,
            LocalAuditKind::FlowBytes,
            LocalAuditKind::FlowPolicyDecision,
        ];
        for kind in kinds {
            let event = stub_event(kind.clone(), None, None);
            let json = serde_json::to_string(&event).unwrap();
            let parsed: LocalAuditEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.kind, kind, "kind round-trip diverged: {kind:?}");
        }
    }

    /// Wire-format pin for the four gateway-flow variants. A future
    /// rename surfaces here as a failing test and forces a conscious
    /// decision about old-log readability.
    #[test]
    fn w7_flow_audit_kinds_use_snake_case_on_the_wire() {
        let kinds_and_strings = vec![
            (LocalAuditKind::FlowOpened, "flow_opened"),
            (LocalAuditKind::FlowClosed, "flow_closed"),
            (LocalAuditKind::FlowBytes, "flow_bytes"),
            (LocalAuditKind::FlowPolicyDecision, "flow_policy_decision"),
        ];
        for (kind, expected) in kinds_and_strings {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(
                json,
                format!("\"{expected}\""),
                "W7 audit kind wire format drifted for {kind:?}"
            );
        }
    }

    /// `FlowPolicyDecision` is distinct from the admission-time
    /// `NetworkPolicyAllow` / `NetworkPolicyDeny` kinds. A future
    /// maintainer who tries to collapse them fails this test and
    /// reads the doc comment explaining why they are separate
    /// (admission-time decisions vs runtime re-evaluations on an
    /// already-open flow).
    #[test]
    fn w7_flow_policy_decision_is_separate_from_w2_network_policy() {
        assert_ne!(
            LocalAuditKind::FlowPolicyDecision,
            LocalAuditKind::NetworkPolicyAllow
        );
        assert_ne!(
            LocalAuditKind::FlowPolicyDecision,
            LocalAuditKind::NetworkPolicyDeny
        );
        let flow = serde_json::to_string(&LocalAuditKind::FlowPolicyDecision).unwrap();
        let allow = serde_json::to_string(&LocalAuditKind::NetworkPolicyAllow).unwrap();
        let deny = serde_json::to_string(&LocalAuditKind::NetworkPolicyDeny).unwrap();
        assert_ne!(
            flow, allow,
            "FlowPolicyDecision and NetworkPolicyAllow must serialize differently \
             — admission-time decisions vs runtime re-evaluations are distinct \
             auditing surfaces."
        );
        assert_ne!(flow, deny);
    }

    /// Each new gateway-flow variant must compose with the standard
    /// `LocalAuditEvent` constructor. Catches a future regression
    /// where a variant accidentally drops `Clone` or stops being
    /// usable with the existing event shape.
    #[test]
    fn w7_flow_audit_kinds_compose_with_event_constructor() {
        let cases = [
            LocalAuditKind::FlowOpened,
            LocalAuditKind::FlowClosed,
            LocalAuditKind::FlowBytes,
            LocalAuditKind::FlowPolicyDecision,
        ];
        for kind in cases {
            let event = stub_event(
                kind.clone(),
                Some("vm-test".to_string()),
                Some("flow_id=deadbeef,bytes_in=42,bytes_out=24".to_string()),
            );
            assert_eq!(event.kind, kind);
            assert_eq!(event.vm_name.as_deref(), Some("vm-test"));
            assert_eq!(
                event.detail.as_deref(),
                Some("flow_id=deadbeef,bytes_in=42,bytes_out=24")
            );
        }
    }

    #[test]
    fn test_local_audit_event_serializes() {
        let event = stub_event(
            LocalAuditKind::VmStart,
            Some("my-vm".to_string()),
            Some("flake=.".to_string()),
        );
        let json = serde_json::to_string(&event).unwrap();
        let parsed: LocalAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kind, LocalAuditKind::VmStart);
        assert_eq!(parsed.vm_name.as_deref(), Some("my-vm"));
        assert_eq!(parsed.detail.as_deref(), Some("flake=."));
        assert!(!parsed.timestamp.is_empty());
    }

    #[test]
    fn test_local_audit_kind_all_variants_serialize() {
        let kinds = [
            LocalAuditKind::VmStart,
            LocalAuditKind::VmStop,
            LocalAuditKind::KeyLookup,
            LocalAuditKind::VolumeCreate,
            LocalAuditKind::VolumeOpen,
            LocalAuditKind::VolumeLock,
            LocalAuditKind::VolumeSnapshot,
            LocalAuditKind::VolumeRestore,
            LocalAuditKind::UpdateInstall,
            LocalAuditKind::Uninstall,
            LocalAuditKind::NetworkCreate,
            LocalAuditKind::NetworkRemove,
            LocalAuditKind::ImageFetch,
            LocalAuditKind::TemplateBuild,
            LocalAuditKind::TemplatePush,
            LocalAuditKind::TemplatePull,
            LocalAuditKind::ConfigChange,
            LocalAuditKind::ConsoleSessionStart,
            LocalAuditKind::ConsoleSessionEnd,
            // Reserved future verbs.
            LocalAuditKind::PlanSubmit,
            LocalAuditKind::PolicyApply,
            LocalAuditKind::PolicyRollback,
            LocalAuditKind::HostTrustSet,
            LocalAuditKind::SupervisorRestart,
            LocalAuditKind::Quarantine,
            LocalAuditKind::Kill,
            LocalAuditKind::ArtifactFetch,
            LocalAuditKind::WorkloadWake,
            LocalAuditKind::WorkloadSleep,
            // Egress L7.
            LocalAuditKind::EgressCaRotated,
            // Lifecycle integrity gap-fillers.
            LocalAuditKind::TemplateBuildError,
            LocalAuditKind::SnapshotIntegrityFailed,
            LocalAuditKind::ImageVerifyFailed,
            // Registry / cache mutations.
            LocalAuditKind::CachePrune,
            LocalAuditKind::SlotRemove,
            LocalAuditKind::SlotPrune,
            // Session lifecycle.
            LocalAuditKind::SessionStart,
            LocalAuditKind::SessionAttach,
            LocalAuditKind::SessionExec,
            LocalAuditKind::SessionRunCode,
            LocalAuditKind::SessionConsoleOpen,
            LocalAuditKind::SessionKill,
            LocalAuditKind::SessionReap,
            // Trust-store mutations.
            LocalAuditKind::TrustAdd,
            LocalAuditKind::TrustRemove,
            // Bundle registry mutations.
            LocalAuditKind::BundleInstall,
            LocalAuditKind::BundleGc,
            // OCI export follow-on.
            LocalAuditKind::ImageExportOci,
            // Stage 0 bootstrap lifecycle.
            LocalAuditKind::Stage0Boot,
            LocalAuditKind::Stage0CachePromoted,
            LocalAuditKind::Stage0Failed,
            // Gateway-flow audit (claim 10 leg 2).
            LocalAuditKind::FlowOpened,
            LocalAuditKind::FlowClosed,
            LocalAuditKind::FlowBytes,
            LocalAuditKind::FlowPolicyDecision,
            // Vendored-blob supply-chain fetch.
            LocalAuditKind::VendorBlobFetched,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn lifecycle_gap_kinds_use_snake_case_on_the_wire() {
        // Pin the casing for the new gap-fillers exactly like the
        // reserved and egress kinds — the audit log is a stable
        // parsed format for downstream tools (`mvmctl audit`, log
        // shippers).
        let kinds_and_strings = [
            (LocalAuditKind::TemplateBuildError, "template_build_error"),
            (
                LocalAuditKind::SnapshotIntegrityFailed,
                "snapshot_integrity_failed",
            ),
            (LocalAuditKind::ImageVerifyFailed, "image_verify_failed"),
            (LocalAuditKind::CachePrune, "cache_prune"),
            (LocalAuditKind::SlotRemove, "slot_remove"),
            (LocalAuditKind::SlotPrune, "slot_prune"),
            (LocalAuditKind::SessionStart, "session_start"),
            (LocalAuditKind::SessionAttach, "session_attach"),
            (LocalAuditKind::SessionExec, "session_exec"),
            (LocalAuditKind::SessionRunCode, "session_run_code"),
            (LocalAuditKind::SessionConsoleOpen, "session_console_open"),
            (LocalAuditKind::SessionKill, "session_kill"),
            (LocalAuditKind::SessionReap, "session_reap"),
            // Trust-store mutations.
            (LocalAuditKind::TrustAdd, "trust_add"),
            (LocalAuditKind::TrustRemove, "trust_remove"),
            // Bundle registry mutations.
            (LocalAuditKind::BundleInstall, "bundle_install"),
            (LocalAuditKind::BundleGc, "bundle_gc"),
            // OCI export follow-on.
            (LocalAuditKind::ImageExportOci, "image_export_oci"),
            // Stage 0 bootstrap lifecycle. Wire strings are
            // load-bearing: downstream log shippers / dashboards filter
            // on `kind == "stage0_boot"` etc., so the snake-case
            // mapping needs a pinned regression test.
            (LocalAuditKind::Stage0Boot, "stage0_boot"),
            (LocalAuditKind::Stage0CachePromoted, "stage0_cache_promoted"),
            (LocalAuditKind::Stage0Failed, "stage0_failed"),
            // Vendored-blob supply-chain fetch. Wire string is
            // load-bearing: `mvmctl audit` + log shippers
            // filter on `kind == "vendor_blob_fetched"`.
            (LocalAuditKind::VendorBlobFetched, "vendor_blob_fetched"),
        ];
        for (kind, expected) in kinds_and_strings {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
        }
    }

    #[test]
    fn test_egress_ca_rotated_uses_snake_case_rename() {
        // Pin the wire form so a future rename can't silently drift the
        // audit log shape — downstream parsers (`mvmctl audit`,
        // out-of-band log shippers) match on the literal string.
        let json = serde_json::to_string(&LocalAuditKind::EgressCaRotated).unwrap();
        assert_eq!(json, "\"egress_ca_rotated\"");
    }
}
