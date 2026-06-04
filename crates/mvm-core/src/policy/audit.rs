use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::security::{GateDecision, ThreatFinding};

// ============================================================================
// Local mvmctl audit log (single-host operations)
// ============================================================================

/// Default path for the local audit log.
///
/// Prefers XDG state directory (`~/.local/state/mvm/log/`). Falls back to
/// legacy `~/.mvm/log/` if an audit log already exists there.
pub fn default_audit_log() -> String {
    // Check legacy location for backward compat
    let legacy = format!("{}/log/audit.jsonl", crate::config::mvm_data_dir());
    if std::path::Path::new(&legacy).exists() {
        return legacy;
    }
    format!("{}/log/audit.jsonl", crate::config::mvm_state_dir())
}

/// Rotate when the audit log exceeds this size.
const ROTATE_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

/// Categories of local mvmctl operations that are audit-logged.
///
/// Plan 37 §6 invariant: "no unaudited control-plane mutation". Every
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
    UpdateInstall,
    Uninstall,
    // --- DX features (Phase 2) ---
    NetworkCreate,
    NetworkRemove,
    ImageFetch,
    TemplateBuild,
    TemplatePush,
    TemplatePull,
    ConfigChange,
    ConsoleSessionStart,
    ConsoleSessionEnd,
    // --- MCP server (plan 32 / Proposal A) ---
    /// `tools/call run` invocation — every LLM-driven code execution
    /// against a microVM is auditable.
    McpToolsCallRun,
    /// `tools/call run` failed before completing (orchestration error,
    /// not a non-zero guest exit code).
    McpToolsCallRunError,
    /// MCP session opened — first call with a previously-unseen
    /// `session=ID` parameter (plan 32 / Proposal A.2).
    McpSessionStarted,
    /// MCP session closed by the client (`close: true`) or reaped
    /// by the server (idle / max-lifetime / shutdown drain).
    McpSessionClosed,
    // --- Plan 37 future verbs (B21) -----------------------------
    // These kinds are reserved here so the wire format is stable
    // before the corresponding CLI verbs ship. Each will be emitted
    // by its own command in a subsequent PR. Reserving them now
    // lets the parallel agents working on Wave 2.6 (egress proxy)
    // and Wave 3 (supervisor commands) land their verbs without
    // re-bumping the audit schema.
    /// `mvmctl plan submit <signed-plan>` — admission of a signed
    /// `ExecutionPlan`. Distinct from the supervisor's per-state
    /// `plan.admitted` event (B19): this is the local CLI verb that
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
    /// supervisor process (plan 37 §7B Zone B).
    SupervisorRestart,
    /// `mvmctl quarantine <workload>` — freeze a running workload.
    /// Distinct from `kill`: quarantined workloads can be resumed
    /// for forensics; killed workloads cannot.
    Quarantine,
    /// `mvmctl kill <workload>` — terminal teardown of a running
    /// workload. Plan 37 Addendum B6.
    Kill,
    /// `mvmctl artifact fetch <plan_id>` — retrieve captured
    /// artifacts from the supervisor's artifact store. Plan 37 §21.
    ArtifactFetch,
    /// `mvmctl wake <workload>` / `mvmctl sleep <workload>` —
    /// supervisor-driven snapshot suspend/resume.
    WorkloadWake,
    WorkloadSleep,
    // --- Egress L7 (plan 34 / ADR-006) ---
    /// Host CA for hypervisor-level L7 egress interception was
    /// rotated. ADR-006 §"Decisions" 7 — rotation is explicit, not
    /// implicit; every rotation lands in the audit log with old +
    /// new fingerprints + the list of VMs whose per-VM leaves were
    /// re-signed. Plan 34 §"Files (summary)".
    EgressCaRotated,
    // --- Lifecycle integrity events ---
    /// `mvmctl build` failed before producing a slot/revision. Paired
    /// with the existing `TemplateBuild` success kind so every build
    /// attempt — success or failure — leaves a single audit line.
    TemplateBuildError,
    /// Snapshot integrity verification failed at resume time. Covers
    /// HMAC tag mismatch (tampered bytes or rotated host key), version
    /// mismatch under strict mode, and lower-level I/O / encoding
    /// failures from `crate::crypto::snapshot_hmac::verify`. ADR-007 /
    /// plan 41 W4 — refusing to resume a tampered snapshot is a
    /// security signal and must be auditable.
    SnapshotIntegrityFailed,
    /// Pre-flight verification of a downloaded dev image manifest
    /// failed: cosign signature invalid, manifest version pin off,
    /// `not_after` past, or the published version is on the signed
    /// revocation list. Plan 36 / ADR 005 — every refusal is an
    /// auditable event so an operator can correlate "image rejected
    /// at 14:03" with their CDN logs.
    ImageVerifyFailed,
    // --- Registry / cache mutations (Plan 37 §6 invariant fillers) ---
    /// `mvmctl cache prune` removed temporary files / empty subdirs
    /// from `~/.cache/mvm`. Pure read-only `cache info` is not
    /// audited; the prune verb is, because it deletes host bytes.
    CachePrune,
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
    /// `mvmctl vm volume add` / `volume remove` — mounts or unmounts
    /// a virtio-fs volume into a running guest. (Plan 45 — rename of
    /// the prior `VmShareAdd` / `VmShareRemove` per Path C; no compat
    /// shim, no behavioural change.)
    VmVolumeAdd,
    VmVolumeRemove,
    // --- Plan 46: metering API ---
    /// One per-minute metering bucket sealed and chained into the
    /// audit log. Plan 46 — auditing-grade resource attribution. The
    /// `detail` field carries a JSON-encoded `MeteringBucket`
    /// (`mvm_core::metering::MeteringBucket`) so a forensic pass can
    /// reconstruct per-tenant resource consumption end-to-end without
    /// trusting the per-tenant JSONL rollup file (which the audit
    /// chain authenticates by sealing each bucket here).
    MeteringEpoch,
    // --- Sprint 52 W2: bundle trust store mutations ---
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
    // --- Plan 47: dm-thin storage pool ops ---
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
    // --- Phase 5 session lifecycle (post-fd-3-fix audit posture) ---
    //
    // Dev sessions hold a long-lived microVM with PTY / shell-exec
    // surface available behind the session id. The session id IS the
    // capability: anyone with read access to
    // `$XDG_RUNTIME_DIR/mvm/sessions/<id>.json` can attach. Every
    // dev-shell entry point therefore lands in the audit log so a
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
    // --- Plan 73 Followup C: deps-volume audit verbs ---
    /// `mvmctl deps audit` re-ran the CVE scan against a cached deps
    /// volume and resealed it. Detail carries the prior + new volume
    /// hashes plus the count of high/critical CVE findings surfaced.
    /// Emitted once per volume processed (so `--all` produces N
    /// records, one per volume).
    DepsAudit,

    // --- Plan 77 W3: Stage 0 builder VM bootstrap lifecycle ---
    //
    // Three events bracket the per-host Stage 0 lifecycle so a
    // contributor can answer "did `dev up` actually run Stage 0 last
    // night, and how did it land?" after the fact. The rescued plan
    // doc sketched a separate `~/.mvm/audit/stage0.jsonl` file; we
    // emit into the shared local audit log instead because (a) every
    // other contributor-side event already lands there, (b) the
    // schema/macro/rotation already exists, and (c) operators filter
    // by `kind` not by file. The `kind` strings (`stage0_boot`,
    // `stage0_cache_promoted`, `stage0_failed`) are stable.
    //
    // Detail formats are space-separated key=value pairs to match
    // every other call site (the macro can't emit JSON without a
    // wider schema change). SHAs are intentionally omitted — hashing
    // a 700 MiB rootfs on every `dev up` is too expensive for an
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

    // --- Plan 74 W2: programmable network policy enforcement events ---
    //
    // Five new kinds wired into the L3 iptables / L4 substrate / DNS
    // pin paths. State-only slice: variants ship here so emission
    // sites land in their own focused PRs without re-bumping the
    // audit schema each time. Wire format is stable (snake_case
    // strings) per the enum's `rename_all` attribute.
    //
    // Detail-format conventions across the five (so a future
    // dashboard parses uniformly):
    //   - `proto=<tcp|udp>` always first when L4 protocol applies.
    //   - `dst=<ip:port>` for the destination tuple, `ip` for an
    //     IP-only event.
    //   - additional key=value pairs comma-separated, no spaces.
    //
    /// L4 allow decision: a flow matched a policy rule and was
    /// permitted. Plan 74 W2 §"Emit audit entries for every
    /// allow/deny". Fired from `L4Policy::evaluate` and from the
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
    /// denials. Plan 74 W2 §item 4. Detail format:
    ///   `proto=<tcp|udp>,dst=<ip:port>,category=<cloud-metadata|link-local|cgnat|loopback>`
    NetworkMandatoryDeny,
    /// Supervisor admission resolved a destination host to one or
    /// more IPs and pinned them for the lifetime of the workload.
    /// Plan 74 W2 item 1. Fires once per `(workload, destination)`
    /// pair at admission, before the guest boots. Detail format:
    ///   `dest=<host>,ips=<ip[,ip...]>,ttl_s=<n>`
    DnsPinSet,
    /// A guest request resolved (via the egress proxy or supervisor
    /// resolver) to an IP that didn't match the admission-time pin.
    /// Distinct from `NetworkPolicyDeny`: this is a TOCTOU /
    /// rebinding signal, not a missing-allow signal. Detail format:
    ///   `dest=<host>,pinned_ips=<ip[,ip...]>,observed_ip=<ip>`
    DnsPinReject,

    // --- Plan 101 W7: gateway-flow audit kinds (claim 10 leg 2) ---
    //
    // Four new kinds emitted by the gvproxy (macOS) / passt (Linux)
    // control-socket wrapper. State-only slice: variants ship here so
    // emission sites land in their own focused PRs without re-bumping
    // the audit schema each time. Wire format is stable (snake_case
    // strings) per the enum's `rename_all` attribute.
    //
    // Detail-format conventions (populated by Plan 101 W6 — emission
    // PR; documented here so the names match the intended payload):
    //   - `flow_id=<u64-hex>` is the join key across all four kinds
    //     for a single flow's lifecycle.
    //   - per-direction byte counters are `bytes_in` / `bytes_out` on
    //     terminal events, `bytes_in_delta` / `bytes_out_delta` on
    //     periodic `FlowBytes` aggregates.
    //   - durations / windows are milliseconds / seconds, named
    //     `*_ms` / `*_s` to match the rest of the audit log.
    //
    /// A new outbound flow opened through gvproxy/passt. Fired once
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
    /// Per-byte audit is too noisy; emission policy lives in Plan
    /// 101 W8 (default: emit every 30s for flows still open beyond
    /// the window). Counters are deltas since the previous
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

    // --- Plan 93 Phase 3: vendored-blob supply-chain fetch ---
    //
    // Emitted once per vendored bootstrap blob each time it is fetched
    // or revalidated from cache, so every hash+signature trust
    // decision in the no-prebuilt-download supply chain is auditable.
    // Today the only such blob is the Plan 91 Alpine minirootfs; the
    // kind is forward-compatible with any future pinned asset. Lands
    // in the shared local audit log (not the chain-signed stream),
    // matching the Stage 0 siblings above. Wire string is stable
    // (`vendor_blob_fetched`) — log shippers / `mvmctl audit` filter
    // on it.
    //
    /// A vendored bootstrap blob was downloaded and verified, or
    /// re-verified on a cache hit. Detail format (space-separated
    /// `key=value`, matching the Stage 0 kinds):
    ///   `url=<url> sha256=<64hex> pgp=<verified|none|failed> bytes=<n> outcome=<fetched|cache_revalidated>`
    VendorBlobFetched,
}

/// A single local audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAuditEvent {
    pub timestamp: String,
    pub kind: LocalAuditKind,
    pub vm_name: Option<String>,
    pub detail: Option<String>,
}

impl LocalAuditEvent {
    /// Create an event stamped with the current UTC time.
    pub fn now(kind: LocalAuditKind, vm_name: Option<String>, detail: Option<String>) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();
        Self {
            timestamp,
            kind,
            vm_name,
            detail,
        }
    }
}

/// Append-only local audit log writer.
pub struct LocalAuditLog {
    path: PathBuf,
}

impl LocalAuditLog {
    /// Open (or create) a local audit log at `path`.
    ///
    /// Creates parent directories if they don't exist.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create audit log dir: {}", parent.display()))?;
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Append one JSONL line.  Rotates to `audit.jsonl.1` when the file
    /// exceeds [`ROTATE_THRESHOLD_BYTES`].
    pub fn append(&self, event: &LocalAuditEvent) -> Result<()> {
        self.maybe_rotate()?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("Failed to open audit log: {}", self.path.display()))?;

        let line = serde_json::to_string(event).context("Failed to serialize audit event")?;
        writeln!(file, "{line}").context("Failed to write audit event")?;
        Ok(())
    }

    fn maybe_rotate(&self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let meta = std::fs::metadata(&self.path)
            .with_context(|| format!("Failed to stat {}", self.path.display()))?;
        if meta.len() >= ROTATE_THRESHOLD_BYTES {
            let rotated = self.path.with_extension("jsonl.1");
            std::fs::rename(&self.path, &rotated)
                .with_context(|| format!("Failed to rotate audit log to {}", rotated.display()))?;
        }
        Ok(())
    }
}

/// Convenience macro for the most common audit emit shapes.
///
/// The four arms mirror the chained-builder forms but collapse the
/// `event(LocalAuditKind::Variant)…emit()` boilerplate to a single
/// line:
///
/// ```ignore
/// // bare — no vm_name, no detail
/// audit_emit!(CachePrune);
///
/// // detail via format-string
/// audit_emit!(StorageGc, "count={count}");
/// audit_emit!(SlotPrune, "source={src} count={n}", src = "x", n = 4);
///
/// // vm_name + no detail
/// audit_emit!(SlotRemove, vm: slot_hash);
///
/// // vm_name + format-string detail (positional or named args)
/// audit_emit!(
///     SlotRemove,
///     vm: slot_hash,
///     "manifest_path={} manifest_file_deleted={deleted}",
///     path.display(),
///     deleted = file_was_deleted,
/// );
/// ```
///
/// More elaborate compositions (multiple modifiers, conditional
/// fields) should drop down to [`event`] + [`LocalAuditBuilder`]
/// directly. The macro deliberately doesn't add knobs beyond the
/// four shapes — every existing call site falls into one of them.
#[macro_export]
macro_rules! audit_emit {
    // Bare:  audit_emit!(CachePrune)
    ($variant:ident $(,)?) => {
        $crate::policy::audit::event(
            $crate::policy::audit::LocalAuditKind::$variant
        ).emit()
    };

    // vm_name + format-string detail (positional or named format args):
    //   audit_emit!(SlotRemove, vm: hash, "path={}", p);
    //   audit_emit!(SlotRemove, vm: hash, "k={v}", v = "x");
    ($variant:ident, vm: $vm:expr, $($args:tt)+) => {
        $crate::policy::audit::event(
            $crate::policy::audit::LocalAuditKind::$variant
        )
            .vm_name($vm)
            .detail(format!($($args)+))
            .emit()
    };

    // vm_name only:  audit_emit!(SlotRemove, vm: hash)
    ($variant:ident, vm: $vm:expr $(,)?) => {
        $crate::policy::audit::event(
            $crate::policy::audit::LocalAuditKind::$variant
        )
            .vm_name($vm)
            .emit()
    };

    // Format-string detail (positional or named format args):
    //   audit_emit!(StorageGc, "count={count}");
    //   audit_emit!(SlotPrune, "src={src} count={n}", src = "x", n = 4);
    ($variant:ident, $($args:tt)+) => {
        $crate::policy::audit::event(
            $crate::policy::audit::LocalAuditKind::$variant
        )
            .detail(format!($($args)+))
            .emit()
    };
}

/// Start composing a local audit event.
///
/// Preferred over the positional [`emit`] / [`emit_to`] helpers — chains
/// read top-to-bottom and adding a new optional field (e.g. `outcome`)
/// won't churn every call site. The event lands in
/// [`default_audit_log`] when terminated with [`LocalAuditBuilder::emit`];
/// tests redirect via [`LocalAuditBuilder::to_path`] before terminating.
///
/// ```ignore
/// audit::event(LocalAuditKind::CachePrune)
///     .detail(format!("count={count}"))
///     .emit();
/// ```
pub fn event(kind: LocalAuditKind) -> LocalAuditBuilder {
    LocalAuditBuilder {
        kind,
        vm_name: None,
        detail: None,
        path_override: None,
    }
}

/// Fluent builder for [`LocalAuditEvent`]. Construct with [`event`].
#[must_use = "the audit event isn't written until `.emit()` is called"]
pub struct LocalAuditBuilder {
    kind: LocalAuditKind,
    vm_name: Option<String>,
    detail: Option<String>,
    path_override: Option<PathBuf>,
}

impl LocalAuditBuilder {
    /// Attach a VM identifier to the event. Optional.
    pub fn vm_name(mut self, name: impl Into<String>) -> Self {
        self.vm_name = Some(name.into());
        self
    }

    /// Attach a free-form `detail` string. Conventionally a
    /// space-separated `key=value` list (`source=… count=…`).
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Redirect the emission to an explicit path instead of
    /// [`default_audit_log`]. Used by tests so emission can be
    /// observed without mutating `MVM_STATE_DIR` (which serializes
    /// badly across the test runner).
    pub fn to_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path_override = Some(path.into());
        self
    }

    /// Land the event. Best-effort: open/write failures are logged
    /// via `tracing::warn!` and never propagated — audit failures
    /// must not block the operation being logged.
    pub fn emit(self) {
        let path = self
            .path_override
            .unwrap_or_else(|| PathBuf::from(default_audit_log()));
        let event = LocalAuditEvent::now(self.kind, self.vm_name, self.detail);
        match LocalAuditLog::open(&path).and_then(|log| log.append(&event)) {
            Ok(()) => {}
            Err(e) => tracing::warn!("audit log write failed: {e}"),
        }
    }
}

/// Emit a local audit event to the default log path (best-effort).
///
/// Thin shim over [`event`] / [`LocalAuditBuilder::emit`] kept for
/// existing positional call sites. New code should prefer the builder
/// — the chained form scales to additional optional fields without
/// touching every caller.
pub fn emit(kind: LocalAuditKind, vm_name: Option<&str>, detail: Option<&str>) {
    let mut b = event(kind);
    if let Some(n) = vm_name {
        b = b.vm_name(n);
    }
    if let Some(d) = detail {
        b = b.detail(d);
    }
    b.emit();
}

/// Emit a local audit event to an explicit path (best-effort).
///
/// Thin shim over [`event`] / [`LocalAuditBuilder::to_path`] kept for
/// existing positional call sites. Tests should prefer
/// `event(kind).to_path(p).emit()` for parity with production-path
/// composition.
pub fn emit_to(path: &Path, kind: LocalAuditKind, vm_name: Option<&str>, detail: Option<&str>) {
    let mut b = event(kind).to_path(path.to_path_buf());
    if let Some(n) = vm_name {
        b = b.vm_name(n);
    }
    if let Some(d) = detail {
        b = b.detail(d);
    }
    b.emit();
}

/// Return the most recent Stage 0 lifecycle event (`Stage0Boot`,
/// `Stage0CachePromoted`, or `Stage0Failed`) in the default local
/// audit log, or `None` if Stage 0 has never run. Plan 93 Phase 3 —
/// `mvmctl doctor` uses this to answer "when did Stage 0 last run and
/// how did it land?" without grep-ing the log.
pub fn read_last_stage0_event() -> Option<LocalAuditEvent> {
    read_last_stage0_event_in(Path::new(&default_audit_log()))
}

/// [`read_last_stage0_event`] against an explicit log path (tests
/// inject a temp JSONL so they don't depend on `$HOME`). Reads only
/// the live `audit.jsonl` (not the rotated `.1`) and caps the scan to
/// the tail so `doctor` stays fast on a large log. Malformed lines are
/// skipped rather than fatal — the log is observability, not a parser
/// contract.
pub fn read_last_stage0_event_in(path: &Path) -> Option<LocalAuditEvent> {
    /// Bound the scan so a near-rotation-size log (10 MiB) doesn't make
    /// `doctor` parse every line; the last Stage 0 event is always near
    /// the tail in practice.
    const MAX_TAIL_LINES: usize = 4096;
    let contents = std::fs::read_to_string(path).ok()?;
    let mut lines: Vec<&str> = contents.lines().collect();
    if lines.len() > MAX_TAIL_LINES {
        lines = lines.split_off(lines.len() - MAX_TAIL_LINES);
    }
    lines
        .iter()
        .rev()
        .filter_map(|line| serde_json::from_str::<LocalAuditEvent>(line).ok())
        .find(|ev| {
            matches!(
                ev.kind,
                LocalAuditKind::Stage0Boot
                    | LocalAuditKind::Stage0CachePromoted
                    | LocalAuditKind::Stage0Failed
            )
        })
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
    // -- Vsock security (Phase 8) --
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
        use crate::security::{GateDecision, Severity, ThreatCategory, ThreatFinding};

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
    // LocalAuditEvent / LocalAuditLog tests
    // -------------------------------------------------------------------------

    #[test]
    fn b21_reserved_audit_kinds_serde_roundtrip() {
        // B21 reserves audit kinds for plan-37 future verbs so the
        // wire format stays stable before each CLI verb ships. This
        // test is the contract — older builds must accept any of
        // these snake_case variants without rejecting them.
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
            let event = LocalAuditEvent::now(kind.clone(), None, None);
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
    // Plan 74 W2 — network policy audit kinds (state-only slice)
    // =====================================================================

    /// Same shape as `b21_reserved_audit_kinds_serde_roundtrip`:
    /// every new W2 variant must serde-roundtrip cleanly so emission
    /// PRs can land independently without re-bumping the audit
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
            let event = LocalAuditEvent::now(kind.clone(), None, None);
            let json = serde_json::to_string(&event).unwrap();
            let parsed: LocalAuditEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.kind, kind, "kind round-trip diverged: {kind:?}");
        }
    }

    /// Wire-format pin for the W2 variants. Pinned so a future
    /// rename surfaces as a failing test and forces a conscious
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
            let event = LocalAuditEvent::now(
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
    // Plan 101 W7 — gateway-flow audit kinds (state-only slice)
    // =====================================================================

    /// Mirrors the W2 / B21 roundtrip pattern: every reserved W7
    /// variant must serde-roundtrip cleanly so the W6 emission PRs
    /// land independently without re-bumping the audit schema.
    #[test]
    fn w7_flow_audit_kinds_serde_roundtrip() {
        let kinds = vec![
            LocalAuditKind::FlowOpened,
            LocalAuditKind::FlowClosed,
            LocalAuditKind::FlowBytes,
            LocalAuditKind::FlowPolicyDecision,
        ];
        for kind in kinds {
            let event = LocalAuditEvent::now(kind.clone(), None, None);
            let json = serde_json::to_string(&event).unwrap();
            let parsed: LocalAuditEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.kind, kind, "kind round-trip diverged: {kind:?}");
        }
    }

    /// Wire-format pin for the four W7 variants. A future rename
    /// surfaces here as a failing test and forces a conscious
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

    /// `FlowPolicyDecision` is distinct from the W2 admission-time
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

    /// Each new W7 variant must compose with the standard
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
            let event = LocalAuditEvent::now(
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
        let event = LocalAuditEvent::now(
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
            LocalAuditKind::McpToolsCallRun,
            LocalAuditKind::McpToolsCallRunError,
            LocalAuditKind::McpSessionStarted,
            LocalAuditKind::McpSessionClosed,
            // B21 reserved future verbs.
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
            // Plan 34 / ADR-006 egress L7.
            LocalAuditKind::EgressCaRotated,
            // Lifecycle integrity gap-fillers.
            LocalAuditKind::TemplateBuildError,
            LocalAuditKind::SnapshotIntegrityFailed,
            LocalAuditKind::ImageVerifyFailed,
            // Registry / cache mutations.
            LocalAuditKind::CachePrune,
            LocalAuditKind::SlotRemove,
            LocalAuditKind::SlotPrune,
            // Phase 5 session lifecycle.
            LocalAuditKind::SessionStart,
            LocalAuditKind::SessionAttach,
            LocalAuditKind::SessionExec,
            LocalAuditKind::SessionRunCode,
            LocalAuditKind::SessionConsoleOpen,
            LocalAuditKind::SessionKill,
            LocalAuditKind::SessionReap,
            // Sprint 52 W2 trust-store mutations.
            LocalAuditKind::TrustAdd,
            LocalAuditKind::TrustRemove,
            // Sprint 52 W2 bundle registry mutations.
            LocalAuditKind::BundleInstall,
            LocalAuditKind::BundleGc,
            // OCI export follow-on.
            LocalAuditKind::ImageExportOci,
            // Plan 77 W3 Stage 0 bootstrap lifecycle.
            LocalAuditKind::Stage0Boot,
            LocalAuditKind::Stage0CachePromoted,
            LocalAuditKind::Stage0Failed,
            // Plan 101 W7 gateway-flow audit (claim 10 leg 2).
            LocalAuditKind::FlowOpened,
            LocalAuditKind::FlowClosed,
            LocalAuditKind::FlowBytes,
            LocalAuditKind::FlowPolicyDecision,
            // Plan 93 Phase 3 vendored-blob supply-chain fetch.
            LocalAuditKind::VendorBlobFetched,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn lifecycle_gap_kinds_use_snake_case_on_the_wire() {
        // Pin the casing for the new gap-fillers exactly like the B21
        // and egress kinds — the audit log is a stable parsed format
        // for downstream tools (`mvmctl audit`, log shippers).
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
            // Sprint 52 W2 trust-store mutations.
            (LocalAuditKind::TrustAdd, "trust_add"),
            (LocalAuditKind::TrustRemove, "trust_remove"),
            // Sprint 52 W2 bundle registry mutations.
            (LocalAuditKind::BundleInstall, "bundle_install"),
            (LocalAuditKind::BundleGc, "bundle_gc"),
            // OCI export follow-on.
            (LocalAuditKind::ImageExportOci, "image_export_oci"),
            // Plan 77 W3 Stage 0 bootstrap lifecycle. Wire strings are
            // load-bearing: downstream log shippers / dashboards filter
            // on `kind == "stage0_boot"` etc., so the snake-case
            // mapping needs a pinned regression test.
            (LocalAuditKind::Stage0Boot, "stage0_boot"),
            (LocalAuditKind::Stage0CachePromoted, "stage0_cache_promoted"),
            (LocalAuditKind::Stage0Failed, "stage0_failed"),
            // Plan 93 Phase 3 vendored-blob supply-chain fetch. Wire
            // string is load-bearing: `mvmctl audit` + log shippers
            // filter on `kind == "vendor_blob_fetched"`.
            (LocalAuditKind::VendorBlobFetched, "vendor_blob_fetched"),
        ];
        for (kind, expected) in kinds_and_strings {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
        }
    }

    #[test]
    fn read_last_stage0_event_picks_the_last_stage0_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        // Interleave non-Stage0 events so the reader must filter.
        emit_to(&path, LocalAuditKind::VmStart, Some("vm-a"), None);
        emit_to(
            &path,
            LocalAuditKind::Stage0Boot,
            None,
            Some("seed=root-dir fingerprint_prefix=aaaaaaaa flavor=current"),
        );
        emit_to(&path, LocalAuditKind::VmStop, Some("vm-a"), None);
        emit_to(
            &path,
            LocalAuditKind::Stage0CachePromoted,
            None,
            Some("cache=/x fingerprint_prefix=bbbbbbbb duration_ms=42"),
        );
        emit_to(&path, LocalAuditKind::CachePrune, None, Some("removed=0"));

        let ev = read_last_stage0_event_in(&path).expect("a stage0 event");
        // The promoted event is the most recent Stage 0 entry.
        assert!(matches!(ev.kind, LocalAuditKind::Stage0CachePromoted));
        assert_eq!(
            ev.detail.as_deref(),
            Some("cache=/x fingerprint_prefix=bbbbbbbb duration_ms=42")
        );
    }

    #[test]
    fn read_last_stage0_event_is_none_without_stage0_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        emit_to(&path, LocalAuditKind::VmStart, Some("vm-a"), None);
        emit_to(&path, LocalAuditKind::CachePrune, None, Some("removed=0"));
        assert!(read_last_stage0_event_in(&path).is_none());
    }

    #[test]
    fn read_last_stage0_event_missing_log_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.jsonl");
        assert!(read_last_stage0_event_in(&path).is_none());
    }

    #[test]
    fn emit_to_writes_a_single_jsonl_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        emit_to(
            &path,
            LocalAuditKind::SnapshotIntegrityFailed,
            Some("vm-x"),
            Some("variant=tag_mismatch"),
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1, "exactly one line per emit");
        assert!(contents.contains("snapshot_integrity_failed"));
        assert!(contents.contains("vm-x"));
        assert!(contents.contains("tag_mismatch"));
    }

    #[test]
    fn builder_with_no_optionals_matches_legacy_emit() {
        // Builder default state is the same wire shape `emit` produces
        // with `(kind, None, None)` — minus the timestamp string,
        // which is `now()` on each call. The kind + null optionals
        // are what matter for the contract.
        let tmp = tempfile::tempdir().unwrap();
        let p_builder = tmp.path().join("builder.jsonl");
        let p_legacy = tmp.path().join("legacy.jsonl");

        event(LocalAuditKind::CachePrune).to_path(&p_builder).emit();
        emit_to(&p_legacy, LocalAuditKind::CachePrune, None, None);

        let builder_line = std::fs::read_to_string(&p_builder).unwrap();
        let legacy_line = std::fs::read_to_string(&p_legacy).unwrap();
        // Drop the timestamp segment from each so we compare shape, not
        // wall-clock drift between the two `chrono::Utc::now()` calls.
        let strip_ts = |s: &str| -> String {
            // Format: {"timestamp":"…","kind":"…",…}
            let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
            let mut obj = v.as_object().unwrap().clone();
            obj.remove("timestamp");
            serde_json::to_string(&obj).unwrap()
        };
        assert_eq!(strip_ts(&builder_line), strip_ts(&legacy_line));
    }

    #[test]
    fn builder_with_vm_name_and_detail_carries_both_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        event(LocalAuditKind::VmStop)
            .vm_name("vm-42")
            .detail("source=test")
            .to_path(&path)
            .emit();
        let body = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(v["kind"], "vm_stop");
        assert_eq!(v["vm_name"], "vm-42");
        assert_eq!(v["detail"], "source=test");
    }

    #[test]
    fn audit_emit_macro_all_four_arms_compile() {
        // The macro routes through `default_audit_log()`, which depends
        // on process env vars — driving it from a unit test would need
        // a process-global mutex around `set_var`/`remove_var`. Skip
        // the file-contents check here: end-to-end validation lives in
        // `tests/audit_emissions_live.rs`, where each migrated call
        // site is exercised via a subprocess with hermetic HOME.
        //
        // What this test buys: a compile-time shape check that all
        // four arms expand cleanly against `LocalAuditKind` variants
        // and the surrounding builder API. Renaming a variant or
        // changing `LocalAuditBuilder`'s signature surfaces here as a
        // compile error before the migration sites notice.
        if false {
            crate::audit_emit!(CachePrune);
            crate::audit_emit!(StorageGc, "count={n}", n = 3);
            let hash = String::from("deadbeef");
            crate::audit_emit!(SlotRemove, vm: hash.clone());
            crate::audit_emit!(SlotRemove, vm: hash, "path={p}", p = "/x");
        }
    }

    #[test]
    fn builder_terminator_required_must_use_emit() {
        // Compile-time check that `#[must_use]` on the builder
        // surfaces a warning if a caller forgets `.emit()`. We can't
        // assert the warning in unit tests; this test just shows that
        // the type is usable in the documented chained form so a
        // refactor that breaks the API surfaces as a compile error.
        let _b = event(LocalAuditKind::CachePrune).detail("noop");
        // intentionally not calling `.emit()` — confirms the dead
        // builder is the lint surface, not a runtime panic.
    }

    #[test]
    fn test_egress_ca_rotated_uses_snake_case_rename() {
        // Pin the wire form so a future rename can't silently drift the
        // audit log shape — downstream parsers (`mvmctl audit`,
        // out-of-band log shippers) match on the literal string.
        let json = serde_json::to_string(&LocalAuditKind::EgressCaRotated).unwrap();
        assert_eq!(json, "\"egress_ca_rotated\"");
    }

    #[test]
    fn test_local_audit_log_append() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        let log = LocalAuditLog::open(&path).unwrap();
        let event = LocalAuditEvent::now(LocalAuditKind::VmStop, Some("vm1".to_string()), None);
        log.append(&event).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("vm_stop"));
        assert!(contents.contains("vm1"));
        // One line per event.
        assert_eq!(contents.lines().count(), 1);

        // Append a second event.
        let event2 = LocalAuditEvent::now(
            LocalAuditKind::UpdateInstall,
            None,
            Some("v1.2.3".to_string()),
        );
        log.append(&event2).unwrap();
        let contents2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents2.lines().count(), 2);
    }

    #[test]
    fn test_local_audit_log_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        // Write a file that exceeds the rotation threshold.
        let big_content = "x".repeat(ROTATE_THRESHOLD_BYTES as usize + 1);
        std::fs::write(&path, big_content).unwrap();

        let log = LocalAuditLog::open(&path).unwrap();
        let event = LocalAuditEvent::now(LocalAuditKind::Uninstall, None, None);
        log.append(&event).unwrap();

        // The rotated file should exist.
        let rotated = path.with_extension("jsonl.1");
        assert!(rotated.exists(), "rotation file should be created");

        // The new log file should contain only the new event.
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        assert!(contents.contains("uninstall"));
    }
}
