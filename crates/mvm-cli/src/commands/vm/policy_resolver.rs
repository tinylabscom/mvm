//! `PolicyRef → concrete component slot` resolver.
//!
//! `mvm-core::plan::ExecutionPlan` carries four policy refs that name (but
//! do not contain) the policy bundle a workload runs under:
//!
//! - `network_policy: PolicyRef`
//! - `fs_policy: FsPolicyRef`
//! - `egress_policy: PolicyRef`
//! - `tool_policy: PolicyRef`
//!
//! Each is a freeform string — `"local-default"` for the
//! single-tenant local dev posture, or `"<tenant>:<workload>"` for a
//! mvmd-managed policy bundle on disk at
//! `~/.mvm/policies/<tenant>/<workload>.toml`. The supervisor needs
//! four trait objects (`SupervisorEgressProxy`, `ToolGate`, `KeystoreReleaser`,
//! `ArtifactCollector`) to make admission decisions; this resolver
//! is the function that turns a plan's refs into those objects.
//!
//! ## What lives where
//!
//! Live consumers shipped after parsing a `<tenant>:<workload>`
//! bundle:
//!
//! - `egress_policy` → `L7EgressProxy::new` from
//!   `mvm_hostd::supervisor::l7_proxy`. The chain wraps a
//!   `DestinationPolicy::new(bundle.egress.allow_list)`; CONNECT
//!   targets that miss the allow-list return 403 + audit. Plain-HTTP
//!   is gated on `bundle.egress.allow_plain_http`.
//! - `tool_policy` → `PolicyToolGate::from_policy(&bundle.tool)`
//!   from `mvm_hostd::supervisor::policy_tool_gate`. RPC calls to tool
//!   names absent from `bundle.tool.allowed` get
//!   `ToolDecision::Deny`.
//!
//! Slots still Noop (await the supervisor lift in mvm-hostd):
//!
//! - `KeystoreReleaser` — secret release on the supervisor's
//!   in-process path. Today the `keystore::default_provider()` +
//!   `mvmctl secret` CLI cover operator-facing CRUD; the in-
//!   workload `KeystoreReleaser` consumer ships with the
//!   `Supervisor::launch` integration.
//! - `ArtifactCollector` — wired with the supervisor lift; the
//!   parsed `bundle.artifact.capture_paths` is read but not yet
//!   handed to a live collector.
//!
//! ## No live consumer yet
//!
//! The current callsite (`up.rs::admit_plan_for_boot`) ships
//! `admit + backend.start()` rather than `Supervisor::launch`. The
//! `BackendLauncher` adapter that would consume `ResolvedSlots` via
//! `Supervisor::with_egress` / `with_tool_gate` / etc. lives in the
//! mvm-hostd lift. This
//! module exists as substrate so the lift is a one-line change.
//! The L7EgressProxy + PolicyToolGate constructors are ready
//! and tested; the consumer just hasn't been built yet.
//!
//! ## Dead-code allow
//!
//! Every public item below is currently unused outside this module's
//! tests because `up.rs::admit_plan_for_boot` ships
//! `admit + backend.start()` rather than `Supervisor::launch`. The
//! `#![allow(dead_code)]` mirrors
//! `AdmittedPlan.signed`'s justification — keeping the surface
//! published stabilises the contract for the eventual mvm-hostd
//! consumer.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use mvm_core::plan::{ExecutionPlan, FsPolicyRef, PolicyRef};
use mvm_core::policy::canonicalize_l4;
use mvm_hostd::supervisor::{
    ArtifactCollector, AuditPolicyValidationError, CanonicalL4Gate, EgressPolicyValidationError,
    KeystoreReleaser, L4Gate, L7EgressProxy, LiveArtifactCollector, LiveKeystoreReleaser,
    NoopArtifactCollector, NoopEgressAuditSink, NoopEgressProxy, NoopKeystoreReleaser, NoopL4Gate,
    NoopToolGate, PiiPolicyError, PolicyToolGate, SupervisorEgressProxy, TokioDnsResolver,
    ToolGate, build_inspector_chain_with_pii, validate_audit_policy_stream_destinations,
    validate_egress_policy_inspector_names,
};

/// The fixed identifier for the local-dev policy bundle. Any
/// `PolicyRef`/`FsPolicyRef` whose inner value equals this string
/// resolves to fail-closed Noops — no allow-list, no tool gate, no
/// secret release. Use `<tenant>:<workload>` to point at a real
/// bundle.
pub const LOCAL_DEFAULT: &str = "local-default";

/// Trait-object bundle the supervisor consumes via its
/// `with_l4_gate` / `with_egress` / `with_tool_gate` / `with_keystore`
/// / `with_artifact_collector` builder calls.
///
/// Each field is a `Box<dyn Trait>` so the resolver can return
/// either a Noop (when the plan's refs are `"local-default"`) or
/// a live impl (when a `<tenant>:<workload>` bundle parses) without
/// leaking the concrete type to callers. `egress` and `tool_gate`
/// are live for parsed bundles; the `network` slot does L4
/// flow gating; `keystore` and `artifacts` stay Noop until the
/// supervisor lift in mvm-hostd.
pub struct ResolvedSlots {
    pub network: Box<dyn L4Gate>,
    pub egress: Box<dyn SupervisorEgressProxy>,
    pub tool_gate: Box<dyn ToolGate>,
    pub keystore: Box<dyn KeystoreReleaser>,
    pub artifacts: Box<dyn ArtifactCollector>,
    pub audit: Option<mvm_core::policy::AuditPolicy>,
}

/// Errors `resolve_supervisor_components` can return.
#[derive(Debug)]
pub enum ResolveError {
    /// A ref names a `<tenant>:<workload>` bundle but the file
    /// isn't there. `expected_path` is where the operator should
    /// drop the bundle.
    BundleNotFound {
        field: &'static str,
        value: String,
        expected_path: PathBuf,
    },

    /// The bundle file exists but couldn't be parsed (TOML error,
    /// schema-version mismatch, unknown field). Detail carries the
    /// underlying loader message so operators can fix the file.
    BundleParseFailed {
        field: &'static str,
        value: String,
        path: PathBuf,
        detail: String,
    },

    /// The plan's four policy refs disagree on which bundle to
    /// load. The current schema requires all four to point at the
    /// same `<tenant>:<workload>` bundle so the supervisor's
    /// component slots resolve consistently.
    MixedRefs {
        first: String,
        second_field: &'static str,
        second: String,
    },

    /// A ref's shape doesn't match `"local-default"` or
    /// `"<tenant>:<workload>"`. We refuse rather than fall back to
    /// Noops so that a typo (`"locale-default"`) fails loudly at
    /// admission instead of silently passing traffic through Noop
    /// slots that error on first consult.
    Unrecognized {
        field: &'static str,
        value: String,
        expected: &'static str,
    },

    /// A bundle parsed but its `[[network.l4]]` rows failed to
    /// canonicalize — unparseable CIDR, unknown protocol, or inverted
    /// port range. The detail carries the underlying error so the
    /// operator knows which row (by zero-based index) to fix.
    L4SpecInvalid {
        value: String,
        path: PathBuf,
        detail: String,
    },

    /// A bundle parsed but its `[egress].disabled_inspectors` list
    /// names an inspector that doesn't exist (typo or future-name
    /// drift). Tightening: `build_inspector_chain` itself stays
    /// lenient (silently skips unknown names) because in-process
    /// callers own their config; the resolver enforces fail-loud at
    /// admission so a typo can't silently leave an inspector
    /// enforced when the operator intended to disable it.
    EgressPolicyInvalid {
        value: String,
        path: PathBuf,
        detail: String,
    },

    /// A bundle parsed but its `[pii]` section names an unknown
    /// mode (typo on `detect` / `redact` / `refuse` / `disabled`)
    /// or an unknown category in `pii.categories`. Fail-loud at
    /// admission so an operator who intended to scan all 4 default
    /// categories but typo'd one doesn't silently get only 3
    /// scanned.
    PiiPolicyInvalid {
        value: String,
        path: PathBuf,
        detail: String,
    },

    /// A bundle parsed but its `[audit].stream_destinations` list
    /// carries a URL whose scheme isn't recognised (typo like
    /// `htpps://...`). Fail-loud at admission so an operator who
    /// thought they were configuring TLS audit replication doesn't
    /// silently boot with the entry dropped. The eventual audit-
    /// stream replicator (after the mvm-hostd lift) is the live
    /// consumer; this validation catches typos *before* the resolver
    /// hands an unusable URL list downstream.
    AuditPolicyInvalid {
        value: String,
        path: PathBuf,
        detail: String,
    },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BundleNotFound {
                field,
                value,
                expected_path,
            } => write!(
                f,
                "policy ref {field} = {value:?} points at a bundle at {} that doesn't exist; \
                 create the file or change the ref",
                expected_path.display()
            ),
            Self::BundleParseFailed {
                field,
                value,
                path,
                detail,
            } => write!(
                f,
                "policy ref {field} = {value:?} loaded from {} failed to parse: {detail}",
                path.display()
            ),
            Self::MixedRefs {
                first,
                second_field,
                second,
            } => write!(
                f,
                "policy refs disagree: one field requests {first:?} but {second_field} requests \
                 {second:?}; all four refs must point at the same bundle"
            ),
            Self::Unrecognized {
                field,
                value,
                expected,
            } => write!(
                f,
                "policy ref {field} = {value:?} is not recognized (expected {expected})"
            ),
            Self::L4SpecInvalid {
                value,
                path,
                detail,
            } => write!(
                f,
                "policy bundle {value:?} (from {}) has an invalid [[network.l4]] row: {detail}",
                path.display()
            ),
            Self::EgressPolicyInvalid {
                value,
                path,
                detail,
            } => write!(
                f,
                "policy bundle {value:?} (from {}) has an invalid [egress] section: {detail}",
                path.display()
            ),
            Self::PiiPolicyInvalid {
                value,
                path,
                detail,
            } => write!(
                f,
                "policy bundle {value:?} (from {}) has an invalid [pii] section: {detail}",
                path.display()
            ),
            Self::AuditPolicyInvalid {
                value,
                path,
                detail,
            } => write!(
                f,
                "policy bundle {value:?} (from {}) has an invalid [audit] section: {detail}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Classify a single ref into the v0 buckets. Pure string inspection
/// — no I/O.
enum RefShape<'a> {
    LocalDefault,
    TenantWorkload { tenant: &'a str, workload: &'a str },
    Unrecognized,
}

fn classify(value: &str) -> RefShape<'_> {
    if value == LOCAL_DEFAULT {
        return RefShape::LocalDefault;
    }
    // `<tenant>:<workload>` — exactly one colon, both halves
    // non-empty, no path separators (keeps the resolved file path
    // confined to `~/.mvm/policies/`).
    if let Some((tenant, workload)) = value.split_once(':')
        && !tenant.is_empty()
        && !workload.is_empty()
        && !tenant.contains('/')
        && !workload.contains('/')
        && !tenant.contains('\\')
        && !workload.contains('\\')
    {
        return RefShape::TenantWorkload { tenant, workload };
    }
    RefShape::Unrecognized
}

/// Default base dir for policy bundles. Mirrors
/// `mvm_core::policy::toml_loader::default_policy_dir` but falls back to
/// the literal `~/.mvm/policies/` (good for error messages) when
/// `$HOME` is unset.
fn default_policy_dir() -> PathBuf {
    mvm_core::policy::toml_loader::default_policy_dir()
        .unwrap_or_else(|| PathBuf::from("~/.mvm/policies"))
}

/// Per-field validation that all four refs share the same shape
/// (all `LOCAL_DEFAULT`, or all the same `<tenant>:<workload>`).
/// Returns the agreed-upon shape on success.
fn classify_plan_refs<'a>(
    network: &'a str,
    fs: &'a str,
    egress: &'a str,
    tool: &'a str,
) -> Result<RefShape<'a>, ResolveError> {
    let fields: [(&'static str, &str); 4] = [
        ("network_policy", network),
        ("fs_policy", fs),
        ("egress_policy", egress),
        ("tool_policy", tool),
    ];
    let first_value = fields[0].1;
    for (field, value) in fields.iter() {
        if *value != first_value {
            return Err(ResolveError::MixedRefs {
                first: first_value.to_string(),
                second_field: field,
                second: value.to_string(),
            });
        }
        if matches!(classify(value), RefShape::Unrecognized) {
            return Err(ResolveError::Unrecognized {
                field,
                value: value.to_string(),
                expected: "\"local-default\" or \"<tenant>:<workload>\"",
            });
        }
    }
    Ok(classify(first_value))
}

/// Resolve a plan's four policy refs into concrete component slots.
///
/// Three outcomes:
///
/// - All four refs == `"local-default"` → Noop slots.
/// - All four refs == `"<tenant>:<workload>"` and the bundle file
///   parses cleanly → **live `L7EgressProxy` + `PolicyToolGate`**
///   constructed from the bundle's `egress` + `tool` sections.
///   Keystore + ArtifactCollector remain Noop until the
///   supervisor lift in mvm-hostd.
/// - Anything else → typed error pointing the operator at what to
///   fix (missing file, parse error, mismatched refs, typo).
pub fn resolve_supervisor_components(plan: &ExecutionPlan) -> Result<ResolvedSlots, ResolveError> {
    resolve_supervisor_components_with_dir(plan, &default_policy_dir())
}

/// Test seam — same as [`resolve_supervisor_components`] but the
/// policy-bundle base dir is supplied by the caller instead of
/// resolved from `$HOME`. Tests use this with a `tempfile::tempdir()`
/// to inject a known-good bundle without touching the host's
/// `~/.mvm/policies/`.
pub fn resolve_supervisor_components_with_dir(
    plan: &ExecutionPlan,
    base_dir: &std::path::Path,
) -> Result<ResolvedSlots, ResolveError> {
    let PolicyRef(network) = &plan.network_policy;
    let FsPolicyRef(fs) = &plan.fs_policy;
    let PolicyRef(egress) = &plan.egress_policy;
    let PolicyRef(tool) = &plan.tool_policy;

    match classify_plan_refs(network, fs, egress, tool)? {
        RefShape::LocalDefault => Ok(noop_slots()),
        RefShape::TenantWorkload { tenant, workload } => {
            let bundle = load_tenant_workload(base_dir, network, tenant, workload)?;
            let bundle_path =
                mvm_core::policy::toml_loader::bundle_path(base_dir, tenant, workload);
            slots_from_bundle(&bundle, network, &bundle_path)
        }
        // classify_plan_refs already converts Unrecognized into a
        // typed error; this branch is dead but keeps the match
        // exhaustive.
        RefShape::Unrecognized => unreachable!("classify_plan_refs handled Unrecognized"),
    }
}

/// Load the tenant `PolicyBundle` a plan resolves to, for delivery to the
/// supervisor's L4 gate + observers via `VmStartConfig.bundle_json`.
/// `None` for a local-default plan — no per-tenant policy, so the
/// bridge enforces mandatory-deny only. Errors identically to
/// [`resolve_supervisor_components`] on a missing or malformed bundle, so
/// admission fails closed before boot.
pub fn resolve_policy_bundle(
    plan: &ExecutionPlan,
) -> Result<Option<mvm_core::policy::PolicyBundle>, ResolveError> {
    resolve_policy_bundle_with_dir(plan, &default_policy_dir())
}

/// Test seam for [`resolve_policy_bundle`] — same, with a caller-supplied
/// policy-bundle base dir instead of `$HOME/.mvm/policies`.
pub fn resolve_policy_bundle_with_dir(
    plan: &ExecutionPlan,
    base_dir: &std::path::Path,
) -> Result<Option<mvm_core::policy::PolicyBundle>, ResolveError> {
    let PolicyRef(network) = &plan.network_policy;
    let FsPolicyRef(fs) = &plan.fs_policy;
    let PolicyRef(egress) = &plan.egress_policy;
    let PolicyRef(tool) = &plan.tool_policy;

    match classify_plan_refs(network, fs, egress, tool)? {
        RefShape::LocalDefault => Ok(None),
        RefShape::TenantWorkload { tenant, workload } => Ok(Some(load_tenant_workload(
            base_dir, network, tenant, workload,
        )?)),
        RefShape::Unrecognized => unreachable!("classify_plan_refs handled Unrecognized"),
    }
}

fn noop_slots() -> ResolvedSlots {
    ResolvedSlots {
        network: Box::new(NoopL4Gate),
        egress: Box::new(NoopEgressProxy),
        tool_gate: Box::new(NoopToolGate),
        keystore: Box::new(NoopKeystoreReleaser),
        artifacts: Box::new(NoopArtifactCollector),
        audit: None,
    }
}

/// Turn a parsed `PolicyBundle` into live supervisor
/// component slots. Egress + tool-gate ship as real `L7EgressProxy`
/// plus `PolicyToolGate`. The `network` slot is a `CanonicalL4Gate`
/// constructed from `bundle.network.l4` rows via `canonicalize_l4`.
/// Keystore + artifacts stay Noop until the mvm-hostd supervisor lift.
///
/// Fallible because a bundle that parses through TOML can still
/// carry an invalid `[[network.l4]]` row (unparseable CIDR,
/// unknown proto, inverted port range). The error path surfaces
/// `ResolveError::L4SpecInvalid` with the underlying detail so the
/// operator knows which row to fix.
fn slots_from_bundle(
    bundle: &mvm_core::policy::PolicyBundle,
    ref_value: &str,
    path: &std::path::Path,
) -> Result<ResolvedSlots, ResolveError> {
    // L4 gate: lower `[[network.l4]]` rows to a `CanonicalEgress` and
    // wrap in a `CanonicalL4Gate`. Empty rows yield default-deny
    // (fail-closed); explicit rows are the only way to permit flows.
    let egress = canonicalize_l4(&bundle.network.l4).map_err(|e| ResolveError::L4SpecInvalid {
        value: ref_value.to_string(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    let l4 = CanonicalL4Gate::new(egress);

    // Tighten `disabled_inspectors` to fail-loud on unknown names
    // *at admission*. `build_inspector_chain` itself stays lenient
    // (silently skips unknown names) so in-process supervisor
    // callers can extend the disabled list ahead of inspector
    // additions; the resolver path is the trust boundary where
    // typos must surface loudly.
    validate_egress_policy_inspector_names(&bundle.egress).map_err(
        |e: EgressPolicyValidationError| ResolveError::EgressPolicyInvalid {
            value: ref_value.to_string(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        },
    )?;

    // Same fail-loud posture for `[audit].stream_destinations` —
    // shape-check each URL's scheme prefix against
    // `KNOWN_AUDIT_STREAM_SCHEMES`. The eventual replicator (after
    // the mvm-hostd lift) is the live
    // consumer; this admission gate catches typos like
    // `htpps://audit...` so the operator sees them at boot rather
    // than after a forensic dig through the audit chain.
    validate_audit_policy_stream_destinations(&bundle.audit).map_err(
        |e: AuditPolicyValidationError| ResolveError::AuditPolicyInvalid {
            value: ref_value.to_string(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        },
    )?;

    // L7 inspector chain: delegate to the supervisor's canonical
    // builder so the order + `disabled_inspectors` semantics stay in
    // one place. Today's chain is:
    //   destination_policy → ssrf_guard → secrets_scanner →
    //   injection_guard → pii_redactor
    // The `with_pii` variant honors the bundle's `[pii]` section
    // (mode + categories) so a tenant policy can switch the
    // redactor to `redact`/`refuse` or scope it to a subset of
    // default categories. `None` for the breaker reporter — the
    // in-process supervisor wraps with `CircuitBreaker` when it
    // owns one; the CLI resolver path doesn't have a reporter to
    // share, so the chain ships raw.
    let chain = build_inspector_chain_with_pii(&bundle.egress, &bundle.pii, None).map_err(
        |e: PiiPolicyError| ResolveError::PiiPolicyInvalid {
            value: ref_value.to_string(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        },
    )?;
    let body_cap = if bundle.egress.body_cap_bytes == 0 {
        mvm_core::policy::DEFAULT_BODY_CAP_BYTES as usize
    } else {
        bundle.egress.body_cap_bytes as usize
    };
    let l7 = L7EgressProxy::new(
        Arc::new(chain),
        Arc::new(TokioDnsResolver),
        Arc::new(NoopEgressAuditSink),
        body_cap,
        bundle.egress.allow_plain_http,
    );
    let tool_gate = PolicyToolGate::from_policy(&bundle.tool);
    // Artifact collector — carries the bundle's `capture_paths` +
    // `retention_days` on the public fields so a future in-process
    // consumer can downcast and consult them. `collect()` itself
    // errors `ArtifactError::NotImplemented` (distinct from
    // `NotWired`) until the mvm-hostd virtiofs-streaming lift wires
    // the real capture mechanism.
    let artifacts = LiveArtifactCollector::from_policy(&bundle.artifact);
    // Keystore releaser — carries the bundle's `rotation_interval_days`
    // on the public field. `release`/`revoke` error
    // `KeystoreError::NotImplemented` until the mvm-hostd
    // attestation-gated release flow wires in. Closing the last
    // Noop slot in slots_from_bundle: every parsed bundle field
    // now surfaces somewhere live.
    let keystore = LiveKeystoreReleaser::from_policy(&bundle.keys);
    Ok(ResolvedSlots {
        network: Box::new(l4),
        egress: Box::new(l7),
        tool_gate: Box::new(tool_gate),
        keystore: Box::new(keystore),
        artifacts: Box::new(artifacts),
        audit: Some(bundle.audit.clone()),
    })
}

fn load_tenant_workload(
    base: &std::path::Path,
    ref_value: &str,
    tenant: &str,
    workload: &str,
) -> Result<mvm_core::policy::PolicyBundle, ResolveError> {
    let path = mvm_core::policy::toml_loader::bundle_path(base, tenant, workload);
    match mvm_core::policy::toml_loader::load_bundle_from_path(base, tenant, workload) {
        Ok(bundle) => Ok(bundle),
        Err(mvm_core::policy::toml_loader::LoadError::NotFound { path }) => {
            Err(ResolveError::BundleNotFound {
                field: "network_policy",
                value: ref_value.to_string(),
                expected_path: path,
            })
        }
        Err(
            mvm_core::policy::toml_loader::LoadError::Parse { detail, .. }
            | mvm_core::policy::toml_loader::LoadError::Io { detail, .. },
        ) => Err(ResolveError::BundleParseFailed {
            field: "network_policy",
            value: ref_value.to_string(),
            path,
            detail,
        }),
        Err(mvm_core::policy::toml_loader::LoadError::SchemaMismatch { got, known, .. }) => {
            Err(ResolveError::BundleParseFailed {
                field: "network_policy",
                value: ref_value.to_string(),
                path,
                detail: format!(
                    "schema_version {got} unsupported (this binary only \
                     understands version {known})"
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::{
        AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, KeyRotationSpec,
        Nonce, PlanId, PlanSeccompTier, PostRunLifecycle, Resources, RuntimeProfileRef,
        SCHEMA_VERSION, SignedImageRef, TenantId, TimeoutSpec, WorkloadId,
    };
    use std::collections::BTreeMap;

    fn fixture_plan() -> ExecutionPlan {
        let now = chrono::Utc::now();
        ExecutionPlan {
            grants: None,
            environment: None,
            build_provenance: Default::default(),
            snapshot_at: Default::default(),
            network_mode: Default::default(),
            stream_retention: Default::default(),
            ingress: Vec::new(),
            network_limits: Default::default(),
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId("plan-test".to_string()),
            plan_version: 1,
            tenant: TenantId("local".to_string()),
            workload: WorkloadId("vm-test".to_string()),
            runtime_profile: RuntimeProfileRef("firecracker".to_string()),
            image: SignedImageRef {
                name: "vm-test".to_string(),
                sha256: "a".repeat(64),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            resources: Resources {
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 0,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef(LOCAL_DEFAULT.to_string()),
            fs_policy: FsPolicyRef(LOCAL_DEFAULT.to_string()),
            secrets: Vec::new(),
            egress_policy: PolicyRef(LOCAL_DEFAULT.to_string()),
            redaction: Default::default(),
            reversible_replacement: Default::default(),
            tool_policy: PolicyRef(LOCAL_DEFAULT.to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: Vec::new(),
                retention_days: 0,
            },
            caller_commitment: None,
            audit_labels: BTreeMap::new(),
            key_rotation: KeyRotationSpec { interval_days: 0 },
            attestation: AttestationRequirement {
                mode: AttestationMode::Noop,
            },
            release_pin: None,
            post_run: PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
            valid_from: now,
            valid_until: now + chrono::Duration::minutes(10),
            nonce: Nonce::from_bytes([0u8; 16]),
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
            agent_verbs: None,
            services: Vec::new(),
            extensions: Vec::new(),
            stream_edges: Vec::new(),
            sdk_uses_sidecar: true,
        }
    }

    #[test]
    fn policy_resolver_returns_noops_for_local_default() {
        // All four PolicyRef fields == "local-default" — happy path.
        // The Noops fail-closed on consult; this test verifies we got
        // *back* a ResolvedSlots and that each slot is in fact the
        // Noop variant by exercising its `NotWired` error.
        let plan = fixture_plan();
        let slots = resolve_supervisor_components(&plan).expect("local-default must resolve");

        // Hit each Noop and assert it errors with NotWired. This is
        // the strongest assertion we can make without inspecting
        // private type identity — and matches how a real
        // misconfigured supervisor would discover it.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let net_err = slots
                .network
                .evaluate(
                    mvm_hostd::supervisor::L4Protocol::Tcp,
                    "1.1.1.1".parse().unwrap(),
                    443,
                )
                .await
                .expect_err("Noop L4 gate must error");
            assert!(
                matches!(net_err, mvm_hostd::supervisor::L4Error::NotWired),
                "unexpected L4 err: {net_err:?}"
            );

            let egress_err = slots
                .egress
                .inspect("example.com", "/")
                .await
                .expect_err("Noop egress must error");
            assert!(
                matches!(egress_err, mvm_hostd::supervisor::EgressError::NotWired),
                "unexpected egress err: {egress_err:?}"
            );

            let tool_err = slots
                .tool_gate
                .check("anything")
                .await
                .expect_err("Noop tool gate must error");
            assert!(
                matches!(tool_err, mvm_hostd::supervisor::ToolError::NotWired),
                "unexpected tool err: {tool_err:?}"
            );

            let revoke_err = slots
                .keystore
                .revoke("anything")
                .await
                .expect_err("Noop keystore must error");
            assert!(
                matches!(revoke_err, mvm_hostd::supervisor::KeystoreError::NotWired),
                "unexpected keystore err: {revoke_err:?}"
            );

            let collect_err = slots
                .artifacts
                .collect(&plan.plan_id)
                .await
                .expect_err("Noop artifact collector must error");
            assert!(
                matches!(collect_err, mvm_hostd::supervisor::ArtifactError::NotWired),
                "unexpected artifact err: {collect_err:?}"
            );
        });
    }

    /// Set all four PolicyRef fields on a plan to the same value.
    /// The schema requires the four refs agree; tests that
    /// violate that on purpose set only one field.
    fn set_all_refs(plan: &mut ExecutionPlan, value: &str) {
        plan.network_policy = PolicyRef(value.to_string());
        plan.fs_policy = FsPolicyRef(value.to_string());
        plan.egress_policy = PolicyRef(value.to_string());
        plan.tool_policy = PolicyRef(value.to_string());
    }

    #[test]
    fn policy_resolver_rejects_tenant_ref_when_bundle_missing() {
        // A "<tenant>:<workload>" ref makes
        // resolve_supervisor_components attempt to load the bundle
        // file. When the file isn't there we surface BundleNotFound
        // with a clear path so operators know exactly where to put it.
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");
        let err = match resolve_supervisor_components(&plan) {
            Err(e) => e,
            Ok(_) => panic!("tenant-scoped ref without bundle must be refused"),
        };
        match err {
            ResolveError::BundleNotFound {
                value,
                expected_path,
                ..
            } => {
                assert_eq!(value, "acme:web-worker");
                let s = expected_path.to_string_lossy();
                assert!(s.contains("acme"), "path missing tenant: {s}");
                assert!(s.contains("web-worker.toml"), "path missing workload: {s}");
                assert!(s.contains("policies"), "path missing policies dir: {s}");
            }
            other => panic!("expected BundleNotFound, got {other:?}"),
        }
    }

    #[test]
    fn policy_resolver_rejects_unrecognized_policy_ref() {
        // Anything that's neither "local-default" nor
        // "<tenant>:<workload>" must be refused. The MixedRefs
        // check runs first, so make all four refs identical (and
        // bogus) to land on the Unrecognized branch.
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "bogus");
        let err = match resolve_supervisor_components(&plan) {
            Err(e) => e,
            Ok(_) => panic!("unrecognized ref must be refused"),
        };
        match err {
            ResolveError::Unrecognized {
                value, expected, ..
            } => {
                assert_eq!(value, "bogus");
                assert!(expected.contains("local-default"));
                assert!(expected.contains("tenant"));
            }
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn policy_resolver_signature_returns_box_dyn_trait_objects() {
        // Compile-time check: the slots inside ResolvedSlots can be
        // moved into builder functions that accept
        // `Box<dyn SupervisorEgressProxy>`, etc. This proves the eventual
        // `Supervisor::with_egress(self, Box<dyn SupervisorEgressProxy>)` lift
        // is just a `.with_egress(slots.egress)` call away — no
        // adapter layer needed.
        fn take_network(_: Box<dyn L4Gate>) {}
        fn take_egress(_: Box<dyn SupervisorEgressProxy>) {}
        fn take_tool_gate(_: Box<dyn ToolGate>) {}
        fn take_keystore(_: Box<dyn KeystoreReleaser>) {}
        fn take_artifacts(_: Box<dyn ArtifactCollector>) {}

        let slots = resolve_supervisor_components(&fixture_plan()).unwrap();
        take_network(slots.network);
        take_egress(slots.egress);
        take_tool_gate(slots.tool_gate);
        take_keystore(slots.keystore);
        take_artifacts(slots.artifacts);
    }

    #[test]
    fn policy_resolver_rejects_mixed_refs() {
        // All four refs must agree (same bundle). If only one
        // points at a tenant bundle while the others stay
        // local-default, the resolver refuses with MixedRefs.
        let mut plan = fixture_plan();
        plan.tool_policy = PolicyRef("acme:tools-v1".to_string());
        let err = match resolve_supervisor_components(&plan) {
            Err(e) => e,
            Ok(_) => panic!("mixed refs must be refused"),
        };
        match err {
            ResolveError::MixedRefs {
                first,
                second_field,
                second,
            } => {
                assert_eq!(first, "local-default");
                assert_eq!(second_field, "tool_policy");
                assert_eq!(second, "acme:tools-v1");
            }
            other => panic!("expected MixedRefs, got {other:?}"),
        }
    }

    #[test]
    fn policy_resolver_inspects_fs_policy_ref() {
        // FsPolicyRef is a distinct newtype but should be treated
        // identically to PolicyRef in the resolver. If fs_policy
        // disagrees with the others, MixedRefs fires.
        let mut plan = fixture_plan();
        plan.fs_policy = FsPolicyRef("typo-default".to_string());
        let err = match resolve_supervisor_components(&plan) {
            Err(e) => e,
            Ok(_) => panic!("mixed fs ref must be refused"),
        };
        match err {
            ResolveError::MixedRefs {
                second_field,
                second,
                ..
            } => {
                assert_eq!(second_field, "fs_policy");
                assert_eq!(second, "typo-default");
            }
            other => panic!("expected MixedRefs, got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // live L7EgressProxy + PolicyToolGate
    //
    // A parsed `<tenant>:<workload>` bundle returns
    // actual `L7EgressProxy` + `PolicyToolGate` impls instead of
    // Noops. These tests use the `_with_dir` seam so they can
    // inject a tempdir without mutating $HOME.
    // ──────────────────────────────────────────────────────────────

    fn write_bundle(dir: &std::path::Path, tenant: &str, workload: &str, body: &str) {
        let tenant_dir = dir.join(tenant);
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(tenant_dir.join(format!("{workload}.toml")), body).unwrap();
    }

    fn fixture_bundle_with_tool_allow(name: &str) -> String {
        format!(
            r#"
schema_version = 1
bundle_id      = "acme/web-worker"
bundle_version = 1

[network]
[egress]
allow_list = [["api.example.com", 443]]
allow_plain_http = false

[pii]
[tool]
allowed = ["{name}"]
[artifact]
[keys]
[audit]
"#,
        )
    }

    #[test]
    fn slice_a_returns_l7_egress_proxy_for_parsed_bundle() {
        // A parsed `<tenant>:<workload>` bundle yields a live
        // L7EgressProxy — proven by:
        //   1. An off-list host returns Deny (DestinationPolicy
        //      gates before DNS, so this is hermetic).
        //   2. An allow-listed host's inspect call does NOT
        //      return `EgressError::NotWired` — a NoopEgressProxy
        //      would. The L7EgressProxy may return `Allow` (when
        //      DNS resolves) or `UpstreamUnreachable` (when DNS
        //      fails, common in sandboxed test environments);
        //      either outcome proves the proxy ran the chain.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_tool_allow("web_search"),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let slots = match resolve_supervisor_components_with_dir(&plan, tmp.path()) {
            Ok(s) => s,
            Err(e) => panic!("expected live slots, got error: {e}"),
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Off-list: DestinationPolicy denies before DNS — hermetic.
            let deny = slots
                .egress
                .inspect("evil.example.com", "/x")
                .await
                .expect("policy lookup must succeed (not NotWired)");
            assert!(
                matches!(deny, mvm_hostd::supervisor::EgressDecision::Deny { .. }),
                "off-list host should produce Deny, got {deny:?}"
            );

            // Allow-listed: the chain runs; outcome is either
            // Allow (network present) or UpstreamUnreachable
            // (sandbox). NotWired would mean the slot is still a
            // NoopEgressProxy.
            match slots.egress.inspect("api.example.com", "/v1/x").await {
                Ok(_) => {} // Allow — DNS resolved
                Err(mvm_hostd::supervisor::EgressError::UpstreamUnreachable(_)) => {} // sandboxed
                Err(mvm_hostd::supervisor::EgressError::NotWired) => {
                    panic!("slot is still a NoopEgressProxy — Slice A wiring missing")
                }
                Err(other) => panic!("unexpected egress error: {other:?}"),
            }
        });
    }

    #[test]
    fn slice_a_returns_policy_tool_gate_for_parsed_bundle() {
        // A parsed bundle's `tool.allowed` list controls
        // PolicyToolGate::check — an on-list tool is Allow, an
        // off-list one is Deny.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_tool_allow("web_search"),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("expected live slots, got {e}"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let allow = slots
                .tool_gate
                .check("web_search")
                .await
                .expect("PolicyToolGate must not return NotWired post-Slice-A");
            assert_eq!(allow, mvm_hostd::supervisor::ToolDecision::Allow);
            let deny = slots
                .tool_gate
                .check("forbidden_tool")
                .await
                .expect("policy lookup itself must succeed");
            assert!(
                matches!(deny, mvm_hostd::supervisor::ToolDecision::Deny { .. }),
                "off-list tool should produce Deny, got {deny:?}"
            );
        });
    }

    fn fixture_bundle_with_key_rotation(days: u32) -> String {
        format!(
            r#"
schema_version = 1
bundle_id      = "acme/web-worker"
bundle_version = 1

[network]
[egress]
[pii]
[tool]
[artifact]

[keys]
rotation_interval_days = {days}

[audit]
"#,
        )
    }

    #[test]
    fn slice_b_returns_live_keystore_releaser_for_parsed_bundle() {
        // A parsed `<tenant>:<workload>` bundle yields a live
        // KeystoreReleaser — release() + revoke() return
        // NotImplemented (configured + pending consumer) rather than
        // NotWired. This is the last Noop slot closed in
        // slots_from_bundle.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_key_rotation(30),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("expected live slots, got {e}"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let err = slots
                .keystore
                .revoke("anything")
                .await
                .expect_err("live keystore must surface NotImplemented");
            match err {
                mvm_hostd::supervisor::KeystoreError::NotImplemented {
                    rotation_interval_days,
                } => assert_eq!(rotation_interval_days, 30),
                other => panic!("expected NotImplemented, got {other:?}"),
            }
        });
    }

    #[test]
    fn slice_b_empty_keys_section_still_yields_live_keystore() {
        // A parsed bundle without an explicit `[keys]` block still
        // produces a Live keystore — distinguishing "configured, no
        // rotation" from "no bundle". The releaser surfaces
        // rotation_interval_days=0 via NotImplemented; Noop would
        // surface NotWired.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_tool_allow("web_search"),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("expected live slots, got {e}"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let err = slots
                .keystore
                .revoke("anything")
                .await
                .expect_err("live keystore must surface NotImplemented");
            assert!(
                matches!(
                    err,
                    mvm_hostd::supervisor::KeystoreError::NotImplemented {
                        rotation_interval_days: 0
                    }
                ),
                "expected NotImplemented{{0}}, got {err:?}"
            );
        });
    }

    fn fixture_bundle_with_artifact_paths(paths: &[&str], retention_days: u32) -> String {
        let list = paths
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"
schema_version = 1
bundle_id      = "acme/web-worker"
bundle_version = 1

[network]
[egress]
[pii]
[tool]

[artifact]
capture_paths = [{list}]
retention_days = {retention_days}

[keys]
[audit]
"#,
        )
    }

    #[test]
    fn slice_b_returns_live_artifact_collector_for_parsed_bundle() {
        // A parsed `<tenant>:<workload>` bundle yields a live
        // ArtifactCollector — collect() returns NotImplemented
        // (configured + pending consumer) rather than NotWired.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_artifact_paths(&["/artifacts", "/output"], 14),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("expected live slots, got {e}"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let err = slots
                .artifacts
                .collect(&plan.plan_id)
                .await
                .expect_err("live collector must surface NotImplemented");
            match err {
                mvm_hostd::supervisor::ArtifactError::NotImplemented {
                    path_count,
                    retention_days,
                } => {
                    assert_eq!(path_count, 2);
                    assert_eq!(retention_days, 14);
                }
                other => panic!("expected NotImplemented, got {other:?}"),
            }
        });
    }

    #[test]
    fn slice_b_empty_artifact_section_still_yields_live_collector() {
        // A parsed bundle without an explicit `capture_paths` list
        // still produces a Live collector — distinguishing
        // "configured, no paths" from "no bundle". The collector
        // surfaces 0 paths via NotImplemented; Noop would surface
        // NotWired.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_tool_allow("web_search"),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("expected live slots, got {e}"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let err = slots
                .artifacts
                .collect(&plan.plan_id)
                .await
                .expect_err("live collector must surface NotImplemented");
            assert!(
                matches!(
                    err,
                    mvm_hostd::supervisor::ArtifactError::NotImplemented {
                        path_count: 0,
                        retention_days: 0
                    }
                ),
                "expected NotImplemented{{0,0}}, got {err:?}"
            );
        });
    }

    // ──────────────────────────────────────────────────────────────
    // live L4Gate from [[network.l4]] rows
    //
    // A parsed `<tenant>:<workload>` bundle yields a
    // `CanonicalL4Gate` in `slots.network` built from the bundle's
    // `[[network.l4]]` rows. Empty rows = default-deny; non-empty
    // rows allow the listed flows.
    // ──────────────────────────────────────────────────────────────

    fn fixture_bundle_with_l4_rule(proto: &str, cidr: &str, port: u16) -> String {
        format!(
            r#"
schema_version = 1
bundle_id      = "acme/net"
bundle_version = 1

[network]
preset = "tenant-isolated"

[[network.l4]]
proto    = "{proto}"
dst_cidr = "{cidr}"
port_lo  = {port}
port_hi  = {port}

[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
"#,
        )
    }

    #[test]
    fn slice_b_returns_live_l4_gate_for_parsed_bundle() {
        // A parsed bundle's `[[network.l4]]` row yields a live
        // L4Gate — on-rule flow returns Allow, off-rule flow returns
        // Deny. The `NotWired` error is what a NoopL4Gate would emit
        // and proves the live gate is wired in when absent.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_l4_rule("tcp", "10.0.0.0/24", 443),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("expected live slots, got {e}"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // On-rule flow: TCP -> 10.0.0.5:443 is permitted.
            let allow = slots
                .network
                .evaluate(
                    mvm_hostd::supervisor::L4Protocol::Tcp,
                    "10.0.0.5".parse().unwrap(),
                    443,
                )
                .await
                .expect("L4Gate must not return NotWired post-Slice-B");
            assert_eq!(allow, mvm_hostd::supervisor::L4Decision::Allow);

            // Off-rule flow: same host, different port → Deny.
            let deny = slots
                .network
                .evaluate(
                    mvm_hostd::supervisor::L4Protocol::Tcp,
                    "10.0.0.5".parse().unwrap(),
                    22,
                )
                .await
                .expect("policy lookup itself must succeed");
            assert!(
                matches!(deny, mvm_hostd::supervisor::L4Decision::Deny { .. }),
                "off-rule flow should produce Deny, got {deny:?}"
            );
        });
    }

    #[test]
    fn slice_b_empty_l4_section_yields_default_deny_gate() {
        // A bundle without any `[[network.l4]]` rows still produces a
        // live (non-Noop) gate — but every evaluate call returns
        // Deny. This pins the fail-closed posture: an operator who
        // forgets to author L4 rows can't accidentally bypass the
        // gate; they get explicit default-deny.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_tool_allow("web_search"),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("expected live slots, got {e}"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d = slots
                .network
                .evaluate(
                    mvm_hostd::supervisor::L4Protocol::Tcp,
                    "8.8.8.8".parse().unwrap(),
                    443,
                )
                .await
                .expect("CanonicalL4Gate must not return NotWired even for empty policy");
            assert!(
                matches!(d, mvm_hostd::supervisor::L4Decision::Deny { .. }),
                "empty L4 policy must default-deny, got {d:?}"
            );
        });
    }

    #[test]
    fn slice_b_refuses_bundle_with_invalid_l4_cidr() {
        // A bundle that parses through TOML but carries an
        // unparseable `dst_cidr` triggers L4SpecInvalid at translate
        // time. The error names the path so operators can fix the
        // file before re-running.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_l4_rule("tcp", "not-a-cidr", 443),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let err = match resolve_supervisor_components_with_dir(&plan, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("bad CIDR must be refused"),
        };
        match err {
            ResolveError::L4SpecInvalid {
                value,
                path,
                detail,
            } => {
                assert_eq!(value, "acme:web-worker");
                let s = path.to_string_lossy();
                assert!(s.contains("acme"), "path missing tenant: {s}");
                assert!(s.contains("web-worker.toml"), "path missing workload: {s}");
                assert!(
                    detail.contains("not-a-cidr"),
                    "detail missing cidr: {detail}"
                );
            }
            other => panic!("expected L4SpecInvalid, got {other:?}"),
        }
    }

    #[test]
    fn slice_b_refuses_bundle_with_unknown_l4_protocol() {
        // Same gate, different translate-time failure mode — proto
        // outside {"tcp", "udp"} fails loudly rather than silently
        // skipping the row.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_l4_rule("icmp", "10.0.0.0/24", 0),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let err = match resolve_supervisor_components_with_dir(&plan, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("unknown proto must be refused"),
        };
        match err {
            ResolveError::L4SpecInvalid { detail, .. } => {
                assert!(detail.contains("icmp"), "detail missing proto: {detail}");
            }
            other => panic!("expected L4SpecInvalid, got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Full L7 inspector chain in `slots_from_bundle`.
    //
    // `slots_from_bundle` delegates to the supervisor's
    // canonical `build_inspector_chain`, which pulls in
    // `SsrfGuard` / `SecretsScanner` / `InjectionGuard` /
    // `PiiRedactor` and respects `bundle.egress.disabled_inspectors`.
    // The L7 chain is private inside `L7EgressProxy`, so these tests
    // verify the wiring by calling `build_inspector_chain` directly
    // against the bundle's egress policy.
    // ──────────────────────────────────────────────────────────────

    fn fixture_bundle_with_disabled_inspectors(disabled: &[&str]) -> String {
        let list = disabled
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"
schema_version = 1
bundle_id      = "acme/web-worker"
bundle_version = 1

[network]
[egress]
allow_list = [["api.example.com", 443]]
disabled_inspectors = [{list}]

[pii]
[tool]
[artifact]
[keys]
[audit]
"#,
        )
    }

    #[test]
    fn resolve_policy_bundle_loads_for_a_tenant_workload_plan() {
        // A tenant:workload plan resolves to the on-disk
        // PolicyBundle the supervisor's L4 gate + observers consume.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_tool_allow("web_search"),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let bundle = resolve_policy_bundle_with_dir(&plan, tmp.path())
            .expect("resolve ok")
            .expect("a tenant:workload plan yields a bundle");
        let expected =
            mvm_core::policy::toml_loader::load_bundle_from_path(tmp.path(), "acme", "web-worker")
                .unwrap();
        assert_eq!(bundle, expected);
    }

    #[test]
    fn resolve_policy_bundle_is_none_for_local_default() {
        // A local-default plan has no per-tenant policy → None (the bridge
        // enforces mandatory-deny only); the policy dir is never touched.
        let plan = fixture_plan();
        let result = resolve_policy_bundle_with_dir(&plan, std::path::Path::new("/nonexistent"))
            .expect("resolve ok");
        assert!(result.is_none());
    }

    #[test]
    fn slice_b_inspector_chain_full_default_has_five_inspectors() {
        // A parsed bundle with no `disabled_inspectors` produces the
        // full canonical chain: destination_policy + ssrf_guard +
        // secrets_scanner + injection_guard + pii_redactor.
        // We invoke `build_inspector_chain` against the bundle's
        // parsed `EgressPolicy` to assert the chain shape, since the
        // L7EgressProxy keeps its chain private.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_tool_allow("web_search"),
        );
        let bundle =
            mvm_core::policy::toml_loader::load_bundle_from_path(tmp.path(), "acme", "web-worker")
                .expect("bundle parses");
        let chain = mvm_hostd::supervisor::build_inspector_chain(&bundle.egress, None);
        assert_eq!(
            chain.len(),
            5,
            "default chain must carry all five inspectors"
        );
    }

    #[test]
    fn slice_b_inspector_chain_honors_disabled_inspectors() {
        // A bundle that disables `ssrf_guard` and `secrets_scanner`
        // must produce a 3-inspector chain. Naming is by
        // `Inspector::name()` strings.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_disabled_inspectors(&["ssrf_guard", "secrets_scanner"]),
        );
        let bundle =
            mvm_core::policy::toml_loader::load_bundle_from_path(tmp.path(), "acme", "web-worker")
                .expect("bundle parses");
        let chain = mvm_hostd::supervisor::build_inspector_chain(&bundle.egress, None);
        assert_eq!(
            chain.len(),
            3,
            "two disabled inspectors must shrink chain to 3"
        );
    }

    #[test]
    fn slice_b_build_inspector_chain_stays_lenient_on_unknown_names() {
        // The underlying `build_inspector_chain` API is intentionally
        // lenient: an unknown name in `disabled_inspectors` is
        // silently skipped (chain still carries all 5 inspectors).
        // The fail-loud tightening lives one layer up — the
        // resolver path calls `validate_egress_policy_inspector_names`
        // before `build_inspector_chain` (see the next test). This
        // separation lets in-process supervisor callers extend their
        // disabled list ahead of inspector additions without
        // breaking, while the admission boundary stays strict.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_disabled_inspectors(&["typo_inspector"]),
        );
        let bundle =
            mvm_core::policy::toml_loader::load_bundle_from_path(tmp.path(), "acme", "web-worker")
                .expect("bundle parses");
        let chain = mvm_hostd::supervisor::build_inspector_chain(&bundle.egress, None);
        assert_eq!(
            chain.len(),
            5,
            "build_inspector_chain itself must stay lenient — unknown disabled names skip silently"
        );
    }

    #[test]
    fn slice_b_resolver_refuses_bundle_with_unknown_disabled_inspector() {
        // Tightening: the resolver path runs
        // `validate_egress_policy_inspector_names` before
        // `build_inspector_chain`, so a typo in `disabled_inspectors`
        // fails admission with `ResolveError::EgressPolicyInvalid`
        // instead of silently leaving the inspector enforced.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_disabled_inspectors(&["ssrf_guard", "secrets_scaner"]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let err = match resolve_supervisor_components_with_dir(&plan, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("typo in disabled_inspectors must be refused"),
        };
        match err {
            ResolveError::EgressPolicyInvalid {
                value,
                path,
                detail,
            } => {
                assert_eq!(value, "acme:web-worker");
                let s = path.to_string_lossy();
                assert!(s.contains("acme"), "path missing tenant: {s}");
                assert!(s.contains("web-worker.toml"), "path missing workload: {s}");
                assert!(
                    detail.contains("secrets_scaner"),
                    "detail must name the typo: {detail}"
                );
                assert!(
                    detail.contains("1"),
                    "detail must name the row index (1): {detail}"
                );
                // Operator should see the valid names enumerated so
                // they can fix the typo without grep-ing source.
                assert!(
                    detail.contains("ssrf_guard")
                        || detail.contains("secrets_scanner")
                        || detail.contains("pii_redactor"),
                    "detail should list at least one valid name: {detail}"
                );
            }
            other => panic!("expected EgressPolicyInvalid, got {other:?}"),
        }
    }

    #[test]
    fn slice_b_resolver_accepts_bundle_with_only_known_disabled_inspectors() {
        // Regression for the tightening: a bundle with the right
        // names continues to resolve cleanly (chain shrinks per the
        // disabled list).
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_disabled_inspectors(&["ssrf_guard", "pii_redactor"]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");
        let _slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("known names should resolve: {e}"));
    }

    // ──────────────────────────────────────────────────────────────
    // `[pii]` policy wiring
    //
    // `slots_from_bundle` calls `build_inspector_chain_with_pii`
    // so a tenant bundle's `[pii]` section (mode + categories) drives
    // runtime behaviour. The resolver path enforces fail-loud on
    // unknown mode strings or category names — typos at admission
    // are an operator error to fix, not silently degraded
    // enforcement.
    // ──────────────────────────────────────────────────────────────

    fn fixture_bundle_with_pii(mode: Option<&str>, categories: &[&str]) -> String {
        let mode_line = match mode {
            Some(m) => format!("mode = \"{m}\""),
            None => String::new(),
        };
        let cats = categories
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let cats_line = if categories.is_empty() {
            String::new()
        } else {
            format!("categories = [{cats}]")
        };
        format!(
            r#"
schema_version = 1
bundle_id      = "acme/web-worker"
bundle_version = 1

[network]
[egress]

[pii]
{mode_line}
{cats_line}

[tool]
[artifact]
[keys]
[audit]
"#,
        )
    }

    #[test]
    fn slice_b_resolver_accepts_pii_mode_redact_and_subset_categories() {
        // `pii.mode = "redact"` + a category subset must parse + resolve.
        // The inspector chain stays at length 5 (pii_redactor present
        // with operator-supplied mode + categories).
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_pii(Some("redact"), &["email", "us_ssn"]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");
        let _slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("redact + subset must resolve: {e}"));
    }

    #[test]
    fn slice_b_resolver_disabled_pii_mode_drops_inspector_from_chain() {
        // `pii.mode = "disabled"` is the operator-natural kill-switch.
        // The chain returned by `build_inspector_chain_with_pii` then
        // has 4 inspectors. We can't observe chain length through the
        // L7EgressProxy directly, but we can probe via the shared
        // builder against the parsed bundle's egress + pii.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_pii(Some("disabled"), &[]),
        );
        let bundle =
            mvm_core::policy::toml_loader::load_bundle_from_path(tmp.path(), "acme", "web-worker")
                .expect("bundle parses");
        let chain = mvm_hostd::supervisor::build_inspector_chain_with_pii(
            &bundle.egress,
            &bundle.pii,
            None,
        )
        .expect("disabled is valid");
        assert_eq!(
            chain.len(),
            4,
            "pii.mode = disabled must drop the inspector"
        );

        // Now drive through the resolver end-to-end too — slots
        // construct without error.
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");
        let _slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("disabled-mode bundle must resolve: {e}"));
    }

    #[test]
    fn slice_b_resolver_refuses_bundle_with_unknown_pii_mode() {
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_pii(Some("paranoid"), &[]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let err = match resolve_supervisor_components_with_dir(&plan, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("unknown pii.mode must be refused"),
        };
        match err {
            ResolveError::PiiPolicyInvalid {
                value,
                path,
                detail,
            } => {
                assert_eq!(value, "acme:web-worker");
                let s = path.to_string_lossy();
                assert!(s.contains("acme"), "path missing tenant: {s}");
                assert!(
                    detail.contains("paranoid"),
                    "detail must name the bad mode: {detail}"
                );
                // Operator should see the valid mode enumeration.
                assert!(
                    detail.contains("detect")
                        && detail.contains("redact")
                        && detail.contains("refuse")
                        && detail.contains("disabled"),
                    "detail should list valid modes: {detail}"
                );
            }
            other => panic!("expected PiiPolicyInvalid, got {other:?}"),
        }
    }

    #[test]
    fn slice_b_resolver_refuses_bundle_with_unknown_pii_category() {
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_pii(Some("detect"), &["email", "license_plate"]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let err = match resolve_supervisor_components_with_dir(&plan, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("unknown pii category must be refused"),
        };
        match err {
            ResolveError::PiiPolicyInvalid { detail, .. } => {
                assert!(
                    detail.contains("license_plate"),
                    "detail must name the bad category: {detail}"
                );
                assert!(
                    detail.contains("email")
                        || detail.contains("us_ssn")
                        || detail.contains("credit_card"),
                    "detail should list at least one valid category: {detail}"
                );
            }
            other => panic!("expected PiiPolicyInvalid, got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // `[audit].stream_destinations` shape validation
    //
    // The resolver runs `validate_audit_policy_stream_destinations`
    // before constructing slots so a typo on an audit-stream URL
    // fails admission rather than silently dropping the entry
    // downstream of the (yet-to-ship) audit replicator.
    // ──────────────────────────────────────────────────────────────

    fn fixture_bundle_with_audit_destinations(destinations: &[&str]) -> String {
        let list = destinations
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"
schema_version = 1
bundle_id      = "acme/web-worker"
bundle_version = 1

[network]
[egress]
[pii]
[tool]
[artifact]
[keys]

[audit]
chain_signing = true
stream_destinations = [{list}]
"#,
        )
    }

    #[test]
    fn slice_b_resolver_accepts_known_audit_schemes() {
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_audit_destinations(&[
                "file:///var/log/mvm/audit.jsonl",
                "https://audit.example.com/ingest",
            ]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");
        let _slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("known schemes must resolve: {e}"));
    }

    #[test]
    fn slice_b_resolver_refuses_bundle_with_typo_in_audit_destination() {
        // `htpps://` is the canonical typo. Validator must catch it
        // and the resolver must surface as PolicyInvalid with the
        // row index named.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_audit_destinations(&[
                "file:///var/log/mvm/audit.jsonl",
                "htpps://audit.example.com/ingest",
            ]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let err = match resolve_supervisor_components_with_dir(&plan, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("typo in audit URL must be refused"),
        };
        match err {
            ResolveError::AuditPolicyInvalid {
                value,
                path,
                detail,
            } => {
                assert_eq!(value, "acme:web-worker");
                let s = path.to_string_lossy();
                assert!(s.contains("acme"), "path missing tenant: {s}");
                assert!(
                    detail.contains("htpps://audit.example.com/ingest"),
                    "detail must name the typo: {detail}"
                );
                assert!(
                    detail.contains("1"),
                    "detail must name the row index (1): {detail}"
                );
                assert!(
                    detail.contains("https://") || detail.contains("file://"),
                    "detail should list at least one valid scheme: {detail}"
                );
            }
            other => panic!("expected AuditPolicyInvalid, got {other:?}"),
        }
    }

    #[test]
    fn slice_b_resolver_refuses_audit_destination_without_scheme() {
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_audit_destinations(&["/var/log/audit.jsonl"]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");
        let err = match resolve_supervisor_components_with_dir(&plan, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("scheme-less audit URL must be refused"),
        };
        assert!(
            matches!(err, ResolveError::AuditPolicyInvalid { .. }),
            "{err}"
        );
    }

    #[test]
    fn slice_b_egress_still_denies_off_allow_list_with_full_chain() {
        // Regression: with the full `build_inspector_chain` chain
        // (rather than a hand-rolled DestinationPolicy one), the
        // off-allow-list deny path
        // still fires (DestinationPolicy stays first in the chain
        // order, so it short-circuits before SSRF / secrets /
        // injection / PII).
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_tool_allow("web_search"),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let slots = resolve_supervisor_components_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("expected live slots, got {e}"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let deny = slots
                .egress
                .inspect("evil.example.com", "/x")
                .await
                .expect("policy lookup must succeed (not NotWired)");
            assert!(
                matches!(deny, mvm_hostd::supervisor::EgressDecision::Deny { .. }),
                "off-list host should still produce Deny after chain expansion, got {deny:?}"
            );
        });
    }
}
