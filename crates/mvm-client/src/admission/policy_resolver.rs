//! `PolicyRef → validated policy bundle` resolver.
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
//! policy bundle on disk at `~/.mvm/policies/<tenant>/<workload>.toml`.
//! Admission validates the refs and every fallible policy field, then
//! hands the parsed bundle to the host bridge that actually enforces
//! the admitted L4 boundary. It does not construct speculative
//! supervisor controls that the launch path cannot consume.

use std::path::PathBuf;

use mvm_core::pii::{PiiPolicyError, PiiRedactor};
use mvm_core::plan::{ExecutionPlan, FsPolicyRef, PolicyRef};
use mvm_core::policy::canonicalize_l4;
use mvm_hostd::supervisor::{
    AuditPolicyValidationError, EgressPolicyValidationError,
    validate_audit_policy_stream_destinations, validate_egress_policy_inspector_names,
};

/// The fixed identifier for the local-dev policy bundle. Any
/// `PolicyRef`/`FsPolicyRef` whose inner value equals this string
/// carries no tenant bundle to the host bridge, preserving its
/// mandatory-deny posture. Use `<tenant>:<workload>` to point at a
/// tenant bundle.
pub const LOCAL_DEFAULT: &str = "local-default";

/// What admission successfully resolved without implying that every
/// section of a policy bundle has a live runtime consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyResolutionKind {
    LocalDefault,
    BundleValidated,
    GeneratedBundleValidated,
}

impl PolicyResolutionKind {
    pub const fn audit_label(self) -> &'static str {
        match self {
            Self::LocalDefault => "local-default",
            Self::BundleValidated => "bundle-validated",
            Self::GeneratedBundleValidated => "generated-bundle-validated",
        }
    }
}

/// A validated policy and the bundle the live host bridge consumes.
#[derive(Debug)]
pub struct ValidatedPolicy {
    pub kind: PolicyResolutionKind,
    pub bundle: Option<mvm_core::policy::PolicyBundle>,
}

/// Errors policy validation can return.
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
    /// same `<tenant>:<workload>` bundle so admission validates one
    /// coherent policy document.
    MixedRefs {
        first: String,
        second_field: &'static str,
        second: String,
    },

    /// A ref's shape doesn't match `"local-default"` or
    /// `"<tenant>:<workload>"`. We refuse rather than fall back to
    /// a default so that a typo (`"locale-default"`) fails loudly at
    /// admission instead of silently changing the policy posture.
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
    /// drift). Admission enforces fail-loud validation so a typo
    /// cannot silently leave an inspector enabled when the operator
    /// intended to disable it.
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

/// Validate a plan's four policy refs and return the bundle used by the
/// live host bridge. Local-default plans carry no bundle and therefore
/// retain the bridge's mandatory-deny posture.
pub fn validate_policy_refs(plan: &ExecutionPlan) -> Result<ValidatedPolicy, ResolveError> {
    validate_policy_refs_with_dir(plan, &default_policy_dir())
}

/// Test seam for [`validate_policy_refs`] with a caller-supplied policy
/// directory instead of `$HOME/.mvm/policies`.
pub fn validate_policy_refs_with_dir(
    plan: &ExecutionPlan,
    base_dir: &std::path::Path,
) -> Result<ValidatedPolicy, ResolveError> {
    let PolicyRef(network) = &plan.network_policy;
    let FsPolicyRef(fs) = &plan.fs_policy;
    let PolicyRef(egress) = &plan.egress_policy;
    let PolicyRef(tool) = &plan.tool_policy;

    match classify_plan_refs(network, fs, egress, tool)? {
        RefShape::LocalDefault => Ok(ValidatedPolicy {
            kind: PolicyResolutionKind::LocalDefault,
            bundle: None,
        }),
        RefShape::TenantWorkload { tenant, workload } => {
            let bundle = load_tenant_workload(base_dir, network, tenant, workload)?;
            let bundle_path =
                mvm_core::policy::toml_loader::bundle_path(base_dir, tenant, workload);
            validate_bundle(&bundle, network, &bundle_path)?;
            Ok(ValidatedPolicy {
                kind: PolicyResolutionKind::BundleValidated,
                bundle: Some(bundle),
            })
        }
        RefShape::Unrecognized => unreachable!("classify_plan_refs handled Unrecognized"),
    }
}

/// Validate the bundle fields whose syntax is stricter than TOML schema
/// parsing. The resulting bundle is later handed to the bridge; this
/// function deliberately constructs no runtime enforcement controls.
fn validate_bundle(
    bundle: &mvm_core::policy::PolicyBundle,
    ref_value: &str,
    path: &std::path::Path,
) -> Result<(), ResolveError> {
    canonicalize_l4(&bundle.network.l4).map_err(|e| ResolveError::L4SpecInvalid {
        value: ref_value.to_string(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    validate_egress_policy_inspector_names(&bundle.egress).map_err(
        |e: EgressPolicyValidationError| ResolveError::EgressPolicyInvalid {
            value: ref_value.to_string(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        },
    )?;

    validate_audit_policy_stream_destinations(&bundle.audit).map_err(
        |e: AuditPolicyValidationError| ResolveError::AuditPolicyInvalid {
            value: ref_value.to_string(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        },
    )?;

    PiiRedactor::validate_policy(&bundle.pii).map_err(|e: PiiPolicyError| {
        ResolveError::PiiPolicyInvalid {
            value: ref_value.to_string(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        }
    })?;
    Ok(())
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
            asset_identities: Vec::new(),
            outputs: Vec::new(),
            agent_verbs: None,
            services: Vec::new(),
            extensions: Vec::new(),
            stream_edges: Vec::new(),
            sdk_uses_sidecar: true,
        }
    }

    #[test]
    fn policy_validation_accepts_local_default_without_a_bundle() {
        let validated = validate_policy_refs(&fixture_plan()).expect("local-default must validate");
        assert_eq!(validated.kind, PolicyResolutionKind::LocalDefault);
        assert!(validated.bundle.is_none());
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
        // validate_policy_refs attempt to load the bundle
        // file. When the file isn't there we surface BundleNotFound
        // with a clear path so operators know exactly where to put it.
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");
        let err = match validate_policy_refs(&plan) {
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
        let err = match validate_policy_refs(&plan) {
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
    fn policy_resolver_rejects_mixed_refs() {
        // All four refs must agree (same bundle). If only one
        // points at a tenant bundle while the others stay
        // local-default, the resolver refuses with MixedRefs.
        let mut plan = fixture_plan();
        plan.tool_policy = PolicyRef("acme:tools-v1".to_string());
        let err = match validate_policy_refs(&plan) {
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
        let err = match validate_policy_refs(&plan) {
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
    // Tenant bundle validation
    //
    // A parsed `<tenant>:<workload>` bundle is validated and returned
    // for the host bridge. These tests use the `_with_dir` seam so
    // they can inject a tempdir without mutating $HOME.
    // ──────────────────────────────────────────────────────────────

    fn write_bundle(dir: &std::path::Path, tenant: &str, workload: &str, body: &str) {
        let tenant_dir = dir.join(tenant);
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(tenant_dir.join(format!("{workload}.toml")), body).unwrap();
    }

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

        let err = match validate_policy_refs_with_dir(&plan, tmp.path()) {
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

        let err = match validate_policy_refs_with_dir(&plan, tmp.path()) {
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
    // Inspector-name validation.
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
    fn policy_validation_returns_the_tenant_bundle_for_bridge_enforcement() {
        // A tenant:workload plan resolves to the on-disk
        // PolicyBundle the supervisor's L4 gate + observers consume.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_disabled_inspectors(&[]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");

        let validated = validate_policy_refs_with_dir(&plan, tmp.path()).expect("resolve ok");
        assert_eq!(validated.kind, PolicyResolutionKind::BundleValidated);
        let bundle = validated
            .bundle
            .expect("a tenant:workload plan yields a bundle");
        let expected =
            mvm_core::policy::toml_loader::load_bundle_from_path(tmp.path(), "acme", "web-worker")
                .unwrap();
        assert_eq!(bundle, expected);
    }

    #[test]
    fn policy_validation_returns_no_bundle_for_local_default() {
        // A local-default plan has no per-tenant policy → None (the bridge
        // enforces mandatory-deny only); the policy dir is never touched.
        let plan = fixture_plan();
        let result = validate_policy_refs_with_dir(&plan, std::path::Path::new("/nonexistent"))
            .expect("resolve ok");
        assert_eq!(result.kind, PolicyResolutionKind::LocalDefault);
        assert!(result.bundle.is_none());
    }

    #[test]
    fn slice_b_resolver_refuses_bundle_with_unknown_disabled_inspector() {
        // Tightening: the resolver path runs
        // `validate_egress_policy_inspector_names`, so a typo in `disabled_inspectors`
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

        let err = match validate_policy_refs_with_dir(&plan, tmp.path()) {
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
        // names continues to validate cleanly.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_disabled_inspectors(&["ssrf_guard", "pii_redactor"]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");
        let _validated = validate_policy_refs_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("known names should resolve: {e}"));
    }

    // ──────────────────────────────────────────────────────────────
    // `[pii]` policy validation. Unknown modes or category names are
    // operator errors, not silently degraded enforcement.
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
        // `pii.mode = "redact"` + a category subset must validate without
        // constructing an inspector chain in the admission path.
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(
            tmp.path(),
            "acme",
            "web-worker",
            &fixture_bundle_with_pii(Some("redact"), &["email", "us_ssn"]),
        );
        let mut plan = fixture_plan();
        set_all_refs(&mut plan, "acme:web-worker");
        let _validated = validate_policy_refs_with_dir(&plan, tmp.path())
            .unwrap_or_else(|e| panic!("redact + subset must resolve: {e}"));
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

        let err = match validate_policy_refs_with_dir(&plan, tmp.path()) {
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

        let err = match validate_policy_refs_with_dir(&plan, tmp.path()) {
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
    // so a typo on an audit-stream URL fails admission rather than
    // silently dropping the entry downstream.
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
        let _validated = validate_policy_refs_with_dir(&plan, tmp.path())
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

        let err = match validate_policy_refs_with_dir(&plan, tmp.path()) {
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
        let err = match validate_policy_refs_with_dir(&plan, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("scheme-less audit URL must be refused"),
        };
        assert!(
            matches!(err, ResolveError::AuditPolicyInvalid { .. }),
            "{err}"
        );
    }
}
