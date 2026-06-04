//! Plan 60 Phase 6 — on-disk TOML loader for `PolicyBundle`.
//!
//! Operators provision policy bundles as TOML at
//! `~/.mvm/policies/<tenant>/<workload>.toml`. The plan-64 W5
//! resolver maps the four `PolicyRef`/`FsPolicyRef` fields on an
//! `ExecutionPlan` onto a single bundle file: a workload's
//! `(network_policy, fs_policy, egress_policy, tool_policy)` refs
//! all point at one TOML, which carries the per-policy sections
//! the supervisor's component slots (`EgressProxy`, `ToolGate`,
//! `KeystoreReleaser`, `ArtifactCollector`) consume at admission.
//!
//! ## Schema
//!
//! ```toml
//! schema_version = 1
//! bundle_id      = "acme/web-worker"
//! bundle_version = 1
//!
//! [network]
//! preset = "tenant-isolated"
//!
//! [egress]
//! mode = "default"
//! allow_list = [["api.example.com", 443]]
//! allow_plain_http = false
//!
//! [pii]
//! mode = "redact"
//! categories = ["email", "ssn"]
//!
//! [tool]
//! allowed = ["web_search", "web_fetch"]
//!
//! [artifact]
//! capture_paths = ["/artifacts"]
//! retention_days = 7
//!
//! [keys]
//! rotation_interval_days = 30
//!
//! [audit]
//! chain_signing = true
//! stream_destinations = ["file:///var/log/mvm/audit.jsonl"]
//!
//! [tenant_overlays]   # optional; empty by default
//! ```
//!
//! `deny_unknown_fields` is enforced by every type so a typo fails
//! loud at parse time rather than silently dropping settings. The
//! `schema_version` field gates the whole bundle — older agents
//! refuse newer versions before per-field deserialization.
//!
//! ## What this module does NOT do (yet)
//!
//! - **Sign / verify the bundle.** mvmd's signing key is the
//!   eventual authoritative source; `verify_bundle` (in
//!   `mvm-policy::signing`) takes a SignedPolicyBundle envelope.
//!   This loader reads bare TOML for the single-host posture —
//!   suitable for `local` tenant; mvmd-signed bundles layer on
//!   later via the same parse + then verify-against-trusted-keys.
//! - **Construct concrete `EgressProxy` / `ToolGate` impls.** That
//!   wiring is the consumer's job (plan 60 Phase 3 builds the
//!   L4/L7 proxies; this loader returns the parsed bundle). Until
//!   Phase 3 ships, the plan-64 W5 resolver returns Noops even
//!   for parsed bundles — the goal here is to ship the file
//!   format so operators can stage bundles ahead of the proxies.

use std::path::{Path, PathBuf};

use crate::policy::bundle::{PolicyBundle, SCHEMA_VERSION};

/// Errors `load_bundle_from_path` can return. Distinguish "file not
/// there" (operator hasn't provisioned a bundle) from
/// "file there but unparseable" (operator's mistake to fix).
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("policy bundle file {path:?} not found")]
    NotFound { path: PathBuf },
    #[error("could not read policy bundle {path:?}: {detail}")]
    Io { path: PathBuf, detail: String },
    #[error("could not parse policy bundle {path:?} as TOML: {detail}")]
    Parse { path: PathBuf, detail: String },
    #[error(
        "policy bundle {path:?} has schema_version {got}; this binary only \
         understands version {known}"
    )]
    SchemaMismatch { path: PathBuf, got: u32, known: u32 },
}

/// Default directory the loader searches: `~/.mvm/policies/`.
/// Per-tenant subdir `<base>/<tenant>/`, per-workload file
/// `<base>/<tenant>/<workload>.toml`.
pub fn default_policy_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".mvm").join("policies"))
}

/// Compose the canonical bundle path: `<base>/<tenant>/<workload>.toml`.
/// Reserved for the file-on-disk lookup; doesn't validate that the
/// file exists.
pub fn bundle_path(base: &Path, tenant: &str, workload: &str) -> PathBuf {
    base.join(tenant).join(format!("{workload}.toml"))
}

/// Parse a TOML string into a `PolicyBundle`. Verifies the
/// schema_version before returning — older verifiers refuse newer
/// schemas without trying to deserialize unknown fields.
pub fn parse_bundle(toml_text: &str) -> Result<PolicyBundle, LoadError> {
    let bundle: PolicyBundle = toml::from_str(toml_text).map_err(|e| LoadError::Parse {
        path: PathBuf::from("<in-memory>"),
        detail: e.to_string(),
    })?;
    if bundle.schema_version != SCHEMA_VERSION {
        return Err(LoadError::SchemaMismatch {
            path: PathBuf::from("<in-memory>"),
            got: bundle.schema_version,
            known: SCHEMA_VERSION,
        });
    }
    Ok(bundle)
}

/// Read `<base>/<tenant>/<workload>.toml`, parse it, validate the
/// schema_version. Returns `LoadError::NotFound` if the file
/// doesn't exist (distinct from `Io` so callers can choose to
/// fall through to a default).
pub fn load_bundle_from_path(
    base: &Path,
    tenant: &str,
    workload: &str,
) -> Result<PolicyBundle, LoadError> {
    let path = bundle_path(base, tenant, workload);
    if !path.exists() {
        return Err(LoadError::NotFound { path });
    }
    let text = std::fs::read_to_string(&path).map_err(|e| LoadError::Io {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    let bundle: PolicyBundle = toml::from_str(&text).map_err(|e| LoadError::Parse {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    if bundle.schema_version != SCHEMA_VERSION {
        return Err(LoadError::SchemaMismatch {
            path,
            got: bundle.schema_version,
            known: SCHEMA_VERSION,
        });
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyId;

    fn minimal_bundle_toml() -> String {
        format!(
            r#"
schema_version = {SCHEMA_VERSION}
bundle_id      = "acme/web-worker"
bundle_version = 1

[network]
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
    fn parse_bundle_round_trips_minimal_toml() {
        let bundle = parse_bundle(&minimal_bundle_toml()).unwrap();
        assert_eq!(bundle.schema_version, SCHEMA_VERSION);
        assert_eq!(bundle.bundle_id, PolicyId("acme/web-worker".to_string()));
        assert_eq!(bundle.bundle_version, 1);
    }

    #[test]
    fn parse_bundle_round_trips_richer_toml() {
        // Confirms that the per-policy sections deserialise — a typo
        // in any one of them would fail because every sub-policy
        // uses #[serde(deny_unknown_fields)].
        let text = format!(
            r#"
schema_version = {SCHEMA_VERSION}
bundle_id      = "acme/web"
bundle_version = 3

[network]
preset = "tenant-isolated"

[egress]
mode = "default"
allow_list = [["api.example.com", 443], ["telemetry.example.com", 0]]
allow_plain_http = false
body_cap_bytes = 0
disabled_inspectors = ["pii_redactor"]

[pii]
mode = "redact"
categories = ["email", "ssn"]

[tool]
allowed = ["web_search", "web_fetch", "code_eval"]

[artifact]
capture_paths = ["/artifacts", "/output"]
retention_days = 30

[keys]
rotation_interval_days = 14

[audit]
chain_signing = true
stream_destinations = ["file:///var/log/mvm/audit.jsonl"]
"#,
        );
        let bundle = parse_bundle(&text).unwrap();
        assert_eq!(bundle.network.preset.as_deref(), Some("tenant-isolated"));
        assert_eq!(bundle.egress.allow_list.len(), 2);
        assert_eq!(bundle.egress.allow_list[0].0, "api.example.com");
        assert_eq!(bundle.egress.allow_list[0].1, 443);
        assert_eq!(bundle.pii.categories, vec!["email", "ssn"]);
        assert_eq!(bundle.tool.allowed.len(), 3);
        assert_eq!(bundle.artifact.retention_days, 30);
        assert_eq!(bundle.keys.rotation_interval_days, 14);
        assert!(bundle.audit.chain_signing);
        assert_eq!(bundle.audit.stream_destinations.len(), 1);
    }

    #[test]
    fn parse_bundle_round_trips_l4_rules() {
        // Plan 60 Phase 3 Slice B — `[[network.l4]]` rows attach an
        // allow-list to the bundle. The supervisor's L4Gate consumes
        // these at flow-establishment time; here we just prove the
        // schema accepts the rows and surfaces them on `bundle.network`.
        let text = format!(
            r#"
schema_version = {SCHEMA_VERSION}
bundle_id      = "acme/net"
bundle_version = 1

[network]
preset = "tenant-isolated"

[[network.l4]]
proto    = "tcp"
dst_cidr = "10.0.0.0/24"
port_lo  = 443
port_hi  = 443

[[network.l4]]
proto    = "udp"
dst_cidr = "8.8.8.8/32"
port_lo  = 0
port_hi  = 0

[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
"#,
        );
        let bundle = parse_bundle(&text).unwrap();
        assert_eq!(bundle.network.l4.len(), 2);
        assert_eq!(bundle.network.l4[0].proto, "tcp");
        assert_eq!(bundle.network.l4[0].dst_cidr, "10.0.0.0/24");
        assert_eq!(bundle.network.l4[0].port_lo, 443);
        assert_eq!(bundle.network.l4[0].port_hi, 443);
        assert_eq!(bundle.network.l4[1].proto, "udp");
        assert_eq!(bundle.network.l4[1].port_lo, 0);
        assert_eq!(bundle.network.l4[1].port_hi, 0);
    }

    #[test]
    fn parse_bundle_treats_missing_l4_section_as_empty() {
        // `#[serde(default)]` on `NetworkPolicy::l4` means bundles
        // authored before Slice B continue to parse — they evaluate
        // as default-deny at the gate.
        let bundle = parse_bundle(&minimal_bundle_toml()).unwrap();
        assert!(
            bundle.network.l4.is_empty(),
            "empty bundle should deserialize l4 as empty vec"
        );
    }

    #[test]
    fn parse_bundle_rejects_unknown_field_inside_l4_row() {
        // L4RuleSpec has deny_unknown_fields — a typo in a row's
        // fields fails loud rather than silently dropping the rule.
        let text = format!(
            r#"
schema_version = {SCHEMA_VERSION}
bundle_id      = "acme/net"
bundle_version = 1

[network]

[[network.l4]]
proto    = "tcp"
dst_cidr = "10.0.0.0/24"
port_lo  = 443
port_hi  = 443
typo     = "oops"

[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
"#,
        );
        let err = parse_bundle(&text).unwrap_err();
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    #[test]
    fn parse_bundle_rejects_schema_version_mismatch() {
        let text = r#"
schema_version = 999
bundle_id      = "acme/web"
bundle_version = 1

[network]
[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
"#;
        let err = parse_bundle(text).unwrap_err();
        match err {
            LoadError::SchemaMismatch { got, known, .. } => {
                assert_eq!(got, 999);
                assert_eq!(known, SCHEMA_VERSION);
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn parse_bundle_rejects_unknown_field_at_top_level() {
        // PolicyBundle has deny_unknown_fields — a typo at the top
        // level must fail parse rather than silently dropping the
        // setting.
        let text = format!(
            r#"
schema_version = {SCHEMA_VERSION}
bundle_id      = "acme/web"
bundle_version = 1
oops_typo      = true

[network]
[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
"#,
        );
        let err = parse_bundle(&text).unwrap_err();
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    #[test]
    fn parse_bundle_rejects_unknown_field_in_sub_policy() {
        // Sub-policy types also have deny_unknown_fields. A typo
        // inside `[egress]` should fail loud.
        let text = format!(
            r#"
schema_version = {SCHEMA_VERSION}
bundle_id      = "acme/web"
bundle_version = 1

[network]
[egress]
mode = "default"
typo_field = "nope"

[pii]
[tool]
[artifact]
[keys]
[audit]
"#,
        );
        let err = parse_bundle(&text).unwrap_err();
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    #[test]
    fn parse_bundle_rejects_malformed_toml() {
        let err = parse_bundle("schema_version = [[\n").unwrap_err();
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    // ──────────────────────────────────────────────────────────────
    // load_bundle_from_path
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn load_bundle_round_trips_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant_dir = tmp.path().join("acme");
        std::fs::create_dir(&tenant_dir).unwrap();
        std::fs::write(tenant_dir.join("web.toml"), minimal_bundle_toml()).unwrap();
        let bundle = load_bundle_from_path(tmp.path(), "acme", "web").unwrap();
        assert_eq!(bundle.bundle_id, PolicyId("acme/web-worker".to_string()));
    }

    #[test]
    fn load_bundle_reports_not_found_distinctly() {
        let tmp = tempfile::tempdir().unwrap();
        let err = load_bundle_from_path(tmp.path(), "acme", "nope").unwrap_err();
        assert!(matches!(err, LoadError::NotFound { .. }));
    }

    #[test]
    fn load_bundle_reports_io_for_unreadable_file() {
        // Create the tenant dir but make the bundle path a directory
        // — std::fs::read_to_string fails with EISDIR rather than
        // ENOENT, which exercises the Io branch.
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("acme").join("web.toml");
        std::fs::create_dir_all(&bad).unwrap();
        let err = load_bundle_from_path(tmp.path(), "acme", "web").unwrap_err();
        assert!(matches!(err, LoadError::Io { .. }));
    }

    #[test]
    fn bundle_path_composes_canonical_layout() {
        let p = bundle_path(Path::new("/x"), "acme", "web");
        assert_eq!(p, PathBuf::from("/x/acme/web.toml"));
    }
}
