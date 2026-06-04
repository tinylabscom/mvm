//! Plan 112 Phase 3c — shared audit-substrate resolution for backends
//! that own a `SupervisorConfig`-shaped audit surface (libkrun, Vz).
//!
//! Lifts the path-derivation + `vm_name` / `tenant_id` allowlist
//! validation out of the per-backend `start()` paths so libkrun.rs and
//! vz.rs share one source of truth. The next plan after 112 — a
//! `NetworkProvider` trait — will lift `compute_audit_substrate(...)`
//! into a trait method (`provider.activate_audit(...)`). Keeping the
//! free-function signature stable now makes that extraction mechanical.
//!
//! Today there's no trait; just one shared module.

use anyhow::{Result, bail};
use std::path::PathBuf;

/// Resolved audit-substrate paths for a single VM. Maps directly into
/// `libkrun_sys::SupervisorConfig`'s five `Option`-wrapped audit
/// fields. `None` on every field means the VM has no admission
/// context — the supervisor stays on the legacy `run_supervisor`
/// path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditSubstrate {
    pub tenant_id: Option<String>,
    pub audit_dir: Option<PathBuf>,
    pub gateway_audit_socket: Option<PathBuf>,
    pub gateway_events_socket: Option<PathBuf>,
    pub signing_key_path: Option<PathBuf>,
}

/// Plan 112 Phase 3c — RFC 1123 DNS-label-shaped allowlist for
/// identifiers that flow into filesystem paths (`tenant_id`,
/// `vm_name`). Allowlist + length cap + ASCII-only — fail-closed.
/// Deny-list patterns (rejecting `..`, `/`, NUL, etc.) are fail-open
/// by construction; allowlist is the correct shape.
///
/// `mvm-plan`'s `TenantId` is an unchecked `String` newtype today
/// (only sha256_hex is validated at `mvm-plan/src/types.rs`); this is
/// the defense-in-depth boundary.
fn validate_dns_label(label: &str, kind: &str) -> Result<()> {
    if label.is_empty() {
        bail!("{kind} must not be empty");
    }
    if label.len() > 63 {
        bail!("{kind} must be 1..=63 chars; got {}", label.len());
    }
    let first = label.chars().next().expect("len > 0 checked above");
    if !first.is_ascii_alphanumeric() {
        bail!("{kind} must start with [A-Za-z0-9]; got {first:?}");
    }
    for c in label.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '-' || c == '_';
        if !ok {
            bail!("{kind} may only contain [A-Za-z0-9_-]; got {c:?}");
        }
    }
    Ok(())
}

pub fn validate_tenant_id(tenant: &str) -> Result<()> {
    validate_dns_label(tenant, "tenant_id")
}

pub fn validate_vm_name(name: &str) -> Result<()> {
    validate_dns_label(name, "vm_name")
}

/// Plan 112 Phase 3c — derive the five audit-substrate paths for
/// `vm_name` from `mvm_core::config::mvm_data_dir()` when `tenant_id`
/// is `Some`. Returns `AuditSubstrate::default()` (all fields `None`)
/// when `tenant_id` is `None` so the calling backend's supervisor
/// takes the legacy `run_supervisor` path. Validates both `vm_name`
/// and `tenant_id` against the DNS-label allowlist before any path
/// derivation.
///
/// **Forward-compat note:** Plan N+1 (NetworkProvider trait) will lift
/// this into a trait method on each provider. This function's
/// signature is the seam — `provider.activate_audit(vm_name,
/// tenant_id)` returning the same `AuditSubstrate` value. Keep that
/// shape stable.
pub fn compute_audit_substrate(vm_name: &str, tenant_id: Option<&str>) -> Result<AuditSubstrate> {
    validate_vm_name(vm_name)?;
    let Some(tenant) = tenant_id else {
        return Ok(AuditSubstrate::default());
    };
    validate_tenant_id(tenant)?;
    let data_dir = PathBuf::from(mvm_core::config::mvm_data_dir());
    let audit_dir = data_dir.join("audit");
    let gw_audit = audit_dir.join(format!("gateway-{vm_name}.sock"));
    let gw_events = audit_dir.join(format!("gateway-events-{vm_name}.sock"));
    let signing_key = data_dir.join("keys").join("host-signer.ed25519");
    Ok(AuditSubstrate {
        tenant_id: Some(tenant.to_string()),
        audit_dir: Some(audit_dir),
        gateway_audit_socket: Some(gw_audit),
        gateway_events_socket: Some(gw_events),
        signing_key_path: Some(signing_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_tenant_id_allowlist_dns_label_shape() {
        // Allowed: starts with alphanumeric, body is [A-Za-z0-9_-], max 63 chars.
        assert!(validate_tenant_id("a").is_ok());
        assert!(validate_tenant_id("acme").is_ok());
        assert!(validate_tenant_id("acme-corp_42").is_ok());
        assert!(validate_tenant_id("A1B2").is_ok());
        assert!(validate_tenant_id(&"a".repeat(63)).is_ok());

        // Rejected: empty, too long, leading non-alnum, disallowed chars,
        // Unicode/non-ASCII.
        assert!(validate_tenant_id("").is_err());
        assert!(validate_tenant_id(&"a".repeat(64)).is_err());
        assert!(validate_tenant_id("-leading-dash").is_err());
        assert!(validate_tenant_id("_leading-underscore").is_err());
        assert!(validate_tenant_id("..").is_err());
        assert!(validate_tenant_id("a/b").is_err());
        assert!(validate_tenant_id("a\\b").is_err());
        assert!(validate_tenant_id("a\0b").is_err());
        // dots out (DNS uses them as separators; we want a single label)
        assert!(validate_tenant_id("a.b").is_err());
        assert!(validate_tenant_id(" trim ").is_err());
        assert!(validate_tenant_id("acmé").is_err());
        // Cyrillic 'а' confusable
        assert!(validate_tenant_id("аcme").is_err());
    }

    #[test]
    fn validate_vm_name_allowlist_dns_label_shape() {
        // Same shape as tenant_id (both end up in filesystem paths).
        assert!(validate_vm_name("vm-01").is_ok());
        assert!(validate_vm_name("").is_err());
        assert!(validate_vm_name("../escape").is_err());
        assert!(validate_vm_name(&"v".repeat(64)).is_err());
    }

    #[test]
    fn compute_with_tenant_derives_all_paths() {
        let s = compute_audit_substrate("test-vm", Some("acme")).expect("compute");
        assert_eq!(s.tenant_id.as_deref(), Some("acme"));
        let dir = s.audit_dir.expect("audit_dir");
        assert!(dir.ends_with("audit"));
        let gw = s.gateway_audit_socket.expect("gw audit");
        assert!(
            gw.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("test-vm")
        );
        let ev = s.gateway_events_socket.expect("gw events");
        assert!(
            ev.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("test-vm")
        );
        assert!(s.signing_key_path.is_some());
    }

    #[test]
    fn compute_without_tenant_returns_default() {
        let s = compute_audit_substrate("dev-vm", None).expect("compute");
        assert_eq!(s, AuditSubstrate::default());
    }

    #[test]
    fn compute_with_unsafe_tenant_errors() {
        assert!(compute_audit_substrate("vm", Some("../escape")).is_err());
        assert!(compute_audit_substrate("vm", Some("a/b")).is_err());
        assert!(compute_audit_substrate("vm", Some("")).is_err());
    }

    #[test]
    fn compute_with_unsafe_vm_name_errors() {
        assert!(compute_audit_substrate("../escape", Some("acme")).is_err());
        assert!(compute_audit_substrate("", Some("acme")).is_err());
        assert!(compute_audit_substrate("vm/escape", Some("acme")).is_err());
    }
}
