//! Active-backend security posture and per-backend balloon capability.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::ui;
use mvm_core::vm_backend::ClaimStatus;
use mvm_runtime::backend::AnyBackend;

/// JSON-serializable view of a backend's security profile,
/// surfaced under `security_posture` in `mvmctl doctor --json`.
#[derive(Debug, Serialize)]
pub(super) struct SecurityPostureReport {
    /// Backend name (e.g. "firecracker", "libkrun").
    backend: String,
    /// Tier label: "Tier 1", "Tier 2", "Tier 3".
    tier: &'static str,
    /// Layer coverage flags (L1..L5).
    layers: [bool; 5],
    /// Whether L1+L2+L3 are all enforced — i.e. this is a real microVM tier.
    is_microvm: bool,
    /// Per-claim status strings (1..7), one of "Holds", "DoesNotApply",
    /// "DoesNotHold".
    claims: [&'static str; 7],
    /// 1-indexed claim numbers that do not hold for this backend.
    dropped_claims: Vec<u8>,
    /// 1-indexed claim numbers that don't apply to this backend.
    na_claims: Vec<u8>,
    /// Per-backend rationale (`notes` field of `BackendSecurityProfile`).
    notes: Vec<&'static str>,
}

/// Enumerate every backend's `capabilities().balloon`. The doctor
/// surfaces this so a user authoring `mem_initial` in `mvm.toml`
/// can see at a glance which backend will honour the opt-in (vs.
/// which will silently ignore it because the underlying VMM doesn't
/// support virtio-balloon).
///
/// Keyed by `&str` rather than `&'static str` so JSON serialisation
/// gets a stable BTreeMap ordering. Names match `VmBackend::name`.
pub(super) fn collect_balloon_support() -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    for descriptor in mvm_runtime::catalog::balloon_support_descriptors() {
        let backend = descriptor.instantiate_dyn();
        out.insert(backend.name().to_string(), backend.capabilities().balloon);
    }
    out
}

/// Print the balloon-support matrix in `mvmctl doctor` text mode.
/// Stays concise — one section, one line per backend.
pub(super) fn render_balloon_support(support: &BTreeMap<String, bool>) {
    let title = "Memory ballooning (virtio-balloon)";
    println!("\n{}", title);
    println!("{}", "-".repeat(title.len()));
    for (backend, ok) in support {
        let mark = if *ok { "yes" } else { "no" };
        ui::status_line(&format!("  {backend}:"), mark);
    }
    if !support.values().any(|v| *v) {
        ui::warn(
            "  · No backend on this host advertises virtio-balloon. \
             `mem_initial` in mvm.toml will be ignored at boot.",
        );
    }
}

// ── Active backend security posture ──────

/// Build the [`SecurityPostureReport`] for the backend that `mvmctl run`
/// would auto-select on this host. Pure data — no I/O beyond reading
/// the platform detection (which is already cached).
pub(super) fn collect_security_posture() -> SecurityPostureReport {
    let backend = AnyBackend::auto_select();
    let profile = backend.security_profile();
    let layers = [
        profile.layer_coverage.l1_host_hypervisor,
        profile.layer_coverage.l2_vmm,
        profile.layer_coverage.l3_guest_kernel,
        profile.layer_coverage.l4_guest_agent,
        profile.layer_coverage.l5_workload,
    ];
    let claims = [
        claim_status_label(profile.claims[0]),
        claim_status_label(profile.claims[1]),
        claim_status_label(profile.claims[2]),
        claim_status_label(profile.claims[3]),
        claim_status_label(profile.claims[4]),
        claim_status_label(profile.claims[5]),
        claim_status_label(profile.claims[6]),
    ];
    SecurityPostureReport {
        backend: backend.name().to_string(),
        tier: profile.tier,
        layers,
        is_microvm: profile.layer_coverage.is_microvm(),
        claims,
        dropped_claims: profile.dropped_claims(),
        na_claims: profile.na_claims(),
        notes: profile.notes.to_vec(),
    }
}

const fn claim_status_label(s: ClaimStatus) -> &'static str {
    match s {
        ClaimStatus::Holds => "Holds",
        ClaimStatus::DoesNotApply => "DoesNotApply",
        ClaimStatus::DoesNotHold => "DoesNotHold",
    }
}

/// Render the per-backend security posture in `mvmctl doctor` text mode.
///
/// Always prints the active backend, tier, layer coverage, and per-claim
/// status. Warns if the active backend is not a hardware-isolated microVM
/// tier.
pub(super) fn render_security_posture(p: &SecurityPostureReport) {
    let title = "Security posture (active backend)";
    println!("\n{}", title);
    println!("{}", "-".repeat(title.len()));
    println!("  Active backend: {}", p.backend);
    println!("  Tier: {}", p.tier);

    let layer_marks: String = p
        .layers
        .iter()
        .enumerate()
        .map(|(i, ok)| format!("L{}{}", i + 1, if *ok { " ✓" } else { " ✗" }))
        .collect::<Vec<_>>()
        .join("  ");
    println!("  Layer coverage: {layer_marks}");

    if !p.dropped_claims.is_empty() {
        let list = p
            .dropped_claims
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  Claims that do NOT hold: {list}");
    } else {
        println!("  Claims: all seven hold ✓");
    }
    if !p.na_claims.is_empty() {
        let list = p
            .na_claims
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  Claims that do not apply: {list}");
    }
    for note in &p.notes {
        println!("  · {note}");
    }

    if !p.is_microvm {
        ui::warn(
            "\n  ⚠ This backend is not a hardware-isolated microVM. The L1-L3\n   \
             layers collapse to the host kernel; ADR-002 claims 1, 2, 3 do NOT\n   \
             hold. See https://docs.mvm.dev/security/matryoshka.",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_balloon_support_omits_runner_backends() {
        let support = collect_balloon_support();
        // Firecracker and libkrun route through the workload runner, which takes
        // no balloon elasticity, so both drop off the balloon matrix. qemu is
        // the one remaining descriptor and its honest `false` is not dropped.
        assert!(!support.contains_key("firecracker"));
        assert!(!support.contains_key("libkrun"));
        assert_eq!(support.get("qemu"), Some(&false));
    }

    #[test]
    fn collect_balloon_support_keeps_catalog_backends_in_stable_order() {
        let support = collect_balloon_support();
        let ordered: Vec<_> = support.into_iter().collect();
        assert_eq!(ordered, vec![("qemu".to_string(), false)]);
    }

    #[test]
    fn collect_security_posture_returns_a_real_tier() {
        let posture = collect_security_posture();
        assert!(
            posture.tier == "Tier 1" || posture.tier == "Tier 2" || posture.tier == "Tier 3",
            "unexpected tier: {}",
            posture.tier
        );
        assert_eq!(posture.claims.len(), 7);
    }
}
