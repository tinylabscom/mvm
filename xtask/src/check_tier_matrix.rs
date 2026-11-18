//! `xtask check-tier-matrix`
//!
//! The per-backend tier matrix published in
//! `specs/adrs/001-microvm-security-posture.md` (between the `tier-matrix`
//! markers) used to be hand-maintained prose on top of the per-backend
//! `security_profile()` declarations. The two drifted silently: a claim
//! flipped to `DoesNotHold` in code, the table still showed ✅, and nothing
//! noticed. This gate closes that gap by deriving every L1–L5 symbol from
//! the canonical `BackendSecurityProfile::for_kind` table and comparing it
//! against the published cell:
//!
//! - `❌` — the backend's `LayerCoverage` does not enforce that layer.
//! - `⚠️` — the layer is enforced, but a claim the backend marks
//!   `DoesNotHold` is tagged to that layer in the ADR's claims table.
//! - `✅` — the layer is enforced and no dropped claim pins it.
//!
//! Qualifier prose after a `⚠️`/`✅` symbol is allowed only for an
//! enumerated exception below; each exception is double-keyed with a
//! reason, so dropping the prose without landing the underlying fix is an
//! edit to this file that a reviewer sees, not a silent table rewrite.
//!
//! Scope boundary: the **Notes column is prose and asserted nothing
//! about**. It carries tier rationale, carve-outs, and the wasm row's
//! "off the isolation scale" statement that opens with no tier label at
//! all, so no prefix or content check could be derived from
//! `security_profile()` without encoding editorial judgment in the gate.
//! The ADR says the same in one sentence just below the end marker.
//!
//! Tripwire: every `BackendKind::ALL` variant must either have a matrix
//! row or a double-keyed exclusion here. A newly added backend kind that
//! lands in neither fails the gate, so the matrix cannot silently lose a
//! backend.

use crate::tier_matrix::{self, Row};
use anyhow::{Context, Result, bail};
use mvm_core::vm_backend::{BackendKind, BackendSecurityProfile};
use std::collections::BTreeMap;
use std::path::Path;

const OK: char = '✅';
const WARN: char = '⚠';
const NO: char = '❌';
/// `⚠️` in the table is U+26A0 followed by a text-style variation
/// selector; the selector belongs to the symbol, not the qualifier.
const VARIATION_SELECTOR: char = '\u{FE0F}';

/// The matrix row each displayed backend must have, identified by the
/// Backend-cell text prefix.
const ROW_LABELS: &[(BackendKind, &str)] = &[
    (BackendKind::Firecracker, "Firecracker (Linux + KVM)"),
    (
        BackendKind::Hvf,
        "HVF / Hypervisor.framework (macOS 26+ Apple Silicon)",
    ),
    (
        BackendKind::Libkrun,
        "libkrun (Linux KVM, macOS Hypervisor.framework)",
    ),
    (BackendKind::Qemu, "QEMU (Linux KVM/TCG)"),
    (BackendKind::Wasm, "`wasm-sandbox` (browser / WASI preview)"),
];

/// Backends deliberately absent from the matrix, each with a reason.
/// Double-keyed like the qualifier exceptions: an entry without a reason
/// fails the gate's self-check, so an exclusion cannot be added silently.
const EXCLUDED_KINDS: &[(BackendKind, &str)] = &[
    (
        BackendKind::Mock,
        "lifecycle test double, addressed inside QEMU's row",
    ),
    (
        BackendKind::WebLinux,
        "no product decision to display it; a matrix row is a follow-up",
    ),
    (
        BackendKind::AppleContainer,
        "no product decision to display it; a matrix row is a follow-up",
    ),
];

/// Qualifier prose permitted after a `⚠️`/`✅` symbol, double-keyed with
/// the reason the prose exists. An entry without a reason fails the
/// self-check.
struct QualifierException {
    kind: BackendKind,
    /// 1-indexed Matryoshka layer (L1..L5).
    layer: u8,
    qualifier: &'static str,
    /// The symbol the exception authorizes. For every entry but QEMU's
    /// L2 this equals the derived symbol — the qualifier merely annotates
    /// it. QEMU's L2 is the one deliberate deviation: no dropped claim is
    /// tagged L2, so derivation says ✅, and the ⚠️ records a documented
    /// audit-cost caveat that claim status cannot express.
    symbol: char,
    reason: &'static str,
}

const QUALIFIER_EXCEPTIONS: &[QualifierException] = &[
    QualifierException {
        kind: BackendKind::Hvf,
        layer: 3,
        qualifier: "block+ext4 verified boot only",
        symbol: WARN,
        reason: "claim 3 is scoped to the block+ext4 backends; the virtiofs-root default cannot be dm-verity-sealed. Derivation already yields WARN from the dropped claim; this pins the qualifier text.",
    },
    QualifierException {
        kind: BackendKind::Libkrun,
        layer: 3,
        qualifier: "block+ext4 verified boot only",
        symbol: WARN,
        reason: "the dm-verity pipeline targets Firecracker today; libkrun verified boot is a follow-up. Derivation already yields WARN from the dropped claim; this pins the qualifier text.",
    },
    QualifierException {
        kind: BackendKind::Qemu,
        layer: 3,
        qualifier: "partial verified boot",
        symbol: WARN,
        reason: "verified boot targets Firecracker. Derivation already yields WARN from the dropped claim; this pins the qualifier text.",
    },
    QualifierException {
        kind: BackendKind::Qemu,
        layer: 1,
        qualifier: "KVM where available",
        symbol: OK,
        reason: "QEMU boots KVM-accelerated when /dev/kvm exists and falls back to TCG otherwise; that is a runtime degradation surfaced by the boot banner, not a layer collapse, so the symbol stays OK.",
    },
    QualifierException {
        kind: BackendKind::Qemu,
        layer: 2,
        qualifier: "larger device-model TCB",
        symbol: WARN,
        reason: "an audit-cost caveat, not a dropped claim: no claim marked DoesNotHold is tagged L2, so derivation yields OK. This exception records the deliberate deviation and why.",
    },
];

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let adr = tier_matrix::load_adr(workspace)?;
    let section = tier_matrix::extract_section(&adr).with_context(|| {
        format!(
            "locating the tier matrix between `{}` and `{}` in {}",
            tier_matrix::BEGIN_MARKER,
            tier_matrix::END_MARKER,
            tier_matrix::adr_path(workspace).display()
        )
    })?;
    let rows = tier_matrix::parse_rows(section).with_context(|| {
        format!(
            "parsing the tier-matrix table in {}",
            tier_matrix::adr_path(workspace).display()
        )
    })?;
    let claim_layers = tier_matrix::claim_layers(&adr).with_context(|| {
        format!(
            "parsing claim layer tags in {}",
            tier_matrix::adr_path(workspace).display()
        )
    })?;

    let mut errors: Vec<String> = Vec::new();
    self_checks(&mut errors);
    let rowed = check_rows(&rows, &claim_layers, &mut errors);
    tripwire(&rowed, &mut errors);

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("[error] {e}");
        }
        bail!(
            "check-tier-matrix: {} problem(s) in the per-backend tier matrix (specs/adrs/001-microvm-security-posture.md)",
            errors.len()
        );
    }

    eprintln!(
        "check-tier-matrix: clean ({} rows, {} layer cells verified against security_profile())",
        rows.len(),
        rows.len() * 5
    );
    Ok(())
}

/// The gate's own tables must be as auditable as the matrix it checks.
fn self_checks(errors: &mut Vec<String>) {
    check_exclusion_reasons(EXCLUDED_KINDS, errors);
    check_exception_reasons(QUALIFIER_EXCEPTIONS, errors);
}

fn check_exclusion_reasons(exclusions: &[(BackendKind, &str)], errors: &mut Vec<String>) {
    for (kind, reason) in exclusions {
        if reason.is_empty() {
            errors.push(format!("{kind:?}: matrix exclusion has no reason"));
        }
    }
}

fn check_exception_reasons(exceptions: &[QualifierException], errors: &mut Vec<String>) {
    let mut seen: Vec<(BackendKind, u8)> = Vec::new();
    for exc in exceptions {
        if exc.reason.is_empty() {
            errors.push(format!(
                "{:?} L{}: qualifier exception has no reason",
                exc.kind, exc.layer
            ));
        }
        if exc.qualifier.is_empty() {
            errors.push(format!(
                "{:?} L{}: qualifier exception has no qualifier text",
                exc.kind, exc.layer
            ));
        }
        if !(1..=5).contains(&exc.layer) {
            errors.push(format!(
                "{:?} L{}: layer must be 1..=5",
                exc.kind, exc.layer
            ));
        }
        let key = (exc.kind, exc.layer);
        if seen.contains(&key) {
            errors.push(format!(
                "{:?} L{}: duplicate qualifier exception",
                exc.kind, exc.layer
            ));
        }
        seen.push(key);
    }
}

/// Check every published row against the derived expectation. Returns the
/// kinds that had a row, for the tripwire.
fn check_rows(
    rows: &[Row],
    claim_layers: &BTreeMap<u8, Vec<String>>,
    errors: &mut Vec<String>,
) -> Vec<BackendKind> {
    let mut rowed = Vec::new();
    let mut claimed: Vec<bool> = vec![false; rows.len()];

    for (kind, label) in ROW_LABELS {
        let matches: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.backend.starts_with(*label))
            .map(|(i, _)| i)
            .collect();
        match matches.as_slice() {
            [] => errors.push(format!(
                "{kind:?}: no matrix row with Backend cell starting `{label}`"
            )),
            [only] => {
                claimed[*only] = true;
                rowed.push(*kind);
                let profile = BackendSecurityProfile::for_kind(*kind);
                for layer in 1..=5u8 {
                    check_cell(
                        *kind,
                        profile,
                        layer,
                        &rows[*only].cells[usize::from(layer - 1)],
                        claim_layers,
                        errors,
                    );
                }
            }
            _ => errors.push(format!(
                "{kind:?}: {} matrix rows match `{label}`; one row per backend",
                matches.len()
            )),
        }
    }

    for (i, was_claimed) in claimed.iter().enumerate() {
        if !was_claimed {
            errors.push(format!(
                "matrix row `{}` matches no known backend label",
                rows[i].backend
            ));
        }
    }
    rowed
}

fn check_cell(
    kind: BackendKind,
    profile: &BackendSecurityProfile,
    layer: u8,
    cell: &str,
    claim_layers: &BTreeMap<u8, Vec<String>>,
    errors: &mut Vec<String>,
) {
    let Some((symbol, qualifier)) = parse_cell(cell) else {
        errors.push(format!(
            "{kind:?} L{layer}: cell {cell:?} does not start with a known symbol \
             ({OK}, {WARN}{VARIATION_SELECTOR}, or {NO})"
        ));
        return;
    };
    let derived = expected_symbol(profile, layer, claim_layers);
    let layer_name = format!("L{layer}");

    if qualifier.is_empty() {
        if symbol != derived {
            errors.push(format!(
                "{kind:?} {layer_name}: expected {derived} (derived from security_profile(): \
                 layer enforced = {}, dropped claims tagged {layer_name} = {:?}), found {symbol}",
                layer_enforced(profile, layer),
                dropped_claims_tagged(profile, layer, claim_layers)
            ));
        }
        return;
    }

    let exception = QUALIFIER_EXCEPTIONS
        .iter()
        .find(|exc| exc.kind == kind && exc.layer == layer);
    let Some(exception) = exception else {
        errors.push(format!(
            "{kind:?} {layer_name}: qualifier {qualifier:?} is not an enumerated exception — \
             derive the symbol from security_profile() or add a reasoned exception"
        ));
        return;
    };
    if exception.qualifier != qualifier {
        errors.push(format!(
            "{kind:?} {layer_name}: qualifier {qualifier:?} does not match the enumerated \
             exception {exc:?}",
            exc = exception.qualifier
        ));
    }
    if symbol != exception.symbol {
        errors.push(format!(
            "{kind:?} {layer_name}: symbol {symbol} does not match the exception's authorized \
             symbol {exc}",
            exc = exception.symbol
        ));
    }
}

/// Split a cell into its leading symbol and the qualifier prose that
/// follows it (with the variation selector kept with the symbol).
fn parse_cell(cell: &str) -> Option<(char, String)> {
    let mut chars = cell.chars();
    let symbol = chars.next()?;
    if !matches!(symbol, OK | WARN | NO) {
        return None;
    }
    let rest = chars.as_str().trim();
    let qualifier = rest
        .strip_prefix(VARIATION_SELECTOR)
        .unwrap_or(rest)
        .trim()
        .to_string();
    Some((symbol, qualifier))
}

fn layer_enforced(profile: &BackendSecurityProfile, layer: u8) -> bool {
    let c = &profile.layer_coverage;
    match layer {
        1 => c.l1_host_hypervisor,
        2 => c.l2_vmm,
        3 => c.l3_guest_kernel,
        4 => c.l4_guest_agent,
        5 => c.l5_workload,
        _ => false,
    }
}

/// Dropped (DoesNotHold) claim numbers tagged to this layer.
fn dropped_claims_tagged(
    profile: &BackendSecurityProfile,
    layer: u8,
    claim_layers: &BTreeMap<u8, Vec<String>>,
) -> Vec<u8> {
    let tag = format!("L{layer}");
    profile
        .dropped_claims()
        .into_iter()
        .filter(|claim| {
            claim_layers
                .get(claim)
                .is_some_and(|tags| tags.iter().any(|t| t == &tag))
        })
        .collect()
}

/// The derived cell symbol: ❌ when the layer is not enforced, ⚠️ when a
/// dropped claim pins the layer, ✅ otherwise.
fn expected_symbol(
    profile: &BackendSecurityProfile,
    layer: u8,
    claim_layers: &BTreeMap<u8, Vec<String>>,
) -> char {
    if !layer_enforced(profile, layer) {
        return NO;
    }
    if dropped_claims_tagged(profile, layer, claim_layers).is_empty() {
        OK
    } else {
        WARN
    }
}

/// Every backend kind must be visible: a matrix row or a reasoned
/// exclusion. A new `BackendKind` variant lands in neither and fails here.
fn tripwire(rowed: &[BackendKind], errors: &mut Vec<String>) {
    for kind in BackendKind::ALL {
        let has_row = rowed.contains(kind);
        let has_exclusion = EXCLUDED_KINDS.iter().any(|(k, _)| k == kind);
        if !has_row && !has_exclusion {
            errors.push(format!(
                "{kind:?}: neither a matrix row nor a reasoned exclusion — add the row or \
                 record why this backend stays off the matrix"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::ClaimStatus;

    /// A Tier-2-shaped profile: full layer coverage with one droppable claim.
    fn droppable_profile(claim3: ClaimStatus) -> BackendSecurityProfile {
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds,
                ClaimStatus::Holds,
                claim3,
                ClaimStatus::Holds,
                ClaimStatus::Holds,
                ClaimStatus::Holds,
                ClaimStatus::Holds,
            ],
            layer_coverage: mvm_core::vm_backend::LayerCoverage::all_layers(),
            tier: "Tier 2",
            notes: &[],
        }
    }

    fn layers(tags: &[(u8, &str)]) -> BTreeMap<u8, Vec<String>> {
        tags.iter()
            .map(|(n, t)| (*n, vec![t.to_string()]))
            .collect()
    }

    #[test]
    fn a_dropped_claim_tagged_to_a_layer_warns_that_layer_only() {
        let profile = droppable_profile(ClaimStatus::DoesNotHold);
        let map = layers(&[(3, "L3")]);
        assert_eq!(expected_symbol(&profile, 1, &map), OK);
        assert_eq!(expected_symbol(&profile, 2, &map), OK);
        assert_eq!(expected_symbol(&profile, 3, &map), WARN);
        assert_eq!(expected_symbol(&profile, 4, &map), OK);
        assert_eq!(expected_symbol(&profile, 5, &map), OK);
    }

    #[test]
    fn a_dropped_claim_tagged_to_no_layer_warns_nothing() {
        // Claims 6/7 are supply-chain claims: dropping one must not bleed
        // onto any Matryoshka layer cell.
        let profile = droppable_profile(ClaimStatus::Holds);
        let mut profile = profile;
        profile.claims[5] = ClaimStatus::DoesNotHold; // claim 6
        let map = layers(&[(6, "supply chain")]);
        for layer in 1..=5 {
            assert_eq!(expected_symbol(&profile, layer, &map), OK, "L{layer}");
        }
        assert!(dropped_claims_tagged(&profile, 3, &map).is_empty());
    }

    #[test]
    fn an_unenforced_layer_derives_cross_regardless_of_claims() {
        let wasm = BackendSecurityProfile::for_kind(BackendKind::Wasm);
        let map = layers(&[(3, "L3")]);
        for layer in 1..=5 {
            assert_eq!(expected_symbol(wasm, layer, &map), NO, "L{layer}");
        }
    }

    #[test]
    fn parse_cell_separates_symbol_variation_selector_and_qualifier() {
        let (symbol, qualifier) = parse_cell("⚠️ block+ext4 verified boot only").unwrap();
        assert_eq!(symbol, WARN);
        assert_eq!(qualifier, "block+ext4 verified boot only");
        let (symbol, qualifier) = parse_cell("✅").unwrap();
        assert_eq!(symbol, OK);
        assert!(qualifier.is_empty());
        assert!(parse_cell("maybe").is_none());
    }

    #[test]
    fn the_real_table_derives_cleanly_for_every_row() {
        // The strongest regression net: run the real derivation against
        // the real const table with the real claim tags, exactly as the
        // gate does, minus the ADR read.
        let adr = tier_matrix::load_adr(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").as_path())
            .unwrap();
        let section = tier_matrix::extract_section(&adr).unwrap();
        let rows = tier_matrix::parse_rows(section).unwrap();
        let claim_layers = tier_matrix::claim_layers(&adr).unwrap();
        let mut errors = Vec::new();
        let rowed = check_rows(&rows, &claim_layers, &mut errors);
        tripwire(&rowed, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn drift_is_reported_with_backend_layer_expected_and_actual() {
        let profile = BackendSecurityProfile::for_kind(BackendKind::Hvf);
        let map = layers(&[(3, "L3")]);
        let mut errors = Vec::new();
        check_cell(BackendKind::Hvf, profile, 3, "✅", &map, &mut errors);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("Hvf"), "{errors:?}");
        assert!(errors[0].contains("L3"), "{errors:?}");
        assert!(errors[0].contains('⚠'), "{errors:?}");
        assert!(errors[0].contains('✅'), "{errors:?}");
    }

    #[test]
    fn an_unknown_qualifier_is_rejected() {
        // L1 has no enumerated exception for HVF, so any qualifier text
        // there hits the "not an enumerated exception" refusal.
        let profile = BackendSecurityProfile::for_kind(BackendKind::Hvf);
        let map = layers(&[(3, "L3")]);
        let mut errors = Vec::new();
        check_cell(
            BackendKind::Hvf,
            profile,
            1,
            "✅ hand-waved caveat",
            &map,
            &mut errors,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].contains("not an enumerated exception"),
            "{errors:?}"
        );
    }

    #[test]
    fn a_qualifier_that_disagrees_with_the_exception_text_is_rejected() {
        let profile = BackendSecurityProfile::for_kind(BackendKind::Hvf);
        let map = layers(&[(3, "L3")]);
        let mut errors = Vec::new();
        check_cell(
            BackendKind::Hvf,
            profile,
            3,
            "⚠️ hand-waved caveat",
            &map,
            &mut errors,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].contains("does not match the enumerated exception"),
            "{errors:?}"
        );
    }

    #[test]
    fn a_symbol_that_disagrees_with_the_exception_is_rejected() {
        let profile = BackendSecurityProfile::for_kind(BackendKind::Qemu);
        let map = layers(&[(3, "L3")]);
        let mut errors = Vec::new();
        check_cell(
            BackendKind::Qemu,
            profile,
            2,
            "✅ larger device-model TCB",
            &map,
            &mut errors,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("authorized symbol"), "{errors:?}");
    }

    #[test]
    fn self_check_rejects_an_exception_without_a_reason() {
        let broken = [QualifierException {
            kind: BackendKind::Hvf,
            layer: 3,
            qualifier: "block+ext4 verified boot only",
            symbol: WARN,
            reason: "",
        }];
        let mut errors = Vec::new();
        check_exception_reasons(&broken, &mut errors);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("no reason"), "{errors:?}");
    }

    #[test]
    fn self_check_rejects_a_duplicate_exception() {
        let first = &QUALIFIER_EXCEPTIONS[0];
        let duplicated = [
            QualifierException {
                kind: first.kind,
                layer: first.layer,
                qualifier: first.qualifier,
                symbol: first.symbol,
                reason: first.reason,
            },
            QualifierException {
                kind: first.kind,
                layer: first.layer,
                qualifier: "another qualifier",
                symbol: OK,
                reason: "a reason",
            },
        ];
        let mut errors = Vec::new();
        check_exception_reasons(&duplicated, &mut errors);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("duplicate qualifier exception")),
            "{errors:?}"
        );
    }

    #[test]
    fn the_three_exclusions_satisfy_the_tripwire() {
        let mut errors = Vec::new();
        // Every ALL variant that has no row is covered by an exclusion.
        let rowed: Vec<BackendKind> = ROW_LABELS.iter().map(|(k, _)| *k).collect();
        tripwire(&rowed, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn a_kind_with_neither_row_nor_exclusion_fails_the_tripwire() {
        // Simulates a newly added BackendKind: no row, no exclusion. Every
        // rowed kind must be named as missing.
        let mut errors = Vec::new();
        tripwire(&[], &mut errors);
        assert_eq!(errors.len(), ROW_LABELS.len(), "{errors:?}");
        for (kind, _) in ROW_LABELS {
            assert!(
                errors.iter().any(|e| e.starts_with(&format!("{kind:?}"))),
                "{errors:?}"
            );
        }
    }
}
