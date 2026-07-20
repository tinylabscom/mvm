//! Capability-aware backend selection.
//!
//! Selection picks the most-preferred backend whose advertised capabilities
//! satisfy a run's `RequiredCapabilities`, and fails closed with the
//! per-candidate shortfall when none qualify — never silently degrading onto a
//! weaker backend.

use mvm_core::vm_backend::{RequiredCapabilities, VmCapabilities};

use crate::backend::{AnyBackend, FirecrackerBackend};
use crate::hvf_backend::HvfBackend;
use crate::libkrun::LibkrunBackend;
use crate::qemu::QemuBackend;

/// No backend could be selected: every candidate lacked a required capability.
/// Carries the per-candidate shortfall so the caller gets a recovery action
/// instead of a silent degrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionError {
    /// `(backend name, missing capabilities)` for each candidate, in
    /// preference order.
    pub shortfalls: Vec<(String, Vec<&'static str>)>,
}

impl std::fmt::Display for SelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no backend satisfies the required capabilities:")?;
        for (name, missing) in &self.shortfalls {
            write!(f, " {name} lacks [{}];", missing.join(", "))?;
        }
        Ok(())
    }
}

impl std::error::Error for SelectionError {}

/// Index of the first candidate (in preference order) whose capabilities
/// satisfy `required`, or a per-candidate shortfall if none qualify.
///
/// Pure — the core of capability-aware selection, independent of how the
/// candidate list is sourced (platform default, mvmd policy, a test).
pub fn first_capable(
    candidates: &[(&str, VmCapabilities)],
    required: &RequiredCapabilities,
) -> Result<usize, SelectionError> {
    let mut shortfalls = Vec::new();
    for (index, (name, caps)) in candidates.iter().enumerate() {
        let missing = caps.shortfall(required);
        if missing.is_empty() {
            return Ok(index);
        }
        shortfalls.push(((*name).to_string(), missing));
    }
    Err(SelectionError { shortfalls })
}

impl AnyBackend {
    /// The capability-selection preference order of candidate backends.
    ///
    /// Mirrors the production-first preference; platform *availability* is a
    /// separate concern handled by [`AnyBackend::auto_select`]. The in-memory
    /// mock is excluded — it is a test double, never selected for a workload.
    /// The wasm portability tier is excluded too — it is opt-in only and
    /// must never be a capability-selection candidate.
    fn capability_candidates() -> [AnyBackend; 4] {
        [
            AnyBackend::Firecracker(FirecrackerBackend),
            AnyBackend::Hvf(HvfBackend),
            AnyBackend::Libkrun(LibkrunBackend),
            AnyBackend::Qemu(QemuBackend),
        ]
    }

    /// Select the most-preferred backend whose capabilities satisfy `required`,
    /// failing closed with the per-candidate shortfall if none qualify. No
    /// silent downgrade onto a weaker backend.
    pub fn select_capable(required: &RequiredCapabilities) -> Result<AnyBackend, SelectionError> {
        let candidates = Self::capability_candidates();
        let index = {
            let named: Vec<(&str, VmCapabilities)> = candidates
                .iter()
                .map(|backend| (backend.name(), backend.capabilities()))
                .collect();
            first_capable(&named, required)?
        };
        Ok(candidates
            .into_iter()
            .nth(index)
            .expect("first_capable returns an in-range index"))
    }

    /// Select the most-preferred backend whose capabilities satisfy `required`
    /// **and** which is actually available on this host, failing closed with
    /// the per-candidate shortfall otherwise.
    pub fn select_capable_available(
        required: &RequiredCapabilities,
    ) -> Result<AnyBackend, SelectionError> {
        let mut shortfalls = Vec::new();
        for backend in Self::capability_candidates() {
            if !backend.is_available().unwrap_or(false) {
                shortfalls.push((backend.name().to_string(), vec!["unavailable"]));
                continue;
            }
            let missing = backend.capabilities().shortfall(required);
            if missing.is_empty() {
                return Ok(backend);
            }
            shortfalls.push((backend.name().to_string(), missing));
        }
        Err(SelectionError { shortfalls })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_capable_picks_first_satisfying_candidate_in_order() {
        let weak = VmCapabilities::default();
        let strong = VmCapabilities {
            vsock: true,
            ..VmCapabilities::default()
        };
        let candidates = [("weak", weak), ("strong", strong)];
        let required = RequiredCapabilities {
            vsock: true,
            ..Default::default()
        };

        assert_eq!(first_capable(&candidates, &required).unwrap(), 1);
    }

    #[test]
    fn first_capable_fails_closed_with_per_candidate_shortfall() {
        let candidates = [
            ("a", VmCapabilities::default()),
            ("b", VmCapabilities::default()),
        ];
        let required = RequiredCapabilities {
            vsock: true,
            ..Default::default()
        };

        let err = first_capable(&candidates, &required).unwrap_err();
        assert_eq!(err.shortfalls.len(), 2);
        assert!(err.shortfalls.iter().all(|(_, m)| m.contains(&"vsock")));
    }

    #[test]
    fn select_capable_rejects_an_unimplemented_capability() {
        // No backend advertises eager-CoW restore yet, so a run requiring it is
        // rejected rather than silently degraded onto a backend that cannot do
        // it.
        let required = RequiredCapabilities {
            vsock: true,
            eager_cow_restore: true,
            ..Default::default()
        };

        match AnyBackend::select_capable(&required) {
            Ok(_) => panic!("eager-CoW is unimplemented; selection must fail closed"),
            Err(err) => assert!(
                err.shortfalls
                    .iter()
                    .all(|(_, m)| m.contains(&"eager_cow_restore"))
            ),
        }
    }

    #[test]
    fn select_capable_picks_the_preferred_backend_for_a_basic_requirement() {
        let required = RequiredCapabilities {
            vsock: true,
            ..Default::default()
        };

        let backend = AnyBackend::select_capable(&required).unwrap();
        assert!(backend.capabilities().vsock);
    }

    /// Capability-based selection is a form of auto-detection: the wasm
    /// portability tier must never be a candidate, even for a trivially
    /// satisfiable requirement (the empty `RequiredCapabilities`).
    #[test]
    fn capability_candidates_never_include_wasm() {
        let backend = AnyBackend::select_capable(&RequiredCapabilities::default()).unwrap();
        assert_ne!(
            backend.kind(),
            mvm_core::vm_backend::BackendKind::Wasm,
            "capability-aware selection must never pick the opt-in wasm tier"
        );
    }
}
