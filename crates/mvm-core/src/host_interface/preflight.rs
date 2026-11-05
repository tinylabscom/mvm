use std::collections::BTreeSet;

use super::error::Denial;

/// The checks the launch invariant requires. Every kind in `REQUIRED` must
/// report a result; a missing one is a denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckKind {
    Policy,
    Image,
    Enforcement,
    NodeAdmission,
    Volumes,
    Resources,
    Secrets,
    Attestation,
}

impl CheckKind {
    pub const REQUIRED: [CheckKind; 8] = [
        Self::Policy,
        Self::Image,
        Self::Enforcement,
        Self::NodeAdmission,
        Self::Volumes,
        Self::Resources,
        Self::Secrets,
        Self::Attestation,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Image => "image",
            Self::Enforcement => "enforcement",
            Self::NodeAdmission => "node-admission",
            Self::Volumes => "volumes",
            Self::Resources => "resources",
            Self::Secrets => "secrets",
            Self::Attestation => "attestation",
        }
    }
}

pub trait PreflightCheck: Send + Sync {
    fn kind(&self) -> CheckKind;
    fn run(&self) -> Result<(), Denial>;
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PreflightReport {
    pub denials: Vec<Denial>,
}

impl PreflightReport {
    pub fn into_result(self) -> Result<(), Denial> {
        self.denials.into_iter().next().map_or(Ok(()), Err)
    }
}

/// Run independent checks concurrently. Fails closed: a panicking check, or a
/// required kind with no check supplied, is a denial; a cache or skipped check
/// can never turn into a pass.
pub fn run_preflight(checks: &[Box<dyn PreflightCheck + '_>]) -> PreflightReport {
    let mut denials = Vec::new();
    let mut seen = BTreeSet::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = checks
            .iter()
            .map(|c| (c.kind(), s.spawn(move || c.run())))
            .collect();
        for (kind, h) in handles {
            seen.insert(kind);
            match h.join() {
                Ok(Ok(())) => {}
                Ok(Err(d)) => denials.push(d),
                Err(_) => denials.push(Denial::CheckMissing(kind.name())),
            }
        }
    });
    for kind in CheckKind::REQUIRED {
        if !seen.contains(&kind) {
            denials.push(Denial::CheckMissing(kind.name()));
        }
    }
    PreflightReport { denials }
}
