//! Cross-field and host-ceiling checks before signing or dispatching a plan.

use anyhow::{Context as _, Result};
use mvm_contract::grants::ceiling::GrantCeiling;
use mvm_contract::grants::{CpuGrant, Grants};
use mvm_contract::protocol::capability_negotiation::negotiate_grants;
use mvm_contract::protocol::mailbox::{MailboxGrant, MailboxRetentionPolicy};
use mvm_contract::protocol::resource_controls::ResourceControls;
use mvm_core::plan::{ExecutionPlan, Variant};
use mvm_core::spawn_scope;
use mvm_core::vm_backend::BackendKind;
use mvm_vmm::quota::QuotaConfig;

use super::{RunPosture, display_grants};

pub(super) fn enforce_mailbox_retention(
    mailbox: Option<&MailboxGrant>,
    max_ms: Option<u64>,
) -> Result<()> {
    let Some(requested) = mailbox.and_then(|grant| grant.retention) else {
        return Ok(());
    };
    let max_ms = max_ms
        .context("local mailbox retention requires max_mailbox_retention_ms in host config.toml")?;
    let ceiling = MailboxRetentionPolicy::new(max_ms)
        .context("host max_mailbox_retention_ms must be a finite, nonzero duration")?;
    anyhow::ensure!(
        requested.retention_ms() <= ceiling.retention_ms(),
        "local mailbox retention {} ms exceeds this host's {} ms ceiling",
        requested.retention_ms(),
        ceiling.retention_ms(),
    );
    Ok(())
}

/// A grant cannot carry a wall-clock bound that contradicts its projection.
pub(super) fn enforce_wall_clock_projection(plan: &ExecutionPlan, grants: &Grants) -> Result<()> {
    let projected = mvm_contract::grants::projection::exec_secs_from_grants(grants);
    let carried = plan.resources.timeouts.exec_secs;
    if projected != carried {
        anyhow::bail!(
            "plan carries exec_secs {carried} but its wall-clock grant projects to \
             {projected}; refusing to choose between two encodings of one bound"
        );
    }
    Ok(())
}

/// Refuse a run whose grants this host will not admit.
///
/// Two independent questions, in this order:
///
/// 1. *May it ask for this?* — the ceiling, which bounds the request.
/// 2. *Can anything here deliver it?* — the mechanisms of the backend that will
///    boot it, which decide whether an admitted grant would be enforced or
///    merely recorded.
///
/// The second is posture-dependent: a sealed production run must not boot with
/// a bound nothing implements, while a developer's laptop legitimately runs on
/// tiers that cannot bound CPU at all. Warning rather than refusing in dev is
/// what keeps the refusal credible in prod instead of training everyone to
/// route around it.
pub(super) fn admit_grants(
    plan: &ExecutionPlan,
    ceiling: &GrantCeiling,
    posture: RunPosture,
) -> Result<()> {
    let undeclared = Grants::default();
    let grants = plan.grants.as_ref().unwrap_or(&undeclared);

    enforce_wall_clock_projection(plan, grants)?;

    // Memory is checked even when nothing was granted: it is fixed at VM
    // creation rather than requested, and an unbounded one reserves the host.
    ceiling
        .admits(grants, plan.resources.mem_mib)
        .map_err(|violation| {
            anyhow::anyhow!(
                "grant exceeds this host's ceiling: {dimension} requested {requested}, \
                 host allows at most {ceiling}",
                dimension = violation.dimension,
                requested = violation.requested,
                ceiling = violation.ceiling,
            )
        })?;

    display_grants::admit_display_input(grants, posture.variant)?;
    enforceability_gate(grants, plan, posture)
}

/// Refuse (prod) or warn (dev) when the backend this run boots on has no
/// mechanism behind a declared grant.
pub(super) fn enforceability_gate(
    grants: &Grants,
    plan: &ExecutionPlan,
    posture: RunPosture,
) -> Result<()> {
    // A run that granted CPU or wall clock is the only one with anything to
    // enforce here; asking otherwise would warn on every unbounded boot.
    //
    // `grants.egress` is deliberately outside both this gate and the ceiling,
    // and is enforced elsewhere rather than left unenforced. It is not bounded
    // by a numeric ceiling, and "can this tier deliver it" is not a per-backend
    // question for egress: every workload's traffic already leaves through the
    // one per-VM substitution endpoint, so a granted allow-list is projected
    // onto the policy that endpoint installs, and its gate is what admits or
    // drops each flow.
    //
    // What this early return does not do is check that the projection happened.
    // It cannot: the policy the endpoint installs rides on the launch config,
    // not in the plan body this function reads, so keeping the two derived from
    // one authored value is the obligation of the seam that builds both. What
    // holds here unconditionally is the floor — an absent egress grant and an
    // empty allow-list both project to deny-all, so a workload that granted
    // nothing reaches nothing.
    if grants.cpu.is_none() && grants.wall_clock.is_none() {
        return Ok(());
    }

    // No backend object, no answer. The plan's own `runtime_profile` is not a
    // substitute: it is a label the plan's author chose, so believing it would
    // let a mislabelled plan pick which resource controls it is measured
    // against.
    let Some(kind) = posture.backend else {
        return refuse_or_warn(
            posture.variant,
            "this run was admitted without the backend that will boot it, so no mechanism \
             can be named for the grants it declares"
                .to_string(),
        );
    };

    // The gate measures against `kind`. But if the plan *does* name a tier and
    // it is not this one, the plan and the launch disagree about what is about
    // to run, and a grant checked against either answer is checked against the
    // wrong one. Refused in both postures: this is a contradiction, not a
    // missing mechanism, so there is nothing for a dev warning to soften.
    //
    // A profile that names no tier at all (`transient-run`) is not a
    // disagreement — it makes no claim to contradict.
    if let Some(declared) = BackendKind::from_label(&plan.runtime_profile.0)
        && declared != kind
    {
        anyhow::bail!(
            "plan declares runtime profile {declared} but this run boots on {actual}; \
             refusing to measure its grants against either",
            declared = declared.as_str(),
            actual = kind.as_str(),
        );
    }

    if let Err(gaps) = negotiate_grants(grants, kind) {
        let detail = gaps
            .iter()
            .map(|gap| format!("{} — {}", gap.capability, gap.alternative.describe()))
            .collect::<Vec<_>>()
            .join("; ");
        return refuse_or_warn(
            posture.variant,
            format!(
                "the {tier} tier cannot enforce every declared grant: {detail}",
                tier = kind.as_str()
            ),
        );
    }

    // The tier says the mechanism exists; this host has to actually have it.
    // `ResourceControls::for_backend` answers per backend kind and, for CPU,
    // per target OS — neither of which knows whether *this* host has a systemd
    // user session to delegate from. Without this second question a sealed run
    // on a Linux host with no session bus is admitted, boots unbounded, and
    // reports `declared`: refused in prose and permitted in code.
    if let Some(detail) = host_cpu_mechanism_gap(grants, kind, spawn_scope::mechanism_gap()) {
        return refuse_or_warn(posture.variant, detail);
    }
    Ok(())
}

/// Refusal detail when the backend's tier claims a CPU share it can serve but
/// this host cannot serve it.
///
/// Pure, with the host probe passed in, so both answers are testable on any
/// host — including the combination that cannot be produced locally (a tier
/// that bounds CPU on a machine whose mechanism is missing).
pub(super) fn host_cpu_mechanism_gap(
    grants: &Grants,
    kind: BackendKind,
    gap: Option<spawn_scope::MechanismGap>,
) -> Option<String> {
    // Only a share rides on this mechanism. A fuel budget is wasmtime's, and an
    // absent CPU grant has nothing to enforce.
    let millicores = match grants.cpu {
        Some(CpuGrant::Share { millicores }) => millicores,
        _ => return None,
    };
    if !ResourceControls::for_backend(kind).cpu.serves_share() {
        // The tier itself cannot serve a share; `negotiate_grants` already
        // spoke to that, and saying it twice would name one problem as two.
        return None;
    }

    // HVF enforces shares with its own in-process scheduler; the cgroup probe
    // is irrelevant there. A share that the scheduler cannot parameterize is
    // the only missing-mechanism case on this tier.
    if kind == BackendKind::Hvf {
        if let Err(e) = QuotaConfig::for_share(millicores) {
            return Some(format!("the hvf tier cannot enforce cpu.share: {e}"));
        }
        return None;
    }

    let gap = gap?;
    Some(format!(
        "the {tier} tier bounds CPU with a cgroup quota, but this host cannot attach one: {reason}",
        tier = kind.as_str(),
        reason = gap.describe()
    ))
}

fn refuse_or_warn(variant: Variant, detail: String) -> Result<()> {
    if variant.is_prod() {
        anyhow::bail!("refusing an unenforceable grant: {detail}");
    }
    tracing::warn!(
        "{detail} — admitting anyway because this is a dev run; the grant is recorded, \
         not enforced"
    );
    Ok(())
}
