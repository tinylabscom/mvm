//! A verified admission's one-VM mailbox authority and private helper handoff.

use anyhow::Result;
use mvm_contract::protocol::mailbox::{BootId, MailboxGrant};
use mvm_core::plan::{ExecutionPlan, Nonce, PlanId, Variant};

/// Launch-only posture retained from host admission, never inferred from plan labels.
#[derive(Debug, Clone)]
pub struct MailboxLaunchPosture {
    pub(super) variant: Variant,
    pub(super) plan_id: PlanId,
    pub(super) plan_nonce: Nonce,
    pub(super) vm_name: String,
    pub(super) grant: MailboxGrant,
}

/// The private-pipe projection is not itself admission authority.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxPostureHandoff {
    variant: Variant,
    plan_id: PlanId,
    plan_nonce: Nonce,
    vm_name: String,
    grant: MailboxGrant,
    reader_boot: Option<BootId>,
}

impl MailboxPostureHandoff {
    pub(crate) fn verify(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
        reader_boot: Option<BootId>,
    ) -> Result<()> {
        MailboxLaunchPosture {
            variant: self.variant,
            plan_id: self.plan_id.clone(),
            plan_nonce: self.plan_nonce.clone(),
            vm_name: self.vm_name.clone(),
            grant: self.grant,
        }
        .verify(plan, vm_name)?;
        anyhow::ensure!(
            self.reader_boot == reader_boot,
            "mailbox helper posture belongs to another guest boot"
        );
        Ok(())
    }

    pub(crate) const fn variant(&self) -> Variant {
        self.variant
    }
}

impl MailboxLaunchPosture {
    #[cfg(test)]
    pub(crate) fn for_test(plan: &ExecutionPlan, variant: Variant) -> Self {
        Self {
            variant,
            plan_id: plan.plan_id.clone(),
            plan_nonce: plan.nonce.clone(),
            vm_name: plan.image.name.clone(),
            grant: plan.mailbox.expect("mailbox posture fixture has a grant"),
        }
    }

    /// Check the private helper handoff against this VM's admitted plan.
    pub fn verify(&self, plan: &ExecutionPlan, vm_name: &str) -> Result<()> {
        anyhow::ensure!(
            plan.plan_id == mvm_core::plan::compute_plan_id(plan)
                && self.plan_id == plan.plan_id
                && self.plan_nonce == plan.nonce
                && self.vm_name == vm_name
                && plan.image.name == vm_name
                && plan.mailbox == Some(self.grant),
            "mailbox helper posture does not match the admitted VM and plan"
        );
        Ok(())
    }

    /// The posture admission selected; not a hint from the image or guest.
    #[must_use]
    pub const fn variant(&self) -> Variant {
        self.variant
    }

    pub(crate) fn handoff(&self, reader_boot: Option<BootId>) -> MailboxPostureHandoff {
        MailboxPostureHandoff {
            variant: self.variant,
            plan_id: self.plan_id.clone(),
            plan_nonce: self.plan_nonce.clone(),
            vm_name: self.vm_name.clone(),
            grant: self.grant,
            reader_boot,
        }
    }
}
